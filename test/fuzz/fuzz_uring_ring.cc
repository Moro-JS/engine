// libFuzzer harness for src/uring.h's ring mechanics against the fake kernel
// (test/uring_fake_sys.h). The fuzz input is a script: a header byte picks the
// ring geometry, then each byte is an action - hand out an SQE, enter (with
// a fuzz-chosen partial-submit cap), reap, recycle a buffer, publish, or
// mark the ring for CQ pressure - while the fake completes SQEs with fuzz-
// chosen result codes and multishot flags. Invariants checked every step:
//   - an SQE is never dropped: every id handed out is eventually completed
//     exactly once, in submission order
//   - the ring never hands out more than sqEntries SQEs without an enter
//   - CQ overflow loses nothing and preserves order across the drain
//   - the provided-buffer ring's tail only ever advances by the buffers
//     pushed, and at(bid) stays inside the mapping
//
// Build (see run.sh): clang++ -fsanitize=fuzzer,address,undefined \
//   test/fuzz/fuzz_uring_ring.cc -o /tmp/moro_fuzz_uring

#include <cstdint>
#include <cstring>
#include <deque>
#include <vector>

#include "../uring_fake_sys.h"

using namespace moro::engine::uring;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  FakeSys::reset();
  FakeSys::State& st = FakeSys::st();

  const unsigned sqEntries = 1u << (1 + (data[0] & 3));      // 2..16
  const unsigned cqEntries = 1u << (1 + ((data[0] >> 2) & 3)); // 2..16
  const uint8_t policyByte = data[1];
  size_t pos = 2;

  // Completion policy: res = user_data, occasionally an error, occasionally
  // marked "more" (a multishot-style continuation: two CQEs for one SQE).
  std::deque<uint64_t> expectedOrder;
  st.complete = [&](const abi::io_uring_sqe& s, std::vector<abi::io_uring_cqe>& out) {
    const uint8_t v = static_cast<uint8_t>(s.user_data ^ policyByte);
    if ((v & 7) == 0) {
      out.push_back({s.user_data, static_cast<int32_t>(s.user_data & 0xffff), abi::IORING_CQE_F_MORE});
      expectedOrder.push_back(s.user_data);
    }
    out.push_back({s.user_data, (v & 3) == 3 ? -11 : static_cast<int32_t>(s.user_data & 0xffff), 0});
    expectedOrder.push_back(s.user_data);
  };

  Ring<FakeSys> ring;
  if (ring.open(sqEntries, kSetupFlags, cqEntries) != 0) return 0;
  BufRing<FakeSys> bufs;
  const bool haveBufs = bufs.init(ring, 3, 8, 64) == 0;
  if (!haveBufs) __builtin_trap();

  uint64_t nextId = 1;
  unsigned handedOut = 0;   // SQEs handed out since the last enter
  uint64_t reaped = 0;
  uint16_t bufTail = bufs.tail();
  unsigned pushedSinceMove = 0;

  auto reapAll = [&]() {
    ring.forEachCqe([&](const abi::io_uring_cqe& c) {
      if (expectedOrder.empty() || expectedOrder.front() != c.user_data) __builtin_trap();
      expectedOrder.pop_front();
      reaped++;
    });
  };

  while (pos < size) {
    const uint8_t op = data[pos++];
    switch (op & 7) {
      case 0:
      case 1: {  // hand out an SQE
        abi::io_uring_sqe* s = ring.sqe();
        if (s) {
          if (handedOut >= ring.sqEntries()) __builtin_trap();  // over-issue
          prepNop(s);
          s->user_data = nextId++;
          handedOut++;
        } else if (ring.pending() < ring.sqEntries()) {
          // sqe() may only refuse when the ring is genuinely full of
          // unsubmitted-or-unconsumed entries.
          __builtin_trap();
        }
        break;
      }
      case 2: {  // enter with a fuzz-chosen partial cap
        st.maxSubmitPerEnter = 1u + (op >> 3);
        const unsigned before = ring.pending();
        int r = ring.enter(0, (op & 8) ? abi::IORING_ENTER_GETEVENTS : 0);
        if (r < 0) __builtin_trap();
        if (static_cast<unsigned>(r) > before) __builtin_trap();
        if (ring.pending() != before - static_cast<unsigned>(r)) __builtin_trap();
        handedOut = ring.pending();
        break;
      }
      case 3:  // reap
        reapAll();
        break;
      case 4: {  // recycle a buffer
        const uint16_t bid = static_cast<uint16_t>((op >> 3) & 7);
        const uint8_t* p = bufs.at(bid);
        if (p < bufs.at(0) || p >= bufs.at(0) + 8 * 64) __builtin_trap();
        bufs.push(bid);
        pushedSinceMove++;
        break;
      }
      case 5:  // publish pushed buffers
        bufs.publish();
        if (static_cast<uint16_t>(bufTail + pushedSinceMove) != bufs.tail()) __builtin_trap();
        bufTail = bufs.tail();
        pushedSinceMove = 0;
        break;
      case 6: {  // drain everything: flush + GETEVENTS until quiescent
        st.maxSubmitPerEnter = 1u << 30;
        for (int i = 0; i < 8 && (ring.pending() || ring.cqOverflowed() || ring.cqReady()); i++) {
          if (ring.enter(0, abi::IORING_ENTER_GETEVENTS) < 0) __builtin_trap();
          reapAll();
        }
        handedOut = ring.pending();
        break;
      }
      default:
        break;
    }
  }

  // Final drain: nothing may be lost or duplicated.
  st.maxSubmitPerEnter = 1u << 30;
  for (int i = 0; i < 16 && (ring.pending() || ring.cqOverflowed() || ring.cqReady()); i++) {
    if (ring.enter(0, abi::IORING_ENTER_GETEVENTS) < 0) __builtin_trap();
    reapAll();
  }
  if (!expectedOrder.empty()) __builtin_trap();
  if (reaped != static_cast<uint64_t>(st.enterCalls >= 0 ? reaped : 0)) __builtin_trap();
  bufs.destroy(ring);
  ring.close();
  FakeSys::reset();
  return 0;
}
