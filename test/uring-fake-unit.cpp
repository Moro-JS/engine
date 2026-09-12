// Unit test for src/uring.h against a FAKE kernel: an in-memory io_uring
// (rings, SQE array, completion policy) behind the Sys interface, so ring
// mechanics are exercised on every OS, with sanitizers, without a Linux
// kernel: SQE hand-out and back-pressure (never a dropped SQE), submit
// accounting including partial submits, in-order reaping across ring
// wrap-around, CQ overflow flagging + drain, provided-buffer ring
// registration/recycling, the SQE builders, and user_data tagging.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "uring_fake_sys.h"

using namespace moro::engine::uring;

static int checks = 0;
static int failures = 0;
#define CHECK(cond)                                                          \
  do {                                                                       \
    ++checks;                                                                \
    if (!(cond)) {                                                           \
      ++failures;                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
    }                                                                        \
  } while (0)

// Complete every SQE with res = its user_data (a NOP-style echo).
static void echoPolicy(const abi::io_uring_sqe& s, std::vector<abi::io_uring_cqe>& out) {
  out.push_back({s.user_data, static_cast<int32_t>(s.user_data & 0x7fffffff), 0});
}

int main() {
  // ---- open / basic geometry ----
  {
    FakeSys::reset();
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags, 16) == 0);
    CHECK(ring.isOpen());
    CHECK(ring.fd() == 100);
    CHECK(ring.sqEntries() == 8);
    CHECK(ring.cqEntries() == 16);
    CHECK((ring.features() & kRequiredFeatures) == kRequiredFeatures);
    CHECK(ring.pending() == 0);
    ring.close();
    CHECK(!ring.isOpen());
  }
  // ---- setup failure surfaces as -errno ----
  {
    FakeSys::reset();
    FakeSys::st().setupErrno = 1;  // EPERM
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags) == -1);
    CHECK(!ring.isOpen());
  }
  // ---- SQE back-pressure: exactly sqEntries handed out, never dropped ----
  {
    FakeSys::reset();
    FakeSys::st().complete = echoPolicy;
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags, 16) == 0);
    int got = 0;
    for (int i = 0; i < 20; i++) {
      abi::io_uring_sqe* s = ring.sqe();
      if (!s) break;
      prepNop(s);
      s->user_data = static_cast<uint64_t>(100 + i);
      got++;
    }
    CHECK(got == 8);
    CHECK(ring.pending() == 8);
    CHECK(ring.enter(0, 0) == 8);
    CHECK(ring.pending() == 0);
    CHECK(ring.sqe() != nullptr);  // room again after the kernel consumed them
  }
  // ---- in-order reaping across wrap-around, in batches ----
  {
    FakeSys::reset();
    FakeSys::st().complete = echoPolicy;
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags, 8) == 0);
    std::vector<uint64_t> seen;
    uint64_t next = 1;
    for (int batch = 0; batch < 10; batch++) {
      for (int i = 0; i < 5; i++) {
        abi::io_uring_sqe* s = ring.sqe();
        CHECK(s != nullptr);
        prepNop(s);
        s->user_data = next++;
      }
      CHECK(ring.enter(0, abi::IORING_ENTER_GETEVENTS) == 5);
      ring.forEachCqe([&](const abi::io_uring_cqe& c) { seen.push_back(c.user_data); });
    }
    CHECK(seen.size() == 50);
    bool ordered = true;
    for (size_t i = 0; i < seen.size(); i++)
      if (seen[i] != i + 1) ordered = false;
    CHECK(ordered);
  }
  // ---- CQ overflow: flagged, nothing lost, drained on the next GETEVENTS ----
  {
    FakeSys::reset();
    FakeSys::st().complete = echoPolicy;
    Ring<FakeSys> ring;
    CHECK(ring.open(16, kSetupFlags, 8) == 0);
    for (int i = 0; i < 12; i++) {
      abi::io_uring_sqe* s = ring.sqe();
      prepNop(s);
      s->user_data = static_cast<uint64_t>(i + 1);
    }
    CHECK(ring.enter(0, 0) == 12);
    CHECK(ring.cqOverflowed());
    CHECK(ring.cqReady() == 8);
    std::vector<uint64_t> seen;
    ring.forEachCqe([&](const abi::io_uring_cqe& c) { seen.push_back(c.user_data); });
    CHECK(seen.size() == 8);
    CHECK(ring.enter(0, abi::IORING_ENTER_GETEVENTS) == 0);
    CHECK(!ring.cqOverflowed());
    ring.forEachCqe([&](const abi::io_uring_cqe& c) { seen.push_back(c.user_data); });
    CHECK(seen.size() == 12);
    bool ordered = true;
    for (size_t i = 0; i < seen.size(); i++)
      if (seen[i] != i + 1) ordered = false;
    CHECK(ordered);
    CHECK(ring.cqOverflow() == 4);
  }
  // ---- partial submit accounting ----
  {
    FakeSys::reset();
    FakeSys::st().complete = echoPolicy;
    FakeSys::st().maxSubmitPerEnter = 3;
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags, 16) == 0);
    for (int i = 0; i < 7; i++) {
      abi::io_uring_sqe* s = ring.sqe();
      prepNop(s);
      s->user_data = static_cast<uint64_t>(i + 1);
    }
    CHECK(ring.enter(0, 0) == 3);
    CHECK(ring.pending() == 4);
    CHECK(ring.enter(0, 0) == 3);
    CHECK(ring.pending() == 1);
    CHECK(ring.enter(0, 0) == 1);
    CHECK(ring.pending() == 0);
    unsigned n = ring.forEachCqe([](const abi::io_uring_cqe&) {});
    CHECK(n == 7);
    CHECK(FakeSys::st().enterCalls == 3);
  }
  // ---- provided-buffer ring ----
  {
    FakeSys::reset();
    Ring<FakeSys> ring;
    CHECK(ring.open(8, kSetupFlags, 16) == 0);
    BufRing<FakeSys> bufs;
    CHECK(bufs.init(ring, 7, 12, 256) == -22);  // not a power of two
    CHECK(bufs.init(ring, 7, 16, 256) == 0);
    CHECK(FakeSys::st().bufRegs.size() == 1);
    CHECK(FakeSys::st().bufRegs[0].bgid == 7);
    CHECK(FakeSys::st().bufRegs[0].ring_entries == 16);
    CHECK(bufs.tail() == 16);  // every buffer handed to the kernel
    CHECK(bufs.count() == 16 && bufs.bufSize() == 256 && bufs.bgid() == 7);
    // distinct, non-overlapping buffers inside the mapping, after the header
    const uint8_t* base = bufs.at(0);
    CHECK(reinterpret_cast<uintptr_t>(base) == FakeSys::st().bufRegs[0].ring_addr + 16 * sizeof(abi::io_uring_buf));
    for (uint16_t i = 1; i < 16; i++) CHECK(bufs.at(i) == base + static_cast<size_t>(i) * 256);
    // ring header entries describe bid/len/addr
    auto* hdr = reinterpret_cast<abi::io_uring_buf_ring*>(FakeSys::st().bufRegs[0].ring_addr);
    // The header's bufs[1] is the UAPI's flexible-array idiom: index through
    // a pointer to the real (16-entry) array so -Warray-bounds stays quiet.
    const abi::io_uring_buf* entries = hdr->bufs;
    CHECK(entries[3].bid == 3 && entries[3].len == 256 && entries[3].addr == reinterpret_cast<uint64_t>(bufs.at(3)));
    CHECK(loadAcquire16(&hdr->tail) == 16);
    // recycle advances the tail and re-describes the buffer at the new slot
    bufs.recycle(5);
    CHECK(bufs.tail() == 17);
    CHECK(entries[16 & 15].bid == 5);
    bufs.push(1);
    bufs.push(2);
    CHECK(bufs.tail() == 17);  // batched: not published yet
    bufs.publish();
    CHECK(bufs.tail() == 19);
    CHECK(loadAcquire16(&hdr->tail) == 19);
    bufs.destroy(ring);
    CHECK(FakeSys::st().bufUnregs.size() == 1 && FakeSys::st().bufUnregs[0] == 7);
  }
  // ---- SQE builders ----
  {
    abi::io_uring_sqe s;
    std::memset(&s, 0, sizeof(s));
    prepAccept(&s, 9, 0x80800, true);  // SOCK_NONBLOCK|SOCK_CLOEXEC on x86-64
    CHECK(s.opcode == abi::IORING_OP_ACCEPT && s.fd == 9 && s.accept_flags == 0x80800 && (s.ioprio & abi::IORING_ACCEPT_MULTISHOT));
    std::memset(&s, 0, sizeof(s));
    prepRecv(&s, 4, 3, true);
    CHECK(s.opcode == abi::IORING_OP_RECV && s.fd == 4 && (s.flags & abi::IOSQE_BUFFER_SELECT) && s.buf_group == 3 && s.len == 0 && (s.ioprio & abi::IORING_RECV_MULTISHOT));
    std::memset(&s, 0, sizeof(s));
    prepRecv(&s, 4, 3, false);
    CHECK(!(s.ioprio & abi::IORING_RECV_MULTISHOT));
    std::memset(&s, 0, sizeof(s));
    const char* data = "hello";
    prepSend(&s, 5, data, 5, 0x4000);
    CHECK(s.opcode == abi::IORING_OP_SEND && s.fd == 5 && s.addr == reinterpret_cast<uint64_t>(data) && s.len == 5 && s.msg_flags == 0x4000);
    std::memset(&s, 0, sizeof(s));
    prepCancelFd(&s, 6);
    CHECK(s.opcode == abi::IORING_OP_ASYNC_CANCEL && s.fd == 6 && s.cancel_flags == (abi::IORING_ASYNC_CANCEL_FD | abi::IORING_ASYNC_CANCEL_ALL));
    std::memset(&s, 0, sizeof(s));
    prepClose(&s, 6);
    CHECK(s.opcode == abi::IORING_OP_CLOSE && s.fd == 6);
    std::memset(&s, 0, sizeof(s));
    prepShutdown(&s, 6, 1);
    CHECK(s.opcode == abi::IORING_OP_SHUTDOWN && s.fd == 6 && s.len == 1);
    std::memset(&s, 0, sizeof(s));
    prepNop(&s);
    CHECK(s.opcode == abi::IORING_OP_NOP);
  }
  // ---- user_data tagging ----
  {
    alignas(8) char object[8];
    for (unsigned t = 0; t < 8; t++) {
      uint64_t ud = tag(object, static_cast<Tag>(t));
      CHECK(tagOf(ud) == static_cast<Tag>(t));
      CHECK(ptrOf(ud) == object);
    }
    abi::io_uring_cqe c{0, 0, abi::IORING_CQE_F_BUFFER | abi::IORING_CQE_F_MORE | (37u << abi::IORING_CQE_BUFFER_SHIFT)};
    CHECK(hasBuffer(c) && hasMore(c) && bufferId(c) == 37);
    abi::io_uring_cqe d{0, 0, 0};
    CHECK(!hasBuffer(d) && !hasMore(d));
  }
  // ---- probe() off Linux reports 'platform' ----
#if !defined(__linux__)
  {
    ProbeResult r = probe();
    CHECK(!r.ok);
    CHECK(std::strcmp(r.reason, "platform") == 0);
  }
#endif

  FakeSys::reset();
  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all io_uring fake-kernel unit tests passed (%d checks)\n", checks);
  return 0;
}
