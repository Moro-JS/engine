// In-memory io_uring "kernel" behind src/uring.h's Sys interface, shared by
// test/uring-fake-unit.cpp and test/fuzz/fuzz_uring_ring.cc. Implements the
// user-visible ring contract: SQ consumption from the user's tail, CQE
// posting into the CQ ring with overflow (IORING_SQ_CQ_OVERFLOW + overflow
// counter, drained on the next GETEVENTS enter), buffer-ring registration,
// partial submits, and a scriptable completion policy per SQE.
#pragma once

#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <vector>

#include "../src/uring.h"

namespace moro {
namespace engine {
namespace uring {

struct FakeSys {
  struct State {
    uint8_t* ring = nullptr;
    size_t ringSize = 0;
    abi::io_uring_sqe* sqes = nullptr;
    unsigned sqEntries = 0;
    unsigned cqEntries = 0;
    uint32_t* sqHead = nullptr;
    uint32_t* sqTail = nullptr;
    uint32_t* sqFlags = nullptr;
    uint32_t* sqArray = nullptr;
    uint32_t* cqHead = nullptr;
    uint32_t* cqTail = nullptr;
    uint32_t* cqOverflow = nullptr;
    abi::io_uring_cqe* cqes = nullptr;
    std::deque<abi::io_uring_cqe> overflowed;  // completions that did not fit
    // completion policy: given a submitted SQE, produce zero or more CQEs
    std::function<void(const abi::io_uring_sqe&, std::vector<abi::io_uring_cqe>&)> complete;
    unsigned maxSubmitPerEnter = 1u << 30;  // simulate partial submits
    int enterCalls = 0;
    int setupErrno = 0;  // simulate setup failure
    uint32_t features = abi::IORING_FEAT_SINGLE_MMAP | abi::IORING_FEAT_NODROP |
                        abi::IORING_FEAT_SUBMIT_STABLE | abi::IORING_FEAT_FAST_POLL;
    std::vector<abi::io_uring_buf_reg> bufRegs;
    std::vector<uint16_t> bufUnregs;
    std::vector<void*> anon;
  };
  static State& st() {
    static State s;
    return s;
  }
  static void reset() {
    State& s = st();
    std::free(s.ring);
    std::free(s.sqes);
    for (void* p : s.anon) std::free(p);
    s = State();
  }
  static unsigned roundPow2(unsigned n) {
    unsigned p = 1;
    while (p < n) p <<= 1;
    return p;
  }
  static int setup(unsigned entries, abi::io_uring_params* p) {
    State& s = st();
    if (s.setupErrno) return -s.setupErrno;
    s.sqEntries = roundPow2(entries);
    s.cqEntries = (p->flags & abi::IORING_SETUP_CQSIZE) ? roundPow2(p->cq_entries) : s.sqEntries * 2;
    // layout: sq head/tail/mask/entries/flags/dropped | cq head/tail/mask/entries/overflow | cqes | sq array
    const uint32_t cqesOff = 64;
    const uint32_t arrayOff = cqesOff + s.cqEntries * sizeof(abi::io_uring_cqe);
    s.ringSize = arrayOff + s.sqEntries * sizeof(uint32_t);
    s.ring = static_cast<uint8_t*>(std::calloc(1, s.ringSize));
    s.sqes = static_cast<abi::io_uring_sqe*>(std::calloc(s.sqEntries, sizeof(abi::io_uring_sqe)));
    auto at = [&](uint32_t off) { return reinterpret_cast<uint32_t*>(s.ring + off); };
    s.sqHead = at(0);
    s.sqTail = at(4);
    *at(8) = s.sqEntries - 1;
    *at(12) = s.sqEntries;
    s.sqFlags = at(16);
    s.cqHead = at(24);
    s.cqTail = at(28);
    *at(32) = s.cqEntries - 1;
    *at(36) = s.cqEntries;
    s.cqOverflow = at(40);
    s.cqes = reinterpret_cast<abi::io_uring_cqe*>(s.ring + cqesOff);
    s.sqArray = at(arrayOff);
    p->sq_entries = s.sqEntries;
    p->cq_entries = s.cqEntries;
    p->features = s.features;
    p->sq_off = {0, 4, 8, 12, 16, 20, arrayOff, 0, 0};
    p->cq_off = {24, 28, 32, 36, 40, cqesOff, 44, 0, 0};
    return 100;  // fd
  }
  static void post(const abi::io_uring_cqe& c) {
    State& s = st();
    const uint32_t head = loadAcquire(s.cqHead);
    const uint32_t tail = *s.cqTail;
    // The kernel keeps completion order across an overflow: while its
    // overflow list is non-empty, every new CQE joins that list even if the
    // ring has room again (io_cqe_cache_refill refuses the ring while the
    // overflow bit is set), and the list is flushed in order on the next
    // GETEVENTS. Posting straight into a freed slot here would let a newer
    // completion overtake the overflowed ones - the ordering bug the ring
    // fuzzer caught in this fake (corpus/uring/regress-cq-overflow-order.raw).
    if (tail - head >= s.cqEntries || !s.overflowed.empty()) {
      s.overflowed.push_back(c);
      (*s.cqOverflow)++;
      *s.sqFlags |= abi::IORING_SQ_CQ_OVERFLOW;
      return;
    }
    s.cqes[tail & (s.cqEntries - 1)] = c;
    storeRelease(s.cqTail, tail + 1);
  }
  static void flushOverflow() {
    State& s = st();
    while (!s.overflowed.empty()) {
      const uint32_t head = loadAcquire(s.cqHead);
      if (*s.cqTail - head >= s.cqEntries) return;
      abi::io_uring_cqe c = s.overflowed.front();
      s.overflowed.pop_front();
      s.cqes[*s.cqTail & (s.cqEntries - 1)] = c;
      storeRelease(s.cqTail, *s.cqTail + 1);
    }
    *s.sqFlags &= ~abi::IORING_SQ_CQ_OVERFLOW;
  }
  static int enter(int, unsigned toSubmit, unsigned, unsigned flags) {
    State& s = st();
    s.enterCalls++;
    const uint32_t tail = loadAcquire(s.sqTail);
    uint32_t head = *s.sqHead;
    unsigned submitted = 0;
    while (head != tail && submitted < toSubmit && submitted < s.maxSubmitPerEnter) {
      const uint32_t idx = s.sqArray[head & (s.sqEntries - 1)];
      std::vector<abi::io_uring_cqe> out;
      if (s.complete) s.complete(s.sqes[idx], out);
      for (const auto& c : out) post(c);
      head++;
      submitted++;
    }
    storeRelease(s.sqHead, head);
    if (flags & abi::IORING_ENTER_GETEVENTS) flushOverflow();
    return static_cast<int>(submitted);
  }
  static int registerOp(int, unsigned opcode, const void* arg, unsigned) {
    State& s = st();
    if (opcode == abi::IORING_REGISTER_PBUF_RING) {
      s.bufRegs.push_back(*static_cast<const abi::io_uring_buf_reg*>(arg));
      return 0;
    }
    if (opcode == abi::IORING_UNREGISTER_PBUF_RING) {
      s.bufUnregs.push_back(static_cast<const abi::io_uring_buf_reg*>(arg)->bgid);
      return 0;
    }
    return -22;
  }
  static void* map(size_t, int, uint64_t off) {
    State& s = st();
    if (off == abi::IORING_OFF_SQ_RING) return s.ring;
    if (off == abi::IORING_OFF_SQES) return s.sqes;
    return nullptr;
  }
  static void unmap(void*, size_t) {}
  static void* mapAnon(size_t len) {
    void* p = std::calloc(1, len);
    st().anon.push_back(p);
    return p;
  }
  static int closeFd(int) { return 0; }
};


}  // namespace uring
}  // namespace engine
}  // namespace moro
