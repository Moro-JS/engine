// io_uring ring management for @morojs/engine's Linux transport.
//
// Self-contained: the kernel ABI (struct layouts, flag values, opcodes,
// syscall numbers) is restated here from the Linux UAPI header
// <linux/io_uring.h> (GPL-2.0 WITH Linux-syscall-note: the note exists so
// user programs may use the interface). Restating it - as Go's syscall
// package, Rust's io-uring crate and Zig's std do - is what makes the engine
// buildable on the glibc-2.35 floor (whose 5.15 headers predate half of what
// is used here) and on Alpine's build-base (no linux/*.h at all), and keeps
// the tree free of third-party code (CONTRIBUTING.md: liburing is not
// vendored; the ring helpers below are Moro-authored).
//
// Layering:
//   abi::           - the kernel interface, verbatim layouts
//   Ring<Sys>       - one ring: mmap'd SQ/CQ, SQE hand-out, submit, reap
//   BufRing<Sys>    - one provided-buffer ring (IORING_REGISTER_PBUF_RING)
//   prep*()         - SQE builders for the six opcodes the transport uses
//   tag/untag()     - user_data = object pointer | 3-bit op tag
//   probe()         - is io_uring usable HERE (feature-based, never
//                     kernel-version-based), with a behavioural self-test
// `Sys` is the syscall surface (LinuxSys, or a FakeSys in unit tests / the
// fuzzer), so ring mechanics are tested on every OS. Everything that needs a
// real kernel is under #if defined(__linux__).
//
// Memory ordering follows the kernel's smp_load_acquire/smp_store_release
// pairs on the ring heads/tails, spelled with the __atomic builtins (libc++
// on Apple clang / Homebrew LLVM 18 lacks std::atomic_ref).
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/epoll.h>  // the probe's epoll wake self-test
#endif
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace moro {
namespace engine {
namespace uring {

// ---------------------------------------------------------------------------
// Kernel ABI (linux/io_uring.h)
// ---------------------------------------------------------------------------
namespace abi {

struct io_uring_sqe {
  uint8_t opcode;
  uint8_t flags;
  uint16_t ioprio;
  int32_t fd;
  union {
    uint64_t off;
    uint64_t addr2;
    struct {
      uint32_t cmd_op;
      uint32_t __pad1;
    };
  };
  union {
    uint64_t addr;
    uint64_t splice_off_in;
    struct {
      uint32_t level;
      uint32_t optname;
    };
  };
  uint32_t len;
  union {
    int32_t rw_flags;
    uint32_t fsync_flags;
    uint16_t poll_events;
    uint32_t poll32_events;
    uint32_t sync_range_flags;
    uint32_t msg_flags;
    uint32_t timeout_flags;
    uint32_t accept_flags;
    uint32_t cancel_flags;
    uint32_t open_flags;
    uint32_t statx_flags;
    uint32_t fadvise_advice;
    uint32_t splice_flags;
    uint32_t rename_flags;
    uint32_t unlink_flags;
    uint32_t hardlink_flags;
    uint32_t xattr_flags;
    uint32_t msg_ring_flags;
    uint32_t uring_cmd_flags;
    uint32_t waitid_flags;
    uint32_t futex_flags;
    uint32_t install_fd_flags;
    uint32_t nop_flags;
  };
  uint64_t user_data;
  union {
    uint16_t buf_index;
    uint16_t buf_group;
  } __attribute__((packed));
  uint16_t personality;
  union {
    int32_t splice_fd_in;
    uint32_t file_index;
    uint32_t optlen;
    struct {
      uint16_t addr_len;
      uint16_t __pad3[1];
    };
  };
  union {
    struct {
      uint64_t addr3;
      uint64_t __pad2[1];
    };
    uint64_t optval;
    uint8_t cmd[0];
  };
};
static_assert(sizeof(io_uring_sqe) == 64, "io_uring_sqe must be 64 bytes");

struct io_uring_cqe {
  uint64_t user_data;
  int32_t res;
  uint32_t flags;
};
static_assert(sizeof(io_uring_cqe) == 16, "io_uring_cqe must be 16 bytes");

struct io_sqring_offsets {
  uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
  uint64_t user_addr;
};
struct io_cqring_offsets {
  uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
  uint64_t user_addr;
};
struct io_uring_params {
  uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd;
  uint32_t resv[3];
  io_sqring_offsets sq_off;
  io_cqring_offsets cq_off;
};

struct io_uring_buf {
  uint64_t addr;
  uint32_t len;
  uint16_t bid;
  uint16_t resv;
};
static_assert(sizeof(io_uring_buf) == 16, "io_uring_buf must be 16 bytes");
// The ring header aliases the first io_uring_buf slot; `tail` sits where that
// slot's `resv` would be.
struct io_uring_buf_ring {
  union {
    struct {
      uint64_t resv1;
      uint32_t resv2;
      uint16_t resv3;
      uint16_t tail;
    };
    io_uring_buf bufs[1];
  };
};
struct io_uring_buf_reg {
  uint64_t ring_addr;
  uint32_t ring_entries;
  uint16_t bgid;
  uint16_t flags;
  uint64_t resv[3];
};
struct io_uring_probe_op {
  uint8_t op;
  uint8_t resv;
  uint16_t flags;  // IO_URING_OP_SUPPORTED = 1
  uint32_t resv2;
};
struct io_uring_probe {
  uint8_t last_op;
  uint8_t ops_len;
  uint16_t resv;
  uint32_t resv2[3];
  io_uring_probe_op ops[];
};

// setup flags
enum : uint32_t {
  IORING_SETUP_IOPOLL = 1u << 0,
  IORING_SETUP_SQPOLL = 1u << 1,
  IORING_SETUP_SQ_AFF = 1u << 2,
  IORING_SETUP_CQSIZE = 1u << 3,
  IORING_SETUP_CLAMP = 1u << 4,
  IORING_SETUP_ATTACH_WQ = 1u << 5,
  IORING_SETUP_R_DISABLED = 1u << 6,
  IORING_SETUP_SUBMIT_ALL = 1u << 7,
  IORING_SETUP_COOP_TASKRUN = 1u << 8,
  IORING_SETUP_TASKRUN_FLAG = 1u << 9,
  IORING_SETUP_SQE128 = 1u << 10,
  IORING_SETUP_CQE32 = 1u << 11,
  IORING_SETUP_SINGLE_ISSUER = 1u << 12,
  IORING_SETUP_DEFER_TASKRUN = 1u << 13,
};
// features (io_uring_params.features)
enum : uint32_t {
  IORING_FEAT_SINGLE_MMAP = 1u << 0,
  IORING_FEAT_NODROP = 1u << 1,
  IORING_FEAT_SUBMIT_STABLE = 1u << 2,
  IORING_FEAT_RW_CUR_POS = 1u << 3,
  IORING_FEAT_CUR_PERSONALITY = 1u << 4,
  IORING_FEAT_FAST_POLL = 1u << 5,
  IORING_FEAT_POLL_32BITS = 1u << 6,
  IORING_FEAT_SQPOLL_NONFIXED = 1u << 7,
  IORING_FEAT_EXT_ARG = 1u << 8,
  IORING_FEAT_NATIVE_WORKERS = 1u << 9,
  IORING_FEAT_RSRC_TAGS = 1u << 10,
  IORING_FEAT_CQE_SKIP = 1u << 11,
  IORING_FEAT_LINKED_FILE = 1u << 12,
};
// sq ring flags (kernel -> user)
enum : uint32_t {
  IORING_SQ_NEED_WAKEUP = 1u << 0,
  IORING_SQ_CQ_OVERFLOW = 1u << 1,
  IORING_SQ_TASKRUN = 1u << 2,
};
// enter flags
enum : uint32_t {
  IORING_ENTER_GETEVENTS = 1u << 0,
  IORING_ENTER_SQ_WAKEUP = 1u << 1,
  IORING_ENTER_SQ_WAIT = 1u << 2,
  IORING_ENTER_EXT_ARG = 1u << 3,
};
// sqe flags
enum : uint8_t {
  IOSQE_FIXED_FILE = 1u << 0,
  IOSQE_IO_DRAIN = 1u << 1,
  IOSQE_IO_LINK = 1u << 2,
  IOSQE_IO_HARDLINK = 1u << 3,
  IOSQE_ASYNC = 1u << 4,
  IOSQE_BUFFER_SELECT = 1u << 5,
  IOSQE_CQE_SKIP_SUCCESS = 1u << 6,
};
// cqe flags
enum : uint32_t {
  IORING_CQE_F_BUFFER = 1u << 0,
  IORING_CQE_F_MORE = 1u << 1,
  IORING_CQE_F_SOCK_NONEMPTY = 1u << 2,
  IORING_CQE_F_NOTIF = 1u << 3,
  IORING_CQE_BUFFER_SHIFT = 16,
};
// opcodes
enum : uint8_t {
  IORING_OP_NOP = 0,
  IORING_OP_ACCEPT = 13,
  IORING_OP_ASYNC_CANCEL = 14,
  IORING_OP_CLOSE = 19,
  IORING_OP_SHUTDOWN = 34,
  IORING_OP_SEND = 26,
  IORING_OP_RECV = 27,
};
// ioprio bits for accept / recv
enum : uint16_t {
  IORING_ACCEPT_MULTISHOT = 1u << 0,
  IORING_RECVSEND_POLL_FIRST = 1u << 0,
  IORING_RECV_MULTISHOT = 1u << 1,
};
// cancel flags
enum : uint32_t {
  IORING_ASYNC_CANCEL_ALL = 1u << 0,
  IORING_ASYNC_CANCEL_FD = 1u << 1,
  IORING_ASYNC_CANCEL_ANY = 1u << 2,
};
// register opcodes
enum : unsigned {
  IORING_REGISTER_PROBE = 8,
  IORING_REGISTER_PBUF_RING = 22,
  IORING_UNREGISTER_PBUF_RING = 23,
};
enum : uint16_t { IO_URING_OP_SUPPORTED = 1u << 0 };
// mmap offsets
enum : uint64_t {
  IORING_OFF_SQ_RING = 0ULL,
  IORING_OFF_CQ_RING = 0x8000000ULL,
  IORING_OFF_SQES = 0x10000000ULL,
};

}  // namespace abi

inline uint32_t loadAcquire(const uint32_t* p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
inline void storeRelease(uint32_t* p, uint32_t v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
inline uint16_t loadAcquire16(const uint16_t* p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
inline void storeRelease16(uint16_t* p, uint16_t v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }

// ---------------------------------------------------------------------------
// Syscall surface
// ---------------------------------------------------------------------------
#if defined(__linux__)
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_register
#define SYS_io_uring_register 427
#endif

struct LinuxSys {
  static int setup(unsigned entries, abi::io_uring_params* p) {
    int r = static_cast<int>(::syscall(SYS_io_uring_setup, entries, p));
    return r < 0 ? -errno : r;
  }
  static int enter(int fd, unsigned toSubmit, unsigned minComplete, unsigned flags) {
    int r = static_cast<int>(::syscall(SYS_io_uring_enter, fd, toSubmit, minComplete, flags, nullptr, 0));
    return r < 0 ? -errno : r;
  }
  static int registerOp(int fd, unsigned opcode, const void* arg, unsigned nrArgs) {
    int r = static_cast<int>(::syscall(SYS_io_uring_register, fd, opcode, arg, nrArgs));
    return r < 0 ? -errno : r;
  }
  static void* map(size_t len, int fd, uint64_t off) {
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                     static_cast<off_t>(off));
    return p == MAP_FAILED ? nullptr : p;
  }
  static void unmap(void* p, size_t len) { ::munmap(p, len); }
  static void* mapAnon(size_t len) {
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? nullptr : p;
  }
  static int closeFd(int fd) { return ::close(fd) < 0 ? -errno : 0; }
};
#endif

// ---------------------------------------------------------------------------
// Ring
// ---------------------------------------------------------------------------
template <class Sys>
class Ring {
 public:
  Ring() = default;
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;
  ~Ring() { close(); }

  // Returns 0, or -errno from io_uring_setup / mmap. `flags` are the
  // IORING_SETUP_* bits; cqEntries is honoured with IORING_SETUP_CQSIZE.
  int open(unsigned entries, uint32_t flags, unsigned cqEntries = 0) {
    abi::io_uring_params p;
    std::memset(&p, 0, sizeof(p));
    p.flags = flags;
    if (cqEntries) {
      p.flags |= abi::IORING_SETUP_CQSIZE;
      p.cq_entries = cqEntries;
    }
    int fd = Sys::setup(entries, &p);
    if (fd < 0) return fd;
    if (!(p.features & abi::IORING_FEAT_SINGLE_MMAP)) {
      // Every kernel with the opcodes this transport needs has it (5.4+);
      // treat its absence as "not usable" rather than carry a second mmap.
      Sys::closeFd(fd);
      return -95;  // EOPNOTSUPP
    }
    const size_t sqSize = p.sq_off.array + static_cast<size_t>(p.sq_entries) * sizeof(uint32_t);
    const size_t cqSize = p.cq_off.cqes + static_cast<size_t>(p.cq_entries) * sizeof(abi::io_uring_cqe);
    ringSize_ = sqSize > cqSize ? sqSize : cqSize;
    ring_ = static_cast<uint8_t*>(Sys::map(ringSize_, fd, abi::IORING_OFF_SQ_RING));
    if (!ring_) {
      Sys::closeFd(fd);
      return -12;  // ENOMEM
    }
    sqesSize_ = static_cast<size_t>(p.sq_entries) * sizeof(abi::io_uring_sqe);
    sqes_ = static_cast<abi::io_uring_sqe*>(Sys::map(sqesSize_, fd, abi::IORING_OFF_SQES));
    if (!sqes_) {
      Sys::unmap(ring_, ringSize_);
      ring_ = nullptr;
      Sys::closeFd(fd);
      return -12;
    }
    fd_ = fd;
    features_ = p.features;
    setupFlags_ = p.flags;
    sqHead_ = reinterpret_cast<uint32_t*>(ring_ + p.sq_off.head);
    sqTail_ = reinterpret_cast<uint32_t*>(ring_ + p.sq_off.tail);
    sqMask_ = *reinterpret_cast<uint32_t*>(ring_ + p.sq_off.ring_mask);
    sqEntries_ = *reinterpret_cast<uint32_t*>(ring_ + p.sq_off.ring_entries);
    sqFlags_ = reinterpret_cast<uint32_t*>(ring_ + p.sq_off.flags);
    sqDropped_ = reinterpret_cast<uint32_t*>(ring_ + p.sq_off.dropped);
    sqArray_ = reinterpret_cast<uint32_t*>(ring_ + p.sq_off.array);
    cqHead_ = reinterpret_cast<uint32_t*>(ring_ + p.cq_off.head);
    cqTail_ = reinterpret_cast<uint32_t*>(ring_ + p.cq_off.tail);
    cqMask_ = *reinterpret_cast<uint32_t*>(ring_ + p.cq_off.ring_mask);
    cqEntries_ = *reinterpret_cast<uint32_t*>(ring_ + p.cq_off.ring_entries);
    cqOverflow_ = reinterpret_cast<uint32_t*>(ring_ + p.cq_off.overflow);
    cqes_ = reinterpret_cast<abi::io_uring_cqe*>(ring_ + p.cq_off.cqes);
    localTail_ = *sqTail_;
    submitted_ = localTail_;
    return 0;
  }

  void close() {
    if (fd_ < 0) return;
    if (sqes_) Sys::unmap(sqes_, sqesSize_);
    if (ring_) Sys::unmap(ring_, ringSize_);
    Sys::closeFd(fd_);
    fd_ = -1;
    ring_ = nullptr;
    sqes_ = nullptr;
  }

  bool isOpen() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  uint32_t features() const { return features_; }
  uint32_t setupFlags() const { return setupFlags_; }
  unsigned sqEntries() const { return sqEntries_; }
  unsigned cqEntries() const { return cqEntries_; }

  // The next free SQE (zeroed), or nullptr when the submission ring is full -
  // the caller then enter()s and retries. Never drops an SQE.
  abi::io_uring_sqe* sqe() {
    const uint32_t head = loadAcquire(sqHead_);
    if (localTail_ - head >= sqEntries_) return nullptr;
    const uint32_t idx = localTail_ & sqMask_;
    abi::io_uring_sqe* e = &sqes_[idx];
    std::memset(e, 0, sizeof(*e));
    sqArray_[idx] = idx;
    localTail_++;
    return e;
  }

  // SQEs written since the last enter().
  unsigned pending() const { return localTail_ - submitted_; }

  // Publish pending SQEs and call io_uring_enter. Returns the number the
  // kernel consumed (>= 0) or -errno. With GETEVENTS it also waits for
  // minComplete completions / runs deferred task work.
  int enter(unsigned minComplete, uint32_t flags) {
    const unsigned toSubmit = pending();
    if (toSubmit) storeRelease(sqTail_, localTail_);
    int r = Sys::enter(fd_, toSubmit, minComplete, flags);
    if (r < 0) return r;
    submitted_ += static_cast<uint32_t>(r) <= toSubmit ? static_cast<uint32_t>(r) : toSubmit;
    return r;
  }

  // Reap every completion currently posted, in order. Releases the CQ head
  // once at the end (the kernel may reuse the slots from then on), so a
  // callback must copy what it needs before returning.
  template <class F>
  unsigned forEachCqe(F&& f) {
    uint32_t head = *cqHead_;
    const uint32_t tail = loadAcquire(cqTail_);
    unsigned n = 0;
    while (head != tail) {
      f(cqes_[head & cqMask_]);
      head++;
      n++;
    }
    if (n) storeRelease(cqHead_, head);
    return n;
  }

  unsigned cqReady() const { return loadAcquire(cqTail_) - *cqHead_; }
  uint32_t sqFlags() const { return loadAcquire(sqFlags_); }
  uint32_t sqDropped() const { return loadAcquire(sqDropped_); }
  uint32_t cqOverflow() const { return loadAcquire(cqOverflow_); }
  bool cqOverflowed() const { return (sqFlags() & abi::IORING_SQ_CQ_OVERFLOW) != 0; }
  bool taskWorkPending() const { return (sqFlags() & abi::IORING_SQ_TASKRUN) != 0; }

 private:
  int fd_ = -1;
  uint8_t* ring_ = nullptr;
  size_t ringSize_ = 0;
  abi::io_uring_sqe* sqes_ = nullptr;
  size_t sqesSize_ = 0;
  uint32_t features_ = 0;
  uint32_t setupFlags_ = 0;
  uint32_t* sqHead_ = nullptr;
  uint32_t* sqTail_ = nullptr;
  uint32_t sqMask_ = 0;
  uint32_t sqEntries_ = 0;
  uint32_t* sqFlags_ = nullptr;
  uint32_t* sqDropped_ = nullptr;
  uint32_t* sqArray_ = nullptr;
  uint32_t* cqHead_ = nullptr;
  uint32_t* cqTail_ = nullptr;
  uint32_t cqMask_ = 0;
  uint32_t cqEntries_ = 0;
  uint32_t* cqOverflow_ = nullptr;
  abi::io_uring_cqe* cqes_ = nullptr;
  uint32_t localTail_ = 0;
  uint32_t submitted_ = 0;
};

// ---------------------------------------------------------------------------
// Provided-buffer ring (IORING_REGISTER_PBUF_RING)
// ---------------------------------------------------------------------------
// One anonymous mapping holds the ring header (count entries of io_uring_buf)
// followed by the buffers themselves; pages become resident only as the
// kernel fills them. A buffer leaves the ring when a recv completes into it
// (bid in the CQE flags) and returns with recycle() once the bytes have been
// consumed - the transport parses straight out of it, so that is right after
// dispatch.
template <class Sys>
class BufRing {
 public:
  BufRing() = default;
  BufRing(const BufRing&) = delete;
  BufRing& operator=(const BufRing&) = delete;

  // count must be a power of two <= 32768; returns 0 or -errno.
  int init(Ring<Sys>& ring, uint16_t bgid, unsigned count, unsigned bufSize) {
    if (count == 0 || (count & (count - 1)) || count > 32768) return -22;  // EINVAL
    headerSize_ = static_cast<size_t>(count) * sizeof(abi::io_uring_buf);
    bufSize_ = bufSize;
    count_ = count;
    mask_ = count - 1;
    mapSize_ = headerSize_ + static_cast<size_t>(count) * bufSize;
    mem_ = static_cast<uint8_t*>(Sys::mapAnon(mapSize_));
    if (!mem_) return -12;
    header_ = reinterpret_cast<abi::io_uring_buf_ring*>(mem_);
    abi::io_uring_buf_reg reg;
    std::memset(&reg, 0, sizeof(reg));
    reg.ring_addr = reinterpret_cast<uint64_t>(mem_);
    reg.ring_entries = count;
    reg.bgid = bgid;
    int r = Sys::registerOp(ring.fd(), abi::IORING_REGISTER_PBUF_RING, &reg, 1);
    if (r < 0) {
      Sys::unmap(mem_, mapSize_);
      mem_ = nullptr;
      return r;
    }
    bgid_ = bgid;
    registered_ = true;
    // Hand every buffer to the kernel.
    for (unsigned i = 0; i < count; i++) push(static_cast<uint16_t>(i));
    publish();
    return 0;
  }

  void destroy(Ring<Sys>& ring) {
    if (registered_) {
      abi::io_uring_buf_reg reg;
      std::memset(&reg, 0, sizeof(reg));
      reg.bgid = bgid_;
      Sys::registerOp(ring.fd(), abi::IORING_UNREGISTER_PBUF_RING, &reg, 1);
      registered_ = false;
    }
    if (mem_) {
      Sys::unmap(mem_, mapSize_);
      mem_ = nullptr;
    }
  }

  uint16_t bgid() const { return bgid_; }
  unsigned count() const { return count_; }
  unsigned bufSize() const { return bufSize_; }
  uint8_t* at(uint16_t bid) { return mem_ + headerSize_ + static_cast<size_t>(bid) * bufSize_; }
  const uint8_t* at(uint16_t bid) const { return mem_ + headerSize_ + static_cast<size_t>(bid) * bufSize_; }

  // Return one buffer to the kernel. Batched: push() several, then publish().
  void push(uint16_t bid) {
    abi::io_uring_buf* b = &header_->bufs[(localTail_ + pushed_) & mask_];
    b->addr = reinterpret_cast<uint64_t>(at(bid));
    b->len = bufSize_;
    b->bid = bid;
    pushed_++;
  }
  void publish() {
    if (!pushed_) return;
    localTail_ = static_cast<uint16_t>(localTail_ + pushed_);
    pushed_ = 0;
    storeRelease16(&header_->tail, localTail_);
  }
  void recycle(uint16_t bid) {
    push(bid);
    publish();
  }
  uint16_t tail() const { return localTail_; }

 private:
  uint8_t* mem_ = nullptr;
  size_t mapSize_ = 0;
  size_t headerSize_ = 0;
  abi::io_uring_buf_ring* header_ = nullptr;
  unsigned bufSize_ = 0;
  unsigned count_ = 0;
  unsigned mask_ = 0;
  uint16_t bgid_ = 0;
  uint16_t localTail_ = 0;
  unsigned pushed_ = 0;
  bool registered_ = false;
};

// ---------------------------------------------------------------------------
// SQE builders
// ---------------------------------------------------------------------------
inline void prepNop(abi::io_uring_sqe* s) { s->opcode = abi::IORING_OP_NOP; s->fd = -1; }

inline void prepAccept(abi::io_uring_sqe* s, int listenFd, uint32_t acceptFlags, bool multishot) {
  s->opcode = abi::IORING_OP_ACCEPT;
  s->fd = listenFd;
  s->accept_flags = acceptFlags;
  if (multishot) s->ioprio |= abi::IORING_ACCEPT_MULTISHOT;
}

inline void prepRecv(abi::io_uring_sqe* s, int fd, uint16_t bgid, bool multishot) {
  s->opcode = abi::IORING_OP_RECV;
  s->fd = fd;
  s->flags |= abi::IOSQE_BUFFER_SELECT;
  s->buf_group = bgid;
  s->len = 0;  // the selected buffer's own length
  if (multishot) s->ioprio |= abi::IORING_RECV_MULTISHOT;
}

inline void prepSend(abi::io_uring_sqe* s, int fd, const void* data, uint32_t len, uint32_t msgFlags) {
  s->opcode = abi::IORING_OP_SEND;
  s->fd = fd;
  s->addr = reinterpret_cast<uint64_t>(data);
  s->len = len;
  s->msg_flags = msgFlags;
}

inline void prepCancelFd(abi::io_uring_sqe* s, int fd) {
  s->opcode = abi::IORING_OP_ASYNC_CANCEL;
  s->fd = fd;
  s->cancel_flags = abi::IORING_ASYNC_CANCEL_FD | abi::IORING_ASYNC_CANCEL_ALL;
}

inline void prepClose(abi::io_uring_sqe* s, int fd) {
  s->opcode = abi::IORING_OP_CLOSE;
  s->fd = fd;
}

// shutdown(fd, how): `how` travels in sqe->len. NOT used on the transport's
// close path (the kernel never issues SHUTDOWN inline; it is punted to an
// io-wq worker, which is exactly the delay a close-race fix cannot afford -
// see Server::uringCloseConn); kept for the builders' unit coverage.
inline void prepShutdown(abi::io_uring_sqe* s, int fd, int how) {
  s->opcode = abi::IORING_OP_SHUTDOWN;
  s->fd = fd;
  s->len = static_cast<uint32_t>(how);
}

// ---------------------------------------------------------------------------
// user_data tagging: pointer | 3-bit tag (objects are new'd, >= 8-aligned)
// ---------------------------------------------------------------------------
enum Tag : unsigned {
  kTagRecv = 0,
  kTagSend = 1,
  kTagCancel = 2,
  kTagClose = 3,
  kTagAccept = 4,
  kTagListenerCancel = 5,
  kTagListenerClose = 6,
  kTagNop = 7,
};
inline uint64_t tag(const void* p, Tag t) {
  return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p)) | static_cast<uint64_t>(t);
}
inline Tag tagOf(uint64_t ud) { return static_cast<Tag>(ud & 7u); }
inline void* ptrOf(uint64_t ud) { return reinterpret_cast<void*>(static_cast<uintptr_t>(ud & ~static_cast<uint64_t>(7u))); }
inline uint16_t bufferId(const abi::io_uring_cqe& c) { return static_cast<uint16_t>(c.flags >> abi::IORING_CQE_BUFFER_SHIFT); }
inline bool hasBuffer(const abi::io_uring_cqe& c) { return (c.flags & abi::IORING_CQE_F_BUFFER) != 0; }
inline bool hasMore(const abi::io_uring_cqe& c) { return (c.flags & abi::IORING_CQE_F_MORE) != 0; }

// ---------------------------------------------------------------------------
// Per-connection transport state (lives in Connection's transport union)
// ---------------------------------------------------------------------------
// Trivially constructible on purpose: it is one arm of an anonymous union
// next to uv_tcp_t, and the Connection is value-initialised (zeroed).
struct UringConn {
  int fd;               // the accepted socket (owned; closed through the ring)
  uint8_t state;        // 0 idle, 1 reading, 2 closing (cancel+close issued), 3 closed
  bool sendInflight;    // one SEND SQE outstanding (the head WriteReq)
  bool recvArmed;       // a multishot RECV SQE is outstanding
  bool eofSeen;         // EOF/error already routed once
  uint32_t inflight;    // SQEs referencing this connection not yet completed
  size_t pendingBytes;  // queued write bytes the kernel has not accepted
  void* wqHead;         // WriteReq* queue (intrusive, FIFO)
  void* wqTail;
};

// ---------------------------------------------------------------------------
// The one ring mode the transport runs
// ---------------------------------------------------------------------------
// Mandatory: one issuer (SINGLE_ISSUER), task work run cooperatively at our
// own kernel transitions instead of by interrupting the JS thread
// (COOP_TASKRUN), a TASKRUN flag so the reap loop knows when an enter is
// needed, submit-everything-or-fail semantics (SUBMIT_ALL), an explicit CQ
// size. A kernel that rejects this set is a kernel without the multishot
// recv fixes the design relies on: it falls back to libuv. No degraded modes.
//
// NOT DEFER_TASKRUN, deliberately: with it the kernel queues a completion as
// local task work WITHOUT waking the ring fd's wait queue, so an epoll-driven
// loop (libuv's uv_poll) never learns about it - the CQE materialises only
// inside an explicit io_uring_enter. Measured on 6.12: epoll never wakes
// under DEFER_TASKRUN; under COOP_TASKRUN it wakes with the CQE already
// posted. (An eventfd would work around it at one extra read per wake.)
constexpr uint32_t kSetupFlags = abi::IORING_SETUP_SINGLE_ISSUER | abi::IORING_SETUP_COOP_TASKRUN |
                                 abi::IORING_SETUP_TASKRUN_FLAG | abi::IORING_SETUP_SUBMIT_ALL |
                                 abi::IORING_SETUP_CLAMP;
constexpr unsigned kSqEntries = 1024;
constexpr unsigned kCqEntries = 4096;
constexpr uint32_t kRequiredFeatures = abi::IORING_FEAT_SINGLE_MMAP | abi::IORING_FEAT_NODROP |
                                       abi::IORING_FEAT_SUBMIT_STABLE | abi::IORING_FEAT_FAST_POLL;
constexpr unsigned kBufSize = 16 * 1024;
constexpr unsigned kBufCount = 512;
constexpr uint16_t kBufGroup = 0;

struct ProbeResult {
  bool ok;
  const char* reason;  // static string; "ok" when usable
};

#if defined(__linux__)
// Is io_uring usable HERE? Feature-based, not version-based: the exact
// setup flags, features, opcodes and provided-buffer registration the
// transport needs, then a behavioural self-test on a socketpair proving that
// a multishot recv posts a completion and an EPOLL on the ring fd wakes for
// it WITHOUT a prior enter (exactly what libuv's uv_poll relies on; plain
// poll() would re-evaluate readiness at call time and hide a missing wake).
// EPERM (Docker's default seccomp, io_uring_disabled=2), ENOSYS (gVisor, old
// kernels) and EINVAL (< 6.1) all mean "use libuv".
inline ProbeResult probe() {
  Ring<LinuxSys> ring;
  int r = ring.open(8, kSetupFlags, 32);
  if (r == -1) return {false, "io_uring_setup: EPERM (seccomp or io_uring_disabled)"};
  if (r == -38) return {false, "io_uring_setup: ENOSYS (no io_uring)"};
  if (r == -22) return {false, "io_uring_setup: EINVAL (kernel < 6.1: setup flags unsupported)"};
  if (r < 0) return {false, "io_uring_setup failed"};
  if ((ring.features() & kRequiredFeatures) != kRequiredFeatures) return {false, "missing io_uring features"};

  // Opcode probe.
  alignas(8) uint8_t buf[sizeof(abi::io_uring_probe) + 256 * sizeof(abi::io_uring_probe_op)];
  std::memset(buf, 0, sizeof(buf));
  auto* pr = reinterpret_cast<abi::io_uring_probe*>(buf);
  if (LinuxSys::registerOp(ring.fd(), abi::IORING_REGISTER_PROBE, pr, 256) < 0) return {false, "IORING_REGISTER_PROBE failed"};
  for (uint8_t op : {abi::IORING_OP_NOP, abi::IORING_OP_ACCEPT, abi::IORING_OP_RECV, abi::IORING_OP_SEND,
                     abi::IORING_OP_ASYNC_CANCEL, abi::IORING_OP_CLOSE}) {
    if (op > pr->last_op || !(pr->ops[op].flags & abi::IO_URING_OP_SUPPORTED)) return {false, "required opcode unsupported"};
  }

  // Provided-buffer ring + multishot recv self-test on a socketpair.
  BufRing<LinuxSys> bufs;
  if (bufs.init(ring, kBufGroup, 16, 256) < 0) return {false, "IORING_REGISTER_PBUF_RING unsupported"};
  int sv[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0) {
    bufs.destroy(ring);
    return {false, "socketpair failed"};
  }
  ProbeResult result{false, "self-test failed"};
  do {
    abi::io_uring_sqe* s = ring.sqe();
    if (!s) break;
    prepRecv(s, sv[0], kBufGroup, true);
    s->user_data = 1;
    if (ring.enter(0, 0) < 0) {
      result.reason = "io_uring_enter failed";
      break;
    }
    // Register the ring fd with epoll BEFORE the data arrives, then require
    // a wake-up: the exact contract uv_poll depends on.
    int ep = ::epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
      result.reason = "epoll_create1 failed";
      break;
    }
    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = ring.fd();
    if (::epoll_ctl(ep, EPOLL_CTL_ADD, ring.fd(), &ev) < 0) {
      ::close(ep);
      result.reason = "epoll_ctl failed";
      break;
    }
    if (::write(sv[1], "x", 1) != 1) {
      ::close(ep);
      break;
    }
    struct epoll_event out;
    int woke = ::epoll_wait(ep, &out, 1, 500);
    if (woke < 0 && errno == EINTR) woke = ::epoll_wait(ep, &out, 1, 500);
    ::close(ep);
    if (woke <= 0 || !(out.events & EPOLLIN)) {
      result.reason = "ring fd did not wake epoll after a completion";
      break;
    }
    // Run task work, reap.
    if (ring.enter(0, abi::IORING_ENTER_GETEVENTS) < 0) break;
    bool got = false;
    bool multishotOk = false;
    ring.forEachCqe([&](const abi::io_uring_cqe& c) {
      if (c.user_data == 1 && c.res == 1 && hasBuffer(c)) {
        got = true;
        multishotOk = hasMore(c);
        bufs.recycle(bufferId(c));
      }
    });
    if (!got) {
      result.reason = "multishot recv did not complete";
      break;
    }
    if (!multishotOk) {
      result.reason = "multishot recv unsupported (no F_MORE)";
      break;
    }
    // Cancel + close: both must complete.
    s = ring.sqe();
    prepCancelFd(s, sv[0]);
    s->user_data = 2;
    s = ring.sqe();
    prepClose(s, sv[0]);
    s->user_data = 3;
    if (ring.enter(2, abi::IORING_ENTER_GETEVENTS) < 0) break;
    unsigned seen = 0;
    for (int spin = 0; spin < 10 && seen < 3; spin++) {
      ring.forEachCqe([&](const abi::io_uring_cqe& c) {
        if (c.user_data == 1 || c.user_data == 2 || c.user_data == 3) seen++;
      });
      if (seen < 3 && ring.enter(1, abi::IORING_ENTER_GETEVENTS) < 0) break;
    }
    if (seen < 3) {
      result.reason = "cancel/close completions missing";
      break;
    }
    sv[0] = -1;  // closed by the ring
    result = {true, "ok"};
  } while (false);
  if (sv[0] >= 0) ::close(sv[0]);
  ::close(sv[1]);
  bufs.destroy(ring);
  return result;
}
#else
inline ProbeResult probe() { return {false, "platform"}; }
#endif

}  // namespace uring
}  // namespace engine
}  // namespace moro
