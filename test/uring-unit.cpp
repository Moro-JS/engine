// Real-kernel unit test for src/uring.h (Linux only). Where io_uring is
// unavailable (seccomp, gVisor, kernel < 6.1) probe() says so and the test
// exits 0 with the reason printed - the fake-kernel unit covers the ring
// mechanics everywhere, this one proves the ABI restatement and the probe's
// self-test against the kernel that will actually run the transport.
//
//   - probe() -> ok (or a specific reason)
//   - a ring opens with the transport's mandatory flags, features present
//   - provided-buffer ring: register, all buffers handed out, recycle
//   - socketpair: multishot recv posts F_BUFFER|F_MORE completions with the
//     bytes in the selected buffer; send completes with the byte count; a
//     partial send (tiny SO_SNDBUF, peer not reading) completes short;
//     cancel(fd) + close(fd) both complete and the recv ends with -ECANCELED
//   - the ring fd is pollable when work is pending, not when idle
#include <cstdio>
#include <cstring>
#include <string>

#include "../src/uring.h"

#if !defined(__linux__)
int main() {
  std::printf("io_uring real-kernel unit: not Linux - skipped\n");
  return 0;
}
#else
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

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

// Reap until `want` CQEs with a given user_data tag prefix arrive (bounded).
template <class F>
static unsigned reapUntil(Ring<LinuxSys>& ring, unsigned want, F&& f) {
  unsigned got = 0;
  for (int spin = 0; spin < 50 && got < want; spin++) {
    ring.enter(got < want ? 1 : 0, abi::IORING_ENTER_GETEVENTS);
    ring.forEachCqe([&](const abi::io_uring_cqe& c) {
      f(c);
      got++;
    });
  }
  return got;
}

int main() {
  ProbeResult pr = probe();
  std::printf("probe: %s (%s)\n", pr.ok ? "ok" : "not usable", pr.reason);
  if (!pr.ok) {
    if (std::getenv("MORO_ENGINE_REQUIRE_TRANSPORT") && std::strcmp(std::getenv("MORO_ENGINE_REQUIRE_TRANSPORT"), "uring") == 0) {
      std::fprintf(stderr, "MORO_ENGINE_REQUIRE_TRANSPORT=uring but io_uring is not usable here: %s\n", pr.reason);
      return 1;
    }
    std::printf("io_uring real-kernel unit: skipped (%s)\n", pr.reason);
    return 0;
  }

  Ring<LinuxSys> ring;
  CHECK(ring.open(kSqEntries, kSetupFlags, kCqEntries) == 0);
  CHECK(ring.sqEntries() == kSqEntries);
  CHECK(ring.cqEntries() == kCqEntries);
  CHECK((ring.features() & kRequiredFeatures) == kRequiredFeatures);
  CHECK((ring.setupFlags() & abi::IORING_SETUP_COOP_TASKRUN) != 0);
  CHECK((ring.setupFlags() & abi::IORING_SETUP_DEFER_TASKRUN) == 0);  // see kSetupFlags: epoll never wakes under DEFER_TASKRUN

  // Idle ring: not readable.
  {
    struct pollfd pfd = {ring.fd(), POLLIN, 0};
    CHECK(::poll(&pfd, 1, 0) == 0);
  }

  BufRing<LinuxSys> bufs;
  CHECK(bufs.init(ring, kBufGroup, 16, 1024) == 0);
  CHECK(bufs.tail() == 16);

  int sv[2];
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) == 0);
  alignas(8) static char recvTag, sendTag, cancelTag, closeTag;

  // Multishot recv on sv[0]; write two messages from sv[1]; expect two
  // F_BUFFER|F_MORE completions carrying the bytes.
  abi::io_uring_sqe* s = ring.sqe();
  CHECK(s != nullptr);
  prepRecv(s, sv[0], kBufGroup, true);
  s->user_data = tag(&recvTag, kTagRecv);
  CHECK(ring.enter(0, 0) == 1);
  CHECK(::write(sv[1], "hello", 5) == 5);
  {
    struct pollfd pfd = {ring.fd(), POLLIN, 0};
    CHECK(::poll(&pfd, 1, 1000) == 1 && (pfd.revents & POLLIN));
  }
  std::string payload;
  unsigned recvCqes = 0;
  reapUntil(ring, 1, [&](const abi::io_uring_cqe& c) {
    if (tagOf(c.user_data) == kTagRecv) {
      recvCqes++;
      CHECK(c.res == 5);
      CHECK(hasBuffer(c) && hasMore(c));
      payload.assign(reinterpret_cast<const char*>(bufs.at(bufferId(c))), static_cast<size_t>(c.res));
      bufs.recycle(bufferId(c));
    }
  });
  CHECK(recvCqes == 1);
  CHECK(payload == "hello");
  CHECK(::write(sv[1], "world!", 6) == 6);
  payload.clear();
  reapUntil(ring, 1, [&](const abi::io_uring_cqe& c) {
    if (tagOf(c.user_data) == kTagRecv && c.res > 0) {
      payload.assign(reinterpret_cast<const char*>(bufs.at(bufferId(c))), static_cast<size_t>(c.res));
      bufs.recycle(bufferId(c));
    }
  });
  CHECK(payload == "world!");

  // Send from sv[0] to sv[1]: full completion with the byte count.
  const char msg[] = "pong";
  s = ring.sqe();
  prepSend(s, sv[0], msg, 4, MSG_NOSIGNAL);
  s->user_data = tag(&sendTag, kTagSend);
  int sendRes = 0;
  reapUntil(ring, 1, [&](const abi::io_uring_cqe& c) {
    if (tagOf(c.user_data) == kTagSend) sendRes = c.res;
  });
  CHECK(sendRes == 4);
  char rbuf[8] = {0};
  CHECK(::read(sv[1], rbuf, sizeof(rbuf)) == 4 && std::memcmp(rbuf, "pong", 4) == 0);

  // TCP_NODELAY set on a listener is inherited by the accepted socket - the
  // transport relies on it (Server::uringListen) instead of a setsockopt per
  // accept.
  {
    int lfd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int on = 1;
    ::setsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    CHECK(::bind(lfd, reinterpret_cast<sockaddr*>(&la), sizeof(la)) == 0);
    CHECK(::listen(lfd, 8) == 0);
    socklen_t ll = sizeof(la);
    ::getsockname(lfd, reinterpret_cast<sockaddr*>(&la), &ll);
    int cfd = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(::connect(cfd, reinterpret_cast<sockaddr*>(&la), sizeof(la)) == 0);
    int afd = -1;
    for (int spin = 0; spin < 1000 && afd < 0; spin++) {
      afd = ::accept4(lfd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (afd < 0) usleep(1000);
    }
    CHECK(afd >= 0);
    int val = 0;
    socklen_t vl = sizeof(val);
    CHECK(::getsockopt(afd, IPPROTO_TCP, TCP_NODELAY, &val, &vl) == 0);
    CHECK(val != 0);  // inherited
    ::close(afd);
    ::close(cfd);
    ::close(lfd);
  }

  // Partial send: shrink the peer's buffers, never read, push more than fits.
  {
    int tiny = 4096;
    ::setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &tiny, sizeof(tiny));
    ::setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &tiny, sizeof(tiny));
    static char big[1 << 20];
    std::memset(big, 'x', sizeof(big));
    s = ring.sqe();
    prepSend(s, sv[0], big, sizeof(big), MSG_NOSIGNAL);
    s->user_data = tag(&sendTag, kTagSend);
    int partial = -1;
    reapUntil(ring, 1, [&](const abi::io_uring_cqe& c) {
      if (tagOf(c.user_data) == kTagSend) partial = c.res;
    });
    CHECK(partial > 0 && partial < static_cast<int>(sizeof(big)));  // short send, no MSG_WAITALL
  }

  // Cancel every op on sv[0] then close it: cancel and close complete, and the
  // multishot recv's terminal CQE is -ECANCELED.
  s = ring.sqe();
  prepCancelFd(s, sv[0]);
  s->user_data = tag(&cancelTag, kTagCancel);
  s = ring.sqe();
  prepClose(s, sv[0]);
  s->user_data = tag(&closeTag, kTagClose);
  bool sawCancel = false, sawClose = false, recvEnded = false;
  int closeRes = 1;
  reapUntil(ring, 3, [&](const abi::io_uring_cqe& c) {
    switch (tagOf(c.user_data)) {
      case kTagCancel: sawCancel = true; break;
      case kTagClose: sawClose = true; closeRes = c.res; break;
      case kTagRecv:
        if (c.res == -ECANCELED && !hasMore(c)) recvEnded = true;
        break;
      default: break;
    }
  });
  CHECK(sawCancel && sawClose && recvEnded);
  CHECK(closeRes == 0);
  // The peer sees EOF: sv[0] is really closed.
  {
    // Whatever the partial send left in the socket buffers drains first
    // (bounded by the peer buffers, well under 1 MiB); then EOF.
    static char drain[64 * 1024];
    ssize_t n = ::read(sv[1], drain, sizeof(drain));
    size_t total = 0;
    while (n > 0 && total < (4u << 20)) {
      total += static_cast<size_t>(n);
      n = ::read(sv[1], drain, sizeof(drain));
    }
    CHECK(n == 0);
  }
  ::close(sv[1]);
  bufs.destroy(ring);
  ring.close();

  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all io_uring real-kernel unit tests passed (%d checks)\n", checks);
  return 0;
}
#endif
