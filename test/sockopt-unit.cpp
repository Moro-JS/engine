// The engine sets TCP_NODELAY once on each listening socket and relies on the
// kernel copying it to every accepted socket (server.h listen(), uringListen)
// instead of paying a setsockopt per connection. This checks that reliance on
// the running kernel: Linux and XNU both inherit the option.
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

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

int main() {
  int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(ls >= 0);
  int one = 1;
  CHECK(::setsockopt(ls, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);
  sockaddr_in a;
  std::memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  CHECK(::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
  CHECK(::listen(ls, 8) == 0);
  socklen_t al = sizeof a;
  CHECK(::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &al) == 0);
  int cs = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(::connect(cs, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
  int fd = ::accept(ls, nullptr, nullptr);
  CHECK(fd >= 0);
  int nd = 0;
  socklen_t l = sizeof nd;
  CHECK(::getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nd, &l) == 0);
  CHECK(nd != 0);  // inherited from the listener
  // And a listener WITHOUT the option yields sockets without it (the check
  // above is not a vacuous "always set").
  int ls2 = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in b;
  std::memset(&b, 0, sizeof b);
  b.sin_family = AF_INET;
  b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(ls2, reinterpret_cast<sockaddr*>(&b), sizeof b) == 0);
  CHECK(::listen(ls2, 8) == 0);
  socklen_t bl = sizeof b;
  CHECK(::getsockname(ls2, reinterpret_cast<sockaddr*>(&b), &bl) == 0);
  int cs2 = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(::connect(cs2, reinterpret_cast<sockaddr*>(&b), sizeof b) == 0);
  int fd2 = ::accept(ls2, nullptr, nullptr);
  int nd2 = 1;
  l = sizeof nd2;
  CHECK(::getsockopt(fd2, IPPROTO_TCP, TCP_NODELAY, &nd2, &l) == 0);
  CHECK(nd2 == 0);
  ::close(fd);
  ::close(cs);
  ::close(ls);
  ::close(fd2);
  ::close(cs2);
  ::close(ls2);
  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all socket-option unit tests passed (%d checks)\n", checks);
  return 0;
}
