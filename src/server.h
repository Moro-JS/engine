// TCP + HTTP/1.1 connection engine for @morojs/engine.
//
// Owns the libuv listener and per-connection state machine: accept, read, drive the HttpParser, and write responses. One request is in flight per connection at a time (RFC 9112 §9.3 - responses are returned in request order), so pipelining is handled structurally: the next buffered request is not surfaced until the current response ends.
//
// No V8 here - the binding layer (binding.cpp) supplies callbacks and reads request data / issues responses by reqId. Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <uv.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>

#include "flat_map.h"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "uring.h"
#endif

#include "http_parser.h"
#include "response_template.h"
#include "tls.h"
#include "websocket.h"
#include "ws_deflate.h"

namespace moro {
namespace engine {

// Cached RFC 9110 §5.6.7 Date header, refreshed at most once per second.
// Holds the COMPLETE "Date: ...\r\n" line so the hot path appends it once.
// time(nullptr), not uv_now: uv_now is loop time, not wall-clock.
inline const std::string& httpDateLine() {
  static thread_local std::string cached;
  static thread_local time_t cachedAt = 0;
  time_t now = time(nullptr);
  if (now != cachedAt || cached.empty()) {
    char buf[48];
    struct tm gmt;
#if defined(_WIN32)
    gmtime_s(&gmt, &now);
#else
    gmtime_r(&now, &gmt);
#endif
    // e.g. "Date: Sun, 06 Jul 2026 21:00:00 GMT\r\n"
    strftime(buf, sizeof(buf), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", &gmt);
    cached.assign(buf);
    cachedAt = now;
  }
  return cached;
}

// Append v in decimal - digits written backwards into a stack buffer, one
// append, no std::to_string temporary on the hot path.
inline void appendDecimal(std::string& out, unsigned long long v) {
  char buf[20];  // max digits of a 64-bit value
  char* p = buf + sizeof(buf);
  do {
    *--p = static_cast<char>('0' + (v % 10));
    v /= 10;
  } while (v != 0);
  out.append(p, static_cast<size_t>(buf + sizeof(buf) - p));
}

// Append the chunked-framing size line "<hex>\r\n" (lowercase, minimal
// digits - byte-identical to the snprintf("%zx\r\n") it replaces).
inline void appendChunkSize(std::string& out, size_t v) {
  char buf[sizeof(size_t) * 2 + 2];  // max hex digits + CRLF
  char* p = buf + sizeof(buf);
  *--p = '\n';
  *--p = '\r';
  do {
    *--p = "0123456789abcdef"[v & 0xF];
    v >>= 4;
  } while (v != 0);
  out.append(p, static_cast<size_t>(buf + sizeof(buf) - p));
}

inline const char* reasonPhrase(int status) {
  switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "OK";
  }
}

class Server;
struct Connection;

// Request id counter + registry mapping a reqId (the binding's only handle)
// back to its Connection, across every Server on the calling thread.
// thread_local, not process-global: worker_threads + reusePort (see
// HttpLimits::reusePort) runs one engine per thread, each with its own uv
// loop, servers and connections, and a reqId only ever crosses the
// JS<->C++ boundary on the thread that created it - per-thread registries
// are race-free without locks.
inline uint32_t& globalReqCounter() {
  static thread_local uint32_t counter = 0;
  return counter;
}
// reqId registry: flat open-addressing map (see flat_map.h) - no per-op
// allocation where std::unordered_map paid a node malloc/free per request.
// Key 0 is the empty sentinel; reqIds are never 0 (surfaceRequest skips it).
using FlatReqMap = FlatMap<Connection*>;

inline FlatReqMap& globalRequests() {
  static thread_local FlatReqMap map;
  return map;
}

// WebSocket connections get their own id space + registry (a wsId outlives the reqId that created it). Same per-thread ownership rules as globalRequests().
inline uint32_t& globalWsCounter() {
  static thread_local uint32_t counter = 0;
  return counter;
}
inline std::unordered_map<uint32_t, Connection*>& globalWebSockets() {
  static thread_local std::unordered_map<uint32_t, Connection*> map;
  return map;
}

// Per-connection state.
// Which I/O transport a Server runs (decided once per process, see
// Server::preferredTransport): libuv streams everywhere, io_uring on Linux
// when the kernel and the sandbox allow it. Behaviour and wire bytes are
// identical; only the syscall layer differs.
enum class TransportKind : uint8_t { Uv, Uring };

// One pre-parsed pipelined request waiting behind the active one (batched
// dispatch, Server::dispatchBatch): the same snapshot fields the Connection
// carries for its active request; activateStaged swaps them in, so
// respond()/the accessors never know a request was staged.
struct StagedRequest {
  uint32_t reqId = 0;
  Method method = Method::OTHER;
  std::string methodStr;
  std::string path;
  std::string query;
  std::vector<Header> headers;
  std::string body;
  bool isHead = false;
  bool reqKeepAlive = true;
  bool reqHttp11 = true;
  // Expect: 100-continue seen while no interim has been sent for it yet: the
  // 100 is written when the slot is activated (right before its own
  // response, after the responses ahead of it), as handleParse does for a
  // request the sequential loop surfaces.
  bool expectContinue = false;
};

struct Connection {
  Server* server = nullptr;
  // Transport state - exactly ONE arm is live, chosen by server->kind_:
  //   uv:    the libuv stream handle. Recovered via handle.data (set in
  //          onConnection), never a &handle->Connection pointer cast, so its
  //          offset here is unconstrained.
  //   uring: the socket fd plus the ring's per-connection bookkeeping
  //          (uring.h UringConn), recovered from the CQE's tagged user_data.
  // Value-initialised with the Connection, so both arms start zeroed.
  union {
    uv_tcp_t handle;
#if defined(__linux__)
    uring::UringConn ring;
#endif
  };
  HttpParser parser;
#if defined(_WIN32)
  // Per-connection receive buffer (uninitialized on purpose - uv only reads
  // back what the socket filled). Windows/IOCP posts this into an overlapped
  // WSARecv that outlives the alloc callback, so it cannot be shared.
  std::unique_ptr<char[]> readBuf;
  size_t readBufSize = 0;
#endif
  std::string pending;         // bytes received while a response is in flight

  // Snapshot of the request currently surfaced to JS (valid for the reqId's lifetime; the parser is reset for the next request).
  uint32_t reqId = 0;
  Method method = Method::OTHER;
  std::string methodStr;
  std::string path;
  std::string query;
  std::vector<Header> headers;
  std::string body;
  bool isHead = false;
  bool reqKeepAlive = true;
  // Snapshotted with reqKeepAlive (the parser may already be on a later
  // pipelined request by response time): governs whether persistence must be
  // affirmed on the wire (HTTP/1.0) or is the version default (HTTP/1.1).
  bool reqHttp11 = true;

  bool active = false;         // a request is surfaced, awaiting its response
  bool responseStarted = false;
  bool responseEnded = false;
  bool chunkedResponse = false;
  bool bodylessStatus = false;   // 1xx/204/304: body bytes are suppressed
  // Fixed-length streaming bookkeeping (writeHead with a Content-Length): ending short of the declared length forces Connection: close so the client sees truncation instead of consuming the next response's bytes as body.
  long long declaredLen = -1;    // -1: chunked/no declared Content-Length
  unsigned long long bodyBytesSent = 0;
  bool sentContinue = false;
  bool closing = false;
  bool wantDrain = false;
  bool abortNotified = false;  // onAborted delivered for the active request
  bool finSent = false;        // our FIN already went with the last response bytes (tTryWriteLast)
  int pendingWrites = 0;       // outstanding uv_write_t
  bool closeAfterFlush = false;
  // Lingering close (RFC 9112 §9.6, the "TCP reset problem"): the last
  // response of a Connection: close exchange is out and our FIN with it; the
  // socket now stays open with its input discarded until the peer's FIN
  // arrives (or Server::kLingerMs passes, onSweep). See closeAfterResponse.
  bool lingering = false;
  uint32_t lingerTicks = 0;
  uv_shutdown_t shutdownReq;   // uv arm: the FIN for a queued (non-coalesced) last write

  // Pipelined-response corking (see dispatchBatch): while `corked`, response bytes accumulate in corkBuf and are flushed with a single write once the buffered input drains - one syscall per pipelined batch instead of one per response. batchClose records a Connection: close response inside the batch (the flush-then-close is handled by the batch loop's tail).
  std::string corkBuf;
  bool corked = false;
  bool batchClose = false;

  // Batched dispatch (Server::dispatchBatch): complete pipelined requests
  // parsed ahead of the active one - a FIFO ring over `staged` (allocated on
  // first use, Server::kMaxStaged slots). Ids are assigned at staging and
  // registered only on activation, so a staged id is a safe no-op for every
  // binding call until then. aheadComplete: the parser holds one more
  // complete request that found no free slot (HttpParser::parse cannot be
  // re-asked once Done, so the status is remembered here).
  std::vector<StagedRequest> staged;
  uint32_t stagedHead = 0;
  uint32_t stagedCount = 0;
  uint32_t batchPos = 0;  // index of the active slot within the current batch call
  bool aheadComplete = false;

  // Reusable response-build buffer: respond()/writeHead()/write()/end() build
  // frames here instead of a fresh local string, so a warm connection writes
  // responses with zero allocations (see writeOutView). Oversized capacity is
  // released after use so one huge response can't stay pinned per connection.
  std::string scratch;

  // WebSocket state (after a successful Upgrade)
  bool isWebSocket = false;
  uint32_t wsId = 0;
  WsParser* wsParser = nullptr;
  bool wsClosing = false;
  // permessage-deflate context (RFC 7692); null unless negotiated for this connection at upgrade time.
  PmdContext* pmd = nullptr;
  // Outbound compression goes through the Server's SharedDeflator instead of
  // this connection's pmd (which is then InflateOnly). Set at upgrade when
  // wsDeflate.sharedCompressor negotiated the server's full window.
  bool pmdShared = false;

  // TLS transform when the server terminates TLS; null on plaintext servers (the hot path pays exactly one null check).
  TlsSession* tls = nullptr;

  // Idle-sweep bookkeeping: reset to 0 on every read, incremented each sweep while not actively running a handler; closed when it exceeds the limit.
  uint32_t idleTicks = 0;
  // Request-timeout bookkeeping: incremented each sweep while a request is partially received; NOT reset by activity (slow-drip defense), only when the request completes or the connection goes back to idle keep-alive.
  uint32_t requestTicks = 0;
  // Write-progress bookkeeping (slow-read defense): writeTicks counts sweeps with uv writes pending and NO drain progress; it resets on any progress and the connection is closed once it spans the whole responseTimeoutMs budget. Progress = the outbound queue SHRANK since the previous sweep (lastWriteQueue), or a write completed (onWrite). Queue shrinkage - not completion alone - is the load-bearing signal: a single large respond() is ONE uv_write that only completes when the whole body has drained, so a steadily-reading slow client would never produce a completion and would be shed mid-transfer despite continuous progress. SIZE_MAX = no baseline yet (next sweep records one).
  uint32_t writeTicks = 0;
  size_t lastWriteQueue = SIZE_MAX;

  ~Connection() {
    delete wsParser;
    delete tls;
    delete pmd;
  }
};

struct WriteReq {
  uv_write_t req;   // uv arm
  Connection* conn;
  std::string data;
  bool terminal;   // this write completes the response
  size_t sent = 0;          // uring arm: bytes the kernel has accepted so far
  WriteReq* next = nullptr; // uring arm: per-connection FIFO
};

// Callbacks into the binding layer. reqId is opaque; the binding maps it back to JS handlers.
struct ServerCallbacks {
  void* user = nullptr;
  void (*onRequest)(void* user, Connection* c) = nullptr;
  // Batched dispatch (Server::dispatchBatch): `count` requests are ready on
  // `c` - the active one plus count-1 staged behind it. The binding hands JS
  // their descriptors in one call; JS answers them in order and stops at the
  // first that goes async (the rest are re-surfaced when it completes).
  void (*onRequestBatch)(void* user, Connection* c, uint32_t count) = nullptr;
  // Delivered by reqId, never by Connection*: both are queued and handed to
  // the binding on a later loop turn (Server::queueNotify), by which time the
  // Connection may already have been freed. Never invoked re-entrantly from
  // inside a binding call (respond/writeHead/write/end).
  void (*onAborted)(void* user, uint32_t reqId) = nullptr;
  void (*onWritable)(void* user, uint32_t reqId) = nullptr;
  // WebSocket lifecycle (RFC 6455). data lives only for the call.
  void (*onWsOpen)(void* user, Connection* c, const std::string& path) = nullptr;
  void (*onWsMessage)(void* user, Connection* c, const char* data, size_t len,
                      bool isBinary) = nullptr;
  void (*onWsClose)(void* user, Connection* c, int code) = nullptr;
};

class Server {
 public:
  Server(uv_loop_t* loop, ServerCallbacks cb, HttpLimits limits)
      : loop_(loop), kind_(preferredTransport()), cb_(cb), limits_(limits) {
    // The uv listener handle is initialised for BOTH transports (an idle uv
    // handle costs nothing; the uring listener is a separate fd) so the
    // close()/liveHandles_ accounting is identical whichever arm runs.
    tcp_.data = this;
    uv_tcp_init(loop_, &tcp_);
    liveHandles_ = 1;  // the listener is a live uv handle from construction
    // Wakeup for deferred onAborted/onWritable delivery (queueNotify).
    // unref'd: a pending notification never keeps the process alive on its
    // own - the queue is only ever non-empty while a connection (a ref'd
    // handle) or the listener exists.
    notifyAsync_.data = this;
    uv_async_init(loop_, &notifyAsync_, onNotifyAsync);
    uv_unref(reinterpret_cast<uv_handle_t*>(&notifyAsync_));
    notifyAsyncLive_ = true;
    liveHandles_++;
    maxPending_ = limits_.maxPendingBytes ? limits_.maxPendingBytes
                                          : limits_.maxHeadSize + limits_.maxBodySize;
  }

  uv_loop_t* loop() const { return loop_; }
  TransportKind transportKind() const { return kind_; }
  static const char* transportName(TransportKind k) { return k == TransportKind::Uring ? "uring" : "uv"; }

  // Decided ONCE per process: MORO_ENGINE_TRANSPORT=uv forces libuv
  // (diagnostics; `uring` is an accepted no-op hint); otherwise io_uring's
  // feature probe + behavioural self-test (uring.h) decides. EPERM (Docker's
  // default seccomp, io_uring_disabled), ENOSYS and EINVAL (< 6.1) all mean
  // libuv - silently, because the transport is never a requirement.
  // libuv unless MORO_ENGINE_TRANSPORT=uring asks for io_uring (then the
  // probe decides, and any refusal falls back to libuv with the reason).
  // Opt-in, not auto-selected, in 1.2: measured on the same binary and box
  // (docs/DESIGN.md, "io_uring measurements"), io_uring halves the syscalls
  // per request but costs more CPU per completion at low batching - it wins
  // keep-alive at 64 and 512 connections, loses at 256, loses connection
  // churn by 10-20% and burns ~40% more CPU per request at a fixed moderate
  // rate. The default therefore stays libuv until the per-completion cost is
  // addressed (DEFER_TASKRUN behind an eventfd, ring-batched sends; see
  // docs/ROADMAP.md).
  static TransportKind preferredTransport() {
#if defined(__linux__)
    static const TransportKind kind = [] {
      const char* env = std::getenv("MORO_ENGINE_TRANSPORT");
      if (!env || std::strcmp(env, "uring") != 0) {
        transportReasonSlot() = (env && std::strcmp(env, "uv") == 0)
                                    ? "MORO_ENGINE_TRANSPORT=uv"
                                    : "opt-in (set MORO_ENGINE_TRANSPORT=uring)";
        return TransportKind::Uv;
      }
      uring::ProbeResult pr = uring::probe();
      transportReasonSlot() = pr.reason;
      return pr.ok ? TransportKind::Uring : TransportKind::Uv;
    }();
    return kind;
#else
    return TransportKind::Uv;
#endif
  }
  static const char* transportReason() {
    (void)preferredTransport();
    return transportReasonSlot();
  }

  // Notification delivery mode. Deferred (the default) hands onAborted /
  // onWritable to the binding from a uv_async callback, so no binding entry
  // point can re-enter JS - the precondition for V8 fast API calls. `sync`
  // restores the pre-1.2 re-entrant delivery for bisecting
  // (MORO_ENGINE_NOTIFY=sync); the binding then never installs fast calls.
  void setDeferredNotify(bool deferred) { notifyDeferred_ = deferred; }
  bool deferredNotify() const { return notifyDeferred_; }

  // Batched pipelined dispatch (capabilities.batchDispatch): on when the
  // binding registered onRequestBatch and MORO_ENGINE_BATCH is not 0;
  // otherwise requests are surfaced one at a time (dispatchBatchSequential).
  void setBatchDispatch(bool on) { batchOn_ = on && cb_.onRequestBatch != nullptr; }
  bool batchDispatch() const { return batchOn_; }
  // The control cell JS polls between slots: the index of the slot that is
  // active within the current batch call, or the batch's count once every
  // slot has been answered. Owned by the binding (an ArrayBuffer's storage),
  // stable for the server's lifetime.
  void setBatchControl(uint32_t* cell) { batchControl_ = cell; }
  static constexpr uint32_t kMaxStaged = 16;

  // Turn on TLS termination with an already-validated context (the binding builds and validates it BEFORE constructing the Server, so a config error throws from serve() instead of leaving a half-built server behind).
  void adoptTls(TlsContext&& tctx) {
    tlsCtx_ = std::move(tctx);
    tlsEnabled_ = tlsCtx_.valid();
  }
  bool tlsEnabled() const { return tlsEnabled_; }

  // Returns the bound port, or 0 on failure. On failure, *uvErr (when non-null) receives the libuv error code (e.g. UV_EADDRINUSE) so the caller can throw a precise, code-bearing Error.
  int listen(const char* host, int port, int* uvErr = nullptr) {
    auto fail = [&](int code) {
      if (uvErr) *uvErr = code;
      return 0;
    };
    // uv_ip4_addr/uv_ip6_addr parse numeric addresses only, not hostnames. Map the common names callers pass (Node's default host is 'localhost') to their loopback address; an empty host binds all interfaces.
    std::string h = host ? host : "";
    if (h.empty() || h == "0.0.0.0" || h == "*") {
      h = "0.0.0.0";
    } else if (h == "localhost") {
      h = "127.0.0.1";
    } else if (h == "ip6-localhost" || h == "localhost6") {
      h = "::1";
    }

    struct sockaddr_storage addr;
    if (uv_ip4_addr(h.c_str(), port, reinterpret_cast<sockaddr_in*>(&addr)) != 0 &&
        uv_ip6_addr(h.c_str(), port, reinterpret_cast<sockaddr_in6*>(&addr)) != 0) {
      return fail(UV_EINVAL);
    }
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      // Per-thread ring, created lazily by the first uring listener on this
      // loop; if it cannot be created (ENOMEM, uv_poll refusal) this server
      // simply runs the uv arm - a downgrade, never a failure.
      uring_ = UringLoop::get(loop_);
      if (!uring_) {
        kind_ = TransportKind::Uv;
      } else {
        int r = uringListen(addr);
        if (r != 0) return fail(r);
      }
    }
    if (kind_ == TransportKind::Uv) {
#endif
#if !defined(_WIN32)
    if (limits_.reusePort) {
      // uv_tcp_bind creates its socket lazily, so to set SO_REUSEPORT before bind we create + configure one explicitly and hand it to libuv.
      int fd = ::socket(addr.ss_family, SOCK_STREAM, 0);
      if (fd >= 0) {
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        if (uv_tcp_open(&tcp_, fd) != 0) ::close(fd);
      }
    }
#endif
    int r = uv_tcp_bind(&tcp_, reinterpret_cast<sockaddr*>(&addr), 0);
    if (r != 0) return fail(r);
    r = uv_listen(reinterpret_cast<uv_stream_t*>(&tcp_), limits_.backlog, onConnection);
    if (r != 0) return fail(r);
#if !defined(_WIN32)
    {
      // TCP_NODELAY on the listener is inherited by every accepted socket
      // (Linux and XNU; test/sockopt-unit.cpp checks it), so the per-connection
      // uv_tcp_nodelay() setsockopt - one syscall on every accept - is not
      // needed on POSIX. Same trick as the io_uring listener (uringListen).
      uv_os_fd_t lfd;
      if (uv_fileno(reinterpret_cast<uv_handle_t*>(&tcp_), &lfd) == 0) {
        int on = 1;
        setsockopt(static_cast<int>(lfd), IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
      }
    }
#endif
#if defined(__linux__)
    }
#endif

    // Start the connection sweep. Granularity adapts to the shortest enabled
    // timeout (capped at 4s, floored at 250ms) so short timeouts still fire
    // promptly. The lingering-close deadline (kLingerMs) is always enabled,
    // so the sweep always runs; unref'd, so the timer alone never keeps the
    // process alive - the listener (and any active connection) does that.
    if (!sweepActive_) {
      uint64_t shortest = kLingerMs;
      if (limits_.idleTimeoutMs > 0 && limits_.idleTimeoutMs < shortest)
        shortest = limits_.idleTimeoutMs;
      if (limits_.requestTimeoutMs > 0 && limits_.requestTimeoutMs < shortest)
        shortest = limits_.requestTimeoutMs;
      if (limits_.responseTimeoutMs > 0 && limits_.responseTimeoutMs < shortest)
        shortest = limits_.responseTimeoutMs;
      uint64_t half = shortest / 2;
      sweepMs_ = half < 250 ? 250 : (half > 4000 ? 4000 : half);
      sweepTimer_.data = this;
      uv_timer_init(loop_, &sweepTimer_);
      uv_unref(reinterpret_cast<uv_handle_t*>(&sweepTimer_));
      uv_timer_start(&sweepTimer_, onSweep, sweepMs_, sweepMs_);
      sweepActive_ = true;
      liveHandles_++;  // the sweep timer is now a live uv handle
    }

    // Resolve the actual bound port (supports port 0). Read the big-endian port bytes directly instead of ntohs(), which would drag ws2_32.lib (Winsock) into the Windows link for a trivial byte swap.
    auto bePort = [](uint16_t netOrder) -> uint16_t {
      const uint8_t* b = reinterpret_cast<const uint8_t*>(&netOrder);
      return static_cast<uint16_t>((static_cast<uint16_t>(b[0]) << 8) | b[1]);
    };
    struct sockaddr_storage bound;
    int len = sizeof(bound);
    if (tBoundName(&bound, &len)) {
      if (bound.ss_family == AF_INET)
        return bePort(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
      if (bound.ss_family == AF_INET6)
        return bePort(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
    }
    return port;
  }

  // Shut down: stop accepting, close the sweep timer and every live connection, and - once all uv handles are actually reaped (async) - delete this Server and invoke onClosed(user) so the binding can free its per-server JS state. Idempotent. Stop accepting new connections while existing ones keep being served - the first half of a graceful shutdown (drain in-flight work, then close()). Idempotent; close() remains the full teardown.
  void stopListening() {
    if (closeRequested_ || listenerClosed_) return;
    listening_ = false;
    listenerClosed_ = true;
    uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), onServerHandleClosed);
    tCloseListener();
  }

  void close(void (*onClosed)(void*) = nullptr, void* user = nullptr) {
    if (closeRequested_) return;
    closeRequested_ = true;
    onClosed_ = onClosed;
    onClosedUser_ = user;
    listening_ = false;

    if (!listenerClosed_) {
      listenerClosed_ = true;
      uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), onServerHandleClosed);
      tCloseListener();
    }
    if (sweepActive_) {
      sweepActive_ = false;
      uv_timer_stop(&sweepTimer_);
      uv_close(reinterpret_cast<uv_handle_t*>(&sweepTimer_), onServerHandleClosed);
    }
    // Close every live connection (doClose mutates conns_, so iterate a copy).
    std::vector<Connection*> live(conns_.begin(), conns_.end());
    for (Connection* c : live) doClose(c);
    // Deliver every onAborted the loop above queued BEFORE returning: the
    // caller (engine.close() in JS) drops its in-flight table right after
    // this returns, so a notification arriving a turn later would find no
    // handler to route to (leaked 'close' listeners, SSE intervals).
    drainNotifications();
    if (notifyAsyncLive_) {
      notifyAsyncLive_ = false;
      uv_close(reinterpret_cast<uv_handle_t*>(&notifyAsync_), onServerHandleClosed);
    }

    checkFullyClosed();  // handles the (rare) zero-handle case synchronously
  }

  static Connection* lookup(uint32_t reqId) {
    return globalRequests().find(reqId);
  }

  std::string remoteAddress(Connection* c) {
    struct sockaddr_storage addr;
    int len = sizeof(addr);
    if (!tPeerName(c, &addr, &len)) return "";
    char ip[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET)
      uv_ip4_name(reinterpret_cast<sockaddr_in*>(&addr), ip, sizeof(ip));
    else if (addr.ss_family == AF_INET6)
      uv_ip6_name(reinterpret_cast<sockaddr_in6*>(&addr), ip, sizeof(ip));
    return ip;
  }

  // ---- prepared response templates (capabilities.responseTemplates) ----

  // Register a template (see response_template.h). Returns its id, 0 when
  // the store is full.
  uint32_t prepareTemplate(ResponseTemplate&& t) { return templates_.add(std::move(t)); }
  void releaseTemplates() { templates_.clear(); }
  size_t templateCount() const { return templates_.size(); }

  // respond()/writeHead() with a stored template instead of a header block.
  // An invalid id (0, released, another server's) must never crash or leave
  // the request hanging: it answers 500 with an empty body and keeps the
  // connection's keep-alive state intact, so the fault is visible to the
  // client and the app's abort/close bookkeeping still completes normally.
  void respondTemplate(Connection* c, uint32_t tplId, const char* body, size_t bodyLen) {
    const ResponseTemplate* t = templates_.get(tplId);
    if (!t) {
      respond(c, 500, emptyHeaders(), -1, nullptr, 0);
      return;
    }
    respond(c, t->status, t->headers, t->customCL, body, bodyLen);
  }
  void writeHeadTemplate(Connection* c, uint32_t tplId) {
    const ResponseTemplate* t = templates_.get(tplId);
    if (!t) {
      writeHead(c, 500, emptyHeaders(), -1);
      return;
    }
    writeHead(c, t->status, t->headers, t->customCL);
  }

  // ---- static routes (capabilities.staticRoutes) ----
  // A fixed (method, path) answered by the engine in surfaceRequest, before
  // the request reaches the binding: no JS call, no routing, no per-request
  // header building. Only an exact method match short-circuits (a HEAD against
  // a registered GET still reaches JS, which owns method policy).
  void setStaticRoute(int32_t method, std::string path, ResponseTemplate&& tpl,
                      std::string body) {
    auto& vec = staticRoutes_[std::move(path)];
    for (StaticRoute& existing : vec) {
      if (existing.method == method) {
        existing.tpl = std::move(tpl);
        existing.body = std::move(body);
        return;
      }
    }
    vec.push_back(StaticRoute{method, std::move(tpl), std::move(body)});
  }
  void clearStaticRoutes() { staticRoutes_.clear(); }

  // ---- response API (called by the binding, by reqId->Connection) ----

  // Responses that MUST NOT carry a body or Content-Length (RFC 9110 §6.4.1, §15.3.5): 1xx informational, 204 No Content, 304 Not Modified.
  static bool isBodyless(int status) {
    return status == 204 || status == 304 || (status >= 100 && status < 200);
  }

  // Single-shot terminal response (the fast path). customCL is an app-supplied Content-Length value, or -1 when none was given; the header block itself never contains Content-Length (the binding strips it).
  void respond(Connection* c, int status, const std::string& headersBlock,
               long long customCL, const char* body, size_t bodyLen) {
    if (!c || c->responseEnded || c->closing) return;

    const bool bodyless = isBodyless(status);
    if (bodyless) bodyLen = 0;  // never emit a body for these statuses

    // Corked plaintext fast path: build the frame STRAIGHT INTO the cork
    // buffer - no scratch, no intermediate memcpy. This is the hot path for
    // every pipelined batch. (TLS must go through writeOutView so the frame is
    // encrypted before it reaches corkBuf.)
    if (c->corked && !c->tls) {
      c->corkBuf.reserve(c->corkBuf.size() + bodyLen + headersBlock.size() +
                         128);
      appendResponse(c->corkBuf, c, status, headersBlock, customCL, body,
                     bodyLen, bodyless);
      c->responseStarted = true;
      c->responseEnded = true;
      completeCorkedResponse(c);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }

    std::string& out = c->scratch;
    out.clear();
    out.reserve(bodyLen + headersBlock.size() + 128);
    appendResponse(out, c, status, headersBlock, customCL, body, bodyLen,
                   bodyless);
    c->responseStarted = true;
    c->responseEnded = true;
    writeOutView(c, out, /*terminal=*/true);
    releaseScratch(c);
  }

  // Append one complete response frame (status line through body) to `out`.
  // Framing belongs to the engine: a body-carrying response always declares
  // the ACTUAL body size (an app-supplied mismatch would desync every
  // follow-up response on a keep-alive connection). HEAD and bodyless statuses
  // legitimately declare the would-be entity length (RFC 9110 §8.6), so the
  // app-supplied value is honored there.
  void appendResponse(std::string& out, Connection* c, int status,
                      const std::string& headersBlock, long long customCL,
                      const char* body, size_t bodyLen, bool bodyless) {
    appendStatusLine(out, status);
    out += httpDateLine();
    out += headersBlock;
    if (!bodyless) {
      const unsigned long long cl =
          (c->isHead && customCL >= 0)
              ? static_cast<unsigned long long>(customCL)
              : static_cast<unsigned long long>(bodyLen);
      out += "Content-Length: ";
      appendDecimal(out, cl);
      out += "\r\n";
    } else if (customCL >= 0) {
      out += "Content-Length: ";
      appendDecimal(out, static_cast<unsigned long long>(customCL));
      out += "\r\n";
    }
    out += connectionHeader(c);
    out += "\r\n";
    if (!c->isHead && bodyLen) out.append(body, bodyLen);
  }

  // One huge response must not pin its capacity to an idle connection; small
  // (typical) responses keep theirs so the next build is allocation-free.
  static void releaseScratch(Connection* c) {
    if (c->scratch.capacity() > 16384) {
      c->scratch.clear();
      c->scratch.shrink_to_fit();
    }
  }

  void writeHead(Connection* c, int status, const std::string& headersBlock,
                 long long customCL) {
    if (!c || c->responseStarted || c->closing) return;
    c->responseStarted = true;
    c->bodylessStatus = isBodyless(status);
    c->bodyBytesSent = 0;
    if (c->bodylessStatus) {
      // No body framing at all; an app-supplied Content-Length (the would-be entity length, e.g. on a 304) is honored verbatim.
      c->chunkedResponse = false;
      c->declaredLen = 0;
    } else {
      c->chunkedResponse = customCL < 0;  // no CL -> chunked framing
      c->declaredLen = customCL;
    }

    std::string& out = c->scratch;
    out.clear();
    appendStatusLine(out, status);
    out += httpDateLine();
    out += headersBlock;
    if (c->bodylessStatus) {
      if (customCL >= 0) {
        out += "Content-Length: ";
        appendDecimal(out, static_cast<unsigned long long>(customCL));
        out += "\r\n";
      }
    } else if (c->chunkedResponse) {
      out += "Transfer-Encoding: chunked\r\n";
    } else {
      out += "Content-Length: ";
      appendDecimal(out, static_cast<unsigned long long>(customCL));
      out += "\r\n";
    }
    out += connectionHeader(c);
    out += "\r\n";
    writeOutView(c, out, /*terminal=*/false);
    releaseScratch(c);
  }

  // Streaming chunk. Returns false on backpressure (wait for onWritable).
  bool write(Connection* c, const char* data, size_t len) {
    if (!c || c->responseEnded || c->closing) return false;
    // write() without writeHead(): synthesize an implicit 200 chunked head (Node behavior). Raw body bytes with no status line would corrupt this response and desync every follow-up response on a keep-alive socket.
    if (!c->responseStarted) writeHead(c, 200, std::string(), -1);
    // HEAD / 1xx / 204 / 304: suppress body bytes
    if (c->isHead || c->bodylessStatus || len == 0) return true;

    std::string& out = c->scratch;
    out.clear();
    if (c->chunkedResponse) {
      appendChunkSize(out, len);
      out.append(data, len);
      out += "\r\n";
    } else {
      // Fixed-length response: never let body bytes overflow the declared Content-Length - excess would be parsed as the next response.
      if (c->declaredLen >= 0) {
        const unsigned long long declared =
            static_cast<unsigned long long>(c->declaredLen);
        if (c->bodyBytesSent >= declared) return true;  // clamp: drop excess
        if (c->bodyBytesSent + len > declared)
          len = static_cast<size_t>(declared - c->bodyBytesSent);
      }
      c->bodyBytesSent += len;
      out.append(data, len);
    }
    writeOutView(c, out, /*terminal=*/false);
    releaseScratch(c);
    bool ok = tPendingBytes(c) < limits_.writeHighWaterMark;
    if (!ok) c->wantDrain = true;
    return ok;
  }

  void end(Connection* c, const char* data, size_t len) {
    if (!c || c->responseEnded || c->closing) return;

    std::string& out = c->scratch;
    out.clear();
    if (!c->responseStarted) {
      // end() without writeHead(): a 200 with the given body as the full payload
      appendStatusLine(out, 200);
      out += httpDateLine();
      out += "Content-Length: ";
      appendDecimal(out, c->isHead ? 0 : len);
      out += "\r\n";
      out += connectionHeader(c);
      out += "\r\n";
      if (!c->isHead && len) out.append(data, len);
    } else if (c->chunkedResponse) {
      if (!c->isHead && !c->bodylessStatus && len) {
        appendChunkSize(out, len);
        out.append(data, len);
        out += "\r\n";
      }
      // RFC 9110 §9.3.2: a HEAD response carries NO body — not even the chunked terminator. Emitting "0\r\n\r\n" here would be parsed by the client as the start of the next pipelined response, desyncing keep-alive.
      if (!c->isHead) out += "0\r\n\r\n";  // last chunk (RFC 9112 §7.1)
    } else {
      if (!c->isHead && !c->bodylessStatus && len) {
        // Same overflow clamp as write()
        if (c->declaredLen >= 0) {
          const unsigned long long declared =
              static_cast<unsigned long long>(c->declaredLen);
          if (c->bodyBytesSent >= declared)
            len = 0;
          else if (c->bodyBytesSent + len > declared)
            len = static_cast<size_t>(declared - c->bodyBytesSent);
        }
        c->bodyBytesSent += len;
        if (len) out.append(data, len);
      }
      // Ending short of the declared Content-Length: the bytes owed can never arrive, so force the connection closed - the client then sees a truncated response (an error) instead of silently consuming the NEXT response's bytes as the remainder of this body.
      if (!c->isHead && c->declaredLen >= 0 &&
          c->bodyBytesSent < static_cast<unsigned long long>(c->declaredLen)) {
        c->reqKeepAlive = false;
      }
    }
    c->responseStarted = true;
    c->responseEnded = true;
    writeOutView(c, out, /*terminal=*/true);
    releaseScratch(c);
  }

  static Connection* lookupWs(uint32_t wsId) {
    auto& map = globalWebSockets();
    auto it = map.find(wsId);
    return it == map.end() ? nullptr : it->second;
  }

  // Upgrade the request's connection to a WebSocket (RFC 6455 §4.2.2). Returns the new wsId, or 0 if the request is not a valid upgrade.
  uint32_t upgradeToWebSocket(Connection* c) {
    if (!c || c->responseStarted || c->closing) return 0;
    // Validate the upgrade (RFC 6455 §4.2.1): Upgrade: websocket, Connection: Upgrade, a Sec-WebSocket-Key, Version 13.
    const std::string* key = nullptr;
    const std::string* extensions = nullptr;
    bool hasUpgrade = false, hasConnUpgrade = false, ver13 = false;
    for (const auto& h : c->headers) {
      if (h.name == "upgrade" && iequals(trimOWS(h.value), "websocket"))
        hasUpgrade = true;
      else if (h.name == "connection") {
        // Connection is a comma-separated list of case-insensitive tokens
        // (RFC 9110 §7.6.1), e.g. "keep-alive, Upgrade" - tokenize and compare
        // each (same tokenization as finalizeHeaders): a substring match would
        // wrongly accept "not-upgrade", a case-sensitive one wrongly reject
        // "UPGRADE".
        std::string_view v = h.value;
        size_t pos = 0;
        while (pos <= v.size()) {
          size_t comma = v.find(',', pos);
          std::string_view tok = trimOWS(v.substr(
              pos, comma == std::string_view::npos ? v.size() - pos : comma - pos));
          if (iequals(tok, "upgrade")) hasConnUpgrade = true;
          if (comma == std::string_view::npos) break;
          pos = comma + 1;
        }
      } else if (h.name == "sec-websocket-key")
        key = &h.value;
      else if (h.name == "sec-websocket-version" && trimOWS(h.value) == "13")
        ver13 = true;
      else if (h.name == "sec-websocket-extensions")
        extensions = &h.value;
    }
    if (!hasUpgrade || !hasConnUpgrade || !key || !ver13) return 0;
    // RFC 6455 §4.1: the key must be the base64 of a 16-byte nonce; refuse
    // malformed/probing clients before the accept-key computation (§4.2.1).
    if (!isValidWsKey(*key)) return 0;

    // permessage-deflate negotiation (RFC 7692), opt-in via options.wsDeflate.
    std::string extResp;
    std::optional<PmdParams> pmdParams;
    if (limits_.wsDeflate.enabled && extensions) {
      pmdParams = parsePmdOffer(*extensions, limits_.wsDeflate);
      if (pmdParams) {
        size_t cap = limits_.wsDeflate.maxDecompressedSize
                         ? limits_.wsDeflate.maxDecompressedSize
                         : limits_.wsMaxMessageSize;
        // wsDeflate.sharedCompressor: route this connection's outbound
        // compression through the ONE server-owned deflate stream instead of
        // a ~262 KB per-connection one. Only when the negotiated server
        // window equals the shared stream's window, i.e. the client did NOT
        // cap server_max_window_bits below the configured value: the shared
        // stream has one FIXED window, and re-negotiating it per client
        // would defeat the sharing - such clients keep today's
        // per-connection full PmdContext (honoring their cap).
        bool useShared =
            limits_.wsDeflate.sharedCompressor &&
            pmdParams->serverMaxWindowBits == limits_.wsDeflate.serverMaxWindowBits;
        if (useShared && !sharedDeflator_) {
          // Created lazily at the first eligible upgrade (not in the Server
          // constructor): a server that enables the option but never sees a
          // pmd client allocates nothing.
          sharedDeflator_.reset(
              new SharedDeflator(limits_.wsDeflate.serverMaxWindowBits));
          if (!sharedDeflator_->valid()) sharedDeflator_.reset();
        }
        if (useShared && !sharedDeflator_) useShared = false;  // zlib init failed
        if (useShared) {
          // The shared stream is reset after EVERY message, so the response
          // must advertise server_no_context_takeover - RFC 7692 §7.1.1.1
          // explicitly permits the server to include it even when the offer
          // didn't ask for it. Set BEFORE buildPmdResponse below.
          pmdParams->serverNoContextTakeover = true;
        }
        auto* ctx = new PmdContext(*pmdParams, cap,
                                   useShared ? PmdContext::Mode::InflateOnly
                                             : PmdContext::Mode::Full);
        if (ctx->valid()) {
          // The threshold lives on the context even in InflateOnly mode so
          // wsSend's threshold check is identical on both paths.
          ctx->setThreshold(limits_.wsDeflate.threshold);
          c->pmd = ctx;
          c->pmdShared = useShared;
          extResp = buildPmdResponse(*pmdParams);
        } else {
          delete ctx;  // zlib init failed - fall back to no compression
          pmdParams.reset();
        }
      }
    }

    // Send the 101 handshake response (with the negotiated extension, if any).
    std::string resp = buildHandshakeResponse(*key, extResp);
    c->responseStarted = true;
    c->responseEnded = true;
    c->isWebSocket = true;
    c->reqKeepAlive = true;  // the socket stays open as a WS
    c->wsParser = new WsParser(
        WsParser::Limits{limits_.wsMaxMessageSize, /*pmdNegotiated=*/c->pmd != nullptr});
    // Skip any id still bound to a live connection: the uint32 counter wraps after 2^32 upgrades/requests, and a collision with a long-lived stream would silently rebind it to this connection.
    auto& wsMap = globalWebSockets();
    do {
      c->wsId = ++globalWsCounter();
    } while (c->wsId == 0 || wsMap.count(c->wsId));
    wsMap[c->wsId] = c;
    // This request's reqId is done; the connection is now a WebSocket.
    globalRequests().erase(c->reqId);
    c->active = false;
    writeOut(c, std::move(resp), /*terminal=*/false);

    const uint32_t wsId = c->wsId;
    if (cb_.onWsOpen) cb_.onWsOpen(cb_.user, c, c->path);
    // Frames the client sent before the 101 went out must reach the WebSocket
    // parser (copied out first: feedWebSocket may tear the connection down on a
    // protocol error, after which c and its parser must not be touched; the
    // copy is also the mutable storage the parser's in-place unmasking needs).
    // Two sources, in receive order: bytes buffered in the HTTP parser from the
    // same segment as the handshake request (leftover), then any frames the
    // client sent in later segments while an async upgrade handler had not yet
    // responded (c->pending). c->pending's only other drain, finishResponse, is
    // unreachable once the 101 is written terminal=false, so without this it
    // would be silently dropped -> WS desync.
    std::string early(c->parser.leftover());
    early.append(c->pending);
    c->pending.clear();
    c->parser = HttpParser(limits_);  // HTTP is done on this connection
    if (!early.empty()) feedWebSocket(c, early.data(), early.size());
    return wsId;
  }

  // Send a WebSocket data frame (server frames are never masked, §5.1). permessage-deflate: when negotiated and the message is at least the configured threshold, compress it and set RSV1 (RFC 7692 §7.2.1).
  bool wsSend(Connection* c, const char* data, size_t len, bool isBinary) {
    if (!c || !c->isWebSocket || c->closing || c->wsClosing) return false;
    bool compressed = false;
    std::string deflated;
    if (c->pmd && len >= c->pmd->threshold()) {
      // pmdShared connections deflate through the server-owned SharedDeflator
      // (their PmdContext is InflateOnly - see upgradeToWebSocket); the reset
      // after every message keeps interleaved connections independent.
      std::string_view in(data, len);
      compressed = c->pmdShared
                       ? (sharedDeflator_ && sharedDeflator_->deflateMessage(in, deflated))
                       : c->pmd->deflateMessage(in, deflated);
    }
    std::string_view payload = compressed ? std::string_view(deflated)
                                          : std::string_view(data, len);
    // Frame into the connection's reusable scratch buffer (same policy as
    // respond()'s non-corked path): a warm connection sends with zero
    // allocations, and releaseScratch keeps one huge frame from pinning its
    // capacity. writeOutView never keeps a reference past the call: the bytes
    // reach the kernel synchronously (uv_try_write) or are copied first -
    // into a queued WriteReq, the TLS ciphertext buffer (writePlain), or
    // corkBuf (a wsSend issued from onWsOpen/onWsMessage inside the upgrade's
    // still-corked dispatch).
    std::string& out = c->scratch;
    out.clear();
    encodeFrame(out, isBinary ? WsOpcode::Binary : WsOpcode::Text, payload,
                /*fin=*/true, /*rsv1=*/compressed);
    writeOutView(c, out, /*terminal=*/false);
    releaseScratch(c);
    size_t q = tPendingBytes(c);
    if (limits_.wsBackpressureLimit && q > limits_.wsBackpressureLimit) {
      // Slow/stalled consumer - shed it (1013 Try Again Later) so its queued frames can't grow memory without bound (limits_.wsBackpressureLimit, 0 = unlimited; maxBackpressure defense).
      wsClose(c, 1013, "", 0);
      return false;
    }
    return q < limits_.writeHighWaterMark;
  }

  // Send a Close frame (§5.5.1) and close the connection after it flushes.
  void wsClose(Connection* c, uint16_t code, const char* reason, size_t rlen) {
    if (!c || !c->isWebSocket || c->wsClosing) return;
    c->wsClosing = true;
    // Notify JS exactly once. The wsClosing guard above + the check in feedWebSocket/onRead means no client-side or EOF path re-fires it, so server-initiated closes (disconnect/kick) no longer leak the JS wrapper.
    if (cb_.onWsClose) cb_.onWsClose(cb_.user, c, code);
    std::string payload;
    encodeClosePayload(payload, code, std::string_view(reason, rlen));
    std::string out;
    encodeFrame(out, WsOpcode::Close, payload);
    c->reqKeepAlive = false;  // close the TCP socket once the frame flushes
    globalWebSockets().erase(c->wsId);
    writeOut(c, std::move(out), /*terminal=*/true);
  }

  bool listening_ = true;

 private:
  void appendStatusLine(std::string& out, int status) {
    // Hot statuses append a prebuilt literal (skips int formatting entirely).
    switch (status) {
      case 200: out += "HTTP/1.1 200 OK\r\n"; return;
      case 201: out += "HTTP/1.1 201 Created\r\n"; return;
      case 204: out += "HTTP/1.1 204 No Content\r\n"; return;
      case 304: out += "HTTP/1.1 304 Not Modified\r\n"; return;
      case 404: out += "HTTP/1.1 404 Not Found\r\n"; return;
      default: break;
    }
    // Clamp to the three-digit range the status line grammar allows (RFC 9112 §4): anything else would corrupt the wire format.
    if (status < 100 || status > 999) status = 500;
    out += "HTTP/1.1 ";
    out += std::to_string(status);
    out += ' ';
    out += reasonPhrase(status);
    out += "\r\n";
  }

  // String literal, not std::string: returning by value would heap-alloc per
  // response for the keep-alive variant (one byte past libc++'s SSO cap).
  // HTTP/1.1 persistence is the version default (RFC 9112 §9.3), so a 1.1
  // keep-alive response carries no Connection header at all - 24 fewer bytes
  // on every response. HTTP/1.0 keep-alive MUST still be affirmed explicitly
  // (for 1.0 the default is close; silence tells the client to hang up), and
  // every close path keeps its header.
  const char* connectionHeader(Connection* c) {
    if (!c->reqKeepAlive) return "Connection: close\r\n";
    return c->reqHttp11 ? "" : "Connection: keep-alive\r\n";
  }

  // libuv's uv_buf_t carries the length in an `unsigned` (32-bit) field and
  // uv_write/uv_try_write count bytes with an int, so a single buffer >= 4 GiB
  // truncates the length (silent corruption + a hung client, since
  // Content-Length then lies) and a >= 2 GiB completion check wraps. Response
  // bodies are app-controlled with no cap, so payloads past this watermark are
  // split into <= 1 GiB segments: the synchronous fast paths defer such a
  // payload to the queued path, and queueWrite hands the segments to ONE
  // uv_write (one WriteReq, one onWrite - terminal bookkeeping still fires
  // exactly once). 1 GiB < INT_MAX, so every length/return cast below a
  // segment boundary is exact.
  static constexpr size_t kMaxWriteChunk = static_cast<size_t>(1) << 30;

  // Frame-level write: response/frame bytes from the HTTP/WS machinery. On a TLS connection the plaintext is encrypted first; `terminal` rides the (single) ciphertext buffer so the flush-then-finish semantics (onWrite -> finishResponse) are identical on both transports.
  void writeOut(Connection* c, std::string&& data, bool terminal) {
    if (c->closing) return;
    if (data.empty() && !terminal) return;
    if (c->tls) {
      std::string cipher;
      if (!data.empty() &&
          !c->tls->writePlain(data.data(), data.size(), cipher)) {
        // Encrypting failed (session torn down / pre-handshake write): the response can never reach the peer - drop the connection.
        doClose(c);
        return;
      }
      transportWrite(c, std::move(cipher), terminal);
      return;
    }
    transportWrite(c, std::move(data), terminal);
  }

  // Transport-level write: bytes go to the socket verbatim (ciphertext on TLS connections, plaintext otherwise).
  //
  // Fast path (the "cork" equivalent): when nothing is already queued, hand the bytes straight to the kernel with uv_try_write - for a small response on a non-backpressured socket (the overwhelmingly common case) this skips the WriteReq heap allocation, libuv's write-request queue, AND the deferred completion callback entirely. Ordering is safe because the fast path only runs with an empty write queue (pendingWrites == 0; uv_try_write itself also refuses to interleave with queued data).
  //
  // A TERMINAL write completed synchronously must also complete the response (finishResponse - previously always deferred to onWrite). That is only taken when no pipelined bytes are buffered (c->pending and the parser's leftover are empty), so finishResponse just resets per-request state and cannot re-enter a JS handler from inside the current respond()/end() crossing. With buffered pipelined data the write falls through to the queued path and completes on a clean stack, exactly as before.
  void transportWrite(Connection* c, std::string&& data, bool terminal) {
    if (c->closing) return;
    if (data.empty() && !terminal) return;

    // Corked (inside dispatchBatch): accumulate instead of writing. A terminal write completes the response's bookkeeping synchronously - safe because the batch loop surfaces the NEXT request only after the current handler returns, so this never re-enters JS from inside a respond()/end() crossing. The buffer is bounded: it flushes at the write high-water mark.
    if (c->corked) {
      if (!data.empty()) c->corkBuf += data;
      if (terminal) completeCorkedResponse(c);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }

    // The single-buffer uv_try_write fast path only handles payloads that fit
    // one uv_buf_t; an oversized body (>= 1 GiB) falls through to queueWrite,
    // which splits it into <= 1 GiB segments (see kMaxWriteChunk).
    if (c->pendingWrites == 0 && data.size() <= kMaxWriteChunk) {
      const bool canFinishSync =
          !terminal || (c->pending.empty() && c->parser.leftover().empty() &&
                        c->stagedCount == 0 && !c->aheadComplete);
      if (canFinishSync) {
        if (data.empty()) {
          // terminal with no bytes owed (e.g. HEAD chunked suppression)
          finishResponse(c);
          return;
        }
        int n = lastWrite(c, terminal) ? tTryWriteLast(c, data.data(), data.size())
                                       : tTryWrite(c, data.data(), data.size());
        if (n == static_cast<int>(data.size())) {
          if (terminal) finishResponse(c);
          return;
        }
        if (n > 0) {
          // Partial write: queue only the remainder (ordering preserved - nothing else was queued).
          data.erase(0, static_cast<size_t>(n));
        }
        // n == UV_EAGAIN or an error: fall through to the queued path (a real socket error then surfaces through uv_write/onWrite as before).
      }
    }
    queueWrite(c, std::move(data), terminal);
  }

  // View-based frame write: the caller retains ownership of the bytes
  // (typically Connection::scratch, whose capacity is reused across
  // responses). The fast path writes straight from the view - zero copies,
  // zero allocations; only a queued/backpressured remainder is copied.
  void writeOutView(Connection* c, std::string_view data, bool terminal) {
    if (c->closing) return;
    if (data.empty() && !terminal) return;
    if (c->tls) {
      std::string cipher;
      if (!data.empty() &&
          !c->tls->writePlain(data.data(), data.size(), cipher)) {
        doClose(c);
        return;
      }
      transportWrite(c, std::move(cipher), terminal);
      return;
    }
    if (c->corked) {
      if (!data.empty()) c->corkBuf.append(data);
      if (terminal) completeCorkedResponse(c);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }
    // See transportWrite: the single-buffer fast path is skipped for an
    // oversized payload so queueWrite can split it into <= 1 GiB segments.
    if (c->pendingWrites == 0 && data.size() <= kMaxWriteChunk) {
      const bool canFinishSync =
          !terminal || (c->pending.empty() && c->parser.leftover().empty() &&
                        c->stagedCount == 0 && !c->aheadComplete);
      if (canFinishSync) {
        if (data.empty()) {
          finishResponse(c);  // terminal with no bytes owed
          return;
        }
        int n = lastWrite(c, terminal) ? tTryWriteLast(c, data.data(), data.size())
                                       : tTryWrite(c, data.data(), data.size());
        if (n == static_cast<int>(data.size())) {
          if (terminal) finishResponse(c);
          return;
        }
        if (n > 0) data.remove_prefix(static_cast<size_t>(n));
      }
    }
    queueWrite(c, std::string(data), terminal);
  }

  // Queued (owned) write: WriteReq holds the bytes until uv flushes them.
  void queueWrite(Connection* c, std::string&& data, bool terminal) {
    WriteReq* wr = new WriteReq{};
    wr->conn = c;
    wr->data = std::move(data);
    wr->terminal = terminal;
    wr->req.data = wr;
    c->pendingWrites++;
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      uringQueueWrite(c, wr);
      if (limits_.responseBackpressureLimit && !c->isWebSocket &&
          tPendingBytes(c) > limits_.responseBackpressureLimit) {
        doClose(c);
      }
      return;
    }
#endif
    int r;
    if (wr->data.size() <= kMaxWriteChunk) {
      uv_buf_t buf = uv_buf_init(wr->data.empty() ? nullptr : &wr->data[0],
                                 static_cast<unsigned>(wr->data.size()));
      r = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&c->handle),
                   &buf, 1, onWrite);
    } else {
      // Oversized payload: uv_buf_t's length is `unsigned`, so a single buf
      // would truncate a >= 4 GiB body. Split into <= 1 GiB segments handed to
      // ONE uv_write - the whole payload rides a single WriteReq and completes
      // with a single onWrite, so `terminal` still fires exactly once.
      std::vector<uv_buf_t> bufs;
      bufs.reserve((wr->data.size() / kMaxWriteChunk) + 1);
      for (size_t off = 0; off < wr->data.size(); off += kMaxWriteChunk) {
        size_t seg = std::min(kMaxWriteChunk, wr->data.size() - off);
        bufs.push_back(uv_buf_init(&wr->data[off], static_cast<unsigned>(seg)));
      }
      r = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&c->handle),
                   bufs.data(), static_cast<unsigned>(bufs.size()), onWrite);
    }
    if (r != 0) {
      c->pendingWrites--;
      delete wr;
      abortConnection(c);
      return;
    }
    // Opt-in outbound hard cap (responseBackpressureLimit) - the HTTP mirror
    // of wsBackpressureLimit: a peer that lets queued response bytes pile
    // past the cap is shed immediately instead of holding WriteReq buffers
    // until the responseTimeoutMs deadline. WS frames are governed by
    // wsBackpressureLimit in wsSend/the Ping path instead.
    if (limits_.responseBackpressureLimit && !c->isWebSocket &&
        tPendingBytes(c) > limits_.responseBackpressureLimit) {
      doClose(c);
    }
  }

  static void onWrite(uv_write_t* req, int status) {
    WriteReq* wr = static_cast<WriteReq*>(req->data);
    Connection* c = wr->conn;
    bool terminal = wr->terminal;
    delete wr;
    c->pendingWrites--;
    c->server->completeWrite(c, terminal, status);
  }

  // A queued write finished (uv: onWrite; uring: the WriteReq's last SEND
  // CQE). Shared core, in the exact order the uv callback always ran it.
  void completeWrite(Connection* c, bool terminal, int status) {
    c->writeTicks = 0;           // a write completed: the drain made progress
    c->lastWriteQueue = SIZE_MAX;  // re-baseline at the next sweep

    if (status != 0) {
      abortConnection(c);
      return;
    }

    if (terminal) {
      finishResponse(c);
    } else if (c->wantDrain) {
      if (tPendingBytes(c) < limits_.writeHighWaterMark) {
        c->wantDrain = false;
        queueNotify(c->reqId, kNotifyWritable);
      }
    }
    if (c->closeAfterFlush && c->pendingWrites == 0) closeAfterResponse(c);
  }

  // Response for the active request is fully flushed: either close or move on to the next pipelined request.
  void finishResponse(Connection* c) {
    if (c->closing) return;
    uint32_t oldId = c->reqId;
    globalRequests().erase(oldId);
    c->active = false;

    if (!c->reqKeepAlive) {
      if (c->pendingWrites == 0) closeAfterResponse(c);
      else c->closeAfterFlush = true;
      return;
    }

    // Reset per-request response state, keep any pipelined/buffered bytes.
    resetResponseState(c);
    if (batchOn_) {
      // Resume: slots still staged (or a parsed-ahead request) go first, with
      // no parse - the parser holds whatever follows them.
      if (c->stagedCount > 0 || c->aheadComplete) dispatchBatch(c, ParseStatus::NeedMore, /*parsed=*/false);
      else dispatchBatch(c, parseNext(c), /*parsed=*/true);
      return;
    }
    c->parser.reset();
    dispatchBatchSequential(c, parseNext(c));
  }

  // Corked variant of finishResponse: same per-request bookkeeping, but no write happened yet (the bytes sit in corkBuf) and the next pipelined request is surfaced by dispatchBatch's loop, not from here. A Connection: close response just flags the batch; the loop's tail closes after the flush.
  void completeCorkedResponse(Connection* c) {
    globalRequests().erase(c->reqId);
    c->active = false;
    if (!c->reqKeepAlive) {
      c->batchClose = true;
      return;
    }
    resetResponseState(c);
    if (!batchOn_) {
      c->parser.reset();
      return;
    }
    // Batched: the parser was reset when this request was staged and may
    // hold the next (partial or parsed-ahead) request - leave it. Hand JS the
    // next slot, or tell it the batch is done.
    if (c->stagedCount > 0) {
      c->batchPos++;
      if (batchControl_) *batchControl_ = c->batchPos;
      activateStaged(c);
    } else if (batchControl_) {
      *batchControl_ = c->batchPos + 1;
    }
  }

  // Flush the accumulated batch with one write. Tries synchronously straight from corkBuf (a full write keeps the buffer's capacity for the next batch); only a partial/backpressured remainder is copied out and queued.
  void flushCork(Connection* c) {
    if (c->corkBuf.empty() || c->closing) return;
    // A single huge corked response (respond() appends the whole frame to
    // corkBuf) can exceed one uv_buf_t; defer it to the queued path below,
    // which splits into <= 1 GiB segments (see kMaxWriteChunk).
    if (c->pendingWrites == 0 && c->corkBuf.size() <= kMaxWriteChunk) {
      int n = (c->batchClose && !c->tls && !c->isWebSocket)
                  ? tTryWriteLast(c, c->corkBuf.data(), c->corkBuf.size())
                  : tTryWrite(c, c->corkBuf.data(), c->corkBuf.size());
      if (n == static_cast<int>(c->corkBuf.size())) {
        c->corkBuf.clear();
        // Don't pin a large batch's capacity to an idle keep-alive connection
        // (same 16 KiB watermark as releaseScratch / the parser body / WS
        // message_).
        if (c->corkBuf.capacity() > 16384) c->corkBuf.shrink_to_fit();
        return;
      }
      if (n > 0) c->corkBuf.erase(0, static_cast<size_t>(n));
      // UV_EAGAIN / error: queue the remainder below (a real socket error surfaces through uv_write/onWrite exactly as on the uncorked path).
    }
    std::string out;
    out.swap(c->corkBuf);
    const bool was = c->corked;
    c->corked = false;  // the queued path, not the cork branch
    transportWrite(c, std::move(out), /*terminal=*/false);
    c->corked = was;
  }

  // Batched variant of the sequential loop below (batchOn_): every complete
  // pipelined request already buffered is parsed into a staged slot FIRST
  // (bounded by kMaxStaged; a Connection: close or Upgrade request ends the
  // batch, as nothing after it may be parsed yet), then JS gets ONE
  // onRequestBatch call for the active request plus the staged ones. JS
  // answers them in order; each synchronous completion
  // (completeCorkedResponse) activates the next slot and advances the
  // control cell so JS knows to continue; the first handler that goes async
  // stops the loop and the remaining slots wait for that response
  // (finishResponse resumes them). Everything else - corking, the
  // close-after-batch tail, 100-continue for a trailing partial request, 400
  // on a parse error (both only once every staged request is answered, so
  // the wire order holds) - is the sequential loop's logic. `parsed`: whether
  // `st` describes the parser's current state (false when the caller has
  // not parsed yet, e.g. a resume with slots still staged).
  void dispatchBatch(Connection* c, ParseStatus st, bool parsed = true) {
    if (!batchOn_) {
      if (!parsed) st = parseNext(c);
      dispatchBatchSequential(c, st);
      return;
    }
    c->corked = true;
    c->batchClose = false;
    if (c->aheadComplete) {  // a parsed-ahead request: stage it first (FIFO order is kept)
      c->aheadComplete = false;
      st = ParseStatus::Complete;
      parsed = true;
    }
    for (;;) {
      // 1. Stage what is already complete.
      while (parsed && st == ParseStatus::Complete && c->stagedCount < kMaxStaged) {
        if (stageRequest(c)) {  // close/upgrade: the batch ends here
          parsed = false;
          break;
        }
        st = parseNext(c);
      }
      c->aheadComplete = parsed && st == ParseStatus::Complete && c->stagedCount == kMaxStaged;
      if (c->stagedCount == 0) {
        if (parsed) handleParse(c, st);  // a partial request (100-continue) or an error
        break;
      }
      // 2. Activate the head slot (static routes answer right there, and
      //    may chain through several slots) and hand JS the rest as ONE
      //    batch: descriptors, the control cell and JS's slot index all
      //    count from the request that is active at the call.
      activateStaged(c);
      if (c->active) {
        c->batchPos = 0;
        if (batchControl_) *batchControl_ = 0;
        cb_.onRequestBatch(cb_.user, c, 1 + c->stagedCount);
      }
      if (c->closing || c->isWebSocket || c->batchClose) break;
      if (c->active) break;  // a handler went async; finishResponse resumes the rest
      // 3. Every slot answered synchronously: parse on.
      if (c->aheadComplete) {
        c->aheadComplete = false;
        st = ParseStatus::Complete;
      } else if (!parsed) {
        st = parseNext(c);
      }
      parsed = true;
      if (st != ParseStatus::Complete) {
        handleParse(c, st);
        break;
      }
    }
    c->corked = false;
    if (!c->closing) flushCork(c);
    if (c->batchClose && !c->closing) {
      if (c->pendingWrites == 0) closeAfterResponse(c);
      else c->closeAfterFlush = true;
    }
  }

  // Parse the next request: the bytes buffered while a response was in
  // flight (swapped into a local, as the sequential loop does, so a huge
  // pipelined backlog's capacity is released at scope exit), else whatever
  // the parser still holds.
  ParseStatus parseNext(Connection* c) {
    if (!c->pending.empty()) {
      std::string p;
      p.swap(c->pending);
      return c->parser.parse(p.data(), p.size());
    }
    return c->parser.parse(nullptr, 0);
  }

  // Move the parser's complete request into the next staged slot and reset
  // the parser for what follows. Returns true when nothing after it may be
  // parsed now: a Connection: close request, or an Upgrade request (what
  // follows is not HTTP if the upgrade succeeds).
  bool stageRequest(Connection* c) {
    if (c->staged.empty()) c->staged.resize(kMaxStaged);
    StagedRequest& sr = c->staged[(c->stagedHead + c->stagedCount) % kMaxStaged];
    c->stagedCount++;
    const bool upgrade = c->parser.findHeader("upgrade") != nullptr;
    sr.expectContinue = false;
    if (!c->sentContinue) {
      const char* exp = c->parser.findHeader("expect");
      if (exp && iequals(trimOWS(std::string_view(exp)), "100-continue")) sr.expectContinue = true;
    }
    sr.reqId = nextReqId();
    sr.method = c->parser.method;
    // Swap, not copy (see surfaceRequest): the slot's previous buffers become
    // the parser's scratch for the next request.
    sr.methodStr.swap(c->parser.methodStr);
    sr.path.swap(c->parser.path);
    sr.query.swap(c->parser.query);
    sr.headers.swap(c->parser.headers);
    sr.body.swap(c->parser.body);
    sr.isHead = (sr.method == Method::HEAD);
    sr.reqKeepAlive = c->parser.keepAlive;
    sr.reqHttp11 = c->parser.minorVersion >= 1;
    c->parser.reset();
    return !sr.reqKeepAlive || upgrade;
  }

  // The head staged slot becomes the active request: fields swapped in, id
  // registered, static routes answered right here (which, inside a corked
  // batch, completes it synchronously and activates the next slot in turn).
  void activateStaged(Connection* c) {
    StagedRequest& sr = c->staged[c->stagedHead];
    c->stagedHead = (c->stagedHead + 1) % kMaxStaged;
    c->stagedCount--;
    c->reqId = sr.reqId;
    c->method = sr.method;
    c->methodStr.swap(sr.methodStr);
    c->path.swap(sr.path);
    c->query.swap(sr.query);
    c->headers.swap(sr.headers);
    c->body.swap(sr.body);
    c->isHead = sr.isHead;
    c->reqKeepAlive = sr.reqKeepAlive;
    c->reqHttp11 = sr.reqHttp11;
    c->active = true;
    c->requestTicks = 0;
    globalRequests().insert(c->reqId, c);
    if (sr.expectContinue && !c->sentContinue) {
      // Same interim the sequential loop sends from handleParse (a client
      // that shipped the body with the head still gets it; Node does too).
      c->sentContinue = true;
      std::string cont = "HTTP/1.1 100 Continue\r\n\r\n";
      writeOut(c, std::move(cont), /*terminal=*/false);
    }
    if (!staticRoutes_.empty()) tryStaticRoute(c);
  }

  uint32_t nextReqId() {
    // Skip ids still bound to live requests: the uint32 counter wraps after
    // 2^32 requests (~12h at 100k rps) and a collision with a still-open
    // long-lived request (e.g. an SSE stream) would silently rebind it.
    auto& reqMap = globalRequests();
    uint32_t id;
    do {
      id = ++globalReqCounter();
    } while (id == 0 || reqMap.contains(id));
    return id;
  }

  // Per-request response state, reset between requests on a keep-alive
  // connection (the parser is handled by the caller: the sequential loop
  // resets it here, the batched loop at staging time).
  void resetResponseState(Connection* c) {
    c->responseStarted = false;
    c->responseEnded = false;
    c->chunkedResponse = false;
    c->bodylessStatus = false;
    c->declaredLen = -1;
    c->bodyBytesSent = 0;
    c->sentContinue = false;
    c->wantDrain = false;
    c->abortNotified = false;
  }

  // Dispatch parsed input, corking synchronous pipelined responses into one batched write (uWS-style): while complete requests are buffered and each handler responds before returning, responses accumulate in corkBuf and hit the socket as a single write when the input drains. Re-entrancy-safe by construction: request N+1 is surfaced HERE, below cb_.onRequest in the stack, only after handler N has returned - never from inside a respond()/end() crossing. Async handlers, upgrades, errors, and Connection: close all exit the loop and preserve their existing paths.
  void dispatchBatchSequential(Connection* c, ParseStatus st) {
    c->corked = true;
    c->batchClose = false;
    for (;;) {
      handleParse(c, st);
      if (c->closing || c->isWebSocket || c->batchClose) break;
      if (c->active) break;  // handler went async; respond() completes later
      if (st != ParseStatus::Complete) break;  // NeedMore: await more bytes
      // Response corked and completed synchronously - surface the next buffered pipelined request (completeCorkedResponse already reset the parser; reads cannot interleave while this loop runs).
      if (!c->pending.empty()) {
        std::string p;
        p.swap(c->pending);
        st = c->parser.parse(p.data(), p.size());
      } else {
        st = c->parser.parse(nullptr, 0);
      }
    }
    c->corked = false;
    if (!c->closing) flushCork(c);
    if (c->batchClose && !c->closing) {
      if (c->pendingWrites == 0) closeAfterResponse(c);
      else c->closeAfterFlush = true;
    }
  }

  // ---- read path ----

  static void onConnection(uv_stream_t* serverHandle, int status) {
    if (status != 0) return;
    Server* s = static_cast<Server*>(serverHandle->data);
    if (s->closeRequested_) return;  // no new work once shutting down
    Connection* c = new Connection();
    c->server = s;
    c->handle.data = c;
    uv_tcp_init(s->loop_, &c->handle);
    s->liveHandles_++;  // balanced by onCloseFree's decrement
    if (uv_accept(serverHandle, reinterpret_cast<uv_stream_t*>(&c->handle)) != 0) {
      uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
      return;
    }
    // Connection-flood defense: over the cap, accept then immediately close (libuv gives no way to refuse the accept itself).
    if (s->limits_.maxConnections && s->conns_.size() >= s->limits_.maxConnections) {
      uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
      return;
    }
#if defined(_WIN32)
    uv_tcp_nodelay(&c->handle, 1);  // POSIX inherits it from the listener (listen())
#endif
    s->attachConnection(c);
    uv_read_start(reinterpret_cast<uv_stream_t*>(&c->handle), onAlloc, onRead);
  }

  // Transport-neutral tail of accepting a connection: protocol state, TLS
  // session, registry. The caller then starts reads its own way.
  void attachConnection(Connection* c) {
    c->parser = HttpParser(limits_);
    if (tlsEnabled_) c->tls = new TlsSession(tlsCtx_.ctx());
    conns_.insert(c);
  }

  static void onAlloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf) {
#if defined(_WIN32)
    // IOCP holds the buffer in an outstanding overlapped read, so it must be
    // per-connection. new[] not std::string::resize: resize value-initializes,
    // and the memset made all 64 KiB resident for every connection.
    Connection* c = static_cast<Connection*>(handle->data);
    if (c->readBufSize < suggested) {
      c->readBuf.reset(new char[suggested]);
      c->readBufSize = suggested;
    }
    buf->base = c->readBuf.get();
    buf->len = static_cast<unsigned>(c->readBufSize);
#else
    // One receive buffer per loop thread, shared by every connection. Safe on
    // POSIX: libuv calls alloc_cb immediately before the synchronous read and
    // the bytes are fully consumed before the next alloc - the parser/pending
    // copy what they keep, and the WS parser's in-place unmasking finishes
    // inside the same read callback (see dispatchPlaintext). Uninitialized on
    // purpose: only pages the kernel actually fills become resident, and the
    // O(connections) x 64 KiB zero-filled footprint collapses to O(1).
    (void)handle;
    static thread_local std::unique_ptr<char[]> sharedBuf;
    static thread_local size_t sharedSize = 0;
    if (sharedSize < suggested) {
      sharedBuf.reset(new char[suggested]);
      sharedSize = suggested;
    }
    buf->base = sharedBuf.get();
    buf->len = static_cast<unsigned>(sharedSize);
#endif
  }

  static void onRead(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    Connection* c = static_cast<Connection*>(handle->data);
    Server* s = c->server;
    if (nread < 0) {
      s->onTransportEof(c);
      return;
    }
    if (nread == 0) return;
    s->onTransportData(c, buf->base, static_cast<size_t>(nread));
  }

  // EOF or a read error on the transport: notify an in-flight request / WS
  // exactly once, then tear the connection down.
  void onTransportEof(Connection* c) {
    if (c->isWebSocket) {
      // Fire onWsClose exactly once: set wsClosing before the impending doClose so its own 1006 guard can't re-fire it.
      if (!c->wsClosing && cb_.onWsClose)
        cb_.onWsClose(cb_.user, c, 1006);  // abnormal closure (§7.1.5)
      c->wsClosing = true;
      globalWebSockets().erase(c->wsId);
    } else if (c->active && !c->abortNotified) {
      // A request was awaiting its response: it's aborted.
      c->abortNotified = true;
      queueNotify(c->reqId, kNotifyAborted);
    }
    abortConnection(c);
  }

  // Bytes arrived on the transport (a uv read, or an io_uring recv into a
  // provided buffer). The buffer is consumed before this returns - the
  // parser/pending/TLS/WS layers copy what they keep (see onAlloc).
  void onTransportData(Connection* c, char* base, size_t nread) {
    Server* s = this;
    // Lingering close: the exchange is over and our FIN is out; whatever the
    // peer still writes (typically a request it sent before seeing the FIN)
    // is read and dropped so the kernel never answers it with a RST. The
    // peer's own FIN (onTransportEof) or kLingerMs ends the connection.
    if (c->lingering) return;
    c->idleTicks = 0;  // activity: reset the idle sweep counter

    if (c->tls) {
      // Ciphertext: pump through the TLS transform; decrypted bytes re-enter the exact plaintext path below via dispatchPlaintext. Outbound ciphertext (handshake flights, key updates, alerts) must go to the wire even when the pump reports failure.
      std::string cipherOut;
      bool ok = c->tls->onCiphertext(
          base, nread,
          [&](const char* d, size_t n) {
            if (!c->closing) s->dispatchPlaintext(c, d, n);
          },
          cipherOut);
      if (!c->closing && !cipherOut.empty())
        s->transportWrite(c, std::move(cipherOut), /*terminal=*/false);
      if (!ok && !c->closing) {
        // Fatal TLS error or clean close_notify: same bookkeeping as EOF - notify an in-flight request/WS exactly once, then tear down.
        if (c->isWebSocket) {
          if (!c->wsClosing && s->cb_.onWsClose)
            s->cb_.onWsClose(s->cb_.user, c, 1006);
          c->wsClosing = true;
          globalWebSockets().erase(c->wsId);
        }
        s->abortConnection(c);
      }
      return;
    }
    s->dispatchPlaintext(c, base, nread);
  }

  // Plaintext ingestion - identical for direct TCP reads and decrypted TLS records. May tear the connection down (doClose sets c->closing; the Connection object itself stays alive until uv's close callback).
  void dispatchPlaintext(Connection* c, const char* data, size_t len) {
    if (c->isWebSocket) {
      // Zero-copy WS receive: the parser unmasks complete frames IN PLACE in
      // this buffer, so feedWebSocket takes mutable bytes. The const here is
      // only an artifact of this shared signature — both actual sources are
      // mutable storage we own: the loop's shared receive buffer for
      // plaintext reads (onAlloc hands it to uv_read; per-connection on
      // win32) and TlsSession::onCiphertext's local
      // decrypt scratch (a stack buffer) for TLS. Neither is reused until
      // the next uv_read / TLS record, after consume() has returned.
      feedWebSocket(c, const_cast<char*>(data), len);
      return;
    }
    if (c->active) {
      // A response is in flight; buffer bytes for after it completes. Cap the buffer so a client can't pipeline unbounded requests and exhaust memory while we're busy (the parser enforces per-request limits, but this bounds the not-yet-parsed backlog). A response is already in flight, so we can't inject an error status - hard-close the flood.
      if (c->pending.size() + len > maxPending_) {
        doClose(c);
        return;
      }
      c->pending.append(data, len);
      return;
    }
    ParseStatus st = c->parser.parse(data, len);
    dispatchBatch(c, st);
  }

  // `data` is mutable: the parser's zero-copy fast path unmasks complete
  // single-frame messages in place and the onWsMessage payload may be a view
  // into it. That view stays valid across everything the JS callback can do
  // (wsSend/wsClose/doClose write to other buffers; nothing re-enters a read)
  // because reads are sequential on the loop: the read buffer is not touched
  // again until the next uv_read/TLS record, after consume() returns.
  void feedWebSocket(Connection* c, char* data, size_t len) {
    if (c->wsClosing || !c->wsParser) return;
    // Set when an inbound message fails inflate/UTF-8 (RFC 7692/6455): the parser itself succeeds, so surface the close code out-of-band.
    uint16_t pmdFail = 0;
    bool ok = c->wsParser->consume(
        reinterpret_cast<uint8_t*>(data), len,
        [&](std::string_view payload, bool isBinary, bool compressed) {
          // Stop delivering once the connection is closing: JS may call
          // wsClose() from inside onWsMessage (which sets wsClosing, fires
          // onWsClose, and erases the wsId), yet consume() keeps handing us the
          // remaining complete frames already in this read buffer - delivering
          // them would fire onWsMessage on a closed/gone socket. The control
          // path already guards Ping this way; mirror it here.
          if (c->wsClosing || c->closing) return;
          if (compressed && c->pmd) {
            // Inflate (hard output cap = zip-bomb defense), then UTF-8-validate text post-inflate (the parser skipped it for compressed frames).
            std::string inflated;
            if (!c->pmd->inflateMessage(payload, inflated)) {
              pmdFail = 1009;  // over the decompressed cap or corrupt stream
              return;
            }
            if (!isBinary && !isValidUtf8(inflated)) {
              pmdFail = 1007;  // invalid UTF-8 after inflate
              return;
            }
            if (cb_.onWsMessage)
              cb_.onWsMessage(cb_.user, c, inflated.data(), inflated.size(), isBinary);
            return;
          }
          if (cb_.onWsMessage)
            cb_.onWsMessage(cb_.user, c, payload.data(), payload.size(), isBinary);
        },
        [&](WsOpcode op, std::string_view payload) {
          switch (op) {
            case WsOpcode::Ping: {
              if (c->wsClosing) break;
              // Respond with Pong echoing the payload (§5.5.2/§5.5.3)
              std::string out;
              encodeFrame(out, WsOpcode::Pong, payload);
              writeOut(c, std::move(out), /*terminal=*/false);
              // Bound the outgoing queue: a peer flooding Pings while never reading our Pongs would otherwise grow libuv's write buffer without limit (OOM). Shed it, same as wsSend's backpressure cap.
              size_t q = tPendingBytes(c);
              if (limits_.wsBackpressureLimit && q > limits_.wsBackpressureLimit)
                wsClose(c, 1013, "", 0);
              break;
            }
            case WsOpcode::Pong:
              break;  // unsolicited pong allowed (§5.5.3)
            case WsOpcode::Close: {
              // Fire onWsClose + echo exactly once (guard against two Close frames arriving in a single read).
              if (!c->wsClosing) {
                c->wsClosing = true;
                uint16_t code = parseCloseCode(payload);
                if (cb_.onWsClose) cb_.onWsClose(cb_.user, c, code);
                std::string out;
                encodeFrame(out, WsOpcode::Close, payload);  // echo (§5.5.1)
                c->reqKeepAlive = false;
                globalWebSockets().erase(c->wsId);
                writeOut(c, std::move(out), /*terminal=*/true);
              }
              break;
            }
            default:
              break;
          }
        });
    if (!ok) {
      // Protocol failure: fail the connection WITH a Close frame first (§7.1.7 SHOULD) carrying the parser's failure code - 1009 for an oversized message, 1007 for invalid UTF-8, 1002 otherwise. wsClose sets wsClosing, fires onWsClose once, erases the ws registry entry, and terminal-writes the Close frame - the flush-then-close machinery (finishResponse -> !reqKeepAlive -> doClose) tears the TCP connection down right after it drains. The parser's failed latch plus the wsClosing early-return above stop any already-buffered bytes from being re-fed. If wsClosing was already set (violation raced a close handshake in flight) this is a no-op and the pending terminal write finishes the job.
      wsClose(c, c->wsParser->failCode(), "", 0);
    } else if (pmdFail && !c->wsClosing) {
      // Inflate/UTF-8 failure on a compressed message: close with the RFC 7692/6455 code (1009 too-big, 1007 bad UTF-8) via the same flush-then-close machinery as a parser failure.
      wsClose(c, pmdFail, "", 0);
    }
  }

  void handleParse(Connection* c, ParseStatus st) {
    if (c->closing) return;

    // Answer Expect: 100-continue before the (already fully-buffered) body - the parser reads the whole body before Complete, so on NeedMore with the head parsed we know a body is pending.
    if (!c->sentContinue && c->parser.headParsed()) {
      const char* exp = c->parser.findHeader("expect");
      if (exp && iequals(trimOWS(std::string_view(exp)), "100-continue")) {
        c->sentContinue = true;
        std::string cont = "HTTP/1.1 100 Continue\r\n\r\n";
        writeOut(c, std::move(cont), /*terminal=*/false);
      }
    }

    switch (st) {
      case ParseStatus::NeedMore:
        return;
      case ParseStatus::Error:
        sendErrorAndClose(c, c->parser.errorStatus);
        return;
      case ParseStatus::Complete:
        surfaceRequest(c);
        return;
    }
  }

  void surfaceRequest(Connection* c) {
    // Snapshot the request so the reqId stays valid across async responses. Skip ids still bound to live requests: the uint32 counter wraps after 2^32 requests (~12h at 100k rps) and a collision with a still-open long-lived request (e.g. an SSE stream) would silently rebind it.
    c->reqId = nextReqId();
    c->method = c->parser.method;
    // Swap, don't copy: the parser is reset before its next request anyway (reset() clears every swapped-in field, keeping its heap capacity), so the previous snapshot's buffers become the parser's scratch for the NEXT request - snapshots are allocation-free on a warm connection.
    c->methodStr.swap(c->parser.methodStr);
    c->path.swap(c->parser.path);
    c->query.swap(c->parser.query);
    c->headers.swap(c->parser.headers);
    c->body.swap(c->parser.body);
    c->isHead = (c->method == Method::HEAD);
    c->reqKeepAlive = c->parser.keepAlive;
    c->reqHttp11 = c->parser.minorVersion >= 1;
    c->active = true;
    c->requestTicks = 0;  // the request-receive budget is per request
    globalRequests().insert(c->reqId, c);

    // Static route: answered right here with the SAME respond() the binding
    // calls, so framing, HEAD handling, corking and keep-alive are identical -
    // the only thing skipped is the trip through JS.
    if (!staticRoutes_.empty() && tryStaticRoute(c)) return;
    if (cb_.onRequest) cb_.onRequest(cb_.user, c);
  }

  bool tryStaticRoute(Connection* c) {
    auto it = staticRoutes_.find(c->path);
    if (it == staticRoutes_.end()) return false;
    const int32_t m = static_cast<int32_t>(c->method);
    for (const StaticRoute& r : it->second) {
      if (r.method != m) continue;
      respond(c, r.tpl.status, r.tpl.headers, r.tpl.customCL, r.body.data(), r.body.size());
      return true;
    }
    return false;
  }

  static const std::string& emptyHeaders() {
    static const std::string empty;
    return empty;
  }

  void sendErrorAndClose(Connection* c, int status) {
    c->reqKeepAlive = false;
    std::string& out = c->scratch;
    out.clear();
    appendStatusLine(out, status);
    out += httpDateLine();
    out += "Content-Length: 0\r\nConnection: close\r\n\r\n";
    c->responseEnded = true;
    writeOutView(c, out, /*terminal=*/true);
  }

  // Orderly end of the last HTTP exchange on a connection (Connection: close,
  // HTTP/1.0, or an error response): half-close and linger, never an
  // immediate close(). The FIN normally rode with the response bytes
  // (tTryWriteLast); a last write that went the queued way gets it here once
  // the queue has drained. The socket then stays open, its input discarded,
  // until the peer's FIN (or kLingerMs, onSweep) - RFC 9112 §9.6: a server
  // that closes outright answers a request the peer had already written
  // with a RST, and that RST can discard the response still sitting unread
  // in the peer's buffer. Measured with autocannon (which writes the next
  // request the moment a response completes, before it has seen the FIN):
  // the immediate close reconnected twice per cycle and ran at a quarter of
  // the rate of servers that linger. TLS keeps its close_notify sequence and
  // WebSockets their Close-frame sequence (doClose).
  void closeAfterResponse(Connection* c) {
    if (c->closing || c->lingering) return;
    if (c->tls || c->isWebSocket) {
      doClose(c);
      return;
    }
    if (!c->finSent) {
#if defined(__linux__)
      if (kind_ == TransportKind::Uring) {
        // Nothing of ours is queued for this fd (pendingWrites == 0): the FIN
        // can go synchronously.
        if (c->ring.fd < 0 || ::shutdown(c->ring.fd, SHUT_WR) != 0) {
          doClose(c);
          return;
        }
        c->finSent = true;
      } else
#endif
      {
        c->shutdownReq.data = c;
        if (uv_shutdown(&c->shutdownReq, reinterpret_cast<uv_stream_t*>(&c->handle), onShutdownDone) != 0) {
          doClose(c);
          return;
        }
        // finSent is set by onShutdownDone; the connection lingers meanwhile.
      }
    }
    c->lingering = true;
    c->lingerTicks = 0;
  }

  static void onShutdownDone(uv_shutdown_t* req, int status) {
    Connection* c = static_cast<Connection*>(req->data);
    // A teardown that raced the shutdown cancels it (UV_ECANCELED) before the
    // close callback frees the Connection, so `c` is still alive here.
    if (c->closing) return;
    if (status == 0) {
      c->finSent = true;
      return;
    }
    c->server->doClose(c);  // peer already gone: nothing left to linger for
  }

  void abortConnection(Connection* c) {
    // Hard teardown (read error/EOF/write error): drop the socket now. Any in-flight writes reference WriteReq buffers, not the connection body, and their completion callbacks tolerate a closing handle.
    doClose(c);
  }

  void doClose(Connection* c) {
    if (tIsClosing(c)) return;
    // Best-effort close_notify on an established TLS session (truncation detection for the peer). uv_try_write: synchronous, non-blocking, no bookkeeping - if the kernel buffer is full the alert is simply lost, which is exactly the semantics "best effort" means here.
    if (c->tls && !c->closing) {
      std::string bye;
      c->tls->shutdown(bye);
      if (!bye.empty()) tTryWrite(c, bye.data(), bye.size());
    }
    c->closing = true;
    // An HTTP request that was surfaced to a handler and never answered owes JS exactly one onAborted (server shutdown, timeout sweep, write error), or 'close' listeners and their resources (SSE intervals, monitors) leak. closing is already set, so a re-entrant respond() from JS is a no-op.
    if (c->active && !c->isWebSocket && !c->abortNotified) {
      c->abortNotified = true;
      queueNotify(c->reqId, kNotifyAborted);
    }
    globalRequests().erase(c->reqId);
    if (c->isWebSocket) {
      // A WebSocket torn down without an explicit wsClose (server shutdown, socket error) still owes JS exactly one onWsClose so wrappers/handlers don't leak. wsClosing guards against a double-fire.
      if (!c->wsClosing && cb_.onWsClose) {
        c->wsClosing = true;
        cb_.onWsClose(cb_.user, c, 1006);  // abnormal closure (§7.1.5)
      }
      globalWebSockets().erase(c->wsId);
    }
    conns_.erase(c);
    tCloseConn(c);
  }

  static void onCloseFree(uv_handle_t* handle) {
    Connection* c = static_cast<Connection*>(handle->data);
    c->server->freeConnection(c);
  }

  // The connection's transport resources are gone (uv close callback, or the
  // last io_uring CQE referencing it): free it and account the handle.
  void freeConnection(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      // Writes never issued (or cancelled before issue) are still queued.
      WriteReq* wr = static_cast<WriteReq*>(c->ring.wqHead);
      while (wr) {
        WriteReq* next = wr->next;
        delete wr;
        wr = next;
      }
      c->ring.wqHead = c->ring.wqTail = nullptr;
      if (uring_) uring_->release();
    }
#endif
    delete c;
    // One fewer live transport handle; may complete a pending server shutdown.
    liveHandles_--;
    checkFullyClosed();
  }

  // Close callback for the listener and sweep timer (Server-owned handles).
  static void onServerHandleClosed(uv_handle_t* handle) {
    Server* s = static_cast<Server*>(handle->data);
    s->liveHandles_--;
    s->checkFullyClosed();
  }

  // When a shutdown was requested AND every uv handle has been reaped, the Server is safe to delete. Frees the C++ object and notifies the binding (which then releases its per-server JS handles) - no leak across serve()/close() cycles.
  void checkFullyClosed() {
    if (!closeRequested_ || liveHandles_ > 0) return;
    void (*cb)(void*) = onClosed_;
    void* user = onClosedUser_;
    delete this;
    if (cb) cb(user);
  }

  // Periodic sweep enforcing the two receive timeouts and the response-delivery deadline. WebSocket connections are exempt from the receive timeouts (they legitimately idle between messages; RFC 6455 ping/pong or the app's own idle policy governs them), as are connections whose request is surfaced to a handler (response time is the app's business) - but NOT from the delivery deadline below.
  //  - idleTimeoutMs: no bytes at all for the window -> hard close.
  //  - requestTimeoutMs: one request has been arriving for longer than the
  //    budget, however slowly -> 408 + close (slow-drip slowloris defense;
  //    idleTicks alone is defeated by one byte per idle window).
  //  - responseTimeoutMs: queued outbound bytes have made no progress for the
  //    whole budget -> hard close (slow-read defense, see below).
  static void onSweep(uv_timer_t* timer) {
    Server* s = static_cast<Server*>(timer->data);
    const uint32_t idleLimit = static_cast<uint32_t>(
        (s->limits_.idleTimeoutMs + s->sweepMs_ - 1) / s->sweepMs_);
    const uint32_t reqLimit = static_cast<uint32_t>(
        (s->limits_.requestTimeoutMs + s->sweepMs_ - 1) / s->sweepMs_);
    const uint32_t respLimit = static_cast<uint32_t>(
        (s->limits_.responseTimeoutMs + s->sweepMs_ - 1) / s->sweepMs_);
    uint32_t lingerLimit = static_cast<uint32_t>((kLingerMs + s->sweepMs_ - 1) / s->sweepMs_);
    if (lingerLimit == 0) lingerLimit = 1;
    std::vector<Connection*> stale;
    std::vector<Connection*> overdue;
    std::vector<Connection*> stalled;
    for (Connection* c : s->conns_) {
      if (c->closing) continue;
      // Lingering close (closeAfterResponse): the peer has our FIN and owes
      // its own; one that never closes is cut at the deadline. Nothing of
      // ours is queued on such a connection, so no other timeout applies.
      if (c->lingering) {
        if (++c->lingerTicks >= lingerLimit) stale.push_back(c);
        continue;
      }
      // Response-delivery deadline (slow-read DoS defense). The `active`
      // exemption below is right for a handler that hasn't answered yet, but
      // once bytes are QUEUED the engine owns them: a peer that stops reading
      // (or pins a zero TCP receive window) would otherwise hold its WriteReq
      // buffers, kernel socket buffers, and fd forever - active never clears
      // because the terminal write never flushes, so BOTH receive timeouts
      // skip it permanently. Progress is measured as the outbound queue
      // SHRINKING between sweeps (plus write completions via onWrite):
      // completion alone is a trap - one large respond() is a single
      // uv_write that only completes when the whole body has drained, so a
      // steadily-reading slow client (weak link, rate-limited download)
      // would be shed mid-transfer despite continuous progress. A stalled /
      // zero-window peer never shrinks the queue and is still shed at the
      // budget. Applies to WebSockets too: a stalled consumer under
      // wsBackpressureLimit that the app stops sending to is otherwise held
      // forever, and a stalled Close-frame flush (closeAfterFlush) likewise.
      // (Known residual, same as nginx's send_timeout semantics: a peer
      // draining a token amount per sweep window resets the budget and can
      // hold its memory - maxConnections / responseBackpressureLimit bound
      // that; see THREAT_MODEL.)
      if (s->limits_.responseTimeoutMs && c->pendingWrites > 0) {
        const size_t q = s->tPendingBytes(c);
        if (q < c->lastWriteQueue) {
          c->writeTicks = 0;  // bytes drained since the last sweep
        } else if (++c->writeTicks >= respLimit) {
          c->lastWriteQueue = q;
          stalled.push_back(c);
          continue;
        }
        c->lastWriteQueue = q;
      }
      if (c->isWebSocket || c->active) continue;
      if (s->limits_.idleTimeoutMs && ++c->idleTicks >= idleLimit) {
        stale.push_back(c);
        continue;
      }
      if (s->limits_.requestTimeoutMs) {
        // A TLS handshake in progress counts as mid-request: the same requestTimeoutMs budget bounds handshake slow-drip (a stalled or byte-trickled ClientHello) with no extra knob.
        bool mid = c->parser.midRequest() || (c->tls && !c->tls->handshakeDone());
        if (!mid)
          c->requestTicks = 0;
        else if (++c->requestTicks >= reqLimit)
          overdue.push_back(c);
      }
    }
    // Mutations deferred: sendErrorAndClose/doClose can erase from conns_ (synchronously on a uv_write failure), which would invalidate the loop.
    for (Connection* c : stale) s->doClose(c);
    for (Connection* c : overdue) {
      // No usable channel for a 408 before the handshake finished.
      if (c->tls && !c->tls->handshakeDone()) s->doClose(c);
      else s->sendErrorAndClose(c, 408);
    }
    // The peer isn't reading, so no error response can reach it: hard close.
    for (Connection* c : stalled) s->doClose(c);
  }

  // ---- transport seam ----
  // Every place the connection machinery touches the socket goes through one
  // of these; the uv bodies are the original code, the uring bodies live in
  // the block below. A per-server byte, tested in ~10 inline helpers: no
  // virtual dispatch on the hot path, and the uring arm compiles out
  // entirely off Linux.

  static const char*& transportReasonSlot() {
    static const char* reason = "platform";
    return reason;
  }

  // Synchronous non-blocking write of one buffer: bytes written (>= 0),
  // UV_EAGAIN when the socket would block, or a negative errno.
  int tTryWrite(Connection* c, const char* p, size_t n) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      ssize_t r = ::send(c->ring.fd, p, n, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (r >= 0) return static_cast<int>(r);
      if (errno == EAGAIN || errno == EWOULDBLOCK) return UV_EAGAIN;
      return -errno;
    }
#endif
    uv_buf_t b = uv_buf_init(const_cast<char*>(p), static_cast<unsigned>(n));
    return uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
  }

  // The last bytes of a Connection: close response (and the whole corked
  // batch when its last response closes): put our FIN in the SAME segment as
  // the data. Sent as two segments a few microseconds apart, a fast peer
  // (wrk, oha) reads the response and closes before the FIN lands, becomes
  // the active closer, and holds the TIME_WAIT - on macOS, with no port
  // reuse, a churning client then drains its 16k ephemeral ports and the
  // connection rate collapses (measured on loopback: 20k conn/s over 10 s
  // decaying to 5.8k over 40 s, against 25.7k for servers whose FIN rides
  // with the data). macOS: send(MSG_EOF) does data + FIN in one syscall (a
  // short send applies no EOF, so the queued path stays correct). Linux:
  // send(MSG_MORE) holds the segment and shutdown(SHUT_WR) piggybacks the FIN
  // on it. Same return contract as tTryWrite; TLS connections are excluded
  // (close_notify must precede the FIN and goes through doClose).
  int tTryWriteLast(Connection* c, const char* p, size_t n) {
#if defined(__APPLE__) || defined(__linux__)
    int fd = -1;
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) fd = c->ring.fd;
    else
#endif
    {
      uv_os_fd_t ofd;
      if (uv_fileno(reinterpret_cast<uv_handle_t*>(&c->handle), &ofd) == 0) fd = static_cast<int>(ofd);
    }
    if (fd < 0) return tTryWrite(c, p, n);
#if defined(__APPLE__)
    // TCP_NOPUSH holds the bytes (a segment shorter than the MSS is not
    // pushed while it is set); with the option cleared again, shutdown(SHUT_WR)
    // queues the FIN and runs tcp_output, which emits the held data + FIN as
    // ONE segment. Without the hold XNU pushes the data segment first and the
    // FIN follows on its own, and a fast peer still closes first ~5% of the
    // time. Two XNU facts shape the sequence: clearing TCP_NOPUSH does not
    // by itself run tcp_output (the bytes would sit until close()), and a
    // send(MSG_EOF) under TCP_NOPUSH stays held for the same reason - both
    // were masked by the immediate close() this path used to end with; the
    // socket now lingers open (closeAfterResponse).
    int on = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &on, sizeof(on));
    ssize_t r = ::send(fd, p, n, MSG_DONTWAIT);
    int off = 0;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &off, sizeof(off));
    if (r == static_cast<ssize_t>(n)) {
      ::shutdown(fd, SHUT_WR);
      c->finSent = true;
    }
    // short send: the remainder goes the queued way, uncorked; its completion
    // sends the FIN (closeAfterResponse).
#else
    ssize_t r = ::send(fd, p, n, MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL);
    if (r == static_cast<ssize_t>(n)) {
      ::shutdown(fd, SHUT_WR);
      c->finSent = true;
    }
#endif
    if (r >= 0) return static_cast<int>(r);
    if (errno == EAGAIN || errno == EWOULDBLOCK) return UV_EAGAIN;
    return -errno;
#else
    return tTryWrite(c, p, n);
#endif
  }

  // A terminal write that ends the connection, eligible for the coalesced FIN.
  bool lastWrite(Connection* c, bool terminal) const {
    return terminal && !c->reqKeepAlive && !c->tls && !c->isWebSocket;
  }

  // Bytes queued for the socket that the kernel has not accepted yet - the
  // backpressure and slow-read-progress signal at every one of its readers.
  size_t tPendingBytes(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) return c->ring.pendingBytes;
#endif
    return uv_stream_get_write_queue_size(reinterpret_cast<uv_stream_t*>(&c->handle));
  }

  bool tIsClosing(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) return c->ring.state >= 2;
#endif
    return uv_is_closing(reinterpret_cast<uv_handle_t*>(&c->handle)) != 0;
  }

  // Begin tearing the socket down; freeConnection runs once the transport is
  // done with it (uv close callback / last CQE).
  void tCloseConn(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      uringCloseConn(c);
      return;
    }
#endif
    uv_read_stop(reinterpret_cast<uv_stream_t*>(&c->handle));
    uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
  }

  bool tPeerName(Connection* c, struct sockaddr_storage* addr, int* len) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) {
      socklen_t sl = static_cast<socklen_t>(*len);
      if (::getpeername(c->ring.fd, reinterpret_cast<sockaddr*>(addr), &sl) != 0) return false;
      *len = static_cast<int>(sl);
      return true;
    }
#endif
    return uv_tcp_getpeername(&c->handle, reinterpret_cast<sockaddr*>(addr), len) == 0;
  }

  bool tBoundName(struct sockaddr_storage* addr, int* len) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring && listenFd_ >= 0) {
      socklen_t sl = static_cast<socklen_t>(*len);
      if (::getsockname(listenFd_, reinterpret_cast<sockaddr*>(addr), &sl) != 0) return false;
      *len = static_cast<int>(sl);
      return true;
    }
#endif
    return uv_tcp_getsockname(&tcp_, reinterpret_cast<sockaddr*>(addr), len) == 0;
  }

  // The uring listener (the uv listener handle is closed by the caller).
  void tCloseListener() {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) uringCloseListener();
#endif
  }

#if defined(__linux__)
  // ---- io_uring arm ----
  // One ring per loop thread (UringLoop), shared by every uring Server on
  // it. The Server owns its listening fd and its connections' fds; the
  // kernel owns the receive buffers (provided-buffer ring) and hands one to
  // us per completed recv. Lifetime rule: a Connection is freed only when
  // state == 3 (its CLOSE completed) AND inflight == 0 (every SQE that named
  // it has completed), so no CQE can ever refer to freed memory.

 public:
  // Public: the binding registers UringLoop::shutdownForThread as the
  // per-thread environment cleanup hook.
  struct UringLoop {
    uring::Ring<uring::LinuxSys> ring;
    uring::BufRing<uring::LinuxSys> bufs;
    uv_loop_t* loop = nullptr;
    uv_poll_t poll;
    uv_prepare_t prepare;
    int refs = 0;         // listening servers + live connections (ref/unref the poll handle)
    bool pollRef = false;
    bool dead = false;    // io_uring_enter started failing: no new uring work
    bool inReap = false;
    int closedHandles = 0;
    std::vector<Connection*> rearm;  // multishot recvs to re-issue after a reap round
    std::unordered_set<Server*> servers;
    int emfileFd = -1;

    static UringLoop*& slot() {
      static thread_local UringLoop* p = nullptr;
      return p;
    }

    static UringLoop* get(uv_loop_t* loop) {
      UringLoop*& s = slot();
      if (s) return s->dead ? nullptr : s;
      auto* u = new UringLoop();
      u->loop = loop;
      if (u->ring.open(uring::kSqEntries, uring::kSetupFlags, uring::kCqEntries) < 0) {
        delete u;
        return nullptr;
      }
      if (u->bufs.init(u->ring, uring::kBufGroup, uring::kBufCount, uring::kBufSize) < 0) {
        u->ring.close();
        delete u;
        return nullptr;
      }
      u->poll.data = u;
      if (uv_poll_init(loop, &u->poll, u->ring.fd()) != 0) {
        u->bufs.destroy(u->ring);
        u->ring.close();
        delete u;
        return nullptr;
      }
      u->prepare.data = u;
      uv_prepare_init(loop, &u->prepare);
      uv_prepare_start(&u->prepare, onPrepare);
      uv_unref(reinterpret_cast<uv_handle_t*>(&u->prepare));
      uv_poll_start(&u->poll, UV_READABLE, onReadable);
      uv_unref(reinterpret_cast<uv_handle_t*>(&u->poll));
      u->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      s = u;
      return u;
    }

    // The poll handle keeps the process alive exactly when a listener or a
    // connection exists - libuv's active-handle rule, reproduced.
    void addRef() {
      if (++refs == 1 && !pollRef) {
        uv_ref(reinterpret_cast<uv_handle_t*>(&poll));
        pollRef = true;
      }
    }
    void release() {
      if (--refs == 0 && pollRef) {
        uv_unref(reinterpret_cast<uv_handle_t*>(&poll));
        pollRef = false;
      }
    }

    // Next SQE; the submission ring is flushed inline when full, so an SQE is
    // never dropped. nullptr only once the ring is dead.
    uring::abi::io_uring_sqe* sqe() {
      if (dead) return nullptr;
      uring::abi::io_uring_sqe* s = ring.sqe();
      if (s) return s;
      if (!flush()) return nullptr;
      return ring.sqe();
    }

    // Submit pending SQEs (no wait). False once the ring is dead.
    bool flush() {
      if (dead) return false;
      if (ring.pending() == 0) return true;
      int r = ring.enter(0, 0);
      if (r < 0 && r != -EINTR && r != -EAGAIN && r != -EBUSY) {
        die();
        return false;
      }
      return true;
    }

    void die() {
      if (dead) return;
      dead = true;
      std::fprintf(stderr, "[morojs-engine] io_uring_enter failed; aborting io_uring connections on this thread\n");
      std::vector<Server*> srvs(servers.begin(), servers.end());
      for (Server* s : srvs) s->uringRingDied();
    }

    static void onPrepare(uv_prepare_t* h) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      // Anything queued outside a reap round (sweep-timer closes, async JS
      // responses that took the queued path) goes to the kernel before the
      // loop blocks.
      if (u->ring.pending()) u->flush();
    }

    static void onReadable(uv_poll_t* h, int status, int) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      if (status < 0) return;
      u->reap();
    }

    // Bounded reap: run deferred task work + submit in ONE enter, dispatch
    // every completion, re-arm starved multishot recvs, repeat while the
    // dispatch produced new SQEs - at most 8 rounds so timers and JS never
    // starve behind a busy ring.
    void reap() {
      if (inReap || dead) return;
      inReap = true;
      for (int round = 0; round < 8 && !dead; round++) {
        if (ring.pending() || ring.taskWorkPending() || ring.cqOverflowed()) {
          int r = ring.enter(0, uring::abi::IORING_ENTER_GETEVENTS);
          if (r < 0 && r != -EINTR && r != -EAGAIN && r != -EBUSY) {
            die();
            break;
          }
        }
        unsigned n = ring.forEachCqe([this](const uring::abi::io_uring_cqe& c) { dispatch(c); });
        rearmStarved();
        if (n == 0 && ring.pending() == 0) break;
      }
      if (!dead && ring.pending()) flush();
      inReap = false;
    }

    void rearmStarved() {
      if (rearm.empty()) return;
      std::vector<Connection*> list;
      list.swap(rearm);
      for (Connection* c : list) {
        if (c->ring.state < 2 && !c->ring.recvArmed) c->server->uringArmRecv(c);
      }
    }

    void dispatch(const uring::abi::io_uring_cqe& cqe) {
      const uring::Tag t = uring::tagOf(cqe.user_data);
      void* p = uring::ptrOf(cqe.user_data);
      switch (t) {
        case uring::kTagRecv: {
          Connection* c = static_cast<Connection*>(p);
          c->server->onRecvCqe(c, cqe);
          c->server->uringFreeIfDone(c);
          break;
        }
        case uring::kTagSend: {
          WriteReq* wr = static_cast<WriteReq*>(p);
          Connection* c = wr->conn;
          c->server->onSendCqe(wr, cqe.res);
          c->server->uringFreeIfDone(c);
          break;
        }
        case uring::kTagCancel: {
          Connection* c = static_cast<Connection*>(p);
          c->ring.inflight--;
          c->server->uringFreeIfDone(c);
          break;
        }
        case uring::kTagClose: {
          Connection* c = static_cast<Connection*>(p);
          c->ring.inflight--;
          c->ring.state = 3;
          c->server->uringFreeIfDone(c);
          break;
        }
        case uring::kTagAccept:
          static_cast<Server*>(p)->onAcceptCqe(cqe.res, uring::hasMore(cqe));
          break;
        case uring::kTagListenerCancel:
        case uring::kTagListenerClose:
          static_cast<Server*>(p)->onListenerCqe(t == uring::kTagListenerClose);
          break;
        default:
          break;
      }
    }

    // Environment teardown for this thread (registered by the binding when
    // the first uring server is created; runs AFTER every server's own
    // cleanup hook, so their cancel/close completions were reaped first).
    static void shutdownForThread() {
      UringLoop*& s = slot();
      if (!s) return;
      UringLoop* u = s;
      s = nullptr;
      uv_close(reinterpret_cast<uv_handle_t*>(&u->poll), onHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&u->prepare), onHandleClosed);
      while (u->closedHandles < 2) uv_run(u->loop, UV_RUN_ONCE);
      if (u->emfileFd >= 0) ::close(u->emfileFd);
      u->bufs.destroy(u->ring);
      u->ring.close();
      delete u;
    }
    static void onHandleClosed(uv_handle_t* h) {
      static_cast<UringLoop*>(h->data)->closedHandles++;
    }
  };

 private:
  int uringListen(const sockaddr_storage& addr) {
    const socklen_t len = addr.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    int on = 1;
    // Mirror uv__tcp_bind: SO_REUSEADDR always, dual-stack for AF_INET6,
    // SO_REUSEPORT when asked for.
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (addr.ss_family == AF_INET6) {
      int off = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }
    if (limits_.reusePort) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    // TCP_NODELAY on the listener is inherited by every accepted socket
    // (Linux clones the listener's tcp_sock, nonagle included; verified by
    // test/uring-unit.cpp), which saves the per-accept setsockopt the uv arm
    // pays through uv_tcp_nodelay.
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), len) < 0) {
      int e = -errno;
      ::close(fd);
      return e;
    }
    if (::listen(fd, limits_.backlog) < 0) {
      int e = -errno;
      ::close(fd);
      return e;
    }
    listenFd_ = fd;
    liveHandles_++;  // balanced when the listener's CLOSE completes
    uring_->addRef();
    uring_->servers.insert(this);
    uringArmAccept();
    return 0;
  }

  void uringArmAccept() {
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (!s) return;
    uring::prepAccept(s, listenFd_, SOCK_NONBLOCK | SOCK_CLOEXEC, /*multishot=*/true);
    s->user_data = uring::tag(this, uring::kTagAccept);
    listenerInflight_++;
    listenerArmed_ = true;
  }

  void onAcceptCqe(int res, bool more) {
    if (!more) {
      listenerArmed_ = false;
      listenerInflight_--;
    }
    if (res >= 0) {
      const int fd = res;
      if (closeRequested_ || listenerClosed_) {
        ::close(fd);
      } else if (limits_.maxConnections && conns_.size() >= limits_.maxConnections) {
        // Connection-flood defense: accept then close, as the uv arm does.
        ::close(fd);
      } else {
        uringAcceptFd(fd);
      }
    } else if (res == -EMFILE || res == -ENFILE) {
      // Out of descriptors: libuv's emfile trick - momentarily free the
      // reserve fd, accept + drop the pending connection (so the peer sees a
      // close instead of a hang), reopen the reserve.
      if (uring_->emfileFd >= 0) {
        ::close(uring_->emfileFd);
        int fd = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd >= 0) ::close(fd);
        uring_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      }
    }
    // -ECANCELED (listener closing) and other errors fall through: re-arm
    // only while still listening.
    if (!more && !listenerArmed_ && !listenerClosed_ && !closeRequested_ && listenFd_ >= 0) uringArmAccept();
    uringListenerDoneCheck();
  }

  void uringAcceptFd(int fd) {
    Connection* c = new Connection();
    c->server = this;
    c->ring.fd = fd;
    c->ring.state = 1;
    // TCP_NODELAY: inherited from the listener (see uringListen).
    liveHandles_++;  // balanced by freeConnection
    uring_->addRef();
    attachConnection(c);
    uringArmRecv(c);
  }

  void uringArmRecv(Connection* c) {
    if (c->ring.recvArmed || c->ring.state >= 2) return;
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (!s) return;
    uring::prepRecv(s, c->ring.fd, uring::kBufGroup, /*multishot=*/true);
    s->user_data = uring::tag(c, uring::kTagRecv);
    c->ring.recvArmed = true;
    c->ring.inflight++;
  }

  void onRecvCqe(Connection* c, const uring::abi::io_uring_cqe& cqe) {
    const bool more = uring::hasMore(cqe);
    const bool hasBuf = uring::hasBuffer(cqe);
    const uint16_t bid = uring::bufferId(cqe);
    if (!more) {
      c->ring.recvArmed = false;
      c->ring.inflight--;
    }
    if (c->ring.state >= 2) {
      if (hasBuf) uring_->bufs.recycle(bid);
      return;
    }
    if (cqe.res == -ENOBUFS) {
      // Burst exhausted the provided buffers between reaps; every buffer is
      // recycled by the end of this round, so re-arm then.
      if (!more) uring_->rearm.push_back(c);
      return;
    }
    if (cqe.res == -ECANCELED) return;
    if (cqe.res <= 0) {
      if (hasBuf) uring_->bufs.recycle(bid);
      if (!c->ring.eofSeen) {
        c->ring.eofSeen = true;
        onTransportEof(c);
      }
      return;
    }
    // Data: parse straight out of the kernel's buffer, then hand it back.
    char* p = reinterpret_cast<char*>(uring_->bufs.at(bid));
    onTransportData(c, p, static_cast<size_t>(cqe.res));
    uring_->bufs.recycle(bid);
    if (!more && c->ring.state < 2) uring_->rearm.push_back(c);
  }

  void uringQueueWrite(Connection* c, WriteReq* wr) {
    wr->next = nullptr;
    if (c->ring.wqTail) static_cast<WriteReq*>(c->ring.wqTail)->next = wr;
    else c->ring.wqHead = wr;
    c->ring.wqTail = wr;
    c->ring.pendingBytes += wr->data.size();
    if (!c->ring.sendInflight) uringIssueSend(c);
  }

  // Exactly one SEND in flight per connection (two poll-armed sends on one
  // socket complete in unspecified order): the head WriteReq, from its
  // `sent` offset, at most kMaxWriteChunk per SQE (len is u32).
  void uringIssueSend(Connection* c) {
    WriteReq* wr = static_cast<WriteReq*>(c->ring.wqHead);
    if (!wr || c->ring.sendInflight || c->ring.state >= 2) return;
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (!s) return;
    const size_t remaining = wr->data.size() - wr->sent;
    if (remaining == 0) {
      // An empty terminal write: complete it on a clean stack via a NOP.
      uring::prepNop(s);
    } else {
      const size_t len = remaining > kMaxWriteChunk ? kMaxWriteChunk : remaining;
      uring::prepSend(s, c->ring.fd, wr->data.data() + wr->sent, static_cast<uint32_t>(len), MSG_NOSIGNAL);
    }
    s->user_data = uring::tag(wr, uring::kTagSend);
    c->ring.sendInflight = true;
    c->ring.inflight++;
  }

  void uringPopWrite(Connection* c, WriteReq* wr) {
    // wr is always the head (one in flight, FIFO).
    c->ring.wqHead = wr->next;
    if (!c->ring.wqHead) c->ring.wqTail = nullptr;
    const size_t remaining = wr->data.size() - wr->sent;
    c->ring.pendingBytes -= remaining < c->ring.pendingBytes ? remaining : c->ring.pendingBytes;
    delete wr;
    c->pendingWrites--;
  }

  void onSendCqe(WriteReq* wr, int res) {
    Connection* c = wr->conn;
    c->ring.inflight--;
    c->ring.sendInflight = false;
    if (res < 0) {
      const bool closing = c->ring.state >= 2 || res == -ECANCELED;
      uringPopWrite(c, wr);
      if (!closing) completeWrite(c, false, res);  // -> abortConnection
      return;
    }
    wr->sent += static_cast<size_t>(res);
    c->ring.pendingBytes -= static_cast<size_t>(res) < c->ring.pendingBytes ? static_cast<size_t>(res) : c->ring.pendingBytes;
    if (wr->sent < wr->data.size()) {
      // Partial (no MSG_WAITALL): the sweep sees progress via pendingBytes;
      // continue this request from the new offset.
      uringIssueSend(c);
      return;
    }
    const bool terminal = wr->terminal;
    c->ring.wqHead = wr->next;
    if (!c->ring.wqHead) c->ring.wqTail = nullptr;
    delete wr;
    c->pendingWrites--;
    completeWrite(c, terminal, 0);
    if (c->ring.state < 2 && c->ring.wqHead) uringIssueSend(c);
  }

  // shutdown(SHUT_WR) NOW, then cancel(fd) + close(fd) through the ring.
  // The FIN has to be on the wire right behind the response, as it is with
  // libuv's synchronous close(): a close that goes through the ring only
  // releases the socket once the cancelled recv's completion has run, a
  // task-work step later, and on a Connection: close exchange a fast peer
  // closes first in that window, inherits TIME_WAIT, and a churn-shaped load
  // (one connection per request) throttles itself on ephemeral-port reuse
  // (measured: 24k conn/s with the client holding 28k TIME_WAITs vs 100k
  // with the server closing first). IORING_OP_SHUTDOWN cannot do this: the
  // kernel refuses to issue it non-blocking and punts it to an io-wq worker,
  // so it lands AFTER the inline cancel/close (measured: 586 conn/s). One
  // shutdown(2) syscall per close is the price - still 2-3 syscalls per
  // connection against libuv's 7-8. ASYNC_CANCEL then resolves the recv and
  // CLOSE drops the descriptor, batched with the round's other SQEs; unread
  // inbound data still turns the close into an RST for the peer, as with
  // close().
  void uringCloseConn(Connection* c) {
    if (c->ring.state >= 2) return;
    c->ring.state = 2;
    if (uring_->dead || c->ring.fd < 0) {
      // No ring to complete through: synchronous close, free when the
      // (impossible now) in-flight count is zero.
      if (c->ring.fd >= 0) ::close(c->ring.fd);
      c->ring.fd = -1;
      c->ring.state = 3;
      c->ring.inflight = 0;
      uringFreeIfDone(c);
      return;
    }
    if (!c->finSent) ::shutdown(c->ring.fd, SHUT_WR);  // FIN now (unless it rode with the response); errors (peer already gone) are irrelevant
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (s) {
      uring::prepCancelFd(s, c->ring.fd);
      s->user_data = uring::tag(c, uring::kTagCancel);
      c->ring.inflight++;
    }
    s = uring_->sqe();
    if (s) {
      uring::prepClose(s, c->ring.fd);
      s->user_data = uring::tag(c, uring::kTagClose);
      c->ring.inflight++;
    } else {
      ::close(c->ring.fd);
      c->ring.state = 3;
    }
    c->ring.fd = -1;
  }

  void uringFreeIfDone(Connection* c) {
    if (c->ring.state == 3 && c->ring.inflight == 0) freeConnection(c);
  }

  void uringCloseListener() {
    if (listenFd_ < 0 || listenerClosing_) return;
    listenerClosing_ = true;
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (s) {
      uring::prepCancelFd(s, listenFd_);
      s->user_data = uring::tag(this, uring::kTagListenerCancel);
      listenerInflight_++;
    }
    s = uring_->sqe();
    if (s) {
      uring::prepClose(s, listenFd_);
      s->user_data = uring::tag(this, uring::kTagListenerClose);
      listenerInflight_++;
    } else {
      ::close(listenFd_);
    }
    listenFd_ = -1;
    uringListenerDoneCheck();
  }

  void onListenerCqe(bool isClose) {
    (void)isClose;
    listenerInflight_--;
    uringListenerDoneCheck();
  }

  void uringListenerDoneCheck() {
    if (!listenerClosing_ || listenerReaped_ || listenerInflight_ != 0) return;
    listenerReaped_ = true;
    uring_->servers.erase(this);
    uring_->release();
    liveHandles_--;
    checkFullyClosed();  // may delete this
  }

  // The ring died underneath us: every uring connection is torn down through
  // the normal abort path (callbacks fire once), synchronously since no CQE
  // will ever arrive again.
  void uringRingDied() {
    std::vector<Connection*> live(conns_.begin(), conns_.end());
    for (Connection* c : live) abortConnection(c);
    if (listenFd_ >= 0) {
      ::close(listenFd_);
      listenFd_ = -1;
      listenerClosing_ = true;
      listenerInflight_ = 0;
      uringListenerDoneCheck();
    }
  }

  int listenFd_ = -1;
  uint32_t listenerInflight_ = 0;
  bool listenerArmed_ = false;
  bool listenerClosing_ = false;
  bool listenerReaped_ = false;
  UringLoop* uring_ = nullptr;
#endif

  // ---- deferred notifications ----
  // onAborted / onWritable are queued here and delivered from onNotifyAsync
  // on a later loop turn. Why: a binding call (respond/write/end) can fail a
  // write or trip responseBackpressureLimit and reach doClose synchronously;
  // delivering onAborted from inside that call re-enters JS in the middle of
  // the very call that failed, and it makes those entry points ineligible
  // for V8 fast API calls (which must never call back into JS). Queued by
  // reqId only: by delivery time the Connection may be gone (closing-phase
  // free), and the binding resolves reqIds through the registry anyway.
  enum : uint8_t { kNotifyAborted = 0, kNotifyWritable = 1 };
  struct PendingNotify {
    uint32_t reqId;
    uint8_t kind;
  };

  void queueNotify(uint32_t reqId, uint8_t kind) {
    // Sync mode (diagnostics), or a server whose async handle is already
    // closing (nothing can queue after close() drained, but never drop a
    // notification on the floor): deliver in place.
    if (!notifyDeferred_ || !notifyAsyncLive_) {
      deliverNotify(reqId, kind);
      return;
    }
    notifyQueue_.push_back(PendingNotify{reqId, kind});
    if (!notifyArmed_) {
      notifyArmed_ = true;
      uv_async_send(&notifyAsync_);
    }
  }

  void deliverNotify(uint32_t reqId, uint8_t kind) {
    if (kind == kNotifyAborted) {
      if (cb_.onAborted) cb_.onAborted(cb_.user, reqId);
    } else {
      if (cb_.onWritable) cb_.onWritable(cb_.user, reqId);
    }
  }

  // Deliver everything queued, in order, including notifications queued by
  // the callbacks themselves. Re-entrancy-safe: a nested drain (a callback
  // that calls close(), which drains) is a no-op and the outer loop picks up
  // whatever it added. The Server cannot be deleted underneath this: deletion
  // happens only from uv close callbacks once liveHandles_ reaches 0, never
  // synchronously inside a callback.
  void drainNotifications() {
    if (notifyDraining_) return;
    notifyDraining_ = true;
    std::vector<PendingNotify> batch;
    while (!notifyQueue_.empty()) {
      batch.clear();
      batch.swap(notifyQueue_);  // batch takes the queue; the queue keeps batch's capacity
      for (const PendingNotify& n : batch) deliverNotify(n.reqId, n.kind);
    }
    notifyDraining_ = false;
  }

  static void onNotifyAsync(uv_async_t* h) {
    Server* s = static_cast<Server*>(h->data);
    s->notifyArmed_ = false;  // re-arm for anything queued during delivery
    s->drainNotifications();
  }

  uv_loop_t* loop_;
  uv_tcp_t tcp_;
  TransportKind kind_ = TransportKind::Uv;
  uv_async_t notifyAsync_;
  bool notifyAsyncLive_ = false;  // handle initialised and not yet closing
  bool notifyArmed_ = false;      // uv_async_send issued, callback pending
  bool notifyDeferred_ = true;
  bool notifyDraining_ = false;
  std::vector<PendingNotify> notifyQueue_;
  TlsContext tlsCtx_;        // valid only when tlsEnabled_
  bool tlsEnabled_ = false;  // set via adoptTls() before listen()
  uv_timer_t sweepTimer_;
  uint64_t sweepMs_ = 4000;  // idle-sweep granularity (set in listen())
  // Lingering-close deadline: how long a half-closed connection waits for the
  // peer's FIN before it is closed anyway (Apache's lingering_close budget;
  // nginx defaults to 5 s). Loopback peers close within a millisecond; the
  // deadline only ever bounds a peer that never does.
  static constexpr uint64_t kLingerMs = 2000;
  bool sweepActive_ = false;
  std::unordered_set<Connection*> conns_;  // all live connections (for close())
  TemplateStore templates_;
  bool batchOn_ = false;
  uint32_t* batchControl_ = nullptr;
  // Keyed by path and looked up with the Connection's own std::string, so the
  // hot path allocates nothing. One or two methods per path in any real app,
  // so the per-path vector is scanned linearly.
  std::unordered_map<std::string, std::vector<StaticRoute>> staticRoutes_;
  ServerCallbacks cb_;
  HttpLimits limits_;
  size_t maxPending_ = 0;  // per-connection not-yet-parsed backlog cap
  // The one deflate stream every pmdShared connection sends through
  // (wsDeflate.sharedCompressor). Created lazily at the first eligible
  // upgrade; unique_ptr so checkFullyClosed's `delete this` frees it with
  // the rest of the Server.
  std::unique_ptr<SharedDeflator> sharedDeflator_;
  // Deferred-shutdown bookkeeping: the Server outlives close() until every uv handle it owns (listener + sweep timer + each connection) is reaped.
  int liveHandles_ = 0;
  bool closeRequested_ = false;
  bool listenerClosed_ = false;  // stopListening() already closed the listener
  void (*onClosed_)(void*) = nullptr;
  void* onClosedUser_ = nullptr;

 public:
  ServerCallbacks& callbacks() { return cb_; }
};

}  // namespace engine
}  // namespace moro
