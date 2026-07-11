// TCP + HTTP/1.1 connection engine for @morojs/engine.
//
// Owns the libuv listener and per-connection state machine: accept, read, drive the HttpParser, and write responses. One request is in flight per connection at a time (RFC 9112 §9.3 - responses are returned in request order), so pipelining is handled structurally: the next buffered request is not surfaced until the current response ends.
//
// No V8 here - the binding layer (binding.cpp) supplies callbacks and reads request data / issues responses by reqId. Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <uv.h>

#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "http_parser.h"
#include "tls.h"
#include "websocket.h"
#include "ws_deflate.h"

namespace moro {
namespace engine {

// Cached RFC 9110 §5.6.7 Date header, refreshed at most once per second.
inline const std::string& httpDate() {
  static thread_local std::string cached;
  static thread_local time_t cachedAt = 0;
  time_t now = time(nullptr);
  if (now != cachedAt || cached.empty()) {
    char buf[40];
    struct tm gmt;
#if defined(_WIN32)
    gmtime_s(&gmt, &now);
#else
    gmtime_r(&now, &gmt);
#endif
    // e.g. "Sun, 06 Jul 2026 21:00:00 GMT"
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gmt);
    cached.assign(buf);
    cachedAt = now;
  }
  return cached;
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
inline std::unordered_map<uint32_t, Connection*>& globalRequests() {
  // Pre-sized with a low load factor: this map takes an insert + an erase on
  // EVERY request, so rehashes and collision chains sit directly on the hot
  // path. 4096 buckets at 0.5 load ≈ 2048 concurrent in-flight requests
  // before the first rehash.
  static thread_local std::unordered_map<uint32_t, Connection*> map = [] {
    std::unordered_map<uint32_t, Connection*> m;
    m.max_load_factor(0.5f);
    m.reserve(2048);
    return m;
  }();
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
struct Connection {
  Server* server = nullptr;
  uv_tcp_t handle;              // must be first for uv_close(&handle)
  HttpParser parser;
  std::string readBuf;         // reused alloc target
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
  int pendingWrites = 0;       // outstanding uv_write_t
  bool closeAfterFlush = false;

  // Pipelined-response corking (see dispatchBatch): while `corked`, response bytes accumulate in corkBuf and are flushed with a single write once the buffered input drains - one syscall per pipelined batch instead of one per response. batchClose records a Connection: close response inside the batch (the flush-then-close is handled by the batch loop's tail).
  std::string corkBuf;
  bool corked = false;
  bool batchClose = false;

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
  // Write-progress bookkeeping (slow-read defense): incremented each sweep while uv writes are pending, reset whenever one completes (onWrite); the connection is closed once no write completes for the whole responseTimeoutMs budget.
  uint32_t writeTicks = 0;

  ~Connection() {
    delete wsParser;
    delete tls;
    delete pmd;
  }
};

struct WriteReq {
  uv_write_t req;
  Connection* conn;
  std::string data;
  bool terminal;   // this write completes the response
};

// Callbacks into the binding layer. reqId is opaque; the binding maps it back to JS handlers.
struct ServerCallbacks {
  void* user = nullptr;
  void (*onRequest)(void* user, Connection* c) = nullptr;
  void (*onAborted)(void* user, Connection* c) = nullptr;
  void (*onWritable)(void* user, Connection* c) = nullptr;
  // WebSocket lifecycle (RFC 6455). data lives only for the call.
  void (*onWsOpen)(void* user, Connection* c, const std::string& path) = nullptr;
  void (*onWsMessage)(void* user, Connection* c, const char* data, size_t len,
                      bool isBinary) = nullptr;
  void (*onWsClose)(void* user, Connection* c, int code) = nullptr;
};

class Server {
 public:
  Server(uv_loop_t* loop, ServerCallbacks cb, HttpLimits limits)
      : loop_(loop), cb_(cb), limits_(limits) {
    tcp_.data = this;
    uv_tcp_init(loop_, &tcp_);
    liveHandles_ = 1;  // the listener is a live uv handle from construction
    maxPending_ = limits_.maxPendingBytes ? limits_.maxPendingBytes
                                          : limits_.maxHeadSize + limits_.maxBodySize;
  }

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

    // Start the idle-connection sweep. Granularity adapts to the configured timeout (capped at 4s, floored at 250ms) so short timeouts still fire promptly while the common 120s default sweeps cheaply. Unref'd so the timer alone never keeps the process alive - the listener (and any active connection) does that.
    if ((limits_.idleTimeoutMs > 0 || limits_.requestTimeoutMs > 0 ||
         limits_.responseTimeoutMs > 0) &&
        !sweepActive_) {
      // Granularity follows the shortest enabled timeout.
      uint64_t shortest = limits_.idleTimeoutMs;
      if (limits_.requestTimeoutMs > 0 &&
          (shortest == 0 || limits_.requestTimeoutMs < shortest))
        shortest = limits_.requestTimeoutMs;
      if (limits_.responseTimeoutMs > 0 &&
          (shortest == 0 || limits_.responseTimeoutMs < shortest))
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
    if (uv_tcp_getsockname(&tcp_, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
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
    }
    if (sweepActive_) {
      sweepActive_ = false;
      uv_timer_stop(&sweepTimer_);
      uv_close(reinterpret_cast<uv_handle_t*>(&sweepTimer_), onServerHandleClosed);
    }
    // Close every live connection (doClose mutates conns_, so iterate a copy).
    std::vector<Connection*> live(conns_.begin(), conns_.end());
    for (Connection* c : live) doClose(c);

    checkFullyClosed();  // handles the (rare) zero-handle case synchronously
  }

  static Connection* lookup(uint32_t reqId) {
    auto& map = globalRequests();
    auto it = map.find(reqId);
    return it == map.end() ? nullptr : it->second;
  }

  std::string remoteAddress(Connection* c) {
    struct sockaddr_storage addr;
    int len = sizeof(addr);
    if (uv_tcp_getpeername(&c->handle, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
      return "";
    char ip[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET)
      uv_ip4_name(reinterpret_cast<sockaddr_in*>(&addr), ip, sizeof(ip));
    else if (addr.ss_family == AF_INET6)
      uv_ip6_name(reinterpret_cast<sockaddr_in6*>(&addr), ip, sizeof(ip));
    return ip;
  }

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
    out += "Date: ";
    out += httpDate();
    out += "\r\n";
    out += headersBlock;
    if (!bodyless) {
      const unsigned long long cl =
          (c->isHead && customCL >= 0)
              ? static_cast<unsigned long long>(customCL)
              : static_cast<unsigned long long>(bodyLen);
      out += "Content-Length: ";
      out += std::to_string(cl);
      out += "\r\n";
    } else if (customCL >= 0) {
      out += "Content-Length: ";
      out += std::to_string(static_cast<unsigned long long>(customCL));
      out += "\r\n";
    }
    out += connectionHeader(c);
    out += "\r\n";
    if (!c->isHead && bodyLen) out.append(body, bodyLen);
  }

  // One huge response must not pin its capacity to an idle connection; small
  // (typical) responses keep theirs so the next build is allocation-free.
  static void releaseScratch(Connection* c) {
    if (c->scratch.capacity() > 65536) {
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
    out += "Date: ";
    out += httpDate();
    out += "\r\n";
    out += headersBlock;
    if (c->bodylessStatus) {
      if (customCL >= 0) {
        out += "Content-Length: ";
        out += std::to_string(static_cast<unsigned long long>(customCL));
        out += "\r\n";
      }
    } else if (c->chunkedResponse) {
      out += "Transfer-Encoding: chunked\r\n";
    } else {
      out += "Content-Length: ";
      out += std::to_string(static_cast<unsigned long long>(customCL));
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
      char sizeLine[24];
      int n = snprintf(sizeLine, sizeof(sizeLine), "%zx\r\n", len);
      out.append(sizeLine, n);
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
    bool ok = uv_stream_get_write_queue_size(reinterpret_cast<uv_stream_t*>(
                  &c->handle)) < limits_.writeHighWaterMark;
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
      out += "Date: ";
      out += httpDate();
      out += "\r\n";
      out += "Content-Length: ";
      out += std::to_string(c->isHead ? 0 : len);
      out += "\r\n";
      out += connectionHeader(c);
      out += "\r\n";
      if (!c->isHead && len) out.append(data, len);
    } else if (c->chunkedResponse) {
      if (!c->isHead && !c->bodylessStatus && len) {
        char sizeLine[24];
        int n = snprintf(sizeLine, sizeof(sizeLine), "%zx\r\n", len);
        out.append(sizeLine, n);
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
    // Frames the client sent in the same TCP segment as the handshake are already buffered in the HTTP parser - hand them to the WebSocket parser (copied out first: feedWebSocket may tear the connection down on a protocol error, after which c and its parser must not be touched; the copy is also the mutable storage the parser's in-place unmasking needs).
    std::string early(c->parser.leftover());
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
    size_t q = uv_stream_get_write_queue_size(reinterpret_cast<uv_stream_t*>(&c->handle));
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

  // String literal, not std::string: the keep-alive variant is one byte past libc++'s SSO cap, so returning by value was a heap alloc per response.
  const char* connectionHeader(Connection* c) {
    return c->reqKeepAlive ? "Connection: keep-alive\r\n"
                           : "Connection: close\r\n";
  }

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

    if (c->pendingWrites == 0) {
      const bool canFinishSync =
          !terminal || (c->pending.empty() && c->parser.leftover().empty());
      if (canFinishSync) {
        if (data.empty()) {
          // terminal with no bytes owed (e.g. HEAD chunked suppression)
          finishResponse(c);
          return;
        }
        uv_buf_t b = uv_buf_init(&data[0], static_cast<unsigned>(data.size()));
        int n = uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
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
    if (c->pendingWrites == 0) {
      const bool canFinishSync =
          !terminal || (c->pending.empty() && c->parser.leftover().empty());
      if (canFinishSync) {
        if (data.empty()) {
          finishResponse(c);  // terminal with no bytes owed
          return;
        }
        uv_buf_t b = uv_buf_init(const_cast<char*>(data.data()),
                                 static_cast<unsigned>(data.size()));
        int n = uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
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
    uv_buf_t buf = uv_buf_init(wr->data.empty() ? nullptr : &wr->data[0],
                               static_cast<unsigned>(wr->data.size()));
    c->pendingWrites++;
    int r = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&c->handle),
                     &buf, 1, onWrite);
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
        uv_stream_get_write_queue_size(reinterpret_cast<uv_stream_t*>(
            &c->handle)) > limits_.responseBackpressureLimit) {
      doClose(c);
    }
  }

  static void onWrite(uv_write_t* req, int status) {
    WriteReq* wr = static_cast<WriteReq*>(req->data);
    Connection* c = wr->conn;
    bool terminal = wr->terminal;
    delete wr;
    c->pendingWrites--;
    c->writeTicks = 0;  // a write completed: the drain is making progress

    if (status != 0) {
      c->server->abortConnection(c);
      return;
    }

    Server* s = c->server;
    if (terminal) {
      s->finishResponse(c);
    } else if (c->wantDrain) {
      size_t q = uv_stream_get_write_queue_size(
          reinterpret_cast<uv_stream_t*>(&c->handle));
      if (q < s->limits_.writeHighWaterMark) {
        c->wantDrain = false;
        if (s->cb_.onWritable) s->cb_.onWritable(s->cb_.user, c);
      }
    }
    if (c->closeAfterFlush && c->pendingWrites == 0) s->doClose(c);
  }

  // Response for the active request is fully flushed: either close or move on to the next pipelined request.
  void finishResponse(Connection* c) {
    if (c->closing) return;
    uint32_t oldId = c->reqId;
    globalRequests().erase(oldId);
    c->active = false;

    if (!c->reqKeepAlive) {
      if (c->pendingWrites == 0) doClose(c);
      else c->closeAfterFlush = true;
      return;
    }

    // Reset per-request response state, keep any pipelined/buffered bytes.
    c->responseStarted = false;
    c->responseEnded = false;
    c->chunkedResponse = false;
    c->bodylessStatus = false;
    c->declaredLen = -1;
    c->bodyBytesSent = 0;
    c->sentContinue = false;
    c->wantDrain = false;
    c->abortNotified = false;
    c->parser.reset();

    ParseStatus st;
    if (!c->pending.empty()) {
      st = c->parser.parse(c->pending.data(), c->pending.size());
      c->pending.clear();
    } else {
      st = c->parser.parse(nullptr, 0);
    }
    dispatchBatch(c, st);
  }

  // Corked variant of finishResponse: same per-request bookkeeping, but no write happened yet (the bytes sit in corkBuf) and the next pipelined request is surfaced by dispatchBatch's loop, not from here. A Connection: close response just flags the batch; the loop's tail closes after the flush.
  void completeCorkedResponse(Connection* c) {
    globalRequests().erase(c->reqId);
    c->active = false;
    if (!c->reqKeepAlive) {
      c->batchClose = true;
      return;
    }
    c->responseStarted = false;
    c->responseEnded = false;
    c->chunkedResponse = false;
    c->bodylessStatus = false;
    c->declaredLen = -1;
    c->bodyBytesSent = 0;
    c->sentContinue = false;
    c->wantDrain = false;
    c->abortNotified = false;
    c->parser.reset();
  }

  // Flush the accumulated batch with one write. Tries synchronously straight from corkBuf (a full write keeps the buffer's capacity for the next batch); only a partial/backpressured remainder is copied out and queued.
  void flushCork(Connection* c) {
    if (c->corkBuf.empty() || c->closing) return;
    if (c->pendingWrites == 0) {
      uv_buf_t b =
          uv_buf_init(&c->corkBuf[0], static_cast<unsigned>(c->corkBuf.size()));
      int n = uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
      if (n == static_cast<int>(c->corkBuf.size())) {
        c->corkBuf.clear();
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

  // Dispatch parsed input, corking synchronous pipelined responses into one batched write (uWS-style): while complete requests are buffered and each handler responds before returning, responses accumulate in corkBuf and hit the socket as a single write when the input drains. Re-entrancy-safe by construction: request N+1 is surfaced HERE, below cb_.onRequest in the stack, only after handler N has returned - never from inside a respond()/end() crossing. Async handlers, upgrades, errors, and Connection: close all exit the loop and preserve their existing paths.
  void dispatchBatch(Connection* c, ParseStatus st) {
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
      if (c->pendingWrites == 0) doClose(c);
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
    uv_tcp_nodelay(&c->handle, 1);
    c->parser = HttpParser(s->limits_);
    if (s->tlsEnabled_) c->tls = new TlsSession(s->tlsCtx_.ctx());
    s->conns_.insert(c);
    uv_read_start(reinterpret_cast<uv_stream_t*>(&c->handle), onAlloc, onRead);
  }

  static void onAlloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf) {
    Connection* c = static_cast<Connection*>(handle->data);
    if (c->readBuf.size() < suggested) c->readBuf.resize(suggested);
    buf->base = &c->readBuf[0];
    buf->len = static_cast<unsigned>(c->readBuf.size());
  }

  static void onRead(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    Connection* c = static_cast<Connection*>(handle->data);
    Server* s = c->server;
    if (nread < 0) {
      // EOF or error.
      if (c->isWebSocket) {
        // Fire onWsClose exactly once: set wsClosing before the impending doClose so its own 1006 guard can't re-fire it.
        if (!c->wsClosing && s->cb_.onWsClose)
          s->cb_.onWsClose(s->cb_.user, c, 1006);  // abnormal closure (§7.1.5)
        c->wsClosing = true;
        globalWebSockets().erase(c->wsId);
      } else if (c->active && !c->abortNotified && s->cb_.onAborted) {
        // A request was awaiting its response: it's aborted.
        c->abortNotified = true;
        s->cb_.onAborted(s->cb_.user, c);
      }
      s->abortConnection(c);
      return;
    }
    if (nread == 0) return;
    c->idleTicks = 0;  // activity: reset the idle sweep counter

    if (c->tls) {
      // Ciphertext: pump through the TLS transform; decrypted bytes re-enter the exact plaintext path below via dispatchPlaintext. Outbound ciphertext (handshake flights, key updates, alerts) must go to the wire even when the pump reports failure.
      std::string cipherOut;
      bool ok = c->tls->onCiphertext(
          buf->base, static_cast<size_t>(nread),
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
    s->dispatchPlaintext(c, buf->base, static_cast<size_t>(nread));
  }

  // Plaintext ingestion - identical for direct TCP reads and decrypted TLS records. May tear the connection down (doClose sets c->closing; the Connection object itself stays alive until uv's close callback).
  void dispatchPlaintext(Connection* c, const char* data, size_t len) {
    if (c->isWebSocket) {
      // Zero-copy WS receive: the parser unmasks complete frames IN PLACE in
      // this buffer, so feedWebSocket takes mutable bytes. The const here is
      // only an artifact of this shared signature — both actual sources are
      // mutable storage we own: c->readBuf for plaintext reads (onAlloc
      // hands its storage to uv_read) and TlsSession::onCiphertext's local
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
              size_t q = uv_stream_get_write_queue_size(
                  reinterpret_cast<uv_stream_t*>(&c->handle));
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
    auto& reqMap = globalRequests();
    do {
      c->reqId = ++globalReqCounter();
    } while (c->reqId == 0 || reqMap.count(c->reqId));
    c->method = c->parser.method;
    // Swap, don't copy: the parser is reset before its next request anyway (reset() clears every swapped-in field, keeping its heap capacity), so the previous snapshot's buffers become the parser's scratch for the NEXT request - snapshots are allocation-free on a warm connection.
    c->methodStr.swap(c->parser.methodStr);
    c->path.swap(c->parser.path);
    c->query.swap(c->parser.query);
    c->headers.swap(c->parser.headers);
    c->body.swap(c->parser.body);
    c->isHead = (c->method == Method::HEAD);
    c->reqKeepAlive = c->parser.keepAlive;
    c->active = true;
    c->requestTicks = 0;  // the request-receive budget is per request
    globalRequests()[c->reqId] = c;

    if (cb_.onRequest) cb_.onRequest(cb_.user, c);
  }

  void sendErrorAndClose(Connection* c, int status) {
    c->reqKeepAlive = false;
    std::string& out = c->scratch;
    out.clear();
    appendStatusLine(out, status);
    out += "Date: ";
    out += httpDate();
    out += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    c->responseEnded = true;
    writeOutView(c, out, /*terminal=*/true);
  }

  void abortConnection(Connection* c) {
    // Hard teardown (read error/EOF/write error): drop the socket now. Any in-flight writes reference WriteReq buffers, not the connection body, and their completion callbacks tolerate a closing handle.
    doClose(c);
  }

  void doClose(Connection* c) {
    if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&c->handle))) return;
    // Best-effort close_notify on an established TLS session (truncation detection for the peer). uv_try_write: synchronous, non-blocking, no bookkeeping - if the kernel buffer is full the alert is simply lost, which is exactly the semantics "best effort" means here.
    if (c->tls && !c->closing) {
      std::string bye;
      c->tls->shutdown(bye);
      if (!bye.empty()) {
        uv_buf_t b = uv_buf_init(&bye[0], static_cast<unsigned>(bye.size()));
        uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
      }
    }
    c->closing = true;
    // An HTTP request that was surfaced to a handler and never answered owes JS exactly one onAborted (server shutdown, timeout sweep, write error), or 'close' listeners and their resources (SSE intervals, monitors) leak. closing is already set, so a re-entrant respond() from JS is a no-op.
    if (c->active && !c->isWebSocket && !c->abortNotified) {
      c->abortNotified = true;
      if (cb_.onAborted) cb_.onAborted(cb_.user, c);
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
    uv_read_stop(reinterpret_cast<uv_stream_t*>(&c->handle));
    uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
  }

  static void onCloseFree(uv_handle_t* handle) {
    Connection* c = static_cast<Connection*>(handle->data);
    Server* s = c->server;
    delete c;
    // One fewer live uv handle; may complete a pending server shutdown.
    s->liveHandles_--;
    s->checkFullyClosed();
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
    std::vector<Connection*> stale;
    std::vector<Connection*> overdue;
    std::vector<Connection*> stalled;
    for (Connection* c : s->conns_) {
      if (c->closing) continue;
      // Response-delivery deadline (slow-read DoS defense). The `active`
      // exemption below is right for a handler that hasn't answered yet, but
      // once bytes are QUEUED the engine owns them: a peer that stops reading
      // (or pins a zero TCP receive window) would otherwise hold its WriteReq
      // buffers, kernel socket buffers, and fd forever - active never clears
      // because the terminal write never flushes, so BOTH receive timeouts
      // skip it permanently. writeTicks resets on every completed write
      // (onWrite), so a slow-but-draining peer lives; only a fully stalled
      // drain is shed. Applies to WebSockets too: a stalled consumer under
      // wsBackpressureLimit that the app stops sending to is otherwise held
      // forever, and a stalled Close-frame flush (closeAfterFlush) likewise.
      if (s->limits_.responseTimeoutMs && c->pendingWrites > 0 &&
          ++c->writeTicks >= respLimit) {
        stalled.push_back(c);
        continue;
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

  uv_loop_t* loop_;
  uv_tcp_t tcp_;
  TlsContext tlsCtx_;        // valid only when tlsEnabled_
  bool tlsEnabled_ = false;  // set via adoptTls() before listen()
  uv_timer_t sweepTimer_;
  uint64_t sweepMs_ = 4000;  // idle-sweep granularity (set in listen())
  bool sweepActive_ = false;
  std::unordered_set<Connection*> conns_;  // all live connections (for close())
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
