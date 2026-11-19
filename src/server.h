// TCP + HTTP/1.1 connection engine for @morojs/engine.
//
// Owns the libuv listener and per-connection state machine: accept, read, drive the HttpParser, and write responses. One request is in flight per connection at a time (RFC 9112 §9.3 - responses are returned in request order), so pipelining is handled structurally: the next buffered request is not surfaced until the current response ends.
//
// No V8 here - the binding layer (binding.cpp) supplies callbacks and reads request data / issues responses by reqId. Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <uv.h>

#include <algorithm>
#include <cstdlib>
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
#ifndef SO_INCOMING_CPU
#define SO_INCOMING_CPU 49  // kernel 3.19+; older libc headers lack the name
#endif
#include "uring.h"
#endif

#include "http2.h"
#include "http_parser.h"
#include "response_template.h"
#include "text.h"
#include "thread_state.h"
#include "tls.h"
#include "websocket.h"
#include "ws_deflate.h"

namespace moro {
namespace engine {

// Cached RFC 9110 §5.6.7 Date header, refreshed at most once per second.
// Holds the COMPLETE "Date: ...\r\n" line so the hot path appends it once.
// time(nullptr), not uv_now: uv_now is loop time, not wall-clock. The cache
// lives on the caller (one per Server, which is one per loop thread): a
// thread_local in a dlopen'd addon is a __tls_get_addr call per access, and
// this ran on every response.
inline void refreshHttpDateLine(std::string& cached, time_t& cachedAt) {
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

// The reason phrase sent with a status code: the registered one (IANA HTTP
// Status Code Registry; 418 has the phrase everyone knows it by). A client
// must not act on it (RFC 9112 §4), but it is what a log line, `curl -i` and
// fetch()'s statusText show, and "429 OK" reads as success. A code the
// registry does not know keeps the "OK" it was always sent with.
inline const char* reasonPhrase(int status) {
  switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 102: return "Processing";
    case 103: return "Early Hints";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "Non-Authoritative Information";
    case 204: return "No Content";
    case 205: return "Reset Content";
    case 206: return "Partial Content";
    case 207: return "Multi-Status";
    case 208: return "Already Reported";
    case 226: return "IM Used";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 305: return "Use Proxy";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 418: return "I'm a Teapot";
    case 421: return "Misdirected Request";
    case 422: return "Unprocessable Content";
    case 423: return "Locked";
    case 424: return "Failed Dependency";
    case 425: return "Too Early";
    case 426: return "Upgrade Required";
    case 428: return "Precondition Required";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 451: return "Unavailable For Legal Reasons";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    case 506: return "Variant Also Negotiates";
    case 507: return "Insufficient Storage";
    case 508: return "Loop Detected";
    case 510: return "Not Extended";
    case 511: return "Network Authentication Required";
    default: return "OK";
  }
}

class Server;
struct Connection;

// Exchange two request-snapshot strings (parser <-> staged slot <-> active
// request). Most requests have no query, no body and a known method, so both
// sides of those fields are empty and there is nothing to exchange; the test
// costs a few instructions where std::string::swap is an out-of-line call
// into libstdc++ that copies both small-string buffers.
inline void swapField(std::string& a, std::string& b) {
  if (a.empty() && b.empty()) return;
  a.swap(b);
}

// Request id counter + registry mapping a reqId (the binding's only handle)
// back to its Connection, across every Server on the calling thread: per
// thread (thread_state.h), since worker_threads + reusePort runs one engine
// per thread, each with its own uv loop, servers and connections, and a
// reqId only ever crosses the JS<->C++ boundary on the thread that created
// it - per-thread registries are race-free without locks.
inline uint32_t& globalReqCounter() { return threadState().reqCounter; }
#if defined(MORO_ENGINE_TEST_FAULTS)
// Test builds only (tools/build.mjs --sanitize defines it; no shipped binary
// does): with MORO_ENGINE_TEST_ID_PERIOD=N in the environment at load, the
// reqId and wsId counters start over after N-1 instead of after 2^32-1, so
// what happens when an id comes round again can be exercised in a test.
inline uint32_t testIdPeriod() {
  static const uint32_t period = [] {
    const char* env = std::getenv("MORO_ENGINE_TEST_ID_PERIOD");
    return env ? static_cast<uint32_t>(std::strtoul(env, nullptr, 10)) : 0u;
  }();
  return period;
}
#endif
// reqId registry: flat open-addressing map (see flat_map.h) - no per-op
// allocation where std::unordered_map paid a node malloc/free per request.
// Key 0 is the empty sentinel; reqIds are never 0 (surfaceRequest skips it).
using FlatReqMap = FlatMap<Connection*>;

inline FlatReqMap& globalRequests() { return threadState().requests; }

// WebSocket connections get their own id space + registry (a wsId outlives the reqId that created it). Same per-thread ownership rules as globalRequests().
inline uint32_t& globalWsCounter() { return threadState().wsCounter; }
inline std::unordered_map<uint32_t, Connection*>& globalWebSockets() { return threadState().webSockets; }

// Per-connection state.
// Which I/O transport a Server runs (decided once per process, see
// Server::preferredTransport): libuv streams everywhere, io_uring on Linux
// when the kernel and the sandbox allow it. Behaviour and wire bytes are
// identical; only the syscall layer differs.
enum class TransportKind : uint8_t { Uv, Uring, Epoll };

#if defined(__linux__)
// Per-connection state of the epoll transport (Server::EpollLoop): a plain
// non-blocking socket watched by a libuv poll handle, no libuv stream.
struct EpollConn {
  uv_poll_t poll;       // libuv's watcher on fd; closed before fd is
  int fd;               // the accepted socket (owned)
  uint8_t state;        // 0 idle, 1 open, 2 closing/closed (events ignored, free pending/done)
  bool wantOut;         // writable interest armed: a queued write hit EAGAIN
  bool eofSeen;         // EOF/error already routed once
  bool inFlush;         // epollFlush is on the stack (re-entrant queueWrite just enqueues)
  bool completionPending;  // fully-sent WriteReqs wait for epollCompleteWrites (clean stack)
  bool readyQueued;     // already on EpollLoop::ready for this turn (see deferReady)
  int readyEvents;      // the events reported for it this turn, OR-ed
  uint32_t servedTurn;  // EpollLoop::iteration when it was last served (one service per loop turn)
  size_t pendingBytes;  // queued write bytes the kernel has not accepted
  void* wqHead;         // WriteReq* queue (intrusive, FIFO; WriteReq::next / sent)
  void* wqTail;
  int peerCpu;          // SO_INCOMING_CPU: the CPU the peer's packets arrive on (-1 unknown); see EpollLoop::serve
  uint32_t reads;       // recv() calls that returned data; peerCpu is re-read every 1024
  int writeError;       // a hard send() error (negative errno) epollFlush met; epollCompleteWrites tears the connection down for it (clean stack)
};
#endif

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
  HeaderList headers;
  std::string body;
  bool isHead = false;
  bool reqKeepAlive = true;
  bool reqHttp11 = true;
  // Expect: 100-continue seen while no interim has been sent for it yet: the
  // 100 is written when the slot is activated (right before its own
  // response, after the responses ahead of it), as handleParse does for a
  // request the sequential loop surfaces.
  bool expectContinue = false;
  // Upgrade: websocket was seen while this request was parsed (the batch
  // ends with it): activateStaged may hand the handshake to the engine's own
  // upgrade (wsAutoUpgrade) before anything reaches JS.
  bool upgrade = false;
  // Connection::routeMissGen as it stood when this request was staged: the
  // route-table generation at which it is known to match no engine route
  // (0: not known).
  uint32_t routeMissGen = 0;
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
    EpollConn ep;
#endif
  };
  HttpParser parser;
  // The engine route the parser's route hook matched for the request being
  // parsed (light mode): answerFromParser() replies from it without a second
  // lookup. Exactly one of the two is set; fastSeg points into parser.path.
  StaticRoute* fastStatic = nullptr;
  ParamRoute* fastParam = nullptr;
  const char* fastSeg = nullptr;
  size_t fastSegLen = 0;
  // The route-table generation (Server::routeGen_) at which the route hook
  // looked the parser's current request up and found no engine route for it;
  // that holds for as long as the tables are still at that generation. 0: the
  // hook did not consult the tables. Written by every hook call except a
  // match, and read only for a request that is not in light mode (a match
  // puts the parser in light mode, and those requests never read it).
  uint32_t routeMissGen = 0;
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
  HeaderList headers;
  std::string body;
  // The body once handed to JS (binding getBody): its storage, kept so a
  // second call hands over the same bytes again. Opaque here; cleared when
  // the next request is surfaced.
  std::shared_ptr<void> jsBody;
  // The body lent to JS (binding getBodyLent): the ArrayBuffer `body` was
  // moved into. Opaque here; released - which detaches the ArrayBuffer and
  // frees the bytes - wherever jsBody is, and before the connection closes.
  std::shared_ptr<void> jsLent;
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
  // Nothing this connection sends is read as HTTP any more; what arrives is
  // dropped (onTransportData). Set with `lingering`, and as soon as an error
  // response (400/408/413/414/431/505) has been written or queued: until
  // that response is flushed the connection is neither closing nor
  // lingering, and the request it answers must stay rejected whatever the
  // peer sends behind it.
  bool inputClosed = false;
  // Request intake is paused because response bytes are waiting on the peer
  // (Server::outputBacklogged): what it sends meanwhile is buffered in
  // `pending`, under the same cap as while a handler is running, and
  // dispatched once the write queue has drained below the high-water mark
  // (Server::resumeHeld). Only ever set while writes are pending.
  bool outHeld = false;
  uv_shutdown_t shutdownReq;   // uv arm: the FIN for a queued (non-coalesced) last write

  // Pipelined-response corking (see dispatchBatch): while `corked`, response bytes accumulate in corkBuf and are flushed with a single write once the buffered input drains - one syscall per pipelined batch instead of one per response. batchClose records a Connection: close response inside the batch (the flush-then-close is handled by the batch loop's tail).
  std::string corkBuf;
  bool corked = false;
  bool batchClose = false;

  // Batched dispatch (Server::dispatchBatch): complete pipelined requests
  // parsed ahead of the active one - a FIFO ring over `staged` (one slot from
  // first use, Server::kMaxStaged once the connection pipelines; see
  // stageRequest). Ids are assigned at staging and
  // registered only on activation, so a staged id is a safe no-op for every
  // binding call until then. aheadComplete: the parser holds one more
  // complete request that found no free slot (HttpParser::parse cannot be
  // re-asked once Done, so the status is remembered here).
  std::vector<StagedRequest> staged;
  uint32_t stagedHead = 0;
  uint32_t stagedCount = 0;
  uint32_t batchPos = 0;  // index of the active slot within the current batch call
  // The active request was activated after JS left its batch loop (see
  // completeCorkedResponse): no handler has seen it yet, dispatchBatch must
  // deliver it.
  bool undelivered = false;
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
  bool wsShedPending = false;  // a 1013 Close is queued for this socket (wsSend backpressure)
  bool wsGonePending = false;  // its teardown is queued: a send could not be completed (closeForFailedSend)
  // permessage-deflate context (RFC 7692); null unless negotiated for this connection at upgrade time.
  PmdContext* pmd = nullptr;
  // Outbound compression goes through the Server's SharedDeflator instead of
  // this connection's pmd (which is then InflateOnly). Set at upgrade when
  // wsDeflate.sharedCompressor negotiated the server's full window.
  bool pmdShared = false;

  // TLS transform when the server terminates TLS; null on plaintext servers (the hot path pays exactly one null check).
  TlsSession* tls = nullptr;

  // HTTP/2 (http2.h, Server "HTTP/2" section). `proto` is settled by a
  // connection's first bytes or by ALPN: 0 undecided, 1 HTTP/1, 2 HTTP/2. A
  // connection speaking HTTP/2 owns a session, and each request on it is
  // surfaced on a Connection of its own - h2Parent set, no socket, no parser
  // in use - that carries the request snapshot and the response state, so
  // everything that answers a request by reqId works on it unchanged.
  uint8_t proto = 0;
  bool h2Feeding = false;            // (the connection) inside Server::h2Feed
  h2::Session* h2 = nullptr;         // (the connection) its session
  Connection* h2Parent = nullptr;    // (a request) the connection it arrived on
  h2::Stream* h2s = nullptr;         // (a request) its stream, while it has one
  uint32_t h2Gen = 0;                // (a request) the batch call it was delivered in
  bool h2Bye = false;                // (the connection) the closing frames were sent, or are pointless
  // (the connection) The slow-read defense for response bytes the session
  // holds for want of flow-control window: sweeps in a row in which they did
  // not move, and Session::heldSent() at the last sweep.
  uint32_t h2HeldTicks = 0;
  uint64_t h2LastSent = 0;

  // Idle-sweep bookkeeping: reset to 0 on every read, incremented each sweep while not actively running a handler; closed when it exceeds the limit.
  // libuv transport: the bytes of the writes handed to uv_write() whose
  // callback has not run (Server::tOutputHeld).
  size_t uvQueued = 0;
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
    delete h2;
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
  // A binary message handed over as the string that holds it: the callee
  // takes the string (swaps or moves it out) instead of copying its bytes.
  // Optional; used for a large message the engine had to buffer anyway, and
  // every other message goes to onWsMessage.
  void (*onWsBinaryOwned)(void* user, Connection* c, std::string& message) = nullptr;
  void (*onWsClose)(void* user, Connection* c, int code) = nullptr;
  // One read's worth of frames (Server::feedWebSocket). When set, the
  // binding is handed the buffer and must call Server::feedWebSocketFrames
  // with it exactly once from inside the call: that lets it open whatever a
  // JS call needs on its own stack once per read rather than once per frame
  // (onWsMessage/onWsClose then fire inside that frame). May nest: frames
  // that came with the upgrade request are fed from inside the request's
  // dispatch.
  void (*onWsRead)(void* user, Connection* c, char* data, size_t len) = nullptr;
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
  static const char* transportName(TransportKind k) {
    return k == TransportKind::Uring ? "uring" : k == TransportKind::Epoll ? "epoll" : "uv";
  }

  // Decided ONCE per process: MORO_ENGINE_TRANSPORT=uv forces libuv
  // (diagnostics; `uring` is an accepted no-op hint); otherwise io_uring's
  // feature probe + behavioural self-test (uring.h) decides. EPERM (Docker's
  // default seccomp, io_uring_disabled), ENOSYS and EINVAL (< 6.1) all mean
  // libuv - silently, because the transport is never a requirement.
  // libuv unless MORO_ENGINE_TRANSPORT=uring asks for io_uring (then the
  // probe decides, and any refusal falls back to libuv with the reason).
  // Opt-in, not auto-selected, in 1.1.6: measured on the same binary and box
  // (docs/DESIGN.md, "io_uring measurements"), io_uring halves the syscalls
  // per request but costs more CPU per completion at low batching - it wins
  // keep-alive at 64 and 512 connections, loses at 256, loses connection
  // churn by 10-20% and burns ~40% more CPU per request at a fixed moderate
  // rate. The per-completion cost is what DEFER_TASKRUN behind an eventfd
  // (uring.h, "Ring modes") addresses; the default stays libuv until that
  // mode is measured to flip the go/no-go (docs/DESIGN.md).
#if defined(__linux__)
  // The io_uring ring mode the probe selected (uring.h, "Ring modes").
  static uring::RingMode& uringModeSlot() {
    static uring::RingMode m = uring::kModeCoop;
    return m;
  }
  // "uv", or the io_uring mode in use: "defer-taskrun" | "coop-taskrun".
  static const char* transportModeName() {
    return preferredTransport() == TransportKind::Uring ? uringModeSlot().name
                                                        : transportName(preferredTransport());
  }
#else
  static const char* transportModeName() { return "uv"; }
#endif

  static TransportKind preferredTransport() {
#if defined(__linux__)
    // Linux: epoll by default (the engine's own readiness loop on a uv_poll,
    // no libuv stream layer per connection), io_uring on request when the
    // kernel and sandbox allow it, libuv on request. Decided once per process.
    static const TransportKind kind = [] {
      const char* env = std::getenv("MORO_ENGINE_TRANSPORT");
      if (env && std::strcmp(env, "uv") == 0) {
        transportReasonSlot() = "MORO_ENGINE_TRANSPORT=uv";
        return TransportKind::Uv;
      }
      if (env && std::strcmp(env, "uring") == 0) {
        uring::ProbeResult pr = uring::probe();
        transportReasonSlot() = pr.reason;
        if (pr.ok) uringModeSlot() = pr.mode;
        return pr.ok ? TransportKind::Uring : TransportKind::Epoll;
      }
      transportReasonSlot() = (env && std::strcmp(env, "epoll") == 0)
                                  ? "MORO_ENGINE_TRANSPORT=epoll"
                                  : "default (epoll); io_uring is opt-in (MORO_ENGINE_TRANSPORT=uring)";
      return TransportKind::Epoll;
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
  // restores the pre-1.1.6 re-entrant delivery for bisecting
  // (MORO_ENGINE_NOTIFY=sync); the binding then never installs fast calls.
  void setDeferredNotify(bool deferred) { notifyDeferred_ = deferred; }
  bool deferredNotify() const { return notifyDeferred_; }

  // Batched pipelined dispatch (capabilities.batchDispatch): on when the
  // binding registered onRequestBatch and MORO_ENGINE_BATCH is not 0;
  // otherwise requests are surfaced one at a time (dispatchBatchSequential).
  void setBatchDispatch(bool on) { batchOn_ = on && cb_.onRequestBatch != nullptr; }
  bool batchDispatch() const { return batchOn_; }
  // WebSocket upgrades performed by the engine itself (capabilities
  // wsAutoUpgrade): a valid handshake is answered and onWsOpen fired without
  // the request ever reaching onRequest; what the handshake carried stays
  // readable on the WebSocket through wsHeaders()/wsQuery()/remoteAddress().
  // An invalid handshake is surfaced to JS like any other request.
  void setWsAutoUpgrade(bool on) { wsAutoUpgrade_ = on; }
  bool wsAutoUpgrade() const { return wsAutoUpgrade_; }
  // The handshake request's headers and query string, kept on the connection
  // for its WebSocket lifetime (nothing parses HTTP on it again).
  const HeaderList& wsHeaders(Connection* c) const { return c->headers; }
  const std::string& wsQuery(Connection* c) const { return c->query; }
  // The control cell JS polls between slots: the index of the slot that is
  // active within the current batch call, or the batch's count once every
  // slot has been answered. Owned by the binding (an ArrayBuffer's storage),
  // stable for the server's lifetime.
  void setBatchControl(uint32_t* cell) { batchControl_ = cell; }

  // JS has returned from its batch loop. The binding calls this before the
  // Node callback scope of the call closes, because closing it runs the
  // microtask and nextTick queues: a response sent from there completes its
  // slot with nobody left reading the control cell, so the slot it uncovers
  // has to be delivered by another call (dispatchBatch, h2DispatchBatch),
  // not by the loop that has already ended.
  void batchLoopReturned() {
    batchLoopConn_ = nullptr;
    h2LoopOpen_ = false;
  }

  // A body buffer nothing refers to any more, handed back for reuse (the
  // binding, when a lent body is released; see recycleBodyBuffer).
  void returnBodyBuffer(std::string& b) { recycleBodyBuffer(b); }
  static constexpr uint32_t kMaxStaged = 16;

  // Turn on TLS termination with an already-validated context (the binding builds and validates it BEFORE constructing the Server, so a config error throws from serve() instead of leaving a half-built server behind).
  void adoptTls(TlsContext&& tctx) {
    tlsCtx_ = std::move(tctx);
    tlsEnabled_ = tlsCtx_.valid();
  }
  bool tlsEnabled() const { return tlsEnabled_; }
  // The live context (updateSsl reads ticket keys / ALPN policy to carry over).
  const TlsContext& tls() const { return tlsCtx_; }

  // Returns the bound port, or 0 on failure. On failure, *uvErr (when non-null) receives the libuv error code (e.g. UV_EADDRINUSE) so the caller can throw a precise, code-bearing Error.
  int listen(const char* host, int port, int* uvErr = nullptr) {
    auto fail = [&](int code) {
      if (uvErr) *uvErr = code;
      return 0;
    };
    // One listener per server, for its whole life: a second listen(), or one
    // after stopListening()/close(), is refused - the answer libuv gives on
    // the uv transport (a bound handle cannot be bound again). The epoll and
    // io_uring transports own their listening socket and would otherwise
    // set up a second one over the first: the watcher of the first
    // initialised again while libuv still holds it, its completions counted
    // against the second.
    if (listenUp_ || listenerClosed_ || closeRequested_) return fail(UV_EINVAL);
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
        kind_ = TransportKind::Epoll;
      } else {
        int r = uringListen(addr);
        if (r != 0) {
          uring_->retireIfUnused();  // (a ring set up for this listener alone)
          return fail(r);
        }
      }
    }
    if (kind_ == TransportKind::Epoll) {
      // Per-thread epoll loop, created lazily by the first epoll listener on
      // this uv loop; if it cannot be created this server runs the uv arm.
      epoll_ = EpollLoop::get(loop_);
      if (!epoll_) {
        kind_ = TransportKind::Uv;
      } else {
        int r = epollListen(addr);
        if (r != 0) return fail(r);
      }
    }
    if (kind_ == TransportKind::Uv) {
      // Linux: the listening socket is the engine's own on this transport
      // too, watched by a poll handle, and the engine makes the accept call
      // (uvListen). A libuv listener cannot be told to stop asking, which is
      // what a process at its descriptor limit needs (pauseAccept).
      int r = uvListen(addr);
      if (r != 0) return fail(r);
    }
#else
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
#endif

    listenUp_ = true;

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
    // HTTP/2 connections are told to open no more streams (GOAWAY); what is
    // in flight on them completes. HTTP/1 connections learn it from the
    // Connection: close of their next response, as before.
    std::vector<Connection*> live(conns_.begin(), conns_.end());
    for (Connection* c : live) {
      if (c->h2 && !c->closing && !c->h2->goawaySent()) {
        c->h2->goaway();
        h2Flush(c);
      }
    }
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
    // Streams stopped for this turn are closed below with every other
    // connection; nothing starts them again.
    uvStopped_.clear();
    if (uvResumeInit_) {
      uvResumeInit_ = false;
      uv_close(reinterpret_cast<uv_handle_t*>(&uvResume_), onServerHandleClosed);
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
    if (c->h2Parent) c = c->h2Parent;  // an HTTP/2 request: its connection's peer
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
    respond(c, t->status, t->headers, t->customCL, body, bodyLen, t);
  }
  void writeHeadTemplate(Connection* c, uint32_t tplId) {
    const ResponseTemplate* t = templates_.get(tplId);
    if (!t) {
      writeHead(c, 500, emptyHeaders(), -1);
      return;
    }
    writeHead(c, t->status, t->headers, t->customCL, t);
  }

  // ---- static routes (capabilities.staticRoutes) ----
  // A fixed (method, path) answered by the engine in surfaceRequest, before
  // the request reaches the binding: no JS call, no routing, no per-request
  // header building. Only an exact method match short-circuits (a HEAD against
  // a registered GET still reaches JS, which owns method policy).
  void setStaticRoute(int32_t method, std::string path, ResponseTemplate&& tpl,
                      std::string body) {
    routesChanged();
    auto& vec = staticRoutes_[std::move(path)];
    for (StaticRoute& existing : vec) {
      if (existing.method == method) {
        existing.tpl = std::move(tpl);
        existing.body = std::move(body);
        existing.frame.clear();  // the cached frame was the old reply
        existing.frameAt = 0;
        return;
      }
    }
    vec.push_back(StaticRoute{method, std::move(tpl), std::move(body)});
  }
  void clearStaticRoutes() {
    routesChanged();
    staticRoutes_.clear();
  }

  // ---- parameter routes (capabilities.paramRoutes) ----
  // A route with ONE variable path segment whose body IS that segment,
  // answered inside the engine exactly like a static route: `/user/:id` is
  // prefix "/user/" and suffix ""; `/files/:name.json` is prefix "/files/"
  // and suffix ".json". The segment must be non-empty and contain no '/', so
  // `/user/` and `/user/1/2` still reach JS. It goes out as it is on the wire,
  // undecoded (what uWS's writeParameterValue does) - a route that needs
  // decoding stays a JS route. Method policy is JS's, as for static routes.
  void setParamRoute(int32_t method, std::string prefix, std::string suffix, ResponseTemplate&& tpl) {
    routesChanged();
    for (ParamRoute& existing : paramRoutes_) {
      if (existing.method == method && existing.prefix == prefix && existing.suffix == suffix) {
        existing.tpl = std::move(tpl);
        existing.head.clear();  // the cached head carried the old template
        existing.headAt = 0;
        return;
      }
    }
    paramRoutes_.push_back(ParamRoute{method, std::move(prefix), std::move(suffix), std::move(tpl)});
  }
  void clearParamRoutes() {
    routesChanged();
    paramRoutes_.clear();
  }
  // Every change to either table starts a new generation: what a connection
  // remembers about a lookup (Connection::routeMissGen: that nothing matched)
  // is good for the generation it was made in and is looked up again after
  // it.
  void routesChanged() {
    if (++routeGen_ == 0) routeGen_ = 1;
  }
  // Any engine-answered route registered (static or parameter): the dispatch
  // sites test this once per request before trying either table.
  bool hasEngineRoutes() const { return !staticRoutes_.empty() || !paramRoutes_.empty(); }

  // ---- response API (called by the binding, by reqId->Connection) ----

  // Responses that never carry a body (RFC 9110 §6.4.1): 1xx informational,
  // 204 No Content, 304 Not Modified. None of them is framed with a length
  // of the engine's own; a length the handler supplies is sent only on a 304,
  // where it describes the representation a 200 would have carried (§8.6) -
  // a 1xx or 204 response must not have a Content-Length at all.
  static bool isBodyless(int status) {
    return status == 204 || status == 304 || (status >= 100 && status < 200);
  }
  // ... and 205 Reset Content, which has a body by framing and must not have
  // content (§15.3.6): it is sent as Content-Length: 0, whatever body or
  // length the handler gave it.
  static bool isContentless(int status) { return isBodyless(status) || status == 205; }

  // Single-shot terminal response (the fast path). customCL is an app-supplied Content-Length value, or -1 when none was given; the header block itself never contains Content-Length (the binding strips it).
  // `tpl`: the template the status and headers came from, when there is one
  // (its cached HTTP/2 header block is used on an HTTP/2 request).
  void respond(Connection* c, int status, const std::string& headersBlock,
               long long customCL, const char* body, size_t bodyLen,
               const ResponseTemplate* tpl = nullptr) {
    if (!c || c->closing) return;
    if (c->responseStarted) {
      if (c->responseEnded) return;  // already answered (a response that has ended has started)
      if (c->h2Parent) {
        h2Respond(c, status, headersBlock, customCL, body, bodyLen, tpl);
        return;
      }
      // The head of this response is already on the wire (writeHead() or
      // write() came first), so the status and headers given here cannot be
      // sent: a second status line would be read by the client as body bytes
      // of the response in progress, and on a keep-alive connection every
      // response after it would be read out of step. The response ends where
      // it is and the connection is closed behind it - a chunked body without
      // its last chunk, a declared length not reached - so the client sees a
      // response that was cut short, which is what happened.
      c->reqKeepAlive = false;
      c->responseEnded = true;
      writeOutView(c, std::string_view(), /*terminal=*/true);
      return;
    }
    if (c->h2Parent) {
      h2Respond(c, status, headersBlock, customCL, body, bodyLen, tpl);
      return;
    }

    const bool bodyless = isBodyless(status);
    if (bodyless || status == 205) bodyLen = 0;  // never emit a body for these statuses

    if (bodyLen >= kDirectBody && !c->tls &&
        respondDirect(c, status, headersBlock, customCL, body, bodyLen, tpl)) {
      return;
    }

    // Corked plaintext fast path: build the frame STRAIGHT INTO the cork
    // buffer - no scratch, no intermediate memcpy. This is the hot path for
    // every pipelined batch. (TLS must go through writeOutView so the frame is
    // encrypted before it reaches corkBuf.)
    if (c->corked && !c->tls) {
      c->corkBuf.reserve(c->corkBuf.size() + bodyLen + headersBlock.size() +
                         128);
      appendResponse(c->corkBuf, c, status, headersBlock, customCL, body,
                     bodyLen, bodyless, tpl);
      c->responseStarted = true;
      c->responseEnded = true;
      completeCorkedResponse(c);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }

    std::string& out = c->scratch;
    out.clear();
    const size_t sendLen = (!c->isHead && !bodyless) ? bodyLen : 0;
    if (c->tls && sendLen > kTlsInlineBody) {
      // TLS, large body: the head is built in scratch and the body is
      // encrypted straight from the caller's bytes - two SSL_writes into one
      // ciphertext buffer, no plaintext copy of the body. The frame used to
      // be assembled whole in scratch, whose capacity was then released
      // again, so a large static file paid a copy and fresh pages per reply.
      // A small body still rides the head's record: one copy of a few
      // kilobytes costs less than a record of its own.
      appendResponseHead(out, c, status, headersBlock, customCL, bodyLen, bodyless, tpl);
      c->responseStarted = true;
      c->responseEnded = true;
      tlsWrite(c, out, std::string_view(body, sendLen), /*terminal=*/true);
      releaseScratch(c);
      return;
    }
    out.reserve(bodyLen + headersBlock.size() + 128);
    appendResponse(out, c, status, headersBlock, customCL, body, bodyLen,
                   bodyless, tpl);
    c->responseStarted = true;
    c->responseEnded = true;
    writeOutView(c, out, /*terminal=*/true);
    releaseScratch(c);
  }

  // A large body on a plaintext keep-alive connection with nothing queued
  // ahead of it: the head is framed (behind whatever the batch has corked so
  // far) and written together with the body in one gathered write, straight
  // from the caller's bytes. Framed whole first, a body this size was copied
  // once more than the kernel's own copy and, being over the capacity the
  // cork and scratch buffers keep, into memory allocated for this response
  // and released after it. The bytes on the wire are the same, and the
  // caller's are not referenced after the return.
  //
  // Inside a batch the write happens here only for its last reply, or when
  // the cork buffer would have been flushed for this reply anyway: several
  // bodies that fit under the high-water mark together still leave in one
  // write. Returns false when the reply is to be framed the usual way (TLS,
  // which encrypts from the caller's bytes on its own path; HEAD; the last
  // response of a connection, whose path sends the FIN with its last bytes;
  // a socket with writes already queued).
  MORO_NOINLINE bool respondDirect(Connection* c, int status, const std::string& headersBlock,
                                   long long customCL, const char* body, size_t bodyLen,
                                   const ResponseTemplate* tpl) {
    if (c->tls || c->isHead || !c->reqKeepAlive || c->pendingWrites != 0) return false;
    std::string& buf = c->corked ? c->corkBuf : c->scratch;
    if (!c->corked) {
      buf.clear();
    } else if ((c->stagedCount != 0 || c->aheadComplete) &&
               buf.size() + bodyLen < limits_.writeHighWaterMark) {
      return false;
    }
    appendResponseHead(buf, c, status, headersBlock, customCL, bodyLen, /*bodyless=*/false, tpl);
    c->responseStarted = true;
    c->responseEnded = true;
    writeBehind(c, buf, body, bodyLen, /*terminal=*/true);
    if (c->corked) {
      completeCorkedResponse(c);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
    }
    return true;
  }

  // Append one complete response frame (status line through body) to `out`.
  // Framing belongs to the engine: a body-carrying response always declares
  // the ACTUAL body size (an app-supplied mismatch would desync every
  // follow-up response on a keep-alive connection). A HEAD response and a
  // 304 legitimately declare the would-be entity length (RFC 9110 §8.6), so
  // the app-supplied value is honored there, and only there: a 1xx or 204
  // carries no Content-Length, and a 205 always says 0. The caller passes
  // bodyLen 0 for a status without content (isContentless).
  void appendResponse(std::string& out, Connection* c, int status,
                      const std::string& headersBlock, long long customCL,
                      const char* body, size_t bodyLen, bool bodyless,
                      const ResponseTemplate* tpl = nullptr) {
    appendResponseHead(out, c, status, headersBlock, customCL, bodyLen, bodyless, tpl);
    if (!c->isHead && bodyLen) out.append(body, bodyLen);
  }

  // The status line and header block of appendResponse, without the body.
  void appendResponseHead(std::string& out, Connection* c, int status,
                          const std::string& headersBlock, long long customCL,
                          size_t bodyLen, bool bodyless,
                          const ResponseTemplate* tpl = nullptr) {
    if (tpl != nullptr && !bodyless) {
      // A prepared response: everything up to the length is the same bytes
      // for a whole second (the template's status and header block and the
      // Date line), kept on the template and appended in one piece.
      const std::string& date = dateLine();
      if (tpl->headAt != dateCachedAt_ || tpl->head.empty()) {
        tpl->head.clear();
        appendStatusLine(tpl->head, tpl->status);
        tpl->head += date;
        tpl->head += tpl->headers;
        tpl->head += "Content-Length: ";
        tpl->headAt = dateCachedAt_;
      }
      out += tpl->head;
      appendDecimal(out, (c->isHead && customCL >= 0 && status != 205)
                             ? static_cast<unsigned long long>(customCL)
                             : static_cast<unsigned long long>(bodyLen));
      out += "\r\n";
      out += connectionHeader(c);
      out += "\r\n";
      return;
    }
    appendStatusLine(out, status);
    out += dateLine();
    out += headersBlock;
    if (!bodyless) {
      const unsigned long long cl =
          (c->isHead && customCL >= 0 && status != 205)
              ? static_cast<unsigned long long>(customCL)
              : static_cast<unsigned long long>(bodyLen);
      out += "Content-Length: ";
      appendDecimal(out, cl);
      out += "\r\n";
    } else if (customCL >= 0 && status == 304) {
      out += "Content-Length: ";
      appendDecimal(out, static_cast<unsigned long long>(customCL));
      out += "\r\n";
    }
    out += connectionHeader(c);
    out += "\r\n";
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
                 long long customCL, const ResponseTemplate* tpl = nullptr) {
    if (!c || c->responseStarted || c->closing) return;
    if (c->h2Parent) {
      h2WriteHead(c, status, headersBlock, customCL, tpl);
      return;
    }
    c->responseStarted = true;
    c->bodylessStatus = isBodyless(status);
    c->bodyBytesSent = 0;
    if (status == 205) customCL = 0;  // no content: framed as an empty body, and write()/end() clamp to it
    if (c->bodylessStatus) {
      // No body framing at all; an app-supplied Content-Length is sent on a
      // 304 only (the would-be entity length), never on a 1xx or 204.
      c->chunkedResponse = false;
      c->declaredLen = 0;
    } else if (customCL < 0 && !c->reqHttp11) {
      // No declared length, and an HTTP/1.0 client: it cannot read chunked
      // framing (a response carries Transfer-Encoding only when the request
      // was HTTP/1.1, RFC 9112 §6.1), so the body goes out as it is and the
      // end of the connection ends it (§6.3). A HEAD response has no body to
      // delimit and leaves the connection as it was.
      c->chunkedResponse = false;
      c->declaredLen = -1;
      if (!c->isHead) c->reqKeepAlive = false;
    } else {
      c->chunkedResponse = customCL < 0;  // no CL -> chunked framing
      c->declaredLen = customCL;
    }

    std::string& out = c->scratch;
    out.clear();
    appendStatusLine(out, status);
    out += dateLine();
    out += headersBlock;
    if (c->bodylessStatus) {
      if (customCL >= 0 && status == 304) {
        out += "Content-Length: ";
        appendDecimal(out, static_cast<unsigned long long>(customCL));
        out += "\r\n";
      }
    } else if (c->chunkedResponse) {
      out += "Transfer-Encoding: chunked\r\n";
    } else if (customCL >= 0) {
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
    if (c->h2Parent) return h2Write(c, data, len);
    // write() without writeHead(): synthesize an implicit 200 chunked head (Node behavior). Raw body bytes with no status line would corrupt this response and desync every follow-up response on a keep-alive socket.
    if (!c->responseStarted) {
      writeHead(c, 200, std::string(), -1);
      // The head may have closed the connection (a session that could not
      // encrypt it, a write over the response limit), and with notifications
      // delivered in place (MORO_ENGINE_NOTIFY=sync) the handler has been
      // told and has run: `data` is the caller's memory and is not read
      // after that.
      if (c->closing) return false;
    }
    // HEAD / 1xx / 204 / 304: suppress body bytes
    if (c->isHead || c->bodylessStatus || len == 0) return true;

    if (c->chunkedResponse) {
      // TLS has a path of its own (the test is the one writeOutView would
      // make), and so has a large chunk on either: it is written, or
      // encrypted, from the caller's bytes.
      if (c->tls || len >= kChunkDirect) return writeChunkApart(c, data, len);
      std::string& out = c->scratch;
      out.clear();
      appendChunkSize(out, len);
      out.append(data, len);
      out += "\r\n";
      transportWriteView(c, out, /*terminal=*/false);
      releaseScratch(c);
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
      // No framing around the bytes of a fixed-length body: they are written
      // (or encrypted) from where the caller has them - writeOutView copies
      // only what it has to keep - and not staged in the scratch buffer.
      writeOutView(c, std::string_view(data, len), /*terminal=*/false);
    }
    bool ok = tPendingBytes(c) < limits_.writeHighWaterMark;
    if (!ok) c->wantDrain = true;
    return ok;
  }

  void end(Connection* c, const char* data, size_t len) {
    if (!c || c->responseEnded || c->closing) return;
    if (c->h2Parent) {
      h2End(c, data, len);
      return;
    }

    std::string& out = c->scratch;
    out.clear();
    std::string_view direct;  // an unframed last piece, written from the caller's bytes
    if (!c->responseStarted) {
      // end() without writeHead(): a 200 with the given body as the full payload
      // (a large one exactly as respond() sends it: the same bytes, and the
      // body is not copied behind its head first).
      if (len >= kDirectBody && !c->isHead) {
        respond(c, 200, emptyHeaders(), -1, data, len);
        return;
      }
      appendStatusLine(out, 200);
      out += dateLine();
      out += "Content-Length: ";
      appendDecimal(out, c->isHead ? 0 : len);
      out += "\r\n";
      out += connectionHeader(c);
      out += "\r\n";
      if (!c->isHead && len) out.append(data, len);
    } else if (c->chunkedResponse) {
      if (!c->isHead && !c->bodylessStatus && len) {
        // A large last chunk, as in write(). (Not the last response of a
        // plaintext connection: its path sends the FIN with its last bytes.)
        if (len >= kChunkDirect && (c->tls || c->reqKeepAlive)) {
          c->responseEnded = true;
          if (c->tls) tlsWriteChunk(c, data, len, /*last=*/true);
          else writeChunkDirect(c, data, len, /*last=*/true);
          releaseScratch(c);
          return;
        }
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
        if (len) direct = std::string_view(data, len);  // as in write()
      }
      // Ending short of the declared Content-Length: the bytes owed can never arrive, so force the connection closed - the client then sees a truncated response (an error) instead of silently consuming the NEXT response's bytes as the remainder of this body.
      if (!c->isHead && c->declaredLen >= 0 &&
          c->bodyBytesSent < static_cast<unsigned long long>(c->declaredLen)) {
        c->reqKeepAlive = false;
      }
    }
    c->responseStarted = true;
    c->responseEnded = true;
    writeOutView(c, direct.empty() ? std::string_view(out) : direct, /*terminal=*/true);
    releaseScratch(c);
  }

  static Connection* lookupWs(uint32_t wsId) {
    auto& map = globalWebSockets();
    auto it = map.find(wsId);
    return it == map.end() ? nullptr : it->second;
  }

  // Upgrade the request's connection to a WebSocket (RFC 6455 §4.2.2). Returns the new wsId, or 0 if the request is not a valid upgrade.
  // `unsupportedVersion` (when given) is set for the one refusal RFC 6455
  // gives an answer of its own (§4.2.2, §4.4): a handshake that is valid in
  // every other respect and asks for a protocol version other than 13.
  uint32_t upgradeToWebSocket(Connection* c, bool* unsupportedVersion = nullptr) {
    if (!c || c->responseStarted || c->closing) return 0;
    if (c->h2Parent) return 0;  // no WebSockets over HTTP/2 (RFC 8441 is not implemented)
    // RFC 6455 §4.2.1 item 1: the handshake is "an HTTP/1.1 or higher GET
    // request". Any other method, and HTTP/1.0, is an ordinary request
    // whatever headers it carries.
    if (c->method != Method::GET || !c->reqHttp11) return 0;
    // Validate the upgrade (RFC 6455 §4.2.1): Upgrade: websocket, Connection: Upgrade, a Sec-WebSocket-Key, Version 13.
    std::string_view key;
    std::string_view extensions;
    bool haveExtensions = false;
    std::string extensionList;  // several Sec-WebSocket-Extensions lines, joined
    // §11.3.1, §11.3.5: Sec-WebSocket-Key and Sec-WebSocket-Version MUST NOT
    // appear more than once in a request; one that repeats either is refused
    // (which of two keys, or of two versions, would be the one meant?).
    unsigned keyLines = 0, versionLines = 0;
    bool hasUpgrade = false, hasConnUpgrade = false, ver13 = false;
    for (const Header h : c->headers) {
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
      } else if (h.name == "sec-websocket-key") {
        key = h.value;
        keyLines++;
      } else if (h.name == "sec-websocket-version") {
        versionLines++;
        if (trimOWS(h.value) == "13") ver13 = true;
      } else if (h.name == "sec-websocket-extensions") {
        // §9.1: the field may be split over several lines, which together
        // are one list of offers, in order.
        if (!haveExtensions) {
          extensions = h.value;
          haveExtensions = true;
        } else {
          if (extensionList.empty()) extensionList = std::string(extensions);
          extensionList += ", ";
          extensionList += h.value;
          extensions = extensionList;
        }
      }
    }
    if (!hasUpgrade || !hasConnUpgrade || keyLines != 1 || versionLines != 1) return 0;
    // RFC 6455 §4.1: the key must be the base64 of a 16-byte nonce; refuse
    // malformed/probing clients before the accept-key computation (§4.2.1).
    if (!isValidWsKey(key)) return 0;
    if (!ver13) {
      if (unsupportedVersion) *unsupportedVersion = true;
      return 0;
    }

    // permessage-deflate negotiation (RFC 7692), opt-in via options.wsDeflate.
    std::string extResp;
    std::optional<PmdParams> pmdParams;
    if (limits_.wsDeflate.enabled && haveExtensions) {
      pmdParams = parsePmdOffer(extensions, limits_.wsDeflate);
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
    std::string resp = buildHandshakeResponse(key, extResp);
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
#if defined(MORO_ENGINE_TEST_FAULTS)
      if (testIdPeriod() != 0 && c->wsId >= testIdPeriod()) c->wsId = globalWsCounter() = 0;
#endif
    } while (c->wsId == 0 || wsMap.count(c->wsId));
    wsMap[c->wsId] = c;
    // This request's reqId is done; the connection is now a WebSocket. The
    // id is zeroed as well: the per-request bookkeeping that runs on a
    // terminal frame (finishResponse, completeCorkedResponse) erases
    // c->reqId from the registry, and 0 is the one value that can never
    // name a live request there.
    globalRequests().erase(c->reqId);
    c->reqId = 0;
    c->active = false;
    c->jsBody.reset();
    c->jsLent.reset();
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
    // Whether bytes of an earlier send are still waiting for the socket (see
    // the backpressure check below). pendingWrites is zero on a connection
    // that is keeping up, so the common case reads one field.
    const bool backlog = c->pendingWrites > 0 && tPendingBytes(c) > 0;
    // Already shed (below) and still not draining: the Close that ends it is
    // on its way, and nothing more is queued behind what the peer has not
    // read. Without this every send between the shed and its delivery on the
    // next loop turn - the replies to a whole read's worth of messages, when
    // the sends come from onWsMessage - joined the queue the limit had just
    // been enforced on.
    if (backlog && c->wsShedPending) return false;
    bool compressed = false;
    // The loop's buffer, not a string of this call: a send that is not
    // compressed never touches it, and one that is does not allocate.
    std::string& deflated = deflateScratch_;
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
    const WsOpcode opcode = isBinary ? WsOpcode::Binary : WsOpcode::Text;
    size_t gathered = 0;  // plaintext this batch still holds for its record (TLS)
    if (payload.size() >= kWsDirectPayload) {
      // A large message: only the frame header is built, and the payload
      // goes to the socket (or into the cipher) from where the caller has
      // it. Framed into a buffer first, every byte of it was copied once
      // more on its way out.
      wsSendDirect(c, opcode, payload, compressed);
    } else if (c->corked && !c->tls) {
      // Inside a read's batch (feedWebSocket) on a plaintext connection: the
      // frame is built straight into the cork buffer, the way respond() builds
      // a corked HTTP reply, so an echo costs one append and no scratch copy.
      // The flush at the high-water mark is the one transportWrite applies.
      encodeShortFrame(c->corkBuf, opcode, payload, /*rsv1=*/compressed);
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
    } else {
      // Frame into the connection's reusable scratch buffer (same policy as
      // respond()'s non-corked path): a warm connection sends with zero
      // allocations, and releaseScratch keeps one huge frame from pinning its
      // capacity. Neither write keeps a reference past the call: the bytes
      // reach the kernel synchronously (uv_try_write) or are copied first -
      // into a queued WriteReq, the TLS ciphertext buffer (writePlain), or
      // on a TLS connection the batch's plaintext or its corkBuf.
      std::string& out = c->scratch;
      out.clear();
      encodeShortFrame(out, opcode, payload, /*rsv1=*/compressed);
      if (c->tls) {
        tlsWrite(c, out, /*terminal=*/false);
        gathered = tlsGatheredBytes(c);
      } else {
        transportWriteView(c, out, /*terminal=*/false);
      }
      releaseScratch(c);
    }
    if (compressed && deflated.capacity() > kCipherScratchKeep) std::string().swap(deflated);
    // Frames corked for this read's batch (feedWebSocket) are queued too:
    // they leave with the flush, so the backpressure signal counts them.
    size_t q = tPendingBytes(c) + c->corkBuf.size() + gathered;
    if (backlog && limits_.wsBackpressureLimit && q > limits_.wsBackpressureLimit) {
      // Slow/stalled consumer - shed it (1013 Try Again Later) so its queued
      // frames can't grow memory without bound (limits_.wsBackpressureLimit,
      // 0 = unlimited; maxBackpressure defense). Only a consumer that had
      // not taken an earlier send is slow: a message larger than the limit,
      // sent to a socket with nothing waiting, is over the limit the moment
      // it is queued whatever its reader does, so it goes out whole, and the
      // next send finds it here if the peer has not drained it. A peer that
      // stops reading with one such message in flight is closed by the
      // response-delivery deadline (responseTimeoutMs, onSweep).
      // The Close goes out on a later loop turn, through the same queue as
      // onAborted/onWritable: a synchronous onWsClose from inside wsSend()
      // would reach JS while the binding still borrows the payload's bytes
      // out of the V8 heap. Under sync notification (MORO_ENGINE_NOTIFY=sync)
      // the binding copies and the shed is immediate, as before.
      if (!c->wsShedPending) {
        c->wsShedPending = true;
        queueNotify(c->wsId, kNotifyWsShed);
      }
      return false;
    }
    return q < limits_.writeHighWaterMark;
  }

  // Send a Close frame (§5.5.1) and close the connection after it flushes.
  // The frame is legal whatever the application passed (closeFramePayload,
  // websocket.h): a code that may not appear on the wire is replaced (1005
  // by a Close without a status, anything else by 1011) and the reason is
  // cut to the 123 bytes a control frame has room for. onWsClose reports the
  // code as it was passed.
  void wsClose(Connection* c, int code, const char* reason, size_t rlen) {
    if (!c || !c->isWebSocket || c->wsClosing) return;
    c->wsClosing = true;
    // Notify JS exactly once. The wsClosing guard above + the check in feedWebSocket/onRead means no client-side or EOF path re-fires it, so server-initiated closes (disconnect/kick) no longer leak the JS wrapper.
    if (cb_.onWsClose) cb_.onWsClose(cb_.user, c, code);
    std::string payload;
    closeFramePayload(payload, code, std::string_view(reason, rlen));
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
  // A TLS body up to this size rides in the head's record (one copy of a few
  // kilobytes); above it the body is encrypted from the caller's bytes.
  static constexpr size_t kTlsInlineBody = 8192;
  // Ciphertext scratch capacity kept between replies (see tlsWrite).
  static constexpr size_t kCipherScratchKeep = 1u << 20;
  // respond() on a plaintext connection: a body from this size on is written
  // from the caller's bytes (respondDirect). It is the capacity the cork and
  // scratch buffers give back after use, so a smaller body is framed into
  // memory that is already there.
  static constexpr size_t kDirectBody = 16384;
  // A buffered binary message in a string of more capacity than this is
  // handed to the application as that string (see feedWebSocketFrames): it
  // is the capacity above which the parser gives its buffer back after a
  // message, so nothing it would have kept is taken from it.
  static constexpr size_t kWsTakeMessage = 16384;
  // A WebSocket message from this size on is written as its frame header
  // and the caller's bytes (wsSendDirect).
  static constexpr size_t kWsDirectPayload = 32 * 1024;
  // A chunk of a streamed response from this size on is written
  // (writeChunkDirect) or encrypted (tlsWriteChunk) from the caller's bytes.
  static constexpr size_t kChunkDirect = 32 * 1024;
  // The small replies of one batch on a TLS connection share records
  // (tlsCork): a reply up to kTlsGatherMax is held as plaintext until
  // kTlsRecord of it has come together or the batch ends.
  static constexpr size_t kTlsGatherMax = 4096;
  static constexpr size_t kTlsRecord = 16384;  // a record's plaintext limit (RFC 8446 5.1)

  // Frame-level write: response/frame bytes from the HTTP/WS machinery. On a TLS connection the plaintext is encrypted first; `terminal` rides the (single) ciphertext buffer so the flush-then-finish semantics (onWrite -> finishResponse) are identical on both transports.
  void writeOut(Connection* c, std::string&& data, bool terminal) {
    if (c->closing) return;
    if (data.empty() && !terminal) return;
    if (c->tls) {
      tlsWrite(c, data, terminal);
      return;
    }
    transportWrite(c, std::move(data), terminal);
  }

  // TLS tail shared by writeOut and writeOutView: the plaintext is encrypted
  // into the server's one ciphertext scratch buffer (a fresh std::string per
  // reply was a malloc/free pair on every TLS response) and the transport is
  // handed a view of it, copying only what it cannot send right away. The
  // scratch is free again before anything below can reach JS: the view is
  // consumed by the send(), the cork append or the queued copy, all of which
  // happen ahead of finishResponse.
  void tlsWrite(Connection* c, std::string_view plain, bool terminal) {
    tlsWrite(c, plain, std::string_view(), terminal);
  }

  // Two plaintext pieces (a response head and its body) encrypted back to
  // back into the one ciphertext buffer and handed to the transport as one
  // write: the body is read where it lives, never copied behind the head.
  void tlsWrite(Connection* c, std::string_view head, std::string_view body, bool terminal) {
    if (c->corked) {
      // Inside a batch the ciphertext is bound for the cork buffer, so the
      // records are appended to it as they are produced. Through the scratch
      // buffer every reply was copied twice on its way to the socket, the
      // second time a full pass over the body for nothing.
      //
      // And when this reply is the batch - nothing in the cork buffer, nothing
      // queued on the socket, no further request staged behind this one - the
      // records go to the socket from where OpenSSL wrote them and are not
      // copied here at all (tlsDirect). Pipelined requests keep the cork: one
      // send for the batch is worth more than a copy saved per reply.
      //
      // A small reply that has company in its batch - pipelined responses,
      // the frames a WebSocket read provokes - is not encrypted here either:
      // its plaintext is gathered (tlsCork) and the batch is sealed as one
      // record per 16 KiB at the flush, where each reply used to be a record
      // of its own, with its own header, tag and pass through the cipher
      // set-up.
      std::string& cork = c->corkBuf;
      const bool direct = cork.empty() && tlsDirectOk(c) && c->stagedCount == 0 &&
                          !c->aheadComplete && tlsGather_.conn != c;
      if (!direct && (tlsGather_.conn == c || tlsCompany(c))) {
        tlsCork(c, head, body, terminal);
        return;
      }
      const size_t mark = cork.size();
      if (direct) c->tls->beginDirect(&Server::tlsDirectSend, c);
      const bool ok =
          (head.empty() || c->tls->writePlain(head.data(), head.size(), cork, !body.empty())) &&
          (body.empty() || c->tls->writePlain(body.data(), body.size(), cork));
      if (direct) c->tls->endDirect();
      if (!ok) {
        cork.resize(mark);  // no part of a reply that could not be encrypted goes out
        closeForFailedSend(c, /*abort=*/false);
        return;
      }
      if (terminal) completeCorkedResponse(c);
      if (cork.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }
    std::string& cipher = cipherScratch_;
    cipher.clear();
    // Outside a batch (a reply sent later, a streamed chunk) the same holds:
    // with nothing queued ahead the records go straight to the socket, and
    // the scratch buffer is left with only what the socket did not take.
    const bool direct = tlsDirectOk(c);
    if (direct) c->tls->beginDirect(&Server::tlsDirectSend, c);
    const bool ok =
        (head.empty() || c->tls->writePlain(head.data(), head.size(), cipher, !body.empty())) &&
        (body.empty() || c->tls->writePlain(body.data(), body.size(), cipher));
    if (direct) c->tls->endDirect();
    if (!ok) {
      // Encrypting failed (session torn down / pre-handshake write): the response can never reach the peer - drop the connection.
      closeForFailedSend(c, /*abort=*/false);
      return;
    }
    transportWriteView(c, cipher, terminal);
    // The buffer is one per loop, so its capacity is kept up to a generous
    // watermark: released after every large reply (the old 64 KiB), a static
    // file's worth of pages was faulted in and zeroed again for each of them.
    if (cipher.capacity() > kCipherScratchKeep) {
      cipher.clear();
      cipher.shrink_to_fit();
    }
  }

  // ---- small TLS replies of one batch, sealed together ----
  //
  // tlsGather_ holds, for at most one connection at a time, the plaintext of
  // the replies its batch has produced so far (`plain`, less than a record's
  // worth) and the records already sealed from it (`sealed`). While a
  // connection has anything here its cork buffer is empty: flushCork, which
  // every batch ends with, finds nothing corked, looks here, and moves the
  // records into the cork buffer to write them. So nothing waits past the
  // batch that produced it, and a plaintext connection's flush never looks.
  //
  // `conn` alone does not say whose the content is: a batch that ends on a
  // closing connection is not flushed, and the address may be given to a
  // later connection. The session carries the ticket it was given when it
  // took the buffers (TlsSession::gatherTicket, zero in a new session), and
  // only a connection whose session holds the current ticket owns them; what
  // anyone else finds here is discarded unread.
  struct TlsGather {
    Connection* conn = nullptr;
    uint32_t ticket = 0;
    std::string plain;
    std::string sealed;
  };

  // Whether more replies are due in the batch in progress on `c`: requests
  // staged behind the one being answered, or input behind the WebSocket
  // frame being delivered. A reply without company is encrypted where it is,
  // as it always was; gathering it would only add a copy.
  bool tlsCompany(const Connection* c) const {
    if (c->isWebSocket) return c->wsParser != nullptr && c->wsParser->moreInRead();
    return c->stagedCount != 0 || c->aheadComplete;
  }

  bool tlsGathering(const Connection* c) const {
    return tlsGather_.conn == c && c->tls != nullptr && c->tls->gatherTicket == tlsGather_.ticket;
  }

  // Plaintext and records of `c`'s batch that are held here and not yet in
  // its cork buffer (they count as queued for a backpressure decision).
  size_t tlsGatheredBytes(const Connection* c) const {
    return tlsGathering(c) ? tlsGather_.plain.size() + tlsGather_.sealed.size() : 0;
  }

  void tlsGatherDrop() {
    tlsGather_.conn = nullptr;
    tlsGather_.plain.clear();
    tlsGather_.sealed.clear();
  }

  // A reply inside a batch that has company (tlsCompany), or follows replies
  // already gathered. A small one is gathered. Any other is encrypted into
  // the cork buffer the way tlsWrite does it, behind what was gathered ahead
  // of it - sealed first, so the records keep the order of the replies.
  MORO_NOINLINE void tlsCork(Connection* c, std::string_view head, std::string_view body,
                             bool terminal) {
    TlsGather& g = tlsGather_;
    const size_t n = head.size() + body.size();
    const bool mine = tlsGathering(c);
    if (n > kTlsGatherMax || (!mine && (!c->corkBuf.empty() || !c->tls->writable()))) {
      if (mine) {
        tlsUngather(c);
        if (c->closing) return;
      }
      std::string& cork = c->corkBuf;
      const size_t mark = cork.size();
      const bool ok =
          (head.empty() || c->tls->writePlain(head.data(), head.size(), cork, !body.empty())) &&
          (body.empty() || c->tls->writePlain(body.data(), body.size(), cork));
      if (!ok) {
        cork.resize(mark);  // no part of a reply that could not be encrypted goes out
        closeForFailedSend(c, /*abort=*/false);
        return;
      }
      if (terminal) completeCorkedResponse(c);
      if (cork.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }
    if (!mine) {
      tlsGatherDrop();  // a batch that ended on a closing connection left it behind
      g.conn = c;
      if (++tlsGatherSeq_ == 0) tlsGatherSeq_ = 1;
      g.ticket = c->tls->gatherTicket = tlsGatherSeq_;
    } else if (g.plain.size() + n > kTlsRecord) {
      if (!tlsSeal(c, g.sealed)) return;
    }
    g.plain.append(head.data(), head.size());
    g.plain.append(body.data(), body.size());
    // The high-water mark applies to what is held here as it does to the
    // cork buffer, and ahead of the bookkeeping that asks whether the peer
    // is keeping up (completeCorkedResponse, holdForOutput).
    if (g.plain.size() + g.sealed.size() >= limits_.writeHighWaterMark) {
      flushCork(c);
      if (c->closing) return;
    }
    if (terminal) completeCorkedResponse(c);
  }

  // Encrypt the plaintext gathered for `c` into one record, appended to
  // `into`. False: the session could not, and the connection is being
  // closed.
  bool tlsSeal(Connection* c, std::string& into) {
    TlsGather& g = tlsGather_;
    if (g.plain.empty()) return true;
    const size_t mark = into.size();
    const bool ok = c->tls->writePlain(g.plain.data(), g.plain.size(), into);
    g.plain.clear();
    if (!ok) {
      into.resize(mark);  // no part of a record that could not be finished goes out
      tlsGatherDrop();
      closeForFailedSend(c, /*abort=*/false);
      return false;
    }
    return true;
  }

  // The gathering for `c` ends: what is left is sealed and the records move
  // to its cork buffer (empty until now - see TlsGather). False when there
  // is nothing to write: the connection is closing, the session failed, or
  // the buffers were not this connection's after all.
  MORO_NOINLINE bool tlsUngather(Connection* c) {
    TlsGather& g = tlsGather_;
    if (!tlsGathering(c) || c->closing) {
      tlsGatherDrop();
      return false;
    }
    // The usual batch is under a record's worth and nothing has been sealed
    // yet: it is encrypted straight into the cork buffer.
    if (g.sealed.empty() && c->corkBuf.empty()) {
      if (!tlsSeal(c, c->corkBuf)) return false;
      g.conn = nullptr;
      return !c->corkBuf.empty();
    }
    if (!tlsSeal(c, g.sealed)) return false;
    g.conn = nullptr;
    if (c->corkBuf.empty()) c->corkBuf.swap(g.sealed);
    else c->corkBuf.append(g.sealed);
    g.sealed.clear();
    // The buffers are one per loop and keep what a batch of small replies
    // needs; a batch that grew past that gives its memory back.
    if (g.sealed.capacity() > kCipherScratchKeep) std::string().swap(g.sealed);
    return !c->corkBuf.empty();
  }

  MORO_NOINLINE void tlsFlushGathered(Connection* c) {
    if (tlsUngather(c)) flushCorked(c);
  }

  // One chunk of a chunked response on TLS (write(), and end() when `last`:
  // the last-chunk marker rides behind it). A small one is assembled in
  // scratch and encrypted from there, as on a plaintext connection. Of a
  // large one only the two ends are copied - the size line with enough of
  // the data to fill a record, and what is left over a whole number of
  // records with the CRLF - and the records between are encrypted from the
  // caller's bytes: the same bytes in the same number of records as when the
  // chunk was assembled whole first, less a pass over all of it.
  //
  // On a plaintext connection a large chunk is one gathered write
  // (writeChunkDirect).
  MORO_NOINLINE bool writeChunkApart(Connection* c, const char* data, size_t len) {
    if (!c->tls) {
      writeChunkDirect(c, data, len, /*last=*/false);
    } else if (len >= kChunkDirect) {
      tlsWriteChunk(c, data, len, /*last=*/false);
    } else {
      std::string& out = c->scratch;
      out.clear();
      appendChunkSize(out, len);
      out.append(data, len);
      out += "\r\n";
      tlsWrite(c, out, /*terminal=*/false);
    }
    releaseScratch(c);
    const bool ok = tPendingBytes(c) < limits_.writeHighWaterMark;
    if (!ok) c->wantDrain = true;
    return ok;
  }

  // A large chunk on a plaintext connection: its size line (behind whatever
  // the batch has corked), the caller's bytes and the CRLF - with the
  // last-chunk marker when `last` - in one gathered write. Assembled in
  // scratch first, every byte of it was copied once more than the kernel's
  // own copy, into memory allocated for the chunk and released after it.
  void writeChunkDirect(Connection* c, const char* data, size_t len, bool last) {
    std::string& buf = c->corked ? c->corkBuf : c->scratch;
    if (!c->corked) buf.clear();
    appendChunkSize(buf, len);
    writeBehind(c, buf, data, len, /*terminal=*/last,
                last ? std::string_view("\r\n0\r\n\r\n", 7) : std::string_view("\r\n", 2));
    if (!c->corked) return;
    if (last) completeCorkedResponse(c);
    if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
  }

  void tlsWriteChunk(Connection* c, const char* data, size_t len, bool last) {
    std::string& out = c->scratch;
    out.clear();
    out.reserve(2 * kTlsRecord + 32);  // both ends at their largest: one allocation
    appendChunkSize(out, len);
    const size_t fill = kTlsRecord - out.size();
    out.append(data, fill);
    const size_t first = out.size();
    const size_t whole = (len - fill) / kTlsRecord * kTlsRecord;
    out.append(data + fill + whole, len - fill - whole);
    out += last ? "\r\n0\r\n\r\n" : "\r\n";
    const std::string_view ends(out);
    tlsWrite3(c, ends.substr(0, first), std::string_view(data + fill, whole), ends.substr(first),
              /*terminal=*/last);
  }

  // tlsWrite for three pieces (the copied front of a large chunk, its middle
  // where the caller has it, its copied end), on the same two routes: into
  // the cork buffer inside a batch, behind whatever the batch has gathered;
  // through the ciphertext scratch, or straight to the socket, outside one.
  MORO_NOINLINE void tlsWrite3(Connection* c, std::string_view a, std::string_view b,
                               std::string_view t, bool terminal) {
    if (c->closing) return;
    if (c->corked && tlsGather_.conn == c) {
      tlsUngather(c);
      if (c->closing) return;
    }
    std::string& out = c->corked ? c->corkBuf : cipherScratch_;
    if (!c->corked) out.clear();
    const size_t mark = out.size();
    const bool direct = mark == 0 && tlsDirectOk(c) &&
                        (!c->corked || (c->stagedCount == 0 && !c->aheadComplete));
    if (direct) c->tls->beginDirect(&Server::tlsDirectSend, c);
    const bool ok = c->tls->writePlain(a.data(), a.size(), out, /*more=*/true) &&
                    (b.empty() || c->tls->writePlain(b.data(), b.size(), out, /*more=*/true)) &&
                    c->tls->writePlain(t.data(), t.size(), out);
    if (direct) c->tls->endDirect();
    if (!ok) {
      if (c->corked) out.resize(mark);
      closeForFailedSend(c, /*abort=*/false);
      return;
    }
    if (c->corked) {
      if (terminal) completeCorkedResponse(c);
      if (out.size() >= limits_.writeHighWaterMark) flushCork(c);
      return;
    }
    transportWriteView(c, out, terminal);
    if (out.capacity() > kCipherScratchKeep) {
      out.clear();
      out.shrink_to_fit();
    }
  }

  // A send could not be completed and the connection cannot go on: the TLS
  // session failed to encrypt, or the transport refused the write outright.
  // An HTTP connection is closed here and now, as it always was - its
  // teardown calls nothing (onAborted is itself queued). The teardown of a
  // WebSocket calls onWsClose, and this may be running inside wsSend(), where
  // the binding may be reading the payload straight out of the V8 heap and no
  // JS may run. So its close is queued with the notifications
  // (kNotifyWsGone) and happens on a later loop turn, the way wsSend()'s shed
  // of a slow consumer does. A socket already in its closing handshake has
  // had its onWsClose and is closed at once. Under MORO_ENGINE_NOTIFY=sync
  // the queue delivers in place and the binding copies, as for the shed.
  void closeForFailedSend(Connection* c, bool abort) {
    if (c->isWebSocket && !c->wsClosing) {
      if (!c->wsGonePending) {
        c->wsGonePending = true;
        queueNotify(c->wsId, kNotifyWsGone);
      }
      return;
    }
    if (abort) abortConnection(c);
    else doClose(c);
  }

  // The socket of an open WebSocket refused a frame outright (the peer reset
  // the connection): the frame is dropped and the close queued, as for any
  // send that cannot be completed. Queued instead, the frame would wait for
  // the transport to report the failure on a later pass of the loop, and
  // until then every further frame for this socket - the replies to a whole
  // read's worth of messages - would be held behind it, uncounted on a
  // transport whose queue size no longer includes a write that has failed.
  // Only the errors that say the peer is gone; any other keeps the queued
  // path, as does a socket already in its closing handshake (its Close
  // frame is the last thing written to it).
  bool wsPeerGone(Connection* c, int err) {
    if (!c->isWebSocket || c->wsClosing) return false;
    if (err != UV_EPIPE && err != UV_ECONNRESET && err != UV_ECONNABORTED && err != UV_ENOTCONN) return false;
    closeForFailedSend(c, /*abort=*/true);
    return true;
  }

  // Whether a TLS reply may be written to the socket record by record as it
  // is encrypted (TlsSession::beginDirect): an HTTP response with nothing
  // queued ahead of it. WebSocket frames keep their batch - a read's worth of
  // small frames is one send.
  bool tlsDirectOk(const Connection* c) const {
    return c->pendingWrites == 0 && !c->isWebSocket && !c->closing;
  }

  MORO_NOINLINE static long tlsDirectSend(void* user, const char* held, size_t heldLen,
                                          const char* data, size_t len, bool more) {
    Connection* c = static_cast<Connection*>(user);
    return c->server->tTryWrite2(c, held, heldLen, data, len, more);
  }

  // `held` and then `data` (and then `tail`), in one gathered write when the
  // socket is free. `held` is the connection's cork buffer inside a batch
  // (what the batch has corked so far, with the head, frame header or chunk
  // size line that goes in front of `data` appended) or its scratch buffer
  // outside one; `data` is the caller's and is not referenced after the
  // return; `tail` is what closes a chunk. What the socket does not take is
  // copied: it is what the cork buffer holds afterwards inside a batch (the
  // caller completes the reply and the batch flushes as usual), and is
  // queued outside one, where `terminal` completes the response as it does
  // for any write.
  void writeBehind(Connection* c, std::string& held, const char* data, size_t len, bool terminal,
                   std::string_view tail = std::string_view()) {
    const size_t heldLen = held.size();
    const size_t all = heldLen + len + tail.size();
    size_t sent = 0;
    if (c->pendingWrites == 0 && all <= kMaxWriteChunk) {
      // (tlsDirectSend is tTryWrite2 by the name the TLS session calls it.)
      const long n = tail.empty()
                         ? tlsDirectSend(c, held.data(), heldLen, data, len, /*more=*/false)
                         : tTryWrite3(c, held.data(), heldLen, data, len, tail.data(), tail.size());
      if (n > 0) {
        sent = static_cast<size_t>(n);
      } else if (n < 0 && n != UV_EAGAIN && wsPeerGone(c, static_cast<int>(n))) {
        held.clear();  // the frames of a socket whose peer is gone; its close is queued
        return;
      }
      // would block, or an error the queued write will meet again
    }
    if (sent == all) {
      held.clear();
    } else if (sent >= heldLen) {
      const size_t into = sent - heldLen;  // how far into `data` and `tail` the socket got
      if (into < len) {
        held.assign(data + into, len - into);
        held.append(tail);
      } else {
        held.assign(tail.substr(into - len));
      }
    } else {
      held.erase(0, sent);
      held.append(data, len);
      held.append(tail);
    }
    if (c->corked) return;
    if (held.empty()) {
      if (terminal) transportWriteView(c, std::string_view(), /*terminal=*/true);
      return;
    }
    std::string rest;
    rest.swap(held);
    queueWrite(c, std::move(rest), terminal);
  }

  // encodeFrame for a payload below kWsDirectPayload, expanded where wsSend
  // uses it: the 64-bit length form cannot occur and is not compiled in.
  static MORO_ALWAYS_INLINE void encodeShortFrame(std::string& out, WsOpcode opcode,
                                                  std::string_view payload, bool rsv1) {
    out += char(uint8_t(0x80) | uint8_t(rsv1 ? 0x40 : 0x00) | uint8_t(opcode));
    const size_t n = payload.size();
    if (n <= 125) {
      out += char(uint8_t(n));
    } else {
      out += char(126);
      out += char(uint8_t(n >> 8));
      out += char(uint8_t(n));
    }
    out.append(payload);
  }

  // A large WebSocket message: its frame header, and the payload from where
  // the caller has it - one gathered write on a plaintext connection (behind
  // whatever the read's batch has corked, so the frames keep their order),
  // the two-piece encrypt on TLS.
  MORO_NOINLINE void wsSendDirect(Connection* c, WsOpcode opcode, std::string_view payload,
                                  bool rsv1) {
    char bytes[10];
    const size_t n = encodeFrameHeader(bytes, opcode, payload.size(), /*fin=*/true, rsv1);
    if (c->tls) {
      tlsWrite(c, std::string_view(bytes, n), payload, /*terminal=*/false);
      return;
    }
    std::string& buf = c->corked ? c->corkBuf : c->scratch;
    if (!c->corked) buf.clear();
    buf.append(bytes, n);
    writeBehind(c, buf, payload.data(), payload.size(), /*terminal=*/false);
    if (c->corked && buf.size() >= limits_.writeHighWaterMark) flushCork(c);
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
        if (n < 0 && n != UV_EAGAIN && wsPeerGone(c, n)) return;
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
      tlsWrite(c, data, terminal);
      return;
    }
    transportWriteView(c, data, terminal);
  }

  // Transport-level write from a view the caller owns (Connection::scratch,
  // the TLS ciphertext scratch): the corked and try-write paths read straight
  // from it, and only a queued or backpressured remainder is copied.
  void transportWriteView(Connection* c, std::string_view data, bool terminal) {
    if (c->closing) return;
    if (data.empty() && !terminal) return;  // nothing owed (a TLS reply that went out directly)
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
        if (n < 0 && n != UV_EAGAIN && wsPeerGone(c, n)) return;
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
    if (kind_ == TransportKind::Uring || kind_ == TransportKind::Epoll) {
      if (kind_ == TransportKind::Uring) uringQueueWrite(c, wr);
      else epollQueueWrite(c, wr);
      if (limits_.responseBackpressureLimit && !c->isWebSocket &&
          tPendingBytes(c) > limits_.responseBackpressureLimit) {
        doClose(c);
      }
      return;
    }
#endif
    c->uvQueued += wr->data.size();  // until onWrite
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
      c->uvQueued -= wr->data.size();
      delete wr;
      closeForFailedSend(c, /*abort=*/true);
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
    c->uvQueued -= wr->data.size();
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
        if (c->h2) h2Drained(c);
        else queueNotify(c->reqId, kNotifyWritable);
      }
    }
    if (c->outHeld) resumeHeld(c);
    if (c->closeAfterFlush && c->pendingWrites == 0) closeAfterResponse(c);
  }

  // Response bytes the transport has queued and the kernel has not taken, at
  // or past the write high-water mark: the peer is not reading as fast as
  // responses are produced. A response a handler gives before it returns is
  // complete the moment it is framed (completeCorkedResponse), not when its
  // bytes have left, so the dispatch loops ask this before they take the
  // next request: a peer that pipelines requests and reads nothing would
  // otherwise have every one of them answered into memory. One field read
  // when nothing is queued.
  bool outputBacklogged(Connection* c) {
    return c->pendingWrites > 0 && tOutputHeld(c) >= limits_.writeHighWaterMark;
  }

  // ... and when it is, the connection's request intake is held (outHeld):
  // nothing more is parsed or handed to a handler, what arrives is buffered
  // (dispatchPlaintext), and completeWrite resumes once the queue is below
  // the mark again. Memory per connection stays at the high-water mark plus
  // the one response that crossed it, plus maxPendingBytes of input.
  bool holdForOutput(Connection* c) {
    if (!outputBacklogged(c)) return false;
    c->outHeld = true;
    return true;
  }

  // A write completed on a held connection: once the queue is below the
  // mark, dispatch what was held back - slots still staged first, then
  // whatever was buffered - exactly as finishResponse resumes behind a
  // response that was in flight. Always on a clean stack (write completions
  // are never delivered from inside a dispatch).
  void resumeHeld(Connection* c) {
    if (c->closing || outputBacklogged(c)) return;
    c->outHeld = false;
    if (c->h2 && !c->inputClosed && !c->closeAfterFlush) {
      // HTTP/2: the session goes on with the input it kept (h2Feed).
      c->h2->resume();
      h2Feed(c, "", 0);
      return;
    }
    if (c->active || c->inputClosed || c->closeAfterFlush || c->isWebSocket || c->h2) return;
    if (batchOn_ && (c->stagedCount > 0 || c->aheadComplete)) dispatchBatch(c, ParseStatus::NeedMore, /*parsed=*/false);
    else dispatchBatch(c, parseNext(c), /*parsed=*/true);
  }

  // The last response of the connection (Connection: close, HTTP/1.0, a
  // response that cannot be framed otherwise) has been given: close once it
  // is out. If bytes are still queued the close waits for them
  // (completeWrite), and from this moment nothing the peer sends is read:
  // the exchange is over, and a request that arrives while the last response
  // is draining gets the same treatment as one that arrives after it (see
  // closeAfterResponse) - dropped, not answered behind a response that said
  // "close".
  void closeOnceFlushed(Connection* c) {
    if (c->pendingWrites == 0) {
      closeAfterResponse(c);
      return;
    }
    c->closeAfterFlush = true;
    c->inputClosed = true;
  }

  // Response for the active request is fully flushed: either close or move on to the next pipelined request.
  void finishResponse(Connection* c) {
    if (c->closing) return;
    uint32_t oldId = c->reqId;
    reqMap_->erase(oldId);
    c->active = false;
    c->jsBody.reset();  // a body JS kept lives on in JS; nothing pins it to an idle connection
    c->jsLent.reset();
    recycleBody(c);

    if (!c->reqKeepAlive) {
      closeOnceFlushed(c);
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
    reqMap_->erase(c->reqId);
    c->active = false;
    c->jsBody.reset();
    c->jsLent.reset();
    recycleBody(c);
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
      // A handshake the engine answers itself (wsAutoUpgrade) is never
      // activated from here. Upgrading calls into JS - onWsOpen, and
      // onWsMessage for frames that came with the handshake - and this runs
      // inside the response call that completed the slot ahead of it, where
      // the binding may be reading the body straight out of the V8 heap and
      // nothing may run JS. The slot stays staged: JS's loop is told its
      // batch is over (a cell value of at least the count), and dispatchBatch
      // activates the slot once onRequestBatch has returned.
      //
      // Nor is the next slot activated while the responses already given
      // are waiting on the peer (holdForOutput): the slots stay staged, the
      // loop is told the same thing, and resumeHeld delivers them once the
      // write queue has drained. The response just completed is still in the
      // cork buffer; once that has reached the mark it is written out first
      // (the caller would do it next), so that the check counts it.
      if (c->corkBuf.size() >= limits_.writeHighWaterMark) {
        flushCork(c);
        if (c->closing) return;  // the write failed or went over a limit; the loop has been told
      }
      if ((wsAutoUpgrade_ && c->staged[c->stagedHead].upgrade) || holdForOutput(c)) {
        if (batchControl_ && batchLoopConn_ == c) *batchControl_ = c->batchPos + 1 + c->stagedCount;
        return;
      }
      c->batchPos++;
      if (batchControl_) *batchControl_ = c->batchPos;
      // Only JS's own loop over this connection's batch picks the next slot
      // up from the control cell. Past it (the response came from a microtask
      // or nextTick of the call, or from another connection's handler) the
      // slot is flagged for dispatchBatch to hand over.
      const bool inLoop = batchLoopConn_ == c;
      activateStaged(c);
      if (!inLoop) c->undelivered = true;
    } else if (batchControl_) {
      *batchControl_ = c->batchPos + 1;
    }
  }

  // Flush the accumulated batch with one write. Tries synchronously straight from corkBuf (a full write keeps the buffer's capacity for the next batch); only a partial/backpressured remainder is copied out and queued.
  //
  // The two tests are made where it is called, so a batch that corked
  // nothing - every read of a request body still arriving ends with one -
  // costs a comparison and no call.
  MORO_ALWAYS_INLINE void flushCork(Connection* c) {
    if (c->corkBuf.empty() || c->closing) {
      // Nothing corked - unless the batch's small TLS replies are still to
      // be sealed (tlsCork): their records are put here, and written.
      if (tlsGather_.conn == c) tlsFlushGathered(c);
      return;
    }
    flushCorked(c);
  }

  MORO_NOINLINE void flushCorked(Connection* c) {
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
      // 1. Stage what is already complete. An engine route with no slot
      //    staged ahead of it is answered from the parser right here, in
      //    request order, and never occupies a slot.
      while (parsed && st == ParseStatus::Complete && c->stagedCount < kMaxStaged) {
        if (c->stagedCount == 0 && !c->tls && hasEngineRoutes() && answerFromParser(c)) {
          if (c->batchClose || c->closing) {  // Connection: close - nothing after it is parsed
            parsed = false;
            break;
          }
          if (holdForOutput(c)) {  // the rest waits for the peer to read
            parsed = false;
            break;
          }
          st = parseNext(c);
          continue;
        }
        if (c->parser.light()) {  // see handleParse: its route is gone; never stage a headerless request
          sendErrorAndClose(c, 500);
          parsed = false;
          break;
        }
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
      for (;;) {
        while (c->active) {
          c->batchPos = 0;
          if (batchControl_) *batchControl_ = 0;
          c->undelivered = false;
          Connection* const outer = batchLoopConn_;
          batchLoopConn_ = c;
          cb_.onRequestBatch(cb_.user, c, 1 + c->stagedCount);
          batchLoopConn_ = outer;
          // A slot activated after JS left its loop has reached no handler:
          // give it (and whatever is staged behind it) a call of its own.
          if (!c->undelivered || c->closing || c->isWebSocket || c->batchClose) break;
        }
        // A slot completeCorkedResponse held back - a handshake the engine
        // answers itself - is activated here, where no response call is on
        // the stack. One the engine turns down is active after that and gets
        // a call of its own, like any request.
        if (c->active || c->stagedCount == 0 || c->closing || c->isWebSocket || c->batchClose || c->outHeld) break;
        activateStaged(c);
      }
      if (c->closing || c->isWebSocket || c->batchClose) break;
      if (c->active) break;  // a handler went async; finishResponse resumes the rest
      if (c->outHeld || holdForOutput(c)) break;  // answered into a queue the peer is not draining; resumeHeld goes on
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
    if (c->batchClose && !c->closing) closeOnceFlushed(c);
  }

  // Parse the next request: the bytes buffered while a response was in
  // flight (swapped into a local, as the sequential loop does, so a huge
  // pipelined backlog's capacity is released at scope exit), else whatever
  // the parser still holds. (Inlined into the dispatch loops, where it runs
  // once per pipelined request.)
  MORO_ALWAYS_INLINE ParseStatus parseNext(Connection* c) {
    if (!c->pending.empty()) {
      std::string p;
      p.swap(c->pending);
      return c->parser.parse(p.data(), p.size());
    }
    // Nothing buffered and no partial request: the next one comes with the
    // next read, which is what an empty parse() call would report.
    if (!c->parser.midRequest()) return ParseStatus::NeedMore;
    return c->parser.parse(nullptr, 0);
  }

  // Move the parser's complete request into the next staged slot and reset
  // the parser for what follows. Returns true when nothing after it may be
  // parsed now: a Connection: close request, or an Upgrade request (what
  // follows is not HTTP if the upgrade succeeds).
  bool stageRequest(Connection* c) {
    // A connection gets one slot at first, and the other fifteen the first
    // time a request is staged behind another (it pipelines): one that sends
    // a request at a time - most of them, and every connection that carries
    // a single request - never constructs and destroys the rest.
    if (c->staged.empty()) c->staged.resize(1);
    // An empty ring starts over at its first slot: a connection that sends
    // one request at a time then uses the same slot for every one of them,
    // where walking the ring spread its header and path strings over sixteen
    // sets of buffers, each cold by the time its turn came round again.
    if (c->stagedCount == 0) c->stagedHead = 0;
    else if (c->staged.size() < kMaxStaged) growStaged(c);
    StagedRequest& sr = c->staged[(c->stagedHead + c->stagedCount) % kMaxStaged];
    c->stagedCount++;
    const bool upgrade = c->parser.hasUpgrade();
    sr.expectContinue = !c->sentContinue && c->parser.expectContinue();
    sr.reqId = nextReqId();
    sr.method = c->parser.method;
    // Swap, not copy (see surfaceRequest): the slot's previous buffers become
    // the parser's scratch for the next request.
    swapField(sr.methodStr, c->parser.methodStr);
    sr.path.swap(c->parser.path);
    swapField(sr.query, c->parser.query);
    sr.headers.swap(c->parser.headers);
    swapField(sr.body, c->parser.body);
    sr.isHead = (sr.method == Method::HEAD);
    sr.reqKeepAlive = c->parser.keepAlive;
    sr.reqHttp11 = c->parser.minorVersion >= 1;
    sr.upgrade = upgrade;
    sr.routeMissGen = c->routeMissGen;  // a staged request is never an engine-answered one
    c->parser.reset();
    return !sr.reqKeepAlive || upgrade;
  }

  // The whole ring, for a connection that has started to pipeline. Its one
  // slot keeps its place (index 0, where an empty ring starts), so the ring
  // arithmetic needs no change; no reference to a slot is held across a call
  // to stageRequest.
  MORO_NOINLINE void growStaged(Connection* c) { c->staged.resize(kMaxStaged); }

  // The head staged slot becomes the active request: fields swapped in, id
  // registered, static routes answered right here (which, inside a corked
  // batch, completes it synchronously and activates the next slot in turn).
  void activateStaged(Connection* c) {
    StagedRequest& sr = c->staged[c->stagedHead];
    c->stagedHead = (c->stagedHead + 1) % kMaxStaged;
    c->stagedCount--;
    c->reqId = sr.reqId;
    c->method = sr.method;
    swapField(c->methodStr, sr.methodStr);
    c->path.swap(sr.path);
    swapField(c->query, sr.query);
    c->headers.swap(sr.headers);
    swapField(c->body, sr.body);
    c->jsBody.reset();
    c->jsLent.reset();
    c->isHead = sr.isHead;
    c->reqKeepAlive = sr.reqKeepAlive;
    c->reqHttp11 = sr.reqHttp11;
    c->active = true;
    c->requestTicks = 0;
    // The id was assigned when the request was staged, and a staged id is in
    // no registry, so nextReqId() does not know to skip it: once the 32-bit
    // counter has gone round (2^32 requests on this thread while the slot
    // waited behind a response that was held or not read), the same number
    // can belong to a request that is live now. Registering it here would
    // hand that request's id to this connection, and the response its
    // handler gives would be written here. The live request keeps the id;
    // this one is activated again under a new one.
    if (!reqMap_->insertNew(c->reqId, c)) {
      activateUnderNewId(c);
      return;
    }
    if (sr.expectContinue && !c->sentContinue) {
      // Same interim the sequential loop sends from handleParse (a client
      // that shipped the body with the head still gets it; Node does too).
      c->sentContinue = true;
      std::string cont = "HTTP/1.1 100 Continue\r\n\r\n";
      writeOut(c, std::move(cont), /*terminal=*/false);
    }
    // Looked up when its request line was parsed (the route hook) and not
    // matched, with the tables unchanged since: not looked up again.
    if (hasEngineRoutes() && sr.routeMissGen != routeGen_ && tryStaticRoute(c)) return;
    if (sr.upgrade && wsAutoUpgrade_) autoUpgrade(c);
  }

  // activateStaged found the slot's id bound to another request. The slot is
  // put back at the head of the ring exactly as it was (every swap
  // activateStaged made is made again, which undoes it), given an id that is
  // free now, and activated a second time. Only ever reached once the id
  // counter has wrapped, so it stays out of line.
  MORO_NOINLINE void activateUnderNewId(Connection* c) {
    c->stagedHead = (c->stagedHead + kMaxStaged - 1) % kMaxStaged;
    c->stagedCount++;
    StagedRequest& sr = c->staged[c->stagedHead];
    c->methodStr.swap(sr.methodStr);
    c->path.swap(sr.path);
    c->query.swap(sr.query);
    c->headers.swap(sr.headers);
    c->body.swap(sr.body);
    c->active = false;
    const uint32_t id = nextReqId();
    sr.reqId = id;
    activateStaged(c);
    // JS's loop over this batch was given the old id as this slot's
    // descriptor. If the request is still for a handler (no engine route or
    // upgrade took it), the loop is told its batch is over, as when the
    // connection closes under it, and dispatchBatch delivers the slot in a
    // call of its own, with the id it has now.
    if (c->active && c->reqId == id && batchLoopConn_ == c) {
      if (batchControl_) *batchControl_ = UINT32_MAX;
      c->undelivered = true;
    }
  }

  // wsAutoUpgrade: the engine's own answer to a request that carries an
  // Upgrade header. True when the request is finished with here: the
  // WebSocket is open, or the handshake asked for a protocol version this
  // server does not speak and was answered 426 naming the one it does
  // (RFC 6455 §4.2.2 item 4, §4.4; the Upgrade field is RFC 9110 §15.5.22's
  // requirement for a 426). False leaves the request for JS, as any request
  // that is not a WebSocket handshake.
  bool autoUpgrade(Connection* c) {
    bool unsupportedVersion = false;
    if (upgradeToWebSocket(c, &unsupportedVersion) != 0) return true;
    if (!unsupportedVersion) return false;
    static const std::string kUpgradeRequired =
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n";
    respond(c, 426, kUpgradeRequired, -1, nullptr, 0);
    return true;
  }

  // The finished request's body buffer goes back to the loop's pool (see
  // HttpParser::bodyPool), most recently used last, which is the one the next
  // body is collected into. A buffer too large to be worth keeping is freed,
  // as a large body's always was; one JS took with getBody is JS's and is not
  // here to give, and neither is one lent with getBodyLent.
  static constexpr size_t kBodyPoolSize = 8;
  static constexpr size_t kBodyPoolKeep = 64 * 1024;
  void recycleBody(Connection* c) { recycleBodyBuffer(c->body); }
  void recycleBodyBuffer(std::string& b) {
    if (b.capacity() < HttpParser::kOwnBodyCapacity) return;
    b.clear();
    if (b.capacity() <= kBodyPoolKeep && bodyPool_.size() < kBodyPoolSize) {
      bodyPool_.emplace_back();
      bodyPool_.back().swap(b);
    } else {
      std::string().swap(b);
    }
  }

  uint32_t nextReqId() {
    // Skip ids still bound to live requests: the uint32 counter wraps after
    // 2^32 requests (~12h at 100k rps) and a collision with a still-open
    // long-lived request (e.g. an SSE stream) would silently rebind it.
    const FlatReqMap& reqMap = *reqMap_;
    uint32_t id;
    do {
      id = ++*reqCounter_;
#if defined(MORO_ENGINE_TEST_FAULTS)
      if (testIdPeriod() != 0 && id >= testIdPeriod()) id = *reqCounter_ = 0;
#endif
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
      if (holdForOutput(c)) break;  // answered into a queue the peer is not draining; resumeHeld goes on
      // Response corked and completed synchronously - surface the next buffered pipelined request (completeCorkedResponse already reset the parser; reads cannot interleave while this loop runs).
      if (!c->pending.empty()) {
        std::string p;
        p.swap(c->pending);
        st = c->parser.parse(p.data(), p.size());
      } else if (c->parser.midRequest()) {
        st = c->parser.parse(nullptr, 0);
      } else {
        break;  // nothing buffered: the next request comes with the next read
      }
    }
    c->corked = false;
    if (!c->closing) flushCork(c);
    if (c->batchClose && !c->closing) closeOnceFlushed(c);
  }

  // ---- HTTP/2 ----
  //
  // http2.h is the protocol; this is where it meets the rest of the server.
  // A request arriving on an HTTP/2 stream is put on a Connection of its own
  // (h2Parent set) and from there on is a request like any other: the same
  // registry, the same accessors, the same respond()/writeHead()/write()/
  // end(), whose first act on such a Connection is to come here instead of
  // framing HTTP/1. What is different is all below: how the bytes are framed,
  // and that many requests are in flight on one socket at once.

 public:
  // The request at slot `k` of the batch call in progress (the binding reads
  // their ids, methods and paths; an HTTP/1 batch reads Connection::staged).
  const Connection* h2BatchAt(uint32_t k) const { return h2Batch_[h2BatchBase_ + k]; }

 private:
  static constexpr size_t kH2FreeMax = 1024;

  // Which protocol a connection speaks, decided once: ALPN on TLS, the
  // client preface on cleartext ("prior knowledge", RFC 9113 3.3). Returns
  // true for HTTP/1 - the caller goes on with the same bytes - and false when
  // HTTP/2 consumed them or the preface is not complete yet.
  bool h2Decide(Connection* c, const char* data, size_t len) {
    if (!limits_.http2.enabled) {
      c->proto = 1;
      return true;
    }
    if (c->tls) {
      if (!c->tls->alpnIsH2()) {
        c->proto = 1;
        return true;
      }
      h2Start(c);
      h2Feed(c, data, len);
      return false;
    }
    // Cleartext. The preface is 24 bytes that no HTTP/1 request begins with
    // ("PRI * HTTP/2.0"); it usually arrives whole, and `pending` - unused
    // until a request is in flight - holds a partial one.
    const std::string_view magic = h2::kPreface;
    const size_t have = c->pending.size();
    const size_t cmp = std::min(len, magic.size() - have);
    if (memcmp(data, magic.data() + have, cmp) != 0) {
      c->proto = 1;
      if (have == 0) return true;
      // What looked like the start of a preface was not: it is HTTP/1 input.
      std::string all;
      all.swap(c->pending);
      all.append(data, len);
      dispatchPlaintext(c, all.data(), all.size());
      return false;
    }
    if (have + cmp < magic.size()) {
      c->pending.append(data, len);
      return false;
    }
    h2Start(c);
    if (have != 0) {
      std::string all;
      all.swap(c->pending);
      all.append(data, len);
      h2Feed(c, all.data(), all.size());
    } else {
      h2Feed(c, data, len);
    }
    return false;
  }

  void h2Start(Connection* c) {
    const Http2Options& o = limits_.http2;
    h2::Settings s;
    if (o.maxConcurrentStreams) s.maxConcurrentStreams = o.maxConcurrentStreams;
    if (o.initialWindowSize) s.initialWindowSize = std::min<uint32_t>(o.initialWindowSize, h2::kMaxWindow);
    if (o.maxFrameSize)
      s.maxFrameSize = std::max<uint32_t>(h2::kMinFrameSize, std::min<uint32_t>(o.maxFrameSize, h2::kMaxFrameSizeLimit));
    if (o.headerTableSize) s.headerTableSize = o.headerTableSize;
    s.maxHeaderListSize = o.maxHeaderListSize
                              ? o.maxHeaderListSize
                              : static_cast<uint32_t>(std::min<size_t>(limits_.maxHeadSize, 0x7fffffffu));
    s.connectionWindow = std::max<uint32_t>(s.connectionWindow, s.initialWindowSize);
    s.maxBodySize = limits_.maxBodySize;
    s.maxHeaders = limits_.maxHeaders;
    s.maxUriSize = limits_.maxUriSize;
    h2::Host host;
    host.user = c;
    host.dispatch = [](void* user, h2::Stream& st) {
      Connection* conn = static_cast<Connection*>(user);
      conn->server->h2OnRequest(conn, st);
    };
    host.aborted = [](void* user, void* held) {
      Connection* conn = static_cast<Connection*>(user);
      conn->server->h2OnAborted(static_cast<Connection*>(held));
    };
    host.writable = [](void* user, void* held) {
      Connection* conn = static_cast<Connection*>(user);
      conn->server->h2OnWritable(static_cast<Connection*>(held));
    };
    c->proto = 2;
    c->h2 = new h2::Session(s, host);
    c->h2->start();
  }

  // Bytes for an HTTP/2 connection. Requests completed by them are handed to
  // JS in batches, and every frame the session and the handlers produced
  // meanwhile goes out in one write afterwards - the cork of the HTTP/1
  // batch, for free: nothing is written while the read is being processed.
  //
  // Flow control does not bound what a connection is answered with: a peer
  // may open its windows as wide as the protocol allows and then not read
  // the socket, and every response it asks for is then complete - its stream
  // closed, room for the next - the moment it is framed. So the rule of the
  // HTTP/1 dispatch loops applies here too (outputBacklogged): once the
  // bytes waiting on the peer reach the write high-water mark, nothing more
  // it sent is acted on - the session stops at the frame it is on (h2Throttle
  // inside a read, here after one), what arrives meanwhile is kept, and
  // resumeHeld goes on when the queue has drained below the mark. Memory per
  // connection stays at the mark plus the responses of one batch, plus the
  // input kept.
  void h2Feed(Connection* c, const char* data, size_t len) {
    if (c->closing) return;
    if (c->pendingWrites > 0 && (c->outHeld || holdForOutput(c))) {
      // Kept, not acted on. A client that keeps to flow control can have at
      // most one connection window of DATA on its way, on top of the
      // allowance every connection has for input it is not being read for
      // (maxPendingBytes); more than that into a connection whose answers
      // are not being read is a flood, and is cut off as on HTTP/1.
      c->h2->pause();
      if (c->h2->inputHeld() + len > maxPending_ + c->h2->settings().connectionWindow) {
        doClose(c);
        return;
      }
      c->h2->feed(data, len, uv_now(loop_));
      return;
    }
    for (;;) {
      c->h2Feeding = true;
      c->h2->feed(data, len, uv_now(loop_));
      h2DispatchBatch(c);
      c->h2Feeding = false;
      if (c->closing) return;
      h2Flush(c);
      if (c->closing) return;
      if (c->h2->dead()) {  // a connection error: the GOAWAY is on its way, then close
        if (c->pendingWrites == 0) closeAfterResponse(c);
        else c->closeAfterFlush = true;
        return;
      }
      if (outputBacklogged(c)) {  // the peer is not reading: resumeHeld goes on
        c->h2->pause();
        c->outHeld = true;
        return;
      }
      if (!c->h2->paused()) return;
      // Stopped part-way through the read, and the socket took everything
      // that was written: go on with the rest of it.
      c->h2->resume();
      data = "";
      len = 0;
    }
  }

  // After a request was answered inside a read: stop the session at this
  // frame when what this read has been answered with so far, on top of what
  // the socket still holds, has reached the write high-water mark.
  void h2Throttle(Connection* c) {
    if (c->h2->out().size() + (c->pendingWrites > 0 ? tPendingBytes(c) : 0) >= limits_.writeHighWaterMark)
      c->h2->pause();
  }

  // Put the session's frames on the wire.
  void h2Flush(Connection* c) {
    std::string& out = c->h2->out();
    if (out.empty()) return;
    if (!c->closing) writeOutView(c, out, /*terminal=*/false);
    out.clear();
    if (out.capacity() > 262144) out.shrink_to_fit();
    if (limits_.responseBackpressureLimit && !c->closing &&
        tPendingBytes(c) > limits_.responseBackpressureLimit) {
      doClose(c);
    }
  }

  // After a response call made outside a read (a handler answering later).
  void h2Written(Connection* p) {
    if (!p->h2Feeding && !p->closing) h2Flush(p);
  }

  Connection* h2Acquire() {
    Connection* sc;
    if (!h2Free_.empty()) {
      sc = h2Free_.back();
      h2Free_.pop_back();
    } else {
      sc = new Connection();
    }
    sc->server = this;
    return sc;
  }

  // A complete request on stream `st` of connection `c` (from the session,
  // inside its feed).
  void h2OnRequest(Connection* c, h2::Stream& st) {
    if (c->closing) return;
    Connection* sc = h2Acquire();
    sc->h2Parent = c;
    sc->h2s = &st;
    sc->proto = 2;
    sc->method = st.method;
    // Swapped, as a staged HTTP/1 request is: the stream gets this
    // Connection's previous buffers for the next request it assembles.
    sc->methodStr.swap(st.methodStr);
    sc->path.swap(st.path);
    sc->query.swap(st.query);
    sc->headers.swap(st.headers);
    sc->body.swap(st.body);
    st.headerCount = 0;
    sc->isHead = (sc->method == Method::HEAD);
    sc->reqKeepAlive = true;
    sc->reqHttp11 = true;
    sc->requestTicks = 0;
    sc->reqId = nextReqId();
    sc->active = true;
    globalRequests().insert(sc->reqId, sc);
    c->h2->hold(st, sc);

    if (hasEngineRoutes() && tryStaticRoute(sc)) {
      h2Throttle(c);
      return;
    }
    if (!batchOn_) {
      if (cb_.onRequest) cb_.onRequest(cb_.user, sc);
      h2Throttle(c);
      return;
    }
    h2Batch_.push_back(sc);
    if (h2Batch_.size() >= kMaxStaged) {
      h2DispatchBatch(c);
      h2Throttle(c);
    }
  }

  // Hand the gathered requests to JS: one call for up to kMaxStaged of them.
  // JS answers slot after slot and reads the control cell between them, which
  // h2Done advances when the slot it names completes synchronously; a handler
  // that goes asynchronous leaves the cell where it was and JS returns. On
  // HTTP/1 the rest of the batch then waits for that response. Here nothing
  // has to wait - streams are independent - so the rest is simply delivered
  // in another call.
  void h2DispatchBatch(Connection* c) {
    size_t pos = 0;
    h2BatchParent_ = c;
    while (pos < h2Batch_.size() && !c->closing) {
      const uint32_t count = static_cast<uint32_t>(h2Batch_.size() - pos);
      h2BatchBase_ = pos;
      if (++h2BatchGen_ == 0) h2BatchGen_ = 1;
      for (uint32_t k = 0; k < count; k++) {
        h2Batch_[pos + k]->h2Gen = h2BatchGen_;
        h2Batch_[pos + k]->batchPos = k;
      }
      if (batchControl_) *batchControl_ = 0;
      h2InBatchCall_ = true;
      h2LoopOpen_ = true;
      cb_.onRequestBatch(cb_.user, h2Batch_[pos], count);
      h2InBatchCall_ = false;
      h2LoopOpen_ = false;
      // Where JS stopped: the slot whose handler did not finish, or the count.
      const uint32_t at = batchControl_ ? *batchControl_ : count;
      pos += at >= count ? count : at + 1;
    }
    h2Batch_.clear();
    h2BatchBase_ = 0;
    h2BatchParent_ = nullptr;
  }

  // The handler's last word on `sc` is about to be sent: its stream is no
  // longer held for it (and must not be touched through `sc` again).
  void h2Detach(Connection* sc) {
    if (sc->h2s != nullptr && sc->h2Parent != nullptr && sc->h2Parent->h2 != nullptr)
      sc->h2Parent->h2->release(*sc->h2s);
    sc->h2s = nullptr;
  }

  // The request on `sc` is finished from the handler's side: off the
  // registry, its buffers released, the Connection ready for another request.
  // The stream, if it still has bytes to send, lives on in the session.
  void h2Done(Connection* sc) {
    Connection* p = sc->h2Parent;
    globalRequests().erase(sc->reqId);
    // h2LoopOpen_: once JS has left its loop the cell stays where the loop
    // stopped, so the slots after it are delivered by the next call instead
    // of being counted as handled.
    if (h2InBatchCall_ && h2LoopOpen_ && batchControl_ && sc->h2Gen == h2BatchGen_ &&
        *batchControl_ == sc->batchPos) {
      *batchControl_ = sc->batchPos + 1;  // the next slot, or the count when it was the last
    }
    sc->active = false;
    sc->jsBody.reset();
    sc->jsLent.reset();
    recycleBody(sc);
    if (sc->h2s != nullptr && p != nullptr && p->h2 != nullptr) p->h2->release(*sc->h2s);
    if (sc->wantDrain) h2ForgetWaiter(sc->reqId);
    sc->reqId = 0;
    sc->h2Parent = nullptr;
    sc->h2s = nullptr;
    sc->h2Gen = 0;
    sc->proto = 0;
    sc->isHead = false;
    sc->responseStarted = false;
    sc->responseEnded = false;
    sc->bodylessStatus = false;
    sc->declaredLen = -1;
    sc->bodyBytesSent = 0;
    sc->wantDrain = false;
    sc->abortNotified = false;
    sc->methodStr.clear();
    sc->path.clear();
    sc->query.clear();
    // Reused when there is room, deleted at the next sweep otherwise - never
    // here, where a caller further up the stack may still be reading it.
    (h2Free_.size() < kH2FreeMax ? h2Free_ : h2Dead_).push_back(sc);
  }

  void h2Reap() {
    for (Connection* sc : h2Dead_) delete sc;
    h2Dead_.clear();
  }

  // The peer reset the stream of a request a handler holds (or its
  // connection is going away): JS is told once, unless it never heard of the
  // request - one still waiting in the batch is simply dropped.
  void h2OnAborted(Connection* sc) {
    sc->h2s = nullptr;  // the stream is gone; nothing more can be sent on it
    for (size_t i = h2BatchBase_; i < h2Batch_.size(); i++) {
      if (h2Batch_[i] != sc) continue;
      if (h2InBatchCall_ && sc->h2Gen == h2BatchGen_) break;  // already handed to JS
      h2Batch_.erase(h2Batch_.begin() + static_cast<std::ptrdiff_t>(i));
      sc->abortNotified = true;
      break;
    }
    // The request is released before JS is told. On a later loop turn (the
    // default) the order makes no difference. Delivered in place
    // (MORO_ENGINE_NOTIFY=sync) it does: the callback, and the continuations
    // the microtask checkpoint behind it runs, must find the request gone as
    // they do in the default mode. Told first, a handler woken by onAborted
    // saw isAborted() false and a write() that reported backpressure, and
    // waited for an onWritable that could never come.
    const bool tell = sc->active && !sc->abortNotified;
    const uint32_t reqId = sc->reqId;
    h2Done(sc);
    if (tell) queueNotify(reqId, kNotifyAborted);
  }

  void h2OnWritable(Connection* sc) {
    if (!sc->wantDrain || !sc->active) return;
    sc->wantDrain = false;
    h2ForgetWaiter(sc->reqId);
    queueNotify(sc->reqId, kNotifyWritable);
  }

  // The connection's socket drained: every request on it that was told to
  // wait may write again.
  void h2Drained(Connection* p) {
    for (size_t i = 0; i < h2Waiters_.size();) {
      if (h2Waiters_[i].second != p) {
        i++;
        continue;
      }
      const uint32_t reqId = h2Waiters_[i].first;
      h2Waiters_[i] = h2Waiters_.back();
      h2Waiters_.pop_back();
      Connection* sc = lookup(reqId);
      if (sc != nullptr && sc->h2Parent == p && sc->wantDrain) {
        sc->wantDrain = false;
        queueNotify(reqId, kNotifyWritable);
      }
    }
  }

  void h2ForgetWaiter(uint32_t reqId) {
    for (size_t i = 0; i < h2Waiters_.size(); i++) {
      if (h2Waiters_[i].first == reqId) {
        h2Waiters_[i] = h2Waiters_.back();
        h2Waiters_.pop_back();
        return;
      }
    }
  }

  // The frames an HTTP/2 connection is closed with (see doClose).
  void h2Goodbye(Connection* p) {
    if (p->h2->dead()) return;  // a connection error already said GOAWAY
    p->h2->shutdown();
    h2Flush(p);
  }

  // The connection is closing while the batch call in progress is its own
  // (a handler closed the server, or the connection went over a limit): the
  // slots JS's loop has not reached must never reach a handler. Their
  // requests are about to be released (h2Teardown), and the descriptors JS
  // holds would name requests that no longer exist. They were never handed
  // over, so they get no onAborted either; the loop is told its batch is
  // over. The slot the cell names stays as it is - its handler may be the
  // one running - and is told once, like any request a handler holds.
  void h2CutBatch() {
    if (!batchControl_) return;
    const uint32_t count = static_cast<uint32_t>(h2Batch_.size() - h2BatchBase_);
    const uint32_t at = *batchControl_;
    for (uint32_t k = at < count ? at + 1 : count; k < count; k++) {
      Connection* sc = h2Batch_[h2BatchBase_ + k];
      if (sc->h2Gen == h2BatchGen_ && sc->active) sc->abortNotified = true;
    }
    if (h2LoopOpen_) {
      *batchControl_ = count;
      h2LoopOpen_ = false;  // the cell is final for this call
    }
  }

  // The connection is closing: every request in flight on it is over.
  void h2Teardown(Connection* p) {
    if (h2InBatchCall_ && h2BatchParent_ == p) h2CutBatch();
    std::vector<Connection*> held;
    p->h2->forEachHeld([&held](void* user) { held.push_back(static_cast<Connection*>(user)); });
    // (Each is checked again when its turn comes: told in place, a handler
    // may answer another of these requests from inside onAborted, and that
    // one is then finished and must not be finished a second time.)
    for (Connection* sc : held) {
      if (sc->h2Parent == p && sc->active) h2OnAborted(sc);
    }
    for (size_t i = 0; i < h2Waiters_.size();) {
      if (h2Waiters_[i].second == p) {
        h2Waiters_[i] = h2Waiters_.back();
        h2Waiters_.pop_back();
      } else {
        i++;
      }
    }
    p->h2->abandon();
  }

  // The header block of a response: the status and the application's headers
  // (from the template's cache when there is one), then the Date field.
  // `headersBlock` is the HTTP/1 form the binding builds - "Name: value\r\n"
  // lines - so one representation serves both protocols; names are lowercased
  // here, and the headers that describe an HTTP/1 connection are dropped.
  void h2Head(std::string& out, int status, const std::string& headersBlock,
              const ResponseTemplate* tpl) {
    if (tpl != nullptr) {
      if (tpl->h2Block.empty()) h2EncodeHead(tpl->h2Block, status, headersBlock);
      out.append(tpl->h2Block);
    } else {
      h2EncodeHead(out, status, headersBlock);
    }
    const std::string& line = dateLine();  // "Date: <29 bytes>\r\n"
    if (h2DateAt_ != dateCachedAt_ || h2Date_.empty()) {
      h2Date_.clear();
      h2::encodeField(h2Date_, "date", std::string_view(line).substr(6, line.size() - 8));
      h2DateAt_ = dateCachedAt_;
    }
    out.append(h2Date_);
  }

  static void h2EncodeHead(std::string& out, int status, const std::string& headersBlock) {
    h2::encodeStatus(out, status);
    char lower[128];
    size_t pos = 0;
    const size_t n = headersBlock.size();
    while (pos < n) {
      size_t eol = headersBlock.find("\r\n", pos);
      if (eol == std::string::npos) eol = n;
      const size_t colon = headersBlock.find(':', pos);
      if (colon != std::string::npos && colon < eol && colon > pos) {
        const size_t nameLen = colon - pos;
        std::string_view value = trimOWS(std::string_view(headersBlock).substr(colon + 1, eol - colon - 1));
        std::string big;
        char* name = lower;
        if (nameLen > sizeof(lower)) {
          big.resize(nameLen);
          name = &big[0];
        }
        for (size_t i = 0; i < nameLen; i++) {
          const char ch = headersBlock[pos + i];
          name[i] = (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + 32) : ch;
        }
        const std::string_view lname(name, nameLen);
        if (!h2::isConnectionSpecific(lname) && lname != "content-length")
          h2::encodeField(out, lname, value, /*sensitive=*/lname == "set-cookie");
      }
      pos = eol + 2;
    }
  }

  static void h2ContentLength(std::string& out, unsigned long long v) {
    char buf[20];
    char* p = buf + sizeof(buf);
    do {
      *--p = static_cast<char>('0' + (v % 10));
      v /= 10;
    } while (v != 0);
    h2::encodeField(out, "content-length", std::string_view(p, static_cast<size_t>(buf + sizeof(buf) - p)));
  }

  // respond() for an HTTP/2 request: HEADERS, then the body as DATA.
  void h2Respond(Connection* sc, int status, const std::string& headersBlock, long long customCL,
                 const char* body, size_t bodyLen, const ResponseTemplate* tpl) {
    Connection* p = sc->h2Parent;
    h2::Stream* st = sc->h2s;
    if (st == nullptr || p->closing) {
      h2Done(sc);
      return;
    }
    // After writeHead() the head is out: a second HEADERS frame would be a
    // malformed response, so this one only finishes the body.
    if (sc->responseStarted) {
      h2End(sc, body, bodyLen);
      return;
    }
    const bool bodyless = isBodyless(status);
    if (bodyless || status == 205) bodyLen = 0;
    std::string& block = h2Block_;
    block.clear();
    h2Head(block, status, headersBlock, tpl);
    // Content-Length exactly as the HTTP/1 path declares it (appendResponseHead).
    if (!bodyless) {
      h2ContentLength(block, (sc->isHead && customCL >= 0 && status != 205)
                                 ? static_cast<unsigned long long>(customCL)
                                 : static_cast<unsigned long long>(bodyLen));
    } else if (customCL >= 0 && status == 304) {
      h2ContentLength(block, static_cast<unsigned long long>(customCL));
    }
    const bool noBody = sc->isHead || bodyLen == 0;
    h2::Session* session = p->h2;
    // The stream is let go of first - once END_STREAM is out it no longer
    // exists - and the request's own buffers last: `body` may be one of
    // them (a lent body sent straight back).
    h2Detach(sc);
    session->sendHeaders(*st, block, noBody);
    if (!noBody) session->sendData(*st, body, bodyLen, /*endStream=*/true);
    h2Done(sc);
    h2Written(p);
  }

  void h2WriteHead(Connection* sc, int status, const std::string& headersBlock, long long customCL,
                   const ResponseTemplate* tpl) {
    Connection* p = sc->h2Parent;
    h2::Stream* st = sc->h2s;
    sc->responseStarted = true;
    sc->bodylessStatus = isBodyless(status);
    sc->bodyBytesSent = 0;
    if (status == 205) customCL = 0;  // no content (see writeHead)
    sc->declaredLen = sc->bodylessStatus ? 0 : customCL;
    if (st == nullptr || p->closing) return;
    std::string& block = h2Block_;
    block.clear();
    h2Head(block, status, headersBlock, tpl);
    // A length on a 304 only, among the statuses without a body (see writeHead).
    if (customCL >= 0 && (!sc->bodylessStatus || status == 304))
      h2ContentLength(block, static_cast<unsigned long long>(customCL));
    p->h2->sendHeaders(*st, block, /*endStream=*/false);
    h2Written(p);
  }

  bool h2Write(Connection* sc, const char* data, size_t len) {
    if (!sc->responseStarted) h2WriteHead(sc, 200, std::string(), -1, nullptr);
    Connection* p = sc->h2Parent;
    h2::Stream* st = sc->h2s;
    if (st == nullptr || p->closing) return false;
    if (sc->isHead || sc->bodylessStatus || len == 0) return true;
    if (sc->declaredLen >= 0) {  // never past a declared Content-Length (8.1.1 makes that malformed)
      const unsigned long long declared = static_cast<unsigned long long>(sc->declaredLen);
      if (sc->bodyBytesSent >= declared) return true;
      if (sc->bodyBytesSent + len > declared) len = static_cast<size_t>(declared - sc->bodyBytesSent);
    }
    sc->bodyBytesSent += len;
    const size_t heldBack = p->h2->sendData(*st, data, len, /*endStream=*/false);
    h2Written(p);
    if (p->closing) return false;
    // Two things can be full: the stream's flow-control window (the session
    // tells us when it opens) and the socket (completeWrite does).
    if (heldBack >= limits_.writeHighWaterMark) {
      sc->wantDrain = true;
      st->wantDrain = true;
      return false;
    }
    if (tPendingBytes(p) >= limits_.writeHighWaterMark) {
      sc->wantDrain = true;
      p->wantDrain = true;
      h2Waiters_.emplace_back(sc->reqId, p);
      return false;
    }
    return true;
  }

  void h2End(Connection* sc, const char* data, size_t len) {
    Connection* p = sc->h2Parent;
    h2::Stream* st = sc->h2s;
    if (st == nullptr || p->closing) {
      h2Done(sc);
      return;
    }
    h2::Session* session = p->h2;
    if (!sc->responseStarted) {  // end() without writeHead(): a 200 with this as the whole body
      std::string& block = h2Block_;
      block.clear();
      h2Head(block, 200, std::string(), nullptr);
      const bool noBody = sc->isHead || len == 0;
      h2ContentLength(block, sc->isHead ? 0 : len);
      h2Detach(sc);
      session->sendHeaders(*st, block, noBody);
      if (!noBody) session->sendData(*st, data, len, /*endStream=*/true);
      h2Done(sc);
      h2Written(p);
      return;
    }
    if (sc->isHead || sc->bodylessStatus) {
      len = 0;
    } else if (sc->declaredLen >= 0) {
      const unsigned long long declared = static_cast<unsigned long long>(sc->declaredLen);
      if (sc->bodyBytesSent >= declared) len = 0;
      else if (sc->bodyBytesSent + len > declared) len = static_cast<size_t>(declared - sc->bodyBytesSent);
    }
    const bool shortOfDeclared =
        !sc->isHead && !sc->bodylessStatus && sc->declaredLen >= 0 &&
        sc->bodyBytesSent + len < static_cast<unsigned long long>(sc->declaredLen);
    h2Detach(sc);
    if (shortOfDeclared) {
      // Fewer bytes than the Content-Length promised: the response is
      // malformed if it ends normally, so it is cut off instead - what
      // closing the connection says on HTTP/1.
      if (len) session->sendData(*st, data, len, /*endStream=*/false);
      session->reset(*st, h2::kInternalError);
    } else {
      session->sendData(*st, data, len, /*endStream=*/true);
    }
    h2Done(sc);
    h2Written(p);
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

#if defined(__linux__)
  // ---- the libuv transport's listener (Linux) ----
  // The connections are libuv streams; the listener is not. libuv's own
  // makes one accept call per readiness report and, when that fails for want
  // of a descriptor and the spare one it keeps for the occasion is gone
  // (another thread took it while it was lent out), returns without a word:
  // the connection stays queued, the listener is reported again on the next
  // loop turn, and the next - a loop that never sleeps for as long as the
  // process stays at its limit. Nothing in its API stops a listener short of
  // closing it. So on Linux the socket is opened, bound and watched here (a
  // poll handle), accept is called here, and each accepted descriptor is
  // handed to a libuv stream: the options libuv sets (SO_REUSEADDR,
  // dual-stack on an IPv6 address), and the same pause at the limit as the
  // epoll and io_uring transports. (Elsewhere the listener is libuv's: the
  // macOS kernel drops a connection whose accept fails for want of a
  // descriptor, so nothing stays queued to be reported again.)
  int uvListen(const sockaddr_storage& addr) {
    const socklen_t len = addr.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (addr.ss_family == AF_INET6) {
      int off = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }
    if (limits_.reusePort) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));  // inherited by every accepted socket
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), len) < 0 || ::listen(fd, limits_.backlog) < 0) {
      int e = -errno;
      ::close(fd);
      return e;
    }
    uvListenPoll_.data = this;
    int r = uv_poll_init(loop_, &uvListenPoll_, fd);
    if (r != 0) {
      ::close(fd);
      return r;
    }
    uvListenFd_ = fd;
    liveHandles_++;  // balanced in onUvListenPollClosed
    // The descriptor that is given up for a moment to turn a waiting peer
    // away at the limit (uvOnListener). Without one - the process is at its
    // limit already - accepting pauses instead.
    uvSpareFd_ = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    uv_poll_start(&uvListenPoll_, UV_READABLE, onUvListenPoll);
    return 0;
  }

  static void onUvListenPoll(uv_poll_t* h, int, int) {
    static_cast<Server*>(h->data)->uvOnListener();
  }

  // One accept per readiness report, as libuv's listener makes: a connection
  // still waiting is reported again on the next loop turn. (Never called
  // once the listener is closed: its watcher is closed with it.)
  void uvOnListener() {
    int fd = ::accept4(uvListenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      if (errno == EMFILE || errno == ENFILE) {
        // Out of descriptors: the spare one is given up for as long as it
        // takes to accept one waiting connection and close it, so that its
        // peer sees a close instead of a hang.
        if (uvSpareFd_ >= 0) {
          ::close(uvSpareFd_);
          int d = ::accept4(uvListenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (d >= 0) ::close(d);
          uvSpareFd_ = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        }
        // Without the spare (something else in the process took the
        // descriptor while it was lent out, or there never was one) the
        // connection can be neither accepted nor dropped, and the listener
        // would report it on every loop turn. It is left alone until a
        // descriptor may be free again (resumeAccept).
        if (uvSpareFd_ < 0) pauseAccept();
      } else if (errno == ENOBUFS || errno == ENOMEM) {
        pauseAccept();  // the same: the connection stays queued, and so would the event
      }
      return;  // EAGAIN, a connection that went away, or an error: nothing to accept right now
    }
    // Connection-flood defense: over the cap, accept then close at once.
    if (limits_.maxConnections && conns_.size() >= limits_.maxConnections) {
      ::close(fd);
      return;
    }
    Connection* c = new Connection();
    c->server = this;
    c->handle.data = c;
    uv_tcp_init(loop_, &c->handle);
    liveHandles_++;  // balanced by onCloseFree's decrement
    if (uv_tcp_open(&c->handle, fd) != 0) {
      ::close(fd);
      uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
      return;
    }
    attachConnection(c);
    uv_read_start(reinterpret_cast<uv_stream_t*>(&c->handle), onAlloc, onRead);
  }

  // The socket is closed here and now, as libuv closes a listener of its
  // own: the port is free the moment close() or stopListening() returns.
  // libuv has let go of the descriptor once uv_close() has returned.
  void uvCloseListener() {
    if (uvListenFd_ < 0) return;
    uv_close(reinterpret_cast<uv_handle_t*>(&uvListenPoll_), onUvListenPollClosed);
    ::close(uvListenFd_);
    uvListenFd_ = -1;
    if (uvSpareFd_ >= 0) ::close(uvSpareFd_);
    uvSpareFd_ = -1;
  }
  static void onUvListenPollClosed(uv_handle_t* h) {
    Server* s = static_cast<Server*>(h->data);
    s->liveHandles_--;
    s->checkFullyClosed();  // may delete s
  }

  void uvPauseAccept() { uv_poll_stop(&uvListenPoll_); }
  void uvResumeAccept() {
    if (uvListenFd_ < 0 || listenerClosed_ || closeRequested_) return;
    if (uvSpareFd_ < 0) uvSpareFd_ = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    uv_poll_start(&uvListenPoll_, UV_READABLE, onUvListenPoll);
  }
  int uvListenFd_ = -1;
  int uvSpareFd_ = -1;
  uv_poll_t uvListenPoll_{};
#endif

  // Transport-neutral tail of accepting a connection: protocol state, TLS
  // session, registry. The caller then starts reads its own way.
  void attachConnection(Connection* c) {
    c->parser = HttpParser(limits_);
    c->parser.routeHook = &Server::routeHook;
    c->parser.routeHookUser = c;
    c->parser.bodyPool = &bodyPool_;
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
    Server* s = static_cast<Connection*>(handle->data)->server;
    if (s->readBufSize_ < suggested) {
      // No buffer yet - or the last read was a full one (onRead), which
      // shows here as a buffer of no size: nothing is added to the path of
      // an ordinary read. One read per stream per loop turn: libuv reads a
      // stream again at once whenever a read filled its buffer, up to 32
      // times - two megabytes of one peer's input, each small frame of it a
      // call into the application, with every timer and every other
      // connection waiting behind it. So that second request is declined (no
      // buffer; libuv reports UV_ENOBUFS to onRead and leaves the stream as
      // it is): the bytes stay in the socket and are reported again on the
      // next turn, which is how the epoll transport reads.
      if (s->uvDeclined_) {
        const bool again = s->uvDeclined_ == static_cast<Connection*>(handle->data);
        s->uvDeclined_ = nullptr;
        s->readBufSize_ = s->uvReadBufKept_;
        if (again) {
          buf->base = nullptr;
          buf->len = 0;
          return;
        }
      }
      if (s->readBufSize_ < suggested) {
        s->readBuf_.reset(new char[suggested]);
        s->readBufSize_ = suggested;
      }
    }
    buf->base = s->readBuf_.get();
    buf->len = static_cast<unsigned>(s->readBufSize_);
#endif
  }

  static void onRead(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    Connection* c = static_cast<Connection*>(handle->data);
    Server* s = c->server;
    if (nread < 0) {
#if !defined(_WIN32)
      if (nread == UV_ENOBUFS) return;  // the read onAlloc declined: nothing was read, nothing is wrong
#endif
      s->onTransportEof(c);
      return;
    }
    if (nread == 0) return;
    if (nread >= static_cast<ssize_t>(kUvReadBound)) {
      s->onFullRead(c, buf->base, static_cast<size_t>(nread));
      return;
    }
    // The protocol is chosen here, where no frame has been set up yet, and
    // each of the plaintext ones is a function of its own: what an HTTP/1
    // request pays on its way in does not depend on the others. (Behind
    // onTransportData they share one function with HTTP/1, and each adds to
    // it - registers to save for the WebSocket and HTTP/2 paths, the frame
    // of the TLS output buffer - by as much as the build's profile makes of
    // them; on this transport nothing else absorbs that.)
    if (c->tls) {
      s->onTransportData(c, buf->base, static_cast<size_t>(nread));
      return;
    }
    if (c->isWebSocket) {
      s->onWebSocketRead(c, buf->base, static_cast<size_t>(nread));
      return;
    }
    s->onPlainRead(c, buf->base, static_cast<size_t>(nread));
  }

  // A plaintext read that is not a WebSocket's: what onTransportData does
  // with it, HTTP/1 first.
  MORO_NOINLINE void onPlainRead(Connection* c, char* base, size_t nread) {
    if (c->inputClosed) return;
    c->idleTicks = 0;
    if (c->proto != 1) {
      // HTTP/2, or a connection whose first bytes have yet to say which
      // (h2Decide) - unless HTTP/2 is off, which settles it here.
      if (c->proto != 0 || limits_.http2.enabled) {
        onOtherProtocol(c, base, nread);
        return;
      }
      c->proto = 1;
    }
    dispatchHttp1(c, base, nread);
  }
  MORO_NOINLINE void onOtherProtocol(Connection* c, char* base, size_t nread) {
    dispatchPlaintext(c, base, nread);
  }
  // ... and a plaintext WebSocket's.
  MORO_NOINLINE void onWebSocketRead(Connection* c, char* base, size_t nread) {
    if (c->inputClosed) return;
    c->idleTicks = 0;
    feedWebSocket(c, base, nread);
  }

  // The libuv transport's share of a loop turn for one stream: one read of
  // this size (libuv asks for 64 KiB). libuv follows a read that filled the
  // buffer with another at once, up to 32 times, and there are two ways of
  // not having it:
  //  - POSIX: its request for the next buffer is declined (onAlloc). Nothing
  //    is added to the stream's state; the bytes stay in the socket and are
  //    reported on the next turn.
  //  - Windows: the stream stops reading (uv_read_stop ends libuv's loop over
  //    it and leaves no read queued) and is started again from the check
  //    phase of the same turn (onUvResume), so that its next read is the next
  //    turn's. Declining a buffer there would lean on how libuv's IOCP code
  //    happens to queue its reads; stopping and starting is its documented
  //    interface.
  // The second way works everywhere, and MORO_ENGINE_TEST_UV_READ_RESTART=1
  // (read once; for tests) selects it on POSIX too, so that what Windows runs
  // is run where the suites are.
  static constexpr size_t kUvReadBound = 64 * 1024;
  static bool uvBoundByRestart() {
#if defined(_WIN32)
    return true;
#else
    static const bool on = [] {
      const char* e = std::getenv("MORO_ENGINE_TEST_UV_READ_RESTART");
      return e && *e && *e != '0';
    }();
    return on;
#endif
  }
  MORO_NOINLINE void onFullRead(Connection* c, char* base, size_t nread) {
    if (uvBoundByRestart()) {
      uvStopReading(c);
    } else {
#if !defined(_WIN32)
      if (!uvDeclined_) {
        uvReadBufKept_ = readBufSize_;
        readBufSize_ = 0;
      }
      uvDeclined_ = c;
#endif
    }
    onTransportData(c, base, nread);
  }
#if !defined(_WIN32)
  Connection* uvDeclined_ = nullptr;  // the stream whose next buffer request is declined
  size_t uvReadBufKept_ = 0;          // readBufSize_, which reads 0 meanwhile
#endif

  // Stop the stream for the rest of this turn. Before its bytes are
  // dispatched: whatever the dispatch does to the connection - close it,
  // upgrade it, close the server - finds a stream that is simply not reading.
  void uvStopReading(Connection* c) {
    uv_read_stop(reinterpret_cast<uv_stream_t*>(&c->handle));
    if (closeRequested_) return;  // (being torn down: nothing is started again)
    uvStopped_.push_back(c);
    if (!uvResumeInit_) {
      uvResume_.data = this;
      uv_check_init(loop_, &uvResume_);
      uvResumeInit_ = true;
      liveHandles_++;  // balanced by onServerHandleClosed (close())
    }
    // Active only while a stream is stopped, and a reference on the loop for
    // that long: a stopped stream holds none of its own.
    if (!uvResumeOn_) {
      uvResumeOn_ = true;
      uv_check_start(&uvResume_, onUvResume);
    }
  }

  // The check phase of the turn in which streams were stopped: each is
  // started again unless it has been closed meanwhile. A closed connection
  // has left conns_ (doClose) and is not touched; its memory is freed by the
  // close callback, later in the loop, and should that order ever be another
  // one the address is at worst that of a newer connection, which is reading
  // already (UV_EALREADY). A stream that cannot be started again is ended
  // like one whose read failed: none is left stopped.
  static void onUvResume(uv_check_t* h) {
    Server* s = static_cast<Server*>(h->data);
    s->uvResumeOn_ = false;
    uv_check_stop(&s->uvResume_);
    std::vector<Connection*> list;
    list.swap(s->uvStopped_);
    for (Connection* c : list) {
      if (s->conns_.count(c) == 0) continue;
      uv_stream_t* stream = reinterpret_cast<uv_stream_t*>(&c->handle);
      if (uv_is_closing(reinterpret_cast<uv_handle_t*>(stream))) continue;
      const int r = uv_read_start(stream, onAlloc, onRead);
      if (r != 0 && r != UV_EALREADY) s->onTransportEof(c);
    }
  }

  // EOF or a read error on the transport: notify an in-flight request / WS
  // exactly once, then tear the connection down. A request that was awaiting
  // its response is aborted by the teardown itself (doClose), which tells JS
  // once the request has been released; told from here, ahead of it, a
  // notification delivered in place (MORO_ENGINE_NOTIFY=sync) reached a
  // handler whose request still looked alive.
  void onTransportEof(Connection* c) {
    if (c->isWebSocket) wsGone(c);
    abortConnection(c);
  }

  // The peer of a WebSocket is gone without a closing handshake (EOF, a
  // read error, a TLS failure): JS is told once, with 1006 (abnormal
  // closure, §7.1.5). wsClosing is set BEFORE the callback: a wsClose()
  // made from inside it must find the socket already closing and return
  // (set afterwards, it would pass wsClose's guard and fire onWsClose a
  // second time), and wsSend() from inside it must report false. The socket
  // stays registered until the callback has returned, so wsGetHeaders() and
  // the other accessors still answer inside it.
  void wsGone(Connection* c) {
    if (!c->wsClosing) {
      c->wsClosing = true;
      if (cb_.onWsClose) cb_.onWsClose(cb_.user, c, 1006);
    }
    globalWebSockets().erase(c->wsId);
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
    // The same goes for a connection whose request was rejected, from the
    // moment the error response is written or queued (inputClosed covers
    // both): the parser stopped at the error, and nothing sent behind a
    // rejected request is read.
    if (c->inputClosed) return;
    c->idleTicks = 0;  // activity: reset the idle sweep counter

    if (c->tls) {
      // Ciphertext: pump through the TLS transform; decrypted bytes re-enter the exact plaintext path below via dispatchPlaintext. Outbound ciphertext (handshake flights, key updates, alerts) must go to the wire even when the pump reports failure.
      std::string cipherOut;
      bool ok = c->tls->onCiphertext(
          base, nread,
          [&](const char* d, size_t n) {
            // Handshake output ahead of this plaintext (the session tickets
            // TLS 1.3 sends right after the handshake, when the request rode
            // in with the client's Finished) goes out before the dispatch
            // can answer: records are sequenced, and a response written
            // first would arrive at the peer out of order.
            if (!cipherOut.empty() && !c->closing) {
              std::string flight;
              flight.swap(cipherOut);
              s->tlsAnswer(c, std::move(flight));
            }
            if (!c->closing) s->dispatchPlaintext(c, d, n);
          },
          cipherOut);
      if (!c->closing && !cipherOut.empty())
        s->tlsAnswer(c, std::move(cipherOut));
      if (!ok && !c->closing) {
        // Fatal TLS error or clean close_notify: same bookkeeping as EOF - notify an in-flight request/WS exactly once, then tear down.
        if (c->isWebSocket) s->wsGone(c);
        s->abortConnection(c);
      }
      return;
    }
    s->dispatchPlaintext(c, base, nread);
  }

  // What the TLS library wrote while reading (handshake flights, and after
  // the handshake its answers to the peer's own records: a KeyUpdate for each
  // KeyUpdate that asks for one, an alert for each renegotiation request it
  // refuses). The peer decides how many of those there are, and a peer that
  // sends them without reading would have every answer queued behind the
  // last, a byte held here for each byte it sends. So what it has left
  // unread of them is bounded: a client that reads never comes near the
  // bound (an answer is a few dozen bytes), and one that does not is closed
  // at it. May tear the connection down.
  static constexpr size_t kTlsAnswerBacklog = 256 * 1024;
  void tlsAnswer(Connection* c, std::string&& out) {
    const bool drained = c->pendingWrites == 0;
    const size_t n = out.size();
    transportWrite(c, std::move(out), /*terminal=*/false);
    if (c->closing || c->pendingWrites == 0) return;
    // With nothing queued before it, what is queued now is the part of this
    // write the socket did not take.
    size_t& queued = c->tls->answerQueued;
    queued = drained ? tPendingBytes(c) : queued + n;
    if (queued > kTlsAnswerBacklog) {
      // The same bookkeeping as a failed read: JS is told once.
      if (c->isWebSocket) wsGone(c);
      abortConnection(c);
    }
  }

  // Plaintext ingestion - identical for direct TCP reads and decrypted TLS records. May tear the connection down (doClose sets c->closing; the Connection object itself stays alive until uv's close callback).
  void dispatchPlaintext(Connection* c, const char* data, size_t len) {
    if (c->proto != 1) {
      if (c->proto == 2) {
        h2Feed(c, data, len);
        return;
      }
      if (!h2Decide(c, data, len)) return;  // HTTP/2 took the bytes, or more are needed to tell
    }
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
    dispatchHttp1(c, data, len);
  }

  // HTTP/1 input: the rest of dispatchPlaintext, and what the libuv
  // transport hands a plaintext HTTP/1 read to directly (onPlainRead).
  // Always inline: it is part of dispatchPlaintext as it was before it had a
  // name of its own. Buffered while a response is in flight ...
  MORO_ALWAYS_INLINE void dispatchHttp1(Connection* c, const char* data, size_t len) {
    // ... or responses already given are waiting on the peer (outHeld, or a
    // queue found over the mark now): the same buffering, until the write
    // queue drains (resumeHeld). outHeld is only ever set while writes are
    // pending, so a connection with nothing queued pays one field read here.
    if (c->active || (c->pendingWrites > 0 && (c->outHeld || holdForOutput(c)))) {
      // A response is in flight; buffer bytes for after it completes. Cap the buffer so a client can't pipeline unbounded requests and exhaust memory while we're busy (the parser enforces per-request limits, but this bounds the not-yet-parsed backlog). A response is already in flight, so we can't inject an error status - hard-close the flood.
      // The cap is on everything received and not yet dispatched: `pending`
      // and the input the parser still holds behind the requests it has
      // handed over. Each time dispatch resumes, `pending` moves into the
      // parser, and one request (or one write queue's worth) is taken out of
      // it; counting `pending` alone let a peer add another maxPendingBytes
      // per response for as long as it liked.
      if (c->pending.size() + c->parser.leftover().size() + len > maxPending_) {
        doClose(c);
        return;
      }
      c->pending.append(data, len);
      return;
    }
    // Nothing queued on the connection in either direction and the parser
    // idle: the fast lane (parsed in place, an engine route answered from
    // its cache) or, failing that, the same dispatch as below with the
    // parse it already did.
    if (!c->tls && !c->closing && c->stagedCount == 0 && !c->aheadComplete &&
        c->pendingWrites == 0 && c->corkBuf.empty() && c->parser.idle() && hasEngineRoutes()) {
      fastLane(c, data, len);
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
    // The binding, when it asks for it, wraps the whole read in the scopes
    // a JS call needs and calls feedWebSocketFrames from inside.
    if (cb_.onWsRead) {
      cb_.onWsRead(cb_.user, c, data, len);
      return;
    }
    feedWebSocketFrames(c, data, len);
  }

  // The frames of one read, each delivered through the callbacks. Called
  // from feedWebSocket, or from the binding's onWsRead (see ServerCallbacks),
  // which is why it is public.
 public:
  void feedWebSocketFrames(Connection* c, char* data, size_t len) {
    if (c->wsClosing || !c->wsParser) return;
    // Corked for the whole read: every reply this buffer provokes - the echo
    // of each frame of a pipelined batch, a Pong, a Close - accumulates in
    // corkBuf and leaves in ONE write once consume() returns, where it used
    // to be one send() per frame (sixteen frames in a segment, sixteen
    // syscalls). The replies keep their order; the Close frame of a batch
    // sets batchClose through completeCorkedResponse exactly as a
    // Connection: close response does inside an HTTP batch, and the tail
    // below closes the socket once the flush is out. Nested inside an HTTP
    // dispatch loop (frames that arrived with the upgrade request, fed from
    // upgradeToWebSocket) the enclosing loop's own tail flushes and closes.
    const bool outerCorked = c->corked;
    if (!outerCorked) {
      c->corked = true;
      c->batchClose = false;
    }
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
          // The same once a message of this read has failed to inflate: the
          // connection is about to be failed for it (below), and the frames
          // behind it in the buffer are not delivered.
          if (c->wsClosing || c->closing || pmdFail) return;
          if (compressed && c->pmd) {
            // Inflate (hard output cap = zip-bomb defense), then UTF-8-validate text post-inflate (the parser skipped it for compressed frames).
            std::string inflated;
            if (!c->pmd->inflateMessage(payload, inflated)) {
              // §7.4.1: 1009 for a message too big to process (past the
              // decompressed cap), 1007 for data that is not consistent with
              // the type of the message - here, bytes that are not a deflate
              // stream.
              pmdFail = c->pmd->inflateOverCap() ? 1009 : 1007;
              return;
            }
            // The validator the parser runs over uncompressed text (ASCII by
            // the word), not the byte-at-a-time check kept for close reasons.
            if (!isBinary) {
              Utf8Validator utf8;
              if (!utf8.accept(inflated) || !utf8.complete()) {
                pmdFail = 1007;  // invalid UTF-8 after inflate
                return;
              }
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
              size_t q = tPendingBytes(c) + c->corkBuf.size() + tlsGatheredBytes(c);
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
        },
        [&](std::string& message, bool isBinary, bool compressed) {
          // A binary message that was buffered here, in memory the parser
          // would release once it is delivered (capacity over its 16 KiB
          // watermark): the application is given that memory instead of a
          // copy of it. Not when much of it is unused (a message grown
          // fragment by fragment): that would stay allocated behind the
          // bytes for as long as the application keeps them.
          if (!isBinary || compressed || !cb_.onWsBinaryOwned || message.capacity() <= kWsTakeMessage ||
              message.capacity() - message.size() > message.size() / 8) {
            return false;
          }
          if (c->wsClosing || c->closing || pmdFail) return true;  // not delivered (see above)
          cb_.onWsBinaryOwned(cb_.user, c, message);
          return true;
        });
    if (!ok) {
      // Protocol failure: fail the connection WITH a Close frame first (§7.1.7 SHOULD) carrying the parser's failure code - 1009 for an oversized message, 1007 for invalid UTF-8, 1002 otherwise. wsClose sets wsClosing, fires onWsClose once, erases the ws registry entry, and terminal-writes the Close frame - the flush-then-close machinery (finishResponse -> !reqKeepAlive -> closeAfterResponse) ends the TCP connection once it drains. The parser's failed latch plus the wsClosing early-return above stop any already-buffered bytes from being re-fed. If wsClosing was already set (violation raced a close handshake in flight) this is a no-op and the pending terminal write finishes the job.
      wsClose(c, c->wsParser->failCode(), "", 0);
    } else if (pmdFail && !c->wsClosing) {
      // Inflate/UTF-8 failure on a compressed message: close with the RFC 7692/6455 code (1009 too big, 1007 not a deflate stream or bad UTF-8) via the same flush-then-close machinery as a parser failure.
      wsClose(c, pmdFail, "", 0);
    }
    if (outerCorked) return;  // the enclosing dispatch loop flushes and closes
    c->corked = false;
    if (c->closing) return;   // torn down mid-batch: whatever was corked is moot
    flushCork(c);
    if (c->batchClose && !c->closing) {
      if (c->pendingWrites == 0) closeAfterResponse(c);
      else c->closeAfterFlush = true;
    }
  }

 private:
  void handleParse(Connection* c, ParseStatus st) {
    if (c->closing) return;

    // An engine-answered route on a complete request: framed straight from
    // the parser, ahead of the Expect scan (a 100 may be omitted once the
    // body has been received, RFC 9110 §10.1.1).
    if (st == ParseStatus::Complete && !c->active && !c->tls && hasEngineRoutes() &&
        answerFromParser(c))
      return;
    if (st == ParseStatus::Complete && c->parser.light()) {
      // The route hook said "engine route" when this request's line was
      // parsed, so its headers were never stored, and the route is no longer
      // there: the application took it out of the tables before the rest of
      // the head arrived. Fail loudly, never hand JS a request without its
      // headers.
      sendErrorAndClose(c, 500);
      return;
    }

    // Answer Expect: 100-continue before the (already fully-buffered) body - the parser reads the whole body before Complete, so on NeedMore with the head parsed we know a body is pending.
    if (!c->sentContinue && c->parser.headParsed()) {
      if (c->parser.expectContinue()) {
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
    swapField(c->methodStr, c->parser.methodStr);
    c->path.swap(c->parser.path);
    swapField(c->query, c->parser.query);
    c->headers.swap(c->parser.headers);
    swapField(c->body, c->parser.body);
    c->jsBody.reset();
    c->jsLent.reset();
    c->isHead = (c->method == Method::HEAD);
    c->reqKeepAlive = c->parser.keepAlive;
    c->reqHttp11 = c->parser.minorVersion >= 1;
    c->active = true;
    c->requestTicks = 0;  // the request-receive budget is per request
    reqMap_->insert(c->reqId, c);

    // Static route: answered right here with the SAME respond() the binding
    // calls, so framing, HEAD handling, corking and keep-alive are identical -
    // the only thing skipped is the trip through JS.
    // Not looked up again when the route hook found no engine route at the
    // request line and the tables have not changed since.
    if (hasEngineRoutes() && c->routeMissGen != routeGen_ && tryStaticRoute(c)) return;
    // The engine's own upgrade (wsAutoUpgrade): a valid WebSocket handshake
    // is answered here and onWsOpen fired; the request never reaches JS. So
    // is one whose only fault is its protocol version (426). Any other
    // request with an Upgrade header is surfaced as usual.
    if (wsAutoUpgrade_ && c->parser.hasUpgrade() && autoUpgrade(c)) return;
    if (cb_.onRequest) cb_.onRequest(cb_.user, c);
  }

  bool tryStaticRoute(Connection* c) {
    const int32_t m = static_cast<int32_t>(c->method);
    auto it = staticRoutes_.find(c->path);
    if (it != staticRoutes_.end()) {
      for (const StaticRoute& r : it->second) {
        if (r.method != m) continue;
        respond(c, r.tpl.status, r.tpl.headers, r.tpl.customCL, r.body.data(), r.body.size());
        return true;
      }
    }
    return tryParamRoute(c, m);
  }

  // The parameter table is a handful of entries scanned linearly; the body
  // points into the request's own path (the Connection's or the parser's),
  // which the response builder copies out before returning, so nothing is
  // allocated per request.
  const ParamRoute* findParamRoute(const std::string& p, int32_t m, const char*& seg,
                                   size_t& len) const {
    for (const ParamRoute& r : paramRoutes_) {
      if (r.method != m) continue;
      const size_t fixed = r.prefix.size() + r.suffix.size();
      if (p.size() <= fixed) continue;
      if (p.compare(0, r.prefix.size(), r.prefix) != 0) continue;
      if (!r.suffix.empty() && p.compare(p.size() - r.suffix.size(), r.suffix.size(), r.suffix) != 0) continue;
      seg = p.data() + r.prefix.size();
      len = p.size() - fixed;
      if (std::memchr(seg, '/', len) != nullptr) continue;
      return &r;
    }
    return nullptr;
  }

  bool tryParamRoute(Connection* c, int32_t m) {
    if (paramRoutes_.empty()) return false;
    const char* seg = nullptr;
    size_t len = 0;
    const ParamRoute* r = findParamRoute(c->path, m, seg, len);
    if (!r) return false;
    respond(c, r->tpl.status, r->tpl.headers, r->tpl.customCL, seg, len);
    return true;
  }

  // Engine-answered route straight from the parser. A static or parameter
  // route needs only the method and the path, so when nothing is queued
  // ahead of this request (no staged slot, no active request - the response
  // order is the request order) the reply is framed right here into the cork
  // buffer: no request id, no registry insert/erase, no snapshot swap, no
  // header scan. Both dispatch loops run corked, and the plaintext frame
  // goes to corkBuf as respond()'s corked path would; TLS keeps the regular
  // path (its frame must be encrypted first). Returns false for anything
  // that is not an engine route, and the caller stages/surfaces it as before.
  // Match an engine route for (method, path); on a hit the reply's template
  // and body land in the Connection's fast* fields.
  bool matchEngineRoute(Connection* c, Method method, const std::string& path) {
    const int32_t m = static_cast<int32_t>(method);
    c->fastStatic = nullptr;
    c->fastParam = nullptr;
    auto it = staticRoutes_.find(path);
    if (it != staticRoutes_.end()) {
      for (StaticRoute& r : it->second) {
        if (r.method != m) continue;
        c->fastStatic = &r;
        return true;
      }
    }
    if (paramRoutes_.empty()) return false;
    const char* seg = nullptr;
    size_t len = 0;
    const ParamRoute* r = findParamRoute(path, m, seg, len);
    if (!r) return false;
    c->fastParam = const_cast<ParamRoute*>(r);
    c->fastSeg = seg;
    c->fastSegLen = len;
    return true;
  }

  // The parser's route hook (HttpParser::routeHook), asked once per request
  // right after its request line: will this request be answered inside the
  // engine? Only when nothing is queued ahead of it on the connection (the
  // reply must go out in request order), the connection is plaintext (the
  // corked frame is written as-is), and the route matches. A yes puts the
  // parser in light mode: headers are scanned, not stored.
  static bool routeHook(void* user, Method method, const std::string& path) {
    Connection* c = static_cast<Connection*>(user);
    Server* s = c->server;
    if (c->active || c->stagedCount > 0 || c->tls || !s->hasEngineRoutes()) {
      c->routeMissGen = 0;
      return false;
    }
    if (s->matchEngineRoute(c, method, path)) return true;
    c->routeMissGen = s->routeGen_;  // no engine route, for as long as the tables stay as they are
    return false;
  }

  bool answerFromParser(Connection* c) {
    HttpParser& p = c->parser;
    // A light request was matched when its request line was parsed, and the
    // fast* fields point into the route tables. That match is used as it is
    // only when the request completed in the same parse call (nothing ran in
    // between). When the rest of the request came in a later read
    // (lightFresh() is false), the application may have changed the tables
    // meanwhile - a route registered, the tables cleared and filled again -
    // and the pointers may be to storage that was moved or freed: the request
    // is matched again, against the tables as they are now.
    //
    // A request the hook found no route for (not light) is not looked up
    // again while the tables are at the generation of that lookup.
    if (!p.lightFresh()) {
      if (!p.light() && c->routeMissGen == routeGen_) return false;
      if (!matchEngineRoute(c, p.method, p.path)) {
        c->routeMissGen = routeGen_;
        return false;
      }
    }
    // The framing inputs appendResponse reads from the Connection.
    c->method = p.method;
    c->isHead = (p.method == Method::HEAD);
    c->reqKeepAlive = p.keepAlive;
    c->reqHttp11 = p.minorVersion >= 1;
    c->requestTicks = 0;
    // The common shape - HTTP/1.1 keep-alive, not HEAD - carries no
    // Connection header and its body, so its frame depends on nothing but
    // the route and the Date line: served from the route's cache, rebuilt
    // only when the Date cache ticks. Every other shape is framed as before.
    const bool plain = c->reqKeepAlive && c->reqHttp11 && !c->isHead;
    std::string& out = c->corkBuf;
    if (plain && plainFrameable(c)) {
      appendPlainFrame(c);
    } else if (StaticRoute* r = c->fastStatic) {
      const bool bodyless = isBodyless(r->tpl.status);
      out.reserve(out.size() + r->body.size() + r->tpl.headers.size() + 128);
      appendResponse(out, c, r->tpl.status, r->tpl.headers, r->tpl.customCL, r->body.data(),
                     isContentless(r->tpl.status) ? 0 : r->body.size(), bodyless);
    } else {
      ParamRoute* pr = c->fastParam;
      const bool bodyless = isBodyless(pr->tpl.status);
      out.reserve(out.size() + c->fastSegLen + pr->tpl.headers.size() + 128);
      appendResponse(out, c, pr->tpl.status, pr->tpl.headers, pr->tpl.customCL, c->fastSeg,
                     isContentless(pr->tpl.status) ? 0 : c->fastSegLen, bodyless);
    }
    // Same per-request bookkeeping completeCorkedResponse does for a
    // surfaced request, minus the registry: nothing was registered.
    resetResponseState(c);
    if (!p.keepAlive) c->batchClose = true;
    p.reset();
    if (c->corkBuf.size() >= limits_.writeHighWaterMark) flushCork(c);
    return true;
  }

  // The common request shape - HTTP/1.1 keep-alive, not HEAD - carries no
  // Connection header and its body, so its frame depends on nothing but the
  // route and the Date line: a static route serves its whole cached frame, a
  // parameter route its cached head up to Content-Length (a bodyless status
  // there is framed the general way).
  bool plainFrameable(Connection* c) const {
    return c->fastStatic != nullptr || !isContentless(c->fastParam->tpl.status);
  }

  void appendPlainFrame(Connection* c) {
    std::string& out = c->corkBuf;
    if (StaticRoute* r = c->fastStatic) {
      dateLine();  // refresh dateCachedAt_
      if (r->frameAt != dateCachedAt_ || r->frame.empty()) {
        r->frame.clear();
        const bool bodyless = isBodyless(r->tpl.status);
        appendResponse(r->frame, c, r->tpl.status, r->tpl.headers, r->tpl.customCL,
                       r->body.data(), isContentless(r->tpl.status) ? 0 : r->body.size(), bodyless);
        r->frameAt = dateCachedAt_;
      }
      out += r->frame;
      return;
    }
    ParamRoute* pr = c->fastParam;
    const std::string& date = dateLine();
    if (pr->headAt != dateCachedAt_ || pr->head.empty()) {
      pr->head.clear();
      appendStatusLine(pr->head, pr->tpl.status);
      pr->head += date;
      pr->head += pr->tpl.headers;
      pr->head += "Content-Length: ";
      pr->headAt = dateCachedAt_;
    }
    out += pr->head;
    appendDecimal(out, c->fastSegLen);
    out += "\r\n\r\n";
    out.append(c->fastSeg, c->fastSegLen);
  }

  // ---- fast lane ----
  // dispatchPlaintext hands a read here when nothing is queued on the
  // connection in either direction (no active or staged request, no bytes
  // waiting to be written, the parser idle). The read is parsed in full -
  // zero-copy, HttpParser::parseDirect, every header validated and the
  // framing ones interpreted - and when it is one complete engine-answered
  // request of the common shape (HTTP/1.1 keep-alive, not HEAD, nothing
  // pipelined behind it) the reply is framed from the route's cache and
  // written, skipping the dispatch machinery. Anything else continues
  // exactly as before, with the parse it did. Every request is parsed and
  // routed; nothing is answered from a previous request's bytes.
  void fastLane(Connection* c, const char* data, size_t len) {
    HttpParser& p = c->parser;
    ParseStatus st = p.parse(data, len);
    if (st == ParseStatus::Complete && p.light() && p.keepAlive && p.minorVersion >= 1 &&
        p.method != Method::HEAD && p.leftover().empty() && plainFrameable(c)) {
      c->method = p.method;
      answerPlain(c);  // fastSeg points into p.path until the reset below
      p.reset();
      return;
    }
    dispatchBatch(c, st);
  }

  // The plain-shape reply for the route in c->fastStatic / c->fastParam:
  // framed from the route cache into corkBuf and written at once. (Holding
  // a readiness round's replies and sending them in one burst was measured
  // too: it wakes the client less often but leaves the server idle until
  // the clients answer the burst, and lost 3-13% throughput at every load.)
  void answerPlain(Connection* c) {
    c->isHead = false;
    c->reqKeepAlive = true;
    c->reqHttp11 = true;
    c->requestTicks = 0;
    appendPlainFrame(c);
    resetResponseState(c);
    flushCork(c);
  }

  static const std::string& emptyHeaders() {
    static const std::string empty;
    return empty;
  }

  // One error response per connection, and nothing is read from it
  // afterwards (inputClosed): the response may sit behind others the peer has
  // not read yet, and until it is flushed the connection is neither closing
  // nor lingering.
  void sendErrorAndClose(Connection* c, int status) {
    if (c->inputClosed) return;
    c->inputClosed = true;
    c->pending.clear();  // never parsed now
    c->reqKeepAlive = false;
    std::string& out = c->scratch;
    out.clear();
    appendStatusLine(out, status);
    out += dateLine();
    out += "Content-Length: 0\r\nConnection: close\r\n\r\n";
    c->responseStarted = true;
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
  // the rate of servers that linger. TLS keeps its close_notify sequence
  // (doClose).
  //
  // A WebSocket ends the same way once its Close frame is out (RFC 6455
  // §7.1.1: half-close, read until the peer has closed too, then close). The
  // peer of a Close the server started - wsClose(), a protocol failure, a
  // message over the size limit - is usually still sending; closed outright,
  // those bytes are answered with a RST and the Close frame, with the status
  // code that says why, is lost with the peer's receive buffer. What the peer
  // sends meanwhile is read and dropped (onTransportData), frames included:
  // nothing is delivered after the Close. kLingerMs bounds a peer that never
  // closes its side.
  void closeAfterResponse(Connection* c) {
    if (c->closing || c->lingering) return;
    if (c->tls) {
      doClose(c);
      return;
    }
    if (!c->finSent) {
#if defined(__linux__)
      if (kind_ != TransportKind::Uv) {
        // Nothing of ours is queued for this fd (pendingWrites == 0): the FIN
        // can go synchronously.
        const int fd = kind_ == TransportKind::Uring ? c->ring.fd : c->ep.fd;
        if (fd < 0 || ::shutdown(fd, SHUT_WR) != 0) {
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
    c->inputClosed = true;
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
    c->h2Bye = true;  // nobody is there to tell
    // Hard teardown (read error/EOF/write error): drop the socket now. Any in-flight writes reference WriteReq buffers, not the connection body, and their completion callbacks tolerate a closing handle.
    doClose(c);
  }

  void doClose(Connection* c) {
    if (tIsClosing(c)) return;
    // An HTTP/2 client is told what became of its streams before the socket
    // goes (best effort, like the close_notify below): the requests still in
    // flight are reset and GOAWAY names the last stream that was acted on.
    // A bare close would leave it to guess which requests are safe to retry.
    if (c->h2 && !c->closing && !c->h2Bye) {
      c->h2Bye = true;
      h2Goodbye(c);
      if (tIsClosing(c)) return;  // the write failed and closed it from underneath
    }
    // Best-effort close_notify on an established TLS session (truncation detection for the peer). uv_try_write: synchronous, non-blocking, no bookkeeping - if the kernel buffer is full the alert is simply lost, which is exactly the semantics "best effort" means here.
    if (c->tls && !c->closing) {
      std::string bye;
      c->tls->shutdown(bye);
      if (!bye.empty()) tTryWrite(c, bye.data(), bye.size());
    }
    c->closing = true;
    c->jsLent.reset();  // a lent body ends with the connection, whatever state the request was in
    // Closed from inside JS's loop over its own batch (a handler closed the
    // server, or the connection went over a limit): the slots still staged
    // die with it, so the loop is told its batch is over and takes no
    // further slot of a connection that is gone.
    if (batchLoopConn_ == c && batchControl_) *batchControl_ = UINT32_MAX;
    if (c->h2) h2Teardown(c);  // every request in flight on it is aborted
    // An HTTP request that was surfaced to a handler and never answered owes JS exactly one onAborted (server shutdown, timeout sweep, write error), or 'close' listeners and their resources (SSE intervals, monitors) leak. closing is already set, so a re-entrant respond() from JS is a no-op.
    // The request is released before JS is told. On a later loop turn (the
    // default) the order makes no difference. Delivered in place
    // (MORO_ENGINE_NOTIFY=sync) it does: the callback, and the continuations
    // the microtask checkpoint behind it runs, must find the request gone as
    // they do in the default mode. Told first, a streaming handler woken by
    // onAborted saw isAborted() false and a write() that reported
    // backpressure, and waited for an onWritable that could never come.
    const uint32_t reqId = c->reqId;
    reqMap_->erase(reqId);
    if (c->active && !c->isWebSocket && !c->abortNotified) {
      c->abortNotified = true;
      queueNotify(reqId, kNotifyAborted);
    }
    if (c->isWebSocket) {
      // A WebSocket torn down without an explicit wsClose (server shutdown, socket error) still owes JS exactly one onWsClose so wrappers/handlers don't leak. wsClosing guards against a double-fire.
      if (!c->wsClosing && cb_.onWsClose) {
        c->wsClosing = true;
        cb_.onWsClose(cb_.user, c, 1006);  // abnormal closure (§7.1.5)
      }
      globalWebSockets().erase(c->wsId);
    }
    // The callbacks above run application code, which may close the server:
    // that closes every connection, this one included, and it must not be
    // closed a second time here (libuv aborts on a handle closed twice).
    if (tIsClosing(c)) return;
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
      delete static_cast<std::string*>(c->ring.held);
      if (uring_) uring_->release();
    } else if (kind_ == TransportKind::Epoll) {
      WriteReq* wr = static_cast<WriteReq*>(c->ep.wqHead);
      while (wr) {
        WriteReq* next = wr->next;
        delete wr;
        wr = next;
      }
      c->ep.wqHead = c->ep.wqTail = nullptr;
    }
#endif
    delete c;
    // One fewer live transport handle; may complete a pending server shutdown.
    liveHandles_--;
#if defined(__linux__)
    if (acceptPaused_) resumeAccept();  // its descriptor is free again
#endif
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
    s->h2Reap();
#if defined(__linux__)
    if (s->acceptPaused_) s->resumeAccept();
#endif
    for (Connection* c : s->conns_) {
      if (c->closing) continue;
#if defined(__linux__)
      if (s->kind_ == TransportKind::Uring) s->uringCheckPeer(c);
#endif
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
      // The same budget for the response bytes an HTTP/2 peer keeps waiting
      // behind its flow-control windows: the socket may be idle while they
      // are, so its queue says nothing about them. Progress is some of them
      // going out (the peer opened a window); writes of anything else - the
      // answer to its PING - are not.
      if (s->limits_.responseTimeoutMs && c->h2 != nullptr) {
        const uint64_t sent = c->h2->heldSent();
        if (c->h2->heldBytes() == 0 || sent != c->h2LastSent) {
          c->h2HeldTicks = 0;
        } else if (++c->h2HeldTicks >= respLimit) {
          stalled.push_back(c);
          continue;
        }
        c->h2LastSent = sent;
      }
      // An HTTP/2 connection is busy while a handler holds one of its
      // requests; streams still waiting for the rest of a request are not
      // work in progress, and the idle timeout covers a peer that stalls them.
      if (c->isWebSocket || c->active || (c->h2 && c->h2->held() > 0)) continue;
      // A response still draining is not an idle connection, whether or not
      // its request is still marked active (a response given inside a batch
      // is complete once framed, with its bytes still queued): the peer is
      // being sent to, and how long that may take is responseTimeoutMs'
      // business, above - which also closes a peer that stops reading. With
      // that budget disabled the idle timeout stays the only bound.
      const bool draining = s->limits_.responseTimeoutMs && c->pendingWrites > 0;
      if (!draining && s->limits_.idleTimeoutMs && ++c->idleTicks >= idleLimit) {
        stale.push_back(c);
        continue;
      }
      // No request budget runs while intake is held for the peer to read
      // (the rest of the request may be sitting in `pending`, unparsed), or
      // once an error response has been queued.
      if (c->outHeld || c->inputClosed) continue;
      if (s->limits_.requestTimeoutMs) {
        // A TLS handshake in progress counts as mid-request: the same requestTimeoutMs budget bounds handshake slow-drip (a stalled or byte-trickled ClientHello) with no extra knob.
        // So does a cleartext connection whose first bytes are a part of the
        // HTTP/2 preface still waiting for the rest.
        bool mid = c->parser.midRequest() || (c->tls && !c->tls->handshakeDone()) ||
                   (c->proto == 0 && !c->pending.empty());
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
    if (kind_ != TransportKind::Uv) {
      const int fd = kind_ == TransportKind::Uring ? c->ring.fd : c->ep.fd;
      ssize_t r = ::send(fd, p, n, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (r >= 0) return static_cast<int>(r);
      if (errno == EAGAIN || errno == EWOULDBLOCK) return UV_EAGAIN;
      return -errno;
    }
#endif
    uv_buf_t b = uv_buf_init(const_cast<char*>(p), static_cast<unsigned>(n));
    return uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), &b, 1);
  }

  // Two buffers in one synchronous non-blocking write, the first possibly
  // empty; `more` holds the segment open for bytes that follow at once
  // (MSG_MORE; ignored where the transport has no such flag). Returns the
  // bytes written across both, UV_EAGAIN, or a negative errno.
  long tTryWrite2(Connection* c, const char* a, size_t an, const char* b, size_t bn, bool more) {
#if defined(__linux__)
    if (kind_ != TransportKind::Uv) {
      const int fd = kind_ == TransportKind::Uring ? c->ring.fd : c->ep.fd;
      const int flags = MSG_DONTWAIT | MSG_NOSIGNAL | (more ? MSG_MORE : 0);
      ssize_t r;
      if (an == 0) {
        r = ::send(fd, b, bn, flags);
      } else {
        struct iovec iov[2] = {{const_cast<char*>(a), an}, {const_cast<char*>(b), bn}};
        struct msghdr msg {};
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        r = ::sendmsg(fd, &msg, flags);
      }
      if (r >= 0) return static_cast<long>(r);
      if (errno == EAGAIN || errno == EWOULDBLOCK) return UV_EAGAIN;
      return -errno;
    }
#endif
    (void)more;
    uv_buf_t bufs[2];
    unsigned nb = 0;
    if (an) bufs[nb++] = uv_buf_init(const_cast<char*>(a), static_cast<unsigned>(an));
    bufs[nb++] = uv_buf_init(const_cast<char*>(b), static_cast<unsigned>(bn));
    return uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), bufs, nb);
  }

  // tTryWrite2 with a third buffer behind the second (the bytes that close a
  // chunk behind its data): one synchronous non-blocking write, nothing
  // queued and nothing accounted, as there. Returns the bytes written across
  // all three, UV_EAGAIN, or a negative errno.
  long tTryWrite3(Connection* c, const char* a, size_t an, const char* b, size_t bn,
                  const char* t, size_t tn) {
#if defined(__linux__)
    if (kind_ != TransportKind::Uv) {
      const int fd = kind_ == TransportKind::Uring ? c->ring.fd : c->ep.fd;
      struct iovec iov[3];
      size_t n = 0;
      if (an) iov[n++] = {const_cast<char*>(a), an};
      iov[n++] = {const_cast<char*>(b), bn};
      iov[n++] = {const_cast<char*>(t), tn};
      struct msghdr msg {};
      msg.msg_iov = iov;
      msg.msg_iovlen = n;
      const ssize_t r = ::sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (r >= 0) return static_cast<long>(r);
      if (errno == EAGAIN || errno == EWOULDBLOCK) return UV_EAGAIN;
      return -errno;
    }
#endif
    uv_buf_t bufs[3];
    unsigned nb = 0;
    if (an) bufs[nb++] = uv_buf_init(const_cast<char*>(a), static_cast<unsigned>(an));
    bufs[nb++] = uv_buf_init(const_cast<char*>(b), static_cast<unsigned>(bn));
    bufs[nb++] = uv_buf_init(const_cast<char*>(t), static_cast<unsigned>(tn));
    return uv_try_write(reinterpret_cast<uv_stream_t*>(&c->handle), bufs, nb);
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
    else if (kind_ == TransportKind::Epoll) fd = c->ep.fd;
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
    // Measured alternative (2026-09-13, Linux container, oha + bombardier,
    // three rotated rounds): sending the data segment first and the FIN as
    // its own segment right behind it - so a fast peer usually closes first
    // and holds the TIME_WAIT - was 15-25% SLOWER on connections per second
    // than this coalesced form (a simultaneous close costs both sides). Keep
    // MSG_MORE + shutdown.
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
    if (kind_ == TransportKind::Epoll) return c->ep.pendingBytes;
#endif
    return uv_stream_get_write_queue_size(reinterpret_cast<uv_stream_t*>(&c->handle));
  }

  // Response bytes handed to the transport and still held for it: what
  // outputBacklogged() measures. On the engine's own transports that is the
  // write queue, which keeps a write that has failed until the failure is
  // acted on. On libuv it is the engine's own count of the writes whose
  // callback has not run - not libuv's queue size, which no longer includes a
  // write once the socket has taken or refused it (on Windows a write that
  // fails at once is never in it), while its bytes are held here until the
  // callback: the responses queued behind a reset would not be counted, and
  // the requests pipelined behind them would all be answered into memory.
  size_t tOutputHeld(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) return c->ring.pendingBytes;
    if (kind_ == TransportKind::Epoll) return c->ep.pendingBytes;
#endif
    return uvOutputHeld(c);
  }
  // (Out of line and through a volatile read, so that the compiler treats it
  // as it treated the libuv call it stands in for. A plain load here was
  // fetched ahead of the test that says whether it is wanted at all: five
  // instructions on the path of every request, on every transport.)
  MORO_NOINLINE static size_t uvOutputHeld(const Connection* c) {
    return *static_cast<const volatile size_t*>(&c->uvQueued);
  }

  bool tIsClosing(Connection* c) {
#if defined(__linux__)
    if (kind_ == TransportKind::Uring) return c->ring.state >= 2;
    if (kind_ == TransportKind::Epoll) return c->ep.state >= 2;
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
    if (kind_ == TransportKind::Epoll) {
      epollCloseConn(c);
      return;
    }
#endif
    uv_read_stop(reinterpret_cast<uv_stream_t*>(&c->handle));
    uv_close(reinterpret_cast<uv_handle_t*>(&c->handle), onCloseFree);
  }

  bool tPeerName(Connection* c, struct sockaddr_storage* addr, int* len) {
#if defined(__linux__)
    if (kind_ != TransportKind::Uv) {
      const int fd = kind_ == TransportKind::Uring ? c->ring.fd : c->ep.fd;
      socklen_t sl = static_cast<socklen_t>(*len);
      if (::getpeername(fd, reinterpret_cast<sockaddr*>(addr), &sl) != 0) return false;
      *len = static_cast<int>(sl);
      return true;
    }
#endif
    return uv_tcp_getpeername(&c->handle, reinterpret_cast<sockaddr*>(addr), len) == 0;
  }

  bool tBoundName(struct sockaddr_storage* addr, int* len) {
#if defined(__linux__)
    if (kind_ != TransportKind::Uv && listenFd_ >= 0) {
      socklen_t sl = static_cast<socklen_t>(*len);
      if (::getsockname(listenFd_, reinterpret_cast<sockaddr*>(addr), &sl) != 0) return false;
      *len = static_cast<int>(sl);
      return true;
    }
    if (uvListenFd_ >= 0) {
      socklen_t sl = static_cast<socklen_t>(*len);
      if (::getsockname(uvListenFd_, reinterpret_cast<sockaddr*>(addr), &sl) != 0) return false;
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
    if (kind_ == TransportKind::Epoll) epollCloseListener();
    if (kind_ == TransportKind::Uv) uvCloseListener();
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
  // The thread's event loops, kept in its ThreadState (thread_state.h), not
  // in thread_locals of their own: UringLoop::slot and EpollLoop::slot hand
  // out these fields.
  struct UringLoop;
  struct EpollLoop;
  struct LoopSlots {
    UringLoop* uring = nullptr;
    EpollLoop* epoll = nullptr;
  };
  static LoopSlots& loopSlots() {
    ThreadState& t = threadState();
    if (t.loopSlots == nullptr) {
      t.loopSlots = new LoopSlots();
      t.freeLoopSlots = [](void* p) { delete static_cast<LoopSlots*>(p); };
    }
    return *static_cast<LoopSlots*>(t.loopSlots);
  }

  struct UringLoop {
    uring::Ring<uring::LinuxSys> ring;
    uring::BufRing<uring::LinuxSys> bufs;
    uv_loop_t* loop = nullptr;
    uv_poll_t poll;
    uv_prepare_t prepare;
    uv_idle_t undertaker;  // runs bury() from the loop for a dead ring (see die), retire() for an unused one
    int refs = 0;         // listening servers + live connections (ref/unref the poll handle)
    bool pollRef = false;
    bool dead = false;    // io_uring_enter started failing: no new uring work
    bool buried = false;  // ... and everything that lived on the ring has been released (bury)
    bool retired = false; // unused and given back (retire): only its handles are still closing
    UringLoop* older = nullptr;  // the ring this one took over from, while that one's handles are closing
    uint8_t inReap = 0;   // 1 inside reap(); 2 once this pass has been given its number (passNo)
    uint32_t passNo = 0;  // numbers the passes in which receive completions were counted (Server::uringCount)
    // Connections that are closed and not freed yet: waiting for their
    // cancel/close completions, or - on a dead ring - for bury(). Intrusive,
    // through UringConn::closingPrev/closingNext.
    Connection* closing = nullptr;
    int closedHandles = 0;
    int efd = -1;         // DEFER_TASKRUN: the registered eventfd the poll handle waits on
    bool woke = false;    // the eventfd fired since the last reap round
    std::vector<Connection*> rearm;  // multishot recvs to re-issue after a reap round
    std::unordered_set<Server*> servers;
    int emfileFd = -1;
    // Receive pacing: the connections that went over the bound in one pass
    // (Server::uringCount). The idle handle serves each of them once per
    // loop turn (onPacer) and keeps the loop turning while there are any.
    std::vector<Connection*> paced;
    std::vector<Connection*> pacedTurn;  // onPacer's working copy, kept for its storage
    uv_idle_t pacer;
    bool pacerOn = false;

    static UringLoop*& slot() { return loopSlots().uring; }

    static UringLoop* get(uv_loop_t* loop) {
      UringLoop*& s = slot();
      if (s && !s->retired) return s->dead ? nullptr : s;
      auto* u = new UringLoop();
      u->loop = loop;
      const uring::RingMode& mode = Server::uringModeSlot();
      if (u->ring.open(uring::kSqEntries, mode.setupFlags, uring::kCqEntries) < 0) {
        delete u;
        return nullptr;
      }
      if (u->bufs.init(u->ring, uring::kBufGroup, uring::kBufCount, uring::kBufSize) < 0) {
        u->ring.close();
        delete u;
        return nullptr;
      }
      // DEFER_TASKRUN posts nothing to the ring fd: the loop waits on a
      // registered eventfd the kernel signals when local task work is queued.
      int waitFd = u->ring.fd();
      if (mode.eventfd) {
        u->efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (u->efd < 0 || u->ring.registerEventfd(u->efd) < 0) {
          if (u->efd >= 0) ::close(u->efd);
          u->bufs.destroy(u->ring);
          u->ring.close();
          delete u;
          return nullptr;
        }
        waitFd = u->efd;
      }
      u->poll.data = u;
      if (uv_poll_init(loop, &u->poll, waitFd) != 0) {
        if (u->efd >= 0) ::close(u->efd);
        u->bufs.destroy(u->ring);
        u->ring.close();
        delete u;
        return nullptr;
      }
      u->prepare.data = u;
      uv_prepare_init(loop, &u->prepare);
      u->undertaker.data = u;
      uv_idle_init(loop, &u->undertaker);
      u->pacer.data = u;
      uv_idle_init(loop, &u->pacer);
      uv_prepare_start(&u->prepare, onPrepare);
      uv_unref(reinterpret_cast<uv_handle_t*>(&u->prepare));
      uv_poll_start(&u->poll, UV_READABLE, onReadable);
      uv_unref(reinterpret_cast<uv_handle_t*>(&u->poll));
      u->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      u->older = s;  // a ring given back whose handles are still closing, if any (retire)
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
      if (--refs == 0) {
        if (pollRef) {
          uv_unref(reinterpret_cast<uv_handle_t*>(&poll));
          pollRef = false;
        }
        retireIfUnused();
      }
    }

    // No listener and no connection is left on this ring: the loop gives it
    // back (retire), from the idle handle - this may be running inside a
    // reap - unless a listener has arrived by then. A dead ring is kept: it
    // is what tells later servers on this thread to use the epoll transport.
    void retireIfUnused() {
      if (refs == 0 && !dead && !retired) uv_idle_start(&undertaker, onUndertaker);
    }

    // The ring, its eventfd and the spare descriptor are closed here and
    // now, so that a process that has closed its last server holds nothing
    // of the transport's; the next listen() on this thread sets up a new
    // ring (get). libuv has let go of the descriptors once uv_close() has
    // returned; the object goes with the last of its handles, and stays
    // reachable until then - as the thread's ring, or through `older` of the
    // one that has taken its place - for shutdownForThread to wait for.
    void retire() {
      retired = true;
      uv_close(reinterpret_cast<uv_handle_t*>(&poll), onRetiredHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&prepare), onRetiredHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&undertaker), onRetiredHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&pacer), onRetiredHandleClosed);
      if (emfileFd >= 0) ::close(emfileFd);
      if (efd >= 0) ::close(efd);
      bufs.destroy(ring);
      ring.close();
    }
    static void onRetiredHandleClosed(uv_handle_t* h) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      if (++u->closedHandles < 4) return;
      UringLoop*& s = slot();
      if (s == u) {
        s = u->older;
      } else {
        for (UringLoop* p = s; p; p = p->older) {
          if (p->older == u) {
            p->older = u->older;
            break;
          }
        }
      }
      delete u;
    }

    void linkClosing(Connection* c) {
      c->ring.closingPrev = nullptr;
      c->ring.closingNext = closing;
      if (closing) closing->ring.closingPrev = c;
      closing = c;
      c->ring.closingLinked = true;
    }
    void unlinkClosing(Connection* c) {
      if (!c->ring.closingLinked) return;
      Connection* prev = static_cast<Connection*>(c->ring.closingPrev);
      Connection* next = static_cast<Connection*>(c->ring.closingNext);
      if (prev) prev->ring.closingNext = next;
      else closing = next;
      if (next) next->ring.closingPrev = prev;
      c->ring.closingLinked = false;
    }

    // io_uring_enter. The sanitizer build has a fault point here, switched
    // on by a test: a ring that refuses every enter from then on.
    int enter(unsigned minComplete, uint32_t flags) {
#if defined(MORO_ENGINE_TEST_FAULTS)
      if (std::getenv("MORO_ENGINE_TEST_FAIL_URING_ENTER")) return -ENXIO;
#endif
      return ring.enter(minComplete, flags);
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
      int r = enter(0, 0);
      if (r < 0 && r != -EINTR && r != -EAGAIN && r != -EBUSY) {
        die();
        return false;
      }
      return true;
    }

    // The ring no longer takes submissions. From here on no SQE is handed
    // out and nothing is entered or reaped. What lived on the ring is
    // released by bury(), which closes and frees every connection and so
    // needs a stack that holds none - and this may be running inside a write
    // the application is making (an SQE was wanted and the queue was full),
    // or inside the dispatch of a completion. So the loop does it, from an
    // idle handle: started here, it runs before the loop can block again.
    MORO_NOINLINE void die() {
      if (dead) return;
      dead = true;
      std::fprintf(stderr, "[morojs-engine] io_uring_enter failed; aborting io_uring connections on this thread\n");
      uv_idle_start(&undertaker, onUndertaker);
    }

    static void onUndertaker(uv_idle_t* h) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      if (!u->dead) {
        uv_idle_stop(&u->undertaker);
        if (u->refs == 0) u->retire();  // (see retireIfUnused)
        return;
      }
      u->bury();
      u->freeClosing();  // also what was closed after the burial (uringCloseDead)
      uv_idle_stop(&u->undertaker);
    }

    // Release everything that lived on a dead ring. No completion will be
    // reaped again, so nothing here may wait for one.
    MORO_NOINLINE void bury() {
      if (buried) return;
      buried = true;
      rearm.clear();
      uv_prepare_stop(&prepare);  // it reads the ring, which is about to go
      // A CLOSE the kernel never took has not closed its descriptor.
      ring.forEachUnsubmitted([](const uring::abi::io_uring_sqe& s) {
        if (s.opcode == uring::abi::IORING_OP_CLOSE && s.fd >= 0) ::close(s.fd);
      });
      // Every live connection goes through the normal abort path (callbacks
      // fire once); none is freed while that runs application code.
      std::vector<Server*> srvs(servers.begin(), servers.end());
      for (Server* s : srvs) s->uringAbortAll();
      // A connection accepted by a completion that was never reaped has no
      // owner.
      ring.forEachCqe([](const uring::abi::io_uring_cqe& c) {
        if (uring::tagOf(c.user_data) == uring::kTagAccept && c.res >= 0) ::close(c.res);
      });
      // The kernel still holds every operation that was in flight: armed
      // receives and accepts, a send waiting for its socket. Closing the
      // ring cancels them, and only then are the buffers they point into
      // freed, with the connections that were already waiting for
      // completions when the ring died.
      uv_poll_stop(&poll);
      bufs.destroy(ring);
      ring.close();
      freeClosing();
      // Servers that were listening carry on, on the epoll transport.
      for (Server* s : srvs) s->uringRingDied();
    }

    void freeClosing() {
      while (closing) {
        Connection* c = closing;
        c->ring.state = 3;
        c->ring.inflight = 0;
        c->server->uringFreeIfDone(c);
      }
    }

    void pace(Connection* c) {
      paced.push_back(c);
      if (!pacerOn) {
        pacerOn = true;
        uv_idle_start(&pacer, onPacer);
      }
    }
    void unpace(Connection* c) {
      auto it = std::find(paced.begin(), paced.end(), c);
      if (it != paced.end()) paced.erase(it);
      if (paced.empty() && pacerOn) {
        pacerOn = false;
        uv_idle_stop(&pacer);
      }
    }
    // One service per paced connection per loop turn. Serving runs
    // application code, which may close any connection (uringCloseConn takes
    // it off `paced`); none is freed while this runs - that takes a reap or
    // the undertaker - so the copy holds no dead pointer.
    static void onPacer(uv_idle_t* h) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      u->pacedTurn.assign(u->paced.begin(), u->paced.end());
      for (Connection* c : u->pacedTurn) {
        if (c->ring.state == 0) c->server->uringServePaced(c);
      }
      u->pacedTurn.clear();
    }

    static void onPrepare(uv_prepare_t* h) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      // Never block with work the kernel is holding for us: deferred task
      // work (DEFER_TASKRUN runs it only inside our own enter, and a wake is
      // a hint, not a contract) or completions already posted. One flag read
      // per loop turn; the reap it triggers is the same one a wake runs.
      if (u->ring.taskWorkPending() || u->ring.cqReady()) {
        u->reap();
        return;
      }
      // Anything queued outside a reap round (sweep-timer closes, async JS
      // responses that took the queued path) goes to the kernel before the
      // loop blocks.
      if (u->ring.pending()) u->flush();
    }

    static void onReadable(uv_poll_t* h, int status, int) {
      UringLoop* u = static_cast<UringLoop*>(h->data);
      if (status < 0) return;
      if (u->efd >= 0) {
        // Clear the counter; the wake itself says local task work
        // (DEFER_TASKRUN) or a completion is waiting for our enter.
        uint64_t n;
        if (::read(u->efd, &n, sizeof(n)) < 0) { /* the wake was the signal; the counter value is irrelevant */ }
        u->woke = true;
      }
      u->reap();
    }

    // Bounded reap: run deferred task work + submit in ONE enter, dispatch
    // every completion, re-arm starved multishot recvs, repeat while the
    // dispatch produced new SQEs - at most 8 rounds so timers and JS never
    // starve behind a busy ring.
    void reap() {
      if (inReap || dead) return;
      inReap = 1;
      for (int round = 0; round < 8 && !dead; round++) {
        if (woke || ring.pending() || ring.taskWorkPending() || ring.cqOverflowed()) {
          woke = false;
          int r = enter(0, uring::abi::IORING_ENTER_GETEVENTS);
          if (r < 0 && r != -EINTR && r != -EAGAIN && r != -EBUSY) {
            die();
            break;
          }
        }
        unsigned n = ring.forEachCqeBatch([this](const uring::abi::io_uring_cqe& c, uint32_t batch) { dispatch(c, batch); });
        rearmStarved();
        if (n == 0 && ring.pending() == 0) break;
      }
      if (!dead && ring.pending()) flush();
      inReap = 0;
    }

    void rearmStarved() {
      if (rearm.empty()) return;
      std::vector<Connection*> list;
      list.swap(rearm);
      for (Connection* c : list) {
        if (c->ring.state < 2 && !c->ring.recvArmed) c->server->uringArmRecv(c);
      }
    }

    void dispatch(const uring::abi::io_uring_cqe& cqe, uint32_t batch) {
      const uring::Tag t = uring::tagOf(cqe.user_data);
      void* p = uring::ptrOf(cqe.user_data);
      switch (t) {
        case uring::kTagRecv: {
          Connection* c = static_cast<Connection*>(p);
          // The first completion a connection has in a batch is dispatched
          // as it is; any further one is counted first (uringCount).
          if (c->ring.seen != batch) c->ring.seen = batch;
          else c->server->uringCount(c, cqe.res, batch);
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
          c->ring.recvCancel = false;
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
      // A ring given back a moment ago still has handles closing.
      if (UringLoop* r = slot()) {
        uv_loop_t* l = r->loop;
        while (slot() && (slot()->retired || slot()->older)) uv_run(l, UV_RUN_ONCE);
      }
      UringLoop*& s = slot();
      if (!s) return;
      UringLoop* u = s;
      s = nullptr;
      if (u->dead) {
        u->bury();
        u->freeClosing();
      }
      uv_close(reinterpret_cast<uv_handle_t*>(&u->poll), onHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&u->prepare), onHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&u->undertaker), onHandleClosed);
      uv_close(reinterpret_cast<uv_handle_t*>(&u->pacer), onHandleClosed);
      while (u->closedHandles < 4) uv_run(u->loop, UV_RUN_ONCE);
      if (u->emfileFd >= 0) ::close(u->emfileFd);
      if (u->efd >= 0) ::close(u->efd);  // the ring's registration dies with the ring
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
      // Every connection that is waiting goes, not just the one this
      // completion was about: the next accept is armed later (below), and
      // none of them should hang until then.
      if (uring_->emfileFd >= 0 && listenFd_ >= 0) {
        ::close(uring_->emfileFd);
        for (int i = 0; i < 1024; i++) {
          int fd = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (fd < 0) break;
          ::close(fd);
        }
        uring_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      }
      // An accept armed now would fail again at once, with or without a
      // connection waiting: the kernel reserves the descriptor before it
      // looks at the queue. Re-arming on the spot is a loop that never
      // sleeps for as long as the process stays at its limit, so the next
      // accept is armed when a descriptor may be free again (resumeAccept).
      pauseAccept();
    } else if (res == -ENOBUFS || res == -ENOMEM) {
      pauseAccept();
    }
    // -ECANCELED (listener closing) and other errors fall through: re-arm
    // only while still listening.
    if (!more && !listenerArmed_ && !acceptPaused_ && !listenerClosed_ && !closeRequested_ && listenFd_ >= 0) uringArmAccept();
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
    if (c->ring.recvArmed || c->ring.state != 1) return;
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
    if (c->ring.state != 1) {
      uringSetAside(c, cqe.res, hasBuf, bid);  // closing: dropped; paced: held for its turn
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

  // ---- receive pacing ----
  // A multishot receive completes once per buffer for as long as its socket
  // has bytes, and a reap dispatches every completion it finds: a peer that
  // sends without pause had megabytes of its input - each small frame of it
  // a call into the application - served in one pass, with every timer and
  // every other connection waiting behind it. So what one connection is
  // served in one pass is bounded, as it is on the epoll transport (one
  // read, of this size, per socket per loop turn). The connection that goes
  // over the bound is paced: its multishot receive is cancelled, the
  // completions already posted for it are copied aside in order, and from
  // then on the loop reads its socket itself, one buffer per turn
  // (uringServePaced), until a read finds it empty and the multishot receive
  // takes over again.
  //
  // Counting starts with a connection's second completion in one batch of a
  // reap, which an ordinary exchange never has: its requests arrive one
  // completion at a time. The first of each batch is taken as a full buffer.
  static constexpr uint32_t kRecvPassBytes = 64 * 1024;

  MORO_NOINLINE void uringCount(Connection* c, int res, uint32_t batch) {
    if (c->ring.state != 1 || res <= 0) return;
    // The pass is numbered when something is first counted in it: a reap
    // that has no second completion for anybody pays nothing for this.
    if (uring_->inReap == 1) {
      uring_->inReap = 2;
      uring_->passNo++;
    }
    const uint32_t pass = uring_->passNo;
    if (c->ring.counted != pass) {
      c->ring.counted = pass;
      c->ring.countedIn = ~batch;
      c->ring.passBytes = 0;
    }
    if (c->ring.countedIn != batch) {
      c->ring.countedIn = batch;
      c->ring.passBytes += uring::kBufSize;
    }
    c->ring.passBytes += static_cast<uint32_t>(res);
    if (c->ring.passBytes > kRecvPassBytes) uringPace(c);  // this completion is the first one held
  }

  void uringPace(Connection* c) {
    c->ring.state = 0;
    uring_->pace(c);
    uringCancelRecv(c);
  }

  // Back to the multishot receive.
  void uringUnpace(Connection* c) {
    c->ring.state = 1;
    uring_->unpace(c);
  }

  void uringCancelRecv(Connection* c) {
    if (!c->ring.recvArmed || c->ring.recvCancel) return;
    uring::abi::io_uring_sqe* s = uring_->sqe();
    if (!s) return;
    uring::prepCancelUserData(s, uring::tag(c, uring::kTagRecv));
    s->user_data = uring::tag(c, uring::kTagCancel);
    c->ring.recvCancel = true;
    c->ring.inflight++;
  }

  // A receive completion for a connection that is not being read through
  // its multishot receive. Closing: nothing of it is wanted. Paced: its
  // bytes wait for their turn behind the ones already held, and an EOF or
  // an error behind those. (Never while uringServePaced is dispatching the
  // held bytes: completions are reaped from the loop, not from inside it.)
  MORO_NOINLINE void uringSetAside(Connection* c, int res, bool hasBuf, uint16_t bid) {
    if (c->ring.state == 0) {
      if (res > 0) {
        if (!c->ring.held) c->ring.held = new std::string();
        static_cast<std::string*>(c->ring.held)->append(reinterpret_cast<const char*>(uring_->bufs.at(bid)), static_cast<size_t>(res));
      } else if (res != -ECANCELED && res != -ENOBUFS) {
        c->ring.heldEof = true;
      }
    }
    if (hasBuf) uring_->bufs.recycle(bid);
  }

  // A paced connection's turn (UringLoop::onPacer): the next buffer's worth
  // of what is held for it, or - once that is gone and its multishot receive
  // has ended - one read of its socket. May run application code and may
  // close the connection.
  void uringServePaced(Connection* c) {
    if (std::string* held = static_cast<std::string*>(c->ring.held)) {
      if (c->ring.heldOff < held->size()) {
        const size_t n = std::min<size_t>(held->size() - c->ring.heldOff, kRecvPassBytes);
        char* p = &(*held)[c->ring.heldOff];
        c->ring.heldOff += n;
        onTransportData(c, p, n);  // (the bytes stay where they are until a later turn, or freeConnection)
        return;
      }
      delete held;
      c->ring.held = nullptr;
      c->ring.heldOff = 0;
    }
    if (c->ring.heldEof) {
      uringUnpace(c);
      c->ring.heldEof = false;
      if (!c->ring.eofSeen) {
        c->ring.eofSeen = true;
        onTransportEof(c);
      }
      return;
    }
    if (c->ring.recvArmed) {
      // Its last completion (the cancel's) has not been reaped: the kernel
      // may still be reading for it, and two readers would take the bytes
      // out of order.
      uringCancelRecv(c);
      return;
    }
    if (!readBuf_) {
      readBuf_.reset(new char[kRecvPassBytes]);
      readBufSize_ = kRecvPassBytes;
    }
    const ssize_t n = ::recv(c->ring.fd, readBuf_.get(), readBufSize_, MSG_DONTWAIT);
    if (n > 0) {
      onTransportData(c, readBuf_.get(), static_cast<size_t>(n));
      // A short read emptied the socket: the burst is over.
      if (static_cast<size_t>(n) < readBufSize_ && c->ring.state == 0) {
        uringUnpace(c);
        uringArmRecv(c);
      }
      return;
    }
    if (n < 0 && errno == EINTR) return;
    uringUnpace(c);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      uringArmRecv(c);
      return;
    }
    if (!c->ring.eofSeen) {
      c->ring.eofSeen = true;
      onTransportEof(c);
    }
  }

  // A reset that reaches the socket together with the last bytes before it
  // is not reported by a multishot receive on a DEFER_TASKRUN ring: the two
  // wake-ups are one by the time the receive runs, it takes the bytes, finds
  // the socket empty and goes back to waiting for a wake-up that has already
  // happened. The connection would stay open, a WebSocket for good. So the
  // sweep asks each socket that has received anything since it was last
  // asked whether it has an error pending or has been hung up, and one that
  // has is paced: the loop's own read finds what the receive did not.
  void uringCheckPeer(Connection* c) {
    if (c->ring.seen == c->ring.probed || c->ring.state != 1) return;
    c->ring.probed = c->ring.seen;
    struct pollfd p {};
    p.fd = c->ring.fd;
    if (::poll(&p, 1, 0) == 1 && (p.revents & (POLLERR | POLLHUP))) uringPace(c);
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
    if (c->ring.state == 0) uring_->unpace(c);
    c->ring.state = 2;
    uring_->linkClosing(c);
    if (uring_->dead) {
      uringCloseDead(c);
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
      c->ring.fd = -1;
    } else {
      uringCloseDead(c);  // the ring died under this very call
    }
  }

  // Close a connection whose ring is dead: no completion will report it
  // closed. The socket is shut down before its descriptor is closed: an
  // operation the kernel still holds for it keeps the socket itself open
  // until the ring is gone, and has to find nothing left to do - the peer
  // gets its FIN now, and a send whose turn came would otherwise read a
  // buffer that is about to be freed. The Connection is not freed here (the
  // caller is using it, as on every other transport): the loop does that
  // (UringLoop::onUndertaker).
  void uringCloseDead(Connection* c) {
    if (c->ring.fd >= 0) {
      ::shutdown(c->ring.fd, SHUT_RDWR);
      ::close(c->ring.fd);
    }
    c->ring.fd = -1;
    uv_idle_start(&uring_->undertaker, UringLoop::onUndertaker);
  }

  void uringFreeIfDone(Connection* c) {
    if (c->ring.state == 3 && c->ring.inflight == 0) {
      uring_->unlinkClosing(c);
      freeConnection(c);
    }
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

  // The ring died underneath us (UringLoop::bury). First every connection
  // is torn down through the normal abort path (callbacks fire once) ...
  void uringAbortAll() {
    std::vector<Connection*> live(conns_.begin(), conns_.end());
    for (Connection* c : live) abortConnection(c);
  }

  // ... then, with those freed, the listener: a server that is still
  // listening keeps its socket and carries on on the epoll transport; one
  // that was closing is done with its listener, whose completions will not
  // come.
  void uringRingDied() {
    if (listenerReaped_) return;
    if (listenFd_ >= 0 && !listenerClosing_ && !listenerClosed_ && !closeRequested_ &&
        uringListenerToEpoll())
      return;
    if (listenFd_ >= 0) ::close(listenFd_);
    listenFd_ = -1;
    listenerClosing_ = true;
    listenerInflight_ = 0;
    uringListenerDoneCheck();
  }

  // The listening socket - bound, with whatever is waiting in its queue -
  // moves to the epoll transport, and with it the server: every connection
  // from here on is an epoll connection. None of the io_uring kind is left
  // at this point (bury freed them), which is what lets kind_ change. The
  // listener's count in liveHandles_ carries over (onListenPollClosed).
  bool uringListenerToEpoll() {
    EpollLoop* ep = EpollLoop::get(loop_);
    listenPoll_.data = this;
    if (!ep || uv_poll_init(loop_, &listenPoll_, listenFd_) != 0) return false;
    uring_->servers.erase(this);
    uring_->release();
    listenerInflight_ = 0;
    listenerArmed_ = false;
    if (acceptPaused_) resumeAccept();  // (arms nothing: the ring is dead)
    kind_ = TransportKind::Epoll;
    epoll_ = ep;
    if (ep->emfileFd < 0) ep->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    ep->servers.insert(this);
    uv_poll_start(&listenPoll_, UV_READABLE, onListenPoll);
    return true;
  }

  // accept() failed for want of a descriptor or of memory, and trying again
  // at once would fail the same way. Accepting stops (the epoll or libuv
  // listener is no longer watched; no io_uring accept is armed) and starts again from
  // the sweep, or as soon as one of this server's own connections has given
  // its descriptor back (freeConnection). The sweep timer holds the loop
  // meanwhile, as the watched listener did.
  void pauseAccept() {
    if (acceptPaused_) return;
    acceptPaused_ = true;
    if (kind_ == TransportKind::Epoll) uv_poll_stop(&listenPoll_);
    if (kind_ == TransportKind::Uv) uvPauseAccept();
    if (sweepActive_) uv_ref(reinterpret_cast<uv_handle_t*>(&sweepTimer_));
  }
  void resumeAccept() {
    acceptPaused_ = false;
    if (sweepActive_) uv_unref(reinterpret_cast<uv_handle_t*>(&sweepTimer_));
    if (kind_ == TransportKind::Uv) {
      uvResumeAccept();
      return;
    }
    if (listenFd_ < 0 || listenerClosed_ || closeRequested_) return;
    if (kind_ == TransportKind::Epoll) {
      if (epoll_->emfileFd < 0) epoll_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      uv_poll_start(&listenPoll_, UV_READABLE, onListenPoll);
    } else if (kind_ == TransportKind::Uring) {
      if (uring_->emfileFd < 0) uring_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      if (!listenerArmed_) uringArmAccept();
    }
  }
  bool acceptPaused_ = false;

  int listenFd_ = -1;
  uint32_t listenerInflight_ = 0;
  bool listenerArmed_ = false;
  bool listenerClosing_ = false;
  bool listenerReaped_ = false;
  UringLoop* uring_ = nullptr;

  // ---------------------------------------------------------------------
  // epoll transport: plain non-blocking sockets, each watched by a libuv
  // poll handle on the loop's own epoll (the integration uWebSockets.js
  // uses), so one epoll_wait per loop iteration delivers every event. Per
  // connection there is the socket and its watcher and nothing else: recv
  // into the server's receive buffer, send straight from the frame, writable
  // interest only while a write is backpressured. It removes libuv's per-stream machinery
  // (alloc/read callbacks, write requests, handle close) from the hot path;
  // the protocol layers above (onTransportData, transportWrite, the cork,
  // TLS, WebSocket, the sweep) are the same ones the uv and io_uring
  // transports drive.
  //
  // Two things only ever happen on a clean stack, never inside the call that
  // caused them:
  //   - completing a queued write (completeWrite -> finishResponse -> the
  //     next pipelined request -> JS) runs from a uv_check on the next loop
  //     turn. libuv defers uv_write callbacks the same way; running them
  //     inside respond() would re-enter JS from a V8 fast call. Bytes are
  //     still pushed to the socket immediately.
  //   - freeing a closed Connection runs from its poll handle's close
  //     callback: freeConnection may `delete this` (a fully closed Server),
  //     which must not happen on a Server method's stack.
 public:
  // Per-thread state of the epoll transport. Every listening and accepted
  // socket is a libuv poll handle on this loop, so libuv's own epoll_wait -
  // one per loop iteration - delivers every readiness event, and the engine
  // makes the accept, receive and send calls itself on plain non-blocking
  // sockets. (1.1.10 kept a private epoll fd behind one poll handle and
  // drained it with a second epoll_wait per iteration; with few events per
  // iteration that second call was measurable.) What is shared across the
  // servers on a thread lives here: the check handle that runs write
  // completions on a clean stack (a write issued from a V8 fast call must
  // not re-enter JS synchronously), the EMFILE spare descriptor, the set of
  // listening servers.
  struct EpollLoop {
    uv_loop_t* loop = nullptr;
    uv_check_t check;
    bool checkActive = false;
    bool checkClosed = false;
    int emfileFd = -1;
    std::vector<Connection*> completions;  // fully-sent queued writes to complete
    std::vector<Connection*> ready;  // sockets the poll phase reported this turn, each once; served by serve()
    std::vector<Connection*> readySpare;  // empty; the storage serve() hands to `ready` for the next turn
    unsigned groups = 1;       // peer-CPU groups seen so far (max peerCpu + 2, -1 being a group)
    unsigned turn = 0;         // serve() calls; the group that goes first rotates with it

    // Which order serves a turn. 'grouped', the default, sorts the turn's
    // sockets by peer CPU (serve() below); 'arrival' serves them as the kernel
    // reported them; 'auto' measures both and keeps whichever the current
    // peers answer faster. A probe is four windows of 200 ms, grouped and
    // arrival alternating, the first 50 ms of each not counted while the
    // peers settle into the order. A probe whose two windows of one order
    // disagree by more than 30% saw the load change and is repeated. Leaving
    // the grouped order takes two consecutive probes that agree (one noisy
    // probe never moves a loop off its default); returning to it takes one.
    // The winner by more than 8% over its two windows then serves for a stay
    // that grows with the margin: 1 s for a near tie, 4 s at a 5% margin,
    // 16 s at 20% or more, and doubles each time the same order wins again,
    // up to 64 s; a confident, repeated decision is kept, an uncertain one is
    // soon re-examined. Stays end on boundaries of the monotonic clock, so
    // the loops of one host (cluster workers, worker threads) probe in step
    // and never measure each other's probes. The stay also ends when the
    // peers change: the live rate (one-second windows) moves 25% away from
    // what the probe measured, in either direction, or the loop accepts more
    // new connections in a second than a quarter of the sockets it has been
    // serving per turn. MORO_ENGINE_SERVE_ORDER=grouped|arrival|auto selects
    // the order (grouped unless set); MORO_ENGINE_SERVE_DEBUG=1 logs the
    // decisions.
    enum class Order : uint8_t { Grouped, Arrival };
    bool autoOrder = false;
    bool debug = false;
    Order order = Order::Grouped;
    uint64_t winStart = 0;     // uv_hrtime() at the start of the current window
    size_t winServed = 0;      // sockets served in it (after the settle time)
    uint8_t phase = 0;         // 0..3: probe windows (G, A, G, A); 4: serving the winner
    double sumGrouped = 0, sumArrival = 0;
    double winGrouped[2] = {0, 0}, winArrival[2] = {0, 0};  // the probe's four windows
    double winnerRate = 0;     // the winner's probe rate
    Order lastWinner = Order::Grouped;
    unsigned repeats = 0;      // consecutive probes won by the same order
    bool arrivalPending = false;  // arrival won the last probe; it needs a second one to take over
    Order before = Order::Grouped;  // the order in effect when the running probe began
    uint64_t subStart = 0;     // live-rate sub-window while serving the winner
    size_t subServed = 0;
    size_t subAccepts = 0;     // connections accepted in the sub-window
    size_t subPeak = 0;        // largest turn in the sub-window (a proxy for the live connection count)
    void noteAccept() { subAccepts++; }
    static constexpr uint64_t kSettleNs = 50ull * 1000 * 1000;
    static constexpr uint64_t kProbeNs = 200ull * 1000 * 1000;
    static constexpr uint64_t kExploitNs = 4000ull * 1000 * 1000;
    uint64_t exploitNs = kExploitNs;  // this stay's length: kExploitNs x (margin / 5%), 0.25x..4x
    static constexpr uint64_t kSubNs = 1000ull * 1000 * 1000;
    EpollLoop() {
      const char* e = getenv("MORO_ENGINE_SERVE_ORDER");
      if (e && strcmp(e, "arrival") == 0) order = Order::Arrival;
      else if (e && strcmp(e, "auto") == 0) autoOrder = true;
      const char* d = getenv("MORO_ENGINE_SERVE_DEBUG");
      debug = d && *d && *d != '0';
    }
    static Order probeOrder(uint8_t ph) { return (ph & 1u) ? Order::Arrival : Order::Grouped; }
    void startProbe(uint64_t now) {
      before = order;
      phase = 0; order = Order::Grouped; winStart = now; winServed = 0; sumGrouped = sumArrival = 0;
    }
    void tune(size_t served) {
      if (!autoOrder) return;
      const uint64_t now = uv_hrtime();
      if (winStart == 0) { startProbe(now); return; }
      const uint64_t elapsed = now - winStart;
      if (phase == 4) {
        subServed += served;
        if (served > subPeak) subPeak = served;
        // The stay ends at the next multiple of its length on the monotonic
        // clock (never sooner than half its length), so co-located loops
        // with the same stay probe together.
        bool reprobe = elapsed >= exploitNs / 2 && (now / exploitNs) != (winStart / exploitNs);
        if (!reprobe && now - subStart >= kSubNs) {
          const double live = static_cast<double>(subServed) * 1e9 / static_cast<double>(now - subStart);
          if (live < winnerRate * 0.75 || live > winnerRate * 1.25) {
            reprobe = true;
            if (debug) fprintf(stderr, "[serve] live %.0f/s vs %.0f/s: re-probe\n", live, winnerRate);
          } else if (subAccepts * 4 > subPeak && subAccepts >= 8) {
            reprobe = true;
            if (debug) fprintf(stderr, "[serve] %zu new connections against turns of %zu: re-probe\n", subAccepts, subPeak);
          }
          subStart = now; subServed = 0; subAccepts = 0; subPeak = 0;
        }
        if (reprobe) startProbe(now);
        return;
      }
      if (elapsed >= kSettleNs) winServed += served;
      if (elapsed < kProbeNs) return;
      const double rate = static_cast<double>(winServed) * 1e9 / static_cast<double>(elapsed - kSettleNs);
      if (probeOrder(phase) == Order::Grouped) { sumGrouped += rate; winGrouped[phase / 2] = rate; }
      else { sumArrival += rate; winArrival[phase / 2] = rate; }
      if (debug) fprintf(stderr, "[serve] probe %u %s %.0f/s\n", phase, probeOrder(phase) == Order::Grouped ? "grouped" : "arrival", rate);
      phase++;
      winStart = now; winServed = 0;
      if (phase < 4) { order = probeOrder(phase); return; }
      // The load changed during the probe (an order's two windows disagree by
      // more than 30%): nothing can be concluded from it. Probe again.
      const auto steady = [](const double* w) {
        const double hi = std::max(w[0], w[1]), lo = std::min(w[0], w[1]);
        return hi <= 0 || lo >= hi * 0.7;
      };
      if (!steady(winGrouped) || !steady(winArrival)) {
        if (debug) fprintf(stderr, "[serve] probe unsteady (grouped %.0f/%.0f, arrival %.0f/%.0f): again\n", winGrouped[0], winGrouped[1], winArrival[0], winArrival[1]);
        startProbe(now);
        return;
      }
      // Grouped unless arrival is clearly better over both of its windows,
      // and, when the loop is still on grouped, better in two probes in a row.
      Order winner = sumArrival > sumGrouped * 1.08 ? Order::Arrival : Order::Grouped;
      if (winner == Order::Arrival && before == Order::Grouped && !arrivalPending) {
        arrivalPending = true;
        order = Order::Grouped;
        winnerRate = sumGrouped / 2.0;
        exploitNs = kExploitNs / 4;  // a short stay: the confirming probe follows soon
        subStart = now; subServed = 0; subAccepts = 0; subPeak = 0;
        if (debug) fprintf(stderr, "[serve] arrival ahead (grouped %.0f/s, arrival %.0f/s): confirming\n", sumGrouped / 2, sumArrival / 2);
        return;
      }
      arrivalPending = false;
      order = winner;
      winnerRate = (winner == Order::Arrival ? sumArrival : sumGrouped) / 2.0;
      subAccepts = 0; subPeak = 0;
      const double hi = std::max(sumArrival, sumGrouped), lo = std::min(sumArrival, sumGrouped);
      const double margin = hi > 0 ? (hi - lo) / hi : 0.0;  // 0.1 = 10%
      const double stretch = std::min(4.0, std::max(0.25, margin / 0.05));
      repeats = winner == lastWinner ? std::min(repeats + 1, 4u) : 0;
      lastWinner = winner;
      exploitNs = static_cast<uint64_t>(static_cast<double>(kExploitNs) * stretch) << repeats;
      if (exploitNs > 64000ull * 1000 * 1000) exploitNs = 64000ull * 1000 * 1000;
      subStart = now; subServed = 0;
      if (debug) fprintf(stderr, "[serve] winner %s (grouped %.0f/s, arrival %.0f/s)\n", winner == Order::Grouped ? "grouped" : "arrival", sumGrouped / 2, sumArrival / 2);
    }
    std::unordered_set<Server*> servers;

    static EpollLoop*& slot() { return loopSlots().epoll; }

    static EpollLoop* get(uv_loop_t* loop) {
      EpollLoop*& s = slot();
      if (s) return s;
      auto* u = new EpollLoop();
      u->loop = loop;
      u->check.data = u;
      uv_check_init(loop, &u->check);
      uv_unref(reinterpret_cast<uv_handle_t*>(&u->check));
      u->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      s = u;
      return u;
    }

    void armCheck() {
      if (!checkActive) {
        checkActive = true;
        uv_check_start(&check, onCheck);
      }
    }
    void deferCompletion(Connection* c) {
      completions.push_back(c);
      armCheck();
    }
    void dropCompletion(Connection* c) {
      auto it = std::find(completions.begin(), completions.end(), c);
      if (it != completions.end()) completions.erase(it);
    }
    // One service per socket per loop turn. The watchers are level-triggered
    // and the poll phase only records what it is told, so a socket reported
    // once is reported again by every further epoll_wait of the same turn -
    // and libuv waits again, up to 48 times, whenever a wait fills its event
    // buffer. A loop with more ready sockets than that buffer holds used to
    // queue each of them once per wait and recv() it that many times, all but
    // the first for EAGAIN: a dozen wasted system calls per request at 4096
    // connections on one loop, and the kernel re-polling a thousand sockets
    // per wait to say so.
    //
    // So the turn's sockets are served as soon as a full buffer's worth has
    // been recorded, which is exactly when libuv is about to wait again: the
    // next wait then reports only what is new. And a socket already served in
    // this turn is not queued a second time, whatever reports it: its report
    // is either stale or about bytes that arrived since, and level-triggered
    // readiness repeats the second kind at the next turn. Repeated reports of
    // a socket still waiting for its service are OR-ed into its one entry.
    static constexpr size_t kPollBatch = 1024;  // libuv's epoll event buffer (uv__io_poll)
    uint32_t iteration = 1;  // the loop turn being served; advanced by settle()
    void deferReady(Connection* c, int events) {
      // The check is armed for every report, the set-aside ones included: the
      // turn then always ends in settle(), which advances `iteration`, so a
      // socket is never left waiting on a turn that does not end.
      armCheck();
      if (c->ep.servedTurn == iteration) return;
      c->ep.readyEvents |= events;
      if (c->ep.readyQueued) return;
      c->ep.readyQueued = true;
      ready.push_back(c);
      if (ready.size() >= kPollBatch) serve();
    }
    // The turn's events for a queued socket, taken as it is served: the entry
    // is spent and the socket is done for this turn.
    int takeReady(Connection* c) const {
      const int events = c->ep.readyEvents;
      c->ep.readyEvents = 0;
      c->ep.readyQueued = false;
      c->ep.servedTurn = iteration;
      return events;
    }
    static void onCheck(uv_check_t* h) { static_cast<EpollLoop*>(h->data)->settle(); }

    // Service order. The poll phase only records which sockets are readable;
    // they are served here, in the check phase of the same loop turn, grouped
    // by the CPU their peer's packets arrive on (SO_INCOMING_CPU: the peer
    // thread's CPU over loopback, the receive queue's CPU behind a NIC) and by
    // socket number within a group. The kernel reports readiness in an order
    // that says nothing about who is on the other end; a peer that drives many
    // connections from one event loop - a proxy, a connection pool, a load
    // generator - then gets its replies back to back and is woken once per
    // group instead of once per reply. That wake-up is paid on this side, in
    // send(), so the grouping is cheaper for both ends. Every socket reported
    // in a turn is served in that turn; which group goes first rotates from
    // turn to turn, so no peer is always the last to be answered.
    void serve() {
      if (ready.empty()) return;
      // The turn's list is taken, and `ready` is left with the storage the
      // previous turn's list gave back: swapped against a fresh vector, it
      // was grown again from nothing on every turn, a handful of allocations
      // each. The list stays this call's own, so nothing a handler does can
      // touch it while it is being walked.
      std::vector<Connection*> list;
      list.swap(readySpare);
      list.swap(ready);
      tune(list.size());
      if (order == Order::Grouped) {
        const unsigned n = groups, rot = turn++ % n;
        const auto key = [n, rot](const Connection* c) { return (static_cast<unsigned>(c->ep.peerCpu + 1) + rot) % n; };
        std::sort(list.begin(), list.end(), [&key](const Connection* a, const Connection* b) {
          const unsigned ka = key(a), kb = key(b);
          if (ka != kb) return ka < kb;
          return a->ep.fd < b->ep.fd;
        });
      }
      for (Connection* c : list) {
        const int events = takeReady(c);
        if (c->ep.state < 2) c->server->epollOnConn(c, events);
      }
      // A burst's worth of capacity is not kept on an idle loop.
      list.clear();
      if (list.capacity() <= 4 * kPollBatch && list.capacity() > readySpare.capacity()) readySpare.swap(list);
    }

    // Clean-stack work: serve this turn's readable sockets, then complete
    // fully-sent writes, which may surface further requests and queue more
    // writes - those complete in the next pass. A connection closed along the
    // way is skipped by its state.
    void settle() {
      if (checkActive) {
        checkActive = false;
        uv_check_stop(&check);
      }
      serve();
      if (++iteration == 0) iteration = 1;  // what is reported from here on belongs to the next turn (0 marks a socket never served)
      for (int pass = 0; pass < 64 && !completions.empty(); pass++) {
        std::vector<Connection*> list;
        list.swap(completions);
        for (Connection* c : list) {
          if (c->ep.state < 2) c->server->epollCompleteWrites(c);
        }
      }
      if (!completions.empty() || !ready.empty()) armCheck();
    }

    static void shutdownForThread() {
      EpollLoop*& s = slot();
      if (!s) return;
      EpollLoop* u = s;
      s = nullptr;
      u->settle();
      uv_close(reinterpret_cast<uv_handle_t*>(&u->check), onCheckClosed);
      while (!u->checkClosed) uv_run(u->loop, UV_RUN_ONCE);
      if (u->emfileFd >= 0) ::close(u->emfileFd);
      delete u;
    }
    static void onCheckClosed(uv_handle_t* h) {
      static_cast<EpollLoop*>(h->data)->checkClosed = true;
    }
  };

 private:
  int epollListen(const sockaddr_storage& addr) {
    const socklen_t len = addr.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (addr.ss_family == AF_INET6) {
      int off = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }
    if (limits_.reusePort) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));  // inherited by every accepted socket
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
    listenPoll_.data = this;
    int r = uv_poll_init(loop_, &listenPoll_, fd);
    if (r != 0) {
      ::close(fd);
      return r;
    }
    listenFd_ = fd;
    liveHandles_++;  // balanced in onListenPollClosed
    if (epoll_->emfileFd < 0) epoll_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);  // (given back with the last listener)
    epoll_->servers.insert(this);
    uv_poll_start(&listenPoll_, UV_READABLE, onListenPoll);
    return 0;
  }

  static void onListenPoll(uv_poll_t* h, int status, int) {
    if (status < 0) return;
    static_cast<Server*>(h->data)->epollOnListener();
  }

  void epollOnListener() {
    if (listenFd_ < 0) return;
    for (int i = 0; i < 64; i++) {
      int fd = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) {
        if (errno == EINTR || errno == ECONNABORTED) continue;
        if (errno == EMFILE || errno == ENFILE) {
          // Out of descriptors: accept and drop one connection so the
          // listener does not stay readable forever (the uv/uring transports
          // do the same through their EMFILE fallbacks).
          if (epoll_->emfileFd >= 0) {
            ::close(epoll_->emfileFd);
            int d = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (d >= 0) ::close(d);
            epoll_->emfileFd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
          }
          // Without the spare (something else in the process took the
          // descriptor while it was lent out) the connection can be neither
          // accepted nor dropped, and the listener would report it on every
          // loop turn: a loop that never sleeps, for as long as the process
          // stays at its limit. The listener is left alone until a
          // descriptor may be free again (resumeAccept).
          if (epoll_->emfileFd < 0) pauseAccept();
        } else if (errno == ENOBUFS || errno == ENOMEM) {
          pauseAccept();  // the same: the connection stays queued, and so would the event
        }
        break;  // EAGAIN or an error: nothing more to accept right now
      }
      if (closeRequested_ || listenerClosed_ ||
          (limits_.maxConnections && conns_.size() >= limits_.maxConnections)) {
        ::close(fd);
        continue;
      }
      epollAcceptFd(fd);
    }
  }

  void epollAcceptFd(int fd) {
    Connection* c = new Connection();
    c->server = this;
    c->ep.fd = fd;
    c->ep.state = 1;
    c->ep.reads = 0;
    c->ep.poll.data = c;
    epollReadPeerCpu(c);
    if (uv_poll_init(loop_, &c->ep.poll, fd) != 0) {
      ::close(fd);
      delete c;
      return;
    }
    liveHandles_++;  // balanced by freeConnection (from onConnPollClosed)
    epoll_->noteAccept();
    attachConnection(c);
    if (!readBuf_) {
      readBuf_.reset(new char[65536]);
      readBufSize_ = 65536;
    }
    uv_poll_start(&c->ep.poll, UV_READABLE | UV_DISCONNECT, onConnPoll);
  }

  // libuv reports a socket error (POLLERR) as a negative status and stops
  // the watcher; a hang-up or half-close arrives as readable / disconnect and
  // recv() then says 0 or the error, which is the EOF path either way.
  //
  // An error does not mean there is nothing to read: what the peer sent
  // before it reset the connection is still in the receive queue, and the
  // kernel hands it over before it reports the reset. So the error is served
  // as a read, like any other input - one buffer per loop turn - and the
  // recv() that finds the queue empty is the one that ends the connection
  // (epollOnConn). The watcher libuv stopped is started again for the turns
  // that takes; the error is reported again on each of them.
  static constexpr int kEpollError = 1 << 8;  // beside the uv_poll_event bits: this service follows an error report
  static void onConnPoll(uv_poll_t* h, int status, int events) {
    Connection* c = static_cast<Connection*>(h->data);
    if (c->ep.state >= 2) return;
    if (status < 0) {
      if (c->ep.eofSeen) return;
      uv_poll_start(&c->ep.poll, UV_READABLE | UV_DISCONNECT | (c->ep.wantOut ? UV_WRITABLE : 0), onConnPoll);
      events = UV_READABLE | kEpollError;
    }
    c->server->epoll_->deferReady(c, events);
  }

  void epollReadPeerCpu(Connection* c) {
    int cpu = -1;
    socklen_t len = sizeof(cpu);
    if (::getsockopt(c->ep.fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, &len) != 0 || cpu < -1) cpu = -1;
    c->ep.peerCpu = cpu;
    if (static_cast<unsigned>(cpu + 2) > epoll_->groups) epoll_->groups = static_cast<unsigned>(cpu + 2);
  }

  void epollOnConn(Connection* c, int events) {
    if (events & UV_WRITABLE) {
      epollFlush(c);
      // A write that failed ends the connection in this turn's completion
      // pass (epollCompleteWrites); nothing more is read from it.
      if (c->ep.state >= 2 || c->ep.writeError) return;
    }
    if (!(events & (UV_READABLE | UV_DISCONNECT))) return;
    ssize_t n = ::recv(c->ep.fd, readBuf_.get(), readBufSize_, 0);
    if (n > 0) {
      if ((++c->ep.reads & 1023u) == 0) epollReadPeerCpu(c);  // the peer may have moved CPU
      // Level-triggered: anything left in the socket raises the next event.
      onTransportData(c, readBuf_.get(), static_cast<size_t>(n));
      return;
    }
    // (An error report that recv() has nothing to say about would be
    // reported again on every turn: it ends the connection, as it always did.)
    if (n < 0 && (errno == EINTR || ((errno == EAGAIN || errno == EWOULDBLOCK) && !(events & kEpollError))))
      return;  // a half-close with the receive queue drained: the FIN arrives as recv() == 0 next
    if (!c->ep.eofSeen) {
      c->ep.eofSeen = true;
      onTransportEof(c);
    }
  }

  void epollQueueWrite(Connection* c, WriteReq* wr) {
    wr->next = nullptr;
    if (c->ep.wqTail) static_cast<WriteReq*>(c->ep.wqTail)->next = wr;
    else c->ep.wqHead = wr;
    c->ep.wqTail = wr;
    c->ep.pendingBytes += wr->data.size();
    epollFlush(c);
  }

  void epollWantOut(Connection* c, bool on) {
    if (c->ep.wantOut == on || c->ep.state >= 2 || c->ep.fd < 0) return;
    uv_poll_start(&c->ep.poll, UV_READABLE | UV_DISCONNECT | (on ? UV_WRITABLE : 0), onConnPoll);
    c->ep.wantOut = on;
  }

  // Push the write queue as far as the socket takes it, in order. Nothing is
  // completed here: a fully-sent WriteReq stays at the head (pendingWrites
  // keeps later writes on the ordered queue) until epollCompleteWrites runs
  // on a clean stack. Nor is the connection torn down here for a hard socket
  // error (the peer reset it): this may be running inside a write the
  // application is making right now, and the teardown of a WebSocket calls
  // onWsClose - inside wsSend() the binding may be reading the payload
  // straight out of the V8 heap, where no JS may run. The error is kept
  // (writeError) and epollCompleteWrites acts on it in the same loop turn,
  // on a clean stack: where the uv and uring transports deliver a failed
  // write. Until then the queue only collects what is written to it.
  void epollFlush(Connection* c) {
    if (c->ep.state >= 2 || c->ep.inFlush || c->ep.writeError) return;
    c->ep.inFlush = true;
    bool anyDone = false;
    for (WriteReq* wr = static_cast<WriteReq*>(c->ep.wqHead); wr; wr = wr->next) {
      const size_t remaining = wr->data.size() - wr->sent;
      if (remaining == 0) {
        anyDone = true;
        continue;
      }
      const size_t len = remaining > kMaxWriteChunk ? kMaxWriteChunk : remaining;
      ssize_t r = ::send(c->ep.fd, wr->data.data() + wr->sent, len, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
          epollWantOut(c, true);
          break;
        }
        c->ep.writeError = -errno;
        break;
      }
      wr->sent += static_cast<size_t>(r);
      c->ep.pendingBytes -= static_cast<size_t>(r) < c->ep.pendingBytes ? static_cast<size_t>(r) : c->ep.pendingBytes;
      if (wr->sent < wr->data.size()) {
        epollWantOut(c, true);
        break;
      }
      anyDone = true;
    }
    c->ep.inFlush = false;
    if (c->ep.wantOut && c->ep.pendingBytes == 0) epollWantOut(c, false);
    if ((anyDone || c->ep.writeError) && !c->ep.completionPending) {
      c->ep.completionPending = true;
      epoll_->deferCompletion(c);
    }
  }

  // Clean stack only (EpollLoop::settle): pop every fully-sent WriteReq from
  // the head, in order, and run its completion - a terminal one finishes the
  // response and may surface the next pipelined request. A write that failed
  // (epollFlush) ends the connection instead: the queue is dropped, nothing
  // on it is completed, and the connection is aborted.
  void epollCompleteWrites(Connection* c) {
    c->ep.completionPending = false;
    if (c->ep.writeError) {
      const int e = c->ep.writeError;
      epollDropQueue(c);
      completeWrite(c, false, e);  // -> abortConnection
      return;
    }
    while (WriteReq* wr = static_cast<WriteReq*>(c->ep.wqHead)) {
      if (wr->sent < wr->data.size()) break;
      const bool terminal = wr->terminal;
      c->ep.wqHead = wr->next;
      if (!c->ep.wqHead) c->ep.wqTail = nullptr;
      delete wr;
      c->pendingWrites--;
      completeWrite(c, terminal, 0);
      if (c->ep.state >= 2) return;
    }
  }

  void epollDropQueue(Connection* c) {
    WriteReq* wr = static_cast<WriteReq*>(c->ep.wqHead);
    while (wr) {
      WriteReq* next = wr->next;
      delete wr;
      c->pendingWrites--;
      wr = next;
    }
    c->ep.wqHead = c->ep.wqTail = nullptr;
    c->ep.pendingBytes = 0;
  }

  // The socket is closed once libuv has let go of its watcher (the close
  // callback), never before: the descriptor number could be reused by the
  // next accept while libuv still had it in its table. The Connection is
  // freed from that same callback, on a clean stack.
  void epollCloseConn(Connection* c) {
    if (c->ep.state >= 2) return;
    c->ep.state = 2;
    // A completion still waiting for the check pass is taken back. Queued
    // from the poll phase it is served in the same loop turn, before any
    // close callback frees a Connection; queued after that turn's check pass
    // (a write made from setImmediate) it waits for the next turn, and a
    // connection closed in between is freed first.
    if (c->ep.completionPending) {
      c->ep.completionPending = false;
      epoll_->dropCompletion(c);
    }
    uv_poll_stop(&c->ep.poll);
    uv_close(reinterpret_cast<uv_handle_t*>(&c->ep.poll), onConnPollClosed);
  }
  static void onConnPollClosed(uv_handle_t* h) {
    Connection* c = static_cast<Connection*>(h->data);
    if (c->ep.fd >= 0) {
      ::close(c->ep.fd);
      c->ep.fd = -1;
    }
    c->server->freeConnection(c);  // may delete the Server (checkFullyClosed)
  }

  void epollCloseListener() {
    if (listenFd_ < 0 || listenerClosing_) return;
    listenerClosing_ = true;
    uv_poll_stop(&listenPoll_);
    uv_close(reinterpret_cast<uv_handle_t*>(&listenPoll_), onListenPollClosed);
  }
  static void onListenPollClosed(uv_handle_t* h) {
    Server* s = static_cast<Server*>(h->data);
    if (s->listenFd_ >= 0) {
      ::close(s->listenFd_);
      s->listenFd_ = -1;
    }
    s->epoll_->servers.erase(s);
    // The spare descriptor is for listeners: with the last of them gone it
    // goes back to the process (epollListen opens it again).
    if (s->epoll_->servers.empty() && s->epoll_->emfileFd >= 0) {
      ::close(s->epoll_->emfileFd);
      s->epoll_->emfileFd = -1;
    }
    s->liveHandles_--;
    s->checkFullyClosed();  // may delete s
  }

  EpollLoop* epoll_ = nullptr;
  uv_poll_t listenPoll_{};
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
  // kNotifyWsShed carries a wsId, not a reqId: a WebSocket that wsSend()
  // found past wsBackpressureLimit, closed with 1013 on this later turn.
  // kNotifyWsGone carries a wsId too: a WebSocket whose send could not be
  // completed (closeForFailedSend), torn down on this later turn - 1006.
  enum : uint8_t { kNotifyAborted = 0, kNotifyWritable = 1, kNotifyWsShed = 2, kNotifyWsGone = 3 };
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
    if (kind == kNotifyWsShed) {
      Connection* c = lookupWs(reqId);
      if (c && !c->wsClosing && !c->closing) wsClose(c, 1013, "", 0);
      return;
    }
    if (kind == kNotifyWsGone) {
      Connection* c = lookupWs(reqId);
      if (c && !c->closing) doClose(c);
      return;
    }
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
  bool wsAutoUpgrade_ = false;
  uint32_t* batchControl_ = nullptr;
  // The connection whose HTTP/1 batch JS is looping over right now (null
  // outside onRequestBatch, and from the moment JS returns from it).
  Connection* batchLoopConn_ = nullptr;
  // Keyed by path and looked up with the Connection's own std::string, so the
  // hot path allocates nothing. One or two methods per path in any real app,
  // so the per-path vector is scanned linearly.
  std::unordered_map<std::string, std::vector<StaticRoute>> staticRoutes_;
  std::vector<ParamRoute> paramRoutes_;
  uint32_t routeGen_ = 1;  // see routesChanged()

  // Per-loop scratch that used to be thread_local (see refreshHttpDateLine
  // and onAlloc): a Server is one per loop thread, so members are the same
  // ownership without the TLS indirection on every read and response.
  std::string dateCache_;
  time_t dateCachedAt_ = 0;
  // The calling thread's request registry and id counter, likewise: looked
  // up once here instead of through a TLS descriptor call (two for the map,
  // which carries an initialisation guard) on every id, insert and erase. A
  // Server is created, used and destroyed on one thread.
  FlatReqMap* const reqMap_ = &globalRequests();
  uint32_t* const reqCounter_ = &globalReqCounter();
  // Ciphertext of the TLS response being written (tlsWrite): one buffer per
  // loop, reused across responses, so a TLS reply allocates nothing.
  std::string cipherScratch_;
  // Where wsSend deflates a message (the frame is built from it before the
  // call returns). Capacity over kCipherScratchKeep is released after use.
  std::string deflateScratch_;
  TlsGather tlsGather_;        // the small TLS replies of the batch in progress (tlsCork)
  uint32_t tlsGatherSeq_ = 0;  // the last ticket given out
  std::vector<std::string> bodyPool_;  // empty strings with capacity; see HttpParser::bodyPool

  // HTTP/2 (see the "HTTP/2" section).
  std::vector<Connection*> h2Free_;      // request Connections ready for reuse
  std::vector<Connection*> h2Dead_;      // ...and ones to delete at the next sweep
  std::vector<Connection*> h2Batch_;     // requests gathered during a read, not yet handed to JS
  size_t h2BatchBase_ = 0;               // where the batch call in progress starts in h2Batch_
  uint32_t h2BatchGen_ = 0;              // identifies the latest batch call
  bool h2InBatchCall_ = false;           // onRequestBatch is on the stack for an HTTP/2 batch
  bool h2LoopOpen_ = false;              // ... and JS is still inside its loop over that batch
  Connection* h2BatchParent_ = nullptr;  // the connection h2Batch_ is being dispatched for
  std::vector<std::pair<uint32_t, Connection*>> h2Waiters_;  // (reqId, connection) waiting for the socket to drain
  std::string h2Block_;                  // header block under construction
  std::string h2Date_;                   // the Date field, encoded; rebuilt with the Date cache
  time_t h2DateAt_ = 0;
  const std::string& dateLine() {
    refreshHttpDateLine(dateCache_, dateCachedAt_);
    return dateCache_;
  }
#if !defined(_WIN32)
  // One receive buffer per loop, shared by every connection (see onAlloc).
  std::unique_ptr<char[]> readBuf_;
  size_t readBufSize_ = 0;
#endif
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
  bool listenUp_ = false;        // listen() succeeded: this server has its listener
  void (*onClosed_)(void*) = nullptr;
  void* onClosedUser_ = nullptr;
  // libuv transport, streams stopped for the rest of a turn (uvStopReading).
  std::vector<Connection*> uvStopped_;
  uv_check_t uvResume_{};
  bool uvResumeInit_ = false;  // uvResume_ is an open handle (counted in liveHandles_)
  bool uvResumeOn_ = false;    // ... and started

 public:
  ServerCallbacks& callbacks() { return cb_; }
};

}  // namespace engine
}  // namespace moro
