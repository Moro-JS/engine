# @morojs/engine — Native Binding API (M1/M2)

The Moro-shaped boundary: **one JS crossing per request in, one out** for the
common case. Everything else is lazy, fetched only when the handler asks.

All functions are exported by the native addon (and re-exported by the
`@morojs/engine` meta package). Request handles (`reqId`) are opaque uint32s,
valid from the `onRequest` call until `respond()`/`end()` returns or
`onAborted` fires — after that every call with the id is a safe no-op
(returns undefined/false).

```ts
// ---- server lifecycle ----
serve(callbacks: {
  onRequest(reqId: number, methodIdx: number, path: string): void;
  onRequestBatch?(count: number): number;   // see "Batched pipelined dispatch"
  onAborted(reqId: number): void;      // client disconnected / server tore the request down
  onWritable(reqId: number): void;     // write() backpressure drained
  // onAborted / onWritable are delivered on a LATER loop turn, never re-entrantly
  // from inside a respond()/writeHead()/write()/end() call (a write failure or a
  // responseBackpressureLimit trip inside respond() surfaces after respond()
  // returned; isAborted(reqId) is already true inside onAborted). The one
  // exception: close() delivers the onAborted of every in-flight request
  // synchronously, before close() returns. capabilities.asyncNotify; the
  // MORO_ENGINE_NOTIFY=sync env var restores the pre-1.1.6 re-entrant delivery
  // for bisecting (probe().notify reports which mode is active).
}, options?: {
  maxBodySize?: number;        // default 10MB; larger bodies 413 natively
  idleTimeoutMs?: number;      // default 120000; 0 disables (resets on any byte)
  requestTimeoutMs?: number;   // default 300000; 0 disables. Budget for receiving ONE
                               // complete request from its first byte - does NOT reset
                               // on activity (slow-drip slowloris defense). Expiry: 408 + close.
  responseTimeoutMs?: number;  // default 300000; 0 disables. Budget for DELIVERING queued
                               // outbound bytes: resets on drain progress (the write queue
                               // shrank since the last sweep, or a write completed), so only a
                               // drain making NO progress for the whole budget is closed -
                               // steady slow readers of large responses are never shed
                               // (slow-read / zero-window DoS defense; capabilities.responseLimits).
  maxConnections?: number;     // default 0 = unlimited
  maxPendingBytes?: number;    // default maxHeadSize + maxBodySize
  reusePort?: boolean;         // default false. SO_REUSEPORT so several engine instances
                               // (cluster workers / worker threads) share one port with
                               // kernel-balanced accepts. POSIX only; ignored on Windows.
  // Runtime-configurable limits (previously compile-time constants).
  // Values are defaults, not caps; nonsense values (0 where 0 is meaningless)
  // are ignored in favor of the default.
  maxHeadSize?: number;        // default 65536; request line + all headers (431 over)
  maxHeaders?: number;         // default 100 (431 over)
  maxUriSize?: number;         // default 0 = no dedicated cap (maxHeadSize still bounds the
                               // head with 431); set to answer 414 for over-long targets
  responseBackpressureLimit?: number; // default 0 = unlimited. Opt-in hard cap on the
                               // not-yet-flushed HTTP outbound queue; over it the connection
                               // is closed immediately (HTTP mirror of wsBackpressureLimit).
                               // Leave 0 unless response sizes are bounded: one large
                               // respond() legitimately queues its whole body. Memory note:
                               // a queued response holds an engine-side copy (~2x body peak
                               // for one slow drain, bounded in time by responseTimeoutMs) -
                               // apps serving large payloads to untrusted clients should set
                               // this cap or stream via writeHead()/write() chunks instead.
  wsMaxMessageSize?: number;   // default 16MB; reassembled WS message cap (close 1009 over)
  wsBackpressureLimit?: number;// default 1MB; slow WS consumer shed with 1013. 0 = unlimited
  writeHighWaterMark?: number; // default 262144; write()/wsSend() report backpressure above
  backlog?: number;            // default 512; TCP listen backlog

  // In-process TLS termination (probe().capabilities.tls). Both
  // MoroJS ssl shapes are accepted; inline PEM wins over a file path for the
  // same slot. Config errors THROW from serve() (never a silent plaintext
  // boot). HTTPS and WSS both work; ALPN negotiates http/1.1.
  ssl?: {
    key_file_name?, cert_file_name?, ca_file_name?: string;     // file shape
    key?, cert?, ca?: string | Buffer | ArrayBuffer;            // inline PEM
    passphrase?: string;               // for an encrypted key
    minVersion?: 'TLSv1.2'|'TLSv1.3';  // default TLSv1.2
    requestCert?: boolean;             // mutual TLS
    rejectUnauthorized?: boolean;      // default true
    // Explicit cipher/group policy (capabilities.tlsPolicy) for compliance
    // baselines; unset = the host Node's OpenSSL defaults. Same semantics as
    // Node's tls.createSecureContext; invalid values THROW from serve().
    ciphers?: string;                  // TLS <= 1.2 cipher list
    ciphersuites?: string;             // TLS 1.3 suites (colon-separated)
    ecdhCurve?: string;                // key-share groups, e.g. 'X25519:P-256'; 'auto' = default
  };

  // WebSocket permessage-deflate (RFC 7692; feature-detect via
  // probe().capabilities.wsDeflate). Off by default (preserves the
  // compression-oracle-free posture). boolean to enable with defaults, or an
  // options object.
  wsDeflate?: boolean | {
    serverNoContextTakeover?, clientNoContextTakeover?: boolean;
    serverMaxWindowBits?, clientMaxWindowBits?: number;   // 8..15
    threshold?: number;             // min message bytes to compress a send (default 1024)
    maxDecompressedSize?: number;   // inflate cap / zip-bomb defense (default wsMaxMessageSize)
  };
}): number;   // -> serverId

listen(serverId: number, host: string, port: number): number; // -> actual port; throws Error w/ .code (e.g. 'EADDRINUSE') on bind error
stopListening(serverId: number): void; // stop accepting, keep serving existing connections
                                       // (graceful-shutdown drain phase; then close())
updateSsl(serverId: number, ssl): void; // certificate rotation (capabilities.tlsReload): validate a
                                       // NEW context from the full ssl shape above and use it for
                                       // every handshake from now on; established connections keep
                                       // theirs. Throws (current context untouched) on bad material
                                       // or a server not started with ssl. ticketKeys carry over
                                       // when omitted.
close(serverId: number): void;   // full teardown: stop accepting AND close every live
                                 // connection; in-flight requests get onAborted

// ---- request data (lazy; single crossing each) ----
// methodIdx indexes METHODS = ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','OTHER']
getMethod(reqId): string | undefined;     // canonical method name; the extra crossing is
                                          // only NEEDED for methodIdx 7 (OTHER)
getQuery(reqId): string;                  // raw query string, '' if none
getHeaders(reqId): string[];              // flat [k1,v1,k2,v2,...], keys lowercased
getHeader(reqId, lowercaseName: string): string | undefined;
getBody(reqId): ArrayBuffer | null;       // engine buffers bodies natively; onRequest
                                          // fires AFTER the body is complete (or 413s natively)
getRemoteAddress(reqId): string;

// ---- response ----
// Body accepts string | ArrayBuffer | Uint8Array | Buffer (Buffer is a Uint8Array).
// Terminal single-shot (the fast path - status+headers+body in one cork):
respond(reqId, status: number, headersFlat: string[] | null, body: string | ArrayBuffer | Uint8Array | Buffer | null): void;

// Streaming (SSE, files, chunked):
writeHead(reqId, status: number, headersFlat: string[] | null): void;
write(reqId, chunk: string | ArrayBuffer | Uint8Array | Buffer): boolean; // false = backpressure, wait for onWritable
end(reqId, chunk?: string | ArrayBuffer | Uint8Array | Buffer): void;

isAborted(reqId): boolean;

// ---- static routes (capabilities.staticRoutes) ----
// A fixed response for one (method, path), answered entirely inside the engine:
// no JS call, no routing, no per-request header building. Header block + body are
// materialised ONCE here with the same code respond() uses, so the bytes on the
// wire are identical to respond(status, headersFlat, body). Only an exact method
// match short-circuits (a HEAD against a registered GET still reaches onRequest,
// so method policy stays in JS); re-registering a (method, path) replaces it.
// method is the engine's index: GET 0, POST 1, PUT 2, DELETE 3, PATCH 4, HEAD 5, OPTIONS 6.
setStaticRoute(serverId, method: number, path: string, status?: number,
               headersFlat?: string[] | null, body?: string | ArrayBuffer | Uint8Array | Buffer | null): void;
clearStaticRoutes(serverId): void;

// ---- prepared response templates (capabilities.responseTemplates) ----
// The part of a response that never varies - status + the app header block - is
// materialised ONCE with the same header builder respond() uses and replayed per
// request with a body; the bytes on the wire are identical to
// respond(status, headersFlat, body), the per-request header walk is gone. Ids
// are per server (dense from 1) and valid until releaseTemplates()/close().
// An INVALID id (0, released, another server's) answers 500 with an empty body
// and keeps the connection's keep-alive state - never a throw, never a hung request.
prepareResponse(serverId, status: number, headersFlat: string[] | null): number; // -> tplId; RangeError when the 4096/server store is full
releaseTemplates(serverId): void;
respondPrepared(reqId, tplId: number, body: string | ArrayBuffer | Uint8Array | Buffer | null): void;
respondPreparedEmpty(reqId, tplId: number): void;     // Content-Length: 0
writeHeadPrepared(reqId, tplId: number): void;        // then write()/end() as usual
endWith(reqId, chunk: string | ArrayBuffer | Uint8Array | Buffer): void; // exactly end(reqId, chunk)

// ---- diagnostics ----
// On success: { ok: true, version, abi, platform, arch, capabilities }
// On failure (no binary for this platform/ABI): { ok: false, abi, platform, arch, error }
// capabilities (absent = all false): feature flags for consumers to
// gate option passing on instead of version-sniffing:
//   { limits: boolean, tls: boolean, http2: boolean, wsDeflate: boolean,
//     responseLimits: boolean,  // responseTimeoutMs / responseBackpressureLimit / maxUriSize parsed
//     tlsPolicy: boolean,       // ssl.ciphers / ssl.ciphersuites / ssl.ecdhCurve parsed
//     tlsReload: boolean,       // updateSsl(serverId, ssl) available
//     staticRoutes: boolean,    // setStaticRoute() / clearStaticRoutes()
//     responseTemplates: boolean, // prepareResponse() & co.
//     callbackScope: boolean,   // JS callbacks run in a Node callback scope: nextTicks + microtasks drain on return
//     fastCalls: boolean }      // V8 fast API calls installed on the hot entry points (informational)
// fastApi: { compiled, installed, reason, compiledV8, runtimeV8 } - why fast calls are on/off
//   reason: 'ok' | 'not-compiled' | 'env-disabled' (MORO_ENGINE_FASTCALL=0) |
//           'sync-notify' (MORO_ENGINE_NOTIFY=sync) | 'v8-mismatch'
// fastCallStats: { <fn>: { fast, slow } } - only with MORO_ENGINE_FASTCALL_STATS=1 at load
// transport: 'uring' | 'uv' - the I/O transport (io_uring on Linux 6.1+ when the sandbox
//   permits it, libuv otherwise); transportReason says why it is not uring ('ok' when it is).
// transportMode: 'uv' | 'defer-taskrun' | 'coop-taskrun' - the io_uring ring mode (defer: task
//   work batched inside the engine's own enter, woken via a registered eventfd; coop: the 1.1.6
//   mode). The probe tries defer first; MORO_ENGINE_URING_TASKRUN=coop|defer pins one.
//   Behaviour and wire bytes are identical either way. MORO_ENGINE_TRANSPORT=uv forces libuv.
//     asyncNotify: boolean,     // onAborted/onWritable delivered on a later turn (never re-entrant)
//     workerThreads: boolean }  // servers left open at thread/env teardown are closed by a cleanup hook
// notify: 'deferred' | 'sync' - the onAborted/onWritable delivery mode in effect
probe(): { ok: boolean, version?: string, abi, platform, arch,
           capabilities?: { limits: boolean, tls: boolean, http2: boolean, wsDeflate: boolean,
                            responseLimits: boolean, tlsPolicy: boolean, tlsReload: boolean, staticRoutes: boolean,
                            responseTemplates: boolean, callbackScope: boolean, asyncNotify: boolean, workerThreads: boolean,
                            fastCalls: boolean },
           notify?: 'deferred' | 'sync',
           fastApi?: { compiled: boolean, installed: boolean, reason: string, compiledV8: string, runtimeV8: string },
           fastCallStats?: { [fn: string]: { fast: number, slow: number } },
           transport?: 'uv' | 'uring', transportReason?: string, transportMode?: string,
           error?: string };
version: string;
```

## Engine-side guarantees

- **Keep-alive** and connection lifecycle are engine concerns; the adapter
  never sees them. `Connection: close` / HTTP/1.0 handled natively.
- **Content-Length** is added automatically by `respond()`/`end()`;
  streaming responses without an explicit `content-length` header use
  chunked transfer encoding automatically. The engine owns response framing:
  a `respond()` body always ships with its ACTUAL length (an app-supplied
  mismatching Content-Length is ignored, except on HEAD/1xx/204/304 where a
  would-be entity length is legitimate); streaming `write()`s beyond a
  declared Content-Length are clamped; `end()`ing short of it forces
  `Connection: close` so the client sees truncation instead of consuming the
  next response's bytes.
- **Response-splitting defense**: header entries whose name is not an
  RFC 9110 token, or whose value contains CR/LF/control bytes, are dropped
  before reaching the wire (the same class Node's http core rejects).
- `write()` before `writeHead()` synthesizes an implicit 200 chunked head
  (Node behavior) rather than emitting raw bytes with no status line.
- Out-of-range status codes are clamped to 500 (the status line grammar
  allows exactly three digits).
- **Date header** injected automatically (cached, refreshed 1/sec).
- HEAD requests: engine suppresses the response body bytes automatically
  (status/headers/content-length still sent as computed).
- **Request smuggling defenses** (hard 400, connection closed): both
  Content-Length and Transfer-Encoding present; conflicting duplicate
  Content-Length; invalid chunk framing. Limits (all configurable via
  serve() options): 64KB request head, 100 headers max, maxBodySize (413).
- `Expect: 100-continue` answered automatically.
- One request in flight per connection: the next pipelined request is not
  parsed until the current response ends (ordering is structural).

## Threading

Everything runs on the loop of the thread that called `serve()` (uv handles
registered on `node::GetCurrentEventLoop`) — the main loop, or a
`worker_threads` loop. Callbacks are invoked from I/O events on that loop — a
single-threaded on-loop model per thread. No locks, no cross-thread
marshaling. Registries (serverIds, reqIds, wsIds) are per thread; an id never
crosses threads.

**Worker threads** (`capabilities.workerThreads`): each thread may run its own
engine (with `reusePort` several threads share one port). A server still open
when its thread's environment is torn down — `worker.terminate()`,
`process.exit()` inside the worker, an uncaught error — is closed by an
environment cleanup hook the engine registers per `serve()`, and its uv
handles are reaped before Node closes the loop. Without that hook Node would
abort the whole process (`uv_loop_close() while having open handles`). No
JS callback runs during that teardown (Node forbids JS execution there).

**Delivery timing.** `onAborted` and `onWritable` are delivered on a later
loop turn, never re-entrantly from inside a binding call: a `respond()` that
fails its write (or trips `responseBackpressureLimit`) returns first, and the
abort arrives from a `uv_async` callback afterwards. `close()` is the one
exception — it delivers every pending `onAborted` synchronously before
returning, so a caller may drop its per-request routing state right after.
`MORO_ENGINE_NOTIFY=sync` (diagnostics only) restores the pre-1.1.6 re-entrant
delivery; `probe().notify` reports the mode.

One case is re-entrant rather than driven by a fresh I/O event:
`upgradeToWebSocket()` calls `onWsOpen` (and, for frames pipelined in the
handshake segment, `onWsMessage`) synchronously **from within the
`upgradeToWebSocket()` call itself**, before it returns. The adapter therefore
sees the socket opened — and possibly its first message — while still inside its
`onRequest` handler. Still single-threaded and lock-free; just delivered on the
same call stack instead of the next loop turn (see the WebSocket section).

## WebSocket (M4 surface, see src/websocket.h)

```ts
upgradeToWebSocket(reqId): number | -1;   // -1 if not a valid upgrade request; else wsId
wsSend(wsId, data: string | ArrayBuffer | Uint8Array | Buffer, isBinary: boolean): boolean;
wsClose(wsId, code?: number, reason?: string): void;
// serve() callbacks gain: onWsOpen(wsId, path), onWsMessage(wsId, data, isBinary),
// onWsClose(wsId, code)
```

**Delivery guarantee (re-entrant open).** `upgradeToWebSocket()` invokes
`onWsOpen` **synchronously and re-entrantly**: the callback has already run by
the time `upgradeToWebSocket()` returns the `wsId`. Register any per-socket
state inside `onWsOpen` (or immediately after the call returns) — never on a
later turn — because inbound frames can arrive at once. In particular, frames
the client pipelined in the **same TCP segment** as the handshake are handed to
`onWsMessage` right after `onWsOpen`, also synchronously within that same
`upgradeToWebSocket()` call, so a client that sends its first frame together
with the Upgrade is never dropped.

permessage-deflate (RFC 7692) is opt-in via options.wsDeflate (off by default,
which declines the extension). Feature-detect support with
`probe().capabilities.wsDeflate` rather than by version. When enabled, the
engine inflates inbound compressed messages (with a zip-bomb output cap → close
1009) and compresses outbound sends over the threshold. Inbound text is
UTF-8-validated after inflate (→ close 1007 on failure).

## Adding a native export (maintainers)

A native function is declared in four places and `npm run check:exports`
fails until all four agree: `Initialize` in `src/binding.cpp`, the
`NATIVE_API` allow-list in `packages/engine/index.js` (a name missing there
reads as `undefined` without ever loading the addon), the live-binding
re-exports in `packages/engine/index.mjs`, and `packages/engine/index.d.ts`
(both the `export function` and the `declare const engine` block). A
capability flag is declared in `Probe()` (`setCap`) and in
`EngineCapabilities`; a `serve()` option in the option parser and in
`ServeOptions`. Document the behaviour here in the same change.

## Fast API calls (capabilities.fastCalls)

The hot entry points — `respondPrepared`, `respondPreparedEmpty`,
`writeHeadPrepared`, `write`, `end`, `endWith`, `isAborted` — are registered
with a V8 fast-call target (`src/fast_api.h`): an optimised JS caller
(Maglev/TurboFan) invokes the engine's C++ directly, with no
`FunctionCallbackInfo`, no HandleScope and no argument boxing, whenever the
arguments already have the declared machine types (Smi ids, a sequential
one-byte string body). Anything else — a two-byte or cons string, a Buffer,
an unoptimised caller — takes the regular callback, which does exactly the
same work; the bytes on the wire never depend on which path ran. A fast
target can never call back into JS, which is why delivery of
`onAborted`/`onWritable` is deferred (above) and why fast calls are refused
under `MORO_ENGINE_NOTIFY=sync`. The fast-call ABI is per V8 version, so the
targets are installed only when the running V8's major.minor matches the one
the binary was compiled against (`probe().fastApi`); the plain callbacks are
always there. `MORO_ENGINE_FASTCALL=0` disables installation (diagnostics);
`MORO_ENGINE_FASTCALL_STATS=1` exposes per-function fast/slow hit counters in
`probe().fastCallStats`.

## Batched pipelined dispatch (capabilities.batchDispatch)

Register `onRequestBatch(count)` alongside `onRequest` and the engine parses
complete pipelined requests ahead of the active one (up to 16 per
connection) and delivers them in ONE call instead of one `onRequest` per
request. The batch is described in the buffers `getBatchBuffers(serverId)`
returns once per server:

```js
const { descriptors, control, paths } = engine.getBatchBuffers(serverId);
// descriptors: Uint32Array, three per slot: reqId, methodIdx, pathIdx
// control:     Uint32Array(1) - the slot the engine has activated
// paths:       string[] - interned paths, indexed by pathIdx
onRequestBatch(count) {
  let i = 0;
  for (;;) {
    const reqId = descriptors[3 * i], methodIdx = descriptors[3 * i + 1], pi = descriptors[3 * i + 2];
    const path = pi === 0xffffffff ? engine.getPath(reqId) : paths[pi];
    handle(reqId, methodIdx, path);          // same code as onRequest
    const next = control[0];
    if (next === i) return i + 1;            // this handler is async: stop here
    if (next >= count) return count;         // every slot answered
    i = next;                                // continue at the slot the engine activated
  }
}
```

Only the active slot's reqId is live; the engine activates the next slot
(and advances `control`) when the previous response completes synchronously,
so responses stay in request order. A handler that goes async ends the
batch: the remaining slots are delivered later, in a new batch, when that
response completes - none are dropped or duplicated. A static route inside a
batch is answered by the engine (the control cell skips it). Requests that
are not pipelined arrive as batches of one. `onRequest` alone (no
`onRequestBatch`) keeps the one-call-per-request delivery. Byte parity with
sequential dispatch is proven by `test/batch-dispatch.test.mjs`.
`MORO_ENGINE_BATCH=0` turns the capability off (diagnostics).

## I/O transports

Everything above runs on one of two transports, chosen once per process.
libuv is the default everywhere; io_uring is opt-in in 1.1.6
(`MORO_ENGINE_TRANSPORT=uring`), for the reasons measured in
`docs/DESIGN.md` ("io_uring measurements"):

- **libuv streams** (`transport: 'uv'`): everywhere. macOS, Windows, Linux
  kernels before 6.1, and any Linux sandbox that blocks `io_uring_setup`
  (Docker's default seccomp profile since 24/25, gVisor,
  `kernel.io_uring_disabled`).
- **io_uring** (`transport: 'uring'`): Linux 6.1+, when `MORO_ENGINE_TRANSPORT=uring`
  is set and a feature probe and a behavioural self-test pass at startup
  (`src/uring.h`); any refusal falls back to libuv with the reason. One ring per loop
  thread, polled through a libuv poll handle so the engine stays on Node's
  loop; multishot accept, multishot receive into kernel-provided buffers,
  one outstanding send per connection, cancel-then-close on teardown. One
  `io_uring_enter` per loop iteration replaces the read/write/epoll trio per
  request and the accept/epoll_ctl/close set per connection.

Behaviour, timeouts, backpressure and the bytes on the wire are identical:
the transport is a syscall layer, selected silently, never required.
`MORO_ENGINE_TRANSPORT=uv` forces libuv (A/B runs, bisecting); `probe()`
reports which one is active and why.
