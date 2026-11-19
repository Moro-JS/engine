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
  idleTimeoutMs?: number;      // default 120000; 0 disables (resets on any byte). Not applied
                               // while a response is still being written to the peer: that is
                               // responseTimeoutMs' business, unless responseTimeoutMs is 0
                               // (capabilities.idleSparesDrainingResponse)
  requestTimeoutMs?: number;   // default 300000; 0 disables. Budget for receiving ONE
                               // complete request from its first byte - does NOT reset
                               // on activity (slow-drip slowloris defense). Expiry: 408 + close.
  responseTimeoutMs?: number;  // default 300000; 0 disables. Budget for DELIVERING queued
                               // outbound bytes: resets on drain progress (the write queue
                               // shrank since the last sweep, or a write completed), so only a
                               // drain making NO progress for the whole budget is closed -
                               // steady slow readers of large responses are never shed
                               // (slow-read / zero-window DoS defense; capabilities.responseLimits).
                               // On HTTP/2 it also covers response bytes held back by the peer's
                               // flow-control windows: none of them sent for the budget -> close.
  maxConnections?: number;     // default 0 = unlimited
  maxPendingBytes?: number;    // default maxHeadSize + maxBodySize. Cap on input buffered
                               // while it cannot be dispatched (a handler is running, or the
                               // responses already given are waiting on the peer), counted
                               // across responses; over it the connection is closed
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
  wsBackpressureLimit?: number;// default 1MB; a WS consumer that is not draining is shed with 1013
                               // (see "WebSocket": one message of any size is never shed for
                               // its size). 0 = unlimited
  writeHighWaterMark?: number; // default 262144; write()/wsSend() report backpressure above
                               // it, and no further pipelined request is taken from a
                               // connection whose unsent response bytes have reached it
  backlog?: number;            // default 512; TCP listen backlog

  // In-process TLS termination (probe().capabilities.tls). Both
  // MoroJS ssl shapes are accepted; inline PEM wins over a file path for the
  // same slot. Config errors THROW from serve() (never a silent plaintext
  // boot). HTTPS and WSS both work; ALPN negotiates http/1.1.
  ssl?: {
    key_file_name?, cert_file_name?, ca_file_name?: string;     // file shape
    key?, cert?, ca?: string | Buffer | ArrayBuffer;            // inline PEM
    crl?: string | Buffer | ArrayBuffer; // PEM revocation lists for client certificates
                                       // (capabilities.tlsCrl); with any given, the CRL of
                                       // every CA in a client's chain must be here
    passphrase?: string;               // for an encrypted key
    minVersion?: 'TLSv1.2'|'TLSv1.3';  // default TLSv1.2 (TLSv1.3 under node --tls-min-v1.3)
    maxVersion?: 'TLSv1.2'|'TLSv1.3';  // default: the library's newest (TLSv1.2 under node --tls-max-v1.2)
    requestCert?: boolean;             // mutual TLS
    rejectUnauthorized?: boolean;      // default true
    // A policy option of the wrong type (requestCert: 1, minVersion: 1.3,
    // ciphers: [...]) THROWS from serve(): it is not read as unset.
    // Options of Node's tls that are not listed here are not read.
    // Explicit cipher/group policy (capabilities.tlsPolicy) for compliance
    // baselines. Same semantics as Node's tls.createSecureContext; invalid
    // values THROW from serve(). Unset = the list node was started with
    // (--tls-cipher-list), else the TLS library's own set, AES-128-GCM
    // ahead of AES-256-GCM, ChaCha20 for a client that lists it first. On the
    // bundled BoringSSL (probe().tls.library) `ciphersuites` can name the three
    // suites it has and `ciphers` has no DHE/CCM; see docs/TLS.md.
    ciphers?: string;                  // TLS <= 1.2 cipher list
    ciphersuites?: string;             // TLS 1.3 suites (colon-separated)
    ecdhCurve?: string;                // key-share groups, e.g. 'X25519:P-256'; 'auto' = default
  };

  // HTTP/2 (RFC 9113; feature-detect via probe().capabilities.http2). Off by
  // default. With `ssl`, negotiated by ALPN ("h2" offered ahead of
  // "http/1.1"); without it, spoken to a client that opens with the HTTP/2
  // connection preface (prior knowledge). HTTP/1.1 is served beside it on
  // the same port. A request on a stream reaches onRequest exactly as an
  // HTTP/1 request does and is answered with the same calls. Not offered:
  // WebSocket over HTTP/2, server push, CONNECT.
  http2?: boolean | {
    maxConcurrentStreams?: number;   // default 256
    initialWindowSize?: number;      // per-stream receive window, default 1 MiB
    maxFrameSize?: number;           // default 16384
    maxHeaderListSize?: number;      // default: maxHeadSize
    headerTableSize?: number;        // default 4096
  };

  // WebSocket permessage-deflate (RFC 7692; feature-detect via
  // probe().capabilities.wsDeflate). Off by default (preserves the
  // compression-oracle-free posture). boolean to enable with defaults, or an
  // options object.
  wsDeflate?: boolean | {
    serverNoContextTakeover?, clientNoContextTakeover?: boolean;
    serverMaxWindowBits?, clientMaxWindowBits?: number;   // 9..15 (an 8-bit window is never negotiated)
    threshold?: number;             // min message bytes to compress a send (default 1024)
    maxDecompressedSize?: number;   // inflate cap / zip-bomb defense (default wsMaxMessageSize)
    sharedCompressor?: boolean;     // one compressor for the server, reset after every message,
                                    // instead of one (about 260 KB) per connection; default false
  };
}): number;   // -> serverId

listen(serverId: number, host: string, port: number): number; // -> actual port; throws Error w/ .code (e.g. 'EADDRINUSE') on bind error.
                                       // One listener per server: a second listen(), or one after
                                       // stopListening()/close(), throws with code 'EINVAL'
stopListening(serverId: number): void; // stop accepting, keep serving existing connections
                                       // (graceful-shutdown drain phase; then close())
updateSsl(serverId: number, ssl): void; // certificate rotation (capabilities.tlsReload): validate a
                                       // NEW context from the full ssl shape above and use it for
                                       // every handshake from now on; established connections keep
                                       // theirs. Throws (current context untouched) on bad material
                                       // or a server not started with ssl. ticketKeys carry over
                                       // when omitted; sessions issued before the update resume
                                       // after it only if the policy (minVersion, ciphers,
                                       // client-certificate settings and CAs) is unchanged.
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
getBodyType(reqId): string | null;        // Content-Type; '' with a body and no header,
                                          // null with no body
getBodyText(reqId): string | null;        // an all-ASCII body as a string (its exact bytes,
                                          // on the JS heap); null otherwise - use getBody
getBodyLent(reqId): ArrayBuffer | null;   // no copy; detached and freed when the response
                                          // completes; getBody (or transfer) for bytes to keep.
                                          // Nothing may still be working on the bytes by then:
                                          // an fs or socket write, a zlib or crypto job that was
                                          // handed them and has not finished keeps a pointer to
                                          // the memory, not the buffer, and goes on to read
                                          // memory that is free or holds another request's body.
                                          // Let it finish before the response is completed
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

// ---- parameter routes (capabilities.paramRoutes) ----
// A route with ONE variable path segment whose body is that segment, answered inside the
// engine like a static route: `/user/:id` is prefix "/user/" and suffix ""; `/files/:name.json`
// is prefix "/files/", suffix ".json". The segment must be non-empty and contain no '/'
// (`/user/` and `/user/1/2` still reach onRequest) and goes out undecoded.
// Header block materialised once; bytes identical to
// respond(status, headersFlat, segment). Method policy stays in JS, as for static routes.
setParamRoute(serverId, method: number, prefix: string, suffix: string, status?: number,
              headersFlat?: string[] | null): void;
clearParamRoutes(serverId): void;
// Both kinds go through the engine's fast lane (1.1.10). A request that arrives whole in one
// read on a connection with nothing queued in either direction is parsed in place - no copy,
// every header validated and the framing ones interpreted, none stored - routed, and answered
// from the route's prepared response head (rebuilt when the Date second changes). Every
// request is parsed and routed; a route-table change (setStaticRoute/clearStaticRoutes/
// setParamRoute/clearParamRoutes) takes effect on the very next request. A request whose
// head is still arriving when the tables change is routed by the tables as they are when it
// completes; if it matched an engine route that is gone by then, it is answered 500 and the
// connection closed (its headers were not kept, so it cannot be handed to onRequest).

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
//     tlsCrl: boolean,          // ssl.crl and ssl.maxVersion honoured
//     staticRoutes: boolean,    // setStaticRoute() / clearStaticRoutes()
//     responseTemplates: boolean, // prepareResponse() & co.
//     callbackScope: boolean,   // JS callbacks run in a Node callback scope: nextTicks + microtasks drain on return
//     batchDispatch: boolean,   // onRequestBatch / getBatchBuffers() / getPath()
//     wsAutoUpgrade: boolean,   // setWsAutoUpgrade() and the wsGet*() handshake accessors
//     wsAutoUpgradeBatch: boolean, // setWsAutoUpgrade() may be combined with onRequestBatch (see "WebSocket")
//     idleSparesDrainingResponse: boolean, // idleTimeoutMs never closes a connection whose response is
//                               // still being written to a peer that reads it (responseTimeoutMs governs
//                               // that). Without the flag (before 1.2.0) a response given before the
//                               // handler returned counted as idle once framed: set idleTimeoutMs only
//                               // above the longest download, or leave it off
//     fastCalls: boolean }      // V8 fast API calls installed on the hot entry points (informational)
// fastApi: { compiled, installed, reason, compiledV8, runtimeV8 } - why fast calls are on/off
//   reason: 'ok' | 'not-compiled' | 'env-disabled' (MORO_ENGINE_FASTCALL=0) |
//           'sync-notify' (MORO_ENGINE_NOTIFY=sync) | 'v8-mismatch'
// fastCallStats: { <fn>: { fast, slow } } - only with MORO_ENGINE_FASTCALL_STATS=1 at load
// transport: 'epoll' | 'uring' | 'uv' - the I/O transport: epoll on Linux by default (the
//   engine's own readiness loop), io_uring when MORO_ENGINE_TRANSPORT=uring and the kernel and
//   sandbox permit it, libuv elsewhere or when MORO_ENGINE_TRANSPORT=uv; transportReason says
//   why ('ok' for io_uring).
// transportMode: 'uv' | 'epoll' | 'defer-taskrun' | 'coop-taskrun' - the transport, or for
//   io_uring its ring mode (defer: task work batched inside the engine's own enter, woken via a
//   registered eventfd; coop: the 1.1.6 mode). The probe tries defer first;
//   MORO_ENGINE_URING_TASKRUN=coop|defer pins one. Behaviour and wire bytes are identical.
//     asyncNotify: boolean,     // onAborted/onWritable delivered on a later turn (never re-entrant)
//     workerThreads: boolean }  // servers left open at thread/env teardown are closed by a cleanup hook
// notify: 'deferred' | 'sync' - the onAborted/onWritable delivery mode in effect
probe(): { ok: boolean, version?: string, abi, platform, arch,
           capabilities?: { limits: boolean, tls: boolean, http2: boolean, wsDeflate: boolean,
                            responseLimits: boolean, tlsPolicy: boolean, tlsReload: boolean, staticRoutes: boolean,
                            responseTemplates: boolean, callbackScope: boolean, asyncNotify: boolean, workerThreads: boolean,
                            batchDispatch: boolean, wsAutoUpgrade: boolean, wsAutoUpgradeBatch: boolean,
                            idleSparesDrainingResponse: boolean, fastCalls: boolean },
           notify?: 'deferred' | 'sync',
           fastApi?: { compiled: boolean, installed: boolean, reason: string, compiledV8: string, runtimeV8: string },
           fastCallStats?: { [fn: string]: { fast: number, slow: number } },
           transport?: 'uv' | 'uring' | 'epoll', transportReason?: string, transportMode?: string,
           tls?: { library: 'boringssl' | 'openssl', version: string, date?: string,
                   reason: string, fallbackReason?: string },
           binary?: { path: string, version?: string },
           error?: string };
// binary: the .node file that was loaded and the version of the platform
//   package it came from, which is always `version` above: a platform package
//   of another release, or one found outside the node_modules tree this
//   package is installed in, is not loaded (probe().error says so).
version: string;

// Which TLS library (1.1.20). Two binaries ship per platform and ABI: one
// carries BoringSSL (the default), one links the running node's OpenSSL.
// selectTls() chooses before the binding is loaded on this thread - the first
// probe() or serve(); for the other library after that it throws
// (code MORO_ENGINE_TLS_LOADED). 'auto' is BoringSSL unless node's OpenSSL is
// configured (FIPS, --openssl-config and friends, OPENSSL_CONF). The
// environment variable MORO_ENGINE_TLS takes the same values. probe().tls
// reports the library loaded, its version (BoringSSL: the pinned upstream tag
// and its date) and the reason. docs/TLS.md has the whole story.
// Passing the ssl options about to be served lets the load check that
// BoringSSL accepts them and settle on OpenSSL if not (reason 'fallback').
selectTls(library: 'boringssl' | 'openssl' | 'auto', ssl?: ServeOptions['ssl']): 'boringssl' | 'openssl' | 'auto';
```

## Engine-side guarantees

- **Keep-alive** and connection lifecycle are engine concerns; the adapter
  never sees them. `Connection: close` / HTTP/1.0 handled natively.
- **Entering a callback**: `onRequest`, `onRequestBatch`, `onAborted` and
  `onWritable` are called with `this` the global object, inside a Node
  callback scope on one resource object per server
  (`capabilities.callbackScope`). What one of them throws is caught and
  logged to stderr (`[morojs-engine] handler threw: …`, or
  `[morojs-engine] onRequestBatch threw: …`); the request stays open and can
  still be answered. The loader enters them through a small function of its
  own, so a stack taken inside a handler shows one loader frame
  (`dispatchRequest`, `dispatchBatch` or `dispatchNotice`) below the
  handler's own. `MORO_ENGINE_DISPATCH=scope` makes the engine call them
  directly instead (diagnostics).
- **Content-Length** is added automatically by `respond()`/`end()`;
  streaming responses without an explicit `content-length` header use
  chunked transfer encoding automatically. The engine owns response framing:
  a `respond()` body always ships with its ACTUAL length (an app-supplied
  mismatching Content-Length is ignored, except on a HEAD response and a 304,
  where a would-be entity length is legitimate); streaming `write()`s beyond
  a declared Content-Length are clamped; `end()`ing short of it forces
  `Connection: close` so the client sees truncation instead of consuming the
  next response's bytes.
- **Statuses without content** (RFC 9110 §6.4.1, §8.6, §15.3.6): a 1xx, 204
  or 304 response never carries a body, whatever the handler passes; a 1xx or
  204 never carries `Content-Length` either, and a 304 carries the handler's
  if it gave one. A 205 is sent with `Content-Length: 0` and no body, whatever
  body or length the handler gave. The same on HTTP/2.
- **HTTP/1.0 clients**: a streamed response without a declared length is not
  chunked for them (they cannot read it): the body is sent as it is, with
  `Connection: close`, and the end of the connection ends it. With a declared
  length, and with `respond()`, an HTTP/1.0 keep-alive connection persists as
  before. An HTTP/1.0 request is never sent `100 Continue`, and one that
  carries `Transfer-Encoding` is answered and the connection then closed
  (RFC 9112 §6.1).
- **Reason phrases**: every status in the IANA registry is sent with its
  registered phrase (`429 Too Many Requests`, `502 Bad Gateway`, ...), and
  418 with `I'm a Teapot`; any other code is sent with `OK`. The engine has
  no API to set one.
- **Response-splitting defense**: header entries whose name is not an
  RFC 9110 token, or whose value contains CR/LF/control bytes, are dropped
  before reaching the wire (the same class Node's http core rejects).
- `write()` before `writeHead()` synthesizes an implicit 200 chunked head
  (Node behavior) rather than emitting raw bytes with no status line.
- `respond()` (or `respondPrepared()`) after `writeHead()` or `write()`, on
  HTTP/1: the head is already on the wire and a response has only one, so the
  status, headers and body given are not sent. The response ends where it is
  and the connection is closed behind it, which the client sees as a response
  cut short (a chunked body without its last chunk, a declared length not
  reached). The request is over, as after any `respond()`. A streamed
  response is finished with `end()`. On HTTP/2 the status and headers given
  are not sent either; the body given is sent as the rest of the stream and
  ends it, as `end(body)` would.
- Out-of-range status codes are clamped to 500 (the status line grammar
  allows exactly three digits).
- **Date header** injected automatically (cached, refreshed 1/sec).
- HEAD requests: engine suppresses the response body bytes automatically
  (status/headers/content-length still sent as computed).
- **Request smuggling defenses** (hard 400, connection closed): both
  Content-Length and Transfer-Encoding present; conflicting duplicate
  Content-Length; invalid chunk framing. Limits (all configurable via
  serve() options): 64KB request head, 100 headers max, maxBodySize (413).
- **Chunked request bodies** (RFC 9112 §7.1): the chunk size is hex digits
  from the first byte of its line; every line of the framing - size lines,
  the last chunk, trailer lines, the final blank line - ends in CRLF (a bare
  LF is accepted as a line end in the request line and the header fields
  only); a chunk-size line, extensions included, is at most 16 KiB up to its
  LF, whether it arrives in one read or several; a chunk extension is not
  interpreted and may hold no control byte; trailer lines must be field lines
  and are then dropped, never merged into the headers. Anything else is a
  400. The trailer section is bounded by `maxHeadSize` (431).
- **Host** (RFC 9112 §3.2): exactly one on an HTTP/1.1 request, at most one
  on HTTP/1.0, and its value must be `uri-host [ ":" port ]` - a name or
  IPv4 address, or an IPv6 address in brackets, optionally followed by a
  colon and digits - else 400. Underscores, a trailing dot, an empty port
  and an empty value are accepted; whitespace, `/`, `?`, `#`, `@`, `\`,
  non-ASCII bytes and an unbracketed IPv6 address are not.
  On HTTP/2 the `Host` a handler reads is the request's `:authority`, or its
  `host` field when it sent no `:authority`; each is checked the same way,
  except that an empty one makes the request malformed
  (`RST_STREAM(PROTOCOL_ERROR)`), and so does an `http` or `https` request
  with neither (RFC 9110 §7.2), `OPTIONS *` included; a request with another
  scheme and neither is delivered without `Host`. `cookie` fields sent
  separately (RFC 9113 §8.2.3) are delivered as one, joined with `; `.
- A rejected request (400/408/413/414/431/505) ends the connection: one error
  response with `Connection: close`, and nothing the client sends afterwards
  is read, not even while that response is still waiting behind earlier ones.
  Which status a request gets does not depend on how its bytes were split
  across reads: 431 for the first line that takes the head over
  `maxHeadSize` (or `maxHeaders`), whatever that line contains; 400 (414,
  505) for a malformed line before that point; 413 for a chunk that would
  take the body over `maxBodySize`, at its size line, before its data is
  received.
- The last response of a connection (`Connection: close`, HTTP/1.0, a
  streamed response to an HTTP/1.0 client) ends its input the same way:
  a request that arrives while that response is still being written is
  dropped, as one that arrives after it always was.
- `Expect: 100-continue` answered automatically (HTTP/1.1 requests only).
- One request in flight per connection: behind a handler that answers
  later, the next pipelined request is not dispatched until that response
  has been written out. Handlers that answer before they return are run back
  to back and their responses written together, until the bytes the peer has
  not taken reach `writeHighWaterMark`: then nothing more is parsed or
  dispatched on that connection until they drain. What the client sends
  meanwhile is buffered up to `maxPendingBytes`.

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
setWsAutoUpgrade(serverId, on: boolean): void;   // the engine answers handshakes itself
wsGetHeaders(wsId): string[] | undefined;        // the handshake's headers, query and peer,
wsGetQuery(wsId): string | undefined;            // for the socket's lifetime
wsGetRemoteAddress(wsId): string | undefined;
// serve() callbacks gain: onWsOpen(wsId, path), onWsMessage(wsId, data, isBinary),
// onWsClose(wsId, code)
```

**The handshake (RFC 6455 §4.2.1).** A request is upgraded when it is a `GET`
over HTTP/1.1 with `Upgrade: websocket`, an `Upgrade` token in `Connection`,
exactly one `Sec-WebSocket-Key` (the base64 of 16 bytes) and exactly one
`Sec-WebSocket-Version: 13`. Anything else is an ordinary request:
`upgradeToWebSocket()` returns `-1`, the request stays open, and the caller
answers it. That covers a `POST` or any other method carrying the upgrade
headers, an HTTP/1.0 request, and a request that repeats the key or the
version line (§11.3.1, §11.3.5). No subprotocol is selected and `Origin` is
not interpreted; both are the application's to check before it upgrades.

**Engine-side upgrades (`setWsAutoUpgrade`, `capabilities.wsAutoUpgrade`).**
With it on, a valid handshake never reaches `onRequest`: the engine sends the
101 and calls `onWsOpen`, and the handshake stays readable through
`wsGetHeaders()`, `wsGetQuery()` and `wsGetRemoteAddress()`. A handshake that
is valid in every respect but its version is answered by the engine as well,
as §4.2.2 and §4.4 require: `426 Upgrade Required` with `Upgrade: websocket`
and `Sec-WebSocket-Version: 13`, on a connection that stays open for the
client's next attempt. Every other request is surfaced to `onRequest` (or
`onRequestBatch`) as usual. With `onRequestBatch` registered, turn it on only
when `probe().capabilities.wsAutoUpgradeBatch` is true. Engines 1.1.15 to
1.1.21 report `wsAutoUpgrade` and `batchDispatch` without that flag: on
them a process abort could occur with pipelined WebSocket handshakes when
batch dispatch and engine-side upgrades were both enabled (fixed in 1.2.0).

**`wsSend()`** returns `false` when the frame did not go out (the socket is
gone or closing, or `data` is not a string or bytes) and when it went out
into a write queue that is over `writeHighWaterMark`. A frame for a peer that
has reset the connection is dropped, not queued; `onWsClose` reports that
socket (1006) on the next loop turn, and a send made before then may still
return `true`.

**Send backpressure (`wsBackpressureLimit`, default 1 MiB, `0` = off).** A
consumer that is not keeping up is shed with close code 1013 instead of
being buffered without bound: a `wsSend()` that finds bytes of an earlier
send still waiting for the socket, and leaves more than the limit queued,
closes it (`wsSend()` returns `false`; the Close goes out, behind what is
already queued, on the next loop turn, and `onWsClose` reports 1013). Until
then a further send to that socket returns `false` and is not queued. A
single message is never shed for its size: sent to a socket with nothing
waiting it is queued whole, however large, and the socket stays open; if the
peer has not drained it by the next send, that send sheds the socket. A peer
that stops reading with one message in flight is closed when
`responseTimeoutMs` (default 300 s) passes without any progress.

The memory this leaves a stalled peer able to hold, per socket: up to
`wsBackpressureLimit` accumulated across sends, or one message of whatever
size the application sends, whichever is larger, plus the send that sheds
it. The engine sets no maximum on the size of one outgoing message - that
bound is the application's: one that sends multi-megabyte messages to
untrusted peers should cap them, or lower `responseTimeoutMs`. Bytes the
kernel's socket buffers have already taken are not counted.

**`wsClose(wsId, code = 1000, reason = '')`** sends a Close frame and ends the
connection. The frame is legal whatever it is given (§5.5, §7.4):

| `code` | on the wire |
| --- | --- |
| 1000-1003, 1007-1014, 3000-4999 | the code, as given |
| 1005 ("no status code was present") | a Close frame with no status and no reason |
| anything else: 1004, 1006, 1015, below 1000, 1016-2999, 5000 and above | 1011 |

`reason` is cut to 123 bytes of UTF-8 (a control frame carries 125, two of
them the code), at a character boundary. `onWsClose` reports `code` as it was
passed.

**`onWsClose(wsId, code)`** fires exactly once per socket: with the peer's
Close code (1005 when its Close had none), 1006 when the peer went away
without a Close, the code of a protocol failure, or the code `wsClose()` was
called with. Inside the callback the socket is already closing - `wsSend()`
returns `false`, `wsClose()` does nothing - and the three `wsGet*()`
accessors still answer; they return `undefined` afterwards.

**Closing (§7.1.1).** Once its Close frame is out - the echo of the peer's,
`wsClose()`, or the Close of a protocol failure (1002; 1007 for invalid
UTF-8; 1009 for a message over `wsMaxMessageSize`) - the server half-closes
the connection and keeps reading, discarding what arrives, until the peer
has closed its side; a peer that never does is cut after two seconds (the
same lingering close an HTTP `Connection: close` response ends with). A peer
that was still sending therefore receives the Close and its status code
instead of a connection reset. Nothing that arrives after the Close is
delivered. A TLS connection is closed after its `close_notify`, without the
linger.

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
1009; bytes that are not a deflate stream → close 1007) and compresses
outbound sends over the threshold. Inbound text is UTF-8-validated after
inflate (→ close 1007 on failure). Once a message has failed either check,
the frames behind it in the same read are not delivered.

Compression makes the size of what is sent depend on its content. Leave it
off for sockets on which a secret and bytes that someone else chooses are
sent together: in one message, or, with context takeover (the default), in
any two messages of one connection, since each message is compressed against
the ones before it. `serverNoContextTakeover` or `sharedCompressor` confine
that to a single message. Each connection that negotiates the extension
holds a compressor of about 260 KB from its handshake on (measured: 207 KiB
resident against 7 KiB for a socket without it); with `sharedCompressor`
there is one for the whole server.

An offer is declined - the 101 carries no `Sec-WebSocket-Extensions` and the
connection works uncompressed - when RFC 7692 §7 says so: an unknown
parameter, the same parameter twice, a value on `server_no_context_takeover`
or `client_no_context_takeover`, or window bits outside 9..15 or written with
a leading zero. The next offer in the list is then considered. Several
`Sec-WebSocket-Extensions` lines are read as one list (RFC 6455 §9.1).

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

The buffers are the application's to keep. One whose `ArrayBuffer` it
transfers away (`.transfer()`, or a transfer list of `structuredClone` or
`postMessage`) goes with the transfer; the engine no longer writes into it
once `getBatchBuffers()` is called again, which returns views of new
storage that later batches are described in.

Only the active slot's reqId is live; the engine activates the next slot
(and advances `control`) when the previous response completes synchronously,
so responses stay in request order. A handler that goes async ends the
batch: the remaining slots are delivered later, in a new batch, when that
response completes - none are dropped or duplicated. A static route inside a
batch is answered by the engine (the control cell skips it). Four things end a
batch early with `control[0] >= count`, which the loop above already returns
on: the next request is a WebSocket handshake the engine answers itself
(`setWsAutoUpgrade`; it is upgraded once the call has returned, and the
handler never sees it); the connection was closed from inside the loop
(a handler closed the server), after which none of its remaining requests
reaches a handler; and the responses already given in the batch are waiting
on a peer that is not reading them (`writeHighWaterMark` of unsent bytes), in
which case the remaining slots are delivered in a later batch, once the peer
has read; and, only once the 32-bit id counter has come round on the thread,
a request that waited so long behind another that its id has since been given
to a different request - it is delivered in a batch of its own, under a new
id (which is why a slot's id is read from its descriptor when its turn comes,
never earlier). Requests that
are not pipelined arrive as batches of one. `onRequest` alone (no
`onRequestBatch`) keeps the one-call-per-request delivery. Byte parity with
sequential dispatch is proven by `test/batch-dispatch.test.mjs`.
`MORO_ENGINE_BATCH=0` turns the capability off (diagnostics).

## I/O transports

Everything above runs on one of three transports, chosen once per process.
On Linux the epoll transport is the default since 1.1.10; libuv streams
are the default on macOS and Windows and available on request; io_uring is
opt-in (`MORO_ENGINE_TRANSPORT=uring`), for the reasons measured in
`docs/DESIGN.md` ("io_uring measurements"):

- **epoll** (`transport: 'epoll'`): Linux, the default. Every listening and
  accepted socket is a libuv poll handle on the loop's epoll, so the engine
  stays on Node's loop and one `epoll_wait` per loop turn delivers every
  event; accept, recv and send are made directly
  on plain non-blocking sockets, with writable interest armed only while a
  write is backpressured. It removes libuv's per-connection stream machinery
  (alloc/read callbacks, write requests, handle close) from the request
  path: the same syscalls as libuv, about a third less CPU around them.
  The sockets a loop turn reports readable are served in the check phase of
  that turn, in one of two orders: grouped by the CPU their peer's packets
  arrive on (`SO_INCOMING_CPU`: the peer thread's CPU over loopback, the
  receive queue's behind a NIC), so a peer driving many connections from one
  event loop gets its replies back to back and wakes once per group (the
  default); or as the kernel reported them (`MORO_ENGINE_SERVE_ORDER=arrival`);
  or, with `MORO_ENGINE_SERVE_ORDER=auto`, whichever of the two the loop
  measures the current peers answering faster (200 ms probe windows, an 8%
  margin, two agreeing probes to leave grouped, a stay on the winner that
  grows with the margin and with repeated wins and ends when the live rate
  moves 25% from what was probed or the peers reconnect en masse).
  `MORO_ENGINE_SERVE_DEBUG=1` logs the decisions.
- **libuv streams** (`transport: 'uv'`): macOS, Windows, and Linux when
  `MORO_ENGINE_TRANSPORT=uv` (A/B runs, bisecting).
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
`MORO_ENGINE_TRANSPORT=uv|epoll|uring` pins one (an io_uring request the
kernel or sandbox refuses falls back to epoll, with the reason); `probe()`
reports which one is active and why.
