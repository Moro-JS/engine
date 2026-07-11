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
  onAborted(reqId: number): void;      // client disconnected / server tore the request down
  onWritable(reqId: number): void;     // write() backpressure drained
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

  // v1.3.0+ - WebSocket permessage-deflate (RFC 7692; capabilities.wsDeflate).
  // Off by default (preserves the compression-oracle-free posture). boolean to
  // enable with defaults, or an options object.
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
close(serverId: number): void;   // full teardown: stop accepting AND close every live
                                 // connection; in-flight requests get onAborted

// ---- request data (lazy; single crossing each) ----
// methodIdx indexes METHODS = ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','OTHER']
getMethod(reqId): string | undefined;     // for methodIdx 7 (OTHER)
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

// ---- diagnostics ----
// On success: { ok: true, version, abi, platform, arch, capabilities }
// On failure (no binary for this platform/ABI): { ok: false, abi, platform, arch, error }
// capabilities (absent = all false): feature flags for consumers to
// gate option passing on instead of version-sniffing:
//   { limits: boolean, tls: boolean, http2: boolean, wsDeflate: boolean,
//     responseLimits: boolean,  // responseTimeoutMs / responseBackpressureLimit / maxUriSize parsed
//     tlsPolicy: boolean }      // ssl.ciphers / ssl.ciphersuites / ssl.ecdhCurve parsed
probe(): { ok: boolean, version?: string, abi, platform, arch,
           capabilities?: { limits: boolean, tls: boolean, http2: boolean, wsDeflate: boolean,
                            responseLimits: boolean, tlsPolicy: boolean },
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

Everything runs on the Node/libuv main loop (uv handles registered on
`node::GetCurrentEventLoop`). Callbacks are invoked synchronously from I/O
events — a single-threaded on-loop model. No locks, no cross-thread
marshaling.

## WebSocket (M4 surface, see src/websocket.h)

```ts
upgradeToWebSocket(reqId): number | -1;   // -1 if not a valid upgrade request; else wsId
wsSend(wsId, data: string | ArrayBuffer | Uint8Array | Buffer, isBinary: boolean): boolean;
wsClose(wsId, code?: number, reason?: string): void;
// serve() callbacks gain: onWsOpen(wsId, path), onWsMessage(wsId, data, isBinary),
// onWsClose(wsId, code)
```
permessage-deflate (RFC 7692) is supported from v1.3.0 - opt-in via
options.wsDeflate (off by default, which declines the extension). When enabled,
the engine inflates inbound compressed messages (with a zip-bomb output cap →
close 1009) and compresses outbound sends over the threshold. Inbound text is
UTF-8-validated after inflate (→ close 1007 on failure).
