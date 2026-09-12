// Type definitions for @morojs/engine.
// The Moro-shaped native HTTP/1.1 + WebSocket binding (see docs/API.md).
//
// DRIFT CHECK (maintainers): this surface must stay in lockstep with what the
// native binding actually parses (src/binding.cpp) and with docs/API.md. When a
// serve() option, capability flag, or native export is added there, add it
// here in the same change. `npm run check:exports` (tools/check-exports.mjs,
// run by CI and by tools/release.mjs) diffs the binding against this file,
// index.js NATIVE_API and index.mjs, and fails on drift.

export interface EngineCapabilities {
  /** The full serve() limit surface (maxHeadSize/maxHeaders/wsMaxMessageSize/
   *  wsBackpressureLimit/writeHighWaterMark/backlog) is parsed. */
  limits: boolean;
  /** In-process TLS termination via ServeOptions.ssl. */
  tls: boolean;
  /** ALPN-negotiated HTTP/2 alongside HTTP/1.1 — reserved for a future
   *  release; not yet configurable (no ServeOptions field). */
  http2: boolean;
  /** WebSocket permessage-deflate (RFC 7692) via ServeOptions.wsDeflate. */
  wsDeflate: boolean;
  /** The response-side / target-size hardening options are parsed:
   *  ServeOptions.responseTimeoutMs, responseBackpressureLimit, and maxUriSize. */
  responseLimits: boolean;
  /** Explicit TLS cipher/group policy is parsed:
   *  ServeOptions.ssl.ciphers, ciphersuites, and ecdhCurve. */
  tlsPolicy: boolean;
  /** setStaticRoute() / clearStaticRoutes() are available. */
  staticRoutes: boolean;
  /** prepareResponse() / releaseTemplates() / respondPrepared() /
   *  respondPreparedEmpty() / writeHeadPrepared() / endWith() are available. */
  responseTemplates: boolean;
  /** onAborted / onWritable are delivered on a later loop turn - never
   *  re-entrantly from inside respond()/writeHead()/write()/end(). close()
   *  still delivers pending onAborted calls before it returns. False only
   *  under the MORO_ENGINE_NOTIFY=sync diagnostics switch. */
  asyncNotify: boolean;
  /** A server left open when its environment is torn down
   *  (worker.terminate(), process.exit() inside a worker thread) is closed by
   *  an environment cleanup hook, so the engine is safe inside worker_threads. */
  workerThreads: boolean;
  /** V8 fast API calls are installed on the hot entry points (respondPrepared,
   *  respondPreparedEmpty, writeHeadPrepared, write, end, endWith, isAborted):
   *  optimised callers invoke the engine directly, skipping the V8 callback
   *  machinery. Informational - behaviour is identical either way. See
   *  EngineProbeResult.fastApi for why it is off. */
  fastCalls: boolean;
  /** Batched pipelined dispatch: the onRequestBatch callback, getBatchBuffers()
   *  and getPath(). Off under MORO_ENGINE_BATCH=0. */
  batchDispatch: boolean;
}

export interface FastApiInfo {
  /** Built with the V8 fast-call targets (tools/build.mjs fetched the
   *  per-tag v8-fast-api-calls.h; `--no-fast-api` turns this off). */
  compiled: boolean;
  /** Fast targets registered on this load. */
  installed: boolean;
  /** 'ok' | 'not-compiled' | 'env-disabled' (MORO_ENGINE_FASTCALL=0) |
   *  'sync-notify' (MORO_ENGINE_NOTIFY=sync forbids it) |
   *  'v8-mismatch' (host V8 major.minor != the compiled one). */
  reason: string;
  /** V8 major.minor this binary was compiled against, e.g. '13.6'. */
  compiledV8: string;
  /** V8 major.minor of the running Node. */
  runtimeV8: string;
}

export interface EngineProbeResult {
  /** True when a native binary loaded for this platform/ABI */
  ok: boolean;
  /** Engine version — the published package version (always set by the loader). */
  version?: string;
  platform: string;
  arch: string;
  /** Node ABI (process.versions.modules) the binary was built for */
  abi: number | string;
  /** Feature flags for consumers to gate option passing on (feature-detect;
   *  treat absent as all-false). */
  capabilities?: EngineCapabilities;
  /** How onAborted / onWritable reach JS: 'deferred' (a later loop turn, the
   *  default) or 'sync' (MORO_ENGINE_NOTIFY=sync, re-entrant, diagnostics). */
  notify?: 'deferred' | 'sync';
  /** Fast-call build/install diagnostics. */
  fastApi?: FastApiInfo;
  /** I/O transport in use: 'uring' (Linux 6.1+ with io_uring permitted by the
   *  sandbox) or 'uv' (libuv streams - macOS, Windows, older kernels,
   *  seccomp-blocked containers, MORO_ENGINE_TRANSPORT=uv). Behaviour and wire
   *  bytes are identical; only the syscall layer differs. */
  transport?: 'uv' | 'uring';
  /** Why the transport is not io_uring ('ok' when it is). */
  transportReason?: string;
  /** Per-thread fast/slow hit counters per hot entry point - present only when
   *  MORO_ENGINE_FASTCALL_STATS=1 was set when the addon loaded (test/CI proof
   *  that the fast path is taken). */
  fastCallStats?: Record<string, { fast: number; slow: number }>;
  /** Load failure detail when ok is false */
  error?: string;
}

export interface ServeCallbacks {
  /** A complete request (head + body) arrived. methodIdx indexes
   *  ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','OTHER']. */
  onRequest(reqId: number, methodIdx: number, path: string): void;
  /** Batched pipelined dispatch (capabilities.batchDispatch). When registered,
   *  complete pipelined requests are parsed ahead and delivered as ONE call:
   *  `count` slots described in getBatchBuffers().descriptors (three
   *  Uint32 per slot: reqId, methodIdx, pathIdx into `paths`, or 0xFFFFFFFF
   *  meaning "call getPath(reqId)"). Answer slot 0, then read `control[0]`:
   *  it is the index of the slot the engine has activated (only a
   *  synchronously completed response activates the next one) - continue at
   *  that index, or return when it still equals the slot you just dispatched
   *  (that handler is async; the remaining slots are delivered later). A
   *  request that stands alone still arrives here with count 1; onRequest is
   *  used only when this callback is absent. Return the slots consumed. */
  onRequestBatch?(count: number): number;
  /** The client disconnected, or the engine tore the request down (write
   *  error, responseBackpressureLimit, timeout, close()), before the response
   *  completed. Delivered on a LATER loop turn, never re-entrantly from
   *  inside a respond()/write()/end() call; isAborted(reqId) is already true
   *  when it runs. Exception: close() delivers the onAborted of every
   *  in-flight request synchronously, before close() returns. */
  onAborted(reqId: number): void;
  /** A backpressured write() drained; safe to write more. Delivered on a
   *  later loop turn (never from inside the write() that reported false). */
  onWritable(reqId: number): void;
  /** WebSocket opened after a successful Upgrade.
   *  DELIVERY GUARANTEE: onWsOpen is invoked SYNCHRONOUSLY, re-entrantly, during
   *  the upgradeToWebSocket() call that returns the wsId — it has already fired
   *  by the time upgradeToWebSocket() returns. Register per-socket state here
   *  before that return, since inbound frames may arrive immediately after. */
  onWsOpen?(wsId: number, path: string): void;
  /** WebSocket message (text -> string, binary -> ArrayBuffer).
   *  Frames the client sent in the SAME TCP segment as the handshake are
   *  delivered here immediately after onWsOpen — also synchronously within the
   *  upgradeToWebSocket() call — so a client that pipelines its first frame with
   *  the Upgrade is never dropped. */
  onWsMessage?(wsId: number, data: string | ArrayBuffer, isBinary: boolean): void;
  /** WebSocket closed (code per RFC 6455 §7.4). */
  onWsClose?(wsId: number, code: number): void;
}

export interface ServeOptions {
  /** Max request body in bytes; larger bodies are rejected natively (413). */
  maxBodySize?: number;
  /** Close a connection after this many ms with no bytes received while not
   *  running a handler (slowloris defense + keep-alive cap). 0 disables.
   *  Default 120000. */
  idleTimeoutMs?: number;
  /** Max simultaneous connections; accepts beyond this are dropped
   *  immediately (connection-flood defense). 0 = unlimited (default). */
  maxConnections?: number;
  /** Cap on bytes buffered for one connection while its response is in flight
   *  (pipelined-flood defense). 0 = maxHeadSize + maxBodySize (default). */
  maxPendingBytes?: number;
  /** Budget in ms for receiving one complete request (head + body), measured
   *  from its first byte. Unlike idleTimeoutMs it does NOT reset on activity,
   *  so slow-drip (slowloris) clients are bounded. Expiry answers 408 and
   *  closes. 0 disables. Default 300000 (Node's server.requestTimeout). */
  requestTimeoutMs?: number;
  /** Budget in ms for DELIVERING queued outbound bytes (the response-side twin
   *  of requestTimeoutMs; feature-detect via probe().capabilities.responseLimits).
   *  Resets on drain progress — the write queue shrinking since the last sweep,
   *  or a write completing — so only a drain making NO progress for the whole
   *  budget is closed; a genuinely slow-but-steady reader of a large download or
   *  SSE stream is never shed, only a stalled / zero-window peer (slow-read /
   *  zero-window DoS defense). Also bounds a stalled WebSocket consumer and a
   *  stalled close-frame flush. 0 disables. Default 300000. */
  responseTimeoutMs?: number;
  /** Bind with SO_REUSEPORT so several engine instances (worker threads or
   *  processes) can share one port with kernel-load-balanced accepts —
   *  required for clustering. POSIX only; ignored on Windows. Default false. */
  reusePort?: boolean;
  /** Max bytes for the request line + all headers; larger heads are rejected
   *  (431). Must be > 0. Default 65536. */
  maxHeadSize?: number;
  /** Max header count; more is rejected (431). Must be > 0. Default 100. */
  maxHeaders?: number;
  /** Dedicated cap on the request target (URI) length; over it answers 414.
   *  Default 0 = no dedicated cap (maxHeadSize still bounds the whole head with
   *  431). Feature-detect via probe().capabilities.responseLimits. */
  maxUriSize?: number;
  /** Opt-in hard cap in bytes on the not-yet-flushed HTTP outbound queue (the
   *  HTTP mirror of wsBackpressureLimit); over it the connection is closed
   *  immediately. Default 0 = unlimited. Leave 0 unless response sizes are
   *  bounded — one large respond() legitimately queues its whole body; a queued
   *  response holds an engine-side copy (~2x body peak for one slow drain,
   *  bounded in time by responseTimeoutMs). Apps serving large payloads to
   *  untrusted clients should set this cap or stream via writeHead()/write().
   *  Feature-detect via probe().capabilities.responseLimits. */
  responseBackpressureLimit?: number;
  /** Cap on a complete (reassembled) WebSocket message; larger messages fail
   *  the connection with close code 1009. Must be > 0. Default 16 MiB. */
  wsMaxMessageSize?: number;
  /** WebSocket send backpressure cap: a slow consumer whose write queue grows
   *  past this is shed with close code 1013 rather than buffering without
   *  bound. 0 = unlimited. Default 1 MiB. */
  wsBackpressureLimit?: number;
  /** Write-queue level above which write()/wsSend() report backpressure
   *  (false) and onWritable is armed. Must be > 0. Default 262144. */
  writeHighWaterMark?: number;
  /** TCP listen backlog handed to the kernel. Must be > 0. Default 512. */
  backlog?: number;
  /** In-process TLS termination (feature-detect via
   *  probe().capabilities.tls). Both shapes work; inline PEM wins when both
   *  are given for the same slot. Config errors THROW from serve(). */
  ssl?: {
    /** File-path shape */
    key_file_name?: string;
    cert_file_name?: string;
    ca_file_name?: string;
    /** Inline-PEM shape (node-style; string | Buffer | ArrayBuffer) */
    key?: string | ArrayBuffer | Uint8Array;
    cert?: string | ArrayBuffer | Uint8Array;
    ca?: string | ArrayBuffer | Uint8Array;
    /** Decrypts an encrypted private key */
    passphrase?: string;
    /** Session-ticket keys, Node tls.Server-compatible: exactly 48 bytes
     *  (16-byte key name + 16-byte HMAC secret + 16-byte AES key). Share the
     *  same buffer across reusePort workers / processes so TLS sessions
     *  resume across all of them. Rotation is the caller's job. */
    ticketKeys?: string | ArrayBuffer | Uint8Array;
    /** Protocol floor. Default 'TLSv1.2'. */
    minVersion?: 'TLSv1.2' | 'TLSv1.3';
    /** Request a client certificate (mutual TLS) */
    requestCert?: boolean;
    /** Fail the handshake when the client cert doesn't verify (default true) */
    rejectUnauthorized?: boolean;
    /** Explicit cipher/group policy for compliance baselines (PCI/FIPS/hardened
     *  profiles; feature-detect via probe().capabilities.tlsPolicy). Same
     *  semantics as Node's tls.createSecureContext; unset = the host Node's
     *  OpenSSL defaults; invalid values THROW from serve(). */
    ciphers?: string; // TLS <= 1.2 cipher list
    ciphersuites?: string; // TLS 1.3 suites (colon-separated)
    ecdhCurve?: string; // key-share groups, e.g. 'X25519:P-256'; 'auto' = default
  };
  /** WebSocket permessage-deflate (RFC 7692). Off by default.
   *  boolean to enable with defaults, or an options object. */
  wsDeflate?:
    | boolean
    | {
        serverNoContextTakeover?: boolean;
        clientNoContextTakeover?: boolean;
        serverMaxWindowBits?: number; // 8..15
        clientMaxWindowBits?: number; // 8..15
        /** Min message bytes before a send is compressed. Default 1024. */
        threshold?: number;
        /** Hard cap on an inflated message (zip-bomb defense).
         *  Default: wsMaxMessageSize. */
        maxDecompressedSize?: number;
        /** Share ONE server-owned deflate stream (reset per message) across
         *  all permessage-deflate connections instead of ~262 KB of deflate
         *  state per connection. Trades per-message compression ratio (no
         *  cross-message context) for memory; forces
         *  server_no_context_takeover in the negotiated response (RFC 7692
         *  §7.1.1.1 permits this even when the client didn't offer it).
         *  Clients that cap server_max_window_bits below serverMaxWindowBits
         *  fall back to a per-connection compressor. Default false. */
        sharedCompressor?: boolean;
      };
}

type BodyInit = string | ArrayBuffer | Uint8Array | Buffer;

/** Register callbacks and create a server. Sockets open only at listen(). */
export function serve(callbacks: ServeCallbacks, options?: ServeOptions): number;
/** Bind + listen; returns the actual bound port (supports port 0). Throws on failure. */
export function listen(serverId: number, host: string, port: number): number;
/** Tear down the server: stop accepting AND close every live connection
 *  (in-flight requests get onAborted). For a graceful shutdown, call
 *  stopListening() first, drain, then close(). */
export function close(serverId: number): void;
/** Stop accepting new connections while existing ones keep being served —
 *  the drain phase of a graceful shutdown. Idempotent. */
export function stopListening(serverId: number): void;

// ---- per-request accessors (valid until the response ends / aborts) ----
export function getMethod(reqId: number): string | undefined;
/** The batch-dispatch buffers of a server (the same objects every call):
 *  descriptors (3 x 16 Uint32), control (1 Uint32), paths (string[]). See
 *  ServeCallbacks.onRequestBatch. Feature-detect via
 *  probe().capabilities.batchDispatch. */
export function getBatchBuffers(serverId: number): {
  descriptors: Uint32Array;
  control: Uint32Array;
  paths: string[];
};
/** The active request's path, for a batch descriptor whose pathIdx is
 *  0xFFFFFFFF (the path was too long or the table full). */
export function getPath(reqId: number): string;
export function getQuery(reqId: number): string;
/** Flat [k0,v0,k1,v1,...] with lowercased keys. */
export function getHeaders(reqId: number): string[];
export function getHeader(reqId: number, lowercaseName: string): string | undefined;
export function getBody(reqId: number): ArrayBuffer | null;
export function getRemoteAddress(reqId: number): string;
export function isAborted(reqId: number): boolean;

// ---- response ----
/** Terminal single-shot response (status + headers + body in one cork). */
export function respond(
  reqId: number,
  status: number,
  headersFlat: string[] | null,
  body: BodyInit | null
): void;
export function writeHead(reqId: number, status: number, headersFlat: string[] | null): void;
/** Stream a chunk; returns false on backpressure (wait for onWritable). */
export function write(reqId: number, chunk: BodyInit): boolean;
export function end(reqId: number, chunk?: BodyInit): void;

// ---- Static routes ----
/** Register a fixed response for one (method, path), answered entirely inside
 *  the engine: no JS call, no routing, no header building per request. The
 *  header block and body are materialised once, here, so the response is
 *  byte-identical to the same reply sent via respond().
 *
 *  Only an exact method match short-circuits - anything else (a HEAD against a
 *  registered GET included) still reaches onRequest, so method policy stays in
 *  JS. Re-registering the same (method, path) replaces it.
 *
 *  `method` is the engine's method index: GET 0, POST 1, PUT 2, DELETE 3,
 *  PATCH 4, HEAD 5, OPTIONS 6.
 *
 *  Feature-detect via probe().capabilities.staticRoutes. */
export function setStaticRoute(
  serverId: number,
  method: number,
  path: string,
  status?: number,
  headersFlat?: string[] | null,
  body?: BodyInit | null
): void;
/** Drop every static route registered on this server. */
export function clearStaticRoutes(serverId: number): void;

// ---- Prepared response templates ----
/** Materialise status + headers ONCE (the same header builder respond() uses,
 *  so the wire bytes are identical) and get back a template id to replay per
 *  request with respondPrepared()/respondPreparedEmpty()/writeHeadPrepared().
 *  Ids are per server, dense from 1, and stay valid until releaseTemplates()
 *  (or close()). Throws a RangeError when the per-server store is full (4096).
 *  A Content-Length in `headersFlat` is honoured on HEAD/bodyless replies only,
 *  exactly as with respond(). Feature-detect via
 *  probe().capabilities.responseTemplates. */
export function prepareResponse(
  serverId: number,
  status: number,
  headersFlat: string[] | null
): number;
/** Invalidate every template id issued by prepareResponse() on this server. */
export function releaseTemplates(serverId: number): void;
/** respond() with a prepared template instead of a header array. An invalid
 *  tplId (0, released, another server's) answers 500 with an empty body and
 *  leaves keep-alive intact - it never throws and never hangs the request. */
export function respondPrepared(reqId: number, tplId: number, body: BodyInit | null): void;
/** respondPrepared() with no body (Content-Length: 0). */
export function respondPreparedEmpty(reqId: number, tplId: number): void;
/** writeHead() with a prepared template (streaming follows with write()/end()). */
export function writeHeadPrepared(reqId: number, tplId: number): void;
/** Exactly end(reqId, chunk): a fixed-arity twin for call sites that always
 *  pass a chunk. */
export function endWith(reqId: number, chunk: BodyInit): void;

// ---- WebSocket (RFC 6455) ----
/** Upgrade the request's connection; returns wsId, or -1 if not a valid upgrade.
 *  onWsOpen (and any early frames pipelined in the handshake's TCP segment, via
 *  onWsMessage) fire SYNCHRONOUSLY during this call, before it returns. */
export function upgradeToWebSocket(reqId: number): number;
/** Send a frame; returns false on backpressure. */
export function wsSend(wsId: number, data: string | ArrayBuffer | Uint8Array | Buffer, isBinary: boolean): boolean;
/** Send a Close frame and close the connection. */
export function wsClose(wsId: number, code?: number, reason?: string): void;

/** Non-throwing load diagnostics. Never throws. */
export function probe(): EngineProbeResult;
// The engine version comes from this package's package.json (stamped from the
// release tag), available without loading the addon via `probe().version` or on
// the default export as `engine.version` — neither forces the native addon to
// load. It is intentionally not a standalone named export, so that a bare
// `import` of this package never loads the addon.

declare const engine: {
  serve: typeof serve;
  listen: typeof listen;
  close: typeof close;
  stopListening: typeof stopListening;
  getMethod: typeof getMethod;
  getBatchBuffers: typeof getBatchBuffers;
  getPath: typeof getPath;
  getQuery: typeof getQuery;
  getHeaders: typeof getHeaders;
  getHeader: typeof getHeader;
  getBody: typeof getBody;
  getRemoteAddress: typeof getRemoteAddress;
  isAborted: typeof isAborted;
  respond: typeof respond;
  writeHead: typeof writeHead;
  write: typeof write;
  end: typeof end;
  setStaticRoute: typeof setStaticRoute;
  clearStaticRoutes: typeof clearStaticRoutes;
  prepareResponse: typeof prepareResponse;
  releaseTemplates: typeof releaseTemplates;
  respondPrepared: typeof respondPrepared;
  respondPreparedEmpty: typeof respondPreparedEmpty;
  writeHeadPrepared: typeof writeHeadPrepared;
  endWith: typeof endWith;
  upgradeToWebSocket: typeof upgradeToWebSocket;
  wsSend: typeof wsSend;
  wsClose: typeof wsClose;
  probe: typeof probe;
  version: string;
};

export default engine;
