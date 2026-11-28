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
  /** HTTP/2 via ServeOptions.http2 (engine >= 1.1.19): negotiated by ALPN on
   *  a TLS listener, by prior knowledge on a cleartext one, with HTTP/1.1
   *  served beside it on the same port. */
  http2: boolean;
  /** WebSocket permessage-deflate (RFC 7692) via ServeOptions.wsDeflate. */
  wsDeflate: boolean;
  /** The response-side / target-size hardening options are parsed:
   *  ServeOptions.responseTimeoutMs, responseBackpressureLimit, and maxUriSize. */
  responseLimits: boolean;
  /** Explicit TLS cipher/group policy is parsed:
   *  ServeOptions.ssl.ciphers, ciphersuites, and ecdhCurve. */
  tlsPolicy: boolean;
  /** updateSsl() is available: the certificate/key (and policy) of a TLS
   *  server can be replaced for new handshakes without a restart. */
  tlsReload: boolean;
  /** ssl.crl and ssl.maxVersion are honoured (an engine without this flag
   *  reads neither). */
  tlsCrl: boolean;
  /** setStaticRoute() / clearStaticRoutes() are available. */
  staticRoutes: boolean;
  /** setParamRoute() / clearParamRoutes() are available: a route with one
   *  variable path segment, echoed as the body, answered inside the engine. */
  paramRoutes: boolean;
  /** prepareResponse() / releaseTemplates() / respondPrepared() /
   *  respondPreparedEmpty() / writeHeadPrepared() / endWith() are available. */
  responseTemplates: boolean;
  /** Every callback into JS (onRequest, onRequestBatch, onAborted, onWritable,
   *  the WebSocket callbacks) runs inside a Node callback scope, so
   *  process.nextTick callbacks and microtasks queued during dispatch run
   *  when the callback returns, as they do after Node's own I/O callbacks. */
  callbackScope: boolean;
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
  /** setWsAutoUpgrade(), wsGetHeaders(), wsGetQuery() and wsGetRemoteAddress()
   *  exist: the engine can perform valid WebSocket upgrades itself, firing
   *  onWsOpen without the request ever reaching onRequest. */
  wsAutoUpgrade: boolean;
  /** trimMemory() exists. */
  memoryTrim: boolean;
  /** A connection between requests holds no parser and no request buffers:
   *  an idle keep-alive connection costs its socket and its bookkeeping. */
  restingConnections: boolean;
  /** 1.2.4: what all connections hold in buffers together is bounded (the
   *  memoryBudget option, probe().bufferBudget). */
  bufferBudget: boolean;
  /** 1.2.5, Linux: the kernel receive buffers of a thread's connections are
   *  held to a budget as well - twice the thread's buffer budget - once it
   *  has more connections than fit in it with the system's buffer each (see
   *  the memoryBudget option, probe().bufferBudget). False on macOS and
   *  Windows; engines before 1.2.5 do not report it. */
  socketBudget: boolean;
  /** Engine-side upgrades (setWsAutoUpgrade) are safe together with batched
   *  dispatch (onRequestBatch). Engines 1.1.15 to 1.1.21 report
   *  wsAutoUpgrade and batchDispatch without this flag and must not be given
   *  both: a process abort could occur there with pipelined WebSocket
   *  handshakes. */
  wsAutoUpgradeBatch: boolean;
  /** idleTimeoutMs does not close a connection whose response is still being
   *  written to a peer that is reading it, whether the handler answered
   *  before it returned or later; responseTimeoutMs governs delivery (and
   *  closes a peer that stops reading). Only with responseTimeoutMs set to 0
   *  does the idle timeout apply to such a connection. Engines without this
   *  flag (before 1.2.0) count a response given before the handler returned
   *  as idle from the moment it is framed, so an idle timeout shorter than a
   *  slow download cuts the download. */
  idleSparesDrainingResponse: boolean;
  /** getBodyType() and getBodyText() exist. */
  bodyText: boolean;
  /** getBodyLent() exists. */
  bodyLent: boolean;
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

/** The TLS library the loaded binary terminates TLS with, and why that binary. */
export interface EngineTlsInfo {
  /** 'boringssl': carried inside the addon (the default since 1.1.20).
   *  'openssl': the OpenSSL the running node exports. */
  library: 'boringssl' | 'openssl';
  /** BoringSSL: the upstream version tag the build is pinned to
   *  (`0.YYYYMMDD.N`). OpenSSL: that library's own version, e.g. '3.5.2'. */
  version: string;
  /** BoringSSL only: the day upstream cut that snapshot, 'YYYY-MM-DD' - how
   *  old the bundled TLS code is. */
  date?: string;
  /** Why this library: 'default', 'selectTls()', 'MORO_ENGINE_TLS',
   *  "node's OpenSSL is configured (...)" (FIPS mode, an OpenSSL config or
   *  provider option), 'fallback' (the BoringSSL binary could not be loaded,
   *  or BoringSSL did not accept the TLS configuration), or
   *  'MORO_ENGINE_BINARY'. */
  reason: string;
  /** With reason 'fallback': why BoringSSL is not the one serving. */
  fallbackReason?: string;
}

/** The native binary that was loaded. */
export interface EngineBinaryInfo {
  /** The `.node` file. */
  path: string;
  /** The version of the platform package it came from: the release the
   *  running code belongs to, always equal to `EngineProbeResult.version`
   *  (a platform package of another release is not loaded). Absent for a
   *  local build and for `MORO_ENGINE_BINARY`. */
  version?: string;
}

export interface EngineProbeResult {
  /** True when a native binary loaded for this platform/ABI */
  ok: boolean;
  /** Engine version — the published package version (always set by the loader). */
  version?: string;
  /** Which binary is loaded, and from which release (`ok: true` only). */
  binary?: EngineBinaryInfo;
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
  /** TLS library in use (1.1.20 and later). */
  tls?: EngineTlsInfo;
  /** I/O transport in use: 'epoll' (Linux default since 1.1.10: the engine's
   *  own readiness loop on one uv_poll, no libuv stream per connection),
   *  'uring' (Linux 6.1+, MORO_ENGINE_TRANSPORT=uring, when the sandbox
   *  permits io_uring) or 'uv' (libuv streams - macOS, Windows,
   *  MORO_ENGINE_TRANSPORT=uv). Behaviour and wire bytes are identical; only
   *  the syscall layer differs. */
  transport?: 'uv' | 'uring' | 'epoll';
  /** Why this transport: 'ok' for io_uring, the default/override note otherwise. */
  transportReason?: string;
  /** 'uv', or the io_uring ring mode in use: 'defer-taskrun' (completions run
   *  as one batch inside the engine's own io_uring_enter, woken through a
   *  registered eventfd) or 'coop-taskrun' (the 1.1.6 mode). The probe tries
   *  defer first; MORO_ENGINE_URING_TASKRUN=coop|defer pins one. */
  transportMode?: 'uv' | 'epoll' | 'defer-taskrun' | 'coop-taskrun';
  /** The connections held by the servers of the calling thread, and how many
   *  of them are at rest: between requests, holding no parser and no request
   *  buffers (capabilities.restingConnections). WebSockets, HTTP/2 connections
   *  and connections with a request in progress are open and not at rest. */
  connections?: { open: number; resting: number };
  /** 1.2.4: the request states the servers of the calling thread keep for
   *  the requests to come, and the heap storage their buffers hold. A state
   *  holding more than 128 KiB is freed instead of kept (the path, query and
   *  header storage of a request can each grow to maxHeadSize), so `bytes`
   *  stays within 128 KiB times `pooled`. Absent on engines before 1.2.4. */
  requestStates?: { pooled: number; bytes: number };
  /** 1.2.4: the buffer budget of the calling thread (the memoryBudget
   *  option). `held`: bytes its connections hold in buffers for their peers -
   *  requests still arriving, responses not yet taken. `limit`: the thread's
   *  share of the process's budget, Infinity when there is none (no server
   *  listening on the thread, or memoryBudget: Infinity). `shed`: connections
   *  closed because the thread had no room for the requests they were
   *  sending. `evicted`: connections closed at the sweep, while it had none,
   *  for requests or unread responses of which nothing had moved for a sweep
   *  interval. Absent on engines before 1.2.4.
   *  1.2.5 (capabilities.socketBudget) adds the socket budget's figures.
   *  `connections`: open connections of the thread's servers. `sockets`: the
   *  thread's share for what the kernel queues for them to read, Infinity
   *  when there is none. `receiveBuffer`: the size each connection's kernel
   *  receive buffer is held to now, 0 while the system's own fits (always 0
   *  off Linux). `resized`: times a connection's buffer was set. */
  bufferBudget?: {
    held: number;
    limit: number;
    shed: number;
    evicted: number;
    connections?: number;
    sockets?: number;
    receiveBuffer?: number;
    resized?: number;
  };
  /** 1.2.4: the calling thread's event loop under load (epoll transport;
   *  zeros elsewhere). `cut`: loop turns that used up their time slice with
   *  sockets still to serve. `waiting`: sockets waiting for a later turn
   *  now. Both are zero on a loop that is keeping up. */
  turns?: { cut: number; waiting: number };
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
   *  used only when this callback is absent. Return the slots consumed.
   *  `control[0]` at or above `count` means the batch is over: every slot was
   *  answered, the next request is a WebSocket handshake the engine answers
   *  itself (setWsAutoUpgrade), or the connection was closed from inside the
   *  loop - in each case, return. */
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
  /** WebSocket closed (code per RFC 6455 §7.4): the peer's Close code (1005
   *  when its Close carried none), 1006 when it went away without one, the
   *  code of a protocol failure (1002, 1007, 1009), or the code wsClose() was
   *  called with, as passed. Fires exactly once per socket. Inside it the
   *  socket is already closing - wsSend() answers false and wsClose() does
   *  nothing - while wsGetHeaders(), wsGetQuery() and wsGetRemoteAddress()
   *  still answer. */
  onWsClose?(wsId: number, code: number): void;
}

export interface ServeOptions {
  /** Max request body in bytes; larger bodies are rejected natively (413). */
  maxBodySize?: number;
  /** Close a connection after this many ms with no bytes received while not
   *  running a handler (slowloris defense + keep-alive cap). 0 disables.
   *  Default 120000. A connection whose response is still being written to
   *  the peer is not idle: responseTimeoutMs governs it, unless that is 0
   *  (capabilities.idleSparesDrainingResponse). A full budget: the
   *  connection is never closed before it has been idle this long, and is
   *  closed within two sweep intervals after (an interval is half the
   *  shortest timeout set, between 250 ms and 1 s). */
  idleTimeoutMs?: number;
  /** Max simultaneous connections; accepts beyond this are dropped
   *  immediately (connection-flood defense). 0 = unlimited (default). */
  maxConnections?: number;
  /** Cap on bytes buffered for one connection while they cannot be
   *  dispatched: a handler is running, or the responses already given are
   *  waiting on the peer (pipelined-flood defense). Over it the connection is
   *  closed. 0 = maxHeadSize + maxBodySize (default). */
  maxPendingBytes?: number;
  /** 1.2.4 (capabilities.bufferBudget): bytes the PROCESS may hold in
   *  buffers for its peers, all connections of all its servers together -
   *  requests still being received (bodies, pipelined input, WebSocket
   *  messages being reassembled) and response bytes peers have not taken.
   *  Every other limit bounds one connection. The budget is divided among
   *  the threads that have a server listening; a thread's share is never
   *  below the largest single message its servers accept (maxHeadSize +
   *  maxBodySize, or wsMaxMessageSize). When a thread is over its share, a
   *  connection with more than 16 KiB of requests still arriving is closed
   *  where its read ends - 503 for an HTTP/1 request, close code 1013 for a
   *  WebSocket message, GOAWAY on HTTP/2; a request of up to 16 KiB is never
   *  refused. Response bytes are counted and never close a connection where
   *  they are queued: a response to a peer that reads it is delivered
   *  whatever its size. At the sweep, while the thread is short, connections
   *  whose requests or unread responses have not moved for a sweep interval
   *  are closed (for a response, the kernel's count of unacknowledged output
   *  is asked too on Linux and macOS, so a slow reader is not taken for one
   *  that has stopped). Unset or 0: an eighth of the memory the process may use
   *  (its cgroup limit, or the machine's). Infinity: no budget.
   *  1.2.5: on a thread over its share, a connection's further requests wait
   *  once it has 16 KiB of responses it has not taken (its part of half the
   *  share on a thread with more connections than that half has 16 KiB for,
   *  4 KiB at the least), where the write high-water mark applies otherwise.
   *  And while a thread holds twice its share, a connection owed more than
   *  that which has taken nothing for half a second - no acknowledgment, no
   *  HTTP/2 window opened - is closed, the one owed most first, until the
   *  thread is within its share again.
   *  1.2.5, Linux (capabilities.socketBudget): twice this budget is what the
   *  kernel may queue for the connections to read. While a thread's
   *  connections fit in its share of that with the receive buffer the system
   *  gives a socket (128 KiB), nothing is set. Past that, each connection's
   *  receive buffer is set to its part, a power of two from 64 KiB down to
   *  16 KiB, and raised again when the thread has room. A request that fits
   *  the buffer is served as before; a larger body from a peer on the
   *  loopback interface arrives a buffer at a time, about five a second,
   *  while the thread is that crowded. Infinity: no socket budget either. */
  memoryBudget?: number;
  /** Budget in ms for receiving one complete request (head + body), measured
   *  from its first byte. Unlike idleTimeoutMs it does NOT reset on activity,
   *  so slow-drip (slowloris) clients are bounded. Expiry answers 408 and
   *  closes. 0 disables. Default 300000 (Node's server.requestTimeout). A
   *  full budget: a request that completes within it is served, and the 408
   *  comes within two sweep intervals after it has passed (an interval is
   *  half the shortest timeout set, between 250 ms and 1 s), never before. */
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
  /** Take a request-target (HTTP/1.1) or `:path` (HTTP/2) that holds bytes of
   *  0x80 and above and hand them over undecoded, as every release before
   *  1.2.2 did. Default false: such a request is answered 400 (a stream error
   *  on HTTP/2). A request-target is ASCII (RFC 3986 §2); clients
   *  percent-encode what is not. */
  allowNonAsciiTarget?: boolean;
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
  /** WebSocket send backpressure cap: a consumer that is not keeping up is
   *  shed with close code 1013 rather than buffered without bound. A socket
   *  is shed by a wsSend() that finds bytes of an earlier send still waiting
   *  and leaves more than this many bytes queued. One message sent to a
   *  socket with nothing waiting is never shed for its size: it is queued
   *  whole and the socket stays open; a peer that stops reading with it in
   *  flight is closed by responseTimeoutMs. A stalled peer can therefore
   *  hold this many bytes across sends, or the largest single message the
   *  application sends, whichever is larger - the engine does not cap the
   *  size of one message, so an application sending very large ones to
   *  untrusted peers should bound them. On Windows the system takes the
   *  first two sends outstanding on a socket whole into its buffer and
   *  reports them sent: they are not counted here and responseTimeoutMs does
   *  not time them (docs/API.md, send backpressure). 0 = unlimited. Default
   *  1 MiB. */
  wsBackpressureLimit?: number;
  /** Write-queue level above which write()/wsSend() report backpressure
   *  (false) and onWritable is armed, and at which no further pipelined
   *  request is taken from a connection until the peer has read. Must be
   *  > 0. Default 262144. */
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
    /** Certificate revocation lists (PEM, one or more) for client
     *  certificates, as Node's tls `crl` (feature-detect via
     *  probe().capabilities.tlsCrl). With any given, a client certificate is
     *  accepted only when the CRL of every CA in its chain is here and does
     *  not list it. */
    crl?: string | ArrayBuffer | Uint8Array;
    /** Decrypts an encrypted private key */
    passphrase?: string;
    /** Session-ticket keys, Node tls.Server-compatible: exactly 48 bytes
     *  (16-byte key name + 16-byte HMAC secret + 16-byte AES key). Share the
     *  same buffer across reusePort workers / processes so TLS sessions
     *  resume across all of them. Rotation is the caller's job. A session
     *  is resumed only by a server with the same policy as the one that
     *  issued it - minVersion, ciphers, ciphersuites, and requestCert /
     *  rejectUnauthorized / the CA certificates: sharing the keys with a
     *  listener that asks for no client certificate does not let its
     *  sessions into one that requires them. */
    ticketKeys?: string | ArrayBuffer | Uint8Array;
    /** Protocol floor. Default 'TLSv1.2' - or 'TLSv1.3' when node was
     *  started with --tls-min-v1.3 (tls.DEFAULT_MIN_VERSION). */
    minVersion?: 'TLSv1.2' | 'TLSv1.3';
    /** Protocol ceiling. Default: the newest the TLS library has - or
     *  'TLSv1.2' when node was started with --tls-max-v1.2. */
    maxVersion?: 'TLSv1.2' | 'TLSv1.3';
    /** Request a client certificate (mutual TLS) */
    requestCert?: boolean;
    /** Fail the handshake when the client cert doesn't verify (default true) */
    rejectUnauthorized?: boolean;
    /** Explicit cipher/group policy for compliance baselines (PCI/FIPS/hardened
     *  profiles; feature-detect via probe().capabilities.tlsPolicy). Same
     *  semantics as Node's tls.createSecureContext; invalid values THROW from
     *  serve(). A value of the wrong type throws too, here and for every
     *  other policy option (`requestCert: 1` is an error, not "off").
     *  Unset: the list node was started with (--tls-cipher-list), else the
     *  TLS library's own set of ciphers, AES-128-GCM ahead
     *  of AES-256-GCM, ChaCha20 for a client that lists it first. With the
     *  bundled BoringSSL (probe().tls.library) `ciphersuites` can name
     *  TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and
     *  TLS_CHACHA20_POLY1305_SHA256, and `ciphers` has no DHE or CCM suites;
     *  a policy that needs others selects OpenSSL (selectTls / MORO_ENGINE_TLS). */
    ciphers?: string; // TLS <= 1.2 cipher list
    ciphersuites?: string; // TLS 1.3 suites (colon-separated)
    ecdhCurve?: string; // key-share groups, e.g. 'X25519:P-256'; 'auto' = default
  };
  /** HTTP/2 (RFC 9113). Off by default. `true`, or an object of settings to
   *  advertise. With `ssl` the listener offers "h2" ahead of "http/1.1" in
   *  ALPN; without it a client speaks HTTP/2 by opening with the connection
   *  preface (prior knowledge, e.g. `curl --http2-prior-knowledge`). Every
   *  other client is served HTTP/1.1 on the same port. A request arriving on
   *  an HTTP/2 stream is delivered exactly as an HTTP/1 request is - the same
   *  callbacks, the same accessors, the same response calls. Not served over
   *  HTTP/2: WebSocket upgrades (RFC 8441), server push, CONNECT. */
  http2?:
    | boolean
    | {
        /** Streams a client may have open at once. Default 256. */
        maxConcurrentStreams?: number;
        /** Per-stream receive window, in bytes. Default 1 MiB. */
        initialWindowSize?: number;
        /** Largest frame payload accepted. Default (and minimum) 16,384. */
        maxFrameSize?: number;
        /** Largest decoded request header list. Default: maxHeadSize. */
        maxHeaderListSize?: number;
        /** HPACK dynamic table size offered to the client. Default 4,096. */
        headerTableSize?: number;
      };
  /** WebSocket permessage-deflate (RFC 7692). Off by default.
   *  boolean to enable with defaults, or an options object. */
  wsDeflate?:
    | boolean
    | {
        serverNoContextTakeover?: boolean;
        clientNoContextTakeover?: boolean;
        /** 9..15. An 8-bit window is never negotiated: zlib's raw deflate
         *  has none, so an offer asking for one is declined. */
        serverMaxWindowBits?: number;
        /** 9..15 (see serverMaxWindowBits). */
        clientMaxWindowBits?: number;
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
/** Bind + listen; returns the actual bound port (supports port 0). Throws on
 *  failure, with a libuv-style `code`. A server listens once: EINVAL for one
 *  that is already listening, has stopped listening or is closing. */
export function listen(serverId: number, host: string, port: number): number;
/** Tear down the server: stop accepting AND close every live connection
 *  (in-flight requests get onAborted). For a graceful shutdown, call
 *  stopListening() first, drain, then close(). */
export function close(serverId: number): void;
/** Stop accepting new connections while existing ones keep being served —
 *  the drain phase of a graceful shutdown. Idempotent. */
export function stopListening(serverId: number): void;
/** Replace the TLS certificate/key (and cipher policy) used for every
 *  handshake from now on, without restarting the listener (feature-detect via
 *  probe().capabilities.tlsReload). `ssl` is the full ServeOptions.ssl shape,
 *  not a diff; ticketKeys carry over when omitted so session resumption
 *  survives a rotation of the certificate (an update that changes the
 *  policy - minVersion, ciphers, the client-certificate settings or CAs -
 *  ends it: those clients get a full handshake). Established connections keep the context they
 *  handshaked with. Throws (leaving the current context in place) on invalid
 *  material, and for a server that was not started with ssl. */
export function updateSsl(serverId: number, ssl: NonNullable<ServeOptions['ssl']>): void;

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
/** The request body, or null when there is none. The bytes are handed over
 *  without a copy and stay valid for as long as JS holds the buffer; a second
 *  call during the same request returns the same storage, not a snapshot. */
export function getBody(reqId: number): ArrayBuffer | null;
/** The request's Content-Type: '' when it has a body but no such header,
 *  null when it has no body (or the request is gone). */
export function getBodyType(reqId: number): string | null;
/** The body as a string when every byte of it is ASCII, null otherwise (read
 *  it with getBody then). The string is the exact bytes received - decoded
 *  as UTF-8 or as Latin-1 it is the same text - and lives on the JS heap
 *  like any other string, where getBody's ArrayBuffer counts as external
 *  memory until a collection frees it. Null once getBody has taken the
 *  bytes. */
export function getBodyText(reqId: number): string | null;
/** The body as an ArrayBuffer that is detached when the response is complete
 *  or the request is aborted (byteLength 0, every view empty). The bytes are
 *  moved into it, not copied, and released at that moment instead of at some
 *  later collection - which is what keeps a server reading bodies at a high
 *  rate out of back-to-back full collections. For a handler that relays,
 *  hashes or echoes a body and keeps none of it. Code that keeps the body
 *  past the response reads it with getBody (a copy, during a loan) or
 *  transfers the lent buffer. Null when there is no body.
 *
 *  "Keeps none of it" includes work in progress. An asynchronous operation
 *  that was handed the bytes - fs.write, a socket or stream write that did
 *  not go out at once, a zlib or crypto job - keeps a pointer to the memory,
 *  not the buffer: if the response is completed before it has finished, it
 *  reads memory that is free or already holds another request's body. Wait
 *  for it before responding, or read the body with getBody. */
export function getBodyLent(reqId: number): ArrayBuffer | null;
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

// ---- Parameter routes ----
/** Register a route with ONE variable path segment whose body IS that
 *  segment, answered entirely inside the engine like a static route:
 *  `/user/:id` is prefix "/user/" and suffix ""; `/files/:name.json` is
 *  prefix "/files/" and suffix ".json". The segment must be non-empty and
 *  contain no '/', so `/user/` and `/user/1/2` still reach onRequest. It is
 *  written as it is on the wire, undecoded; a route that needs decoding
 *  stays a JS route. The header block
 *  is materialised once, so the reply is byte-identical to
 *  respond(status, headersFlat, segment). Only an exact method match
 *  short-circuits; re-registering (method, prefix, suffix) replaces it.
 *  Feature-detect via probe().capabilities.paramRoutes. */
export function setParamRoute(
  serverId: number,
  method: number,
  prefix: string,
  suffix: string,
  status?: number,
  headersFlat?: string[] | null
): void;
/** Drop every parameter route registered on this server. */
export function clearParamRoutes(serverId: number): void;

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
 *  onWsMessage) fire SYNCHRONOUSLY during this call, before it returns.
 *  A valid upgrade (RFC 6455 §4.2.1) is a GET over HTTP/1.1 with
 *  `Upgrade: websocket`, `Connection: Upgrade`, exactly one Sec-WebSocket-Key
 *  (16 bytes, base64) and exactly one `Sec-WebSocket-Version: 13`. After -1
 *  the request is still open and the caller answers it (a handshake whose
 *  only fault is its version is owed a 426 with `Sec-WebSocket-Version: 13`,
 *  which setWsAutoUpgrade sends by itself). */
export function upgradeToWebSocket(reqId: number): number;
/** Send a frame. false when it did not go out - the socket is gone or
 *  closing, or `data` is not a string or bytes - and on backpressure (the
 *  frame is queued, the write queue is over writeHighWaterMark). */
export function wsSend(wsId: number, data: string | ArrayBuffer | Uint8Array | Buffer, isBinary: boolean): boolean;
/** Send a Close frame (code 1000 unless given) and end the connection: the
 *  server half-closes and reads until the peer has closed too (at most two
 *  seconds), so the peer receives the Close even while it is still sending;
 *  over TLS the close_notify goes out behind the frame and ahead of the FIN
 *  (1.2.4; earlier a TLS connection was closed at once). The frame is legal
 *  whatever is passed: a `code` that may not appear on the wire (RFC 6455
 *  §7.4) is replaced - 1005 by a Close without a status, any other
 *  (1004, 1006, 1015, below 1000, 1016-2999, 5000 and up) by 1011 - and
 *  `reason` is cut to 123 bytes of UTF-8 at a character boundary. onWsClose
 *  reports `code` as passed. */
export function wsClose(wsId: number, code?: number, reason?: string): void;
/** With `on`, every valid WebSocket handshake is answered by the engine itself:
 *  the 101 goes out, onWsOpen fires (and any frames pipelined with the
 *  handshake reach onWsMessage), and onRequest is never called for it. A
 *  handshake that is valid except for its Sec-WebSocket-Version is answered
 *  too: 426 with `Sec-WebSocket-Version: 13` (RFC 6455 §4.4). Any other
 *  request - not a GET, HTTP/1.0, a missing or repeated key - is surfaced to
 *  onRequest as an ordinary request. Applies to this server only; register
 *  it again after close() + serve(). Together with onRequestBatch only on an
 *  engine that reports capabilities.wsAutoUpgradeBatch. */
export function setWsAutoUpgrade(serverId: number, on: boolean): void;
/** The handshake request's headers, flat [name, value, ...] with names
 *  lowercased (the shape getHeaders() gives), kept for the socket's lifetime;
 *  undefined once the socket is gone. */
export function wsGetHeaders(wsId: number): string[] | undefined;
/** The handshake request's raw query string ('' when it had none). */
export function wsGetQuery(wsId: number): string | undefined;
/** The peer's address, as getRemoteAddress() gives it for a request. */
export function wsGetRemoteAddress(wsId: number): string | undefined;

/**
 * Give back the memory this thread's start-up left behind: one synchronous,
 * memory-reducing collection of the calling isolate's heap, and on glibc the
 * free pages of the allocator. Call it once per isolate after start-up (a
 * server that has just loaded holds about as much free heap as live heap,
 * and keeps it while it is quiet), never on a request path. The heap grows
 * again as load needs it. Feature-detect via probe().capabilities.memoryTrim.
 */
export function trimMemory(): void;

/** Non-throwing load diagnostics. Never throws. */
export function probe(): EngineProbeResult;
/**
 * Choose the TLS library before the engine's binary is loaded. Returns the
 * library in effect.
 *
 * - 'boringssl': BoringSSL, carried inside the addon. The default.
 * - 'openssl': the OpenSSL of the running node - for FIPS mode, OpenSSL
 *   providers or engines, a system crypto policy.
 * - 'auto': no choice made in code. MORO_ENGINE_TLS decides if it is set;
 *   otherwise BoringSSL, unless node's OpenSSL is specially configured
 *   (--enable-fips, --force-fips, --openssl-config, --openssl-shared-config,
 *   --openssl-legacy-provider, OPENSSL_CONF, OPENSSL_MODULES, or FIPS mode on),
 *   in which case OpenSSL.
 *
 * The choice is per thread and must be made before the first probe() or
 * serve() there: a loaded addon cannot be swapped, and asking for the other
 * library afterwards throws (code 'MORO_ENGINE_TLS_LOADED'). The environment
 * variable MORO_ENGINE_TLS takes the same three values and needs no code.
 *
 * `ssl`: the ssl options the server is about to be created with. When no
 * library is named ('auto', no MORO_ENGINE_TLS), the load checks that
 * BoringSSL accepts them - its set of key types, cipher suites and groups is
 * narrower than OpenSSL's - and settles on OpenSSL when it does not
 * (probe().tls: reason 'fallback'). Without it, serve() makes the same move
 * for the first TLS server of a thread, as long as no other native function
 * has been taken from the module yet.
 */
export function selectTls(
  library: 'boringssl' | 'openssl' | 'auto',
  ssl?: ServeOptions['ssl']
): 'boringssl' | 'openssl' | 'auto';
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
  updateSsl: typeof updateSsl;
  getMethod: typeof getMethod;
  getBatchBuffers: typeof getBatchBuffers;
  getPath: typeof getPath;
  getQuery: typeof getQuery;
  getHeaders: typeof getHeaders;
  getHeader: typeof getHeader;
  getBody: typeof getBody;
  getBodyType: typeof getBodyType;
  getBodyText: typeof getBodyText;
  getBodyLent: typeof getBodyLent;
  getRemoteAddress: typeof getRemoteAddress;
  isAborted: typeof isAborted;
  respond: typeof respond;
  writeHead: typeof writeHead;
  write: typeof write;
  end: typeof end;
  setStaticRoute: typeof setStaticRoute;
  clearStaticRoutes: typeof clearStaticRoutes;
  setParamRoute: typeof setParamRoute;
  clearParamRoutes: typeof clearParamRoutes;
  prepareResponse: typeof prepareResponse;
  releaseTemplates: typeof releaseTemplates;
  respondPrepared: typeof respondPrepared;
  respondPreparedEmpty: typeof respondPreparedEmpty;
  writeHeadPrepared: typeof writeHeadPrepared;
  endWith: typeof endWith;
  upgradeToWebSocket: typeof upgradeToWebSocket;
  wsSend: typeof wsSend;
  wsClose: typeof wsClose;
  setWsAutoUpgrade: typeof setWsAutoUpgrade;
  wsGetHeaders: typeof wsGetHeaders;
  wsGetQuery: typeof wsGetQuery;
  wsGetRemoteAddress: typeof wsGetRemoteAddress;
  trimMemory: typeof trimMemory;
  probe: typeof probe;
  selectTls: typeof selectTls;
  version: string;
};

export default engine;
