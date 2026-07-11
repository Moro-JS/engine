// Type definitions for @morojs/engine.
// The Moro-shaped native HTTP/1.1 + WebSocket binding (see docs/API.md).

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
  /** Load failure detail when ok is false */
  error?: string;
}

export interface ServeCallbacks {
  /** A complete request (head + body) arrived. methodIdx indexes
   *  ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','OTHER']. */
  onRequest(reqId: number, methodIdx: number, path: string): void;
  /** The client disconnected before the response completed. */
  onAborted(reqId: number): void;
  /** A backpressured write() drained; safe to write more. */
  onWritable(reqId: number): void;
  /** WebSocket opened after a successful Upgrade. */
  onWsOpen?(wsId: number, path: string): void;
  /** WebSocket message (text -> string, binary -> ArrayBuffer). */
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
  /** Bind with SO_REUSEPORT so several engine instances (worker threads or
   *  processes) can share one port with kernel-load-balanced accepts —
   *  required for clustering. POSIX only; ignored on Windows. Default false. */
  reusePort?: boolean;
  /** Max bytes for the request line + all headers; larger heads are rejected
   *  (431). Must be > 0. Default 65536. */
  maxHeadSize?: number;
  /** Max header count; more is rejected (431). Must be > 0. Default 100. */
  maxHeaders?: number;
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

// ---- WebSocket (RFC 6455) ----
/** Upgrade the request's connection; returns wsId, or -1 if not a valid upgrade. */
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
  upgradeToWebSocket: typeof upgradeToWebSocket;
  wsSend: typeof wsSend;
  wsClose: typeof wsClose;
  probe: typeof probe;
  version: string;
};

export default engine;
