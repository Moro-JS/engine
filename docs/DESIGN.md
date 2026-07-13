# @morojs/engine — Design

MoroJS's native HTTP engine: Moro-authored C++ with raw-V8 bindings (per-ABI builds, chosen for maximum performance including V8 Fast API calls), exposing a **Moro-shaped batched API** rather than a general-purpose server surface.

Goal: saturate the hardware (~105k req/s hello-world reference ceiling on the benchmark rig) with an API that needs **2–4 JS boundary crossings per request** instead of the ~10–20 a general-purpose binding needs.

## Architecture (three layers)

### L1 — Socket/event layer
- Integrates with Node's own libuv loop (`uv_poll` on the main loop; libuv ships with Node's headers and is the platform API).
- Accept, per-socket state machines, corked writes, backpressure, idle/slowloris timeouts, graceful shutdown.
- Multi-core via SO_REUSEPORT worker processes (MoroJS already has the clustering harness).

### L2 — Protocol engine
- HTTP/1.1: incremental SIMD-friendly parser; strict RFC 9112 (hard-reject conflicting Content-Length/Transfer-Encoding), header count/size limits, keep-alive, chunked bodies.
- WebSocket: RFC 6455 framing + permessage-deflate (zlib), Autobahn-validated.
- TLS: BoringSSL as a linked dependency (nobody writes TLS from scratch).
- Out of scope: HTTP/3/QUIC; HTTP/2 (MoroJS has a separate http2 server).

### L3 — Raw-V8 binding layer (per-ABI, Moro-shaped)
- **Batched request snapshot**: one crossing delivers method/URL/query/headers as offsets into a single external ArrayBuffer. No per-header calls; no "request dies after the callback returns" hazard.
- **Single corked response write**: status + headers + body in one call — matches MoroJS's build-then-write-once response pattern. V8 Fast API variants on the hot calls (fast calls take primitives/TypedArrays and can't re-enter JS; the batched design fits those constraints exactly).
- **Native route-map fast path**: listen-time route registration returns integer IDs; dispatch indexes a JS handler array.
- **Stream hooks**: onWritable/tryEnd-style backpressure + native file streaming, shaped so the JS adapter can present real Node-stream semantics (write/writeHead/'finish'/'close'/'drain', pipe target).
- Body delivery: batched chunks; multipart parsing stays JS-side (shared MoroJS util).

## Milestones (benchmark/conformance-gated)

- **M0 — bring-up** ✅: build driver + ABI matrix (115/127/131/137/141/147), probe() binding, packaging layout, CI skeleton, smoke matrix.
- **M1 — plaintext HTTP/1.1 core** ✅: accept/parse/keep-alive/batched boundary/route dispatch. Parser (`src/http_parser.h`, 91 unit checks), libuv socket engine (`src/server.h`), raw-V8 binding (`src/binding.cpp`). **Gate PASSED**: 21/21 HTTP conformance (`test/conformance.test.mjs`) and hello-world throughput at the benchmark rig's ceiling (engine ~86–91k req/s; MoroJS full stack on-engine ~78–80k).
- **M2 — streaming** ✅: writeHead/write/end with backpressure via libuv `onWritable` → drain, chunked transfer encoding, native Date/Content-Length, HEAD body suppression, Expect: 100-continue. Drives MoroJS SSE/range/sendFile middleware (verified by `tests/integration/engine-streaming.test.ts`).
- **M3 — TLS** ✅: in-process termination via `serve()` `options.ssl` — OpenSSL from the host Node binary (never vendored), a memory-BIO transform (`src/tls.h`), ALPN, and HTTPS+WSS conformance + hardening suites + `fuzz_tls_transport`. SNI multi-identity is out of scope (one key/cert per server). See `docs/ROADMAP.md`.
- **M4 — WebSocket** ✅ (protocol): RFC 6455 framing + handshake
  (`src/websocket.h`/`src/sha1.h`, 183 unit checks, ASan/UBSan clean), integrated into the engine (upgrade, ping/pong, close, binary+text) and MoroJS via `EngineWebSocketAdapter`. End-to-end verified with the `ws` client and `tests/integration/engine-websocket.test.ts`. permessage-deflate is shipped (opt-in via `options.wsDeflate`, off by default; `src/ws_deflate.h`).
- **M5 — hardening** ✅: libFuzzer harnesses + seed corpus for both parsers (`test/fuzz/`), nightly CI fuzz + sanitizer jobs, ASan/UBSan clean, idle/ slowloris timeout, functional load soak (no crash/hang/leak), `SECURITY.md` + `docs/THREAT_MODEL.md`. Found+fixed a Content-Length overflow smuggling bug during the threat-model pass. As with any TLS-terminating software, a formal independent security audit is recommended for the highest-assurance untrusted-facing deployments.
- **M6 — GA 1.0.0** ✅: the first published release — HTTP/1.1, WebSocket (+ permessage-deflate), in-process TLS, and fully runtime-configurable limits behind a stable surface. MoroJS ships the engine as its default (`engine: 'moro'`) with automatic Node.js fallback.

## Packaging

esbuild-style: `@morojs/engine` meta package (loader + types) with per-platform packages as exact-version optionalDependencies:

```
@morojs/engine-darwin-arm64      @morojs/engine-linux-x64-gnu
@morojs/engine-darwin-x64        @morojs/engine-linux-arm64-gnu
@morojs/engine-win32-x64         @morojs/engine-linux-x64-musl
@morojs/engine-linux-arm64-musl
```

Each platform package carries one binary per supported ABI:
`moro_engine_<platform>_<arch>_<abi>.node`. ABI policy: 115/127/131/137/141/147 (Node 20/22/23/24/25/26); new Node major = one TARGETS line + CI run + minor release. The loader is libc-aware (glibc vs musl via `process.report`) and exports non-throwing `probe()` diagnostics that MoroJS's preflight consumes.

## Versioning

Independent semver. `0.x` through the milestones, `1.0.0` at M6.
New Node ABI → minor; rebuilds/fixes → patch; API break → major.
