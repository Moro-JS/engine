# @morojs/engine — Roadmap

Status snapshot (see `docs/DESIGN.md` for the full milestone definitions).
**Shipped in 1.0.0** — HTTP/1.1 + WebSocket (+ permessage-deflate) +
in-process TLS/HTTPS/WSS + full runtime limit configurability, hardened with
fuzzing and sanitizers. In progress: ALPN HTTP/2 (vendored nghttp2) and the
Windows (MSVC) CI build leg (the local build has landed in `tools/build.mjs`).

| Milestone | Status | Notes |
|-----------|--------|-------|
| M0 bring-up | ✅ done | build driver, 6-ABI matrix (Node 20–26), packaging, probe() |
| M1 HTTP/1.1 core | ✅ done | parser + libuv engine + V8 binding; 21/21 conformance; **benchmark gate passed** (hello-world throughput ceiling met) |
| M2 streaming | ✅ done | writeHead/write/end, backpressure, chunked, HEAD, 100-continue, sendFile |
| M3 TLS | ✅ done | `serve()` `options.ssl` (both MoroJS shapes), OpenSSL from the host Node binary, memory-BIO transform (`src/tls.h`), ALPN, HTTPS+WSS conformance + hardening suites + `fuzz_tls_transport`. SNI multi-identity not implemented (one key/cert per server). |
| M4 WebSocket | ✅ done | RFC 6455 framing/handshake, integrated, `EngineWebSocketAdapter`; socket conformance green; failure closes carry 1002/1007/1009 per §7.4.1; permessage-deflate shipped (opt-in) |
| M5 hardening | ✅ done | libFuzzer harnesses + corpus, ASan/UBSan clean, idle/slowloris timeout, CI fuzz/sanitizer jobs, SECURITY.md + THREAT_MODEL.md; found+fixed a Content-Length overflow smuggling bug. External review recommended before untrusted-facing TLS production (a human gate, not yet done). |
| M6 GA 1.0.0 | ✅ done | first published release; stable surface; every cap runtime-configurable via serve() options; `probe().capabilities` feature flags; MoroJS ships the engine as its default (`engine: 'moro'`) with Node fallback |

## Beyond 1.0

1.0.0 is a complete HTTP/1.1 + WebSocket + TLS engine. On the list next:

- **ALPN HTTP/2** (vendored nghttp2) — in progress.
- **Windows (MSVC) CI build leg** — the local build lands in `tools/build.mjs`;
  wiring the CI matrix leg is the remaining packaging work.
- **SNI multi-identity** — one key/cert per server today; per-SNI dispatch is future.
- **External security review** before untrusted-facing production — a human gate,
  not self-certifiable.
- **max-connections cap + per-request total-time / min-throughput timeouts** —
  the idle sweep reaps silent connections but not a steady byte-trickle.

## How the 1.0 features landed

### TLS

Landed as designed, with two deviations from the sketch below: the entry point
is `serve()` `options.ssl` rather than a separate `serveTLS()` (additive, and
MoroJS passes one options object either way), and SNI multi-identity dispatch
was dropped from scope (one key/cert per server; run one server per identity).
The original plan, for the record:

1. **Link a TLS library.** BoringSSL as a vendored submodule (as planned), or
   — cheaper — link against the OpenSSL that Node already bundles and ships in
   its headers (`openssl/ssl.h` is available in the Node header tarball we
   already download). Using Node's OpenSSL avoids vendoring a large tree and a
   second build, at the cost of coupling to Node's OpenSSL version. Recommend
   **starting with Node's bundled OpenSSL** and revisiting BoringSSL only if a
   feature gap appears.
2. **TLS state machine in the Connection.** A `SSL*` per connection; on read,
   feed ciphertext into a memory BIO, pull plaintext out into the existing
   `HttpParser`/`WsParser`; on write, push plaintext through `SSL_write` and
   flush the output BIO to the socket. The read/write paths in `server.h`
   already funnel through `feedWebSocket`/`onRead` and `writeOut`, so this is a
   localized insertion (an "encrypt on the way out, decrypt on the way in"
   shim), not a rewrite.
3. **Handshake + SNI.** `SSL_accept` non-blocking, driven by socket readability;
   `SSL_CTX` built from `key_file_name`/`cert_file_name` (the config fields
   already exist and flow through `MoroEngineServer`'s `ssl` option, currently
   warned-as-unsupported). SNI via `SSL_CTX_set_tlsext_servername_callback`.
4. **`SSLApp`-equivalent entry point** in the binding: `serveTLS(callbacks,
   {key_file_name, cert_file_name, passphrase})`.

### permessage-deflate

WebSocket compression (RFC 7692) is now supported, opt-in via
`options.wsDeflate` (off by default preserves the declined-extension posture).
Per-connection zlib inflate/deflate over raw-deflate streams (`src/ws_deflate.h`),
negotiated at upgrade, with a hard inflate output cap (zip-bomb → 1009) and
post-inflate UTF-8 validation (→ 1007). zlib links the copy inside the host
Node binary, same model as TLS. Covered by `ws-deflate-unit.cpp`,
`ws-deflate-conformance.test.mjs`, and `fuzz_ws_deflate`.

### Hardening (done in 1.0; ongoing)

Completed for 1.0:
- libFuzzer harnesses (`test/fuzz/`) for both parsers + a seed corpus
  (`test/fuzz/corpus/{http,ws}`), run nightly in CI (`.github/workflows/fuzz.yml`)
  with a persisted/accumulating corpus.
- ASan/UBSan: the C++ unit tests build clean under sanitizers (CI
  `sanitizers.yml`); the parsers verified clean over millions of adversarial
  inputs; a functional load soak drives the connection lifecycle (concurrency,
  keep-alive, aborts, slowloris, streaming, smuggling, shutdown-with-live-conns)
  with no crash/hang/leak.
- Idle/slowloris timeout (`idleTimeoutMs`, adaptive unref'd sweep).
- `SECURITY.md` + `docs/THREAT_MODEL.md` (attack surface, mitigations mapped to
  code, honest limitations, reviewer quick-start).
- Fixed a real Content-Length integer-overflow → request-smuggling bug found via
  the threat-model pass (reject during digit accumulation, regression-tested).

Ongoing / recommended:
- **External security review** before relying on the engine for untrusted-facing
  production traffic — a human gate, not self-certifiable.
- max-connections cap and per-request total-time / min-throughput timeouts (the
  idle sweep reaps silent connections but not steady byte-trickle).

## Platform coverage

Binaries build locally for darwin/arm64 across all 6 ABIs. The CI matrix
(`.github/workflows/build.yml`) covers darwin x64+arm64, linux gnu x64+arm64,
linux musl x64, and a Node 20–26 smoke matrix. Windows (MSVC) is the one
remaining build leg to wire up.
