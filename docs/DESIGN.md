# @morojs/engine — Design

MoroJS's native HTTP engine: Moro-authored C++ with raw-V8 bindings (per-ABI builds, chosen for maximum performance including V8 Fast API calls), exposing a **Moro-shaped batched API** rather than a general-purpose server surface.

Goal: saturate the hardware (~105k req/s hello-world reference ceiling on the benchmark rig) with an API that needs **2–4 JS boundary crossings per request** instead of the ~10–20 a general-purpose binding needs.

## Architecture (three layers)

### L1 — Socket/event layer
- Integrates with Node's own libuv loop (`uv_poll` on the main loop; libuv ships with Node's headers and is the platform API).
- Two transports behind one seam (`TransportKind` per server, `src/server.h`): **libuv streams** everywhere (the default), and **io_uring** on Linux 6.1+ (`src/uring.h`, a hand-rolled ring with no liburing dependency), opt-in in 1.1.6 through `MORO_ENGINE_TRANSPORT=uring` (see "io_uring measurements" below for why it is not auto-selected yet). The ring is probed once per process at the first `listen()` — mandatory setup flags (`SINGLE_ISSUER | COOP_TASKRUN | TASKRUN_FLAG`; not `DEFER_TASKRUN`, which never wakes an epoll-driven loop), required features, opcode probe, a provided-buffer ring, and a socketpair self-test — and any refusal (`EPERM` under Docker's default seccomp profile, `ENOSYS` under gVisor, `EINVAL` on older kernels) silently selects libuv. One ring per loop thread, driven from the same libuv loop (`uv_poll` on the ring fd, `uv_prepare` flushes SQEs before the loop blocks), multishot accept and multishot recv into kernel-provided buffers, one in-flight `SEND` per connection, shutdown(2)-then-cancel-close on teardown (the FIN goes out synchronously, so the server still closes first on a `Connection: close` exchange). Byte streams are identical across transports (`test/transport-parity.test.mjs`); `probe().transport` says which one is live and `transportReason` why.
- Accept, per-socket state machines, corked writes, backpressure, idle/slowloris timeouts, graceful shutdown.
- **`TCP_NODELAY` is inherited, not set per connection**: the listening socket carries it (uv arm: `listen()`; io_uring arm: `uringListen`) and Linux and XNU copy it to every accepted socket, which `test/sockopt-unit.cpp` verifies on the running kernel — one `setsockopt` less on every accept (Windows keeps `uv_tcp_nodelay` per socket).
- **The FIN rides with the last bytes of a `Connection: close` response, and the connection then lingers** (`tTryWriteLast`, `closeAfterResponse`). macOS: `TCP_NOPUSH` on, `send`, `TCP_NOPUSH` off, `shutdown(SHUT_WR)` — XNU does not run `tcp_output` when the option is cleared, and a `send(MSG_EOF)` under `TCP_NOPUSH` stays held too; the pending FIN is what pushes data + FIN as one segment. Linux: `send(MSG_MORE)` + `shutdown(SHUT_WR)`. So the peer can never close first: two segments a few microseconds apart let a fast client (wrk, oha) become the active closer and hold the TIME_WAIT, and on macOS, with no port reuse, a churning client then drains its 16k ephemeral ports (measured: 5.8k conn/s over 40 s; 27.5k after, ahead of Bun's 25.9k and uWS's 23.5k on the same harness). After the FIN the socket is **not** closed: it lingers with its input discarded until the peer's FIN arrives or `kLingerMs` (2 s, the sweep's granularity floor) passes — RFC 9112 §9.6's staged close. A client that writes its next request the moment a response completes, before it has seen the FIN (autocannon does exactly this), would otherwise have that request answered by the kernel with a RST, and a RST discards whatever of the response the client has not yet read. Measured with autocannon and `connection: close`: one error per connection and two reconnects per cycle before, none after. uWebSockets.js and node:http linger the same way; Bun.serve resets. Lingering connections count against `maxConnections` and are bounded by the deadline (THREAT_MODEL §6). TLS keeps the close_notify-then-close sequence, WebSockets the Close-frame sequence.
- Multi-core via SO_REUSEPORT: one engine per worker **thread** (MoroJS 1.9+, one process, shared code pages) or per worker process. A server still open when its thread's environment is torn down is closed by an environment cleanup hook (`capabilities.workerThreads`), so `worker.terminate()` never leaves libuv handles behind.

### L2 — Protocol engine
- HTTP/1.1: incremental SIMD-friendly parser; strict RFC 9112 (hard-reject conflicting Content-Length/Transfer-Encoding), header count/size limits, keep-alive, chunked bodies.
- WebSocket: RFC 6455 framing + permessage-deflate (zlib), Autobahn-validated.
- TLS: BoringSSL as a linked dependency (nobody writes TLS from scratch).
- Out of scope: HTTP/3/QUIC; HTTP/2 (MoroJS has a separate http2 server).

### L3 — Raw-V8 binding layer (per-ABI, Moro-shaped)
- **Batched request snapshot**: one crossing delivers method/URL/query/headers as offsets into a single external ArrayBuffer. No per-header calls; no "request dies after the callback returns" hazard.
- **Single corked response write**: status + headers + body in one call — matches MoroJS's build-then-write-once response pattern. **V8 fast API calls** (1.1.6) on the hot calls (`respondPrepared`, `respondPreparedEmpty`, `writeHeadPrepared`, `write`, `end`, `endWith`, `isAborted`): an optimised caller reaches the engine's C++ directly, with no callback machinery. Their precondition is that no binding call can re-enter JS, which is why `onAborted`/`onWritable` are delivered from a `uv_async` on a later loop turn (`capabilities.asyncNotify`). The per-tag `v8-fast-api-calls.h` is fetched sha-pinned at build time (Node's headers tarball omits it) and the targets install only when the host V8 matches the compiled one.
- **Prepared response templates** (1.1.6): the fixed part of a response (status + app header block) is materialised once (`prepareResponse`) and replayed per request (`respondPrepared`) — byte-identical to `respond()`, minus the per-request header walk. **Static routes** (`setStaticRoute`) are a template plus a fixed body answered inside the engine before the request reaches JS.
- **Batched pipelined dispatch** (1.1.6, `capabilities.batchDispatch`): complete pipelined requests are parsed into a per-connection staging ring (16 slots; a `Connection: close` or `Upgrade` request ends the batch) and delivered in ONE `onRequestBatch(count)` call over engine-owned buffers — three `Uint32` per slot (reqId, method, interned path index) plus a control cell the engine advances as each synchronous response completes, so JS answers in order and stops at the first async handler (the rest are re-delivered when its response completes). Only the active slot's id is registered; static routes are answered by the engine inside the batch; the bytes match sequential dispatch exactly (`test/batch-dispatch.test.mjs`). `MORO_ENGINE_BATCH=0` restores one call per request. Gate (2026-09-11, M2 Ultra, wrk -c100, same binary, batch off → on, best of 3 / median): raw engine pipelined ×10 893.7k → 935.1k (+4.6%) / 881.0k → 915.5k (+3.9%), MoroJS-on-engine 887.2k → 935.0k (+5.4%) / 880.8k → 912.8k (+3.6%); plain 114.1k → 113.6k and 113.3k → 114.1k (within ±1%), CPU/req unchanged at 8.5 µs. The plan's bar was +5% on the median; the gain is consistent but sits just under it — the staging code ships behind the kill switch pending sign-off.
- **Stream hooks**: onWritable/tryEnd-style backpressure + native file streaming, shaped so the JS adapter can present real Node-stream semantics (write/writeHead/'finish'/'close'/'drain', pipe target).
- Body delivery: batched chunks; multipart parsing stays JS-side (shared MoroJS util).

### io_uring measurements (2026-09-11)

Same binary, same box, transport switched by `MORO_ENGINE_TRANSPORT`: Docker
Desktop VM (linuxkit 6.12, arm64, 8 vCPU), `node:24-bookworm`, seccomp
unconfined, `bench/transport-ab.sh --runs 3 --duration 10` (oha 1.16, median
of 3) and `bench/syscalls.sh` (strace -c). Numbers are relative, not absolute
(a VM on a shared host).

| shape | conc | libuv rps / p99 / CPU µs/req | io_uring rps / p99 / CPU µs/req |
|---|---|---|---|
| keep-alive | 64 | 171.5k / 0.75 ms / 5.83 | 199.0k / 0.41 ms / 5.02 |
| keep-alive | 256 | 194.6k / 2.15 ms / 5.11 | 166.7k / 1.81 ms / 5.99 |
| keep-alive | 512 | 179.6k / 4.17 ms / 5.53 | 181.4k / 3.51 ms / 5.48 |
| conn/req | 64 | 77.1k / 0.93 ms / 12.95 | 69.4k / 1.13 ms / 14.39 |
| conn/req | 256 | 78.1k / 3.51 ms / 12.77 | 64.4k / 4.44 ms / 15.49 |
| conn/req | 512 | 78.6k / 6.97 ms / 12.65 | 63.2k / 9.07 ms / 15.73 |
| fixed 20k rps | 256 | 20.0k / 1.13 ms / 15.45 | 20.0k / 2.07 ms / 22.03 |

Syscalls per request: keep-alive 2.02 (read + write) → 1.00 (sendto; recv is
multishot, ~0 `io_uring_enter`); conn/req 8.0 (accept4, epoll_ctl,
setsockopt, read, write, epoll_ctl, close, epoll_wait) → 3.0 (sendto,
shutdown, amortised enter). The syscall goal is met; the CPU is not: each
multishot completion costs a task-work round trip (`io_poll_wake` → task work
→ re-issue → CQE post → poll re-arm) that only amortises when many
completions land per loop turn, so io_uring wins at 64 and 512 keep-alive
connections and loses everywhere the batches are small - including the
fixed-rate cell, where it burns ~40% more CPU per request. Two bugs were
found and fixed on the way: `IORING_SETUP_DEFER_TASKRUN` never wakes an
epoll-driven loop (completions only materialise inside an explicit
`io_uring_enter`), and a close submitted at the end of a reap round loses the
FIN race to a fast peer on `Connection: close` (the peer inherits TIME_WAIT
and a churn load throttles itself on ephemeral ports: 24k vs 100k conn/s
until the transport `shutdown(SHUT_WR)`s synchronously). A later run with
`TCP_NODELAY` inherited from the listener (one `setsockopt` fewer per
accept) narrowed the churn gap to 85.4k vs 91.6k conn/s at c=64 and put
keep-alive c=64 at 247k vs 179k. Go/no-go (`transport-ab.sh` header): not met
→ libuv stays the default, io_uring ships opt-in with the full test matrix
behind it. Follow-ups that could flip it:
`DEFER_TASKRUN` behind a registered eventfd (task work batched inside our own
`enter`), ring-submitted sends batched per loop turn (`SUBMIT_ALL`), and
`IORING_RECVSEND_BUNDLE` on 6.10+. The full-framework Linux matrix on the
same VM (MoroJS-on-engine vs raw Bun.serve, both transports, worker-thread
clustering) lives in the MoroJS Benchmark repo, `candidates/2026-09-11/`.

Of those follow-ups, ring-batched sends were already in place (a SEND SQE is
only prepared at issue time; the reap loop's next `enter` submits every SQE
of the round, hence the 1.00 syscalls/req above), and `RECVSEND_BUNDLE` cannot
help a one-request-in-flight keep-alive shape (each recv completes with one
small request; there is nothing to bundle). `DEFER_TASKRUN` behind a
registered eventfd is implemented as the ring's first-choice mode (`uring.h`,
"Ring modes"; `probe().transportMode` reports which one is running):
completions stay queued as local task work until the engine's own
`io_uring_enter(GETEVENTS)` runs them as one batch, so the per-completion
round trip that cost the CPU above is paid once per wake. The 1.1.6 mode
remains selectable with `MORO_ENGINE_URING_TASKRUN=coop` for A/B runs.

## Milestones (benchmark/conformance-gated)

- **M0 — bring-up** ✅: build driver + ABI matrix (115/127/131/137/141/147), probe() binding, packaging layout, CI skeleton, smoke matrix.
- **M1 — plaintext HTTP/1.1 core** ✅: accept/parse/keep-alive/batched boundary/route dispatch. Parser (`src/http_parser.h`, 91 unit checks), libuv socket engine (`src/server.h`), raw-V8 binding (`src/binding.cpp`). **Gate PASSED**: 21/21 HTTP conformance (`test/conformance.test.mjs`) and hello-world throughput at the benchmark rig's ceiling (engine ~86–91k req/s; MoroJS full stack on-engine ~78–80k).
- **M2 — streaming** ✅: writeHead/write/end with backpressure via libuv `onWritable` → drain, chunked transfer encoding, native Date/Content-Length, HEAD body suppression, Expect: 100-continue. Drives MoroJS SSE/range/sendFile middleware (verified by `tests/integration/engine-streaming.test.ts`).
- **M3 — TLS** ✅: in-process termination via `serve()` `options.ssl` — OpenSSL from the host Node binary (never vendored), a memory-BIO transform (`src/tls.h`), ALPN, and HTTPS+WSS conformance + hardening suites + `fuzz_tls_transport`. SNI multi-identity is out of scope (one key/cert per server). See `docs/ROADMAP.md`.
- **M4 — WebSocket** ✅ (protocol): RFC 6455 framing + handshake
  (`src/websocket.h`/`src/sha1.h`, 183 unit checks, ASan/UBSan clean), integrated into the engine (upgrade, ping/pong, close, binary+text) and MoroJS via `EngineWebSocketAdapter`. End-to-end verified with the `ws` client and `tests/integration/engine-websocket.test.ts`. permessage-deflate is shipped (opt-in via `options.wsDeflate`, off by default; `src/ws_deflate.h`).
- **M5 — hardening** ✅: libFuzzer harnesses + seed corpus for both parsers (`test/fuzz/`), nightly CI fuzz + sanitizer jobs, ASan/UBSan clean, idle/ slowloris timeout, functional load soak (no crash/hang/leak), `SECURITY.md` + `docs/THREAT_MODEL.md`. Found+fixed a Content-Length overflow smuggling bug during the threat-model pass. As with any TLS-terminating software, a formal independent security audit is recommended for the highest-assurance untrusted-facing deployments.
- **M6 — GA 1.0.0** ✅: the first published release — HTTP/1.1, WebSocket (+ permessage-deflate), in-process TLS, and fully runtime-configurable limits behind a stable surface. MoroJS ships the engine as its default (`engine: 'moro'`) with automatic Node.js fallback.
- **1.1.6 — the JS boundary and the toolchain**: deferred `onAborted`/`onWritable` delivery (never re-entrant from a binding call), prepared response templates + static routes, V8 fast API calls on the hot entry points, zero-copy string bodies through `String::ValueView` (Node 23+) with the Node 25/26 write API fixed, an environment cleanup hook that makes the engine safe inside `worker_threads`, HTTP/1.1 keep-alive responses without a redundant `Connection: keep-alive` line, an export-drift gate (`tools/check-exports.mjs`), and a PGO release toolchain (clang + lld, `tools/pgo.mjs`). Wire bytes are proven identical across every response path by `test/wire-parity.test.mjs`.

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
