# @morojs/engine — Threat Model

This document is the starting point for an external security reviewer and the engine's own record of its security posture. It describes what the engine does to defend itself against hostile network input, maps each defense to the code that implements it, and — just as importantly — states plainly where it does **not** defend and what a deployment must therefore provide.

> **Status honesty.** No external security review has been performed yet. This document *prepares* for one; it does not assert that one has happened. See [Testing & assurance](#testing--assurance) and the M5/M6 gates in [`ROADMAP.md`](ROADMAP.md).

Related: [`SECURITY.md`](../SECURITY.md) (reporting policy), [`DESIGN.md`](DESIGN.md) (architecture), [`CONTRIBUTING.md`](../CONTRIBUTING.md) (the non-negotiable "parser code lands with a fuzz harness" rule).

---

## Attack surface

The engine's job is to turn **raw, untrusted TCP bytes** into a safe, bounded request/message object for a JavaScript handler, and to serialize the handler's response back onto the wire. Everything hostile arrives as a byte stream on an accepted socket. That stream is parsed in hand-written C++ with manual memory management (raw V8 handles + libuv), which is precisely the code a reviewer should scrutinize hardest.

### Trust boundaries

```
  ┌──────────────┐   raw bytes   ┌──────────────┐   parsed view   ┌──────────────┐   snapshot   ┌──────────────┐
  │  Network      │ ───────────► │  Protocol     │ ─────────────► │  V8 boundary  │ ──────────► │  JS handler   │
  │  (untrusted)  │   libuv TCP  │  parsers (C++) │   bounded,     │  (binding.cpp)│   by reqId  │  (app code)   │
  │               │   server.h   │  http_parser.h │   validated    │               │             │               │
  │               │              │  websocket.h   │                │               │             │               │
  └──────────────┘              └──────────────┘                └──────────────┘             └──────────────┘
     TB0: attacker      TB1: only bounded,       TB2: only a numeric reqId/wsId    TB3: app trusts the engine to
     controls every     spec-validated data      crosses into V8; stale ids         have bounded/validated the
     byte and its        crosses out of the       resolve to a safe no-op            data; app owns its own logic
     arrival timing      parser
```

- **TB0 — Network → libuv/socket engine (`src/server.h`).** The attacker controls every byte, how it is fragmented across TCP segments, and its timing. The socket engine accepts connections, feeds bytes to the parser incrementally, writes responses in request order, and enforces connection lifecycle/timeouts.
- **TB1 — Socket → protocol parsers (`src/http_parser.h`, `src/websocket.h`).** The parsers are pure state machines (no I/O, no dependencies beyond the C++ standard library) so they can be unit-tested and fuzzed standalone. They are the primary memory-safety and protocol-correctness surface. Only bounded, validated data is allowed to cross out of them.
- **TB2 — Parser → V8 boundary (`src/binding.cpp`).** The only handle that crosses into JavaScript is an integer `reqId` (HTTP) or `wsId` (WebSocket). The binding resolves it back to a `Connection*` through a registry; a stale id resolves to `nullptr` and every accessor is a safe no-op.
- **TB3 — V8 boundary → JS handler (app code).** The handler receives a batched, already-validated request snapshot. Application logic (auth, injection, business rules) is **out of scope** for the engine (see [`SECURITY.md`](../SECURITY.md)).

---

## Threats considered & mitigations

Every mitigation below cites the code that implements it. Where a defense is partial or absent, that is stated here or in [Known limitations](#known-limitations--non-goals).

### 1. Memory-safety bugs in parsing (over-read / overflow / UAF)

Hand-written C++ parsing of attacker-controlled bytes is the highest-risk surface.

- **Incremental, bounds-checked state machines.** `HttpParser::parse` (`http_parser.h`) and `WsParser::consume` (`websocket.h`) consume bytes against explicit state enums and length counters; any byte of a header or frame may arrive in a separate call, and the parsers persist partial state (e.g. WebSocket `maskPos_` persists across `consume()` calls so a payload split anywhere still unmasks correctly). Payload/length reads are gated on "do we actually have this many bytes buffered" checks (`available < contentLength_`, `available < chunkRemaining_ + 2`, `cont >= n - i` for truncated UTF-8 sequences) before any access.
- **Failed-parser latch.** Once `WsParser` returns `false` it stays failed (`failed_`), so a caller cannot be tricked into feeding more bytes into a corrupt state.
- **libFuzzer + ASan/UBSan.** Both parsers ship libFuzzer harnesses (`test/fuzz/fuzz_http_parser.cc`, `test/fuzz/fuzz_websocket.cc`) that feed arbitrary bytes in randomized split sizes and assert the parser never crashes, over-reads, or hangs. `test/fuzz/run.sh` builds them with `-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all`, so **every fuzzed input is checked by AddressSanitizer and UndefinedBehaviorSanitizer.** See [Testing & assurance](#testing--assurance).

### 2. HTTP request smuggling / desync (RFC 9112 §6, §11.2)

`finalizeHeaders()` in `http_parser.h` implements the spec-mandated rejections (these are treated as hard requirements in `CONTRIBUTING.md`, not best-effort):

- **`Content-Length` + `Transfer-Encoding` together → reject (400).** If a `Transfer-Encoding` header is present and a `Content-Length` is also present, the request is rejected (RFC 9112 §6.1/§6.3.3).
- **Conflicting duplicate `Content-Length` → reject (400).** Every `Content-Length` is parsed; a second value that disagrees with the first is rejected (RFC 9112 §6.3.5). Empty or non-digit `Content-Length` is also a 400.
- **`Transfer-Encoding` other than `chunked` → reject (400).** Only `chunked` as the (final) transfer coding is accepted; anything else fails.
- **Whitespace before the header colon → reject.** `parseHeaderLine` validates the field name with `isTokenChar` (RFC 9110 §5.6.2), so a space/tab before the `:` — a classic smuggling/obs-fold vector — makes the name a non-token and the line is rejected (RFC 9112 §5.1). Header lines that begin with whitespace (obs-fold continuations) are rejected for the same reason.
- **Strict request-line and HTTP-version validation.** The method must be all token chars; the version must match `HTTP/1.<DIGIT>` exactly (else 400), and a non-`1` major version returns 505.
- **Strict chunked framing.** Chunk sizes are hex-validated, each chunk's trailing CRLF is required, and the terminating `0`-chunk + trailer are parsed explicitly (RFC 9112 §7.1). A stuck chunk-size line is bounded (a chunk-size line over 1 KiB without a newline is a 400).

> **Reviewer note (integer handling):** both length paths reject *inside* their accumulation loops. The chunked path checks `sz > maxBodySize` inside the hex loop; the fixed-length path checks `parsed > maxBodySize` after each `parsed = parsed*10 + digit` step, so the accumulator is bounded by `10*maxBodySize + 9` per iteration and cannot wrap `size_t` to a small value (which would desync the body length → request smuggling). Covered by regression tests: a 30-digit `Content-Length` is rejected 413 with the handler never invoked (`test/http-parser-unit.cpp`, `test/limits-conformance.test.mjs`).

### 3. Header / body denial-of-service (oversized requests)

Configurable limits in `HttpLimits` (`http_parser.h`), enforced during parsing:

- **Request head (request line + all headers):** `maxHeadSize` (default 64 KiB). Exceeding it returns **431 Request Header Fields Too Large**.
- **Header count:** `maxHeaders` (default 100). Exceeding it returns **431**.
- **Body:** `maxBodySize` (default 10 MiB), enforced for both `Content-Length` and chunked bodies (accumulated across chunks). Exceeding it returns **413 Content Too Large**.
- **Configurable at `serve()`:** every limit is read from the JS options object in `binding.cpp` (`Serve`) — `maxBodySize`, `maxHeadSize`, `maxHeaders`, `idleTimeoutMs`, `requestTimeoutMs`, `maxConnections`, `maxPendingBytes`, `wsMaxMessageSize`, `wsBackpressureLimit`, `writeHighWaterMark`, `backlog`. The values above are defaults, not caps; nonsensical values (e.g. `maxHeadSize: 0`) are ignored in favor of the default.

### 4. Slowloris / slow-drip connection starvation

- **Idle sweep timer (`server.h`).** `listen()` starts an unref'd periodic timer (`onSweep`) whose granularity adapts to the configured timeout (capped 4 s, floored 250 ms). Every sweep increments an `idleTicks` counter on each connection that is **not** actively running a handler; `onRead` resets `idleTicks` to 0 on any received bytes. A connection idle beyond `idleTimeoutMs` (default 120 s; `0` disables) is closed. The timer is unref'd so it never keeps the process alive on its own.
- This defeats the **classic** slowloris — open a socket and send nothing (or stop mid-request) — and caps keep-alive reuse of a silent connection.

> **Honest limitation:** because `idleTicks` resets on *any* read, a **slow-drip** attacker who trickles a byte before each sweep interval will not be reaped by this timer. The head/body size limits still bound the *total* bytes such a connection can consume (it eventually hits `maxHeadSize`/`maxBodySize`), but there is **no minimum-throughput enforcement and no total-request-time budget**. WebSocket connections are exempt from the sweep entirely (they may legitimately idle between messages). See [Known limitations](#known-limitations--non-goals).

### 5. WebSocket protocol attacks (RFC 6455)

`WsParser` (`websocket.h`) fails the connection on any of the following (each cites the RFC section in-code):

- **Unmasked client frame → fail (§5.1).** A client-to-server frame without the MASK bit set is a protocol error.
- **Reserved bits / reserved opcodes → fail (§5.2).** Any RSV bit set (no extension is ever negotiated) or any opcode outside `{0,1,2,8,9,A}` fails.
- **Control-frame limits → fail (§5.5).** A control frame (Close/Ping/Pong) with payload > 125 bytes or with FIN clear (fragmented) is rejected.
- **Fragmentation state machine (§5.4).** A continuation frame with no message in progress, or a new Text/Binary frame arriving mid-message, fails.
- **Length encoding (§5.2).** A 64-bit length with the high bit set, or a non-minimally-encoded extended length, fails.
- **UTF-8 validation (§5.6, §8.1).** Text-message payloads and Close-frame reason strings are validated with a RFC 3629 validator that rejects overlong encodings, surrogates, out-of-range code points, and truncated sequences. Validation runs on the *reassembled* message, so multi-byte sequences split across fragments are handled correctly.
- **Close-frame body sanity (§5.5.1).** A 1-byte close body (a status code must be 2 bytes) is rejected.
- **Max message size.** `WsParser::Limits::maxMessageSize` (default 16 MiB) is enforced across reassembled fragments, checked in `commitLength()` **before** any allocation and written to avoid `uint64` overflow.
- **Handshake accept key.** Computed with clean-room SHA-1 + Base64 (`sha1.h`); SHA-1 is used only for the RFC 6455 §4.2.2 accept-key ritual, not for any security property that relies on collision resistance (documented as such in `sha1.h`).

### 6. Resource exhaustion / connection lifecycle

- **One request in flight per connection (`server.h`).** Responses are returned in request order (RFC 9112 §9.3); the next pipelined request is not surfaced to JS until the current response fully flushes (`finishResponse`). This prevents request interleaving and unbounded concurrent handler fan-out per connection.
- **Backpressure.** Streaming `write`/`wsSend` report backpressure against a 256 KiB high-water mark and resume via `onWritable`, so a slow-reading client cannot force unbounded server-side write buffering silently (the app is told to pause).
- **Deterministic cleanup on close.** `doClose` erases the connection from the `globalRequests`/`globalWebSockets` registries and the live-connection set, stops reads, and frees the `Connection` (and its `WsParser`) in the libuv close callback. `Server::close()` iterates a snapshot of live connections and closes each, so no keep-alive socket keeps the loop alive after shutdown.

> **Hardened (v1.0):** bytes received while a response is in flight are now bounded by a per-connection `maxPendingBytes` cap (default `maxHeadSize + maxBodySize`; the connection is hard-closed on overflow), and a `maxConnections` cap drops accepts beyond the limit (0 = unlimited, matching Node's `http.Server` default). WebSocket sends are bounded by a 1 MiB write-queue cap (the slow consumer is shed with a 1013 close once the queue overflows). Per-server JS state (V8 `Global` callback/context handles) and the `Server`/`Connection` C++ objects are freed via deferred cleanup once every libuv handle is reaped — no leak across `serve()`/`close()` cycles. **Remaining:** `maxConnections` is opt-in (unlimited by default), and there is no per-request total-time / min-throughput timeout (the idle sweep reaps only silent connections; a steady byte-trickle within `idleTimeoutMs` is not reaped). Terminate untrusted traffic behind a proxy that adds request-time limits. See [Known limitations](#known-limitations--non-goals).

### 7. Use-after-free at the V8 boundary (stale reqId/wsId)

The only handle JS holds is an integer id; a response can be produced synchronously or much later (async), during which the request may have already ended or the socket aborted.

- **Registry indirection (`server.h` / `binding.cpp`).** `reqId → Connection*` and `wsId → Connection*` live in global registries. `connFrom`/`wsFrom` in `binding.cpp` call `Server::lookup`/`lookupWs`, which return `nullptr` when the id is absent.
- **Terminal removal.** A reqId is erased from `globalRequests` the moment its response finishes (`finishResponse`), on abort/close (`doClose`, `abortConnection`), and on WebSocket upgrade (the HTTP reqId is retired and a wsId is issued). A wsId is erased on close/abort.
- **Safe no-op on stale ids.** Every accessor and response function guards on `if (!c) return;` (or returns a benign default). `isAborted(reqId)` is implemented as "the id is no longer in the registry", which is exactly how a handler learns its request went away. So a handler that calls `respond()`, `write()`, `wsSend()`, etc. on an id that has already ended does nothing rather than dereferencing freed memory.
- **Handler exceptions are contained.** The binding wraps JS callbacks in a `TryCatch`; a throwing handler is logged to stderr and does not tear down the event loop or leave the connection in a half-open C++ state.

> **Reviewer note (id reuse):** `reqId`/`wsId` are monotonically increasing `uint32_t` counters. Wraparound would require ~4 billion requests, after which a new id could in principle collide with a still-live id in the registry. This is a theoretical concern worth a reviewer's eye, not a demonstrated issue.

---

## Known limitations & non-goals

Stated plainly. Several of these are the reason the engine should sit behind a proxy for untrusted-facing production today.

- **TLS termination — new trust boundary.** The engine terminates TLS in-process via `serve()` `options.ssl` (`src/tls.h`): OpenSSL is the one exported by the host Node binary (never vendored; headers come from the same Node version's tarball, so versions cannot skew), driven through a memory-BIO pair so the TLS layer is a pure transform with no socket access. Hardening defaults: TLS ≥ 1.2 (configurable floor), renegotiation and TLS-level compression disabled, server cipher preference, config errors throw from `serve()` (a misconfigured TLS server never silently boots as plaintext). A TLS handshake in progress counts against the `requestTimeoutMs` budget (handshake slow-drip is bounded with no extra knob); plaintext or garbage bytes on a TLS port get the OpenSSL alert and a close. Close: best-effort `close_notify` on teardown (truncation signaling). Not implemented: session resumption/tickets tuning, OCSP stapling, multi-identity SNI (one key/cert per server; SNI names are not dispatched). **The external-review gate below applies with extra force now that the engine parses TLS from untrusted peers — front with a proxy or review before exposing it raw.**
- **`permessage-deflate` (RFC 7692) — opt-in, off by default.** When *not* enabled it stays *declined* (no `Sec-WebSocket-Extensions` in the handshake; any RSV bit on the wire is a protocol error), preserving the compression-oracle-free default posture. When enabled via `options.wsDeflate`, inbound messages are inflated with a hard output cap (`maxDecompressedSize`, default `wsMaxMessageSize`) checked incrementally *before* allocation — a zip bomb hits close code 1009, not OOM — and text is UTF-8-validated after inflate (1007 on failure). Enabling it is a deliberate app decision (the compression side-channel is why it's off by default).
- **No HTTP/2 or HTTP/3.** Out of scope by design (MoroJS has a separate http2 server). The engine is HTTP/1.1 only.
- **No built-in *rate* limiting.** Per-IP/per-tenant rate limiting is the framework's/operator's responsibility, not the engine's. A **`maxConnections` cap** IS available (drops accepts beyond the limit) but defaults to unlimited, matching Node's `http.Server`; operators facing untrusted traffic should set it (or cap connections at a proxy).
- **Per-connection memory is bounded.** Head (64 KiB), body (10 MiB), and WebSocket message (16 MiB) default limits bound a single request/message; the `pending` pipelined-bytes buffer is bounded by `maxPendingBytes` (default head+body); WebSocket send backpressure is bounded by a 1 MiB write-queue cap (`wsBackpressureLimit`; `0` disables — an operator raising limits owns the memory math). Every one of these is run-time configurable via `serve()` options. The one un-capped-by-default axis is the *count* of live connections (see `maxConnections`, opt-in above).
- **Slow-drip is only partially mitigated.** As noted above, the idle timer reaps silent connections but not connections that trickle bytes; there is no minimum data-rate or total-request-time enforcement, and no per-handler response timeout (a handler that never responds holds its connection).
- **WebSocket protocol-violation close:** the engine sends a Close frame before tearing the connection down (§7.1.7 SHOULD) — `1009` for an oversized message, `1007` for invalid UTF-8 payload data, `1002` for other violations — then closes the TCP socket once it flushes, surfacing the same code to `onWsClose`. (A cleanly *received* Close frame is echoed per §5.5.1.)
- **Lenient line endings.** The HTTP parser splits on `\n` and strips an optional trailing `\r`, so a bare-LF line terminator is accepted. This is a minor leniency relative to strict CRLF (RFC 9112 §2.2); a reviewer should consider whether it creates a parsing differential with a stricter upstream proxy.
- **No external security review yet.** See below.

---

## Testing & assurance

What backs the claims above today, and what is still pending.

### Fuzzing

- **Harnesses:** `test/fuzz/fuzz_http_parser.cc` and `test/fuzz/fuzz_websocket.cc`. Each treats its first input byte as a chunk-size selector and replays the remaining bytes through the parser in randomized splits, exercising the incremental path (a header/frame byte can land in any `parse()`/`consume()` call). The HTTP harness also drives the keep-alive reset + pipelined-continuation path; the WebSocket harness asserts the parser stays failed after the first protocol error.
- **Sanitizers:** built with `-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all` (`test/fuzz/run.sh`), so ASan + UBSan check every input.
- **Seed corpora:** `test/fuzz/corpus/http` and `test/fuzz/corpus/ws` ship hand-authored seeds covering the interesting cases — smuggling vectors (`smuggle-cl-te.raw`, `smuggle-dual-cl-conflict.raw`, `te-not-chunked.raw`), whitespace-before-colon (`header-ws-before-colon.raw`), oversized head, chunked extensions/trailers, and (WS) bad opcodes, RSV set, unmasked text, oversized control frames, 1-byte close, and extended lengths.
- **Status / pending:** the harnesses run today via `npm run test:fuzz`. A **sustained, scheduled CI fuzz campaign with a persisted corpus** (beyond per-PR smoke) is a tracked **remaining** M5 item — see `ROADMAP.md` ("M5 remainder"). Do not read this section as "the parsers have been fuzzed for thousands of CPU-hours"; they have not yet.

### Conformance suites

Wire-level suites that talk to the engine over raw TCP sockets (no `http.request`), so framing and connection lifecycle are asserted byte-for-byte:

- `test/conformance.test.mjs` — **21** HTTP/1.1 cases (the M1 gate; DESIGN.md records 21/21 passing).
- `test/conformance-edge.test.mjs` — **17** additional edge cases.
- `test/ws-conformance.test.mjs` — **20** WebSocket cases.
- Standalone C++ unit tests: `test/http-parser-unit.cpp` and `test/websocket-unit.cpp` (DESIGN.md cites 91 HTTP parser checks and 183 WebSocket checks), run via `npm run test:unit`.

### Sanitizer-clean builds

The parsers are pure, dependency-light state machines specifically so they can be built and run under sanitizers. The fuzz harnesses build clean under ASan+UBSan (above), and the C++ unit suites are held to sanitizer-clean status (DESIGN.md notes the WebSocket suite is "ASan/UBSan clean"); a reviewer can rebuild `test/*-unit.cpp` with `-fsanitize=address,undefined` to re-verify.

### External review — NOT yet done

> **An external security review is recommended before relying on the engine for untrusted-facing production traffic (TLS-terminated), and it has NOT yet been performed.** It is an explicit remaining item in the M5 hardening milestone and a gate before M6/GA and before MoroJS flips its default engine (`ROADMAP.md`, `DESIGN.md`). Nothing in this repository should be read as a claim that such a review has occurred.

---

## Reviewer quick-start

Audit these first, in order — this is where hostile bytes are handled:

1. **`src/http_parser.h`** — the HTTP/1.1 state machine. Focus on `finalizeHeaders()` (smuggling rejections + Content-Length parsing/overflow), the chunked body loop, and all the `buf_`/`scanPos_`/`consumed_` index math.
2. **`src/websocket.h`** — `WsParser::consume`/`beginFrame`/`finishExtendedLength`/`commitLength`/`finishFrame`, the unmask loop, and `isValidUtf8`.
3. **`src/server.h`** — the libuv read/write paths (`onRead`, `writeOut`, `onWrite`), the `pending`/pipelining logic, the idle sweep, and connection teardown/registry bookkeeping (lifetime correctness).
4. **`src/binding.cpp`** — the V8 boundary: `extractBytes`, `buildHeaders`, the reqId/wsId lookups, and the `TryCatch` handler containment.
5. **`src/sha1.h`** — clean-room SHA-1/Base64 (correctness of the handshake key).

### Build

```sh
node tools/build.mjs          # build the addon for the running Node ABI
node test/smoke.mjs           # load + probe the built binary
```

### Run the parser fuzzers (ASan + UBSan + libFuzzer)

```sh
# Linux: stock clang ships the libFuzzer runtime.
sh test/fuzz/run.sh                       # ~60s each by default
SECONDS=600 sh test/fuzz/run.sh           # longer campaign

# macOS: Apple clang lacks libFuzzer; use Homebrew LLVM.
brew install llvm
CXX=/opt/homebrew/opt/llvm/bin/clang++ sh test/fuzz/run.sh
```

The seed corpora in `test/fuzz/corpus/{http,ws}` are replayed and then mutated; new coverage-expanding inputs are written back into them. A reviewer's own crash/regression inputs can be dropped into those directories.

### Run the conformance + unit suites

```sh
npm run test:unit             # standalone C++ parser + WebSocket unit tests
npm run test:conformance      # 21 HTTP/1.1 wire-level cases
npm run test:conformance-edge # 17 HTTP edge cases
npm run test:ws-conformance   # 20 WebSocket cases

# Re-verify the unit tests under sanitizers:
clang++ -std=c++20 -O1 -fsanitize=address,undefined \
  test/http-parser-unit.cpp -o /tmp/hp && /tmp/hp
clang++ -std=c++20 -O1 -fsanitize=address,undefined \
  test/websocket-unit.cpp -o /tmp/ws && /tmp/ws
```
