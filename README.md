# @morojs/engine

MoroJS's native HTTP engine: a Moro-authored C++ core with raw-V8 bindings,
built for maximum throughput with an API shaped exactly for how MoroJS serves
requests. MIT licensed.

**Status: GA (1.1.x).** HTTP/1.1 + WebSocket cores (with permessage-deflate),
in-process TLS/HTTPS/WSS, fully configurable limits, hardening, sanitizers,
fuzzing, and the release pipeline are all shipped (M0–M6 complete). 1.1.0 added
pipelined response corking and a zero-allocation hot path (~3.7× pipelined
throughput vs 1.0.0). 1.1.6 takes on the JS boundary itself: prepared response
templates and static routes, V8 fast API calls on the hot entry points,
deferred `onAborted`/`onWritable` delivery, zero-copy string bodies, a
teardown hook that makes the engine safe inside `worker_threads` (MoroJS
clusters with threads on it), and PGO-trained release binaries - with every
response path proven byte-identical on the wire. Measured comparisons live in the
[MoroJS Benchmark repo](https://github.com/Moro-JS/benchmark). In progress:
ALPN HTTP/2 (vendored nghttp2). See [docs/DESIGN.md](docs/DESIGN.md) and
[docs/ROADMAP.md](docs/ROADMAP.md).

## Why

- MoroJS's framework overhead is already ~zero; the remaining performance
  ceiling **is** the engine. Owning it is the only lever left.
- Owning the binaries means day-one support for every Node release —
  off-the-shelf native bindings routinely lag (no prebuilt binary for the
  Node 25 / ABI 141 line for months).
- The Moro-shaped boundary (batched request snapshot, single corked response
  write) needs 2–4 JS crossings per request vs ~10–20 for a general-purpose
  binding.
- Two transports behind one seam: libuv streams (the default everywhere) and
  an opt-in io_uring transport on Linux 6.1+ (`MORO_ENGINE_TRANSPORT=uring`:
  multishot accept/recv, half the syscalls per request) — identical bytes on
  the wire, the whole test matrix on both, `probe().transport` reporting which
  is live. Measured numbers and why libuv stays the default: docs/DESIGN.md.

## Usage (with MoroJS)

MoroJS installs `@morojs/engine` by default and falls back to Node's http
server automatically wherever a prebuilt binary isn't available:

```js
// moro config
server: {
  engine: 'moro',   // default - native engine when loadable, Node http otherwise
  // engine: 'node' - always use Node http
  // engine: 'uws'  - opt in to uWebSockets.js
}
```

MoroJS always degrades to the Node `http` server when the native engine can't
load (the reason is logged at startup and exposed via
`app.engine.fallbackReason`); there is **no** "fail fast" engine value. The
legacy `'auto'`/`'native'` values map to `'moro'` with a deprecation warning.
See [`packages/engine/README.md`](packages/engine/README.md) for the canonical
config reference.

## Development

```bash
node tools/build.mjs     # build for the running Node ABI (downloads headers)
node test/smoke.mjs      # load + probe the binary
node tools/build.mjs --all   # full ABI matrix
npm test                 # C++ units, smoke, every node --test suite
npm run check:exports    # the native surface is identical in binding/index.js/index.mjs/index.d.ts
node tools/pgo.mjs --strict   # profile-guided build cycle (clang; what the release lanes do)
tools/dev-linux.sh       # the same build + tests inside a Linux container (io_uring, seccomp fallback, --musl)
```

Prebuilt binaries ship only from tagged CI runs with npm provenance — never
from developer machines, never committed to git.

## Acknowledgments

Hats off to [uWebSockets](https://github.com/uNetworking/uWebSockets) for years
of showing what high-performance networking on Node and V8 can look like. Moro's
engine is its own implementation, but that's prior art worth acknowledging.
