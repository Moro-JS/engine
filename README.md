# @morojs/engine

MoroJS's native HTTP engine: a Moro-authored C++ core with raw-V8 bindings,
built for maximum throughput with an API shaped exactly for how MoroJS serves
requests. MIT licensed.

**Status: GA (1.1.x).** HTTP/1.1 + WebSocket cores (with permessage-deflate),
in-process TLS/HTTPS/WSS, fully configurable limits, hardening, sanitizers,
fuzzing, and the release pipeline are all shipped (M0–M6 complete). 1.1.0 added
pipelined response corking and a zero-allocation hot path — the engine now
outperforms uWebSockets.js in both real-world and pipelined benchmark profiles
on a single thread. In progress: ALPN HTTP/2 (vendored nghttp2). See
[docs/DESIGN.md](docs/DESIGN.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Why

- MoroJS's framework overhead is already ~zero; the remaining performance
  ceiling **is** the engine. Owning it is the only lever left.
- Owning the binaries means day-one support for every Node release —
  off-the-shelf native bindings routinely lag (no prebuilt binary for the
  Node 25 / ABI 141 line for months).
- The Moro-shaped boundary (batched request snapshot, single corked response
  write) needs 2–4 JS crossings per request vs ~10–20 for a general-purpose
  binding.

## Usage (with MoroJS)

MoroJS installs `@morojs/engine` by default and falls back to Node's http
server automatically wherever a prebuilt binary isn't available:

```js
// moro config
server: {
  engine: 'auto',   // engine when loadable, Node http otherwise (default in 2.0)
  // engine: 'native' - require the engine, fail fast
  // engine: 'node'   - opt out
}
```

## Development

```bash
node tools/build.mjs     # build for the running Node ABI (downloads headers)
node test/smoke.mjs      # load + probe the binary
node tools/build.mjs --all   # full ABI matrix
```

Prebuilt binaries ship only from tagged CI runs with npm provenance — never
from developer machines, never committed to git.

## Acknowledgments

Hats off to [uWebSockets](https://github.com/uNetworking/uWebSockets) for years
of showing what high-performance networking on Node and V8 can look like. Moro's
engine is its own implementation, but that's prior art worth acknowledging.
