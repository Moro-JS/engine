# @morojs/engine

MoroJS's native HTTP engine: a Moro-authored C++ core with raw-V8 bindings,
built for maximum throughput with an API shaped exactly for how MoroJS serves
requests. It serves HTTP/1.1, HTTP/2 and WebSocket (with permessage-deflate)
and terminates TLS in-process. MIT licensed.

## Why

- MoroJS's framework overhead is already ~zero; the remaining performance
  ceiling **is** the engine. Owning it is the only lever left.
- Owning the binaries means day-one support for every Node release —
  off-the-shelf native bindings routinely lag.
- The Moro-shaped boundary (batched request snapshot, single corked response
  write) needs 2–4 JS crossings per request vs ~10–20 for a general-purpose
  binding.
- Three transports behind one seam: the engine's own socket path on
  libuv's epoll (the Linux default since 1.1.10, no libuv stream per
  connection, one `epoll_wait` per loop turn), libuv streams (macOS,
  Windows, or `MORO_ENGINE_TRANSPORT=uv`) and an opt-in io_uring transport on
  Linux 6.1+ (`MORO_ENGINE_TRANSPORT=uring`: multishot accept/recv, half the
  syscalls per request) — identical bytes on the wire, the whole test matrix
  on each, `probe().transport` reporting which is live. Measured numbers:
  docs/DESIGN.md.

## Usage (with MoroJS)

MoroJS installs `@morojs/engine` by default and falls back to Node's http
server automatically wherever a prebuilt binary isn't available:

```js
// moro config
server: {
  engine: 'moro',   // default - native engine when loadable, Node http otherwise
  // engine: 'node' - always use Node http
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

## Docs

[API](docs/API.md) · [Design](docs/DESIGN.md) · [TLS](docs/TLS.md) ·
[Threat model](docs/THREAT_MODEL.md) · [Roadmap](docs/ROADMAP.md) ·
[Changelog](CHANGELOG.md) · [Benchmarks](https://github.com/Moro-JS/benchmark)
