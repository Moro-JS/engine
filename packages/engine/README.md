# @morojs/engine

MoroJS's native HTTP engine: a Moro-authored C++ core with raw-V8 bindings,
shipped as **prebuilt binaries per platform x Node ABI**. It serves HTTP/1.1,
HTTP/2 and WebSocket (with permessage-deflate) and terminates TLS in-process.
MIT licensed.

This is the meta package. It contains only a small JavaScript loader plus the
TypeScript types; the actual `.node` binaries are delivered by per-platform
optional dependencies (`@morojs/engine-<platform>-<arch>[-<libc>]`). The loader
selects the correct binary for your `process.platform` / `arch` /
`versions.modules` (Node ABI), and is glibc/musl-aware on Linux.

## Install

```bash
npm install @morojs/engine
```

You normally do not install this directly - MoroJS depends on it and uses it
automatically, falling back to Node's built-in `http` server wherever a
prebuilt binary is not available:

```js
// moro config
server: {
  engine: 'moro',   // default - native engine when loadable, Node http otherwise
  // engine: 'node' - always use Node http
}
```

MoroJS always degrades to the Node `http` server when the native engine can't
load (the reason is logged at startup and exposed via `app.engine.fallbackReason`);
there is no "fail fast" engine value. The legacy `'auto'`/`'native'` values map
to `'moro'` with a deprecation warning.

## Graceful degradation

Requiring/importing this package **never throws**, even on a platform with no
prebuilt binary. Use the non-throwing `probe()` to detect availability:

```js
const engine = require('@morojs/engine');

const info = engine.probe();
// { ok: true,  version, platform, arch, abi }  when a binary loaded
// { ok: false, platform, arch, abi, error }    otherwise (actionable message)

if (info.ok) {
  // engine.serve(...), engine.listen(...), ...
}
```

Actual API calls (`serve`, `listen`, ...) on a platform without a binary throw a
rich, actionable error (`err.code === 'MORO_ENGINE_BINARY_MISSING'`) that names
the expected package, the running Node ABI, and the remediation for npm's
optional-dependency lockfile bug ([npm/cli#4828](https://github.com/npm/cli/issues/4828)).

## TLS

Each platform package carries two builds of the engine per Node version. The
default terminates TLS with a bundled [BoringSSL](https://boringssl.googlesource.com/boringssl);
the other uses the OpenSSL of the running Node.js and is selected by itself
when that library is specially configured (FIPS mode, `--openssl-config`,
`OPENSSL_CONF`, ...), or with `MORO_ENGINE_TLS=openssl` /
`engine.selectTls('openssl')`. `engine.probe().tls` reports which is loaded.

The bundled library is updated by a scheduled release every time upstream
publishes a snapshot (every two to three weeks), so **keep this package
updated** the way you keep Node.js updated; a TLS server on a build more than
180 days old says so in a process warning (`MORO_ENGINE_TLS_STALE`). Details:
[docs/TLS.md](https://github.com/Moro-JS/engine/blob/main/docs/TLS.md).

## Supported platforms

| Package                          | os     | cpu     | libc  |
| -------------------------------- | ------ | ------- | ----- |
| `@morojs/engine-darwin-arm64`    | darwin | arm64   | -     |
| `@morojs/engine-darwin-x64`      | darwin | x64     | -     |
| `@morojs/engine-linux-x64-gnu`   | linux  | x64     | glibc |
| `@morojs/engine-linux-arm64-gnu` | linux  | arm64   | glibc |
| `@morojs/engine-linux-x64-musl`  | linux  | x64     | musl  |
| `@morojs/engine-linux-arm64-musl` | linux | arm64 | musl  |
| `@morojs/engine-win32-x64`       | win32  | x64     | -     |

Node ABIs: 115/127/131/137/141/147 (Node 20/22/23/24/25/26). Any other
platform/ABI falls back to Node's `http` server via MoroJS.

## I/O transport

On Linux the engine runs its own socket path on libuv's epoll by default
(since 1.1.10): plain non-blocking sockets as libuv poll handles, one
`epoll_wait` per loop turn, each turn's sockets served grouped by the CPU
their peer sends from. macOS and Windows run on libuv streams, which Linux
can also select with `MORO_ENGINE_TRANSPORT=uv`. On Linux 6.1+ an io_uring
transport is available opt-in (`MORO_ENGINE_TRANSPORT=uring`): it is probed
once per process by a feature check and a self-test, and anywhere it is
unavailable (kernels before 6.1, gVisor, containers under Docker's default
seccomp profile, which blocks `io_uring_setup`) the engine silently stays on
epoll. No transport changes a byte on the wire. `probe().transport`
reports which one is live, `probe().transportReason` why, and
`probe().transportMode` which io_uring ring mode is running: `defer-taskrun`
(completions run as one batch inside the engine's own `io_uring_enter`, woken
through a registered eventfd) or `coop-taskrun` (the 1.1.6 mode, also
selectable with `MORO_ENGINE_URING_TASKRUN=coop`).

## License

MIT licensed.
