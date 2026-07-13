# @morojs/engine

MoroJS's native HTTP engine: a Moro-authored C++ core with raw-V8 bindings,
shipped as **prebuilt binaries per platform x Node ABI**. MIT licensed.

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
  // engine: 'uws'  - opt in to uWebSockets.js
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

## License

MIT licensed.
