# Publishing layout for `@morojs/engine`

esbuild/napi-rs-style split: one platform-agnostic **meta package** plus one
**per-platform package** per supported target. The meta package is the public
entry point; the per-platform packages are pure binary carriers.

```
packages/
  engine/                     -> @morojs/engine           (loader + types + LICENSE; NO binaries)
  engine-darwin-arm64/        -> @morojs/engine-darwin-arm64
  engine-darwin-x64/          -> @morojs/engine-darwin-x64
  engine-linux-x64-gnu/       -> @morojs/engine-linux-x64-gnu
  engine-linux-arm64-gnu/     -> @morojs/engine-linux-arm64-gnu
  engine-linux-x64-musl/      -> @morojs/engine-linux-x64-musl
  engine-linux-arm64-musl/    -> @morojs/engine-linux-arm64-musl
  engine-win32-x64/           -> @morojs/engine-win32-x64
```

Each per-platform directory ships a **committed `package.json` scaffold only**
(`os` / `cpu` / `libc` set for npm's install-time filtering). The `.node`
binaries are **never committed** (`.gitignore` excludes `*.node` and `build/`)
and are injected by CI at release time. The meta package lists every
per-platform package as an **exact-version `optionalDependency`**, so npm
installs only the one matching the host (and silently skips the rest - a missing
or unsupported optional dependency never fails `npm install`).

## Release assembly (CI, `.github/workflows/release.yml`)

Binaries ship **only** from a tagged CI run with npm provenance, never from a
developer machine (see `CONTRIBUTING.md`). Pushing a `v*` tag runs `release.yml`,
which:

1. Rebuilds every platform (same matrix as `ci.yml`) and collects the
   `build/*.node` artifacts (`moro_engine_<platform>_<arch>[_<libc>]_<abi>.node`,
   one per supported ABI — the `libc` segment keeps glibc and musl distinct).
2. Runs `node tools/prepare-release.mjs <version> --check`, which for each
   per-platform package directory copies that platform's matching `.node` files
   in, drops the root `LICENSE` alongside them, and sets `version`; then syncs
   the meta package's own `version` **and** every exact-pinned
   `optionalDependencies` entry to the same version (so the eight version
   strings can never drift). `--check` fails the release if any published
   platform received zero binaries.
3. Publishes each per-platform package, then the meta package (`packages/engine`)
   **last**, so its `optionalDependencies` already resolve on the registry.

`publishConfig` in every package already pins `access: public` (required for
first publish of a scoped package) and `provenance: true`.

Do **not** run `npm publish`/`npm pack` in a per-platform directory by hand: the
committed scaffold contains no `.node` files and would publish an empty package.

## Adding a new Node ABI

Add one line to `TARGETS` in `tools/build.mjs`, add the Node version to the
smoke matrix in `.github/workflows/ci.yml`, and ship a minor release. No
package-layout change is needed - each per-platform package simply carries the
additional `.node`.

## win32 status

`@morojs/engine-win32-x64` is a **fully shipped platform**, on the same footing
as darwin and linux:

- It is listed as an exact-version `optionalDependency` of the meta package
  (`packages/engine/package.json`), so npm installs it on a matching Windows
  host.
- `tools/build.mjs` has a complete MSVC compile branch — it downloads the
  per-ABI `node.lib` (SHASUMS-verified) and compiles with `cl.exe`
  (`/DELAYLOAD:node.exe` + the `src/win_delay_load_hook.h` hook so the addon
  binds to whatever process hosts it).
- `.github/workflows/ci.yml` and `release.yml` build, load-smoke, and
  conformance-test the win32-x64 binary alongside every other flavor.

On a Windows host with a matching prebuilt binary the native engine loads; on
any platform/ABI without one, MoroJS falls back to Node's `http` server.
