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

1. Rebuilds every platform (same matrix as `build.yml`) and collects the
   `build/*.node` artifacts (`moro_engine_<platform>_<arch>[_<libc>]_<abi>.node`,
   one per supported ABI — the `libc` segment keeps glibc and musl distinct).
2. Runs `node tools/prepare-release.mjs <version> --check`, which for each
   per-platform package directory copies that platform's matching `.node` files
   in, drops the root `LICENSE` alongside them, and sets `version`; then syncs
   the meta package's own `version` **and** every exact-pinned
   `optionalDependencies` entry to the same version (so the seven version
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
smoke matrix in `.github/workflows/build.yml`, and ship a minor release. No
package-layout change is needed - each per-platform package simply carries the
additional `.node`.

## win32 status

`@morojs/engine-win32-x64` is scaffolded (the package directory exists) but is
**deliberately NOT listed as an optionalDependency** of the meta package, and is
not published: `tools/build.mjs` has no MSVC compile branch yet (the `build`
workflow's `windows` leg is `continue-on-error` / expected to fail).

It is left out of `optionalDependencies` on purpose — pinning an unpublished
version there makes strict installers (notably Yarn Classic) fail `install` on
**every** platform with "package not found". On Windows the engine simply isn't
found and MoroJS falls back to Node's `http` server.

To start shipping Windows: add an MSVC branch to `build.mjs` (download `node.lib`
per ABI + `cl.exe` flags, mirroring the darwin/linux branches), then add
`@morojs/engine-win32-x64` back to the meta package's `optionalDependencies`.
The packaging scaffold is otherwise already in place.
