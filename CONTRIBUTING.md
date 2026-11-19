# Contributing to @morojs/engine

## Original-code policy (read this first)

This engine is **100% Moro-authored, MIT-licensed code**. Keep it that way:

- **Write original code.** Don't copy, paste, or transliterate code from any
  other HTTP server or networking library into this repository — not a
  function, not a table, not a macro.
- **Protocol code cites RFCs.** A PR adding parser or protocol behavior must
  reference the governing spec section (RFC 9110/9112 for HTTP/1.1
  semantics/syntax, RFC 6455 for WebSocket) in its description or comments.
- Test corpora and conformance suites (Autobahn, h1spec-style cases) are data,
  not code — using them is encouraged.

- **TLS is the one thing not written here.** The engine links a TLS library
  and never implements one: the OpenSSL of the running node, or BoringSSL,
  which is fetched at build time at a pinned commit (`tools/boringssl.json`)
  and linked into the binary that carries it. None of BoringSSL's source is
  committed to this repository, and none of it is to be copied into `src/`.

This keeps the codebase genuinely original, MIT-licensable, and auditable.

## Security posture

Hand-written C++ parser code is held to a non-negotiable bar:

- New parser/framing code lands **with libFuzzer harnesses** in `test/fuzz/`.
- CI runs ASan/UBSan legs; a sanitizer finding is a release blocker.
- Request-smuggling defenses are spec-mandated, not best-effort: conflicting
  `Content-Length`/`Transfer-Encoding` is a hard reject (RFC 9112 §6.3).

## Build

```
node tools/build.mjs          # current Node ABI, host platform
node tools/build.mjs --all    # all supported ABIs
node test/smoke.mjs           # load + probe the built binaries
```

Each ABI builds two binaries: one carrying BoringSSL and one linked to node's
OpenSSL ([docs/TLS.md](docs/TLS.md)). The first needs `git` and `cmake` 3.22+
on the machine (`ninja` is used when present; on Windows also `nasm`); the
static libraries are built once per snapshot and cached in `build/boringssl/`.
`--tls=openssl` builds only the second and needs none of that.
`npm run test:suites` runs everything against the BoringSSL binary and the
TLS and HTTP/2 suites again against the OpenSSL one.

New Node ABI runbook: add one line to `TARGETS` in `tools/build.mjs`, add one
entry to `TRAINING_NODES` in `tools/pgo.mjs` (the Node.js release the new ABI's
profile is trained under, with its checksums; without it the ABI is built from
the nearest ABI's profile), add the
Node version to the smoke matrices in `.github/workflows/ci.yml` and
`release.yml`, ship a minor release.

## Releases

One note per release, written before the release, in `changelog/vX.Y.Z.md`,
with its line added at the top of [`CHANGELOG.md`](CHANGELOG.md). The note
is the GitHub Release body, so it is written for users of the package: what
changed in behaviour, what was added or removed from the API, what was
measured and how. Then:

```sh
node tools/release.mjs patch      # or minor / major / an explicit version (1.2.0, 1.2.0-rc.1)
```

The script refuses to run without the note and its index line, and refuses
when the pinned BoringSSL is stale (upstream has a newer snapshot and the
pinned one is over 21 days old: `node tools/boringssl.mjs roll`, rebuild,
`npm test`, commit, then release). It bumps the
version everywhere it lives, commits `chore: release vX.Y.Z`, tags and
pushes. Drafting the GitHub Release for that tag with the note as its body
and clicking Publish starts the CI build and the npm publish; nothing
publishes from a developer machine.

### Release candidates

A version with a prerelease identifier is a release candidate:

```sh
node tools/release.mjs 1.2.0-rc.1   # then 1.2.0-rc.2 ..., then 1.2.0
```

It goes through the same workflow and the same gates, and every package is
published under the npm dist-tag `next`. `latest` does not move, so a plain
`npm install @morojs/engine` and every semver range keep getting the last
release; a candidate is installed with `npm install @morojs/engine@next` or
by its exact version. The note it carries is that of the release it leads to
(`changelog/v1.2.0.md`). Mark the GitHub Release as a pre-release
(`gh release create v1.2.0-rc.1 --prerelease ...`; the workflow sets the mark
if it is missing).

While `main` is at a candidate, the version is always named in full:
`patch` / `minor` / `major` are refused, as is any version that is not above
the current one, and the scheduled BoringSSL release waits (it opens its
issue instead). The forms are `X.Y.Z-rc.N`, `-beta.N` and `-alpha.N`, with N
from 1; anything else (`1.2.0-rc1`, `1.2.0-1`, build metadata) is refused by
the script and by the workflow. After `1.2.0` is released, `next` still names
the last candidate; `npm dist-tag rm @morojs/engine next` (and the same for
the platform packages) clears it, or the next candidate replaces it.

## The bundled TLS library

`tools/boringssl.json` pins the BoringSSL snapshot the published binaries
carry. Nobody is expected to maintain it by hand:
`.github/workflows/boringssl-roll.yml` checks upstream every week, runs the
whole CI gate against a newer snapshot, and on green commits the pin and
publishes a patch release by itself; on red it opens an issue. It releases
only when `main` is exactly the last release: with commits for the next
release on `main` it stops (and opens the issue), and the pin moves with
that next release. To move the pin
yourself (`node tools/boringssl.mjs roll`), rebuild and run `npm test` before
committing. `node tools/boringssl.mjs check` says whether the pin is stale;
`git config core.hooksPath .githooks` runs that check on every push (it warns,
it never blocks).

## Binaries

Binaries are **never committed to git** and never built on developer machines
for release. They ship exclusively from tagged CI runs via
`npm publish --provenance`.
