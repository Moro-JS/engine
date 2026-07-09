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
node test/smoke.mjs           # load + probe the built binary
```

New Node ABI runbook: add one line to `TARGETS` in `tools/build.mjs`, add the
Node version to the smoke matrix in `.github/workflows/build.yml`, ship a
minor release.

## Binaries

Binaries are **never committed to git** and never built on developer machines
for release. They ship exclusively from tagged CI runs via
`npm publish --provenance`.
