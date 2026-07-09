# Security Policy

`@morojs/engine` is a native HTTP/1.1 + WebSocket engine for
Node.js (C++ with raw-V8 bindings). Because it parses untrusted bytes off the
network in hand-written C++, we take security reports seriously and want to make
them easy to file.

> **Maturity note.** The engine is pre-1.0 and has **not** yet had an external
> security review (that review is a tracked M5/M6 gate — see
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)). Until it has, run it behind a
> hardened reverse proxy for TLS termination, or use MoroJS's `engine: 'node'`
> fallback for untrusted-facing production traffic.

## Supported versions

The engine ships independent semver and is still in its `0.x` line. Security
fixes land on the **latest published version** only; there is no long-term
back-port branch during `0.x`.

| Version | Supported |
| ------- | --------- |
| Latest published release | ✅ |
| Any older release | ❌ (upgrade to the latest) |

When a `1.0.0` GA line exists, this table will be updated to name the supported
major line(s).

## Reporting a vulnerability

**Please do not open a public GitHub issue, discussion, or pull request for a
suspected vulnerability.** Public disclosure before a fix is available puts
every user at risk.

Report privately through either channel:

1. **GitHub Security Advisory (preferred).** Open the repository's **Security**
   tab and choose **"Report a vulnerability"**. This creates a private advisory
   thread visible only to you and the maintainers.
2. **Email.** Send details to **security@morojs.com**. If you want to encrypt
   the report, ask in an initial (contentless) message and we will arrange a
   key.

Please include, as far as you can:

- affected version(s) and platform/ABI (`probe()` output helps),
- a description of the flaw and its impact (crash, over-read, request
  desync/smuggling, DoS, memory disclosure, etc.),
- a minimal reproduction — ideally a raw byte sequence or a fuzz corpus file
  that can be dropped into `test/fuzz/corpus/{http,ws}` (see the threat model's
  reviewer quick-start),
- any suggested remediation.

## What to expect

These are good-faith targets, not contractual SLAs (this is a volunteer,
pre-1.0 project):

- **Acknowledgement:** typically within a few business days.
- **Triage & assessment:** we will confirm the report, assess severity, and keep
  you updated on progress.
- **Fix & disclosure:** we aim to ship a fix promptly for confirmed issues and
  will coordinate a disclosure timeline with you. We are happy to credit
  reporters in the advisory unless you prefer to remain anonymous.

We will not pursue legal action against researchers who report in good faith,
avoid privacy violations and service degradation, and give us a reasonable
window to remediate before public disclosure.

## Scope

**In scope** — the native engine's own attack surface, i.e. the code that
touches untrusted network bytes:

- HTTP/1.1 request parsing and framing (`src/http_parser.h`)
- WebSocket framing, masking, and UTF-8 handling (`src/websocket.h`,
  `src/sha1.h`)
- The TCP/connection engine and its lifecycle/timeout handling (`src/server.h`)
- The V8 boundary — request/response and WebSocket bindings (`src/binding.cpp`)
- The build/packaging/loader pipeline as it affects binary integrity
  (`tools/build.mjs`, npm provenance publishing)

**Out of scope** — things the engine deliberately does not own:

- **Your application code / route handlers.** The engine hands validated,
  bounded request data to JS; logic bugs, injection, auth, and business-rule
  flaws in handlers are the application's responsibility.
- **The MoroJS framework layer** (routing, middleware, rate limiting, auth).
  Report those to the MoroJS framework repository.
- **Node.js itself and its bundled libraries** (V8, libuv, OpenSSL). Report
  those upstream to Node.js.
- **Third-party dependencies** pulled in by your app.
- **TLS.** The engine ships **no** TLS of its own today; encryption is expected
  to be terminated at a proxy or by running `engine: 'node'`. Weaknesses in that
  external termination are out of scope for this project (though we welcome
  reports about how the engine behaves behind such a terminator).
- **Denial of service that the framework/operator is expected to bound** (e.g.
  application-level rate limiting, per-tenant quotas). The engine provides the
  parsing/DoS primitives documented in the threat model, not a full rate limiter.

For the full attack-surface analysis, trust boundaries, mitigations, and the
honest list of known limitations, see
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
