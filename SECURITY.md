# Security Policy

`@morojs/engine` is a native HTTP/1.1 + WebSocket engine for
Node.js (C++ with raw-V8 bindings). Because it parses untrusted bytes off the
network in hand-written C++, we take security reports seriously and want to make
them easy to file.

> **Maturity note.** The engine is on its `1.x` line and terminates TLS in-process — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)).

## Supported versions

The engine ships independent semver on its `1.x` line. Security fixes land on
the **latest published version** only; there is no long-term back-port branch.

| Version | Supported |
| ------- | --------- |
| Latest published release | ✅ |
| Any older release | ❌ (upgrade to the latest) |

If a supported-branch policy is added for a future major line, this table will
be updated to name the supported major line(s).

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
  that can be dropped into `test/fuzz/corpus/{http,ws,tls,pmd}` (see the threat
  model's reviewer quick-start),
- any suggested remediation.

## What to expect

These are good-faith targets, not contractual SLAs (this is a volunteer
project):

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
- **In-process TLS termination** — the engine's handshake/record pump around
  OpenSSL, ALPN, mutual TLS, and session/ticket resumption (`src/tls.h`)
- **WebSocket permessage-deflate** (RFC 7692) — the inflate/deflate framing and
  the zip-bomb output cap (`src/ws_deflate.h`)
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
  those upstream to Node.js. The engine's TLS is in scope (see above), but a
  vulnerability in the **OpenSSL library** it links (the host Node's) is an
  upstream issue — report the engine's *use* of it here, the library itself to
  Node.js/OpenSSL.
- **Third-party dependencies** pulled in by your app.
- **Denial of service that the framework/operator is expected to bound** (e.g.
  application-level rate limiting, per-tenant quotas). The engine provides the
  parsing/DoS primitives documented in the threat model, not a full rate limiter.

For the full attack-surface analysis, trust boundaries, mitigations, and the
honest list of known limitations, see
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
