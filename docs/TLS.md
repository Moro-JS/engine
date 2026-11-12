# The TLS library

From 1.1.20 the engine ships **two binaries** per platform and Node ABI. They
are the same engine built from the same source and differ in one thing: the
library that does TLS.

| Binary | TLS library | Loaded |
| --- | --- | --- |
| `moro_engine_<platform>_<arch>[_<libc>]_<abi>_boringssl.node` | [BoringSSL](https://boringssl.googlesource.com/boringssl), carried inside the addon | by default |
| `moro_engine_<platform>_<arch>[_<libc>]_<abi>.node` | the OpenSSL the running `node` exports (every binary up to 1.1.19 was this one) | when node's OpenSSL is specially configured, when asked for, and as the fallback |

`probe().tls` says which one is loaded and why:

```js
import engine from '@morojs/engine';
engine.probe().tls;
// { library: 'boringssl', version: '0.20261105.0', date: '2026-11-05', reason: 'default' }
// { library: 'openssl',   version: '3.5.4',                             reason: 'MORO_ENGINE_TLS' }
```

## Choosing

The choice is made once per thread, when the binding is first loaded (the first
`probe()` or `serve()`), in this order:

1. `selectTls('boringssl' | 'openssl')`, called before that first load.
   Calling it afterwards for the other library throws
   (`MORO_ENGINE_TLS_LOADED`): a loaded addon cannot be swapped.
   `selectTls('auto')` makes no choice and leaves it to the next two rules.
2. The environment variable `MORO_ENGINE_TLS` (`boringssl`, `openssl`, `auto`;
   `node` is accepted for `openssl`). No code change needed. Any other value is
   an error, not a default.
3. Otherwise, `auto`: BoringSSL, **unless node's OpenSSL has been configured** —
   the process was started with `--enable-fips`, `--force-fips`,
   `--openssl-config`, `--openssl-shared-config` or `--openssl-legacy-provider`
   (on the command line or in `NODE_OPTIONS`), `OPENSSL_CONF` or
   `OPENSSL_MODULES` is set, or `crypto.getFips()` reports FIPS mode. An
   operator who set any of those expects TLS to go through that library, and
   it does, with nothing to change. `reason` names what was found.

### Nothing breaks on update

A server behind a proxy that terminates TLS never reaches any of this: it
serves plaintext, and the two binaries run the same code for that.

For a server that does terminate TLS, two fallbacks apply whenever nobody
named a library, and both report `reason: 'fallback'` with a `fallbackReason`
in `probe().tls`:

- **The BoringSSL binary cannot be loaded.** The OpenSSL binary is loaded
  instead.
- **BoringSSL does not accept the TLS configuration.** Its set of key types,
  cipher suites and groups is narrower than OpenSSL's (table below). A
  configuration outside it was served up to 1.1.19 and still is, by the
  OpenSSL binary. The clean way to get there is to tell the loader what is
  about to be served: `selectTls('auto', ssl)` checks the options against
  BoringSSL while the binding is being loaded (MoroJS 1.8.24 and later do
  this with their `server.ssl`). Without that, the first `serve()` with `ssl` on a thread makes
  the same move itself, provided the thread holds nothing of the BoringSSL
  binary yet — no server created, no other native function taken from the
  module — because ids and functions of two binaries cannot be mixed. If it
  does hold something, the error is thrown unchanged with
  `MORO_ENGINE_TLS=openssl` named as the way out (under MoroJS 1.8.23 and
  earlier that is what happens, and the app is served by the framework's
  Node.js fallback with that message in the log).

Asked for by name, a library is never substituted: a missing binary or a
refused configuration is an error.

What no fallback can see is a *client* that only speaks something BoringSSL
lacks — in practice a TLS 1.2 client with no ECDHE support. Set
`MORO_ENGINE_TLS=openssl` for a deployment that has one.

`MORO_ENGINE_BINARY` (a path to one specific `.node`, for builds and A/B runs)
bypasses all of the above.

## What differs between the two

Everything in `ServeOptions.ssl` works on both. The differences:

| | BoringSSL (bundled) | OpenSSL (node's) |
| --- | --- | --- |
| TLS 1.3 suites (`ssl.ciphersuites`) | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. Naming any other throws from `serve()`. | whatever that OpenSSL has (adds the CCM suites) |
| TLS ≤ 1.2 ciphers (`ssl.ciphers`) | ECDHE and RSA key exchange with AES-GCM, ChaCha20-Poly1305 and the legacy AES-CBC suites. No DHE, CCM, ARIA or Camellia. | whatever that OpenSSL has |
| FIPS mode, OpenSSL providers and engines, `openssl.cnf`, a distribution's crypto policy | not consulted | honoured |
| Session tickets (TLS 1.3) | sent with the first response (one packet instead of two) | sent right after the handshake |
| Resumption across servers sharing `ssl.ticketKeys` | between servers on the same library | between servers on the same library |
| Security fixes arrive with | an engine release | a Node.js release |

The default policy is the same on both: TLS 1.2 or later, no renegotiation, no
TLS compression, the server's cipher order, AES-128-GCM ahead of AES-256-GCM,
and ChaCha20-Poly1305 for a client that lists it first. (On a machine without
AES instructions the BoringSSL binary leads with ChaCha20, which is the faster
and safer choice there.) A ticket minted by one library is not understood by
the other; a client holding one simply gets a full handshake.

## Why bundle a TLS library

For the cost of every TLS record. Measured on the engine itself, one worker,
CPU per request (lower is better), same machine, runs interleaved:

| Workload | OpenSSL binary | BoringSSL binary |
| --- | --- | --- |
| JSON reply over TLS, 1–50 items | 16.7 µs | 15.1 µs |
| 10 KB echo over TLS | 17.6 µs | 15.4 µs |

OpenSSL 3 pays for its provider architecture on each record; BoringSSL does
not have one. Plaintext traffic is untouched: the two binaries run the same
code there.

## Keeping the bundled library current

Bundling moves a duty: a fix made in BoringSSL reaches a server running this
engine only through an engine release, where a fix in OpenSSL reaches it
through a Node.js release. BoringSSL publishes no security advisories; it
publishes dated snapshots (`0.YYYYMMDD.N`) every two to three weeks. So the
engine follows every snapshot, automatically, and refuses to let its copy grow
old by accident:

- **One pin.** `tools/boringssl.json` names the upstream tag and the commit it
  resolves to. The build fetches that tag and refuses anything that does not
  resolve to that commit. BoringSSL's source is never committed to this
  repository.
- **A weekly roll** (`.github/workflows/boringssl-roll.yml`). When upstream has
  a newer tag, the whole CI gate — every suite, the sanitizers, every published
  binary on every platform — runs against it *before* anything is committed.
  Green, and the workflow commits the pin, cuts a patch release and publishes
  it to npm. Red, and it opens an issue and releases nothing. It can be started
  by hand when a fix cannot wait for Tuesday.
- **A release gate.** `tools/release.mjs` asks upstream before every release
  and refuses to cut one when a newer snapshot exists and the pinned one is
  more than 21 days old (`node tools/boringssl.mjs check`). `--allow-stale-tls`
  overrides it, on the record.
- **A notice at run time.** A server that terminates TLS on a BoringSSL binary
  whose snapshot is more than 180 days old emits one process warning
  (`MORO_ENGINE_TLS_STALE`) saying so and what to do: update `@morojs/engine`.
  Once per process; `MORO_ENGINE_TLS_AGE_WARNING=0` turns it off.
- **A nudge on push.** `git config core.hooksPath .githooks` enables a
  pre-push hook that prints the same staleness check. It warns and never
  blocks.

For someone running the engine this comes to one habit, the same one Node.js
asks for: update. `npm update @morojs/engine` picks up the newest snapshot;
Dependabot and Renovate propose each release by themselves.

## Building

`node tools/build.mjs` builds both binaries. The BoringSSL one needs `git` and
`cmake` (3.22 or later) on the machine, `ninja` if present (otherwise make),
and on Windows `nasm`. The static libraries are built once per snapshot and
toolchain and cached under `build/boringssl/`. `--tls=openssl` builds only the
binary on node's OpenSSL and needs none of that.

BoringSSL's symbols are compiled hidden and kept out of the addon's dynamic
symbol table, so inside the process they bind to each other and never to the
OpenSSL symbols of the same names that `node` exports.

## Licence

The engine's source is MIT. A BoringSSL binary also contains BoringSSL, which
is licensed separately (Apache-2.0, with parts under ISC, MIT and
OpenSSL-era licences); its licence text ships beside the binaries in every
platform package as `LICENSE-BORINGSSL`.
