# Fuzzing

libFuzzer harnesses for the code that parses untrusted bytes. `run.sh` builds
and runs them; `.github/workflows/fuzz.yml` runs a sustained nightly campaign
and a weekly corpus-minimization pass. See `../../SECURITY.md` and
`../../docs/THREAT_MODEL.md`.

```sh
sh test/fuzz/run.sh            # all targets, $FUZZ_SECONDS each
sh test/fuzz/run.sh pmd        # one target
FUZZ_MODE=merge sh test/fuzz/run.sh pmd   # minimize a target's corpus in place
```

## Targets

| Target | Harness                 | Surface under test              |
| ------ | ----------------------- | ------------------------------- |
| `http` | `fuzz_http_parser.cc`   | HTTP/1.1 request parsing/framing |
| `httpdiff` | `fuzz_http_diff.cc` | The HTTP/1.1 parser's three paths (buffered, in-place with stored headers, in-place storing nothing) against each other, whole and split: any difference in status, request or leftover aborts |
| `ws`   | `fuzz_websocket.cc`     | WebSocket framing/masking/UTF-8  |
| `http2` | `fuzz_http2.cc`        | HTTP/2 session and HPACK (`src/http2.h`), with a host that answers at once, later, or never, writes its answers whole or in pieces, and stops the session part-way through its input - which must change nothing but when things happen |
| `tls`  | `fuzz_tls_transport.cc` | TLS pump state machine (`src/tls.h`) |
| `pmd`  | `fuzz_ws_deflate.cc`    | permessage-deflate inflate path (`src/ws_deflate.h`) |

## Seed corpora (`corpus/<target>/`)

libFuzzer replays every file in a target's directory, then mutates and writes
new coverage-expanding inputs back into it. Only **hand-written seeds** are
committed — `.gitignore` tracks `corpus/**/*.raw` and `corpus/**/*.frame` and
ignores the thousands of fuzzer-generated hash-named files that accumulate
locally / in the Actions cache. Name new seeds accordingly (`.raw`, or `.frame`
for `ws`).

### HTTP/2 seeds (`corpus/http2/*.raw`)

Byte 0 is the split size and byte 1 the host's behaviour (the bits are listed at
the top of `fuzz_http2.cc`); the rest is the client's side of a connection,
without the preface when bit 0 of byte 1 asks the harness to supply it. The
seeds cover what a mutation is unlikely to assemble by itself: a header block in
`CONTINUATION` frames at its limits, the reset budget spent, windows used up and
given back under limits small enough to reach (bit 3), an answer written in
pieces behind a window the peer opens later, and a session paused at every
request (bit 4), where the harness runs the input twice and aborts if pausing
changed a request, an abort or a byte on the wire.

### permessage-deflate seeds (`corpus/pmd/*.raw`)

The harness feeds each byte string to `PmdContext::inflateMessage`
(`src/ws_deflate.h`), which — per RFC 7692 — appends the `00 00 FF FF` tail and
raw-inflates. A valid seed is therefore what a permessage-deflate *sender* puts
on the wire: the raw-DEFLATE of a message, `Z_SYNC_FLUSH`ed, with the trailing
`00 00 FF FF` octets stripped. Generate more with:

```python
import zlib
def pmd_payload(msg: bytes) -> bytes:
    co = zlib.compressobj(6, zlib.DEFLATED, -15)   # raw deflate, 15-bit window
    out = co.compress(msg) + co.flush(zlib.Z_SYNC_FLUSH)
    assert out.endswith(b"\x00\x00\xff\xff")
    return out[:-4]                                # RFC 7692 sender tail-strip
```

The committed seeds cover a short text message (`hello.raw`), the empty message
(`empty.raw`), a highly compressible run that exercises the incremental-output /
output-cap loop the harness targets (`repeat.raw`), and a small JSON control
frame (`json.raw`).
