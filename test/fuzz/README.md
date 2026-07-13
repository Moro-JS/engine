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
| `ws`   | `fuzz_websocket.cc`     | WebSocket framing/masking/UTF-8  |
| `tls`  | `fuzz_tls_transport.cc` | TLS pump state machine (`src/tls.h`) |
| `pmd`  | `fuzz_ws_deflate.cc`    | permessage-deflate inflate path (`src/ws_deflate.h`) |

## Seed corpora (`corpus/<target>/`)

libFuzzer replays every file in a target's directory, then mutates and writes
new coverage-expanding inputs back into it. Only **hand-written seeds** are
committed — `.gitignore` tracks `corpus/**/*.raw` and `corpus/**/*.frame` and
ignores the thousands of fuzzer-generated hash-named files that accumulate
locally / in the Actions cache. Name new seeds accordingly (`.raw`, or `.frame`
for `ws`).

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
