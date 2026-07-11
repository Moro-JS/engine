// libFuzzer harness for the permessage-deflate inflate path (src/ws_deflate.h).
//
// The fresh attack surface is OUR framing around zlib: the tail-append, the
// incremental output loop, and above all the hard output cap (zip-bomb
// defense). Arbitrary bytes are fed as a "compressed" payload with a small
// output cap; the invariants are no crash, no hang, and output never exceeds
// the cap.
//
// Build (see run.sh): clang++ -fsanitize=fuzzer,address,undefined \
//   test/fuzz/fuzz_ws_deflate.cc -lz -o /tmp/moro_fuzz_pmd

#include <cstdint>
#include <string>

#include "../../src/ws_deflate.h"

using moro::engine::PmdContext;
using moro::engine::PmdParams;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  PmdParams params;  // default 15-bit windows, context takeover on
  const size_t kCap = 4096;
  PmdContext ctx(params, kCap);
  if (!ctx.valid()) return 0;

  std::string out;
  bool ok = ctx.inflateMessage(
      std::string_view(reinterpret_cast<const char*>(data), size), out);
  // On success or failure, the output must never exceed the cap (the check
  // runs before each append, so not even transiently).
  if (out.size() > kCap) __builtin_trap();
  (void)ok;

  // Feed it again through a fresh context in no-context-takeover mode to
  // exercise the reset path.
  PmdParams ncto;
  ncto.clientNoContextTakeover = true;
  PmdContext ctx2(ncto, kCap);
  if (ctx2.valid()) {
    std::string out2;
    ctx2.inflateMessage(
        std::string_view(reinterpret_cast<const char*>(data), size), out2);
    if (out2.size() > kCap) __builtin_trap();
  }
  return 0;
}
