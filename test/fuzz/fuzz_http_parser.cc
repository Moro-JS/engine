// libFuzzer harness for the HTTP/1.1 request parser (CONTRIBUTING.md: new
// parser code lands with a fuzz harness). Feeds arbitrary bytes, in random
// splits, and asserts the parser never crashes, reads out of bounds, or hangs.
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     test/fuzz/fuzz_http_parser.cc -o /tmp/fuzz_http && \
//   /tmp/fuzz_http -max_total_time=60
//
// The parser is a pure state machine (no I/O), so the harness is the parser
// plus a splitter that exercises the incremental path.

#include <cstddef>
#include <cstdint>

#include "../../src/http_parser.h"

using namespace moro::engine;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  // Byte 0 chooses a chunk size (1..16) so we exercise arbitrary read splits;
  // the parser must produce the same result regardless of framing.
  size_t chunk = (data[0] % 16) + 1;
  const uint8_t* body = data + 1;
  size_t bodyLen = size - 1;

  HttpLimits limits;
  limits.maxHeadSize = 16 * 1024;
  limits.maxHeaders = 100;
  limits.maxBodySize = 1 * 1024 * 1024;
  HttpParser parser(limits);

  size_t off = 0;
  while (off < bodyLen) {
    size_t n = chunk < (bodyLen - off) ? chunk : (bodyLen - off);
    ParseStatus st = parser.parse(reinterpret_cast<const char*>(body + off), n);
    off += n;
    if (st == ParseStatus::Complete) {
      // Touch the parsed fields to catch any invalid views, then reset and
      // continue parsing pipelined data (keep-alive path).
      volatile size_t sink = parser.path.size() + parser.query.size() +
                             parser.headers.size() + parser.body.size();
      (void)sink;
      for (const auto& h : parser.headers) {
        volatile size_t s2 = h.name.size() + h.value.size();
        (void)s2;
      }
      parser.reset();
    } else if (st == ParseStatus::Error) {
      break;  // a real server closes the connection here
    }
  }
  return 0;
}
