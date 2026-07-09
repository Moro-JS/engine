// libFuzzer harness for the RFC 6455 WebSocket frame parser. Feeds arbitrary
// bytes as an untrusted client stream in random splits; the parser must never
// crash, over-read, or hang, and must stay failed after the first error.
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     test/fuzz/fuzz_websocket.cc -o /tmp/fuzz_ws && /tmp/fuzz_ws -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <string>

#include "../../src/websocket.h"

using namespace moro::engine;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;
  size_t chunk = (data[0] % 16) + 1;
  const uint8_t* body = data + 1;
  size_t bodyLen = size - 1;

  WsParser::Limits limits;
  limits.maxMessageSize = 1 * 1024 * 1024;
  WsParser parser(limits);

  auto onMessage = [](std::string_view payload, bool isBinary) {
    volatile size_t s = payload.size() + (isBinary ? 1 : 0);
    (void)s;
  };
  auto onControl = [](WsOpcode op, std::string_view payload) {
    volatile size_t s = static_cast<size_t>(op) + payload.size();
    (void)s;
  };

  size_t off = 0;
  while (off < bodyLen) {
    size_t n = chunk < (bodyLen - off) ? chunk : (bodyLen - off);
    bool ok = parser.consume(body + off, n, onMessage, onControl);
    off += n;
    if (!ok) break;  // failed connection: a real server stops feeding it
  }
  return 0;
}
