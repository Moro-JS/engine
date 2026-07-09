// permessage-deflate configuration (RFC 7692) as a plain, dependency-free
// struct, so http_parser.h can carry it in HttpLimits without pulling in zlib
// (only ws_deflate.h's PmdContext needs zlib). Original-code policy applies.

#pragma once

#include <cstddef>

namespace moro {
namespace engine {

// Options the app passes via serve() options.wsDeflate.
struct PmdOptions {
  bool enabled = false;
  bool serverNoContextTakeover = false;
  bool clientNoContextTakeover = false;
  int serverMaxWindowBits = 15;
  int clientMaxWindowBits = 15;
  size_t threshold = 1024;         // min message bytes before compressing a send
  size_t maxDecompressedSize = 0;  // 0 => fall back to wsMaxMessageSize
};

}  // namespace engine
}  // namespace moro
