// Byte-level text helpers shared by the binding's string paths.
//
// V8 hands the engine one-byte strings as Latin-1. On the wire we send UTF-8,
// so ASCII passes through untouched and anything >= 0x80 is encoded exactly
// the way String::Utf8Value would encode it (two bytes per code point) -
// byte-for-byte identical output whichever path a body took.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace moro {
namespace text {

// True when every byte is < 0x80 (Latin-1 == UTF-8 for the whole buffer).
// Eight bytes per step through a word mask; the tail byte-wise.
inline bool isAscii(const uint8_t* p, size_t n) {
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t w;
    std::memcpy(&w, p + i, 8);
    if (w & 0x8080808080808080ULL) return false;
  }
  for (; i < n; ++i)
    if (p[i] & 0x80) return false;
  return true;
}

// Latin-1 (ISO-8859-1, one byte per code point U+0000..U+00FF) -> UTF-8.
// Output replaces `out`. Capacity is reserved for the worst case (every byte
// >= 0x80) so a warm reused buffer never reallocates mid-encode.
inline void latin1ToUtf8(const uint8_t* p, size_t n, std::string& out) {
  out.clear();
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t c = p[i];
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back(static_cast<char>(0xC0 | (c >> 6)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
}

}  // namespace text
}  // namespace moro
