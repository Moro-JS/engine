// Byte-level text helpers shared by the binding's string paths.
//
// V8 hands the engine one-byte strings as Latin-1. On the wire we send UTF-8,
// so ASCII passes through untouched and anything >= 0x80 is encoded exactly
// the way String::Utf8Value would encode it (two bytes per code point) -
// byte-for-byte identical output whichever path a body took.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace moro {
namespace text {

// True when every byte is < 0x80 (Latin-1 == UTF-8 for the whole buffer).
// Thirty-two bytes per step while that many remain - four words OR-ed
// together and tested once, which is what a response body of any size spends
// its time in - then eight per step through a word mask; the tail byte-wise.
inline bool isAscii(const uint8_t* p, size_t n) {
  size_t i = 0;
  for (; i + 32 <= n; i += 32) {
    uint64_t a, b, c, d;
    std::memcpy(&a, p + i, 8);
    std::memcpy(&b, p + i + 8, 8);
    std::memcpy(&c, p + i + 16, 8);
    std::memcpy(&d, p + i + 24, 8);
    if ((a | b | c | d) & 0x8080808080808080ULL) return false;
  }
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

// Hash for the engine's small string-keyed tables that are looked up per
// request with the request's own path or a header name (StringMap,
// flat_map.h). Keys are short, so a word at a time through a
// multiply-xorshift step, keyed with a value fixed per process at load: no
// worse against a peer choosing paths to collide than an unkeyed hash (the
// tables a peer can add to are capped by their owners).
inline const uint64_t kKeySeed =
    static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) * 0x9E3779B97F4A7C15ull ^
    static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&kKeySeed));
struct KeyHash {
  uint64_t operator()(std::string_view s) const {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    uint64_t h = kKeySeed ^ (n * 0x9E3779B97F4A7C15ull);
    uint64_t w = 0;
    if (n >= 8) {
      size_t i = 0;
      for (; i + 8 <= n; i += 8) {
        std::memcpy(&w, p + i, 8);
        h = (h ^ w) * 0xBF58476D1CE4E5B9ull;
        h ^= h >> 31;
      }
      // The tail as the last eight bytes (the length is in the seed).
      if (i < n) std::memcpy(&w, p + n - 8, 8);
      else w = 0;
    } else if (n >= 4) {
      uint32_t a, b;
      std::memcpy(&a, p, 4);
      std::memcpy(&b, p + n - 4, 4);
      w = (static_cast<uint64_t>(b) << 32) | a;
    } else if (n > 0) {
      w = p[0] | (static_cast<uint64_t>(p[n / 2]) << 8) | (static_cast<uint64_t>(p[n - 1]) << 16);
    }
    // The low bits of a product depend only on the low bits of its factors,
    // and the slot is chosen by the low bits: the high half is folded down,
    // multiplied through and folded again, so every input bit reaches them.
    h = (h ^ w) * 0x94D049BB133111EBull;
    h ^= h >> 32;
    h *= 0x9E3779B97F4A7C15ull;
    h ^= h >> 32;
    return h;
  }
};

}  // namespace text
}  // namespace moro
