// V8 API shims for the per-ABI builds (Node 20..26 = V8 11.3..14.6).
//
// Every V8 API whose shape changed inside that range is wrapped here ONCE, so
// the hot path never carries its own #if forest. The fences are by V8
// major.minor, taken from the headers each ABI is compiled against.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <v8.h>
#include <v8-version.h>

#include <cstdint>

#define MORO_V8_AT_LEAST(maj, min) \
  (V8_MAJOR_VERSION > (maj) || (V8_MAJOR_VERSION == (maj) && V8_MINOR_VERSION >= (min)))

// String::ValueView (zero-copy read of a flat string's bytes): V8 12.9+
// (Node 23+). Older ABIs copy through String::WriteOneByte instead.
#define MORO_V8_HAS_VALUE_VIEW MORO_V8_AT_LEAST(12, 9)

// String::WriteOneByteV2 replaced WriteOneByte in V8 13.6 (Node 24; the old
// spelling is deprecated there and gone in 14.6 / Node 26).
#define MORO_V8_HAS_WRITE_V2 MORO_V8_AT_LEAST(13, 6)

namespace moro {
namespace v8compat {

// Copy exactly `len` one-byte code units of a one-byte string into `out`
// (no NUL terminator). The caller guarantees len <= s->Length() and that
// s->IsOneByte() - the V2 API CHECKs the range.
inline void writeOneByte(v8::Isolate* iso, v8::Local<v8::String> s, uint8_t* out,
                         uint32_t len) {
  if (len == 0) return;
#if MORO_V8_HAS_WRITE_V2
  s->WriteOneByteV2(iso, 0, len, out, /*flags=*/0);
#else
  s->WriteOneByte(iso, out, 0, static_cast<int>(len), v8::String::NO_NULL_TERMINATION);
#endif
}

// The V8 runtime this binary runs on, as "major.minor" - compared against the
// compiled V8_MAJOR/MINOR to refuse installing anything ABI-shaped (fast
// calls) on a mismatched host.
inline bool runtimeVersionMatches(int* rtMajor = nullptr, int* rtMinor = nullptr) {
  const char* v = v8::V8::GetVersion();  // e.g. "13.6.233.10-node.28"
  int maj = 0, min = 0;
  const char* p = v ? v : "";
  while (*p >= '0' && *p <= '9') maj = maj * 10 + (*p++ - '0');
  if (*p == '.') {
    ++p;
    while (*p >= '0' && *p <= '9') min = min * 10 + (*p++ - '0');
  }
  if (rtMajor) *rtMajor = maj;
  if (rtMinor) *rtMinor = min;
  return maj == V8_MAJOR_VERSION && min == V8_MINOR_VERSION;
}

}  // namespace v8compat
}  // namespace moro
