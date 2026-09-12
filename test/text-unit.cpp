// Differential unit test for src/text.h: the word-at-a-time ASCII scan and
// the Latin-1 -> UTF-8 encoder must agree with byte-at-a-time reference
// implementations on every byte value, every buffer length up to a few words,
// and random buffers (so odd tails and mid-word non-ASCII bytes are covered).
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/text.h"

static int checks = 0;
static int failures = 0;
#define CHECK(cond)                                                          \
  do {                                                                       \
    ++checks;                                                                \
    if (!(cond)) {                                                           \
      ++failures;                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
    }                                                                        \
  } while (0)

static bool refIsAscii(const std::vector<uint8_t>& v) {
  for (uint8_t b : v)
    if (b >= 0x80) return false;
  return true;
}

static std::string refLatin1ToUtf8(const std::vector<uint8_t>& v) {
  std::string out;
  for (uint8_t c : v) {
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else {
      // U+0080..U+00FF: 110xxxxx 10xxxxxx
      out.push_back(static_cast<char>(0xC0 | (c >> 6)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
  return out;
}

static uint32_t rng = 0x9E3779B9u;
static uint8_t nextByte() {
  rng = rng * 1664525u + 1013904223u;
  return static_cast<uint8_t>(rng >> 24);
}

int main() {
  using moro::text::isAscii;
  using moro::text::latin1ToUtf8;
  std::string out;

  // Every single byte value, alone.
  for (int b = 0; b < 256; ++b) {
    std::vector<uint8_t> v{static_cast<uint8_t>(b)};
    CHECK(isAscii(v.data(), v.size()) == refIsAscii(v));
    latin1ToUtf8(v.data(), v.size(), out);
    CHECK(out == refLatin1ToUtf8(v));
  }

  // Empty input.
  CHECK(isAscii(nullptr, 0) == true);
  latin1ToUtf8(nullptr, 0, out);
  CHECK(out.empty());

  // One non-ASCII byte at every position of buffers spanning several words
  // (catches a wrong mask, a wrong tail loop, an off-by-one at a word edge).
  for (size_t len = 1; len <= 40; ++len) {
    for (size_t pos = 0; pos < len; ++pos) {
      std::vector<uint8_t> v(len, 'a');
      v[pos] = 0xE9;  // 'é'
      CHECK(isAscii(v.data(), v.size()) == false);
      latin1ToUtf8(v.data(), v.size(), out);
      CHECK(out == refLatin1ToUtf8(v));
      CHECK(out.size() == len + 1);
    }
    std::vector<uint8_t> all(len, 'z');
    CHECK(isAscii(all.data(), all.size()) == true);
  }

  // Random buffers, both mixed and forced-ASCII.
  for (int iter = 0; iter < 20000; ++iter) {
    const size_t len = nextByte() % 96;
    std::vector<uint8_t> v(len);
    const bool forceAscii = (nextByte() & 1) != 0;
    for (size_t i = 0; i < len; ++i) v[i] = forceAscii ? (nextByte() & 0x7F) : nextByte();
    CHECK(isAscii(v.data(), v.size()) == refIsAscii(v));
    latin1ToUtf8(v.data(), v.size(), out);
    CHECK(out == refLatin1ToUtf8(v));
  }

  // The reused-output contract: a second encode replaces, never appends.
  std::vector<uint8_t> a{'x', 0xFF};
  latin1ToUtf8(a.data(), a.size(), out);
  std::vector<uint8_t> b{'y'};
  latin1ToUtf8(b.data(), b.size(), out);
  CHECK(out == "y");

  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all text unit tests passed (%d checks)\n", checks);
  return 0;
}
