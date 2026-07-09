// sha1.h — clean-room SHA-1 (FIPS 180-4) and Base64 (RFC 4648 §4).
//
// Written directly from the specifications; no code taken from any other
// implementation (see CONTRIBUTING.md original-code policy).
//
// SHA-1 here exists solely to compute the WebSocket handshake accept key
// (RFC 6455 §4.2.2 step 5.4). It is not used for any security purpose that
// depends on SHA-1's (broken) collision resistance, so correctness — not
// hardening — is the bar.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace moro::engine {

namespace detail {

// FIPS 180-4 §3.2: circular left shift on 32-bit words.
inline uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

}  // namespace detail

// SHA-1 per FIPS 180-4 §6.1. One-shot over a contiguous buffer.
inline void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
  // §5.3.1: initial hash value H(0).
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                   0xC3D2E1F0u};

  // §6.1.2: process one 512-bit (64-byte) message block.
  auto processBlock = [&h](const uint8_t* p) {
    // §6.1.2 step 1: prepare the message schedule W[0..79].
    uint32_t w[80];
    for (int t = 0; t < 16; ++t) {
      w[t] = (uint32_t(p[4 * t]) << 24) | (uint32_t(p[4 * t + 1]) << 16) |
             (uint32_t(p[4 * t + 2]) << 8) | uint32_t(p[4 * t + 3]);
    }
    for (int t = 16; t < 80; ++t) {
      w[t] = detail::rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    // §6.1.2 step 2: initialize working variables.
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    // §6.1.2 step 3: 80 rounds using the §4.1.1 functions f_t and the
    // §4.2.1 constants K_t.
    for (int t = 0; t < 80; ++t) {
      uint32_t f, k;
      if (t < 20) {
        f = (b & c) | (~b & d);  // Ch(b,c,d)
        k = 0x5A827999u;
      } else if (t < 40) {
        f = b ^ c ^ d;  // Parity(b,c,d)
        k = 0x6ED9EBA1u;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);  // Maj(b,c,d)
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;  // Parity(b,c,d)
        k = 0xCA62C1D6u;
      }
      uint32_t tmp = detail::rotl32(a, 5) + f + e + k + w[t];
      e = d;
      d = c;
      c = detail::rotl32(b, 30);
      b = a;
      a = tmp;
    }

    // §6.1.2 step 4: compute the intermediate hash value.
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  };

  // Hash all complete blocks in place.
  size_t i = 0;
  for (; i + 64 <= len; i += 64) {
    processBlock(data + i);
  }

  // §5.1.1: padding — append 0x80, then zeros, so that the final 8 bytes
  // hold the message length in bits as a 64-bit big-endian integer. The
  // tail spans one block, or two when fewer than 9 bytes remain free.
  uint8_t tail[128] = {0};
  const size_t rem = len - i;
  for (size_t j = 0; j < rem; ++j) {
    tail[j] = data[i + j];
  }
  tail[rem] = 0x80;
  const size_t tailLen = (rem + 1 + 8 <= 64) ? 64 : 128;
  const uint64_t bitLen = uint64_t(len) * 8;
  for (int j = 0; j < 8; ++j) {
    tail[tailLen - 1 - j] = uint8_t(bitLen >> (8 * j));
  }
  processBlock(tail);
  if (tailLen == 128) {
    processBlock(tail + 64);
  }

  // §6.1.2: the digest is H0..H4, big-endian (§3.1 word-to-byte order).
  for (int j = 0; j < 5; ++j) {
    out[4 * j] = uint8_t(h[j] >> 24);
    out[4 * j + 1] = uint8_t(h[j] >> 16);
    out[4 * j + 2] = uint8_t(h[j] >> 8);
    out[4 * j + 3] = uint8_t(h[j]);
  }
}

// Base64 per RFC 4648 §4: standard alphabet, '=' padding (§3.5 requires
// canonical zero pad bits, which this construction produces by design).
inline std::string base64(const uint8_t* data, size_t len) {
  // RFC 4648 Table 1: the Base 64 alphabet.
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  out.reserve(((len + 2) / 3) * 4);

  size_t i = 0;
  for (; i + 3 <= len; i += 3) {
    const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) |
                       uint32_t(data[i + 2]);
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += kAlphabet[v & 63];
  }

  const size_t rem = len - i;
  if (rem == 1) {
    // §4: final quantum of 8 bits -> two characters + "==".
    const uint32_t v = uint32_t(data[i]) << 16;
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += "==";
  } else if (rem == 2) {
    // §4: final quantum of 16 bits -> three characters + "=".
    const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += '=';
  }
  return out;
}

}  // namespace moro::engine
