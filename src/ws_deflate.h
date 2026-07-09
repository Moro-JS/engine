// WebSocket permessage-deflate (RFC 7692) for @morojs/engine.
//
// Opt-in (off by default) - it stays declined unless serve() enables it,
// preserving the engine's default posture (a compression side-channel is an
// app-level decision). zlib is the one bundled inside the host Node binary
// (symbols verified per-ABI in CI), same linkage model as TLS.
//
// This header is pure: negotiation parsing + per-message inflate/deflate over
// raw-deflate z_streams, with a hard output cap on inflate (zip-bomb defense).
// It holds no socket state; server.h owns the per-connection PmdContext.
//
// Original-code policy (CONTRIBUTING.md); zlib API usage per the
// official manual, RFC 7692 for the framing/negotiation rules.

#pragma once

#include <zlib.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "pmd_options.h"  // PmdOptions

namespace moro {
namespace engine {

// Negotiated permessage-deflate parameters for one connection (RFC 7692 §7).
struct PmdParams {
  bool serverNoContextTakeover = false;
  bool clientNoContextTakeover = false;
  int serverMaxWindowBits = 15;  // 8..15 (zlib treats 8 as 9)
  int clientMaxWindowBits = 15;  // 8..15
};

// Trim OWS from both ends of a view.
inline std::string_view pmdTrim(std::string_view s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
  return s.substr(b, e - b);
}

// Parse a client Sec-WebSocket-Extensions offer and, if it contains an
// acceptable permessage-deflate offer, return the negotiated params bounded by
// the server's PmdOptions. Returns nullopt when no offer is acceptable (the
// extension is then simply not negotiated - a valid outcome). Only the FIRST
// acceptable permessage-deflate offer is honored (RFC 7692 §5.1).
inline std::optional<PmdParams> parsePmdOffer(std::string_view header,
                                              const PmdOptions& opt) {
  if (!opt.enabled) return std::nullopt;
  // Offers are comma-separated; each is "; "-separated params.
  size_t i = 0;
  while (i < header.size()) {
    size_t comma = header.find(',', i);
    std::string_view offer =
        pmdTrim(header.substr(i, comma == std::string_view::npos ? std::string_view::npos
                                                                 : comma - i));
    i = (comma == std::string_view::npos) ? header.size() : comma + 1;

    // Extension name is the token before the first ';'.
    size_t semi = offer.find(';');
    std::string_view name = pmdTrim(offer.substr(0, semi));
    if (name != "permessage-deflate") continue;

    PmdParams p;
    p.serverNoContextTakeover = opt.serverNoContextTakeover;
    p.clientNoContextTakeover = opt.clientNoContextTakeover;
    p.serverMaxWindowBits = opt.serverMaxWindowBits;
    p.clientMaxWindowBits = opt.clientMaxWindowBits;
    bool ok = true;

    size_t j = (semi == std::string_view::npos) ? offer.size() : semi + 1;
    while (j < offer.size() && ok) {
      size_t s2 = offer.find(';', j);
      std::string_view param =
          pmdTrim(offer.substr(j, s2 == std::string_view::npos ? std::string_view::npos : s2 - j));
      j = (s2 == std::string_view::npos) ? offer.size() : s2 + 1;
      if (param.empty()) continue;

      size_t eq = param.find('=');
      std::string_view key = pmdTrim(param.substr(0, eq));
      std::string_view val =
          eq == std::string_view::npos ? std::string_view{} : pmdTrim(param.substr(eq + 1));
      // Values may be quoted.
      if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
        val = val.substr(1, val.size() - 2);

      auto toInt = [](std::string_view v, int& out) -> bool {
        if (v.empty()) return false;
        int n = 0;
        for (char c : v) {
          if (c < '0' || c > '9') return false;
          n = n * 10 + (c - '0');
        }
        out = n;
        return true;
      };

      if (key == "client_no_context_takeover") {
        p.clientNoContextTakeover = true;  // client offers to reset its context
      } else if (key == "server_no_context_takeover") {
        p.serverNoContextTakeover = true;  // client requires us to reset ours
      } else if (key == "client_max_window_bits") {
        // May be a bare flag (client supports the param) or a value.
        if (eq != std::string_view::npos) {
          int bits;
          if (!toInt(val, bits) || bits < 8 || bits > 15) {
            ok = false;
          } else if (bits < p.clientMaxWindowBits) {
            p.clientMaxWindowBits = bits;  // honor the client's smaller window
          }
        }
      } else if (key == "server_max_window_bits") {
        int bits;
        if (!toInt(val, bits) || bits < 8 || bits > 15) {
          ok = false;
        } else if (bits < p.serverMaxWindowBits) {
          p.serverMaxWindowBits = bits;  // client caps our window
        }
      } else {
        ok = false;  // unknown parameter -> decline this offer (RFC 7692 §5.1)
      }
    }
    if (ok) {
      // zlib's minimum windowBits is 9 for raw deflate; clamp 8 up to 9.
      if (p.serverMaxWindowBits < 9) p.serverMaxWindowBits = 9;
      if (p.clientMaxWindowBits < 9) p.clientMaxWindowBits = 9;
      return p;
    }
    // else try the next offer
  }
  return std::nullopt;
}

// Build the Sec-WebSocket-Extensions response header value for negotiated
// params. Mirrors back only what we agreed to (RFC 7692 §7).
inline std::string buildPmdResponse(const PmdParams& p) {
  std::string out = "permessage-deflate";
  if (p.clientNoContextTakeover) out += "; client_no_context_takeover";
  if (p.serverNoContextTakeover) out += "; server_no_context_takeover";
  if (p.serverMaxWindowBits < 15) {
    out += "; server_max_window_bits=";
    out += std::to_string(p.serverMaxWindowBits);
  }
  if (p.clientMaxWindowBits < 15) {
    out += "; client_max_window_bits=";
    out += std::to_string(p.clientMaxWindowBits);
  }
  return out;
}

// Per-connection compression contexts. Inflate handles inbound (RSV1) messages;
// deflate handles outbound sends. Both are raw deflate (negative windowBits).
class PmdContext {
 public:
  PmdContext(const PmdParams& params, size_t maxDecompressed)
      : params_(params), maxDecompressed_(maxDecompressed) {
    inflate_.zalloc = Z_NULL;
    inflate_.zfree = Z_NULL;
    inflate_.opaque = Z_NULL;
    inflateOk_ = inflateInit2(&inflate_, -params_.clientMaxWindowBits) == Z_OK;

    deflate_.zalloc = Z_NULL;
    deflate_.zfree = Z_NULL;
    deflate_.opaque = Z_NULL;
    deflateOk_ = deflateInit2(&deflate_, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                              -params_.serverMaxWindowBits, 8,
                              Z_DEFAULT_STRATEGY) == Z_OK;
  }
  PmdContext(const PmdContext&) = delete;
  PmdContext& operator=(const PmdContext&) = delete;
  ~PmdContext() {
    if (inflateOk_) inflateEnd(&inflate_);
    if (deflateOk_) deflateEnd(&deflate_);
  }

  bool valid() const { return inflateOk_ && deflateOk_; }

  // Inflate a received compressed message payload (RFC 7692 §7.2.2: append the
  // 4-byte 0x00 0x00 0xFF 0xFF tail before inflating). Returns false on a
  // corrupt stream OR when the output would exceed maxDecompressed_ (zip-bomb
  // defense); out holds the decompressed bytes on success.
  bool inflateMessage(std::string_view in, std::string& out) {
    if (!inflateOk_) return false;
    out.clear();
    static const unsigned char kTail[4] = {0x00, 0x00, 0xFF, 0xFF};

    auto run = [&](const unsigned char* data, size_t len, int flush) -> bool {
      inflate_.next_in = const_cast<unsigned char*>(data);
      inflate_.avail_in = static_cast<uInt>(len);
      unsigned char buf[16384];
      do {
        inflate_.next_out = buf;
        inflate_.avail_out = sizeof(buf);
        int r = inflate(&inflate_, flush);
        if (r != Z_OK && r != Z_BUF_ERROR && r != Z_STREAM_END) return false;
        size_t produced = sizeof(buf) - inflate_.avail_out;
        if (maxDecompressed_ && out.size() + produced > maxDecompressed_) return false;
        out.append(reinterpret_cast<char*>(buf), produced);
        if (r == Z_BUF_ERROR && inflate_.avail_in == 0) break;
      } while (inflate_.avail_out == 0);
      return true;
    };

    if (!in.empty() &&
        !run(reinterpret_cast<const unsigned char*>(in.data()), in.size(), Z_NO_FLUSH))
      return false;
    if (!run(kTail, sizeof(kTail), Z_SYNC_FLUSH)) return false;

    if (params_.clientNoContextTakeover) inflateReset(&inflate_);
    return true;
  }

  // Deflate a message for sending (RFC 7692 §7.2.1: Z_SYNC_FLUSH, then strip
  // the trailing 4-byte 0x00 0x00 0xFF 0xFF). Returns false on error.
  bool deflateMessage(std::string_view in, std::string& out) {
    if (!deflateOk_) return false;
    out.clear();
    deflate_.next_in = reinterpret_cast<unsigned char*>(const_cast<char*>(in.data()));
    deflate_.avail_in = static_cast<uInt>(in.size());
    unsigned char buf[16384];
    do {
      deflate_.next_out = buf;
      deflate_.avail_out = sizeof(buf);
      int r = deflate(&deflate_, Z_SYNC_FLUSH);
      if (r != Z_OK && r != Z_BUF_ERROR) return false;
      out.append(reinterpret_cast<char*>(buf), sizeof(buf) - deflate_.avail_out);
    } while (deflate_.avail_out == 0);

    // Strip the 4-byte empty-block tail that Z_SYNC_FLUSH appends.
    if (out.size() >= 4) out.resize(out.size() - 4);
    if (params_.serverNoContextTakeover) deflateReset(&deflate_);
    return true;
  }

  size_t threshold() const { return threshold_; }
  void setThreshold(size_t t) { threshold_ = t; }

 private:
  PmdParams params_;
  size_t maxDecompressed_;
  size_t threshold_ = 1024;
  z_stream inflate_{};
  z_stream deflate_{};
  bool inflateOk_ = false;
  bool deflateOk_ = false;
};

}  // namespace engine
}  // namespace moro
