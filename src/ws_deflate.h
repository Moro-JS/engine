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
  int serverMaxWindowBits = 15;  // 9..15 (8 is never negotiated; see parsePmdOffer)
  int clientMaxWindowBits = 15;  // 9..15
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
    // §7.1.2.2: client_max_window_bits may appear in the response only when
    // the client's offer contained the parameter.
    bool sawClientMaxWindowBits = false;

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
          // No valid window-bits value exceeds 15; bailing here also bounds n
          // (an attacker-length digit string would overflow int - UB).
          if (n > 15) return false;
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
        sawClientMaxWindowBits = true;
        if (eq != std::string_view::npos) {
          int bits;
          // Acceptable range is 9..15: zlib's raw deflate cannot produce an
          // 8-bit window, and answering 9 to an offer of 8 exceeds the offer
          // (the client then MUST fail the connection, §7.1.2.1).
          if (!toInt(val, bits) || bits < 9 || bits > 15) {
            ok = false;
          } else if (bits < p.clientMaxWindowBits) {
            p.clientMaxWindowBits = bits;  // honor the client's smaller window
          }
        }
      } else if (key == "server_max_window_bits") {
        int bits;
        // 9..15 only, same constraint as client_max_window_bits (§7.1.2.1).
        if (!toInt(val, bits) || bits < 9 || bits > 15) {
          ok = false;
        } else if (bits < p.serverMaxWindowBits) {
          p.serverMaxWindowBits = bits;  // client caps our window
        }
      } else {
        ok = false;  // unknown parameter -> decline this offer (RFC 7692 §5.1)
      }
    }
    if (ok) {
      // §7.1.2.2: without the client's opt-in the response cannot carry
      // client_max_window_bits, so the client will use its full 15-bit
      // window - any configured preference below 15 must be dropped
      // (buildPmdResponse emits the param only when < 15).
      if (!sawClientMaxWindowBits) p.clientMaxWindowBits = 15;
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

// Deflate one whole message through `zs` per RFC 7692 §7.2.1: Z_SYNC_FLUSH,
// then strip the trailing 4-byte 0x00 0x00 0xFF 0xFF empty-block tail. Shared
// by PmdContext (per-connection deflate) and SharedDeflator (server-owned
// stream); context-takeover policy (whether/when to deflateReset) stays with
// the caller. deflateBound() is a worst-case output size for a Z_FINISH
// stream with this stream's params; Z_SYNC_FLUSH's empty stored block can run
// at most ~5 bytes past it (incompressible input), so the reserve saves the
// append loop's reallocation in all but that worst case.
inline bool pmdDeflateMessage(z_stream& zs, std::string_view in, std::string& out) {
  out.clear();
  out.reserve(deflateBound(&zs, static_cast<uLong>(in.size())));
  zs.next_in = reinterpret_cast<unsigned char*>(const_cast<char*>(in.data()));
  zs.avail_in = static_cast<uInt>(in.size());
  unsigned char buf[16384];
  do {
    zs.next_out = buf;
    zs.avail_out = sizeof(buf);
    int r = deflate(&zs, Z_SYNC_FLUSH);
    if (r != Z_OK && r != Z_BUF_ERROR) return false;
    out.append(reinterpret_cast<char*>(buf), sizeof(buf) - zs.avail_out);
  } while (zs.avail_out == 0);

  // Strip the 4-byte empty-block tail that Z_SYNC_FLUSH appends.
  if (out.size() >= 4) out.resize(out.size() - 4);
  return true;
}

// Per-connection compression contexts. Inflate handles inbound (RSV1) messages;
// deflate handles outbound sends. Both are raw deflate (negative windowBits).
class PmdContext {
 public:
  // InflateOnly: connections whose outbound compression goes through the
  // server's SharedDeflator (PmdOptions::sharedCompressor) never deflate
  // here - skipping deflateInit2 saves the ~256 KB per-connection deflate
  // state, which is the entire point of that option. Full is the default
  // per-connection mode (inflate + deflate), unchanged.
  enum class Mode { Full, InflateOnly };

  PmdContext(const PmdParams& params, size_t maxDecompressed, Mode mode = Mode::Full)
      : params_(params),
        maxDecompressed_(maxDecompressed),
        inflateOnly_(mode == Mode::InflateOnly) {
    // A zero cap would disable the inflate output cap (zip-bomb defense);
    // refuse it - valid() stays false - so no caller can run uncapped.
    if (maxDecompressed_ == 0) return;
    inflate_.zalloc = Z_NULL;
    inflate_.zfree = Z_NULL;
    inflate_.opaque = Z_NULL;
    inflateOk_ = inflateInit2(&inflate_, -params_.clientMaxWindowBits) == Z_OK;

    if (inflateOnly_) return;  // no per-connection deflate stream (see Mode)
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

  bool valid() const { return inflateOk_ && (deflateOk_ || inflateOnly_); }

  // Inflate a received compressed message payload (RFC 7692 §7.2.2: append the
  // 4-byte 0x00 0x00 0xFF 0xFF tail before inflating). Returns false on a
  // corrupt stream OR when the output would exceed maxDecompressed_ (zip-bomb
  // defense); out holds the decompressed bytes on success.
  bool inflateMessage(std::string_view in, std::string& out) {
    if (!inflateOk_) return false;
    out.clear();
    // Typical text ratios are 3-5x; a modest up-front reserve avoids repeated
    // 16 KiB-append reallocation without pre-committing the whole cap.
    out.reserve(in.size() < maxDecompressed_ / 4 ? in.size() * 4 : maxDecompressed_);
    static const unsigned char kTail[4] = {0x00, 0x00, 0xFF, 0xFF};

    // Set when a BFINAL=1 block finished the DEFLATE stream exactly at the
    // end of the consumed input (RFC 7692 §7.2.3.6 permits ending a message
    // this way; one message may even hold several such streams back to back).
    bool streamEnded = false;

    auto run = [&](const unsigned char* data, size_t len, int flush) -> bool {
      inflate_.next_in = const_cast<unsigned char*>(data);
      inflate_.avail_in = static_cast<uInt>(len);
      unsigned char buf[16384];
      for (;;) {
        inflate_.next_out = buf;
        inflate_.avail_out = sizeof(buf);
        int r = inflate(&inflate_, flush);
        if (r != Z_OK && r != Z_BUF_ERROR && r != Z_STREAM_END) return false;
        size_t produced = sizeof(buf) - inflate_.avail_out;
        if (out.size() + produced > maxDecompressed_) return false;
        out.append(reinterpret_cast<char*>(buf), produced);
        if (r == Z_STREAM_END) {
          // BFINAL=1 put the stream in DONE; reset - otherwise every later
          // message on this context inflates to "" - and keep consuming this
          // message's remaining input.
          if (inflateReset(&inflate_) != Z_OK) return false;
          if (inflate_.avail_in == 0) {
            streamEnded = true;
            return true;
          }
          continue;
        }
        if (r == Z_BUF_ERROR) return true;         // no progress possible: input exhausted
        if (inflate_.avail_out != 0) return true;  // input consumed this pass
      }
    };

    if (!in.empty() &&
        !run(reinterpret_cast<const unsigned char*>(in.data()), in.size(), Z_NO_FLUSH))
      return false;
    // §7.2.2's appended tail completes the empty stored block a stripped
    // Z_SYNC_FLUSH left open. When the message ended its stream outright
    // (BFINAL=1) no block is open: on the reset stream the 4 tail bytes would
    // begin a PARTIAL stored block (LEN/NLEN unfinished), corrupting the next
    // message's input - so the tail MUST be skipped.
    if (!streamEnded && !run(kTail, sizeof(kTail), Z_SYNC_FLUSH)) return false;

    if (params_.clientNoContextTakeover) inflateReset(&inflate_);
    return true;
  }

  // Deflate a message for sending (RFC 7692 §7.2.1: Z_SYNC_FLUSH, then strip
  // the trailing 4-byte 0x00 0x00 0xFF 0xFF). Returns false on error (always,
  // in InflateOnly mode - outbound compression belongs to SharedDeflator).
  bool deflateMessage(std::string_view in, std::string& out) {
    if (!deflateOk_) return false;
    if (!pmdDeflateMessage(deflate_, in, out)) return false;
    if (params_.serverNoContextTakeover) deflateReset(&deflate_);
    return true;
  }

  size_t threshold() const { return threshold_; }
  void setThreshold(size_t t) { threshold_ = t; }

 private:
  PmdParams params_;
  size_t maxDecompressed_;
  size_t threshold_ = 1024;
  bool inflateOnly_ = false;
  z_stream inflate_{};
  z_stream deflate_{};
  bool inflateOk_ = false;
  bool deflateOk_ = false;
};

// One server-owned deflate stream shared across ALL permessage-deflate
// connections (PmdOptions::sharedCompressor). The stream is unconditionally
// deflateReset() after every message - that reset IS the
// server_no_context_takeover semantics the negotiated response advertises
// (RFC 7692 §7.1.1.1), and it is what makes one stream shareable: no message
// ever back-references a previous message's window, so interleaving messages
// from different connections cannot leak bytes across them. The trade: no
// cross-message compression context (worse per-message ratio) in exchange
// for ~262 KB of deflate state saved per connection.
class SharedDeflator {
 public:
  // windowBits is the server's CONFIGURED serverMaxWindowBits (9..15). The
  // window is fixed for the stream's lifetime: connections negotiated to a
  // smaller server window cannot use this stream (server.h falls back to a
  // per-connection PmdContext for them).
  explicit SharedDeflator(int windowBits) {
    deflate_.zalloc = Z_NULL;
    deflate_.zfree = Z_NULL;
    deflate_.opaque = Z_NULL;
    ok_ = deflateInit2(&deflate_, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                       -windowBits, 8, Z_DEFAULT_STRATEGY) == Z_OK;
  }
  SharedDeflator(const SharedDeflator&) = delete;
  SharedDeflator& operator=(const SharedDeflator&) = delete;
  ~SharedDeflator() {
    if (ok_) deflateEnd(&deflate_);
  }

  bool valid() const { return ok_; }

  // Same wire format as PmdContext::deflateMessage, followed by an
  // UNCONDITIONAL deflateReset (the no-context-takeover semantics). Reset
  // even when the deflate loop failed, so one bad message cannot poison the
  // stream for every other connection's next send.
  bool deflateMessage(std::string_view in, std::string& out) {
    if (!ok_) return false;
    bool produced = pmdDeflateMessage(deflate_, in, out);
    if (deflateReset(&deflate_) != Z_OK) ok_ = false;
    return produced && ok_;
  }

 private:
  z_stream deflate_{};
  bool ok_ = false;
};

}  // namespace engine
}  // namespace moro
