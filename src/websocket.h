// websocket.h — RFC 6455 WebSocket protocol logic (server side).
//
// Pure protocol code: operates on byte buffers only, performs zero I/O. Written directly from RFC 6455 (protocol behaviors cite their sections below);
// (see CONTRIBUTING.md policy).
//
// Scope notes:
// - Server role only: incoming (client) frames MUST be masked and outgoing
//   (server) frames MUST NOT be masked (§5.1).
// - No extensions are negotiated; permessage-deflate is declined simply by
//   omitting Sec-WebSocket-Extensions from the handshake response (§9.1),
//   therefore all RSV bits MUST be 0 on the wire (§5.2).

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>

#include "sha1.h"

namespace moro::engine {

// ---------------------------------------------------------------------------
// Opening handshake (RFC 6455 §4.2)
// ---------------------------------------------------------------------------

// §4.2.2 step 5.4: the accept key is the base64 encoding of the SHA-1 of the
// client's Sec-WebSocket-Key value concatenated with the fixed GUID
// "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (defined in §1.3).
inline std::string computeAcceptKey(std::string_view secWebSocketKey) {
  static constexpr std::string_view kGuid =
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string joined;
  joined.reserve(secWebSocketKey.size() + kGuid.size());
  joined.append(secWebSocketKey);
  joined.append(kGuid);
  uint8_t digest[20];
  sha1(reinterpret_cast<const uint8_t*>(joined.data()), joined.size(), digest);
  return base64(digest, sizeof(digest));
}

// §4.1 handshake requirement 7: |Sec-WebSocket-Key| is the base64 encoding of
// a 16-byte nonce - exactly 24 bytes on the wire: 22 base64-alphabet chars
// followed by "==" padding. The accept-key math is well-defined for any input,
// so this is early rejection of malformed/probing clients (§4.2.1 requires
// refusing a handshake whose requirements aren't met), not a safety need.
// (Canonical zero low-bits of the 22nd char are deliberately not enforced.)
inline bool isValidWsKey(std::string_view key) {
  if (key.size() != 24) return false;
  for (size_t i = 0; i < 22; ++i) {
    const char c = key[i];
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/';
    if (!ok) return false;
  }
  return key[22] == '=' && key[23] == '=';
}

// Builds the complete server handshake response head per §4.2.2 step 5:
// a 101 status line plus Upgrade, Connection, and Sec-WebSocket-Accept
// headers. An optional Sec-WebSocket-Extensions value accepts a negotiated
// extension (permessage-deflate, RFC 7692); when empty, every offered
// extension is declined (§9.1). No subprotocol is selected (§4.2.2/5.5).
inline std::string buildHandshakeResponse(std::string_view secWebSocketKey,
                                          std::string_view extensions = {}) {
  std::string out;
  out.reserve(160 + extensions.size());
  out +=
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: ";
  out += computeAcceptKey(secWebSocketKey);
  if (!extensions.empty()) {
    out += "\r\nSec-WebSocket-Extensions: ";
    out += extensions;
  }
  out += "\r\n\r\n";
  return out;
}

// ---------------------------------------------------------------------------
// Framing (RFC 6455 §5)
// ---------------------------------------------------------------------------

// §5.2 / §11.8: opcode registry. %x3-7 and %xB-F are reserved and MUST be
// treated as a protocol failure when received (§5.2).
enum class WsOpcode : uint8_t {
  Continuation = 0x0,
  Text = 0x1,
  Binary = 0x2,
  Close = 0x8,
  Ping = 0x9,
  Pong = 0xA
};

// UTF-8 validation per RFC 3629 §4 (the syntax RFC 6455 §8.1 defers to):
// rejects overlong encodings, surrogate code points U+D800..U+DFFF, values
// above U+10FFFF, bare/misplaced continuation bytes, and truncated
// sequences. Used for text message payloads (§5.6) and close reasons
// (§5.5.1); invalid data MUST fail the WebSocket connection (§8.1, §7.1.7).
inline bool isValidUtf8(std::string_view s) {
  const size_t n = s.size();
  size_t i = 0;
  while (i < n) {
    const uint8_t b = uint8_t(s[i]);
    if (b < 0x80) {  // one byte: U+0000..U+007F
      ++i;
      continue;
    }
    size_t cont;    // number of continuation bytes required
    uint32_t cp;    // code point being decoded
    uint32_t min;   // smallest code point this length may encode (overlongs)
    if ((b & 0xE0) == 0xC0) {  // two bytes: U+0080..U+07FF
      cont = 1;
      cp = b & 0x1F;
      min = 0x80;
    } else if ((b & 0xF0) == 0xE0) {  // three bytes: U+0800..U+FFFF
      cont = 2;
      cp = b & 0x0F;
      min = 0x800;
    } else if ((b & 0xF8) == 0xF0) {  // four bytes: U+10000..U+10FFFF
      cont = 3;
      cp = b & 0x07;
      min = 0x10000;
    } else {
      return false;  // 0x80..0xBF stray continuation, or 0xF8..0xFF
    }
    if (cont >= n - i) return false;  // truncated sequence
    for (size_t k = 1; k <= cont; ++k) {
      const uint8_t c = uint8_t(s[i + k]);
      if ((c & 0xC0) != 0x80) return false;  // not a continuation byte
      cp = (cp << 6) | (c & 0x3F);
    }
    if (cp < min) return false;                      // overlong encoding
    if (cp > 0x10FFFF) return false;                 // beyond Unicode range
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // UTF-16 surrogates
    i += cont + 1;
  }
  return true;
}

// Streaming UTF-8 validator: the incremental form of isValidUtf8 above,
// enforcing the same RFC 3629 §4 rules (overlong encodings, UTF-16
// surrogates, code points above U+10FFFF, stray continuation bytes, invalid
// leading bytes). Bytes may arrive in any splits — a multi-byte sequence can
// span chunk boundaries (WebSocket fragment or consume()-call boundaries,
// §5.4) — so truncation is not knowable per chunk: the caller checks
// complete() at end-of-message. Lets a text message be rejected (1007) at
// the offending chunk instead of after buffering the whole message.
class Utf8Validator {
 public:
  // Feed the next chunk. Returns false at the first byte that makes the
  // stream irrecoverably invalid (no suffix could make it valid UTF-8); the
  // validator is then in an undefined state — reset() before reuse.
  bool accept(std::string_view s) {
    const char* p = s.data();
    const char* const end = p + s.size();
    while (p != end) {
      if (need_ == 0) {
        // Between sequences, ASCII goes by eight bytes at a time: a word with
        // no high bit set is eight one-byte characters. Most text is nothing
        // else, and a byte at a time it cost seven instructions each. A long
        // run goes by thirty-two first, four words tested at once; the word
        // with the high bit, when there is one, is then found eight at a time.
        while (end - p >= 32) {
          uint64_t a, b, c, d;
          std::memcpy(&a, p, 8);
          std::memcpy(&b, p + 8, 8);
          std::memcpy(&c, p + 16, 8);
          std::memcpy(&d, p + 24, 8);
          if ((a | b | c | d) & 0x8080808080808080ull) break;
          p += 32;
        }
        while (end - p >= 8) {
          uint64_t w;
          std::memcpy(&w, p, 8);
          if (w & 0x8080808080808080ull) break;
          p += 8;
        }
        if (p == end) break;
      }
      const uint8_t b = uint8_t(*p++);
      if (need_ == 0) {
        if (b < 0x80) continue;               // one byte: U+0000..U+007F
        // The first continuation byte of a sequence has a narrower range
        // after four lead bytes (RFC 3629 §4): E0 A0..BF (below that is an
        // overlong form), ED 80..9F (above it is a surrogate), F0 90..BF
        // (overlong), F4 80..8F (above it is past U+10FFFF). Checking it
        // there rejects the sequence at the byte that makes it invalid, not
        // when its last byte arrives.
        lo_ = 0x80;
        hi_ = 0xBF;
        if ((b & 0xE0) == 0xC0) {             // two bytes: U+0080..U+07FF
          if (b < 0xC2) return false;         // C0/C1 can only start an overlong form
          need_ = 1;
          cp_ = b & 0x1F;
          min_ = 0x80;
        } else if ((b & 0xF0) == 0xE0) {      // three bytes: U+0800..U+FFFF
          need_ = 2;
          cp_ = b & 0x0F;
          min_ = 0x800;
          if (b == 0xE0) lo_ = 0xA0;
          else if (b == 0xED) hi_ = 0x9F;
        } else if ((b & 0xF8) == 0xF0) {      // four bytes: U+10000..U+10FFFF
          if (b > 0xF4) return false;         // F5..F7 start nothing at or below U+10FFFF
          need_ = 3;
          cp_ = b & 0x07;
          min_ = 0x10000;
          if (b == 0xF0) lo_ = 0x90;
          else if (b == 0xF4) hi_ = 0x8F;
        } else {
          return false;  // 0x80..0xBF stray continuation, or 0xF8..0xFF
        }
      } else {
        if (b < lo_ || b > hi_) return false;  // not a continuation byte, or out of range for its lead
        lo_ = 0x80;
        hi_ = 0xBF;
        cp_ = (cp_ << 6) | (b & 0x3F);
        if (--need_ == 0) {
          if (cp_ < min_) return false;                      // overlong
          if (cp_ > 0x10FFFF) return false;                  // beyond Unicode
          if (cp_ >= 0xD800 && cp_ <= 0xDFFF) return false;  // surrogates
        }
      }
    }
    return true;
  }

  // True when the stream does not end mid multi-byte sequence — required at
  // the end of a message (§5.6: the COMPLETE message must be valid UTF-8).
  // When true the validator is already in its initial state, so no reset()
  // is needed between messages.
  bool complete() const { return need_ == 0; }

  void reset() { need_ = 0; }

 private:
  uint32_t need_ = 0;  // continuation bytes still required
  uint32_t cp_ = 0;    // code point accumulated so far
  uint32_t min_ = 0;   // smallest code point this sequence length may encode
  uint8_t lo_ = 0x80;  // range the next continuation byte must fall in
  uint8_t hi_ = 0xBF;
};

// §7.4.1 / §7.4.2: the status codes a Close frame may carry. 1004, 1005,
// 1006 and 1015 are reserved and MUST NOT be set by an endpoint; 0-999 are
// not used; 1016-2999 are reserved for future revisions of the protocol;
// nothing above 4999 is defined. One rule for both directions: what a peer
// may send (WsParser) and what the server itself sends (closeFramePayload).
inline bool isWireCloseCode(int code) {
  return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
         (code >= 3000 && code <= 4999);
}

// §5.5: a control frame's payload is at most 125 bytes, so a Close reason
// has 123 after the two-byte status code. A longer one is cut at the last
// character boundary that fits (§5.5.1: the reason MUST be valid UTF-8, so a
// character is never split).
inline std::string_view truncateCloseReason(std::string_view reason) {
  static constexpr size_t kMax = 123;
  if (reason.size() <= kMax) return reason;
  size_t n = kMax;
  while (n > 0 && (uint8_t(reason[n]) & 0xC0) == 0x80) --n;
  return reason.substr(0, n);
}

// Incremental server-side frame decoder (RFC 6455 §5.2). Feed bytes as they
// arrive off the wire — any byte of a header or payload may arrive in a
// separate consume() call. Emits complete MESSAGES (fragments reassembled
// per §5.4) and control frames (surfaced immediately, even when interleaved
// between fragments of a data message, §5.4/§5.5).
class WsParser {
 public:
  struct Limits {
    // Cap on a complete (reassembled) message payload.
    size_t maxMessageSize = 16 * 1024 * 1024;
    // permessage-deflate negotiated: RSV1 is then permitted on the first frame
    // of a data message (marks it compressed, RFC 7692 §6). Off by default.
    bool pmdNegotiated = false;
  };

  // compressed=true when the message carried RSV1 (permessage-deflate). The
  // payload is then still DEFLATED - the caller inflates it (and does the
  // UTF-8 check post-inflate); the parser skips UTF-8 validation for it.
  using MessageFn =
      std::function<void(std::string_view payload, bool isBinary, bool compressed)>;
  using ControlFn = std::function<void(WsOpcode opcode, std::string_view payload)>;

  WsParser() = default;
  explicit WsParser(Limits limits) : limits_(limits) {}

  // Returns false on protocol error:
  //   - unmasked client-to-server frame (§5.1)
  //   - any RSV bit set with no extension negotiated (§5.2)
  //   - reserved opcode %x3-7 / %xB-F (§5.2)
  //   - control frame with payload > 125 bytes or FIN clear (§5.5)
  //   - continuation frame with no message in progress, or a new Text/Binary
  //     frame while a fragmented message is in progress (§5.4)
  //   - 64-bit payload length with the most significant bit set (§5.2)
  //   - extended payload length not minimally encoded (§5.2)
  //   - reassembled message exceeding Limits.maxMessageSize
  //   - invalid UTF-8 in a text message (§5.6, §8.1) or close reason (§5.5.1)
  //   - close frame with a 1-byte payload (§5.5.1: a body, if present,
  //     begins with a 2-byte status code)
  // Once false is returned the parser stays failed: the caller must fail the
  // WebSocket connection (§7.1.7) and stop feeding it. failCode() then holds
  // the close code to use: 1009 when Limits.maxMessageSize was exceeded,
  // 1007 for invalid UTF-8 payload data, 1002 for every other violation.
  //
  // onMessage(payload, isBinary): a complete (possibly reassembled) data
  // message. Text payloads have already been UTF-8 validated.
  // onControl(opcode, payload): Close/Ping/Pong with unmasked payload
  // (<= 125 bytes, §5.5).
  // The string_views are only valid for the duration of the callback.
  // Templated on the callable types so callers' lambdas are invoked directly
  // (no std::function allocation per read); MessageFn/ControlFn document the
  // required signatures.
  //
  // `data` is MUTABLE: a data frame that is a whole message by itself (first
  // frame, FIN set) and whose full payload sits in this buffer is unmasked
  // (§5.3) IN PLACE and emitted as a view into `data` — the zero-copy fast
  // path. The caller must not rely on the buffer's contents after the call
  // and must keep the buffer untouched until consume() returns (the views'
  // valid-only-during-the-callback contract already implies both).
  template <typename OnMessage, typename OnControl>
  bool consume(uint8_t* data, size_t len, OnMessage&& onMessage,
               OnControl&& onControl) {
    return consume(data, len, onMessage, onControl, LeaveBuffer{});
  }

  // The same, with a say for the caller in how a message that had to be
  // buffered - reassembled from fragments, or one frame over several reads -
  // is handed over. onBuffer(std::string& message, isBinary, compressed) is
  // called first, with the parser's own buffer holding exactly the message:
  // the callee may take the string (swap or move it out; the parser carries
  // on with whatever it is left) and return true, and onMessage is then not
  // called for that message. Returning false leaves the buffer as it is and
  // the message goes to onMessage as a view, as always. A message delivered
  // in place from `data` never comes this way.
  template <typename OnMessage, typename OnControl, typename OnBuffer>
  bool consume(uint8_t* data, size_t len, OnMessage&& onMessage,
               OnControl&& onControl, OnBuffer&& onBuffer) {
    if (failed_) return false;
    size_t i = 0;
    while (i < len) {
      switch (state_) {
        case State::Header: {
          // §5.2: first two header bytes — FIN/RSV/opcode and MASK/len7.
          hdr_[hdrHave_++] = data[i++];
          if (hdrHave_ == 2 && !beginFrame()) return fail();
          break;
        }
        case State::ExtLen: {
          // §5.2: 2- or 8-byte extended payload length, network byte order.
          ext_[extHave_++] = data[i++];
          if (extHave_ == extNeed_ && !finishExtendedLength()) return fail();
          break;
        }
        case State::MaskKey: {
          // §5.2/§5.3: 4-byte masking key (always present on client frames).
          mask_[maskHave_++] = data[i++];
          if (maskHave_ == 4) {
            if (payloadRemaining_ == 0) {
              readLeft_ = len - i;
              if (!finishFrame(onMessage, onControl, onBuffer)) return fail();
            } else {
              state_ = State::Payload;
            }
          }
          break;
        }
        case State::Payload: {
          const size_t avail = len - i;
          // Zero-copy fast path: this data frame is an entire message on its
          // own (first frame of the message, FIN set, no fragment bytes
          // buffered) and its whole payload is already in this input buffer.
          // Unmask it IN PLACE in the wire buffer and emit a view into it —
          // message_ is never touched, so a warm connection receives with
          // zero copies. Applies to compressed frames too (the view feeds
          // inflate). Fragmented messages, control frames (<= 125 bytes and
          // interleavable inside a fragmented message — not worth it), and
          // frames split across consume() calls take the buffering path
          // below. The caller-facing contract is unchanged: the view is only
          // valid for the duration of the callback.
          if (!isControl_ && frameStartsMessage_ && fin_ && message_.empty() &&
              payloadRemaining_ <= avail) {
            const size_t take = size_t(payloadRemaining_);
            char* p = reinterpret_cast<char*>(data) + i;
            unmaskInPlace(p, take, mask_, maskPos_);
            // §5.6/§8.1: an uncompressed text payload MUST be valid UTF-8.
            // The frame is the whole message, so the validator must accept
            // every byte AND end outside a multi-byte sequence. Compressed
            // payloads are still deflated here — the caller validates
            // post-inflate (skip). Binary: no UTF-8 requirement.
            if (!messageIsBinary_ && !messageCompressed_ &&
                (!utf8_.accept(std::string_view(p, take)) ||
                 !utf8_.complete())) {
              failCode_ = 1007;  // §7.4.1: Invalid frame payload data
              return fail();
            }
            // Reset frame + message state BEFORE the callback (the next
            // bytes begin a new frame header), mirroring finishFrame().
            i += take;
            payloadRemaining_ = 0;
            state_ = State::Header;
            hdrHave_ = 0;
            inMessage_ = false;
            const bool isBinary = messageIsBinary_;
            const bool compressed = messageCompressed_;
            messageCompressed_ = false;
            readLeft_ = avail - take;
            onMessage(std::string_view(p, take), isBinary, compressed);
            break;
          }
          const size_t take = size_t(std::min<uint64_t>(payloadRemaining_, avail));
          std::string& sink = isControl_ ? control_ : message_;
          // Large declared payloads: reserve once (bounded by commitLength's
          // limit check) so chunked appends don't re-copy the buffer
          // geometrically. Deferred to here — after the fast path above — so
          // frames it consumes never allocate. Small frames keep amortized
          // growth: a per-frame exact reserve would make many-small-fragment
          // messages quadratic.
          // The reserve waits until a sixteenth of the message has arrived
          // (the first read, for a frame up to sixteen read buffers long).
          // Until then the length is only a claim: a peer that sent a frame
          // header and one byte had the whole declared size set aside for
          // it - address space, and committed memory on a platform that
          // commits at allocation - for as long as it kept the connection
          // open, and WebSockets have no receive timeout.
          if (!isControl_ && payloadRemaining_ > 65536 &&
              sink.size() + size_t(payloadRemaining_) > sink.capacity() &&
              sink.size() + take >= (sink.size() + size_t(payloadRemaining_)) / kReserveShare) {
            sink.reserve(sink.size() + size_t(payloadRemaining_));
          }
          const size_t base = sink.size();
          // §5.3: transformed-octet-i = original-octet-i XOR
          // masking-key-octet-(i MOD 4). maskPos_ persists across consume()
          // calls so a payload split anywhere still unmasks correctly:
          // append raw (memcpy, no zero-fill), then unmask in place in the
          // sink.
          sink.append(reinterpret_cast<const char*>(data + i), take);
          unmaskInPlace(sink.data() + base, take, mask_, maskPos_);
          maskPos_ = (maskPos_ + take) & 3;
          i += take;
          payloadRemaining_ -= take;
          // §5.6/§8.1, incrementally: validate each uncompressed-text chunk
          // as it is unmasked, so invalid UTF-8 fails (1007) at the
          // offending chunk instead of after buffering up to maxMessageSize
          // bytes. Truncation (a dangling multi-byte sequence) is checked at
          // FIN in finishFrame() via utf8_.complete().
          if (!isControl_ && !messageIsBinary_ && !messageCompressed_ &&
              !utf8_.accept(std::string_view(sink.data() + base, take))) {
            failCode_ = 1007;  // §7.4.1: Invalid frame payload data
            return fail();
          }
          if (payloadRemaining_ == 0) {
            readLeft_ = len - i;
            if (!finishFrame(onMessage, onControl, onBuffer)) return fail();
          }
          break;
        }
      }
    }
    return true;
  }

  const Limits& limits() const { return limits_; }

  // Inside a callback: whether the buffer being consumed holds more bytes
  // behind the frame that is being delivered - another frame, or the start
  // of one. (What a reply to this frame may share a write, or on TLS a
  // record, with.) Outside a callback it is what the last one left.
  bool moreInRead() const { return readLeft_ != 0; }

  // Close code the caller should fail the connection with; meaningful only
  // after consume() has returned false.
  uint16_t failCode() const { return failCode_; }

 private:
  enum class State : uint8_t { Header, ExtLen, MaskKey, Payload };

  // consume() without an onBuffer: every buffered message goes to onMessage.
  struct LeaveBuffer {
    bool operator()(std::string&, bool, bool) const { return false; }
  };

  // A message's buffer is reserved in full once this fraction of it has
  // been received (see the buffering path in consume()).
  static constexpr size_t kReserveShare = 16;

  bool fail() {
    failed_ = true;
    return false;
  }

  // §5.3: transformed-octet-i = original-octet-i XOR
  // masking-key-octet-(i MOD 4). Unmasks p[0..n) in place, 8 bytes at a
  // time: the 8-byte key is the 4-byte mask repeated, rotated to `pos` (the
  // payload offset this chunk starts at, mod 4), so byte j of every word
  // lines up with mask[(pos + j) & 3] regardless of endianness. Shared by
  // the zero-copy fast path (wire buffer) and the copy path (sink buffer).
  static void unmaskInPlace(char* p, size_t n, const uint8_t mask[4],
                            size_t pos) {
    uint8_t km[8];
    for (size_t j = 0; j < 8; ++j) km[j] = mask[(pos + j) & 3];
    uint64_t key;
    std::memcpy(&key, km, 8);
    size_t k = 0;
    for (; k + 8 <= n; k += 8) {
      uint64_t w;
      std::memcpy(&w, p + k, 8);
      w ^= key;
      std::memcpy(p + k, &w, 8);
    }
    for (; k < n; ++k) {
      p[k] = char(uint8_t(p[k]) ^ mask[(pos + k) & 3]);
    }
  }

  // Both base header bytes are in hdr_; validate them and decide what the
  // frame still needs (extended length and/or masking key).
  bool beginFrame() {
    fin_ = (hdr_[0] & 0x80) != 0;
    const bool rsv1 = (hdr_[0] & 0x40) != 0;

    // §5.2: RSV2/RSV3 MUST always be 0 (no extension defines them). RSV1 is
    // the permessage-deflate "compressed" bit (RFC 7692 §6): permitted only on
    // the FIRST frame of a DATA message and only when negotiated; forbidden on
    // continuation and control frames. Anything else fails the connection.
    if (hdr_[0] & 0x30) return false;  // RSV2/RSV3 set
    if (rsv1 && !limits_.pmdNegotiated) return false;

    const uint8_t op = hdr_[0] & 0x0F;
    // §5.2: receiving a reserved opcode fails the connection.
    switch (op) {
      case 0x0:
      case 0x1:
      case 0x2:
      case 0x8:
      case 0x9:
      case 0xA:
        break;
      default:
        return false;
    }

    // §5.1: a client MUST mask all frames it sends; the server MUST close
    // the connection upon receiving an unmasked frame.
    if (!(hdr_[1] & 0x80)) return false;

    const uint64_t len7 = hdr_[1] & 0x7F;
    isControl_ = (op & 0x8) != 0;

    if (isControl_) {
      // §5.5: control frames MUST have a payload of 125 bytes or less and
      // MUST NOT be fragmented. RFC 7692 §6.1: RSV1 (the per-message
      // compressed bit) MUST NOT be set on control frames.
      if (!fin_ || len7 > 125 || rsv1) return false;
      controlOpcode_ = static_cast<WsOpcode>(op);
    } else if (op == uint8_t(WsOpcode::Continuation)) {
      // §5.4: a continuation frame is only valid while a fragmented message
      // is in progress. RFC 7692 §6: RSV1 MUST NOT be set on continuation
      // frames (the compressed bit lives only on the first frame).
      if (!inMessage_) return false;
      if (rsv1) return false;
      frameStartsMessage_ = false;
    } else {
      // §5.4: fragments after the first carry opcode 0, so a new Text or
      // Binary frame while a message is in progress is a protocol error.
      if (inMessage_) return false;
      inMessage_ = true;
      frameStartsMessage_ = true;
      messageIsBinary_ = (op == uint8_t(WsOpcode::Binary));
      messageCompressed_ = rsv1;  // RFC 7692: RSV1 on the first frame = compressed
    }

    if (len7 <= 125) {
      // §5.2: 0-125 is the payload length itself.
      payloadLen_ = len7;
      return commitLength();
    }
    // §5.2: 126 -> 16-bit extended length; 127 -> 64-bit extended length.
    extNeed_ = (len7 == 126) ? 2 : 8;
    extHave_ = 0;
    state_ = State::ExtLen;
    return true;
  }

  bool finishExtendedLength() {
    // §5.2: extended payload length is in network byte order (big-endian).
    uint64_t v = 0;
    for (size_t j = 0; j < extNeed_; ++j) {
      v = (v << 8) | ext_[j];
    }
    if (extNeed_ == 2) {
      // §5.2: the minimal number of bytes MUST be used to encode the
      // length; a 16-bit length below 126 fits in the base header.
      if (v < 126) return false;
    } else {
      // §5.2: the most significant bit of the 64-bit length MUST be 0.
      if (v & (uint64_t(1) << 63)) return false;
      // §5.2: minimal encoding — a 64-bit length below 65536 fits in 16 bits.
      if (v < 65536) return false;
    }
    payloadLen_ = v;
    return commitLength();
  }

  // Payload length is now known; enforce limits and move on to the mask key.
  bool commitLength() {
    if (!isControl_) {
      // Enforce Limits.maxMessageSize across reassembled fragments (§5.4),
      // checked before any allocation. Written to avoid uint64 overflow.
      if (payloadLen_ > limits_.maxMessageSize ||
          message_.size() > limits_.maxMessageSize - payloadLen_) {
        failCode_ = 1009;  // §7.4.1: Message Too Big
        return false;
      }
      // (The large-payload reserve for message_ lives in consume()'s copy
      // path, deferred past the zero-copy fast path so frames that never
      // touch message_ never allocate.)
    }
    payloadRemaining_ = payloadLen_;
    maskHave_ = 0;
    maskPos_ = 0;
    state_ = State::MaskKey;
    return true;
  }

  // The frame's payload (possibly empty) is fully buffered and unmasked.
  template <typename OnMessage, typename OnControl, typename OnBuffer>
  bool finishFrame(OnMessage& onMessage, OnControl& onControl, OnBuffer& onBuffer) {
    // Next bytes begin a new frame header.
    state_ = State::Header;
    hdrHave_ = 0;

    if (isControl_) {
      if (controlOpcode_ == WsOpcode::Close) {
        // §5.5.1: if a close frame has a body, its first two bytes MUST be
        // a status code — a 1-byte body is malformed.
        if (control_.size() == 1) return false;
        if (control_.size() >= 2) {
          // §7.4.1: the status code MUST be a permitted value. Reserved codes
          // (1004/1005/1006/1015), 0-999, 1016-2999, and >4999 MUST NOT appear
          // on the wire — a peer sending one is a protocol error (fail, 1002).
          uint16_t code = uint16_t((uint16_t(uint8_t(control_[0])) << 8) | uint8_t(control_[1]));
          if (!isWireCloseCode(code)) return false;
          // §5.5.1: the reason data following the code MUST be valid UTF-8.
          if (control_.size() > 2 &&
              !isValidUtf8(std::string_view(control_).substr(2))) {
            failCode_ = 1007;  // §7.4.1: Invalid frame payload data
            return false;
          }
        }
      }
      // §5.4/§5.5: control frames interleaved between message fragments are
      // surfaced immediately; the fragmentation buffer is untouched.
      onControl(controlOpcode_, std::string_view(control_));
      control_.clear();
      return true;
    }

    // §5.4: not the final fragment — keep accumulating into message_.
    if (!fin_) return true;

    // §5.6/§8.1: a text message's complete payload MUST be valid UTF-8.
    // Every chunk was already validated incrementally as it was unmasked
    // (multi-byte sequences split across fragment or consume() boundaries
    // carry over in utf8_'s state), so all that remains at FIN is that the
    // message does not END mid multi-byte sequence. For a COMPRESSED message
    // the payload is still deflated here, so the caller inflates first and
    // validates UTF-8 on the result (skip it here). When complete() holds,
    // utf8_ is already back in its initial state for the next message.
    if (!messageIsBinary_ && !messageCompressed_ && !utf8_.complete()) {
      failCode_ = 1007;  // §7.4.1: Invalid frame payload data
      return false;
    }

    if (!onBuffer(message_, messageIsBinary_, messageCompressed_))
      onMessage(std::string_view(message_), messageIsBinary_, messageCompressed_);
    message_.clear();
    // One huge message must not pin its capacity to an idle connection (same
    // 16 KiB watermark as server.h's releaseScratch).
    if (message_.capacity() > 16384) message_.shrink_to_fit();
    inMessage_ = false;
    messageCompressed_ = false;
    return true;
  }

 public:
  // Heap storage of the message being reassembled: what a peer that sends a
  // message in fragments, or a frame over several reads, has made this
  // connection hold (the server's buffer budget counts it).
  size_t memory() const { return message_.capacity() >= sizeof(std::string) ? message_.capacity() : 0; }
  // The same by content: the bytes of the message being reassembled (the
  // buffer keeps its capacity after a message has been delivered).
  size_t arriving() const { return message_.size(); }
  // The connection is being closed for what it holds: give the storage back
  // now, and take nothing more (the parser is latched as after a failure).
  void abandon() {
    std::string().swap(message_);
    failed_ = true;
  }

 private:
  Limits limits_{};
  State state_ = State::Header;
  bool failed_ = false;
  uint16_t failCode_ = 1002;  // §7.4.1 close code for the failure (see failCode())

  // Base header accumulator (§5.2 first two bytes).
  uint8_t hdr_[2] = {};
  size_t hdrHave_ = 0;

  // Extended length accumulator (§5.2, 2 or 8 bytes).
  uint8_t ext_[8] = {};
  size_t extNeed_ = 0;
  size_t extHave_ = 0;

  // Masking key (§5.3) and running payload position for unmasking.
  uint8_t mask_[4] = {};
  size_t maskHave_ = 0;
  size_t maskPos_ = 0;
  size_t readLeft_ = 0;  // see moreInRead()

  // Current frame.
  uint64_t payloadLen_ = 0;
  uint64_t payloadRemaining_ = 0;
  bool fin_ = false;
  bool isControl_ = false;
  // True when the current data frame opened its message (opcode Text/Binary,
  // not Continuation) — with fin_, the zero-copy fast path's "this frame is
  // the whole message" test. Meaningless for control frames (they never set
  // or read it; beginFrame's data branches always reassign it).
  bool frameStartsMessage_ = false;
  WsOpcode controlOpcode_ = WsOpcode::Close;

  // Fragmented-message reassembly (§5.4).
  bool inMessage_ = false;
  bool messageIsBinary_ = false;
  bool messageCompressed_ = false;  // RFC 7692: RSV1 on the first frame
  std::string message_;  // data message reassembly buffer
  std::string control_;  // control frame payload buffer (<= 125 bytes)
  // Per-message streaming UTF-8 state for UNCOMPRESSED text messages (§5.6).
  // Invariant: between messages it is always in its initial state — a
  // message either ends with complete() true (initial state by definition)
  // or fails, which latches the parser for good.
  Utf8Validator utf8_;
};

// Frame encoder (§5.2). Appends one complete frame (header + payload) to
// out. Server-to-client frames are NEVER masked (§5.1), so the MASK bit is
// 0 and no masking key is written. Uses the minimally sized length encoding
// required by §5.2 (7-bit, 16-bit, or 64-bit).
// rsv1 sets the RSV1 bit (permessage-deflate "compressed" marker, RFC 7692
// §6) - valid only on the first frame of a data message.
// The header of that frame alone, for a payload of `n` bytes that is written
// from where it is: at most ten bytes into `out`, returns how many.
inline size_t encodeFrameHeader(char out[10], WsOpcode opcode, uint64_t n,
                                bool fin = true, bool rsv1 = false) {
  out[0] = char(uint8_t(fin ? 0x80 : 0x00) | uint8_t(rsv1 ? 0x40 : 0x00) |
                uint8_t(opcode));
  if (n <= 125) {
    out[1] = char(uint8_t(n));
    return 2;
  }
  if (n <= 0xFFFF) {
    out[1] = char(126);
    out[2] = char(uint8_t(n >> 8));
    out[3] = char(uint8_t(n));
    return 4;
  }
  out[1] = char(127);
  for (int i = 0; i < 8; ++i) out[2 + i] = char(uint8_t(n >> (56 - 8 * i)));
  return 10;
}

inline void encodeFrame(std::string& out, WsOpcode opcode,
                        std::string_view payload, bool fin = true,
                        bool rsv1 = false) {
  out += char(uint8_t(fin ? 0x80 : 0x00) | uint8_t(rsv1 ? 0x40 : 0x00) |
              uint8_t(opcode));
  const uint64_t n = payload.size();
  if (n <= 125) {
    out += char(uint8_t(n));
  } else if (n <= 0xFFFF) {
    out += char(126);
    out += char(uint8_t(n >> 8));
    out += char(uint8_t(n));
  } else {
    out += char(127);
    for (int s = 56; s >= 0; s -= 8) {
      out += char(uint8_t(n >> s));
    }
  }
  out.append(payload);
}

// §5.5.1: a close frame body is a 2-byte unsigned status code in network
// byte order, optionally followed by a UTF-8 reason.
inline void encodeClosePayload(std::string& out, uint16_t code,
                               std::string_view reason) {
  out += char(uint8_t(code >> 8));
  out += char(uint8_t(code));
  out.append(reason);
}

// The body of a Close frame the application asked for with `code` and
// `reason`, made legal for the wire whatever it passed:
//   - a code that may be sent (isWireCloseCode) goes out as given;
//   - 1005 means "no status code was present" (§7.4.1), and that is exactly
//     what is sent: a Close frame with an empty body (a reason cannot be
//     carried without a code, so it is dropped);
//   - any other value - the reserved 1004/1006/1015, anything below 1000,
//     1016-2999, 5000 and above - is not expressible and goes out as 1011
//     (the server met a condition it did not expect);
//   - the reason is cut to the 123 bytes a control frame leaves for it.
inline void closeFramePayload(std::string& out, int code, std::string_view reason) {
  if (code == 1005) return;
  encodeClosePayload(out, isWireCloseCode(code) ? uint16_t(code) : uint16_t(1011),
                     truncateCloseReason(reason));
}

// Parse the status code out of a close frame body. §7.1.5: if the close
// frame contains no status code, the connection close code is 1005.
inline uint16_t parseCloseCode(std::string_view payload) {
  if (payload.size() < 2) return 1005;
  return uint16_t((uint16_t(uint8_t(payload[0])) << 8) | uint8_t(payload[1]));
}

}  // namespace moro::engine
