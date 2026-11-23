// HTTP/2 (RFC 9113) for @morojs/engine: HPACK (RFC 7541) and the server side
// of one connection.
//
// A Session is a pure protocol machine, like the HTTP/1 parser and the TLS
// session beside it: bytes in (feed), bytes out (appended to out()), and
// three calls to its host - a request is complete, a request the host holds
// was reset by the peer, a stream it was told to wait on can take more data.
// It does no I/O and knows nothing of V8 or libuv, which is what lets the
// fuzzer and the unit tests drive it directly.
//
// What the host sees of a request is exactly what it sees of an HTTP/1
// request: a method, a path, a query string, a list of lowercased header
// lines and a body. Pseudo-header fields never reach it (":authority" does,
// as the Host header: in place of the value of a Host field that came with
// it, or as one when the request carried none), so an application
// cannot tell which protocol a request arrived on unless it asks.
//
// Scope, deliberately: a server, prior-knowledge cleartext or ALPN "h2". No
// server push (RFC 9113 deprecates it and browsers have removed it), no
// "Upgrade: h2c" (RFC 9113 removed it), and priorities are parsed and
// ignored (RFC 9113 5.3 deprecates the scheme; RFC 9218 priorities are
// advisory). CONNECT is refused.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "flat_map.h"
#include "hpack_tables.h"
#include "http_parser.h"

// Every call in the body of a function so marked is made in line.
#if defined(__GNUC__) || defined(__clang__)
#define MORO_H2_FLATTEN __attribute__((flatten))
#else
#define MORO_H2_FLATTEN
#endif

namespace moro {
namespace engine {
namespace h2 {

inline constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 9113 6).
enum : uint8_t {
  kData = 0,
  kHeaders = 1,
  kPriority = 2,
  kRstStream = 3,
  kSettings = 4,
  kPushPromise = 5,
  kPing = 6,
  kGoaway = 7,
  kWindowUpdate = 8,
  kContinuation = 9,
};

enum : uint8_t {
  kFlagEndStream = 0x1,
  kFlagAck = 0x1,
  kFlagEndHeaders = 0x4,
  kFlagPadded = 0x8,
  kFlagPriority = 0x20,
};

// Error codes (RFC 9113 7). The names carry a prefix because <winerror.h>
// claims NO_ERROR.
enum : uint32_t {
  kNoError = 0x0,
  kProtocolError = 0x1,
  kInternalError = 0x2,
  kFlowControlError = 0x3,
  kSettingsTimeout = 0x4,
  kStreamClosed = 0x5,
  kFrameSizeError = 0x6,
  kRefusedStream = 0x7,
  kCancel = 0x8,
  kCompressionError = 0x9,
  kConnectError = 0xa,
  kEnhanceYourCalm = 0xb,
  kInadequateSecurity = 0xc,
  kHttp11Required = 0xd,
};

enum : uint16_t {
  kSettingHeaderTableSize = 0x1,
  kSettingEnablePush = 0x2,
  kSettingMaxConcurrentStreams = 0x3,
  kSettingInitialWindowSize = 0x4,
  kSettingMaxFrameSize = 0x5,
  kSettingMaxHeaderListSize = 0x6,
};

inline constexpr uint32_t kDefaultWindow = 65535;
inline constexpr uint32_t kMaxWindow = 0x7fffffffu;
inline constexpr uint32_t kMinFrameSize = 16384;
inline constexpr uint32_t kMaxFrameSizeLimit = 16777215;

// ---------------------------------------------------------------------------
// HPACK: Huffman decoding
// ---------------------------------------------------------------------------

// The code of RFC 7541 Appendix B decoded four bits at a time. A state is an
// internal node of the code tree; since the shortest code is five bits, four
// input bits finish at most one symbol, so one table entry per (state,
// nibble) carries everything a step can do: the next state, the symbol it
// completed if any, and whether it ran into EOS.
class HuffmanDecoder {
 public:
  // Decodes `n` bytes into `out` (replacing its content). False when the
  // input holds the EOS symbol, or ends in padding that is not the leading
  // bits of EOS or is longer than seven bits (RFC 7541 5.2).
  //
  // A step completes at most one symbol, so 2n bytes hold any output. The
  // symbol is stored every step and the write position moves only when the
  // step completed one; a step into EOS is remembered and the walk goes on
  // (every entry's next state is a state), which leaves one test for the
  // whole string where there were four per byte.
  static bool decode(const uint8_t* p, size_t n, std::string& out) {
    const HuffmanDecoder& d = instance();
    out.resize(2 * n);
    char* const base = out.data();
    char* w = base;
    uint16_t state = 0;
    uint8_t seen = 0;
    for (size_t i = 0; i < n; i++) {
      const Step hi = d.step_[state][p[i] >> 4];
      *w = static_cast<char>(hi.symbol);
      w += hi.flags & kEmit;
      const Step lo = d.step_[hi.next][p[i] & 0x0f];
      *w = static_cast<char>(lo.symbol);
      w += lo.flags & kEmit;
      seen |= hi.flags | lo.flags;
      state = lo.next;
    }
    out.resize(static_cast<size_t>(w - base));
    return (seen & kFail) == 0 && d.accept_[state];
  }

 private:
  enum : uint8_t { kEmit = 1, kFail = 2 };
  struct Step {
    uint16_t next;
    uint8_t symbol;
    uint8_t flags;
  };
  static constexpr int kStates = 256;  // internal nodes of a 257-leaf binary tree

  static const HuffmanDecoder& instance() {
    static const HuffmanDecoder d;
    return d;
  }

  HuffmanDecoder() {
    // The code tree: child[b] is a node index, or -(symbol + 1) for a leaf.
    struct Node {
      int child[2] = {0, 0};
    };
    std::vector<Node> nodes(1);
    for (int sym = 0; sym <= 256; sym++) {
      const uint32_t code = kHuffman[sym].code;
      const int bits = kHuffman[sym].bits;
      int at = 0;
      for (int i = bits - 1; i >= 0; i--) {
        const int b = static_cast<int>((code >> i) & 1u);
        if (i == 0) {
          nodes[at].child[b] = -(sym + 1);
        } else {
          if (nodes[at].child[b] == 0) {
            nodes[at].child[b] = static_cast<int>(nodes.size());
            nodes.emplace_back();
          }
          at = nodes[at].child[b];
        }
      }
    }
    // nodes.size() is 256 for a complete code; each is a state.
    for (int s = 0; s < kStates; s++) {
      accept_[s] = false;
      for (int v = 0; v < 16; v++) {
        Step st{0, 0, 0};
        int at = s < static_cast<int>(nodes.size()) ? s : 0;
        for (int i = 3; i >= 0; i--) {
          const int next = nodes[at].child[(v >> i) & 1];
          if (next < 0) {
            const int sym = -next - 1;
            if (sym == 256) {
              st.flags |= kFail;
              break;
            }
            st.symbol = static_cast<uint8_t>(sym);
            st.flags |= kEmit;
            at = 0;
          } else {
            at = next;
          }
        }
        st.next = static_cast<uint16_t>(at);
        step_[s][v] = st;
      }
    }
    // Valid places to stop: the root, and up to seven 1-bits below it.
    int at = 0;
    accept_[0] = true;
    for (int depth = 1; depth <= 7; depth++) {
      const int next = nodes[at].child[1];
      if (next <= 0) break;
      at = next;
      accept_[at] = true;
    }
  }

  Step step_[kStates][16];
  bool accept_[kStates];
};

// ---------------------------------------------------------------------------
// HPACK: integers, strings, the decoder
// ---------------------------------------------------------------------------

// An integer with an N-bit prefix (RFC 7541 5.1). Values past 2^30 are
// refused: nothing HPACK carries is that large, and it keeps the arithmetic
// far from overflow.
inline bool decodeInt(const uint8_t*& p, const uint8_t* end, int prefixBits, uint32_t& out) {
  if (p >= end) return false;
  const uint32_t mask = (1u << prefixBits) - 1;
  uint32_t value = *p++ & mask;
  if (value < mask) {
    out = value;
    return true;
  }
  int shift = 0;
  for (;;) {
    if (p >= end || shift > 28) return false;
    const uint8_t b = *p++;
    // 64 bits for the sum: at shift 28 the seven bits reach past bit 31, and
    // a 32-bit sum would wrap to a small value instead of being refused.
    const uint64_t sum = value + (static_cast<uint64_t>(b & 0x7f) << shift);
    if (sum > (1u << 30)) return false;
    value = static_cast<uint32_t>(sum);
    if ((b & 0x80) == 0) break;
    shift += 7;
  }
  out = value;
  return true;
}

inline void encodeInt(std::string& out, int prefixBits, uint8_t high, uint32_t value) {
  const uint32_t mask = (1u << prefixBits) - 1;
  if (value < mask) {
    out.push_back(static_cast<char>(high | value));
    return;
  }
  out.push_back(static_cast<char>(high | mask));
  value -= mask;
  while (value >= 128) {
    out.push_back(static_cast<char>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<char>(value));
}

class HpackDecoder {
 public:
  // The largest dynamic table the peer's encoder may use: our
  // SETTINGS_HEADER_TABLE_SIZE. The table starts at the protocol default.
  void setMaxTableSize(uint32_t settingsMax) {
    settingsMax_ = settingsMax;
    if (maxSize_ > settingsMax_) resize(settingsMax_);
  }

  // Decodes one complete header block, calling sink(name, value) for each
  // field in order. The views are valid only during the call. Returns false
  // on any error, all of which are COMPRESSION_ERROR for the connection: the
  // table can no longer be trusted to match the peer's.
  template <typename Sink>
  bool decode(const uint8_t* p, size_t n, Sink&& sink) {
    const uint8_t* const end = p + n;
    bool sawField = false;
    while (p < end) {
      const uint8_t b = *p;
      if (b & 0x80) {  // indexed field
        uint32_t index;
        if (!decodeInt(p, end, 7, index)) return false;
        std::string_view name, value;
        if (!lookup(index, name, value)) return false;
        sink(name, value);
        sawField = true;
      } else if (b & 0x40) {  // literal, added to the table
        uint32_t index;
        if (!decodeInt(p, end, 6, index)) return false;
        std::string_view name, value;
        if (index != 0) {
          std::string_view unused;
          if (!lookup(index, name, unused)) return false;
        } else if (!readString(p, end, nameBuf_, name)) {
          return false;
        }
        if (!readString(p, end, valueBuf_, value)) return false;
        // Copied before the insert: an indexed name refers to an entry the
        // insert may evict.
        std::string ownName(name), ownValue(value);
        sink(std::string_view(ownName), std::string_view(ownValue));
        insert(std::move(ownName), std::move(ownValue));
        sawField = true;
      } else if (b & 0x20) {  // dynamic table size update
        if (sawField) return false;  // only at the start of a block (RFC 7541 4.2)
        uint32_t size;
        if (!decodeInt(p, end, 5, size)) return false;
        if (size > settingsMax_) return false;
        resize(size);
      } else {  // literal, not added (0000) or never indexed (0001)
        uint32_t index;
        if (!decodeInt(p, end, 4, index)) return false;
        std::string_view name, value;
        if (index != 0) {
          std::string_view unused;
          if (!lookup(index, name, unused)) return false;
        } else if (!readString(p, end, nameBuf_, name)) {
          return false;
        }
        if (!readString(p, end, valueBuf_, value)) return false;
        sink(name, value);
        sawField = true;
      }
    }
    return true;
  }

  size_t tableSize() const { return size_; }
  size_t tableEntries() const { return table_.size(); }

 private:
  struct Entry {
    std::string name;
    std::string value;
  };

  bool lookup(uint32_t index, std::string_view& name, std::string_view& value) const {
    if (index == 0) return false;
    if (index <= kStaticCount) {
      name = kStaticTable[index].name;
      value = kStaticTable[index].value;
      return true;
    }
    const size_t i = index - kStaticCount - 1;
    if (i >= table_.size()) return false;
    name = table_[i].name;
    value = table_[i].value;
    return true;
  }

  // A string literal (RFC 7541 5.2): a view of the input when it is plain,
  // of `scratch` when it had to be Huffman-decoded.
  static bool readString(const uint8_t*& p, const uint8_t* end, std::string& scratch,
                         std::string_view& out) {
    if (p >= end) return false;
    const bool huffman = (*p & 0x80) != 0;
    uint32_t len;
    if (!decodeInt(p, end, 7, len)) return false;
    if (len > static_cast<size_t>(end - p)) return false;
    if (huffman) {
      if (!HuffmanDecoder::decode(p, len, scratch)) return false;
      out = scratch;
    } else {
      out = std::string_view(reinterpret_cast<const char*>(p), len);
    }
    p += len;
    return true;
  }

  static size_t entrySize(const std::string& name, const std::string& value) {
    return name.size() + value.size() + 32;  // RFC 7541 4.1
  }

  void insert(std::string&& name, std::string&& value) {
    const size_t sz = entrySize(name, value);
    while (!table_.empty() && size_ + sz > maxSize_) evict();
    if (sz > maxSize_) return;  // larger than the table: it is emptied, nothing added
    size_ += sz;
    table_.push_front(Entry{std::move(name), std::move(value)});
  }

  void evict() {
    size_ -= entrySize(table_.back().name, table_.back().value);
    table_.pop_back();
  }

  void resize(uint32_t size) {
    maxSize_ = size;
    while (!table_.empty() && size_ > maxSize_) evict();
  }

  std::deque<Entry> table_;  // newest first: index 62 is table_[0]
  size_t size_ = 0;
  uint32_t maxSize_ = 4096;
  uint32_t settingsMax_ = 4096;
  std::string nameBuf_;
  std::string valueBuf_;
};

// ---------------------------------------------------------------------------
// HPACK: the encoder
// ---------------------------------------------------------------------------
//
// Stateless on purpose: every field is a static-table index or a literal that
// is not added to the dynamic table. The dynamic table would save a few bytes
// per response on a connection, at the price of a table per connection and of
// header blocks that can no longer be prepared once and replayed on every
// connection - which is what a response template is here (Server), and what
// makes a templated reply one append. Nothing is Huffman-coded either: the
// bytes saved are not worth a table lookup per character on the way out.

// The static-table index of a response header name (lowercase), 0 when it
// has none. Only names a server sends are listed.
inline uint32_t staticNameIndex(std::string_view name) {
  // By length first: a name the table does not have - most of what an
  // application adds - is turned away on one comparison.
  const auto is = [name](std::string_view known) {
    return memcmp(name.data(), known.data(), known.size()) == 0;
  };
  switch (name.size()) {
    case 3: return is("age") ? 21 : 0;
    case 4: return is("etag") ? 34 : is("date") ? 33 : is("link") ? 45 : is("vary") ? 59 : 0;
    case 5: return is("allow") ? 22 : 0;
    case 6: return is("server") ? 54 : 0;
    case 7: return is("expires") ? 36 : 0;
    case 8: return is("location") ? 46 : 0;
    case 10: return is("set-cookie") ? 55 : 0;
    case 11: return is("retry-after") ? 53 : 0;
    case 12: return is("content-type") ? 31 : 0;
    case 13:
      return is("cache-control") ? 24
             : is("accept-ranges") ? 18
             : is("content-range") ? 30
             : is("last-modified") ? 44
             : 0;
    case 14: return is("content-length") ? 28 : 0;
    case 16:
      return is("content-encoding") ? 26
             : is("content-language") ? 27
             : is("content-location") ? 29
             : is("www-authenticate") ? 61
             : 0;
    case 19: return is("content-disposition") ? 25 : 0;
    case 25: return is("strict-transport-security") ? 56 : 0;
    case 27: return is("access-control-allow-origin") ? 20 : 0;
    default: return 0;
  }
}

// An HPACK integer (RFC 7541 5.1) written at `w`: at most six bytes for a
// 32-bit value. Returns the end.
inline char* putInt(char* w, int prefixBits, uint8_t high, uint32_t value) {
  const uint32_t mask = (1u << prefixBits) - 1;
  if (value < mask) {
    *w++ = static_cast<char>(high | value);
    return w;
  }
  *w++ = static_cast<char>(high | mask);
  value -= mask;
  while (value >= 128) {
    *w++ = static_cast<char>((value & 0x7f) | 0x80);
    value >>= 7;
  }
  *w++ = static_cast<char>(value);
  return w;
}

// One header field as a literal that is not indexed (RFC 7541 6.2.2), or one
// that must never be (6.2.3) when `sensitive`: a credential an intermediary
// re-encoding the block must not put in a table either.
inline void encodeField(std::string& out, std::string_view lowerName, std::string_view value,
                        bool sensitive = false) {
  const uint8_t kind = sensitive ? 0x10 : 0x00;
  const uint32_t index = staticNameIndex(lowerName);
  // The bytes around the strings are put together first and appended in one
  // piece, not a byte at a time.
  char pre[16];
  char* w = pre;
  if (index != 0) {
    w = putInt(w, 4, kind, index);
  } else {
    *w++ = static_cast<char>(kind);
    w = putInt(w, 7, 0, static_cast<uint32_t>(lowerName.size()));
    out.append(pre, static_cast<size_t>(w - pre));
    out.append(lowerName);
    w = pre;
  }
  w = putInt(w, 7, 0, static_cast<uint32_t>(value.size()));
  out.append(pre, static_cast<size_t>(w - pre));
  out.append(value);
}

inline void encodeStatus(std::string& out, int status) {
  switch (status) {
    case 200: out.push_back(static_cast<char>(0x88)); return;
    case 204: out.push_back(static_cast<char>(0x89)); return;
    case 206: out.push_back(static_cast<char>(0x8a)); return;
    case 304: out.push_back(static_cast<char>(0x8b)); return;
    case 400: out.push_back(static_cast<char>(0x8c)); return;
    case 404: out.push_back(static_cast<char>(0x8d)); return;
    case 500: out.push_back(static_cast<char>(0x8e)); return;
    default: break;
  }
  if (status < 100 || status > 999) status = 500;
  out.push_back(static_cast<char>(0x08));  // literal, name = index 8 (":status")
  out.push_back(static_cast<char>(0x03));
  out.push_back(static_cast<char>('0' + status / 100));
  out.push_back(static_cast<char>('0' + (status / 10) % 10));
  out.push_back(static_cast<char>('0' + status % 10));
}

// A byte of a field name as HTTP/2 writes one (RFC 9113 8.2.1): a token
// character that is not an uppercase letter.
inline constexpr std::array<bool, 256> kFieldNameChar = [] {
  std::array<bool, 256> t{};
  for (unsigned c = 0; c < 256; ++c) t[c] = kTokenChar[c] && !(c >= 'A' && c <= 'Z');
  return t;
}();

// The header names RFC 9113 8.2.2 bars from HTTP/2: they describe an
// HTTP/1.1 connection. A response carrying one is malformed, so the host
// drops them from a block written for HTTP/1.
inline bool isConnectionSpecific(std::string_view lowerName) {
  switch (lowerName.size()) {
    case 7: return lowerName == "upgrade";
    case 10: return lowerName == "connection" || lowerName == "keep-alive";
    case 16: return lowerName == "proxy-connection";
    case 17: return lowerName == "transfer-encoding";
    default: return false;
  }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

inline void appendFrameHeader(std::string& out, size_t length, uint8_t type, uint8_t flags,
                              uint32_t streamId) {
  const char h[9] = {
      static_cast<char>((length >> 16) & 0xff), static_cast<char>((length >> 8) & 0xff),
      static_cast<char>(length & 0xff),         static_cast<char>(type),
      static_cast<char>(flags),                 static_cast<char>((streamId >> 24) & 0x7f),
      static_cast<char>((streamId >> 16) & 0xff), static_cast<char>((streamId >> 8) & 0xff),
      static_cast<char>(streamId & 0xff),
  };
  out.append(h, 9);
}

inline void appendU32(std::string& out, uint32_t v) {
  const char b[4] = {static_cast<char>((v >> 24) & 0xff), static_cast<char>((v >> 16) & 0xff),
                     static_cast<char>((v >> 8) & 0xff), static_cast<char>(v & 0xff)};
  out.append(b, 4);
}

inline uint32_t readU32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

struct Settings {
  // What we advertise (SETTINGS).
  uint32_t headerTableSize = 4096;
  uint32_t maxConcurrentStreams = 256;
  uint32_t initialWindowSize = 1u << 20;
  uint32_t maxFrameSize = kMinFrameSize;
  uint32_t maxHeaderListSize = 64 * 1024;
  // The connection-level receive window, raised from the protocol's 65,535
  // with a WINDOW_UPDATE right after the SETTINGS.
  uint32_t connectionWindow = 8u << 20;
  // The server's own limits, applied to each request as HTTP/1 applies them.
  size_t maxBodySize = 10 * 1024 * 1024;
  size_t maxHeaders = 100;
  size_t maxUriSize = 0;
  bool allowNonAsciiTarget = false;
};

struct Stream {
  uint32_t id = 0;
  int64_t sendWindow = 0;     // what the peer will take on this stream
  int64_t recvWindow = 0;     // what we have told the peer it may send
  uint32_t recvUnacked = 0;   // received and not yet given back
  bool remoteClosed = false;  // END_STREAM received: the request is whole
  bool localClosed = false;   // END_STREAM (or a reset) sent
  bool dispatched = false;    // handed to the host
  bool wantDrain = false;     // the host was told to wait for onWritable
  long long declared = -1;    // the request's Content-Length, -1 when it gave none

  // The request, assembled here and taken by the host at dispatch.
  Method method = Method::OTHER;
  std::string methodStr;
  std::string path;
  std::string query;
  HeaderList headers;
  size_t headerCount = 0;
  std::string body;
  size_t bodyHeld = 0;  // capacity of `body` counted in the session's reserved total
  bool expectContinue = false;

  // Response bytes flow control is holding back: pending[pendingOff..] is
  // what is still owed. The part already sent stays in front until at least
  // half of the buffer is such a part (Session::flushStream), so a body that
  // drains over many window updates is not moved down once per update.
  std::string pending;
  size_t pendingOff = 0;
  bool pendingEnd = false;
  bool blocked = false;

  // The host's own object for the request, while it holds one.
  void* user = nullptr;
};

// The host's side of a session. `user` is passed back as given.
struct Host {
  void* user = nullptr;
  // `st` is a complete request. The host takes the request fields (swapping
  // is the cheap way) and, to keep answering it after this call returns,
  // attaches its own object with Session::hold. It may answer right here.
  void (*dispatch)(void* user, Stream& st) = nullptr;
  // The peer reset a stream the host holds, or its request turned out to be
  // invalid: no response can be sent any more. `held` is what the host
  // attached; the stream itself is gone after the call.
  void (*aborted)(void* user, void* held) = nullptr;
  // A stream the host was told to wait on (sendData reported bytes held back
  // and the host set st.wantDrain) has room again.
  void (*writable)(void* user, void* held) = nullptr;
};

class Session {
 public:
  Session(const Settings& local, Host host) : local_(local), host_(host), streams_(16) {
    hpack_.setMaxTableSize(local_.headerTableSize);
    connRecvWindow_ = kDefaultWindow;
    calm_ = kCalmBurst;
  }
  ~Session() {
    streams_.forEach([](uint32_t, Stream* st) { delete st; });
    for (Stream* st : free_) delete st;
  }
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Frames to put on the wire. The host writes and clears it.
  std::string& out() { return out_; }

  // The server's half of the connection preface: SETTINGS, and the window
  // update that opens the connection-level window.
  void start() {
    std::string s;
    auto add = [&s](uint16_t id, uint32_t v) {
      s.push_back(static_cast<char>(id >> 8));
      s.push_back(static_cast<char>(id & 0xff));
      appendU32(s, v);
    };
    if (local_.headerTableSize != 4096) add(kSettingHeaderTableSize, local_.headerTableSize);
    add(kSettingMaxConcurrentStreams, local_.maxConcurrentStreams);
    add(kSettingInitialWindowSize, local_.initialWindowSize);
    if (local_.maxFrameSize != kMinFrameSize) add(kSettingMaxFrameSize, local_.maxFrameSize);
    add(kSettingMaxHeaderListSize, local_.maxHeaderListSize);
    appendFrameHeader(out_, s.size(), kSettings, 0, 0);
    out_.append(s);
    if (local_.connectionWindow > kDefaultWindow) {
      appendFrameHeader(out_, 4, kWindowUpdate, 0, 0);
      appendU32(out_, local_.connectionWindow - kDefaultWindow);
      connRecvWindow_ = local_.connectionWindow;
    }
  }

  // True once the connection is over: a connection error was sent (GOAWAY is
  // in out()), or the peer's preface was not HTTP/2. The host flushes out()
  // and closes.
  bool dead() const { return dead_; }
  // Streams whose request the host holds.
  size_t held() const { return held_; }
  size_t streamCount() const { return streams_.size(); }
  bool goawaySent() const { return goawaySent_; }
  // Response bytes held back by the peer's flow-control windows, on every
  // stream: what it is owed and has not let the server send.
  size_t heldBytes() const {
    size_t n = 0;
    for (const uint32_t id : blocked_) {
      if (const Stream* st = find(id)) n += st->pending.size() - st->pendingOff;
    }
    return n;
  }
  // How many held-back bytes have gone out since the session began: it moves
  // only when the peer opens a window for them.
  uint64_t heldSent() const { return heldSent_; }

  // Bytes from the peer. `nowMs` is any monotonic clock; it paces the budget
  // for frames that cost the server work and the peer nothing.
  void feed(const char* data, size_t len, uint64_t nowMs) {
    if (dead_) return;
    now_ = nowMs;
    size_t off = 0;  // how much of `data` has been taken
    for (;;) {
      // Input kept from earlier reads comes first (joinKept); once there is
      // none, the read is gone through where it is.
      const bool kept = !in_.empty();
      const size_t taken = off;
      if (kept && !joinKept(data, len, off)) break;
      const uint8_t* const p = kept ? reinterpret_cast<const uint8_t*>(in_.data()) + inOff_
                                    : reinterpret_cast<const uint8_t*>(data) + off;
      const size_t n = kept ? in_.size() - inOff_ : len - off;
      const size_t pos = run(p, n);
      if (dead_) {
        in_.clear();
        inOff_ = 0;
        return;
      }
      if (!kept) {
        if (pos < n) in_.assign(reinterpret_cast<const char*>(p) + pos, n - pos);
        break;
      }
      if (!keptDone(pos, off == len)) break;
      if (pos == 0 && off == taken && !stop_) break;  // nothing moved: never the case, and never a loop
    }
    if (in_.capacity() > 65536 && in_.empty()) in_.shrink_to_fit();
  }

  // ---- the response side (called by the host) ----

  // The response head: `block` is a complete HPACK header block.
  void sendHeaders(Stream& st, std::string_view block, bool endStream) {
    if (st.localClosed) return;
    size_t off = std::min<size_t>(block.size(), peerMaxFrame_);
    uint8_t flags = endStream ? kFlagEndStream : 0;
    if (off == block.size()) flags |= kFlagEndHeaders;
    appendFrameHeader(out_, off, kHeaders, flags, st.id);
    out_.append(block.data(), off);
    while (off < block.size()) {
      const size_t take = std::min<size_t>(block.size() - off, peerMaxFrame_);
      appendFrameHeader(out_, take, kContinuation,
                        off + take == block.size() ? kFlagEndHeaders : 0, st.id);
      out_.append(block.data() + off, take);
      off += take;
    }
    if (endStream) localEnd(st);
  }

  // Response body bytes. What the stream's and the connection's windows
  // allow goes out now; the rest is kept and sent as the peer opens them.
  // Returns the bytes still held back for this stream. After a call with
  // endStream the host must not touch `st` again unless bytes are held back.
  size_t sendData(Stream& st, const char* data, size_t len, bool endStream) {
    if (st.localClosed) return 0;
    if (!st.pending.empty() || st.pendingEnd) {  // order: behind what is already waiting
      st.pending.append(data, len);
      st.pendingEnd = st.pendingEnd || endStream;
      return st.pending.size() - st.pendingOff;
    }
    bool finished = false;
    const size_t sent = writeData(st, data, len, endStream, finished);
    if (finished) return 0;  // everything went, END_STREAM with it: the stream is gone
    if (sent < len || endStream) {
      st.pending.assign(data + sent, len - sent);
      st.pendingOff = 0;
      st.pendingEnd = endStream;
      if (!st.blocked) {
        st.blocked = true;
        blocked_.push_back(st.id);
      }
      waitsForConnection();
    }
    return st.pending.size();
  }

  // The host keeps the request past dispatch(): `held` comes back in
  // aborted() and writable(), and the stream counts as held until release().
  void hold(Stream& st, void* held) {
    if (st.user == nullptr && held != nullptr) held_++;
    st.user = held;
  }

  // The host is done with the request (it answered, or gave up).
  void release(Stream& st) {
    if (st.user != nullptr) {
      st.user = nullptr;
      if (held_ > 0) held_--;
    }
    st.wantDrain = false;
  }

  // Abandon a stream from the host's side (the handler's response can never
  // complete, the server is shedding it): RST_STREAM, and the stream is gone.
  void reset(Stream& st, uint32_t code) {
    release(st);
    const uint32_t id = st.id;
    sendRst(id, code);
    drop(st);
  }

  // The host's object of every stream it holds.
  template <typename Fn>
  void forEachHeld(Fn&& fn) const {
    streams_.forEach([&fn](uint32_t, Stream* st) {
      if (st->user != nullptr) fn(st->user);
    });
  }

  // The connection is going away without ceremony: nothing more is read,
  // written or reported.
  void abandon() { dead_ = stop_ = true; }

  // The host stops the session where it is in its input: the answers already
  // given are waiting on a peer that is not reading them, and acting on more
  // of what it sent would only add to them. The frame being processed is
  // finished; from then on feed() keeps what arrives without acting on it,
  // until resume() - after which the host calls feed() (with or without new
  // bytes) to go on. inputHeld() is how much is waiting.
  void pause() { paused_ = stop_ = true; }
  void resume() {
    paused_ = false;
    stop_ = dead_;
  }
  bool paused() const { return paused_; }
  size_t inputHeld() const { return in_.size() - inOff_; }
  const Settings& settings() const { return local_; }

  // The server is closing the connection with requests on it: each stream
  // still open is reset (the response it was owed will not come), then
  // GOAWAY. The host is not called back - it is the one closing.
  void shutdown() {
    std::vector<uint32_t> ids;
    streams_.forEach([&ids](uint32_t id, Stream* st) {
      if (!st->localClosed) ids.push_back(id);
    });
    for (const uint32_t id : ids) sendRst(id, kInternalError);
    goaway(kNoError);
  }

  // Tell the peer to open no more streams (a graceful shutdown): what is in
  // flight completes, anything newer is not processed.
  void goaway(uint32_t code = kNoError) {
    if (goawaySent_) return;
    goawaySent_ = true;
    appendFrameHeader(out_, 8, kGoaway, 0, 0);
    appendU32(out_, lastStreamId_);
    appendU32(out_, code);
  }

 private:
  // ---- frame dispatch ----

  // Input kept from earlier reads is joined with only as much of the new
  // bytes as completes the frame it begins - a header, or a frame that has
  // to be whole before it is acted on - and the rest of the read is gone
  // through where it is. (Joined whole with every read, a body arriving in
  // frames that never line up with the reads, which is every body over TLS,
  // was copied twice on its way to the request.) A session that is stopped
  // keeps all of it. `off` is how much of `data` has been taken. False when
  // what is kept is still not whole and there is nothing more to add.
  MORO_NOINLINE bool joinKept(const char* data, size_t len, size_t& off) {
    const size_t want = stop_ ? len - off : missing();
    const size_t take = std::min(want, len - off);
    in_.append(data + off, take);
    off += take;
    return take == want;
  }

  // run() consumed `pos` bytes of the kept input. True when feed() is to go
  // on: with the rest of the read once nothing is kept, or with what is
  // kept when more of the read can be joined to it.
  MORO_NOINLINE bool keptDone(size_t pos, bool readTaken) {
    inOff_ += pos;
    if (inOff_ == in_.size()) {
      in_.clear();
      inOff_ = 0;
      return true;
    }
    // What was consumed is dropped once it is at least as much as what is
    // left: a session paused over a large backlog and resumed many times
    // moves each byte once, not once per resume.
    if (inOff_ >= in_.size() - inOff_) {
      in_.erase(0, inOff_);
      inOff_ = 0;
    }
    return !(stop_ && readTaken);
  }

  // Act on the frames in [p, p + n): returns how many bytes were consumed.
  // What is left is a frame that is not all there yet (or everything, once
  // the session is stopped).
  MORO_ALWAYS_INLINE size_t run(const uint8_t* p, size_t n) {
    size_t pos = 0;
    if (prefaceSeen_ < kPreface.size()) {
      const size_t take = std::min(n, kPreface.size() - prefaceSeen_);
      if (memcmp(p, kPreface.data() + prefaceSeen_, take) != 0) {
        connectionError(kProtocolError);
        return 0;
      }
      prefaceSeen_ += take;
      pos = take;
    }
    if (dataLeft_ != 0 && !stop_) {  // the rest of a DATA frame whose payload is taken as it arrives
      pos += dataPiece(p + pos, n - pos);
      if (dataLeft_ != 0) return pos;
    }
    while (!stop_ && n - pos >= 9) {
      const uint32_t length = (static_cast<uint32_t>(p[pos]) << 16) |
                              (static_cast<uint32_t>(p[pos + 1]) << 8) | p[pos + 2];
      if (length > local_.maxFrameSize) {
        connectionError(kFrameSizeError);
        return pos;
      }
      const uint8_t type = p[pos + 3];
      const uint8_t flags = p[pos + 4];
      const uint32_t streamId = readU32(p + pos + 5) & 0x7fffffffu;
      if (n - pos < 9 + static_cast<size_t>(length)) {
        // Not all of it is here. A DATA frame is acted on from its header:
        // what there is of its payload goes to the request now and the rest
        // as it arrives, never waiting in the session's own buffer first.
        // Any other frame (and a padded DATA frame, whose padding is known
        // from its first payload byte) waits until it is whole.
        if (!streamable(type, flags)) break;
        pos += 9;
        dataBegin(flags, streamId, length);
        if (dataLeft_ != 0) pos += dataPiece(p + pos, n - pos);  // all of what is here
        break;
      }
      frame(type, flags, streamId, p + pos + 9, length);
      pos += 9 + length;
    }
    return pos;
  }

  static bool streamable(uint8_t type, uint8_t flags) {
    return type == kData && (flags & kFlagPadded) == 0;
  }

  // How many more bytes the input kept in in_ needs before run() can act on
  // what it begins: the rest of a frame header, or of a frame that must be
  // whole. Zero when it can be acted on as it is.
  size_t missing() const {
    if (dataLeft_ != 0) return 0;
    const size_t have = in_.size() - inOff_;
    if (have < 9) return 9 - have;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(in_.data()) + inOff_;
    const size_t length = (static_cast<size_t>(p[0]) << 16) | (static_cast<size_t>(p[1]) << 8) | p[2];
    if (length > local_.maxFrameSize || streamable(p[3], p[4])) return 0;
    return have >= 9 + length ? 0 : 9 + length - have;
  }

  // What every frame is checked for before its type is looked at. False: a
  // connection error was raised.
  bool admit(uint8_t type, uint32_t id) {
    // A header block in progress admits nothing but its CONTINUATION frames
    // (RFC 9113 6.10).
    if (contStream_ != 0 && (type != kContinuation || id != contStream_)) {
      connectionError(kProtocolError);
      return false;
    }
    if (!settingsSeen_ && type != kSettings) {  // the preface ends with SETTINGS (3.4)
      connectionError(kProtocolError);
      return false;
    }
    return true;
  }

  void frame(uint8_t type, uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (!admit(type, id)) return;
    switch (type) {
      case kData: onData(flags, id, p, len); break;
      case kHeaders: onHeaders(flags, id, p, len); break;
      case kPriority: onPriority(id, p, len); break;
      case kRstStream: onRstStream(id, p, len); break;
      case kSettings: onSettings(flags, id, p, len); break;
      case kPushPromise: connectionError(kProtocolError); break;  // a client cannot push (8.4)
      case kPing: onPing(flags, id, p, len); break;
      case kGoaway: onGoaway(id, len); break;
      case kWindowUpdate: onWindowUpdate(id, p, len); break;
      case kContinuation: onContinuation(flags, id, p, len); break;
      default: break;  // unknown types are ignored (4.1)
    }
  }

  // ---- SETTINGS, PING, GOAWAY ----

  void onSettings(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (id != 0) return connectionError(kProtocolError);
    if (flags & kFlagAck) {
      if (len != 0) connectionError(kFrameSizeError);
      return;
    }
    if (len % 6 != 0) return connectionError(kFrameSizeError);
    if (settingsSeen_ && !calm(kCostControl)) return;
    settingsSeen_ = true;
    // SETTINGS_INITIAL_WINDOW_SIZE moves every stream's window. A frame may
    // carry it thousands of times; the streams are visited once, after the
    // loop: the last value is the one that stays, and the largest decides
    // whether some window went past 2^31-1 on the way (6.9.2).
    bool windowSet = false;
    uint32_t lastWindow = 0, largestWindow = 0;
    for (uint32_t i = 0; i + 6 <= len; i += 6) {
      const uint16_t key = static_cast<uint16_t>((p[i] << 8) | p[i + 1]);
      const uint32_t value = readU32(p + i + 2);
      switch (key) {
        case kSettingEnablePush:
          if (value > 1) return connectionError(kProtocolError);
          break;
        case kSettingInitialWindowSize:
          if (value > kMaxWindow) return connectionError(kFlowControlError);
          if (!windowSet || value > largestWindow) largestWindow = value;
          lastWindow = value;
          windowSet = true;
          break;
        case kSettingMaxFrameSize:
          if (value < kMinFrameSize || value > kMaxFrameSizeLimit)
            return connectionError(kProtocolError);
          peerMaxFrame_ = value;
          break;
        default:
          break;  // header table size (our encoder uses none), the advisory ones, unknown ones
      }
    }
    if (windowSet) {
      const int64_t peak = static_cast<int64_t>(largestWindow) - static_cast<int64_t>(peerInitialWindow_);
      const int64_t delta = static_cast<int64_t>(lastWindow) - static_cast<int64_t>(peerInitialWindow_);
      peerInitialWindow_ = lastWindow;
      bool overflow = false;
      streams_.forEach([&](uint32_t, Stream* st) {
        if (st->sendWindow + peak > static_cast<int64_t>(kMaxWindow)) overflow = true;
        st->sendWindow += delta;
      });
      if (overflow) return connectionError(kFlowControlError);
    }
    appendFrameHeader(out_, 0, kSettings, kFlagAck, 0);
    flushBlocked();  // a larger initial window may have opened streams
  }

  void onPing(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (id != 0) return connectionError(kProtocolError);
    if (len != 8) return connectionError(kFrameSizeError);
    if (flags & kFlagAck) return;
    if (!calm(kCostControl)) return;
    appendFrameHeader(out_, 8, kPing, kFlagAck, 0);
    out_.append(reinterpret_cast<const char*>(p), 8);
  }

  void onGoaway(uint32_t id, uint32_t len) {
    if (id != 0) return connectionError(kProtocolError);
    if (len < 8) return connectionError(kFrameSizeError);
    // The peer will open no more streams; the ones in flight complete.
  }

  // ---- WINDOW_UPDATE, PRIORITY, RST_STREAM ----

  void onWindowUpdate(uint32_t id, const uint8_t* p, uint32_t len) {
    if (len != 4) return connectionError(kFrameSizeError);
    const uint32_t inc = readU32(p) & 0x7fffffffu;
    if (!windowUpdateAllowed()) return;
    if (id == 0) {
      if (inc == 0) return connectionError(kProtocolError);
      connSendWindow_ += inc;
      connGranted_ += inc;
      if (connSendWindow_ > static_cast<int64_t>(kMaxWindow))
        return connectionError(kFlowControlError);
      // Only when a stream is waiting for this window: one held back by its
      // own window gains nothing from it, and is not gone through.
      if (connStarved_) flushBlocked();
      return;
    }
    if (isIdle(id)) return connectionError(kProtocolError);
    Stream* st = find(id);
    if (!st) return;  // closed: a late update is expected and harmless (5.1)
    if (inc == 0) return streamError(id, kProtocolError);
    st->sendWindow += inc;
    if (st->sendWindow > static_cast<int64_t>(kMaxWindow)) return streamError(id, kFlowControlError);
    if (st->blocked) {
      void* wake = nullptr;
      if (flushStream(*st, wake) && !st->blocked) unblock(id);
      // Last: the host may end the stream from inside the call.
      if (wake != nullptr) host_.writable(host_.user, wake);
    }
  }

  // WINDOW_UPDATE frames cost the peer nothing, and the server the work of
  // going to the streams that wait. A client sends them as it takes in what
  // it was sent and as it opens streams, so that many are free: two for each
  // stream it has opened, one for each kWindowUpdateBytes of DATA it has been
  // sent, and a few on top. One past that draws on the budget every frame of
  // that kind draws on (calm). False: the budget is spent and the connection
  // has been told so.
  bool windowUpdateAllowed() {
    const uint64_t sent = static_cast<uint64_t>(connGranted_ - connSendWindow_);
    const uint64_t allowed = kWindowUpdateFree + lastStreamId_ + 1 + sent / kWindowUpdateBytes;
    if (windowUpdates_ < allowed) {
      windowUpdates_++;
      return true;
    }
    return calm(kCostControl);
  }

  void onPriority(uint32_t id, const uint8_t* p, uint32_t len) {
    if (id == 0) return connectionError(kProtocolError);
    if (len != 5) return streamError(id, kFrameSizeError);
    if ((readU32(p) & 0x7fffffffu) == id) return streamError(id, kProtocolError);  // depends on itself
    calm(kCostControl);  // otherwise ignored (5.3.2)
  }

  void onRstStream(uint32_t id, const uint8_t* /*p*/, uint32_t len) {
    if (id == 0) return connectionError(kProtocolError);
    if (len != 4) return connectionError(kFrameSizeError);
    if (isIdle(id)) return connectionError(kProtocolError);
    // Opening streams only to reset them costs the peer two frames and the
    // server a request's worth of work each (CVE-2023-44487).
    if (!calm(kCostReset)) return;
    Stream* st = find(id);
    if (!st) return;
    abortHeld(*st);
    drop(*st);
    creditConnection();  // what it had buffered is gone: the window may reopen
  }

  // ---- HEADERS / CONTINUATION ----

  void onHeaders(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (id == 0 || (id & 1) == 0) return connectionError(kProtocolError);
    size_t off = 0;
    size_t pad = 0;
    if (flags & kFlagPadded) {
      if (len < 1) return connectionError(kFrameSizeError);
      pad = p[0];
      off = 1;
    }
    if (flags & kFlagPriority) {
      if (len < off + 5) return connectionError(kFrameSizeError);
      if ((readU32(p + off) & 0x7fffffffu) == id) {
        // A stream that depends on itself (5.3.1): a stream error, but the
        // block must still be decoded to keep the table in step.
        blockOdd_ |= kOddSelfDependent;
      }
      off += 5;
    }
    if (pad > len - off) return connectionError(kProtocolError);
    const uint8_t* frag = p + off;
    const size_t fragLen = len - off - pad;
    contEndStream_ = (flags & kFlagEndStream) != 0;
    if (flags & kFlagEndHeaders) {
      headerBlock(id, frag, fragLen, contEndStream_);
      return;
    }
    contStream_ = id;
    contFrames_ = 0;
    hbuf_.assign(reinterpret_cast<const char*>(frag), fragLen);
  }

  void onContinuation(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (contStream_ == 0 || id != contStream_) return connectionError(kProtocolError);
    // A header block may be cut into any number of frames, each of which may
    // be empty: bounded in bytes and in frames, or it never has to end
    // (CVE-2024-27316).
    if (++contFrames_ > kMaxContinuations || hbuf_.size() + len > maxHeaderBlock())
      return connectionError(kEnhanceYourCalm);
    hbuf_.append(reinterpret_cast<const char*>(p), len);
    if ((flags & kFlagEndHeaders) == 0) return;
    contStream_ = 0;
    std::string block;
    block.swap(hbuf_);
    headerBlock(id, reinterpret_cast<const uint8_t*>(block.data()), block.size(), contEndStream_);
    block.clear();
    hbuf_.swap(block);  // keep the capacity
    if (hbuf_.capacity() > 65536) hbuf_.shrink_to_fit();
  }

  size_t maxHeaderBlock() const { return static_cast<size_t>(local_.maxHeaderListSize) + 4096; }

  // A complete header block for stream `id`. It is always decoded, whatever
  // becomes of the stream: the HPACK table is the connection's.
  void headerBlock(uint32_t id, const uint8_t* p, size_t n, bool endStream) {
    if (n > maxHeaderBlock()) return connectionError(kEnhanceYourCalm);

    Stream* st = find(id);
    if (st != nullptr) {  // a second block on an open stream: trailers
      blockOdd_ = 0;
      bool pseudo = false;
      if (!hpack_.decode(p, n, [&](std::string_view name, std::string_view) {
            if (!name.empty() && name[0] == ':') pseudo = true;
          }))
        return connectionError(kCompressionError);
      if (st->remoteClosed) return streamError(id, kStreamClosed);
      if (!endStream || pseudo) return streamError(id, kProtocolError);  // 8.1
      bodyGiven(*st);
      return endOfRequest(*st);
    }

    if (id <= lastStreamId_) {
      // Closed. One we reset may still have frames in flight, which are
      // ignored; anything else is a peer that lost track (5.1).
      blockOdd_ = 0;
      if (!hpack_.decode(p, n, [](std::string_view, std::string_view) {}))
        return connectionError(kCompressionError);
      if (!recentlyReset(id)) connectionError(kStreamClosed);
      return;
    }
    lastStreamId_ = id;

    if (goawaySent_ || streams_.size() >= local_.maxConcurrentStreams) {
      blockOdd_ = 0;
      if (!hpack_.decode(p, n, [](std::string_view, std::string_view) {}))
        return connectionError(kCompressionError);
      if (!goawaySent_) sendRst(id, kRefusedStream);  // safe for the client to retry (8.7)
      return;
    }

    st = open(id);
    Request rq;
    rq.st = st;
    if (!hpack_.decode(p, n, [&](std::string_view name, std::string_view value) {
          requestField(rq, name, value);
        })) {
      drop(*st);
      return connectionError(kCompressionError);
    }
    st->headers.resize(st->headerCount);
    // What few blocks have, behind one test: a stream made to depend on
    // itself (onHeaders), and cookie fields to join (requestField).
    if (const uint8_t odd = blockOdd_; odd != 0) {
      blockOdd_ = 0;
      if (odd & kOddSelfDependent) return streamError(id, kProtocolError);
      joinedCookie(*st, rq.cookieAt);
    }

    // A request is malformed without exactly one :method, :scheme and :path
    // (8.3.1); CONNECT, which has neither of the last two, is not served.
    if ((rq.bad & kMalformed) || !rq.method || !rq.scheme || !rq.path || st->path.empty())
      return streamError(id, kProtocolError);
    if (rq.bad != 0) return refuse(*st, 431, endStream);  // too large (malformed was seen to above)
    if (local_.maxUriSize && st->path.size() + st->query.size() + 1 > local_.maxUriSize)
      return refuse(*st, 414, endStream);
    if (rq.contentLength >= 0 && static_cast<uint64_t>(rq.contentLength) > local_.maxBodySize)
      return refuse(*st, 413, endStream);
    st->declared = rq.contentLength;
    if (!rq.sawHost && !rq.authority.empty()) {
      addHeader(*st, "host", rq.authority);
    } else if ((rq.authoritySeen && rq.authority.empty()) || (!rq.sawHost && rq.scheme == kSchemeHttp)) {
      // The authority of a request is never empty: there is no target
      // without a host (RFC 9110 4.2), and a request with no authority to
      // convey carries no :authority at all (8.3.1). And an http or https
      // target always has one, which a client must send, as :authority or
      // as Host (RFC 9110 7.2): a request with neither is malformed, as an
      // HTTP/1.1 request without Host is a 400 - and, as there, only once
      // the limits above have had their say. That holds for OPTIONS * as for
      // any other target. A scheme of another kind may have no authority at
      // all and is left as it is. (Looked at here, where a request that
      // names its authority in :authority alone - nearly every one - has
      // already been told apart.)
      return streamError(id, kProtocolError);
    }
    st->headers.resize(st->headerCount);

    if (endStream) return endOfRequest(*st);
    if (st->expectContinue) {  // the client is waiting to be told to send the body
      std::string block;
      encodeStatus(block, 100);
      appendFrameHeader(out_, block.size(), kHeaders, kFlagEndHeaders, id);
      out_.append(block);
    }
    // Room for a small declared body at once; a larger one waits for part
    // of it to arrive (dataBody).
    if (rq.contentLength > 0 && static_cast<uint64_t>(rq.contentLength) <= kReserveAtOnce)
      st->body.reserve(static_cast<size_t>(rq.contentLength));
  }

  struct Request {
    Stream* st = nullptr;
    bool method = false, path = false;
    uint8_t scheme = 0;     // kSchemeNone until :scheme is seen, then what kind it names
    bool regular = false;   // a regular field has been seen: no pseudo-header may follow
    uint8_t bad = 0;        // kMalformed, kTooLarge: one byte, looked at once for every field
    bool sawHost = false;
    bool authoritySeen = false;
    uint8_t cookie = 0;     // cookie fields seen: none, one (in the list, at cookieAt), or more (joined in cookie_)
    size_t cookieAt = 0;
    size_t listSize = 0;
    long long contentLength = -1;
    std::string authority;
  };

  enum : uint8_t { kMalformed = 1, kTooLarge = 2 };

  // What :scheme names: http and https, whose requests must name their
  // authority, or something else.
  enum : uint8_t { kSchemeNone = 0, kSchemeOther = 1, kSchemeHttp = 2 };

  // "http" or "https", in any case (RFC 3986 3.1). This is asked of every
  // request, and nearly every request names its scheme by one of the two
  // entries of the HPACK static table: the value is then that entry's own,
  // known by where it is, and the test is two comparisons in line. Spelled
  // out, it is compared four bytes at once (httpSchemeSpelled).
  static MORO_ALWAYS_INLINE bool isHttpScheme(std::string_view v) {
    return v.data() == kStaticTable[6].value.data() || v.data() == kStaticTable[7].value.data() ||
           httpSchemeSpelled(v);
  }

  static MORO_NOINLINE bool httpSchemeSpelled(std::string_view v) {
    if (v.size() - 4 > 1) return false;
    uint32_t word;
    std::memcpy(&word, v.data(), 4);
    constexpr uint32_t http = std::endian::native == std::endian::little ? 0x70747468u : 0x68747470u;
    if ((word | 0x20202020u) != http) return false;
    return v.size() == 4 || (v[4] | 0x20) == 's';
  }

  // In line wherever it is called, and the list's own add() in line in it:
  // two of the calls are made for every request, and as functions of their
  // own each cost more than its body.
  static MORO_ALWAYS_INLINE MORO_H2_FLATTEN void addHeader(Stream& st, std::string_view name,
                                                           std::string_view value) {
    if (st.headerCount == 0) st.headers.clear();
    st.headers.add(name, value);
    st.headerCount++;
  }

  // More than one cookie field came, and the field the first of them became
  // (number `at` of the request's) is given the joined value. The list keeps
  // its text behind offsets and a field of it cannot be changed, so that
  // field and the ones after it are taken out and put back. Out of line:
  // most requests carry one cookie field or none, and pay one test for this.
  MORO_NOINLINE void joinedCookie(Stream& st, size_t at) {
    std::string later;  // the fields behind the cookie: names and values end to end
    std::vector<std::pair<size_t, size_t>> lengths;
    for (size_t i = at + 1; i < st.headerCount; i++) {
      const Header h = st.headers[i];
      lengths.emplace_back(h.name.size(), h.value.size());
      later.append(h.name);
      later.append(h.value);
    }
    st.headers.resize(at);
    st.headerCount = at;
    addHeader(st, "cookie", cookie_);
    size_t off = 0;
    for (const auto& [nameLen, valueLen] : lengths) {
      addHeader(st, std::string_view(later.data() + off, nameLen),
                std::string_view(later.data() + off + nameLen, valueLen));
      off += nameLen + valueLen;
    }
    if (cookie_.capacity() > 16384) std::string().swap(cookie_);
  }

  // One decoded field of a request head (RFC 9113 8.2, 8.3).
  void requestField(Request& rq, std::string_view name, std::string_view value) {
    Stream& st = *rq.st;
    rq.listSize += name.size() + value.size() + 32;
    if (rq.listSize > local_.maxHeaderListSize) rq.bad |= kTooLarge;
    if (rq.bad != 0) return;  // still decoded, no longer kept
    if (name.empty()) {
      rq.bad |= kMalformed;
      return;
    }
    // Field values carry no NUL, CR or LF, and no surrounding whitespace
    // (8.2.1): what would split a line once this is forwarded as HTTP/1. The
    // other control bytes are refused with them (RFC 9110 5.5), as the
    // HTTP/1 parser refuses them: a request reaches a handler with the same
    // bytes ruled out whichever protocol carried it.
    if (!validValueBytes(reinterpret_cast<const unsigned char*>(value.data()), value.size())) {
      rq.bad |= kMalformed;
      return;
    }
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.back() == ' ' ||
                           value.back() == '\t')) {
      rq.bad |= kMalformed;
      return;
    }
    if (name[0] == ':') {
      if (rq.regular) {
        rq.bad |= kMalformed;
        return;
      }
      if (name == ":method") {
        if (rq.method || value.empty()) {
          rq.bad |= kMalformed;
          return;
        }
        for (const char ch : value) {
          if (!isTokenChar(static_cast<unsigned char>(ch))) {
            rq.bad |= kMalformed;
            return;
          }
        }
        rq.method = true;
        st.method = methodFrom(value);
        if (st.method == Method::OTHER) st.methodStr.assign(value);
        if (value == "CONNECT") rq.bad |= kMalformed;
      } else if (name == ":path") {
        if (rq.path) {
          rq.bad |= kMalformed;
          return;
        }
        rq.path = true;
        for (const char ch : value) {  // the request-target hygiene of the HTTP/1 parser
          const unsigned char u = static_cast<unsigned char>(ch);
          if (u <= 0x20 || u == 0x7f || (u > 0x7f && !local_.allowNonAsciiTarget)) {
            rq.bad |= kMalformed;
            return;
          }
        }
        const size_t q = value.find('?');
        if (q == std::string_view::npos) {
          st.path.assign(value);
          st.query.clear();
        } else {
          st.path.assign(value.data(), q);
          st.query.assign(value.data() + q + 1, value.size() - q - 1);
        }
      } else if (name == ":scheme") {
        if (rq.scheme) {
          rq.bad |= kMalformed;
          return;
        }
        rq.scheme = isHttpScheme(value) ? kSchemeHttp : kSchemeOther;
      } else if (name == ":authority") {
        // Once (8.3), and of the shape the HTTP/1 parser asks of Host: it is
        // what the application reads as the host. (Never empty either: that
        // is settled with the rest of the authority, once the block is
        // complete - headerBlock.)
        if (rq.authoritySeen || !validHostValue(value)) {
          rq.bad |= kMalformed;
          return;
        }
        rq.authoritySeen = true;
        rq.authority.assign(value);
      } else {
        rq.bad |= kMalformed;  // a response pseudo-header, or one that does not exist
      }
      return;
    }
    rq.regular = true;
    std::string_view stored = value;  // what the host is given for this field
    // Names are lowercase tokens (8.2.1); an uppercase letter is a token
    // character, so it is checked for separately.
    for (const char ch : name) {
      if (!kFieldNameChar[static_cast<unsigned char>(ch)]) {
        rq.bad |= kMalformed;
        return;
      }
    }
    if (isConnectionSpecific(name)) {
      rq.bad |= kMalformed;
      return;
    }
    switch (name.size()) {
      case 2:
        if (name == "te" && value != "trailers") {
          rq.bad |= kMalformed;
          return;
        }
        break;
      case 4:
        if (name == "host") {
          // One Host line, holding a host (RFC 9112 3.2, as on HTTP/1) - and
          // not an empty one, for the reason :authority may not be.
          if (rq.sawHost || value.empty() || !validHostValue(value)) {
            rq.bad |= kMalformed;
            return;
          }
          rq.sawHost = true;
          // With :authority present a server must not use Host (RFC 9113
          // 8.3.1): the line stays where the client put it and holds the
          // :authority value. Pseudo-header fields precede regular ones
          // (8.3), so :authority, if the request has one, is already known.
          if (!rq.authority.empty()) stored = rq.authority;
        }
        break;
      case 6:
        // (By first letter: "accept" is in nearly every request and is
        // neither, and is not compared with both.)
        if (name[0] == 'e') {
          if (name == "expect" && iequals(value, "100-continue")) st.expectContinue = true;
        } else if (name[0] == 'c' && name == "cookie") {
          // A client may send each cookie pair as a field of its own, which
          // compresses better (8.2.3). They are one field to anything that
          // reads HTTP. The first is added to the request like any other
          // field; the ones behind it are joined to its value with "; ", and
          // the field is given the whole once the block is complete
          // (headerBlock, joinedCookie). Left as several, a framework that
          // folds repeated fields with ", " would hand its application
          // cookie values that are not the ones sent.
          if (rq.cookie != 0) {
            if (!value.empty()) {
              if (rq.cookie == 1) {
                cookie_.assign(st.headers[rq.cookieAt].value);
                rq.cookie = 2;
                blockOdd_ |= kOddCookies;
              }
              if (!cookie_.empty()) cookie_ += "; ";
              cookie_ += value;
            }
            return;
          }
          rq.cookie = 1;
          rq.cookieAt = st.headerCount;
        }
        break;
      case 14:
        if (name == "content-length") {
          long long v = 0;
          if (value.empty() || value.size() > 18) {
            rq.bad |= kMalformed;
            return;
          }
          for (const char ch : value) {
            if (ch < '0' || ch > '9') {
              rq.bad |= kMalformed;
              return;
            }
            v = v * 10 + (ch - '0');
          }
          if (rq.contentLength >= 0 && rq.contentLength != v) {
            rq.bad |= kMalformed;
            return;
          }
          rq.contentLength = v;
        }
        break;
      default:
        break;
    }
    if (st.headerCount >= local_.maxHeaders) {
      rq.bad |= kTooLarge;
      return;
    }
    addHeader(st, name, stored);
  }

  // ---- DATA ----

  void onData(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    size_t off = 0;
    size_t n = 0;
    Stream* st = dataHead(flags, id, p, len, off, n);
    if (st == nullptr) return;
    dataBody(*st, p + off, n);
    dataTail(*st, len, (flags & kFlagEndStream) != 0);
  }

  // A DATA frame of `len` bytes, before any of its payload is taken: the
  // windows, the padding, the stream's state, the body limit. Returns the
  // stream the payload belongs to, with where it lies in the frame (`off`,
  // `n` bytes), or null when the frame is not going to a request (it is then
  // read past). `p` is read only for the pad length of a padded frame.
  MORO_ALWAYS_INLINE Stream* dataHead(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len,
                                      size_t& off, size_t& n) {
    if (id == 0 || isIdle(id)) {
      connectionError(kProtocolError);
      return nullptr;
    }
    // The whole frame, padding included, counts against the connection's
    // window whatever happens to the stream (6.9.1).
    connRecvWindow_ -= len;
    if (connRecvWindow_ < 0) {
      connectionError(kFlowControlError);
      return nullptr;
    }
    connRecvUnacked_ += len;

    size_t pad = 0;
    if (flags & kFlagPadded) {
      if (len < 1) {
        connectionError(kFrameSizeError);
        return nullptr;
      }
      pad = p[0];
      off = 1;
      if (pad > len - off) {
        connectionError(kProtocolError);
        return nullptr;
      }
    }
    n = len - off - pad;
    const bool endStream = (flags & kFlagEndStream) != 0;
    // A frame that carries nothing, on a stream in any state (one that is
    // closed is answered with a reset each time).
    if (n == 0 && !endStream && !calm(kCostControl)) return nullptr;

    Stream* st = find(id);
    if (st == nullptr || st->remoteClosed) {
      // Closed, or half-closed from the peer's side (5.1). A stream we reset
      // ourselves may still have frames in flight; those are read past.
      creditConnection();
      if (st != nullptr) {
        streamError(id, kStreamClosed);
      } else if (!recentlyReset(id)) {
        sendRst(id, kStreamClosed);
      }
      return nullptr;
    }
    st->recvWindow -= len;
    if (st->recvWindow < 0) {
      creditConnection();
      streamError(id, kFlowControlError);
      return nullptr;
    }
    if (st->body.size() + n > local_.maxBodySize) {
      refuse(*st, 413, endStream);
      creditConnection();  // after the stream's buffer is released
      return nullptr;
    }
    return st;
  }

  // Payload bytes of a DATA frame, appended to the request's body.
  MORO_ALWAYS_INLINE void dataBody(Stream& st, const uint8_t* p, size_t n) {
    // A declared Content-Length is room set aside in one piece: at once for
    // a body up to kReserveAtOnce (headerBlock), and for a larger one only
    // once a sixteenth of it has arrived - the rule the HTTP/1 and WebSocket
    // parsers keep. Until then the length is only a claim: set aside when
    // the header block came in, every stream of a connection had the whole
    // of what it declared reserved (maxBodySize each, 256 of them at once)
    // for a peer that had sent a few dozen bytes per stream and need never
    // send more - address space, and committed memory on a platform that
    // commits at allocation.
    const size_t need = st.body.size() + n;
    if (need > st.body.capacity() ||
        (st.declared > 0 && static_cast<size_t>(st.declared) > st.body.capacity() &&
         need >= static_cast<size_t>(st.declared) / kReserveShare)) {
      roomFor(st, need);
    }
    st.body.append(reinterpret_cast<const char*>(p), n);
    buffered_ += n;
  }

  // Room in a request's body for `need` bytes: the declared length once a
  // sixteenth of it is in, and otherwise - past one frame's worth - a power
  // of two, at least double what there was. Those are the steps a body
  // arriving in whole frames always took, and the same ones when the reads
  // cut its frames into pieces; left to grow from whatever size the first
  // piece happened to have, the doubling overshot, and a 4 MiB body could end
  // in a buffer of 8.
  //
  // What the connection has set aside this way is counted (reserved_), and
  // a declared length is set aside only while the count stays within what
  // the connection may have buffered: the bound on bytes received did not
  // cover room reserved ahead of them, and forty-eight streams that each
  // declared the body limit and sent a sixteenth of it had 480 MiB reserved
  // for 30 MiB sent. Past the bound a body grows with what arrives.
  MORO_NOINLINE void roomFor(Stream& st, size_t need) {
    const size_t cap = st.body.capacity();
    size_t target = need > cap && need >= kMinFrameSize ? std::bit_ceil(std::max(need, 2 * cap)) : 0;
    if (st.declared > 0) {
      const size_t declared = static_cast<size_t>(st.declared);
      if (declared >= need && declared <= local_.maxBodySize && need >= declared / kReserveShare &&
          reserved_ - st.bodyHeld + declared <= maxBuffered()) {
        target = declared;
      }
    }
    if (target > cap) st.body.reserve(target);
    reserved_ += st.body.capacity() - st.bodyHeld;
    st.bodyHeld = st.body.capacity();
  }

  // The frame's payload is all in.
  MORO_ALWAYS_INLINE void dataTail(Stream& st, uint32_t len, bool endStream) {
    st.recvUnacked += len;
    creditStream(st, endStream);
    if (endStream) {
      bodyGiven(st);
      return endOfRequest(st);  // credits the connection once the host has the request
    }
    creditConnection();  // may give streams up, this one among them: `st` is not used after it
  }

  // A DATA frame (without padding) whose payload has not all arrived: it is
  // admitted and checked from its header, exactly as a whole one is, and its
  // payload is then taken in whatever pieces the reads bring (dataPiece).
  MORO_NOINLINE void dataBegin(uint8_t flags, uint32_t id, uint32_t len) {
    if (!admit(kData, id)) return;
    size_t off = 0;
    size_t n = 0;
    Stream* st = dataHead(flags, id, nullptr, len, off, n);
    if (dead_) return;
    dataLeft_ = len;
    dataLen_ = len;
    dataEnd_ = (flags & kFlagEndStream) != 0;
    dataStream_ = st != nullptr ? id : 0;  // 0: the payload is read past
  }

  MORO_NOINLINE size_t dataPiece(const uint8_t* p, size_t avail) {
    const size_t take = std::min<size_t>(dataLeft_, avail);
    Stream* st = dataStream_ != 0 ? find(dataStream_) : nullptr;
    if (st != nullptr && !st->remoteClosed) {
      dataBody(*st, p, take);
    } else {
      st = nullptr;  // the stream went away while its frame was arriving
    }
    dataLeft_ -= static_cast<uint32_t>(take);
    if (dataLeft_ == 0) {
      const bool mine = dataStream_ != 0;
      dataStream_ = 0;
      if (st != nullptr) dataTail(*st, dataLen_, dataEnd_);
      else if (mine) creditConnection();
    }
    return take;
  }

  // Give the peer back what it has used of a stream's window, once that is
  // half of it: one WINDOW_UPDATE per half window rather than per frame.
  void creditStream(Stream& st, bool endStream) {
    if (endStream || st.recvUnacked < local_.initialWindowSize / 2) return;
    appendFrameHeader(out_, 4, kWindowUpdate, 0, st.id);
    appendU32(out_, st.recvUnacked);
    st.recvWindow += st.recvUnacked;
    st.recvUnacked = 0;
  }

  // The same for the connection - held back while more request body is
  // buffered than the session will hold at once, which is what stops a peer
  // with many streams from making the server buffer maxBodySize for each.
  void creditConnection() {
    if (connRecvUnacked_ < local_.connectionWindow / 2) return;
    if (buffered_ > maxBuffered()) {
      if (connRecvWindow_ > 0) return;
      shedBuffered();
      if (buffered_ > maxBuffered()) return;
    }
    appendFrameHeader(out_, 4, kWindowUpdate, 0, 0);
    appendU32(out_, connRecvUnacked_);
    connRecvWindow_ += connRecvUnacked_;
    connRecvUnacked_ = 0;
  }

  size_t maxBuffered() const {
    return std::max<size_t>(2 * local_.maxBodySize, static_cast<size_t>(local_.connectionWindow) * 4);
  }

  // More request body is buffered than the session holds at once and the
  // connection's window is spent: no request still arriving can receive
  // another byte, so none of them would ever complete and the window would
  // never reopen. The newest of them are given up - reset as refused, which
  // tells a client nothing was processed and it may retry (8.7) - until the
  // rest fit, and those go on.
  void shedBuffered() {
    while (buffered_ > maxBuffered()) {
      Stream* newest = nullptr;
      streams_.forEach([&newest](uint32_t, Stream* st) {
        if (!st->remoteClosed && (newest == nullptr || st->id > newest->id)) newest = st;
      });
      if (newest == nullptr) return;
      sendRst(newest->id, kRefusedStream);
      drop(*newest);
    }
  }

  // END_STREAM on a request: check the declared length, hand it to the host.
  // A body is complete and about to be the host's: what was set aside for it
  // no longer counts. (Where a body ends - a request without one, which is
  // most requests, has nothing set aside and does not come by here.)
  void bodyGiven(Stream& st) {
    if (st.bodyHeld != 0) {
      reserved_ -= st.bodyHeld;
      st.bodyHeld = 0;
    }
  }

  void endOfRequest(Stream& st) {
    st.remoteClosed = true;
    if (st.declared >= 0 && static_cast<uint64_t>(st.declared) != st.body.size())
      return streamError(st.id, kProtocolError);  // 8.1.1: the lengths must agree
    buffered_ -= std::min(buffered_, st.body.size());
    st.dispatched = true;
    host_.dispatch(host_.user, st);
    // The host may have answered and the stream may be gone: `st` is not
    // touched again.
    creditConnection();
  }

  // ---- answers the session gives by itself ----

  // A request refused before it reaches the host (431, 413, 414): a response
  // with no body. When the request is still arriving the client is told to
  // stop (8.1.1), and what is already in flight is read past.
  void refuse(Stream& st, int status, bool endStream) {
    std::string block;
    encodeStatus(block, status);
    encodeField(block, "content-length", "0");
    appendFrameHeader(out_, block.size(), kHeaders, kFlagEndHeaders | kFlagEndStream, st.id);
    out_.append(block);
    if (!endStream) sendRst(st.id, kNoError);
    drop(st);
  }

  // ---- sending DATA ----

  // Emits DATA frames for as much of [data, data+len) as the windows and the
  // peer's frame size allow, END_STREAM on the last when everything went -
  // in which case `finished` is set and the stream no longer exists.
  size_t writeData(Stream& st, const char* data, size_t len, bool endStream, bool& finished) {
    size_t off = 0;
    // A body of many frames: room for all of them at once (payload plus nine
    // bytes a frame), so the output buffer is not regrown - and its content
    // copied - several times on the way. Never less than double, which keeps
    // the growth geometric when several such bodies are queued in one pass.
    if (len >= kReserveBody) {
      const int64_t allow = std::min<int64_t>(st.sendWindow, connSendWindow_);
      if (allow > 0) {
        const size_t body = std::min<size_t>(len, static_cast<size_t>(allow));
        const size_t need = out_.size() + body + (body / peerMaxFrame_ + 1) * 9;
        if (need > out_.capacity()) out_.reserve(std::max(need, out_.capacity() * 2));
      }
    }
    for (;;) {
      const size_t left = len - off;
      if (left == 0) {
        if (endStream) {  // an empty frame carries the flag (no window needed)
          appendFrameHeader(out_, 0, kData, kFlagEndStream, st.id);
          localEnd(st);
          finished = true;
        }
        return off;
      }
      const int64_t allow = std::min<int64_t>(st.sendWindow, connSendWindow_);
      if (allow <= 0) return off;
      size_t take = std::min<size_t>(left, peerMaxFrame_);
      if (static_cast<int64_t>(take) > allow) take = static_cast<size_t>(allow);
      const bool last = endStream && take == left;
      appendFrameHeader(out_, take, kData, last ? kFlagEndStream : 0, st.id);
      out_.append(data + off, take);
      st.sendWindow -= static_cast<int64_t>(take);
      connSendWindow_ -= static_cast<int64_t>(take);
      off += take;
      if (last) {
        localEnd(st);
        finished = true;
        return off;
      }
    }
  }

  // A stream has bytes held back. When the connection's window is what is
  // spent, a connection-level WINDOW_UPDATE has to come back for it
  // (onWindowUpdate); one held back by its own window alone gains nothing
  // from that frame. Noted where a stream is found waiting, which is off the
  // path of a response that goes out whole.
  void waitsForConnection() {
    if (connSendWindow_ <= 0) connStarved_ = true;
  }

  // Returns false when the stream finished (and is gone). `wake` is set to
  // the host's object for the stream when the host is to be told that it has
  // room again. The caller tells it (host_.writable) and does so last: told
  // from here, a host that ended the response inside the call - which it may,
  // when it is called in place - left the caller reading a stream that had
  // been released, or one already given to another request.
  bool flushStream(Stream& st, void*& wake) {
    bool finished = false;
    const size_t sent = writeData(st, st.pending.data() + st.pendingOff,
                                  st.pending.size() - st.pendingOff, st.pendingEnd, finished);
    heldSent_ += sent;
    if (finished) return false;
    st.pendingOff += sent;
    if (st.pendingOff == st.pending.size()) {
      st.pending.clear();
      st.pendingOff = 0;
    } else if (st.pendingOff >= kPendingCompact && st.pendingOff >= st.pending.size() / 2) {
      // The sent part is dropped once it is the larger half: each byte is
      // moved at most once, whatever the number of window updates it takes
      // to drain (erasing per update moved the whole rest every time).
      st.pending.erase(0, st.pendingOff);
      st.pendingOff = 0;
    }
    if (st.pending.empty() && !st.pendingEnd) st.blocked = false;
    else waitsForConnection();
    if (st.wantDrain && st.user != nullptr && st.pending.size() - st.pendingOff < kDrainMark &&
        host_.writable) {
      st.wantDrain = false;
      wake = st.user;
    }
    return true;
  }

  // Streams waiting on a window, in the order they began to wait. The list
  // is gone through in a copy the host cannot reach (it is called from
  // here, and may queue more), kept from call to call so that going through
  // it allocates nothing; and no further than the connection's window
  // lasts - past that no stream can send, and the rest keep their places.
  void flushBlocked() {
    if (blocked_.empty()) return;
    flushing_.clear();
    flushing_.swap(blocked_);
    connStarved_ = false;
    size_t i = 0;
    for (; i < flushing_.size(); i++) {
      if (dead_) return;
      if (connSendWindow_ <= 0) break;
      const uint32_t id = flushing_[i];
      Stream* st = find(id);
      if (st == nullptr || !st->blocked) continue;
      void* wake = nullptr;
      if (flushStream(*st, wake) && st->blocked) blocked_.push_back(id);
      if (wake != nullptr) host_.writable(host_.user, wake);  // last: `st` may be gone after it
    }
    if (i < flushing_.size()) {
      blocked_.insert(blocked_.end(), flushing_.begin() + static_cast<std::ptrdiff_t>(i), flushing_.end());
      connStarved_ = true;
    }
  }

  // Our END_STREAM is out. A request still arriving is no longer wanted
  // (8.1: the response may complete first); the stream is over either way.
  void localEnd(Stream& st) {
    st.localClosed = true;
    st.pending.clear();
    st.pendingOff = 0;
    st.pendingEnd = false;
    if (!st.remoteClosed) sendRst(st.id, kNoError);
    release(st);
    drop(st);
  }

  // ---- errors ----

  void sendRst(uint32_t id, uint32_t code) {
    appendFrameHeader(out_, 4, kRstStream, 0, id);
    appendU32(out_, code);
    recentReset_[recentAt_++ % kRecentResets] = id;
  }

  bool recentlyReset(uint32_t id) const {
    for (const uint32_t r : recentReset_)
      if (r == id) return true;
    return false;
  }

  // An error confined to one stream (5.4.2).
  void streamError(uint32_t id, uint32_t code) {
    Stream* st = find(id);
    // The peer made the server reset the stream. For a request the host was
    // given that is a request's worth of work for nothing, exactly as when
    // the peer resets it itself, and it costs the same (CVE-2023-44487); any
    // other is one more frame answered for free.
    if (!calm(st != nullptr && st->dispatched ? kCostReset : kCostControl)) return;
    sendRst(id, code);
    if (st == nullptr) return;
    abortHeld(*st);
    drop(*st);
    creditConnection();  // what it had buffered is gone: the window may reopen
  }

  // The host loses a request it holds: it is told, and the stream is no
  // longer its to answer.
  void abortHeld(Stream& st) {
    void* const held = st.user;
    if (held == nullptr) return;
    st.user = nullptr;
    if (held_ > 0) held_--;
    if (host_.aborted) host_.aborted(host_.user, held);
  }

  void unblock(uint32_t id) {
    for (size_t i = 0; i < blocked_.size(); i++) {
      if (blocked_[i] == id) {
        blocked_.erase(blocked_.begin() + static_cast<std::ptrdiff_t>(i));
        return;
      }
    }
  }

  // An error that ends the connection (5.4.1): GOAWAY, then nothing more.
  void connectionError(uint32_t code) {
    if (dead_) return;
    appendFrameHeader(out_, 8, kGoaway, 0, 0);
    appendU32(out_, lastStreamId_);
    appendU32(out_, code);
    goawaySent_ = true;
    dead_ = stop_ = true;
  }

  // The budget for frames that make the server work for nothing: it refills
  // at kCalmRate a second up to kCalmBurst. A peer that outruns it is told so
  // and disconnected (ENHANCE_YOUR_CALM).
  bool calm(uint32_t cost) {
    if (now_ > calmAt_) {
      const uint64_t gained = (now_ - calmAt_) * kCalmRate / 1000;
      if (gained > 0) {
        calm_ = static_cast<uint32_t>(std::min<uint64_t>(kCalmBurst, calm_ + gained));
        calmAt_ = now_;
      }
    }
    if (calm_ < cost) {
      connectionError(kEnhanceYourCalm);
      return false;
    }
    calm_ -= cost;
    return true;
  }

  // ---- streams ----

  bool isIdle(uint32_t id) const { return (id & 1) == 0 || id > lastStreamId_; }

  Stream* find(uint32_t id) const { return streams_.find(id); }

  Stream* open(uint32_t id) {
    Stream* st;
    if (!free_.empty()) {
      st = free_.back();
      free_.pop_back();
    } else {
      st = new Stream();
    }
    st->id = id;
    st->sendWindow = peerInitialWindow_;
    st->recvWindow = local_.initialWindowSize;
    streams_.insert(id, st);
    return st;
  }

  // The stream is over: forget it, keep its buffers for the next one.
  void drop(Stream& st) {
    if (st.user != nullptr) {
      st.user = nullptr;
      if (held_ > 0) held_--;
    }
    if (!st.dispatched) {
      buffered_ -= std::min(buffered_, st.body.size());
      reserved_ -= st.bodyHeld;
      st.bodyHeld = 0;
    }
    if (st.blocked) unblock(st.id);
    streams_.erase(st.id);
    st.id = 0;
    st.recvUnacked = 0;
    st.declared = -1;
    st.remoteClosed = st.localClosed = st.dispatched = st.wantDrain = false;
    st.method = Method::OTHER;
    st.methodStr.clear();
    st.path.clear();
    st.query.clear();
    st.headerCount = 0;
    st.body.clear();
    if (st.body.capacity() > 16384) st.body.shrink_to_fit();
    st.expectContinue = false;
    st.pending.clear();
    st.pendingOff = 0;
    if (st.pending.capacity() > 16384) st.pending.shrink_to_fit();
    st.pendingEnd = false;
    st.blocked = false;
    if (free_.size() < kFreeStreams) {
      free_.push_back(&st);
    } else {
      delete &st;
    }
  }

  static constexpr uint32_t kCalmBurst = 2000;
  static constexpr uint32_t kCalmRate = 200;   // per second
  static constexpr uint32_t kCostControl = 1;  // PING, SETTINGS, PRIORITY, an empty DATA frame
  static constexpr uint32_t kCostReset = 4;    // RST_STREAM
  static constexpr uint32_t kMaxContinuations = 64;
  static constexpr size_t kRecentResets = 32;
  static constexpr size_t kFreeStreams = 128;
  static constexpr size_t kDrainMark = 64 * 1024;
  static constexpr size_t kPendingCompact = 64 * 1024;
  static constexpr size_t kReserveBody = 32 * 1024;
  // A request body's declared length is reserved in full when the header
  // block arrives if it is at most kReserveAtOnce, and otherwise once one
  // kReserveShare-th of it has been received (dataBody).
  // WINDOW_UPDATE frames that are free before any stream or DATA (a client
  // opens its connection window with one), and the DATA bytes that pay for
  // one more (windowUpdateAllowed): no client sends them more often than
  // once per four kilobytes it takes in.
  static constexpr uint64_t kWindowUpdateFree = 16;
  static constexpr uint64_t kWindowUpdateBytes = 1024;
  static constexpr size_t kReserveAtOnce = 64 * 1024;
  static constexpr size_t kReserveShare = 16;

  Settings local_;
  Host host_;
  HpackDecoder hpack_;
  std::string out_;
  std::string in_;  // a frame split across reads, or input kept while paused
  size_t inOff_ = 0;  // how much of in_ has been consumed
  size_t prefaceSeen_ = 0;
  // A DATA frame whose payload is being taken as it arrives (dataBegin):
  // the payload bytes still to come, the frame's length and END_STREAM
  // flag, and its stream (0 when the payload is only read past).
  uint32_t dataLeft_ = 0;
  uint32_t dataLen_ = 0;
  uint32_t dataStream_ = 0;
  bool dataEnd_ = false;
  bool settingsSeen_ = false;
  bool dead_ = false;
  bool paused_ = false;
  bool stop_ = false;  // dead_ || paused_: the one flag the frame loop reads
  bool goawaySent_ = false;

  // The peer's settings.
  uint32_t peerMaxFrame_ = kMinFrameSize;
  uint32_t peerInitialWindow_ = kDefaultWindow;

  int64_t connSendWindow_ = kDefaultWindow;
  int64_t connGranted_ = kDefaultWindow;  // the window the peer has given in all: less connSendWindow_, the DATA bytes sent
  uint64_t windowUpdates_ = 0;            // WINDOW_UPDATE frames taken free of charge
  bool connStarved_ = false;              // a stream is waiting for the connection's window
  int64_t connRecvWindow_ = kDefaultWindow;
  uint32_t connRecvUnacked_ = 0;
  size_t buffered_ = 0;  // request body bytes held for requests not yet dispatched
  size_t reserved_ = 0;  // ...and the capacity set aside for them (roomFor)
  std::string cookie_;   // the cookie fields of the header block being decoded, joined
  uint64_t heldSent_ = 0;  // see heldSent()

  FlatMap<Stream*> streams_;
  std::vector<Stream*> free_;
  std::vector<uint32_t> blocked_;
  std::vector<uint32_t> flushing_;  // flushBlocked's working copy
  uint32_t lastStreamId_ = 0;
  size_t held_ = 0;

  // A header block spread over CONTINUATION frames.
  uint32_t contStream_ = 0;
  uint32_t contFrames_ = 0;
  bool contEndStream_ = false;
  enum : uint8_t { kOddSelfDependent = 1, kOddCookies = 2 };
  uint8_t blockOdd_ = 0;  // what the header block being taken in has that few have (headerBlock)
  std::string hbuf_;

  uint32_t recentReset_[kRecentResets] = {};
  size_t recentAt_ = 0;

  uint64_t now_ = 0;
  uint64_t calmAt_ = 0;
  uint32_t calm_ = 0;
};

}  // namespace h2
}  // namespace engine
}  // namespace moro
