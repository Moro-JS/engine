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
// as the Host header when the request carried none), so an application
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
  static bool decode(const uint8_t* p, size_t n, std::string& out) {
    const HuffmanDecoder& d = instance();
    out.clear();
    out.reserve(n + n / 2 + 8);
    uint16_t state = 0;
    for (size_t i = 0; i < n; i++) {
      const Step& hi = d.step_[state][p[i] >> 4];
      if (hi.flags & kFail) return false;
      if (hi.flags & kEmit) out.push_back(static_cast<char>(hi.symbol));
      const Step& lo = d.step_[hi.next][p[i] & 0x0f];
      if (lo.flags & kFail) return false;
      if (lo.flags & kEmit) out.push_back(static_cast<char>(lo.symbol));
      state = lo.next;
    }
    return d.accept_[state];
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
    value += static_cast<uint32_t>(b & 0x7f) << shift;
    if (value > (1u << 30)) return false;
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
  struct Known {
    std::string_view name;
    uint32_t index;
  };
  static constexpr Known kKnown[] = {
      {"age", 21},
      {"etag", 34},
      {"date", 33},
      {"link", 45},
      {"vary", 59},
      {"allow", 22},
      {"server", 54},
      {"expires", 36},
      {"location", 46},
      {"set-cookie", 55},
      {"retry-after", 53},
      {"content-type", 31},
      {"accept-ranges", 18},
      {"cache-control", 24},
      {"content-range", 30},
      {"last-modified", 44},
      {"content-length", 28},
      {"content-encoding", 26},
      {"content-language", 27},
      {"content-location", 29},
      {"www-authenticate", 61},
      {"content-disposition", 25},
      {"strict-transport-security", 56},
      {"access-control-allow-origin", 20},
  };
  for (const Known& k : kKnown) {
    if (k.name.size() == name.size() && memcmp(k.name.data(), name.data(), name.size()) == 0)
      return k.index;
  }
  return 0;
}

// One header field as a literal that is not indexed (RFC 7541 6.2.2), or one
// that must never be (6.2.3) when `sensitive`: a credential an intermediary
// re-encoding the block must not put in a table either.
inline void encodeField(std::string& out, std::string_view lowerName, std::string_view value,
                        bool sensitive = false) {
  const uint8_t kind = sensitive ? 0x10 : 0x00;
  const uint32_t index = staticNameIndex(lowerName);
  if (index != 0) {
    encodeInt(out, 4, kind, index);
  } else {
    out.push_back(static_cast<char>(kind));
    encodeInt(out, 7, 0, static_cast<uint32_t>(lowerName.size()));
    out.append(lowerName);
  }
  encodeInt(out, 7, 0, static_cast<uint32_t>(value.size()));
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
  std::vector<Header> headers;
  size_t headerCount = 0;
  std::string body;
  bool expectContinue = false;

  // Response bytes flow control is holding back.
  std::string pending;
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

  // Bytes from the peer. `nowMs` is any monotonic clock; it paces the budget
  // for frames that cost the server work and the peer nothing.
  void feed(const char* data, size_t len, uint64_t nowMs) {
    if (dead_) return;
    now_ = nowMs;
    const uint8_t* p;
    size_t n;
    const bool buffered = !in_.empty();
    if (buffered) {
      in_.append(data, len);
      p = reinterpret_cast<const uint8_t*>(in_.data());
      n = in_.size();
    } else {
      p = reinterpret_cast<const uint8_t*>(data);
      n = len;
    }
    size_t pos = 0;
    if (prefaceSeen_ < kPreface.size()) {
      const size_t take = std::min(n, kPreface.size() - prefaceSeen_);
      if (memcmp(p, kPreface.data() + prefaceSeen_, take) != 0) {
        connectionError(kProtocolError);
        return;
      }
      prefaceSeen_ += take;
      pos = take;
    }
    while (!dead_ && n - pos >= 9) {
      const uint32_t length = (static_cast<uint32_t>(p[pos]) << 16) |
                              (static_cast<uint32_t>(p[pos + 1]) << 8) | p[pos + 2];
      if (length > local_.maxFrameSize) {
        connectionError(kFrameSizeError);
        return;
      }
      if (n - pos < 9 + static_cast<size_t>(length)) break;
      const uint8_t type = p[pos + 3];
      const uint8_t flags = p[pos + 4];
      const uint32_t streamId = readU32(p + pos + 5) & 0x7fffffffu;
      frame(type, flags, streamId, p + pos + 9, length);
      pos += 9 + length;
    }
    if (dead_) {
      in_.clear();
      return;
    }
    if (buffered) {
      in_.erase(0, pos);
    } else if (pos < n) {
      in_.assign(reinterpret_cast<const char*>(p) + pos, n - pos);
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
      return st.pending.size();
    }
    bool finished = false;
    const size_t sent = writeData(st, data, len, endStream, finished);
    if (finished) return 0;  // everything went, END_STREAM with it: the stream is gone
    if (sent < len || endStream) {
      st.pending.assign(data + sent, len - sent);
      st.pendingEnd = endStream;
      if (!st.blocked) {
        st.blocked = true;
        blocked_.push_back(st.id);
      }
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
  void abandon() { dead_ = true; }

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

  void frame(uint8_t type, uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    // A header block in progress admits nothing but its CONTINUATION frames
    // (RFC 9113 6.10).
    if (contStream_ != 0 && (type != kContinuation || id != contStream_)) {
      connectionError(kProtocolError);
      return;
    }
    if (!settingsSeen_ && type != kSettings) {  // the preface ends with SETTINGS (3.4)
      connectionError(kProtocolError);
      return;
    }
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
    for (uint32_t i = 0; i + 6 <= len; i += 6) {
      const uint16_t key = static_cast<uint16_t>((p[i] << 8) | p[i + 1]);
      const uint32_t value = readU32(p + i + 2);
      switch (key) {
        case kSettingEnablePush:
          if (value > 1) return connectionError(kProtocolError);
          break;
        case kSettingInitialWindowSize: {
          if (value > kMaxWindow) return connectionError(kFlowControlError);
          const int64_t delta = static_cast<int64_t>(value) - static_cast<int64_t>(peerInitialWindow_);
          peerInitialWindow_ = value;
          bool overflow = false;
          streams_.forEach([&](uint32_t, Stream* st) {
            st->sendWindow += delta;
            if (st->sendWindow > static_cast<int64_t>(kMaxWindow)) overflow = true;
          });
          if (overflow) return connectionError(kFlowControlError);
          break;
        }
        case kSettingMaxFrameSize:
          if (value < kMinFrameSize || value > kMaxFrameSizeLimit)
            return connectionError(kProtocolError);
          peerMaxFrame_ = value;
          break;
        default:
          break;  // header table size (our encoder uses none), the advisory ones, unknown ones
      }
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
    if (id == 0) {
      if (inc == 0) return connectionError(kProtocolError);
      connSendWindow_ += inc;
      if (connSendWindow_ > static_cast<int64_t>(kMaxWindow))
        return connectionError(kFlowControlError);
      flushBlocked();
      return;
    }
    if (isIdle(id)) return connectionError(kProtocolError);
    Stream* st = find(id);
    if (!st) return;  // closed: a late update is expected and harmless (5.1)
    if (inc == 0) return streamError(id, kProtocolError);
    st->sendWindow += inc;
    if (st->sendWindow > static_cast<int64_t>(kMaxWindow)) return streamError(id, kFlowControlError);
    if (st->blocked && flushStream(*st) && !st->blocked) unblock(id);
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
        selfDependent_ = true;
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
    const bool selfDependent = selfDependent_;
    selfDependent_ = false;
    if (n > maxHeaderBlock()) return connectionError(kEnhanceYourCalm);

    Stream* st = find(id);
    if (st != nullptr) {  // a second block on an open stream: trailers
      bool pseudo = false;
      if (!hpack_.decode(p, n, [&](std::string_view name, std::string_view) {
            if (!name.empty() && name[0] == ':') pseudo = true;
          }))
        return connectionError(kCompressionError);
      if (st->remoteClosed) return streamError(id, kStreamClosed);
      if (!endStream || pseudo) return streamError(id, kProtocolError);  // 8.1
      return endOfRequest(*st);
    }

    if (id <= lastStreamId_) {
      // Closed. One we reset may still have frames in flight, which are
      // ignored; anything else is a peer that lost track (5.1).
      if (!hpack_.decode(p, n, [](std::string_view, std::string_view) {}))
        return connectionError(kCompressionError);
      if (!recentlyReset(id)) connectionError(kStreamClosed);
      return;
    }
    lastStreamId_ = id;

    if (goawaySent_ || streams_.size() >= local_.maxConcurrentStreams) {
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
    if (selfDependent) return streamError(id, kProtocolError);

    // A request is malformed without exactly one :method, :scheme and :path
    // (8.3.1); CONNECT, which has neither of the last two, is not served.
    if (rq.malformed || !rq.method || !rq.scheme || !rq.path || st->path.empty())
      return streamError(id, kProtocolError);
    if (rq.tooLarge) return refuse(*st, 431, endStream);
    if (local_.maxUriSize && st->path.size() + st->query.size() + 1 > local_.maxUriSize)
      return refuse(*st, 414, endStream);
    if (rq.contentLength >= 0 && static_cast<uint64_t>(rq.contentLength) > local_.maxBodySize)
      return refuse(*st, 413, endStream);
    st->declared = rq.contentLength;
    if (!rq.sawHost && !rq.authority.empty()) addHeader(*st, "host", rq.authority);
    st->headers.resize(st->headerCount);

    if (endStream) return endOfRequest(*st);
    if (st->expectContinue) {  // the client is waiting to be told to send the body
      std::string block;
      encodeStatus(block, 100);
      appendFrameHeader(out_, block.size(), kHeaders, kFlagEndHeaders, id);
      out_.append(block);
    }
    if (rq.contentLength > 0) st->body.reserve(static_cast<size_t>(rq.contentLength));
  }

  struct Request {
    Stream* st = nullptr;
    bool method = false, scheme = false, path = false;
    bool regular = false;   // a regular field has been seen: no pseudo-header may follow
    bool malformed = false;
    bool tooLarge = false;
    bool sawHost = false;
    size_t listSize = 0;
    long long contentLength = -1;
    std::string authority;
  };

  static void addHeader(Stream& st, std::string_view name, std::string_view value) {
    if (st.headerCount < st.headers.size()) {
      Header& h = st.headers[st.headerCount];
      h.name.assign(name);
      h.value.assign(value);
    } else {
      st.headers.push_back(Header{std::string(name), std::string(value)});
    }
    st.headerCount++;
  }

  // One decoded field of a request head (RFC 9113 8.2, 8.3).
  void requestField(Request& rq, std::string_view name, std::string_view value) {
    Stream& st = *rq.st;
    rq.listSize += name.size() + value.size() + 32;
    if (rq.listSize > local_.maxHeaderListSize) rq.tooLarge = true;
    if (rq.malformed || rq.tooLarge) return;  // still decoded, no longer kept
    if (name.empty()) {
      rq.malformed = true;
      return;
    }
    // Field values carry no NUL, CR or LF, and no surrounding whitespace
    // (8.2.1): what would split a line once this is forwarded as HTTP/1.
    for (const char ch : value) {
      if (ch == '\0' || ch == '\r' || ch == '\n') {
        rq.malformed = true;
        return;
      }
    }
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.back() == ' ' ||
                           value.back() == '\t')) {
      rq.malformed = true;
      return;
    }
    if (name[0] == ':') {
      if (rq.regular) {
        rq.malformed = true;
        return;
      }
      if (name == ":method") {
        if (rq.method || value.empty()) {
          rq.malformed = true;
          return;
        }
        for (const char ch : value) {
          if (!isTokenChar(static_cast<unsigned char>(ch))) {
            rq.malformed = true;
            return;
          }
        }
        rq.method = true;
        st.method = methodFrom(value);
        if (st.method == Method::OTHER) st.methodStr.assign(value);
        if (value == "CONNECT") rq.malformed = true;
      } else if (name == ":path") {
        if (rq.path) {
          rq.malformed = true;
          return;
        }
        rq.path = true;
        for (const char ch : value) {  // the request-target hygiene of the HTTP/1 parser
          const unsigned char u = static_cast<unsigned char>(ch);
          if (u <= 0x20 || u == 0x7f) {
            rq.malformed = true;
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
          rq.malformed = true;
          return;
        }
        rq.scheme = true;
      } else if (name == ":authority") {
        rq.authority.assign(value);
      } else {
        rq.malformed = true;  // a response pseudo-header, or one that does not exist
      }
      return;
    }
    rq.regular = true;
    // Names are lowercase tokens (8.2.1); an uppercase letter is a token
    // character, so it is checked for separately.
    for (const char ch : name) {
      const unsigned char u = static_cast<unsigned char>(ch);
      if (!isTokenChar(u) || (u >= 'A' && u <= 'Z')) {
        rq.malformed = true;
        return;
      }
    }
    if (isConnectionSpecific(name)) {
      rq.malformed = true;
      return;
    }
    switch (name.size()) {
      case 2:
        if (name == "te" && value != "trailers") {
          rq.malformed = true;
          return;
        }
        break;
      case 4:
        if (name == "host") rq.sawHost = true;
        break;
      case 6:
        if (name == "expect" && iequals(value, "100-continue")) st.expectContinue = true;
        break;
      case 14:
        if (name == "content-length") {
          long long v = 0;
          if (value.empty() || value.size() > 18) {
            rq.malformed = true;
            return;
          }
          for (const char ch : value) {
            if (ch < '0' || ch > '9') {
              rq.malformed = true;
              return;
            }
            v = v * 10 + (ch - '0');
          }
          if (rq.contentLength >= 0 && rq.contentLength != v) {
            rq.malformed = true;
            return;
          }
          rq.contentLength = v;
        }
        break;
      default:
        break;
    }
    if (st.headerCount >= local_.maxHeaders) {
      rq.tooLarge = true;
      return;
    }
    addHeader(st, name, value);
  }

  // ---- DATA ----

  void onData(uint8_t flags, uint32_t id, const uint8_t* p, uint32_t len) {
    if (id == 0) return connectionError(kProtocolError);
    if (isIdle(id)) return connectionError(kProtocolError);
    // The whole frame, padding included, counts against the connection's
    // window whatever happens to the stream (6.9.1).
    connRecvWindow_ -= len;
    if (connRecvWindow_ < 0) return connectionError(kFlowControlError);
    connRecvUnacked_ += len;

    size_t off = 0;
    size_t pad = 0;
    if (flags & kFlagPadded) {
      if (len < 1) return connectionError(kFrameSizeError);
      pad = p[0];
      off = 1;
      if (pad > len - off) return connectionError(kProtocolError);
    }
    const size_t n = len - off - pad;
    const bool endStream = (flags & kFlagEndStream) != 0;

    Stream* st = find(id);
    if (st == nullptr || st->remoteClosed) {
      // Closed, or half-closed from the peer's side (5.1). A stream we reset
      // ourselves may still have frames in flight; those are read past.
      creditConnection();
      if (st != nullptr) return streamError(id, kStreamClosed);
      if (!recentlyReset(id)) sendRst(id, kStreamClosed);
      return;
    }
    st->recvWindow -= len;
    if (st->recvWindow < 0) {
      creditConnection();
      return streamError(id, kFlowControlError);
    }
    if (n == 0 && !endStream && !calm(kCostControl)) return;  // a frame that carries nothing

    if (st->body.size() + n > local_.maxBodySize) {
      creditConnection();
      return refuse(*st, 413, endStream);
    }
    st->body.append(reinterpret_cast<const char*>(p + off), n);
    buffered_ += n;
    st->recvUnacked += len;
    creditStream(*st, endStream);
    creditConnection();
    if (endStream) endOfRequest(*st);
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
    if (buffered_ > maxBuffered()) return;
    appendFrameHeader(out_, 4, kWindowUpdate, 0, 0);
    appendU32(out_, connRecvUnacked_);
    connRecvWindow_ += connRecvUnacked_;
    connRecvUnacked_ = 0;
  }

  size_t maxBuffered() const {
    return std::max<size_t>(2 * local_.maxBodySize, static_cast<size_t>(local_.connectionWindow) * 4);
  }

  // END_STREAM on a request: check the declared length, hand it to the host.
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

  // Returns false when the stream finished (and is gone).
  bool flushStream(Stream& st) {
    bool finished = false;
    const size_t sent = writeData(st, st.pending.data(), st.pending.size(), st.pendingEnd, finished);
    if (finished) return false;
    st.pending.erase(0, sent);
    if (st.pending.empty() && !st.pendingEnd) st.blocked = false;
    if (st.wantDrain && st.user != nullptr && st.pending.size() < kDrainMark && host_.writable) {
      st.wantDrain = false;
      host_.writable(host_.user, st.user);
    }
    return true;
  }

  // Streams waiting on a window, in the order they began to wait.
  void flushBlocked() {
    if (blocked_.empty()) return;
    std::vector<uint32_t> ids;
    ids.swap(blocked_);
    for (const uint32_t id : ids) {
      if (dead_) return;
      Stream* st = find(id);
      if (st == nullptr || !st->blocked) continue;
      if (flushStream(*st) && st->blocked) blocked_.push_back(id);
    }
  }

  // Our END_STREAM is out. A request still arriving is no longer wanted
  // (8.1: the response may complete first); the stream is over either way.
  void localEnd(Stream& st) {
    st.localClosed = true;
    st.pending.clear();
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
    sendRst(id, code);
    Stream* st = find(id);
    if (st == nullptr) return;
    abortHeld(*st);
    drop(*st);
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
    dead_ = true;
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
    if (!st.dispatched) buffered_ -= std::min(buffered_, st.body.size());
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

  Settings local_;
  Host host_;
  HpackDecoder hpack_;
  std::string out_;
  std::string in_;  // a frame split across reads
  size_t prefaceSeen_ = 0;
  bool settingsSeen_ = false;
  bool dead_ = false;
  bool goawaySent_ = false;

  // The peer's settings.
  uint32_t peerMaxFrame_ = kMinFrameSize;
  uint32_t peerInitialWindow_ = kDefaultWindow;

  int64_t connSendWindow_ = kDefaultWindow;
  int64_t connRecvWindow_ = kDefaultWindow;
  uint32_t connRecvUnacked_ = 0;
  size_t buffered_ = 0;  // request body bytes held for requests not yet dispatched

  FlatMap<Stream*> streams_;
  std::vector<Stream*> free_;
  std::vector<uint32_t> blocked_;
  uint32_t lastStreamId_ = 0;
  size_t held_ = 0;

  // A header block spread over CONTINUATION frames.
  uint32_t contStream_ = 0;
  uint32_t contFrames_ = 0;
  bool contEndStream_ = false;
  bool selfDependent_ = false;
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
