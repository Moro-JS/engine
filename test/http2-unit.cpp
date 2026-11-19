// Unit tests for src/http2.h: HPACK and the HTTP/2 session, driven directly.
//
// HPACK decoding is checked against test/fixtures/hpack-vectors.txt: header
// blocks produced by an independent encoder (the `hpack` Python package) with
// the dynamic table in use, Huffman coding on and off, every byte value
// Huffman-coded alone and in runs, entries larger than the table, and table
// size changes mid-connection. The fixture is data, regenerated only when a
// case is added.
//
// The session tests feed frames built here and read the frames it writes:
// the preface, a request with and without a body, flow control in both
// directions, header blocks cut into CONTINUATION frames, every way a
// request can be malformed, the limits that stop a peer from making the
// server work for nothing, and that none of it depends on how the bytes were
// split across reads.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "../src/http2.h"

// The largest single allocation, and how many of 64 KiB or more, since the
// counters were last cleared (sessionDeclaredLength).
static size_t gLargestAlloc = 0;
static size_t gLargeAllocs = 0;
static size_t gLiveBytes = 0;  // allocated and not freed (sessionReservedBodies)
void* operator new(size_t n) {
  if (n > gLargestAlloc) gLargestAlloc = n;
  if (n >= 65536) ++gLargeAllocs;
  // The size is kept in front of the block, so that a free can be counted.
  size_t* p = static_cast<size_t*>(std::malloc(n + 16));
  if (p == nullptr) std::abort();
  p[0] = n;
  gLiveBytes += n;
  return p + 2;
}
void operator delete(void* p) noexcept {
  if (p == nullptr) return;
  size_t* q = static_cast<size_t*>(p) - 2;
  gLiveBytes -= q[0];
  std::free(q);
}
void operator delete(void* p, size_t) noexcept { operator delete(p); }

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

using namespace moro::engine;
using namespace moro::engine::h2;

using Fields = std::vector<std::pair<std::string, std::string>>;

static std::string unhex(const std::string& h) {
  if (h == "-") return std::string();
  std::string out;
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    out.push_back(static_cast<char>(std::strtol(h.substr(i, 2).c_str(), nullptr, 16)));
  return out;
}

// ---------------------------------------------------------------------------
// HPACK
// ---------------------------------------------------------------------------

static void hpackVectors(const char* path) {
  std::ifstream in(path);
  if (!in) {
    std::fprintf(stderr, "cannot open %s\n", path);
    ++failures;
    return;
  }
  HpackDecoder* dec = nullptr;
  std::string line, block;
  Fields expected;
  size_t blocks = 0;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    if (line[0] == 'N') {
      delete dec;
      dec = new HpackDecoder();
      dec->setMaxTableSize(static_cast<uint32_t>(std::atoi(line.c_str() + 2)));
    } else if (line[0] == 'B') {
      const size_t sp = line.find(' ', 2);
      block = unhex(line.substr(sp + 1));
      expected.clear();
    } else if (line[0] == 'H') {
      const size_t sp = line.find(' ', 2);
      expected.emplace_back(unhex(line.substr(2, sp - 2)), unhex(line.substr(sp + 1)));
    } else if (line[0] == 'E') {
      Fields got;
      const bool ok = dec->decode(reinterpret_cast<const uint8_t*>(block.data()), block.size(),
                                  [&](std::string_view n, std::string_view v) {
                                    got.emplace_back(std::string(n), std::string(v));
                                  });
      ++blocks;
      if (!ok || got != expected) {
        ++failures;
        std::fprintf(stderr, "FAIL hpack vector %zu (ok=%d, %zu fields, expected %zu)\n", blocks,
                     static_cast<int>(ok), got.size(), expected.size());
        if (failures > 5) break;
      }
      ++checks;
    }
  }
  delete dec;
  CHECK(blocks > 600);
}

static bool decodeAll(HpackDecoder& d, const std::string& block, Fields& out) {
  return d.decode(reinterpret_cast<const uint8_t*>(block.data()), block.size(),
                  [&](std::string_view n, std::string_view v) {
                    out.emplace_back(std::string(n), std::string(v));
                  });
}

static void hpackUnits() {
  // Integers (RFC 7541 C.1).
  {
    std::string s;
    encodeInt(s, 5, 0, 10);
    CHECK(s == std::string("\x0a", 1));
    s.clear();
    encodeInt(s, 5, 0, 1337);
    CHECK(s == std::string("\x1f\x9a\x0a", 3));
    s.clear();
    encodeInt(s, 8, 0, 42);
    CHECK(s == std::string("\x2a", 1));
    for (uint32_t v : {0u, 1u, 30u, 31u, 32u, 127u, 128u, 255u, 16383u, 16384u, 1u << 20, 1u << 30}) {
      for (int prefix = 1; prefix <= 8; prefix++) {
        std::string e;
        encodeInt(e, prefix, 0, v);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(e.data());
        uint32_t back = 0;
        CHECK(decodeInt(p, p + e.size(), prefix, back) && back == v);
        CHECK(p == reinterpret_cast<const uint8_t*>(e.data()) + e.size());
      }
    }
    // Never-ending and oversized integers are refused.
    const uint8_t endless[] = {0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t* p = endless;
    uint32_t v = 0;
    CHECK(!decodeInt(p, endless + sizeof(endless), 5, v));
    const uint8_t cut[] = {0x1f, 0x80};
    p = cut;
    CHECK(!decodeInt(p, cut + sizeof(cut), 5, v));
    p = cut;
    CHECK(!decodeInt(p, cut, 5, v));  // empty input
  }

  // The encoder's output is what the decoder reads back.
  {
    std::string block;
    encodeStatus(block, 200);
    encodeStatus(block, 404);
    encodeStatus(block, 201);
    encodeStatus(block, 503);
    encodeField(block, "content-type", "application/json");
    encodeField(block, "content-length", "1234");
    encodeField(block, "x-custom-header", "some value");
    encodeField(block, "set-cookie", "sid=secret", /*sensitive=*/true);
    encodeField(block, "x-empty", "");
    encodeField(block, "x-long", std::string(300, 'q'));
    HpackDecoder d;
    Fields got;
    CHECK(decodeAll(d, block, got));
    const Fields want = {{":status", "200"},
                         {":status", "404"},
                         {":status", "201"},
                         {":status", "503"},
                         {"content-type", "application/json"},
                         {"content-length", "1234"},
                         {"x-custom-header", "some value"},
                         {"set-cookie", "sid=secret"},
                         {"x-empty", ""},
                         {"x-long", std::string(300, 'q')}};
    CHECK(got == want);
    CHECK(d.tableEntries() == 0);  // nothing the encoder writes is indexed
  }

  // Every name the encoder indexes is the static table's name at that index.
  for (uint32_t i = 1; i <= kStaticCount; i++) {
    const uint32_t idx = staticNameIndex(kStaticTable[i].name);
    if (idx != 0) CHECK(kStaticTable[idx].name == kStaticTable[i].name);
  }
  CHECK(staticNameIndex("content-type") == 31);
  CHECK(staticNameIndex("x-nope") == 0);

  // Huffman: EOS in the data, and padding that is not the top of EOS.
  {
    std::string out;
    const uint8_t eos[] = {0xff, 0xff, 0xff, 0xff};  // 30 one-bits is EOS, then 2 more
    CHECK(!HuffmanDecoder::decode(eos, sizeof(eos), out));
    const uint8_t zeroPad[] = {0x00};  // '0' (00000) then three 0-bits of padding
    CHECK(!HuffmanDecoder::decode(zeroPad, 1, out));
    const uint8_t goodPad[] = {0x07};  // '0' then three 1-bits
    CHECK(HuffmanDecoder::decode(goodPad, 1, out) && out == "0");
    const uint8_t longPad[] = {0x07, 0xff};  // a whole byte of padding more
    CHECK(!HuffmanDecoder::decode(longPad, 2, out));
    CHECK(HuffmanDecoder::decode(nullptr, 0, out) && out.empty());
    // "www.example.com" (RFC 7541 C.4.1)
    const uint8_t www[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    CHECK(HuffmanDecoder::decode(www, sizeof(www), out) && out == "www.example.com");
  }

  // The table-driven decoder against the code read one bit at a time: every
  // byte value in strings of every short length, and arbitrary bytes, where
  // both must agree on whether the input decodes and on what to.
  {
    auto refDecode = [](const uint8_t* p, size_t n, std::string& out) {
      out.clear();
      uint32_t acc = 0;
      int len = 0;
      for (size_t i = 0; i < n; i++) {
        for (int b = 7; b >= 0; b--) {
          acc = (acc << 1) | ((p[i] >> b) & 1u);
          len++;
          for (int sym = 0; sym <= 256; sym++) {
            if (kHuffman[sym].bits == len && kHuffman[sym].code == acc) {
              if (sym == 256) return false;
              out.push_back(static_cast<char>(sym));
              acc = 0;
              len = 0;
              break;
            }
          }
        }
      }
      return len < 8 && acc == (1u << len) - 1;
    };
    auto encode = [](const std::string& text) {
      std::string bytes;
      uint64_t acc = 0;
      int have = 0;
      for (const char ch : text) {
        const auto& code = kHuffman[static_cast<uint8_t>(ch)];
        acc = (acc << code.bits) | code.code;
        have += code.bits;
        while (have >= 8) {
          bytes.push_back(static_cast<char>((acc >> (have - 8)) & 0xff));
          have -= 8;
        }
      }
      if (have > 0) bytes.push_back(static_cast<char>(((acc << (8 - have)) | ((1u << (8 - have)) - 1)) & 0xff));
      return bytes;
    };
    uint32_t seed = 0x2545F491u;
    auto next = [&seed]() {
      seed = seed * 1664525u + 1013904223u;
      return static_cast<uint8_t>(seed >> 24);
    };
    std::string out, ref;
    for (int iter = 0; iter < 6000; iter++) {
      std::string text(next() % 48, '\0');
      for (char& ch : text) ch = static_cast<char>(iter % 3 == 0 ? next() : 0x20 + next() % 0x5f);
      const std::string bytes = encode(text);
      const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes.data());
      CHECK(HuffmanDecoder::decode(p, bytes.size(), out) && out == text);
      CHECK(refDecode(p, bytes.size(), ref) && ref == text);
    }
    for (int iter = 0; iter < 20000; iter++) {
      std::string bytes(next() % 24, '\0');
      for (char& ch : bytes) ch = static_cast<char>(iter % 4 == 0 ? next() | 0xf0 : next());
      const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes.data());
      const bool ok = HuffmanDecoder::decode(p, bytes.size(), out);
      const bool refOk = refDecode(p, bytes.size(), ref);
      CHECK(ok == refOk);
      if (ok && refOk) CHECK(out == ref);
    }
  }

  // A name one byte away from an indexed one, or one byte longer, is not it.
  for (uint32_t i = 1; i <= kStaticCount; i++) {
    const std::string name(kStaticTable[i].name);
    if (staticNameIndex(name) == 0) continue;
    CHECK(staticNameIndex(name + "x") == 0);
    CHECK(staticNameIndex(name.substr(1)) == 0);
    for (size_t at = 0; at < name.size(); at++) {
      std::string other = name;
      other[at] = other[at] == 'q' ? 'z' : 'q';
      CHECK(staticNameIndex(other) == 0);
    }
  }

  // Decoder errors: index 0, an index past the tables, a string longer than
  // the block, a size update after a field or above the setting.
  {
    auto bad = [](std::initializer_list<uint8_t> bytes, uint32_t settingsMax = 4096) {
      HpackDecoder d;
      d.setMaxTableSize(settingsMax);
      std::string block(bytes.begin(), bytes.end());
      Fields got;
      return !decodeAll(d, block, got);
    };
    CHECK(bad({0x80}));                    // indexed, index 0
    CHECK(bad({0xbe}));                    // index 62 with an empty dynamic table
    CHECK(bad({0x00, 0x05, 'a', 'b'}));    // name longer than what is left
    CHECK(bad({0x00, 0x01, 'a', 0x09, 'x'}));  // value likewise
    CHECK(bad({0x82, 0x20}));              // size update after a field
    CHECK(!bad({0x3f, 0xe1, 0x1f}));       // size update to 4096: what the setting allows
    CHECK(bad({0x3f, 0xe1, 0x1f}, 100));   // ...and more than a smaller setting does
    CHECK(bad({0x40}));                    // literal cut off after its first byte
    CHECK(!bad({0x82, 0x86, 0x84}));       // three static entries
  }

  // The dynamic table: newest first, evicted oldest first, sized by the rule.
  {
    HpackDecoder d;
    d.setMaxTableSize(4096);
    Fields got;
    // literal with indexing, new name "a" value "b": 0x40 01 'a' 01 'b'
    CHECK(decodeAll(d, std::string("\x40\x01" "a" "\x01" "b", 5), got));
    CHECK(d.tableEntries() == 1 && d.tableSize() == 34);
    CHECK(decodeAll(d, std::string("\xbe", 1), got));  // index 62 is that entry
    CHECK(got.size() == 2 && got[1] == std::make_pair(std::string("a"), std::string("b")));
    // Size update to 0 empties it; index 62 is then an error.
    CHECK(decodeAll(d, std::string("\x20", 1), got));
    CHECK(d.tableEntries() == 0 && d.tableSize() == 0);
    Fields none;
    CHECK(!decodeAll(d, std::string("\xbe", 1), none));
  }
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

struct Frame {
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
  std::string payload;
};

static std::vector<Frame> parseFrames(const std::string& bytes) {
  std::vector<Frame> out;
  size_t pos = 0;
  while (bytes.size() - pos >= 9) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes.data()) + pos;
    const size_t len = (static_cast<size_t>(p[0]) << 16) | (static_cast<size_t>(p[1]) << 8) | p[2];
    if (bytes.size() - pos < 9 + len) break;
    out.push_back(Frame{p[3], p[4], readU32(p + 5) & 0x7fffffffu, bytes.substr(pos + 9, len)});
    pos += 9 + len;
  }
  return out;
}

static std::string frame(uint8_t type, uint8_t flags, uint32_t stream, const std::string& payload) {
  std::string out;
  appendFrameHeader(out, payload.size(), type, flags, stream);
  out += payload;
  return out;
}

static std::string u32(uint32_t v) {
  std::string s;
  appendU32(s, v);
  return s;
}

// A request head as literals without indexing (the session's own encoder).
static std::string head(const Fields& fields) {
  std::string block;
  for (const auto& f : fields) {
    block.push_back(0x00);
    encodeInt(block, 7, 0, static_cast<uint32_t>(f.first.size()));
    block += f.first;
    encodeInt(block, 7, 0, static_cast<uint32_t>(f.second.size()));
    block += f.second;
  }
  return block;
}

static Fields get(const std::string& path = "/") {
  return {{":method", "GET"}, {":scheme", "https"}, {":path", path}, {":authority", "example.test"}};
}

struct Seen {
  uint32_t id;
  Method method;
  std::string methodStr, path, query, body;
  Fields headers;
};

struct Harness {
  Settings settings;
  Session* session = nullptr;
  std::vector<Seen> requests;
  std::vector<void*> aborted;
  std::vector<void*> writable;
  // When set, a dispatched stream is kept (hold) with this tag + its id.
  bool hold = false;
  std::vector<Stream*> heldStreams;
  // When not zero, the host pauses the session at every request once this
  // many have been dispatched (as a server whose answers are not being read).
  size_t pauseFrom = 0;
  // When set, the host ends the response from inside writable(), as a
  // handler does that is told in place.
  bool endOnWritable = false;

  explicit Harness(Settings s = Settings()) : settings(s) {
    Host host;
    host.user = this;
    host.dispatch = [](void* u, Stream& st) {
      Harness* h = static_cast<Harness*>(u);
      Seen seen{st.id, st.method, st.methodStr, st.path, st.query, st.body, {}};
      for (const Header& hd : st.headers) seen.headers.emplace_back(hd.name, hd.value);
      h->requests.push_back(std::move(seen));
      if (h->hold) {
        h->session->hold(st, &st);
        h->heldStreams.push_back(&st);
      }
      if (h->pauseFrom != 0 && h->requests.size() >= h->pauseFrom) h->session->pause();
    };
    host.aborted = [](void* u, void* held) { static_cast<Harness*>(u)->aborted.push_back(held); };
    host.writable = [](void* u, void* held) {
      Harness* h = static_cast<Harness*>(u);
      h->writable.push_back(held);
      if (h->endOnWritable) {
        Stream& st = *static_cast<Stream*>(held);
        h->session->release(st);
        h->session->sendData(st, "tail", 4, true);
      }
    };
    session = new Session(settings, host);
    session->start();
  }
  ~Harness() { delete session; }

  // Feed bytes; return the frames written since the last call.
  std::vector<Frame> feed(const std::string& bytes, uint64_t now = 1000) {
    session->feed(bytes.data(), bytes.size(), now);
    return take();
  }
  std::vector<Frame> take() {
    std::vector<Frame> f = parseFrames(session->out());
    session->out().clear();
    return f;
  }
  // The client preface and an empty SETTINGS; discards the server's side.
  void open() {
    feed(std::string(kPreface) + frame(kSettings, 0, 0, ""));
  }
  // Answer a held request with a status and nothing else.
  void answer(Stream& st, int status = 200) {
    std::string block;
    encodeStatus(block, status);
    session->release(st);
    session->sendHeaders(st, block, true);
  }
};

static bool has(const std::vector<Frame>& frames, uint8_t type, uint32_t stream = 0xffffffff) {
  for (const Frame& f : frames)
    if (f.type == type && (stream == 0xffffffff || f.stream == stream)) return true;
  return false;
}

static uint32_t goawayCode(const std::vector<Frame>& frames) {
  for (const Frame& f : frames)
    if (f.type == kGoaway && f.payload.size() >= 8)
      return readU32(reinterpret_cast<const uint8_t*>(f.payload.data()) + 4);
  return 0xffffffff;
}

static uint32_t rstCode(const std::vector<Frame>& frames, uint32_t stream) {
  for (const Frame& f : frames)
    if (f.type == kRstStream && f.stream == stream && f.payload.size() == 4)
      return readU32(reinterpret_cast<const uint8_t*>(f.payload.data()));
  return 0xffffffff;
}

// The status of the response the session wrote on `stream` ("" when none).
static std::string statusOn(const std::vector<Frame>& out, uint32_t stream) {
  for (const Frame& f : out) {
    if (f.type != kHeaders || f.stream != stream) continue;
    HpackDecoder d;
    Fields got;
    if (d.decode(reinterpret_cast<const uint8_t*>(f.payload.data()), f.payload.size(),
                 [&](std::string_view n, std::string_view v) { got.emplace_back(std::string(n), std::string(v)); }) &&
        !got.empty())
      return got[0].second;
  }
  return std::string();
}

static std::string times(const std::string& one, int n) {
  std::string out;
  out.reserve(one.size() * static_cast<size_t>(n));
  for (int i = 0; i < n; i++) out += one;
  return out;
}

static void sessionBasics() {
  // The server preface: SETTINGS first, then the connection window update;
  // the client's SETTINGS is acknowledged.
  {
    Harness h;
    std::vector<Frame> first = h.take();
    CHECK(first.size() == 2);
    CHECK(first[0].type == kSettings && first[0].flags == 0 && first[0].stream == 0);
    CHECK(first[0].payload.size() % 6 == 0);
    CHECK(first[1].type == kWindowUpdate && first[1].stream == 0);
    std::vector<Frame> ack = h.feed(std::string(kPreface) + frame(kSettings, 0, 0, ""));
    CHECK(ack.size() == 1 && ack[0].type == kSettings && ack[0].flags == kFlagAck);
    CHECK(!h.session->dead());
  }

  // Not HTTP/2, or HTTP/2 that does not open with SETTINGS.
  {
    Harness h;
    h.take();
    h.feed("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(h.session->dead());
    Harness h2;
    h2.take();
    std::vector<Frame> f = h2.feed(std::string(kPreface) + frame(kPing, 0, 0, std::string(8, 'p')));
    CHECK(h2.session->dead() && goawayCode(f) == kProtocolError);
  }

  // A GET: what the host sees, and the answer.
  {
    Harness h;
    h.open();
    Fields f = get("/hello/world?a=1&b=two");
    f.emplace_back("accept", "*/*");
    f.emplace_back("cookie", "a=1");
    f.emplace_back("cookie", "b=2");
    h.hold = true;
    std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(f)));
    CHECK(out.empty());
    CHECK(h.requests.size() == 1);
    const Seen& r = h.requests[0];
    CHECK(r.id == 1 && r.method == Method::GET && r.path == "/hello/world" && r.query == "a=1&b=two");
    const Fields want = {{"accept", "*/*"}, {"cookie", "a=1; b=2"}, {"host", "example.test"}};
    CHECK(r.headers == want);
    CHECK(h.session->held() == 1 && h.session->streamCount() == 1);

    Stream& st = *h.heldStreams[0];
    std::string block;
    encodeStatus(block, 200);
    encodeField(block, "content-type", "text/plain");
    h.session->sendHeaders(st, block, false);
    h.session->release(st);
    CHECK(h.session->sendData(st, "hello", 5, true) == 0);
    out = h.take();
    CHECK(out.size() == 2);
    CHECK(out[0].type == kHeaders && out[0].flags == kFlagEndHeaders && out[0].stream == 1);
    CHECK(out[1].type == kData && out[1].flags == kFlagEndStream && out[1].payload == "hello");
    CHECK(h.session->held() == 0 && h.session->streamCount() == 0);
    CHECK(!has(out, kRstStream));  // the request was complete: nothing to cancel
  }

  // A POST with a body in two DATA frames; :authority wins over the host
  // header the client sent (RFC 9113 8.3.1), which keeps its place in the
  // list; an unknown method keeps its name.
  {
    Harness h;
    h.open();
    Fields f = {{":method", "POST"}, {":scheme", "http"}, {":path", "/upload"},
                {":authority", "real.test"}, {"host", "ignored"}, {"content-length", "11"}};
    h.feed(frame(kHeaders, kFlagEndHeaders, 1, head(f)));
    CHECK(h.requests.empty());
    h.feed(frame(kData, 0, 1, "hello "));
    CHECK(h.requests.empty());
    h.feed(frame(kData, kFlagEndStream, 1, "world"));
    CHECK(h.requests.size() == 1 && h.requests[0].body == "hello world");
    CHECK(h.requests[0].method == Method::POST);
    bool sawReal = false, sawIgnored = false;
    int hosts = 0;
    for (const auto& kv : h.requests[0].headers) {
      if (kv.first == "host" && kv.second == "real.test") sawReal = true;
      if (kv.first == "host") hosts++;
      if (kv.second == "ignored") sawIgnored = true;
    }
    CHECK(sawReal && !sawIgnored && hosts == 1);
    CHECK(h.requests[0].headers.size() == 2 && h.requests[0].headers[0].first == "host");

    Fields p = {{":method", "PROPFIND"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/dav"}};
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(p)));
    CHECK(h.requests.size() == 2 && h.requests[1].method == Method::OTHER &&
          h.requests[1].methodStr == "PROPFIND");
  }

  // Padding and the priority fields are skipped; trailers end the request.
  {
    Harness h;
    h.open();
    std::string block = head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/p"}});
    std::string payload;
    payload.push_back(4);          // pad length
    payload += u32(0);             // stream dependency
    payload.push_back(15);         // weight
    payload += block;
    payload += std::string(4, '\0');
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagPadded | kFlagPriority, 1, payload));
    std::string data;
    data.push_back(3);
    data += "abc";
    data += std::string(3, '\0');
    h.feed(frame(kData, kFlagPadded, 1, data));
    CHECK(h.requests.empty());
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head({{"x-trailer", "t"}})));
    CHECK(h.requests.size() == 1 && h.requests[0].body == "abc" && h.requests[0].path == "/p");
  }

  // Expect: 100-continue is answered before the body.
  {
    Harness h;
    h.open();
    std::vector<Frame> out = h.feed(frame(
        kHeaders, kFlagEndHeaders, 1,
        head({{":method", "PUT"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/x"}, {"expect", "100-continue"}})));
    CHECK(out.size() == 1 && out[0].type == kHeaders && out[0].flags == kFlagEndHeaders);
    HpackDecoder d;
    Fields got;
    CHECK(decodeAll(d, out[0].payload, got) && got.size() == 1 && got[0].second == "100");
  }
}

static void sessionFlowControl() {
  // A response larger than the peer's windows waits for them, and END_STREAM
  // goes with the last byte.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    Stream& st = *h.heldStreams[0];
    std::string block;
    encodeStatus(block, 200);
    h.session->sendHeaders(st, block, false);
    const std::string body(100000, 'x');
    const size_t left = h.session->sendData(st, body.data(), body.size(), true);
    CHECK(left == 100000 - 65535);
    std::vector<Frame> out = h.take();
    size_t sent = 0;
    for (const Frame& f : out)
      if (f.type == kData) {
        sent += f.payload.size();
        CHECK(f.payload.size() <= 16384 && f.flags == 0);
      }
    CHECK(sent == 65535);
    CHECK(h.session->streamCount() == 1);
    // The stream's window alone is not enough: the connection's is spent too.
    out = h.feed(frame(kWindowUpdate, 0, 1, u32(100000)));
    CHECK(out.empty());
    st.wantDrain = true;
    out = h.feed(frame(kWindowUpdate, 0, 0, u32(20000)));
    sent = 0;
    for (const Frame& f : out)
      if (f.type == kData) sent += f.payload.size();
    CHECK(sent == 20000);
    CHECK(h.writable.size() == 1 && h.writable[0] == &st);  // below the mark: the host may write on
    h.session->release(st);
    out = h.feed(frame(kWindowUpdate, 0, 0, u32(1 << 20)));
    sent = 0;
    bool end = false;
    for (const Frame& f : out)
      if (f.type == kData) {
        sent += f.payload.size();
        end = end || (f.flags & kFlagEndStream);
      }
    CHECK(sent == 100000 - 65535 - 20000 && end);
    CHECK(h.session->streamCount() == 0);
  }

  // A larger SETTINGS_INITIAL_WINDOW_SIZE opens streams that were waiting;
  // SETTINGS_MAX_FRAME_SIZE raises the frame size used.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kWindowUpdate, 0, 0, u32(1 << 20)));
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    Stream& st = *h.heldStreams[0];
    std::string block;
    encodeStatus(block, 200);
    h.session->sendHeaders(st, block, false);
    h.session->release(st);
    const std::string body(200000, 'y');
    CHECK(h.session->sendData(st, body.data(), body.size(), true) == 200000 - 65535);
    h.take();
    std::string settings;
    settings += std::string("\x00\x04", 2) + u32(1 << 20);
    settings += std::string("\x00\x05", 2) + u32(65536);
    std::vector<Frame> out = h.feed(frame(kSettings, 0, 0, settings));
    size_t sent = 0, largest = 0;
    for (const Frame& f : out)
      if (f.type == kData) {
        sent += f.payload.size();
        largest = std::max(largest, f.payload.size());
      }
    CHECK(sent == 200000 - 65535 && largest == 65536);
    CHECK(h.session->streamCount() == 0);
  }

  // SETTINGS_INITIAL_WINDOW_SIZE many times in one frame: the last value
  // stays, a value on the way that takes a window past 2^31-1 is still an
  // error, and the streams are not walked once per entry.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    Stream& st = *h.heldStreams[0];
    std::string block;
    encodeStatus(block, 200);
    h.session->sendHeaders(st, block, false);
    const std::string body(10000, 'z');
    CHECK(h.session->sendData(st, body.data(), body.size(), false) == 0);  // window 65535 - 10000
    h.take();
    std::string s;
    s += std::string("\x00\x04", 2) + u32(70000);
    s += std::string("\x00\x04", 2) + u32(0);
    s += std::string("\x00\x04", 2) + u32(10000);  // 10000 - 10000: nothing may be sent
    h.feed(frame(kSettings, 0, 0, s));
    CHECK(h.session->sendData(st, "a", 1, false) == 1);
    h.take();
    CHECK(!has(h.feed(frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(10001))), kGoaway));
    h.feed(frame(kWindowUpdate, 0, 1, u32(20000)));  // the stream's window: 20000, initial 10001
    s = std::string("\x00\x04", 2) + u32(kMaxWindow);  // past 2^31-1 on the way...
    s += std::string("\x00\x04", 2) + u32(100);        // ...and back
    CHECK(goawayCode(h.feed(frame(kSettings, 0, 0, s))) == kFlowControlError);

    auto timeSettings = [](int streams) {
      Settings big;
      big.maxFrameSize = 1 << 20;
      Harness t(big);
      t.open();
      std::string bytes;
      for (int i = 0; i < streams; i++)
        bytes += frame(kHeaders, kFlagEndHeaders, 1 + 2 * i,
                       head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}));
      t.feed(bytes);
      std::string payload;
      for (int i = 0; i < (1 << 20) / 6; i++)
        payload += std::string("\x00\x04", 2) + u32((i & 1) ? 65535 : 100000);
      bytes.clear();
      for (int i = 0; i < 20; i++) bytes += frame(kSettings, 0, 0, payload);
      const auto t0 = std::chrono::steady_clock::now();
      t.feed(bytes);
      const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                          std::chrono::steady_clock::now() - t0).count();
      CHECK(!t.session->dead() && t.session->streamCount() == static_cast<size_t>(streams));
      return static_cast<double>(us);
    };
    const double one = timeSettings(1);
    const double many = timeSettings(256);
    CHECK(many < one * 8 + 20000);  // walked once per entry, it is ~100 times more
  }

  // The request side: the peer is given its window back as it is used, and
  // exceeding a window is an error.
  {
    Settings s;
    s.initialWindowSize = 65535;
    s.connectionWindow = 65535;
    Harness h(s);
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/big"}})));
    std::vector<Frame> all;
    for (int i = 0; i < 10; i++) {
      std::vector<Frame> out = h.feed(frame(kData, 0, 1, std::string(16384, 'd')));
      all.insert(all.end(), out.begin(), out.end());
    }
    CHECK(!h.session->dead());
    CHECK(has(all, kWindowUpdate, 0) && has(all, kWindowUpdate, 1));
    h.feed(frame(kData, kFlagEndStream, 1, "end"));
    CHECK(h.requests.size() == 1 && h.requests[0].body.size() == 10 * 16384 + 3);

    // More than the window in one frame is an error on the stream; more
    // than the connection's, on the connection.
    Settings tiny;
    tiny.initialWindowSize = 10000;
    tiny.connectionWindow = 65535;
    Harness t(tiny);
    t.open();
    t.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/big"}})));
    std::vector<Frame> out = t.feed(frame(kData, 0, 1, std::string(16384, 'd')));
    CHECK(rstCode(out, 1) == kFlowControlError && !t.session->dead());

    Settings wide;
    wide.initialWindowSize = 1 << 20;
    wide.connectionWindow = 65535;
    Harness c(wide);
    c.open();
    std::string bytes;
    for (uint32_t id = 1; id <= 9; id += 2) {
      bytes += frame(kHeaders, kFlagEndHeaders, id,
                     head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/big"}}));
      bytes += frame(kData, 0, id, std::string(16384, 'd'));
    }
    c.feed(bytes);
    CHECK(!c.session->dead());  // credited as it is used: five frames never exceed the window
  }

  // A zero increment, and an increment past 2^31-1.
  {
    Harness h;
    h.open();
    CHECK(goawayCode(h.feed(frame(kWindowUpdate, 0, 0, u32(0)))) == kProtocolError);
    Harness h2;
    h2.open();
    CHECK(goawayCode(h2.feed(frame(kWindowUpdate, 0, 0, u32(0x7fffffff)))) == kFlowControlError);
    Harness h3;
    h3.open();
    h3.hold = true;
    h3.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    CHECK(rstCode(h3.feed(frame(kWindowUpdate, 0, 1, u32(0))), 1) == kProtocolError);
    CHECK(h3.aborted.size() == 1);  // the host held it and is told
  }
}

static void sessionErrors() {
  auto streamCode = [](const Fields& f, uint8_t flags = kFlagEndHeaders | kFlagEndStream) {
    Harness h;
    h.open();
    std::vector<Frame> out = h.feed(frame(kHeaders, flags, 1, head(f)));
    CHECK(h.requests.empty());
    CHECK(!h.session->dead());
    return rstCode(out, 1);
  };
  // Malformed requests (RFC 9113 8.2, 8.3): each is a stream error.
  CHECK(streamCode({{":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}) == kProtocolError);                       // no :method
  CHECK(streamCode({{":method", "GET"}, {":path", "/"}}) == kProtocolError);                        // no :scheme
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}}) == kProtocolError);                   // no :path
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", ""}}) == kProtocolError);    // empty :path
  CHECK(streamCode({{":method", "GET"}, {":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {":status", "200"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {":unknown", "x"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {"accept", "x"}, {":path", "/"}}) == kProtocolError);  // pseudo after regular
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"Accept", "x"}}) == kProtocolError);  // uppercase
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"connection", "close"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"transfer-encoding", "chunked"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"te", "gzip"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"x", "a\r\nb"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"x", " lead"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/a b"}}) == kProtocolError);
  CHECK(streamCode({{":method", "G ET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}) == kProtocolError);
  CHECK(streamCode({{":method", "CONNECT"}, {":authority", "x:443"}}) == kProtocolError);
  CHECK(streamCode({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"content-length", "x"}}) == kProtocolError);
  CHECK(streamCode({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"content-length", "1"}, {"content-length", "2"}}) == kProtocolError);
  // te: trailers is the one allowed value.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1,
                 head({{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"te", "trailers"}})));
    CHECK(h.requests.size() == 1);
  }
  // A body that disagrees with its Content-Length, short or long.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"content-length", "5"}})));
    CHECK(rstCode(h.feed(frame(kData, kFlagEndStream, 1, "abc")), 1) == kProtocolError);
    CHECK(h.requests.empty());
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"content-length", "5"}})));
    CHECK(h.requests.empty());
  }

  // Connection errors, with the code each must carry.
  auto connCode = [](const std::string& bytes) {
    Harness h;
    h.open();
    std::vector<Frame> out = h.feed(bytes);
    CHECK(h.session->dead());
    return goawayCode(out);
  };
  const std::string okHead = head(get());
  CHECK(connCode(frame(kHeaders, kFlagEndHeaders, 0, okHead)) == kProtocolError);          // stream 0
  CHECK(connCode(frame(kHeaders, kFlagEndHeaders, 2, okHead)) == kProtocolError);          // even id
  CHECK(connCode(frame(kData, 0, 1, "x")) == kProtocolError);                              // idle stream
  CHECK(connCode(frame(kRstStream, 0, 1, u32(0))) == kProtocolError);                      // idle stream
  CHECK(connCode(frame(kWindowUpdate, 0, 5, u32(1))) == kProtocolError);                   // idle stream
  CHECK(connCode(frame(kPushPromise, kFlagEndHeaders, 1, u32(2))) == kProtocolError);
  CHECK(connCode(frame(kPing, 0, 0, "short")) == kFrameSizeError);
  CHECK(connCode(frame(kPing, 0, 1, std::string(8, 'p'))) == kProtocolError);
  CHECK(connCode(frame(kSettings, 0, 0, "12345")) == kFrameSizeError);
  CHECK(connCode(frame(kSettings, kFlagAck, 0, "123456")) == kFrameSizeError);
  CHECK(connCode(frame(kSettings, 0, 1, "")) == kProtocolError);
  CHECK(connCode(frame(kSettings, 0, 0, std::string("\x00\x02", 2) + u32(2))) == kProtocolError);        // ENABLE_PUSH 2
  CHECK(connCode(frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(0x80000000u))) == kFlowControlError);
  CHECK(connCode(frame(kSettings, 0, 0, std::string("\x00\x05", 2) + u32(100))) == kProtocolError);      // frame size too small
  CHECK(connCode(frame(kRstStream, 0, 0, u32(0))) == kProtocolError);
  CHECK(connCode(frame(kWindowUpdate, 0, 0, "123")) == kFrameSizeError);
  CHECK(connCode(frame(kGoaway, 0, 1, std::string(8, '\0'))) == kProtocolError);
  CHECK(connCode(frame(kContinuation, kFlagEndHeaders, 1, okHead)) == kProtocolError);     // no block open
  CHECK(connCode(frame(kHeaders, 0, 1, okHead) + frame(kPing, 0, 0, std::string(8, 'p'))) == kProtocolError);
  CHECK(connCode(frame(kHeaders, 0, 1, okHead) + frame(kContinuation, kFlagEndHeaders, 3, "")) == kProtocolError);
  CHECK(connCode(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, std::string("\x80", 1))) == kCompressionError);
  CHECK(connCode(frame(kHeaders, kFlagEndHeaders | kFlagPadded, 1, std::string("\xff", 1) + okHead)) == kProtocolError);  // padding past the frame
  {
    std::string big;
    appendFrameHeader(big, 16385, kData, 0, 1);
    big += std::string(16385, 'x');
    CHECK(connCode(big) == kFrameSizeError);
  }
  // A lower stream id than one already used, and HEADERS on a stream that
  // closed without a reset from us.
  CHECK(connCode(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 5, okHead) +
                 frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, okHead)) == kStreamClosed);

  // Unknown frame types and unknown settings are ignored; a PRIORITY frame
  // is too, wherever it arrives.
  {
    Harness h;
    h.open();
    h.feed(frame(0x42, 0xff, 7, "whatever") + frame(kPriority, 0, 9, u32(0) + std::string(1, 'w')) +
           frame(kSettings, 0, 0, std::string("\x00\x99", 2) + u32(7)));
    CHECK(!h.session->dead());
    CHECK(rstCode(h.feed(frame(kPriority, 0, 3, u32(3) + std::string(1, 'w'))), 3) == kProtocolError);  // depends on itself
    CHECK(rstCode(h.feed(frame(kPriority, 0, 3, "1234")), 3) == kFrameSizeError);
    CHECK(!h.session->dead());
  }

  // PING is answered with its payload; an ACK is not.
  {
    Harness h;
    h.open();
    std::vector<Frame> out = h.feed(frame(kPing, 0, 0, "12345678"));
    CHECK(out.size() == 1 && out[0].type == kPing && out[0].flags == kFlagAck && out[0].payload == "12345678");
    CHECK(h.feed(frame(kPing, kFlagAck, 0, "12345678")).empty());
  }

  // DATA on a half-closed stream, and on one that is closed.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    CHECK(rstCode(h.feed(frame(kData, 0, 1, "late")), 1) == kStreamClosed);
    CHECK(h.aborted.size() == 1);
    CHECK(h.feed(frame(kData, 0, 1, "later")).empty());  // reset by us: read past
    CHECK(!h.session->dead());
  }
}

static void sessionLimits() {
  // A header block in CONTINUATION frames, cut anywhere.
  {
    Harness h;
    h.open();
    Fields f = get("/continued");
    f.emplace_back("x-long", std::string(500, 'h'));
    const std::string block = head(f);
    std::string bytes = frame(kHeaders, kFlagEndStream, 1, block.substr(0, 10));
    bytes += frame(kContinuation, 0, 1, block.substr(10, 200));
    bytes += frame(kContinuation, 0, 1, "");
    bytes += frame(kContinuation, kFlagEndHeaders, 1, block.substr(210));
    h.feed(bytes);
    CHECK(h.requests.size() == 1 && h.requests[0].path == "/continued");
  }
  // A block that never ends: bounded in frames and in bytes.
  {
    Harness h;
    h.open();
    std::string bytes = frame(kHeaders, 0, 1, "");
    for (int i = 0; i < 200; i++) bytes += frame(kContinuation, 0, 1, "");
    CHECK(goawayCode(h.feed(bytes)) == kEnhanceYourCalm);
    Settings s;
    s.maxHeaderListSize = 1024;
    Harness big(s);
    big.open();
    bytes = frame(kHeaders, 0, 1, std::string(4000, 'a'));
    bytes += frame(kContinuation, 0, 1, std::string(4000, 'a'));
    CHECK(goawayCode(big.feed(bytes)) == kEnhanceYourCalm);
  }
  // A header list over the limit, too many fields, a body over the limit: a
  // response from the session, not a dead connection.
  {
    Settings s;
    s.maxHeaderListSize = 300;
    s.maxHeaders = 5;
    s.maxBodySize = 10;
    s.maxUriSize = 20;
    auto statusOf = [](const std::vector<Frame>& out, uint32_t stream) {
      for (const Frame& f : out) {
        if (f.type != kHeaders || f.stream != stream) continue;
        HpackDecoder d;
        Fields got;
        if (decodeAll(d, f.payload, got) && !got.empty()) return got[0].second;
      }
      return std::string();
    };
    Harness h(s);
    h.open();
    Fields f = get();
    f.emplace_back("x-big", std::string(400, 'b'));
    std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(f)));
    CHECK(statusOf(out, 1) == "431" && h.requests.empty() && !h.session->dead());

    f = get();
    for (int i = 0; i < 6; i++) f.emplace_back("x" + std::to_string(i), "v");
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(f)));
    CHECK(statusOf(out, 3) == "431");

    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 5, head(get("/a/very/long/path/indeed"))));
    CHECK(statusOf(out, 5) == "414");

    out = h.feed(frame(kHeaders, kFlagEndHeaders, 7,
                       head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}, {"content-length", "11"}})));
    CHECK(statusOf(out, 7) == "413" && rstCode(out, 7) == kNoError);
    CHECK(h.feed(frame(kData, kFlagEndStream, 7, "hello world")).empty());  // already in flight: read past

    out = h.feed(frame(kHeaders, kFlagEndHeaders, 9,
                       head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}})));
    CHECK(out.empty());
    out = h.feed(frame(kData, 0, 9, "0123456789A"));
    CHECK(statusOf(out, 9) == "413" && rstCode(out, 9) == kNoError);
    CHECK(h.requests.empty() && !h.session->dead() && h.session->streamCount() == 0);
  }
  // More streams than allowed: refused, which a client may retry.
  {
    Settings s;
    s.maxConcurrentStreams = 3;
    Harness h(s);
    h.open();
    h.hold = true;
    std::string bytes;
    for (uint32_t id = 1; id <= 9; id += 2)
      bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, head(get()));
    std::vector<Frame> out = h.feed(bytes);
    CHECK(h.requests.size() == 3);
    CHECK(rstCode(out, 7) == kRefusedStream && rstCode(out, 9) == kRefusedStream);
    CHECK(!h.session->dead());
  }
  // Streams opened only to be reset, and control frames by the thousand.
  {
    Harness h;
    h.open();
    std::string bytes;
    for (uint32_t id = 1; id < 2001; id += 2) {
      bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, head(get()));
      bytes += frame(kRstStream, 0, id, u32(kCancel));
    }
    std::vector<Frame> out = h.feed(bytes);
    CHECK(h.session->dead() && goawayCode(out) == kEnhanceYourCalm);
    CHECK(h.requests.size() < 600);

    // The same when the reset is ours, answering a frame the peer sent on a
    // stream whose request the host holds: the slot is freed while the
    // handler works on, so it costs what the peer's RST_STREAM costs.
    for (int kind = 0; kind < 5; kind++) {
      Harness held;
      held.open();
      held.hold = true;
      bytes.clear();
      for (uint32_t id = 1; id < 4001; id += 2) {
        bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, head(get()));
        switch (kind) {
          case 0: bytes += frame(kData, 0, id, ""); break;  // DATA after END_STREAM
          case 1: bytes += frame(kWindowUpdate, 0, id, u32(0)); break;  // an increment of zero
          case 2: bytes += frame(kWindowUpdate, 0, id, u32(0x7fffffff)); break;  // past 2^31-1
          case 3: bytes += frame(kPriority, 0, id, u32(id) + std::string(1, 16)); break;  // on itself
          default: bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, ""); break;
        }
      }
      out = held.feed(bytes);
      CHECK(held.session->dead() && goawayCode(out) == kEnhanceYourCalm);
      CHECK(held.requests.size() < 600);
    }

    Harness pings;
    pings.open();
    bytes.clear();
    for (int i = 0; i < 3000; i++) bytes += frame(kPing, 0, 0, "12345678");
    out = pings.feed(bytes);
    CHECK(pings.session->dead() && goawayCode(out) == kEnhanceYourCalm);

    // At a human rate the budget refills and nothing happens.
    Harness slow;
    slow.open();
    uint64_t now = 1000;
    for (int i = 0; i < 5000; i++) {
      slow.feed(frame(kPing, 0, 0, "12345678"), now);
      now += 10;
    }
    CHECK(!slow.session->dead());
  }
  // A peer reset tells the host exactly once, and only when it holds the request.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    h.feed(frame(kRstStream, 0, 1, u32(kCancel)));
    CHECK(h.aborted.size() == 1 && h.aborted[0] == h.heldStreams[0]);
    CHECK(h.session->held() == 0 && h.session->streamCount() == 0);
    h.feed(frame(kRstStream, 0, 1, u32(kCancel)));  // again: closed, ignored
    CHECK(h.aborted.size() == 1 && !h.session->dead());
  }
  // The response complete while the request is still arriving: the client is
  // told to stop, and what it had in flight is read past.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}})));
    // No request has been dispatched (the body is not complete); a server
    // that sheds the stream resets it.
    CHECK(h.session->streamCount() == 1);
  }
  // GOAWAY from our side: new streams are ignored, the connection lives.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(get())));
    h.session->goaway();
    std::vector<Frame> out = h.take();
    CHECK(out.size() == 1 && out[0].type == kGoaway && goawayCode(out) == kNoError);
    CHECK(readU32(reinterpret_cast<const uint8_t*>(out[0].payload.data())) == 1);
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(get())));
    CHECK(h.requests.size() == 1 && out.empty() && !h.session->dead());
  }
}

// Whatever the session does with a byte stream, it does the same when the
// stream arrives one byte at a time or in any other pieces.
static void sessionSplitting() {
  Fields f = get("/split?x=1");
  f.emplace_back("accept", "text/html");
  std::string bytes = std::string(kPreface) + frame(kSettings, 0, 0, "");
  bytes += frame(kHeaders, kFlagEndStream, 1, head(f).substr(0, 7));
  bytes += frame(kContinuation, kFlagEndHeaders, 1, head(f).substr(7));
  bytes += frame(kHeaders, kFlagEndHeaders, 3,
                 head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/body"}}));
  bytes += frame(kData, 0, 3, std::string(3000, 'q'));
  bytes += frame(kPing, 0, 0, "abcdefgh");
  bytes += frame(kData, kFlagEndStream, 3, std::string(5000, 'r'));
  bytes += frame(kWindowUpdate, 0, 0, u32(1000));

  auto run = [&](size_t piece) {
    Harness h;
    std::string out;
    for (size_t off = 0; off < bytes.size(); off += piece) {
      const size_t n = std::min(piece, bytes.size() - off);
      h.session->feed(bytes.data() + off, n, 1000);
      out += h.session->out();
      h.session->out().clear();
    }
    std::string summary = out;
    for (const Seen& r : h.requests)
      summary += "|" + std::to_string(r.id) + r.path + "?" + r.query + "#" + std::to_string(r.body.size());
    CHECK(!h.session->dead());
    CHECK(h.requests.size() == 2);
    return summary;
  };
  const std::string whole = run(bytes.size());
  for (size_t piece : {size_t(1), size_t(2), size_t(3), size_t(7), size_t(9), size_t(10), size_t(100), size_t(4096)})
    CHECK(run(piece) == whole);
}

// The budget for frames that cost the peer nothing and the server work: 2000
// units at once, 200 more a second, RST_STREAM four units and PING, SETTINGS,
// PRIORITY and an empty DATA frame one. Each at the last unit and one past it.
static void sessionBudget() {
  const std::string ping = frame(kPing, 0, 0, "12345678");
  const std::string okHead = head(get());
  auto request = [&](uint32_t id) { return frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, okHead); };
  // What 2000 units buy of each kind, and that one more ends the connection.
  struct Kind {
    const char* name;
    int afford;
    std::string (*one)(uint32_t id);
    std::string setup;
  };
  const Kind kinds[] = {
      {"PING", 2000, [](uint32_t) { return frame(kPing, 0, 0, "12345678"); }, ""},
      {"SETTINGS", 2000, [](uint32_t) { return frame(kSettings, 0, 0, ""); }, ""},
      {"PRIORITY", 2000, [](uint32_t) { return frame(kPriority, 0, 3, u32(0) + std::string(1, 'w')); }, ""},
      {"empty DATA", 2000, [](uint32_t) { return frame(kData, 0, 1, ""); },
       frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}))},
      {"padding-only DATA", 2000, [](uint32_t) { return frame(kData, kFlagPadded, 1, std::string("\x02\0\0", 3)); },
       frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}))},
      {"RST_STREAM", 500,
       [](uint32_t id) {
         return frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, head(get())) + frame(kRstStream, 0, id, u32(kCancel));
       },
       ""},
  };
  for (const Kind& k : kinds) {
    Harness h;
    h.open();
    h.feed(k.setup);
    std::string bytes;
    for (int i = 0; i < k.afford; i++) bytes += k.one(101 + 2 * static_cast<uint32_t>(i));
    h.feed(bytes);
    if (h.session->dead()) std::fprintf(stderr, "budget: %d of %s ended the connection\n", k.afford, k.name);
    CHECK(!h.session->dead());
    const std::vector<Frame> out = h.feed(k.one(101 + 2 * static_cast<uint32_t>(k.afford)));
    if (!h.session->dead()) std::fprintf(stderr, "budget: %d of %s did not end the connection\n", k.afford + 1, k.name);
    CHECK(h.session->dead() && goawayCode(out) == kEnhanceYourCalm);
  }
  // The kinds draw on one budget: 499 resets and four PINGs are all of it.
  {
    Harness h;
    h.open();
    std::string bytes;
    for (uint32_t i = 0; i < 499; i++) bytes += request(1 + 2 * i) + frame(kRstStream, 0, 1 + 2 * i, u32(kCancel));
    h.feed(bytes + times(ping, 4));
    CHECK(!h.session->dead());
    CHECK(goawayCode(h.feed(ping)) == kEnhanceYourCalm);
  }
  // The refill: nothing in 4 ms, one unit in 5, 200 in a second, and never
  // more than the burst however long the connection was quiet.
  {
    Harness a;
    a.open();
    a.feed(times(ping, 2000), 1000);
    CHECK(goawayCode(a.feed(ping, 1004)) == kEnhanceYourCalm);
    Harness b;
    b.open();
    b.feed(times(ping, 2000), 1000);
    b.feed(ping, 1005);
    CHECK(!b.session->dead());
    CHECK(goawayCode(b.feed(ping, 1005)) == kEnhanceYourCalm);
    Harness c;
    c.open();
    c.feed(times(ping, 2000), 1000);
    c.feed(times(ping, 200), 2000);
    CHECK(!c.session->dead());
    CHECK(goawayCode(c.feed(ping, 2000)) == kEnhanceYourCalm);
    Harness d;
    d.open();
    d.feed(times(ping, 2000), 1000);
    d.feed(times(ping, 2000), 1000 + 3600 * 1000);
    CHECK(!d.session->dead());
    CHECK(goawayCode(d.feed(ping, 1000 + 3600 * 1000)) == kEnhanceYourCalm);
  }

  // A request the host was given and the peer then makes the server reset -
  // by any frame that is a stream error on it - costs what resetting it
  // costs: the host did the work of a request either way.
  struct Provoke {
    const char* name;
    std::string (*one)(uint32_t id);
    uint32_t code;
  };
  const Provoke provokes[] = {
      {"WINDOW_UPDATE of zero", [](uint32_t id) { return frame(kWindowUpdate, 0, id, u32(0)); }, kProtocolError},
      {"WINDOW_UPDATE past 2^31-1", [](uint32_t id) { return frame(kWindowUpdate, 0, id, u32(0x7fffffff)); }, kFlowControlError},
      {"DATA after END_STREAM", [](uint32_t id) { return frame(kData, 0, id, "x"); }, kStreamClosed},
      {"HEADERS after END_STREAM",
       [](uint32_t id) { return frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, head({{"x-trailer", "t"}})); },
       kStreamClosed},
      {"PRIORITY of the wrong size", [](uint32_t id) { return frame(kPriority, 0, id, "1234"); }, kFrameSizeError},
      {"PRIORITY on itself", [](uint32_t id) { return frame(kPriority, 0, id, u32(id) + std::string(1, 'w')); }, kProtocolError},
  };
  for (const Provoke& pv : provokes) {
    Harness h;
    h.open();
    h.hold = true;
    bool wrongCode = false;
    for (uint32_t i = 0; i < 500; i++) {
      const uint32_t id = 1 + 2 * i;
      h.feed(request(id));
      if (rstCode(h.feed(pv.one(id)), id) != pv.code) wrongCode = true;
    }
    CHECK(!wrongCode);
    CHECK(!h.session->dead() && h.requests.size() == 500 && h.aborted.size() == 500);
    h.feed(request(1001));
    const std::vector<Frame> out = h.feed(pv.one(1001));
    if (!h.session->dead()) std::fprintf(stderr, "budget: 501 requests reset through %s did not end the connection\n", pv.name);
    CHECK(h.session->dead() && goawayCode(out) == kEnhanceYourCalm);
  }
  // A stream error on a stream the host does not have - a malformed request,
  // a frame of the wrong size for a stream that does not exist - is a frame
  // answered for free: one unit.
  {
    Harness h;
    h.open();
    h.feed(times(frame(kPriority, 0, 3, "1234"), 2000));
    CHECK(!h.session->dead());
    CHECK(goawayCode(h.feed(frame(kPriority, 0, 3, "1234"))) == kEnhanceYourCalm);
    Harness m;
    m.open();
    Fields bad = get();
    bad.emplace_back("Upper", "x");
    std::string bytes;
    for (uint32_t i = 0; i < 2000; i++) bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1 + 2 * i, head(bad));
    m.feed(bytes);
    CHECK(!m.session->dead() && m.requests.empty());
    CHECK(goawayCode(m.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 4001, head(bad)))) == kEnhanceYourCalm);
  }
  // Empty DATA frames on streams that are closed are each answered with a
  // reset; they draw on the budget like those on an open stream.
  {
    Harness h;
    h.open();
    h.hold = true;
    std::string bytes;
    for (uint32_t i = 0; i < 40; i++) bytes += request(1 + 2 * i);
    h.feed(bytes);
    for (Stream* st : h.heldStreams) h.answer(*st);
    h.take();
    CHECK(h.session->streamCount() == 0);
    bytes.clear();
    for (uint32_t i = 0; i < 2000; i++) bytes += frame(kData, 0, 1 + 2 * (i % 40), "");
    h.feed(bytes);
    CHECK(!h.session->dead());
    CHECK(goawayCode(h.feed(frame(kData, 0, 1, ""))) == kEnhanceYourCalm);
  }
}

// The other bounds a connection has, each at the bound and one past it.
static void sessionBounds() {
  const std::string okHead = head(get());
  auto request = [&](uint32_t id) { return frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, okHead); };

  // maxConcurrentStreams at its default: 256 at once, the 257th refused, and
  // room again as soon as one is answered.
  {
    Harness h;
    h.open();
    h.hold = true;
    std::string bytes;
    for (uint32_t i = 0; i < 256; i++) bytes += request(1 + 2 * i);
    std::vector<Frame> out = h.feed(bytes);
    CHECK(h.requests.size() == 256 && !has(out, kRstStream) && h.session->streamCount() == 256);
    out = h.feed(request(513));
    CHECK(rstCode(out, 513) == kRefusedStream && h.requests.size() == 256 && !h.session->dead());
    h.answer(*h.heldStreams[0]);
    h.take();
    out = h.feed(request(515));
    CHECK(!has(out, kRstStream) && h.requests.size() == 257);
  }

  // A header block in CONTINUATION frames: 64 of them, empty ones included.
  {
    auto continued = [&](int frames) {
      std::string bytes = frame(kHeaders, kFlagEndStream, 1, "");
      for (int i = 0; i < frames - 1; i++) bytes += frame(kContinuation, 0, 1, "");
      return bytes + frame(kContinuation, kFlagEndHeaders, 1, okHead);
    };
    Harness h;
    h.open();
    h.feed(continued(64));
    CHECK(!h.session->dead() && h.requests.size() == 1);
    Harness over;
    over.open();
    CHECK(goawayCode(over.feed(continued(65))) == kEnhanceYourCalm && over.requests.empty());
  }
  // ...and in bytes: maxHeaderListSize + 4096, in one frame or in several.
  // (The filler is table size updates, which a block may open with and which
  // add nothing to the header list.)
  {
    Settings s;
    s.maxHeaderListSize = 1024;
    const size_t limit = 1024 + 4096;
    auto block = [&](size_t size) { return std::string(size - okHead.size(), '\x20') + okHead; };
    Harness one(s);
    one.open();
    one.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, block(limit)));
    CHECK(!one.session->dead() && one.requests.size() == 1);
    Harness oneOver(s);
    oneOver.open();
    CHECK(goawayCode(oneOver.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, block(limit + 1)))) == kEnhanceYourCalm);
    Harness cut(s);
    cut.open();
    cut.feed(frame(kHeaders, kFlagEndStream, 1, block(limit).substr(0, 3000)) +
             frame(kContinuation, kFlagEndHeaders, 1, block(limit).substr(3000)));
    CHECK(!cut.session->dead() && cut.requests.size() == 1);
    Harness cutOver(s);
    cutOver.open();
    CHECK(goawayCode(cutOver.feed(frame(kHeaders, kFlagEndStream, 1, block(limit + 1).substr(0, 3000)) +
                                  frame(kContinuation, kFlagEndHeaders, 1, block(limit + 1).substr(3000)))) ==
          kEnhanceYourCalm);
  }

  // The HPACK table: a size update to the advertised 4096 and to one more.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, std::string("\x3f\xe1\x1f", 3) + okHead));
    CHECK(!h.session->dead() && h.requests.size() == 1);
    Harness over;
    over.open();
    CHECK(goawayCode(over.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1,
                                     std::string("\x3f\xe2\x1f", 3) + okHead))) == kCompressionError);
  }
  // ...its content never larger than that, an entry of exactly the table's
  // size kept and one a byte larger emptying it.
  {
    auto indexed = [](const std::string& name, const std::string& value) {
      std::string b(1, '\x40');
      encodeInt(b, 7, 0, static_cast<uint32_t>(name.size()));
      b += name;
      encodeInt(b, 7, 0, static_cast<uint32_t>(value.size()));
      return b + value;
    };
    HpackDecoder d;
    Fields got;
    bool within = true;
    for (int i = 0; i < 300; i++) {
      if (!decodeAll(d, indexed("k", std::string(97, static_cast<char>('a' + i % 26))), got)) within = false;
      if (d.tableSize() > 4096) within = false;
    }
    CHECK(within && d.tableEntries() == 31 && d.tableSize() == 31 * 130);
    CHECK(decodeAll(d, indexed("a", std::string(4096 - 33, 'v')), got));
    CHECK(d.tableEntries() == 1 && d.tableSize() == 4096);
    CHECK(decodeAll(d, indexed("a", std::string(4096 - 32, 'v')), got));
    CHECK(d.tableEntries() == 0 && d.tableSize() == 0);
  }
  // HPACK integers: 2^30 is the largest, in at most five continuation bytes,
  // and the fifth cannot carry the value past 32 bits unnoticed.
  {
    auto decodes = [](std::initializer_list<uint8_t> bytes, uint32_t& v) {
      const std::vector<uint8_t> b(bytes);
      const uint8_t* p = b.data();
      return decodeInt(p, b.data() + b.size(), 5, v);
    };
    uint32_t v = 0;
    std::string e;
    encodeInt(e, 5, 0, 1u << 30);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(e.data());
    CHECK(e.size() == 6 && decodeInt(p, p + e.size(), 5, v) && v == (1u << 30));
    CHECK(!decodes({0x1f, 0xe2, 0xff, 0xff, 0xff, 0x03}, v));        // 2^30 + 1
    CHECK(decodes({0x1f, 0x80, 0x80, 0x80, 0x80, 0x00}, v) && v == 31);  // five bytes, padded with zeros
    CHECK(!decodes({0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, v));  // six
    CHECK(!decodes({0x1f, 0x80, 0x80, 0x80, 0x80, 0x10}, v));        // 31 + 2^32: not 31
    CHECK(!decodes({0x1f, 0x80, 0x80, 0x80, 0x80, 0x7f}, v));
  }

  // The header list: exactly maxHeaderListSize (name + value + 32 a field,
  // pseudo-headers included) is a request, a byte more is a 431.
  {
    Settings s;
    s.maxHeaderListSize = 300;
    Fields f = get();  // 178 by that count
    f.emplace_back("x-pad", std::string(300 - 178 - 37, 'p'));
    Harness h(s);
    h.open();
    std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(f)));
    CHECK(h.requests.size() == 1 && statusOn(out, 1).empty());
    f.back().second.push_back('p');
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(f)));
    CHECK(h.requests.size() == 1 && statusOn(out, 3) == "431" && !h.session->dead());

    // A block that went over the limit was still decoded to its end: an
    // entry it added to the table after that point is there for the next.
    std::string block = head(get());
    block += head({{"x-big", std::string(400, 'b')}});
    block += std::string("\x40\x03" "x-a" "\x01" "1", 7);
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 5, block));
    CHECK(statusOn(out, 5) == "431");
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 7, head(get()) + std::string("\xbe", 1)));
    CHECK(h.requests.size() == 2 && !h.session->dead());
    CHECK(h.requests.back().headers.size() == 2 && h.requests.back().headers[0] == std::make_pair(std::string("x-a"), std::string("1")));
  }
  // maxHeaders: that many fields are a request, one more is a 431.
  {
    Settings s;
    s.maxHeaders = 5;
    Harness h(s);
    h.open();
    Fields f = get();
    for (int i = 0; i < 5; i++) f.emplace_back("x" + std::to_string(i), "v");
    std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(f)));
    CHECK(h.requests.size() == 1 && statusOn(out, 1).empty());
    f.emplace_back("x5", "v");
    out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(f)));
    CHECK(h.requests.size() == 1 && statusOn(out, 3) == "431");
  }

  // maxBodySize: a body of exactly that size, declared or not, and one byte
  // more.
  {
    Settings s;
    s.maxBodySize = 10;
    Harness h(s);
    h.open();
    auto post = [](uint32_t id, const char* declared) {
      Fields f = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}};
      if (declared) f.emplace_back("content-length", declared);
      return frame(kHeaders, kFlagEndHeaders, id, head(f));
    };
    h.feed(post(1, nullptr) + frame(kData, kFlagEndStream, 1, "0123456789"));
    CHECK(h.requests.size() == 1 && h.requests[0].body == "0123456789");
    h.feed(post(3, "10") + frame(kData, 0, 3, "01234") + frame(kData, kFlagEndStream, 3, "56789"));
    CHECK(h.requests.size() == 2 && h.requests[1].body == "0123456789");
    std::vector<Frame> out = h.feed(post(5, "11"));
    CHECK(statusOn(out, 5) == "413");
    out = h.feed(post(7, nullptr) + frame(kData, 0, 7, "0123456789") + frame(kData, kFlagEndStream, 7, "A"));
    CHECK(statusOn(out, 7) == "413" && h.requests.size() == 2 && !h.session->dead());
  }

  // Flow control: a window raised to exactly 2^31-1 and one past it, on the
  // connection, on a stream, and through SETTINGS_INITIAL_WINDOW_SIZE.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(request(1));
    CHECK(h.feed(frame(kWindowUpdate, 0, 0, u32(0x7fffffff - 65535))).empty() && !h.session->dead());
    std::vector<Frame> out = h.feed(frame(kWindowUpdate, 0, 1, u32(0x7fffffff - 65535)));
    CHECK(out.empty() && h.aborted.empty());
    out = h.feed(frame(kWindowUpdate, 0, 1, u32(1)));
    CHECK(rstCode(out, 1) == kFlowControlError && h.aborted.size() == 1 && !h.session->dead());
    CHECK(goawayCode(h.feed(frame(kWindowUpdate, 0, 0, u32(1)))) == kFlowControlError);

    Harness viaSettings;
    viaSettings.open();
    viaSettings.hold = true;
    viaSettings.feed(request(1));
    viaSettings.feed(frame(kWindowUpdate, 0, 1, u32(0x7fffffff - 65535)));
    CHECK(!viaSettings.session->dead());
    CHECK(goawayCode(viaSettings.feed(frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(65536)))) == kFlowControlError);
    Harness largest;
    largest.open();
    largest.feed(frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(0x7fffffff)));
    CHECK(!largest.session->dead());
  }
  // ...and a peer that sends exactly the window it was given, and one byte more.
  {
    Settings s;
    s.initialWindowSize = 10000;
    s.connectionWindow = 65535;
    const std::string post = frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}}));
    Harness h(s);
    h.open();
    std::vector<Frame> out = h.feed(post + frame(kData, kFlagEndStream, 1, std::string(10000, 'd')));
    CHECK(!has(out, kRstStream) && h.requests.size() == 1);
    Harness over(s);
    over.open();
    out = over.feed(post + frame(kData, kFlagEndStream, 1, std::string(10001, 'd')));
    CHECK(rstCode(out, 1) == kFlowControlError && over.requests.empty() && !over.session->dead());

    Settings c;
    c.maxFrameSize = 65536;
    c.initialWindowSize = 1 << 20;
    c.connectionWindow = 65535;
    Harness conn(c);
    conn.open();
    conn.feed(post + frame(kData, kFlagEndStream, 1, std::string(65535, 'd')));
    CHECK(!conn.session->dead() && conn.requests.size() == 1);
    Harness connOver(c);
    connOver.open();
    CHECK(goawayCode(connOver.feed(post + frame(kData, kFlagEndStream, 1, std::string(65536, 'd')))) == kFlowControlError);
  }
}

// A client that keeps to flow control, uploading on several streams at once:
// it sends what the windows it was given allow, a frame per stream in turn.
struct Uploader {
  Harness& h;
  struct Up {
    uint32_t id;
    size_t left;
    int64_t window;
    bool over = false;
    size_t sent = 0;
  };
  std::vector<Up> ups;
  int64_t connWindow = 65535;
  size_t peakBuffered = 0;
  std::vector<uint32_t> refused;

  Uploader(Harness& harness, int streams, size_t each, uint32_t streamWindow) : h(harness) {
    for (int i = 0; i < streams; i++) {
      const uint32_t id = 1 + 2 * static_cast<uint32_t>(i);
      ups.push_back(Up{id, each, streamWindow});
      take(h.feed(frame(kHeaders, kFlagEndHeaders, id, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}}))));
    }
  }
  void take(const std::vector<Frame>& out) {
    for (const Frame& f : out) {
      if (f.type == kWindowUpdate) {
        const uint32_t inc = readU32(reinterpret_cast<const uint8_t*>(f.payload.data()));
        if (f.stream == 0) connWindow += inc;
        for (Up& u : ups)
          if (u.id == f.stream) u.window += inc;
      } else if (f.type == kRstStream) {
        for (Up& u : ups)
          if (u.id == f.stream && !u.over) {
            u.over = true;
            if (readU32(reinterpret_cast<const uint8_t*>(f.payload.data())) == kRefusedStream) refused.push_back(u.id);
          }
      }
    }
  }
  // One frame on every stream that can send; false when none could.
  bool round() {
    bool any = false;
    for (Up& u : ups) {
      if (u.over) continue;
      const size_t n = static_cast<size_t>(std::min<int64_t>({16384, connWindow, u.window, static_cast<int64_t>(u.left)}));
      if (n == 0) continue;
      any = true;
      u.left -= n;
      u.sent += n;
      u.window -= static_cast<int64_t>(n);
      connWindow -= static_cast<int64_t>(n);
      size_t buffered = 0;
      for (const Up& b : ups)
        if (!b.over) buffered += b.sent;
      peakBuffered = std::max(peakBuffered, buffered);
      if (u.left == 0) u.over = true;
      take(h.feed(frame(kData, u.left == 0 ? kFlagEndStream : 0, u.id, std::string(n, 'u'))));
    }
    return any;
  }
  bool allOver() const {
    for (const Up& u : ups)
      if (!u.over) return false;
    return true;
  }
};

// Request bodies buffered before dispatch: bounded per connection, and a
// connection at the bound is never left with requests that cannot complete.
static void sessionBuffering() {
  Settings s;
  s.maxBodySize = 100000;
  s.initialWindowSize = 65535;
  s.connectionWindow = 65535;
  const size_t bound = 4 * 65535;  // the larger of 2 x maxBodySize and four connection windows
  // Four uploads of maxBodySize, arriving evenly, are more than the bound
  // and a window on top of it. The session never holds more than that; each
  // time the window is spent with no request able to complete, the newest is
  // refused and the others go on. The bound holds two of these bodies and
  // part of a third, so two complete - where, with nothing refused, none
  // ever would.
  {
    Harness h(s);
    h.open();
    Uploader up(h, 4, 100000, 65535);
    while (up.round()) {
    }
    CHECK(up.peakBuffered > bound && up.peakBuffered <= bound + 65535);
    CHECK(up.allOver());
    CHECK(h.requests.size() == 2 && up.refused == (std::vector<uint32_t>{7, 5}));
    for (const Seen& r : h.requests) CHECK(r.body.size() == 100000);
    CHECK(!h.session->dead() && h.session->streamCount() == 2);
  }
  // Three, the last of them shorter: one is refused and two complete, the
  // short one among them.
  {
    Harness h(s);
    h.open();
    Uploader up(h, 3, 100000, 65535);
    up.ups[2].left = 90000;
    while (up.round()) {
    }
    CHECK(up.allOver() && h.requests.size() == 3 && up.refused.empty());
  }
  // Under the bound nothing is refused: two uploads of maxBodySize.
  {
    Harness h(s);
    h.open();
    Uploader up(h, 2, 100000, 65535);
    while (up.round()) {
    }
    CHECK(up.allOver() && up.refused.empty() && h.requests.size() == 2);
  }
  // Over the bound with window left, the connection's window stays shut -
  // and reopens when a stream that was buffered goes away: reset by the
  // peer, or refused for its size.
  for (const bool byReset : {true, false}) {
    Settings t = s;
    t.maxBodySize = 90000;  // the bound is still four windows
    Harness h(t);
    h.open();
    Uploader up(h, 4, 90000, 65535);
    for (int i = 0; i < 4; i++) up.round();  // 4 x 65536: four bytes past the bound
    CHECK(up.connWindow == 65535 - 32768);   // half a window used and not given back
    std::vector<Frame> out;
    if (byReset) {
      out = h.feed(frame(kRstStream, 0, 7, u32(kCancel)));
    } else {
      out = h.feed(frame(kData, 0, 7, std::string(16384, 'u')) + frame(kData, 0, 7, std::string(8081, 'u')));  // 90001
      CHECK(statusOn(out, 7) == "413");
    }
    CHECK(has(out, kWindowUpdate, 0));
    CHECK(!h.session->dead());
  }
}

// What the HTTP/1 parser refuses in a request, a request over HTTP/2 is
// refused for as well: a handler sees the same bytes ruled out on both.
static void sessionHttp1Parity() {
  auto verdict = [](const Fields& extra, Fields base = get()) {
    Harness h;
    h.open();
    for (const auto& f : extra) base.push_back(f);
    const std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(base)));
    CHECK(!h.session->dead());
    if (rstCode(out, 1) == kProtocolError && h.requests.empty()) return 'R';  // refused
    return h.requests.size() == 1 ? 'D' : '?';                                // delivered
  };
  // Control bytes in a field value (RFC 9110 5.5): all but HTAB, and DEL.
  for (int c = 0; c < 0x20; c++) {
    if (c == '\t') continue;
    std::string v = "a";
    v.push_back(static_cast<char>(c));
    v += "b";
    CHECK(verdict({{"x-v", v}}) == 'R');
  }
  CHECK(verdict({{"x-v", std::string("a\x7f" "b")}}) == 'R');
  CHECK(verdict({{"x-v", "a\tb c"}}) == 'D');
  CHECK(verdict({{"x-v", "caf\xc3\xa9"}}) == 'D');  // obs-text stays
  // ...and in the target.
  CHECK(verdict({}, {{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", std::string("/a\x01" "b")}}) == 'R');
  CHECK(verdict({}, {{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", std::string("/a\x7f")}}) == 'R');
  CHECK(verdict({}, {{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/caf\xc3\xa9?q=\xff"}}) == 'D');

  // Host (RFC 9112 3.2, RFC 9110 7.2): one, of the shape host[:port] -
  // whether it arrives as Host or as :authority, which is delivered as Host.
  const Fields noAuthority = {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}};
  for (const char* host : {"example.test", "example.test:8443", "[::1]:80", "EXAMPLE.test.", "10.0.0.1"}) {
    CHECK(verdict({{"host", host}}, noAuthority) == 'D');
    CHECK(verdict({{":authority", host}}, {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}}) == 'D');
  }
  for (const char* host : {"a b", "evil.test/path", "user@evil.test", "a.test:80:90", "a.test, b.test", "a.test?x", "a.test#x",
                           "a\\b", "[::1", "caf\xc3\xa9.test", "a.test:8o"}) {
    CHECK(verdict({{"host", host}}, noAuthority) == 'R');
    CHECK(verdict({{":authority", host}}, {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}}) == 'R');
  }
  CHECK(verdict({{"host", "a.test"}, {"host", "a.test"}}, noAuthority) == 'R');
  CHECK(verdict({{"host", "a.test"}, {"host", "b.test"}}, noAuthority) == 'R');
  CHECK(verdict({}, {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "a.test"}, {":authority", "b.test"}}) == 'R');
  CHECK(verdict({}, {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "a.test"}, {":authority", "a.test"}}) == 'R');

  // Content-Length: digits only, one value, and the body that long.
  const Fields post = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/"}};
  for (const char* cl : {"", "+1", "-1", "1,1", "1, 1", "0x1", " 1", "1 1", "1e1", "99999999999999999999"})
    CHECK(verdict({{"content-length", cl}}, post) == 'R');
  CHECK(verdict({{"content-length", "0"}}, post) == 'D');
  CHECK(verdict({{"content-length", "0"}, {"content-length", "0"}}, post) == 'D');  // repeated, the same: one value
  CHECK(verdict({{"content-length", "0"}, {"content-length", "00"}}, post) == 'D');
  CHECK(verdict({{"content-length", "1"}}, post) == 'R');  // END_STREAM with no byte of it
}

// The host stops the session part-way through its input and lets it go on
// later: the same requests in the same order, whatever arrived in between.
static void sessionPausing() {
  const std::string okHead = head(get());
  std::string bytes;
  for (uint32_t i = 0; i < 50; i++) bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1 + 2 * i, head(get("/p" + std::to_string(i))));
  {
    Harness h;
    h.open();
    h.pauseFrom = 3;
    h.feed(bytes.substr(0, 700));  // some whole frames and a part of one
    CHECK(h.requests.size() == 3 && h.session->paused());
    const size_t heldAfterThree = h.session->inputHeld();
    CHECK(heldAfterThree > 0 && heldAfterThree < 700);
    h.feed(bytes.substr(700));     // kept, not acted on
    CHECK(h.requests.size() == 3);
    CHECK(h.session->inputHeld() == heldAfterThree + (bytes.size() - 700));
    // Resumed, it stops again at each request while the host says so.
    for (size_t want = 4; want <= 50; want++) {
      h.session->resume();
      h.feed("");
      CHECK(h.requests.size() == want);
    }
    h.session->resume();
    h.feed("");
    CHECK(!h.session->paused() && h.session->inputHeld() == 0 && !h.session->dead());
    bool inOrder = h.requests.size() == 50;
    for (size_t i = 0; inOrder && i < 50; i++) inOrder = h.requests[i].path == "/p" + std::to_string(i);
    CHECK(inOrder);
  }
  // Paused before anything arrived, a byte at a time: nothing is acted on
  // until it resumes, and then everything is.
  {
    Harness h;
    h.session->pause();
    const std::string all = std::string(kPreface) + frame(kSettings, 0, 0, "") + bytes + frame(kPing, 0, 0, "12345678");
    for (const char ch : all) h.session->feed(&ch, 1, 1000);
    CHECK(h.requests.empty() && h.session->inputHeld() == all.size() - kPreface.size());
    h.take();
    h.session->resume();
    const std::vector<Frame> out = h.feed("");
    CHECK(h.requests.size() == 50 && has(out, kPing) && h.session->inputHeld() == 0);
  }
  // A connection error while paused input is being gone through ends it there.
  {
    Harness h;
    h.open();
    h.pauseFrom = 1;
    const std::string two = frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, okHead) +
                            frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, okHead);
    h.feed(two + frame(kData, 0, 0, "x") + frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 5, okHead));
    CHECK(h.requests.size() == 1 && !h.session->dead());
    h.pauseFrom = 0;
    h.session->resume();
    const std::vector<Frame> out = h.feed("");
    CHECK(h.requests.size() == 2 && h.session->dead() && goawayCode(out) == kProtocolError && h.session->inputHeld() == 0);
  }
}

// A DATA frame's payload goes to its request as it arrives: the session does
// not hold a frame back until it is whole, and whatever it does with a byte
// stream of request bodies - bodies delivered, refused, read past, flow
// control given back, errors - it does the same however the stream is cut.
static void sessionDataInPieces() {
  // Half of a frame's payload has arrived: it is in the request already and
  // nothing of it waits in the session's input.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}})));
    const std::string data = frame(kData, kFlagEndStream, 1, std::string(16384, 'd'));
    h.feed(data.substr(0, 9 + 8000));
    CHECK(h.session->inputHeld() == 0);
    CHECK(h.requests.empty());
    h.feed(data.substr(9 + 8000, 5));
    h.feed(data.substr(9 + 8005, 0));
    CHECK(h.session->inputHeld() == 0);
    h.feed(data.substr(9 + 8005));
    CHECK(h.requests.size() == 1 && h.requests[0].body == std::string(16384, 'd'));
    CHECK(h.session->inputHeld() == 0 && !h.session->dead());
  }
  // A frame header cut in two is the only part that waits; a padded frame
  // waits whole (its padding is not payload).
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}})));
    const std::string data = frame(kData, 0, 1, std::string(1000, 'a'));
    h.feed(data.substr(0, 4));
    CHECK(h.session->inputHeld() == 4);
    h.feed(data.substr(4, 300));
    CHECK(h.session->inputHeld() == 0);
    h.feed(data.substr(304));
    const std::string padded = frame(kData, kFlagPadded | kFlagEndStream, 1, std::string(1, '\x05') + std::string(500, 'b') + std::string(5, '\0'));
    h.feed(padded.substr(0, 200));
    CHECK(h.session->inputHeld() == 200);
    h.feed(padded.substr(200));
    CHECK(h.requests.size() == 1 && h.requests[0].body == std::string(1000, 'a') + std::string(500, 'b'));
    CHECK(h.session->inputHeld() == 0);
  }

  // One stream of everything a body can meet, cut every way.
  Settings s;
  s.maxBodySize = 40000;
  s.initialWindowSize = 65535;
  const Fields post = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}};
  auto body = [](size_t n, char seed) {
    std::string b(n, '\0');
    for (size_t i = 0; i < n; i++) b[i] = static_cast<char>(seed + i % 61);
    return b;
  };
  std::string bytes = std::string(kPreface) + frame(kSettings, 0, 0, "");
  // 1: three frames, one of them padded, another stream's frames in between.
  bytes += frame(kHeaders, kFlagEndHeaders, 1, head(post));
  bytes += frame(kHeaders, kFlagEndHeaders, 3, head(post));
  bytes += frame(kData, 0, 1, body(9000, 'a'));
  bytes += frame(kData, 0, 3, body(16384, 'k'));
  bytes += frame(kData, kFlagPadded, 1, std::string(1, '\x07') + body(3000, 'b') + std::string(7, '\0'));
  bytes += frame(kPing, 0, 0, "abcdefgh");
  bytes += frame(kData, 0, 1, "");
  bytes += frame(kData, kFlagEndStream, 1, body(5000, 'c'));
  // 3: ends with trailers.
  bytes += frame(kData, 0, 3, body(100, 'l'));
  bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head({{"x-trailer", "1"}}));
  // 5: over the body limit part-way: refused, and what follows is read past.
  bytes += frame(kHeaders, kFlagEndHeaders, 5, head(post));
  bytes += frame(kData, 0, 5, body(16384, 'm'));
  bytes += frame(kData, 0, 5, body(16384, 'n'));
  bytes += frame(kData, 0, 5, body(16384, 'o'));
  bytes += frame(kData, kFlagEndStream, 5, body(16384, 'p'));
  // 7: a declared length the body does not match.
  Fields declared = post;
  declared.emplace_back("content-length", "20000");
  bytes += frame(kHeaders, kFlagEndHeaders, 7, head(declared));
  bytes += frame(kData, kFlagEndStream, 7, body(12000, 'q'));
  // 9: declared and matching, in frames of unequal size.
  bytes += frame(kHeaders, kFlagEndHeaders, 9, head(declared));
  bytes += frame(kData, 0, 9, body(1, 'r'));
  bytes += frame(kData, 0, 9, body(16384, 's'));
  bytes += frame(kData, kFlagEndStream, 9, body(3615, 't'));
  // DATA on a stream that is over, and on one the peer reset.
  bytes += frame(kData, 0, 1, body(2000, 'u'));
  bytes += frame(kHeaders, kFlagEndHeaders, 11, head(post));
  bytes += frame(kData, 0, 11, body(4000, 'v'));
  bytes += frame(kRstStream, 0, 11, u32(kCancel));
  bytes += frame(kData, kFlagEndStream, 11, body(4000, 'w'));
  bytes += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 13, head(get("/after")));

  auto run = [&](size_t piece, size_t pauseFrom) {
    Harness h(s);
    h.pauseFrom = pauseFrom;
    std::string out;
    size_t maxHeld = 0;
    for (size_t off = 0; off < bytes.size(); off += piece) {
      const size_t n = std::min(piece, bytes.size() - off);
      h.session->feed(bytes.data() + off, n, 1000);
      if (pauseFrom == 0) maxHeld = std::max(maxHeld, h.session->inputHeld());
      // A host that stopped the session lets it go on before the next read.
      while (h.session->paused()) {
        h.session->resume();
        h.session->feed("", 0, 1000);
      }
      out += h.session->out();
      h.session->out().clear();
    }
    std::string summary = out;
    for (const Seen& r : h.requests) summary += "|" + std::to_string(r.id) + r.path + "#" + r.body;
    CHECK(!h.session->dead());
    CHECK(h.requests.size() == 4);
    // Never more waiting than a frame that has to be whole: here the padded
    // one (3,017 bytes), far below a DATA frame of 16 KiB.
    if (pauseFrom == 0) CHECK(maxHeld < 3100);
    return summary;
  };
  const std::string whole = run(bytes.size(), 0);
  {
    Harness h(s);
    h.feed(bytes);
    CHECK(h.requests.size() == 4);
    if (h.requests.size() == 4) {
      CHECK(h.requests[0].id == 1 && h.requests[0].body == body(9000, 'a') + body(3000, 'b') + body(5000, 'c'));
      CHECK(h.requests[1].id == 3 && h.requests[1].body == body(16384, 'k') + body(100, 'l'));
      CHECK(h.requests[2].id == 9 && h.requests[2].body == body(1, 'r') + body(16384, 's') + body(3615, 't'));
      CHECK(h.requests[3].id == 13 && h.requests[3].body.empty());
    }
  }
  for (size_t piece : {size_t(1), size_t(2), size_t(3), size_t(5), size_t(8), size_t(9), size_t(10), size_t(13),
                       size_t(100), size_t(1000), size_t(4096), size_t(16384), size_t(16393), size_t(16394), size_t(40000)}) {
    CHECK(run(piece, 0) == whole);
    CHECK(run(piece, 1) == whole);  // ...and when the host stops the session at every request
  }

  // A connection error found in a frame's header is raised when the header
  // arrives, with the same code as when the frame arrives whole.
  for (const size_t cut : {size_t(9), size_t(10), size_t(5000)}) {
    Harness h;
    h.open();
    const std::string onIdle = frame(kData, 0, 5, std::string(6000, 'x'));
    const std::vector<Frame> out = h.feed(onIdle.substr(0, cut));
    CHECK(h.session->dead() && goawayCode(out) == kProtocolError);
  }
  {
    Settings small;
    small.initialWindowSize = 1000;
    Harness h(small);
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1, head(post)));
    const std::string over = frame(kData, 0, 1, std::string(1001, 'x'));
    const std::vector<Frame> out = h.feed(over.substr(0, 20));
    CHECK(rstCode(out, 1) == kFlowControlError && !h.session->dead());
    h.feed(over.substr(20));  // read past
    const std::vector<Frame> next = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(get())));
    CHECK(h.requests.size() == 1 && h.requests[0].id == 3 && !h.session->dead());
  }
}

// A request's declared Content-Length is not room set aside when its header
// block arrives: the buffer follows what has been received until a sixteenth
// of the declared length is in, and is then reserved once.
static void sessionDeclaredLength() {
  const size_t kSize = 10 * 1024 * 1024;  // the default body limit
  Harness h;
  h.open();
  Fields f = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}};
  f.emplace_back("content-length", std::to_string(kSize));
  // 64 streams, each declaring the limit and sending nothing: no buffer.
  gLargestAlloc = 0;
  for (uint32_t i = 0; i < 64; i++) h.feed(frame(kHeaders, kFlagEndHeaders, 1 + 2 * i, head(f)));
  CHECK(h.session->streamCount() == 64);
  CHECK(gLargestAlloc < 65536);
  // ...nor for one byte each.
  for (uint32_t i = 0; i < 64; i++) h.feed(frame(kData, 0, 1 + 2 * i, "x"));
  CHECK(gLargestAlloc < 65536);
  for (uint32_t i = 1; i < 64; i++) h.feed(frame(kRstStream, 0, 1 + 2 * i, u32(kCancel)));

  // The first stream goes on. Up to a sixteenth of the body the buffer stays
  // within a small multiple of what was received.
  std::string chunk(16384, '\0');
  size_t sent = 1;
  bool proportionate = true;
  auto fill = [&](size_t at) {
    for (size_t i = 0; i < chunk.size(); i++) chunk[i] = static_cast<char>('a' + (at + i) % 23);
  };
  while (sent + chunk.size() < kSize / 16) {
    fill(sent);
    h.feed(frame(kData, 0, 1, chunk));
    sent += chunk.size();
    proportionate = proportionate && gLargestAlloc <= 4 * sent + 65536;
  }
  CHECK(proportionate);
  // From there it is reserved in full, once: no further growth however many
  // frames the body takes.
  fill(sent);
  h.feed(frame(kData, 0, 1, chunk));
  sent += chunk.size();
  CHECK(gLargestAlloc >= kSize);
  gLargeAllocs = 0;
  size_t bodyAllocs = 0;
  while (sent < kSize) {
    const size_t n = std::min(chunk.size(), kSize - sent);
    fill(sent);
    const size_t before = gLargeAllocs;
    h.session->feed(frame(kData, sent + n == kSize ? kFlagEndStream : 0, 1, chunk.substr(0, n)).data(), 9 + n, 1000);
    // (the harness's own copies of the request are not the session's)
    if (sent + n < kSize) bodyAllocs += gLargeAllocs - before;
    h.session->out().clear();
    sent += n;
  }
  CHECK(bodyAllocs == 0);
  // A body of up to 64 KiB has its room from the header block on: nothing
  // is allocated for it while it arrives.
  {
    Fields small = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/small"}};
    small.emplace_back("content-length", "65536");
    gLargestAlloc = 0;
    h.session->feed(frame(kHeaders, kFlagEndHeaders, 201, head(small)).data(), 9 + head(small).size(), 1000);
    CHECK(gLargestAlloc >= 65536 && gLargestAlloc < 2 * 65536);
    const std::string part = frame(kData, 0, 201, std::string(16384, 's'));
    gLargeAllocs = 0;
    for (int i = 0; i < 3; i++) h.session->feed(part.data(), part.size(), 1000);
    CHECK(gLargeAllocs == 0);
    Fields over = small;
    over.back().second = "65537";  // one byte more: it waits, like any large body
    gLargestAlloc = 0;
    h.session->feed(frame(kHeaders, kFlagEndHeaders, 203, head(over)).data(), 9 + head(over).size(), 1000);
    CHECK(gLargestAlloc < 4096);
    h.feed(frame(kRstStream, 0, 201, u32(kCancel)) + frame(kRstStream, 0, 203, u32(kCancel)));
    h.session->out().clear();
  }
  // A body with no declared length grows through the same sizes however the
  // reads cut its frames: 1 MiB arriving 5,000 bytes at a time ends in a
  // buffer of 1 MiB, as it does arriving frame by frame.
  {
    Harness g;
    g.open();
    g.feed(frame(kHeaders, kFlagEndHeaders, 1, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/grow"}})));
    std::string wire;
    for (int i = 0; i < 64; i++) wire += frame(kData, i == 63 ? kFlagEndStream : 0, 1, std::string(16384, static_cast<char>('a' + i % 26)));
    gLargestAlloc = 0;
    size_t largestWhileArriving = 0;
    for (size_t off = 0; off < wire.size(); off += 5000) {
      g.session->feed(wire.data() + off, std::min<size_t>(5000, wire.size() - off), 1000);
      g.session->out().clear();
      if (g.requests.empty()) largestWhileArriving = gLargestAlloc;
    }
    CHECK(largestWhileArriving >= (1u << 20) - 16384 && largestWhileArriving <= (1u << 20) + 64);
    CHECK(g.requests.size() == 1 && g.requests[0].body.size() == (1u << 20));
  }
  CHECK(h.requests.size() == 1 && h.requests[0].body.size() == kSize);
  bool intact = h.requests.size() == 1 && h.requests[0].body[0] == 'x';
  for (size_t i = 1; intact && i < kSize; i += 4099) intact = h.requests[0].body[i] == static_cast<char>('a' + i % 23);
  CHECK(intact);
  CHECK(!h.session->dead());
}

// A host told in place that a stream has room may end the response there and
// then. The stream is released inside that call - and, with the session's
// spare streams all in use, freed - so nothing after the call may read it:
// not the window update that drained it, not the pass over the streams that
// were waiting.
static void sessionHostEndsInWritable() {
  for (const bool byConnection : {false, true}) {
    Settings s;
    Harness h(s);
    // The client's stream window is zero (or, for the connection case, large
    // with the connection's own window left at its 65,535).
    h.feed(std::string(kPreface) + frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(byConnection ? (1u << 24) : 0)));
    h.take();
    // 200 requests left waiting for a body, then the one under test, then
    // the 200 completed and answered: more streams released than the session
    // keeps spare, so the next one released is freed.
    h.hold = true;
    std::string wire;
    for (uint32_t i = 0; i < 200; i++)
      wire += frame(kHeaders, kFlagEndHeaders, 1 + 2 * i, head({{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/s"}}));
    const uint32_t target = 401;
    wire += frame(kHeaders, kFlagEndHeaders | kFlagEndStream, target, head(get("/t")));
    h.feed(wire);
    CHECK(h.heldStreams.size() == 1);
    Stream* t = h.heldStreams.empty() ? nullptr : h.heldStreams[0];
    if (t == nullptr) continue;
    std::string block;
    encodeStatus(block, 200);
    h.session->sendHeaders(*t, block, false);
    const std::string body(400000, 'a');
    const size_t heldBack = h.session->sendData(*t, body.data(), body.size(), false);
    CHECK(heldBack > 300000);
    t->wantDrain = true;
    h.take();
    h.heldStreams.clear();
    for (uint32_t i = 0; i < 200; i++) {
      h.feed(frame(kData, kFlagEndStream, 1 + 2 * i, ""));
      if (!h.heldStreams.empty()) {
        h.answer(*h.heldStreams.back());
        h.heldStreams.pop_back();
      }
    }
    h.take();
    CHECK(h.session->streamCount() == 1 && h.session->held() == 1);

    h.endOnWritable = true;
    std::vector<Frame> out;
    if (byConnection) {
      out = h.feed(frame(kWindowUpdate, 0, 0, u32(1u << 22)));
    } else {
      h.feed(frame(kWindowUpdate, 0, 0, u32(1u << 20)));
      out = h.feed(frame(kWindowUpdate, 0, target, u32(1u << 20)));
    }
    size_t bytes = 0;
    bool ended = false;
    for (const Frame& f : out) {
      if (f.type == kData && f.stream == target) {
        bytes += f.payload.size();
        ended = ended || (f.flags & kFlagEndStream) != 0;
      }
    }
    CHECK(h.writable.size() == 1);
    CHECK(bytes >= heldBack + 4 && ended);  // what was held back, and the host's last piece
    CHECK(h.session->streamCount() == 0 && h.session->held() == 0 && h.session->heldBytes() == 0);
    CHECK(!h.session->dead());
    // The session goes on: another window update, another request.
    h.endOnWritable = false;
    h.hold = false;
    h.feed(frame(kWindowUpdate, 0, 0, u32(1000)));
    const size_t before = h.requests.size();
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 403, head(get("/next"))));
    CHECK(h.requests.size() == before + 1 && !h.session->dead());
  }
}

// WINDOW_UPDATE frames beyond what the peer was sent and asked for draw on the
// budget for frames that cost it nothing; the ones a client sends as it opens
// streams and takes in DATA never do.
static void sessionWindowUpdateBudget() {
  const std::string okHead = head(get());
  // Nothing sent, nothing asked for: 16 are free, then one unit each, and
  // the connection is ended when the 2000 units are spent.
  {
    Harness h;
    h.open();
    std::string flood;
    for (int i = 0; i < 16 + 1 + 2000; i++) flood += frame(kWindowUpdate, 0, 0, u32(1));
    h.feed(flood);
    CHECK(!h.session->dead());
    const std::vector<Frame> out = h.feed(frame(kWindowUpdate, 0, 0, u32(1)));
    CHECK(h.session->dead() && goawayCode(out) == kEnhanceYourCalm);
  }
  // On a stream that waits with its window shut, as well.
  {
    Settings s;
    Harness h(s);
    h.feed(std::string(kPreface) + frame(kSettings, 0, 0, std::string("\x00\x04", 2) + u32(0)));
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, okHead));
    std::string block;
    encodeStatus(block, 200);
    h.session->sendHeaders(*h.heldStreams[0], block, false);
    const std::string body(100000, 'b');
    h.session->sendData(*h.heldStreams[0], body.data(), body.size(), false);
    h.take();
    std::string flood;
    for (int i = 0; i < 5000; i++) flood += frame(kWindowUpdate, 0, 1, u32(1));
    const std::vector<Frame> out = h.feed(flood);
    CHECK(h.session->dead() && goawayCode(out) == kEnhanceYourCalm);
  }
  // A client that updates both windows for every DATA frame of a 16 MiB
  // response - twice the frames any real one sends - is never charged.
  {
    Harness h;
    h.open();
    h.hold = true;
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, okHead));
    std::string block;
    encodeStatus(block, 200);
    Stream& st = *h.heldStreams[0];
    h.session->sendHeaders(st, block, false);
    const std::string body(16u << 20, 'c');
    h.session->sendData(st, body.data(), body.size(), true);
    size_t got = 0, updates = 0;
    std::vector<Frame> out = h.take();
    for (int round = 0; round < 100000 && !h.session->dead(); round++) {
      std::string acks;
      for (const Frame& f : out) {
        if (f.type != kData || f.payload.empty()) continue;
        got += f.payload.size();
        acks += frame(kWindowUpdate, 0, 0, u32(static_cast<uint32_t>(f.payload.size())));
        acks += frame(kWindowUpdate, 0, 1, u32(static_cast<uint32_t>(f.payload.size())));
        updates += 2;
      }
      if (acks.empty()) break;
      out = h.feed(acks);
    }
    CHECK(got == body.size() && updates > 2000 && !h.session->dead());
  }
  // ...nor is one that sends a WINDOW_UPDATE with every request it opens,
  // for however many requests, whatever the size of the answers.
  {
    Harness h;
    h.open();
    h.hold = true;
    for (uint32_t i = 0; i < 6000 && !h.session->dead(); i++) {
      const uint32_t id = 1 + 2 * i;
      h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, id, okHead) + frame(kWindowUpdate, 0, id, u32(1u << 20)));
      h.answer(*h.heldStreams.back());
      h.heldStreams.pop_back();
      h.take();
    }
    CHECK(!h.session->dead() && h.requests.size() == 6000);
  }
}

// What a connection has set aside for request bodies is bounded as what it
// has received is: a declared length is reserved in full only while the
// connection's reserved total stays within its buffering bound.
static void sessionReservedBodies() {
  const size_t kMiB = 1024 * 1024;
  Harness h;  // body limit 10 MiB, bound on buffered bodies 32 MiB
  h.open();
  Fields f = {{":method", "POST"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/up"}};
  f.emplace_back("content-length", std::to_string(10 * kMiB));
  const size_t before = gLiveBytes;
  for (uint32_t i = 0; i < 48; i++) h.feed(frame(kHeaders, kFlagEndHeaders, 1 + 2 * i, head(f)));
  const std::string chunk(16384, 'u');
  size_t sent = 0;
  for (size_t off = 0; off < 10 * kMiB / 16 + 16384; off += chunk.size()) {
    for (uint32_t i = 0; i < 48; i++) {
      h.session->feed(frame(kData, 0, 1 + 2 * i, chunk).data(), 9 + chunk.size(), 1000);
      sent += chunk.size();
    }
    h.session->out().clear();
  }
  CHECK(!h.session->dead() && h.session->streamCount() == 48);
  const size_t held = gLiveBytes - before;
  // 30.8 MiB received. Reserved in full for each, that was 480 MiB.
  CHECK(sent > 30 * kMiB && sent < 32 * kMiB);
  CHECK(held >= sent && held < 100 * kMiB);
  // The first streams did get their declared length in one piece...
  CHECK(gLargestAlloc >= 10 * kMiB);
  // ...and every body is still whole when its request completes.
  h.hold = false;
  size_t whole = 0;
  for (uint32_t i = 0; i < 48; i++) {
    const uint32_t id = 1 + 2 * i;
    h.feed(frame(kRstStream, 0, id, u32(kCancel)));
  }
  CHECK(h.session->streamCount() == 0);
  // Released with the streams: a second round reserves as the first did.
  const size_t after = gLiveBytes;
  CHECK(after < before + 8 * kMiB);
  for (uint32_t i = 48; i < 52; i++) h.feed(frame(kHeaders, kFlagEndHeaders, 1 + 2 * i, head(f)));
  gLargeAllocs = 0;
  gLargestAlloc = 0;
  for (size_t off = 0; off < 10 * kMiB / 16 + 16384; off += chunk.size()) {
    for (uint32_t i = 48; i < 52; i++) h.session->feed(frame(kData, 0, 1 + 2 * i, chunk).data(), 9 + chunk.size(), 1000);
    h.session->out().clear();
  }
  CHECK(gLargestAlloc >= 10 * kMiB && !h.session->dead());
  (void)whole;
}

// Cookie fields are one field to the application (RFC 9113 8.2.3), and an
// authority is never empty.
static void sessionCookieAndAuthority() {
  auto seen = [](const Fields& extra, Settings s = Settings()) {
    Harness h(s);
    h.open();
    Fields f = get("/c");
    for (const auto& e : extra) f.push_back(e);
    const std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(f)));
    if (h.requests.size() != 1) return Fields{{"status", statusOn(out, 1)}, {"rst", std::to_string(rstCode(out, 1))}};
    return h.requests[0].headers;
  };
  CHECK(seen({{"cookie", "a=1"}}) == (Fields{{"cookie", "a=1"}, {"host", "example.test"}}));
  CHECK(seen({{"cookie", "a=1"}, {"x-between", "1"}, {"cookie", "b=2"}, {"cookie", "c=3; d=4"}}) ==
        (Fields{{"cookie", "a=1; b=2; c=3; d=4"}, {"x-between", "1"}, {"host", "example.test"}}));
  CHECK(seen({{"cookie", ""}, {"cookie", "b=2"}, {"cookie", ""}}) == (Fields{{"cookie", "b=2"}, {"host", "example.test"}}));
  CHECK(seen({{"cookie", ""}}) == (Fields{{"cookie", ""}, {"host", "example.test"}}));
  // However many fields it came in, it is one of the headers counted.
  {
    Settings s;
    s.maxHeaders = 3;
    Fields many;
    for (int i = 0; i < 20; i++) many.emplace_back("cookie", "k" + std::to_string(i) + "=v");
    many.emplace_back("x-a", "1");
    many.emplace_back("x-b", "2");
    const Fields got = seen(many, s);
    CHECK(got.size() == 4 && got[0].first == "cookie" && got[0].second.size() > 20 * 5 && got[1].first == "x-a" &&
          got[2] == (Fields::value_type{"x-b", "2"}) && got[3].first == "host");
    // The joined field stands where the first of them stood, the fields around it as they were.
    CHECK(seen({{"x-first", "1"}, {"cookie", "a=1"}, {"x-mid", "22"}, {"cookie", "b=2"}, {"x-last", ""}, {"cookie", "c=3"}}) ==
          (Fields{{"x-first", "1"}, {"cookie", "a=1; b=2; c=3"}, {"x-mid", "22"}, {"x-last", ""}, {"host", "example.test"}}));
    many.emplace_back("x-c", "3");
    CHECK(seen(many, s) == (Fields{{"status", "431"}, {"rst", std::to_string(0xffffffffu)}}));
  }
  // A control byte in any one of them still makes the request malformed.
  CHECK(seen({{"cookie", "a=1"}, {"cookie", std::string("b=\x01")}}) == (Fields{{"status", ""}, {"rst", std::to_string(kProtocolError)}}));

  // An empty :authority, and an empty Host, with or without the other.
  auto refused = [](const Fields& fields) {
    Harness h;
    h.open();
    const std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, head(fields)));
    return h.requests.empty() && rstCode(out, 1) == kProtocolError && !h.session->dead();
  };
  const Fields base = {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}};
  auto with = [&base](const Fields& extra) {
    Fields f = base;
    for (const auto& e : extra) f.push_back(e);
    return f;
  };
  CHECK(refused(with({{":authority", ""}})));
  CHECK(refused(with({{":authority", ""}, {"host", "evil.test"}})));
  CHECK(refused(with({{"host", ""}})));
  CHECK(refused(with({{":authority", "a.test"}, {"host", ""}})));
  CHECK(!refused(with({{":authority", "a.test"}})));
  CHECK(!refused(with({{"host", "a.test"}})));
  // An http or https request names its authority, in one field or the other
  // (RFC 9110 7.2): with neither it is malformed, whatever the target.
  CHECK(refused(base));
  CHECK(refused({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}}));
  CHECK(refused({{":method", "GET"}, {":scheme", "HTTPS"}, {":path", "/"}, {"accept", "*/*"}}));
  CHECK(refused({{":method", "OPTIONS"}, {":scheme", "https"}, {":path", "*"}}));
  CHECK(!refused({{":method", "OPTIONS"}, {":scheme", "https"}, {":path", "*"}, {":authority", "a.test"}}));
  CHECK(!refused({{":method", "OPTIONS"}, {":scheme", "http"}, {":path", "*"}, {"host", "a.test"}}));
  // ...and however the scheme is spelled: as an entry of the static table
  // (0x86 http, 0x87 https), which is how nearly every client sends it.
  for (const char* block : {"\x82\x86\x84", "\x82\x87\x84"}) {
    Harness h;
    h.open();
    const std::vector<Frame> out = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1, block));
    CHECK(h.requests.empty() && rstCode(out, 1) == kProtocolError && !h.session->dead());
    const std::string named = std::string(block) + std::string("\x01\x06" "a.test", 8);  // :authority a.test
    const std::vector<Frame> out2 = h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, named));
    CHECK(h.requests.size() == 1 && rstCode(out2, 3) != kProtocolError);
  }
  // A scheme of another kind may have no authority, and is left alone.
  for (const char* scheme : {"urn", "file", "httpx", "htt", "ws"}) {
    CHECK(!refused({{":method", "GET"}, {":scheme", scheme}, {":path", "/"}}));
  }
}

int main(int argc, char** argv) {
  const char* vectors = argc > 1 ? argv[1] : "test/fixtures/hpack-vectors.txt";
  hpackVectors(vectors);
  hpackUnits();
  sessionBasics();
  sessionFlowControl();
  sessionErrors();
  sessionLimits();
  sessionSplitting();
  sessionBudget();
  sessionBounds();
  sessionBuffering();
  sessionHttp1Parity();
  sessionPausing();
  sessionDataInPieces();
  sessionDeclaredLength();
  sessionHostEndsInWritable();
  sessionWindowUpdateBudget();
  sessionReservedBodies();
  sessionCookieAndAuthority();

  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all HTTP/2 unit tests passed (%d checks)\n", checks);
  return 0;
}
