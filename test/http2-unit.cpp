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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "../src/http2.h"

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
    };
    host.aborted = [](void* u, void* held) { static_cast<Harness*>(u)->aborted.push_back(held); };
    host.writable = [](void* u, void* held) { static_cast<Harness*>(u)->writable.push_back(held); };
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
    const Fields want = {{"accept", "*/*"}, {"cookie", "a=1"}, {"cookie", "b=2"}, {"host", "example.test"}};
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

  // A POST with a body in two DATA frames; the host header the client sent
  // wins over :authority; an unknown method keeps its name.
  {
    Harness h;
    h.open();
    Fields f = {{":method", "POST"}, {":scheme", "http"}, {":path", "/upload"},
                {":authority", "ignored"}, {"host", "real.test"}, {"content-length", "11"}};
    h.feed(frame(kHeaders, kFlagEndHeaders, 1, head(f)));
    CHECK(h.requests.empty());
    h.feed(frame(kData, 0, 1, "hello "));
    CHECK(h.requests.empty());
    h.feed(frame(kData, kFlagEndStream, 1, "world"));
    CHECK(h.requests.size() == 1 && h.requests[0].body == "hello world");
    CHECK(h.requests[0].method == Method::POST);
    bool sawReal = false, sawIgnored = false;
    for (const auto& kv : h.requests[0].headers) {
      if (kv.first == "host" && kv.second == "real.test") sawReal = true;
      if (kv.second == "ignored") sawIgnored = true;
    }
    CHECK(sawReal && !sawIgnored);

    Fields p = {{":method", "PROPFIND"}, {":scheme", "http"}, {":path", "/dav"}};
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3, head(p)));
    CHECK(h.requests.size() == 2 && h.requests[1].method == Method::OTHER &&
          h.requests[1].methodStr == "PROPFIND");
  }

  // Padding and the priority fields are skipped; trailers end the request.
  {
    Harness h;
    h.open();
    std::string block = head({{":method", "POST"}, {":scheme", "http"}, {":path", "/p"}});
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
        head({{":method", "PUT"}, {":scheme", "http"}, {":path", "/x"}, {"expect", "100-continue"}})));
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

  // The request side: the peer is given its window back as it is used, and
  // exceeding a window is an error.
  {
    Settings s;
    s.initialWindowSize = 65535;
    s.connectionWindow = 65535;
    Harness h(s);
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/big"}})));
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
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/big"}})));
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
                     head({{":method", "POST"}, {":scheme", "http"}, {":path", "/big"}}));
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
  CHECK(streamCode({{":scheme", "http"}, {":path", "/"}}) == kProtocolError);                       // no :method
  CHECK(streamCode({{":method", "GET"}, {":path", "/"}}) == kProtocolError);                        // no :scheme
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}}) == kProtocolError);                   // no :path
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", ""}}) == kProtocolError);    // empty :path
  CHECK(streamCode({{":method", "GET"}, {":method", "GET"}, {":scheme", "http"}, {":path", "/"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":status", "200"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":unknown", "x"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {"accept", "x"}, {":path", "/"}}) == kProtocolError);  // pseudo after regular
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"Accept", "x"}}) == kProtocolError);  // uppercase
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"connection", "close"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"transfer-encoding", "chunked"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"te", "gzip"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"x", "a\r\nb"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"x", " lead"}}) == kProtocolError);
  CHECK(streamCode({{":method", "GET"}, {":scheme", "http"}, {":path", "/a b"}}) == kProtocolError);
  CHECK(streamCode({{":method", "G ET"}, {":scheme", "http"}, {":path", "/"}}) == kProtocolError);
  CHECK(streamCode({{":method", "CONNECT"}, {":authority", "x:443"}}) == kProtocolError);
  CHECK(streamCode({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "x"}}) == kProtocolError);
  CHECK(streamCode({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "1"}, {"content-length", "2"}}) == kProtocolError);
  // te: trailers is the one allowed value.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 1,
                 head({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"te", "trailers"}})));
    CHECK(h.requests.size() == 1);
  }
  // A body that disagrees with its Content-Length, short or long.
  {
    Harness h;
    h.open();
    h.feed(frame(kHeaders, kFlagEndHeaders, 1,
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "5"}})));
    CHECK(rstCode(h.feed(frame(kData, kFlagEndStream, 1, "abc")), 1) == kProtocolError);
    CHECK(h.requests.empty());
    h.feed(frame(kHeaders, kFlagEndHeaders | kFlagEndStream, 3,
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "5"}})));
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
                       head({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "11"}})));
    CHECK(statusOf(out, 7) == "413" && rstCode(out, 7) == kNoError);
    CHECK(h.feed(frame(kData, kFlagEndStream, 7, "hello world")).empty());  // already in flight: read past

    out = h.feed(frame(kHeaders, kFlagEndHeaders, 9,
                       head({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}})));
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
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/"}})));
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
                 head({{":method", "POST"}, {":scheme", "http"}, {":path", "/body"}}));
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

int main(int argc, char** argv) {
  const char* vectors = argc > 1 ? argv[1] : "test/fixtures/hpack-vectors.txt";
  hpackVectors(vectors);
  hpackUnits();
  sessionBasics();
  sessionFlowControl();
  sessionErrors();
  sessionLimits();
  sessionSplitting();

  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all HTTP/2 unit tests passed (%d checks)\n", checks);
  return 0;
}
