// websocket-unit.cpp — standalone unit tests for src/sha1.h and
// src/websocket.h.
//
// Build and run:
//   clang++ -std=c++20 test/websocket-unit.cpp -o /tmp/wstest && /tmp/wstest
//
// Test vectors come from FIPS 180-4 / NIST examples (SHA-1), RFC 4648 §10
// (base64), and RFC 6455 §1.3 / §5.7 (handshake and masking examples).

#undef NDEBUG
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "../src/sha1.h"
#include "../src/websocket.h"

using namespace moro::engine;

static int gChecks = 0;
#define CHECK(cond)      \
  do {                   \
    assert(cond);        \
    ++gChecks;           \
  } while (0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string toHex(const uint8_t* d, size_t n) {
  static const char* k = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) {
    s += k[d[i] >> 4];
    s += k[d[i] & 15];
  }
  return s;
}

static std::string sha1Hex(std::string_view msg) {
  uint8_t digest[20];
  sha1(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), digest);
  return toHex(digest, sizeof(digest));
}

static std::string b64(std::string_view msg) {
  return base64(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

// Records every parser callback, in order, so tests can assert on the exact
// event sequence (e.g. a ping surfacing between fragments of a message).
struct Events {
  struct Item {
    bool isControl;
    WsOpcode op;      // meaningful when isControl
    std::string payload;
    bool isBinary;    // meaningful when !isControl
    bool compressed = false;  // RFC 7692 RSV1 marker
  };
  std::vector<Item> items;

  WsParser::MessageFn onMessage() {
    return [this](std::string_view p, bool bin, bool compressed) {
      items.push_back({false, WsOpcode::Text, std::string(p), bin, compressed});
    };
  }
  WsParser::ControlFn onControl() {
    return [this](WsOpcode op, std::string_view p) {
      items.push_back({true, op, std::string(p), false});
    };
  }
};

// Feed bytes into the parser in chunks of at most chunkSize (SIZE_MAX = all
// at once). Returns false as soon as consume() reports a protocol error.
// consume() unmasks complete frames in place (zero-copy receive), so it
// takes mutable bytes: feed from a scratch copy, like the server's read
// buffer. Tests that assert on the in-place mutation call consume() on
// their own buffer directly.
static bool feed(WsParser& p, std::string_view bytes, Events& ev,
                 size_t chunkSize = size_t(-1)) {
  std::string buf(bytes);
  size_t i = 0;
  if (buf.empty()) {
    return p.consume(nullptr, 0, ev.onMessage(), ev.onControl());
  }
  while (i < buf.size()) {
    const size_t n = std::min(chunkSize, buf.size() - i);
    if (!p.consume(reinterpret_cast<uint8_t*>(buf.data()) + i, n,
                   ev.onMessage(), ev.onControl())) {
      return false;
    }
    i += n;
  }
  return true;
}

// Turn an unmasked (server-form) frame produced by encodeFrame into a masked
// client-form frame: set the MASK bit, insert the 4-byte key after the
// length field, and XOR-mask the payload (RFC 6455 §5.3). Test-side helper
// so all client frames are derived from our own encoder.
static std::string maskFrame(std::string_view serverFrame,
                             const uint8_t key[4]) {
  const uint8_t len7 = uint8_t(serverFrame[1]) & 0x7F;
  const size_t hdrLen = 2 + (len7 == 126 ? 2 : (len7 == 127 ? 8 : 0));
  std::string out;
  out.reserve(serverFrame.size() + 4);
  out += serverFrame[0];
  out += char(uint8_t(serverFrame[1]) | 0x80);  // set MASK bit (§5.2)
  out.append(serverFrame.substr(2, hdrLen - 2));  // extended length, verbatim
  out.append(reinterpret_cast<const char*>(key), 4);
  const std::string_view payload = serverFrame.substr(hdrLen);
  for (size_t j = 0; j < payload.size(); ++j) {
    out += char(uint8_t(payload[j]) ^ key[j & 3]);
  }
  return out;
}

static const uint8_t kKey[4] = {0x11, 0xC2, 0x3A, 0x7F};

static std::string clientFrame(WsOpcode op, std::string_view payload,
                               bool fin = true) {
  std::string server;
  encodeFrame(server, op, payload, fin);
  return maskFrame(server, kKey);
}

// A byte sequence must make the parser fail, and the parser must stay
// failed on subsequent input.
static bool rejects(std::string_view bytes, WsParser::Limits limits = {}) {
  WsParser p(limits);
  Events ev;
  if (feed(p, bytes, ev)) return false;  // was accepted: not rejected
  uint8_t zero = 0;
  if (p.consume(&zero, 1, ev.onMessage(), ev.onControl())) return false;
  return true;
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4) and base64 (RFC 4648 §10) vectors
// ---------------------------------------------------------------------------

static void testSha1() {
  // FIPS 180-4 / NIST SHA-1 example: one-block message "abc".
  CHECK(sha1Hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d");
  // NIST SHA-1 example: two-block message (56 bytes forces two-block padding).
  CHECK(sha1Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  // NIST long-message vector: one million repetitions of 'a'.
  CHECK(sha1Hex(std::string(1000000, 'a')) ==
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
  // Empty message (block consists of padding only).
  CHECK(sha1Hex("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  std::printf("ok  sha1 (FIPS 180-4 vectors)\n");
}

static void testBase64() {
  // RFC 4648 §10 test vectors.
  CHECK(b64("") == "");
  CHECK(b64("f") == "Zg==");
  CHECK(b64("fo") == "Zm8=");
  CHECK(b64("foo") == "Zm9v");
  CHECK(b64("foob") == "Zm9vYg==");
  CHECK(b64("fooba") == "Zm9vYmE=");
  CHECK(b64("foobar") == "Zm9vYmFy");
  std::printf("ok  base64 (RFC 4648 vectors)\n");
}

// ---------------------------------------------------------------------------
// Handshake (RFC 6455 §1.3 / §4.2.2)
// ---------------------------------------------------------------------------

static void testHandshake() {
  // RFC 6455 §1.3 worked example.
  CHECK(computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") ==
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  CHECK(buildHandshakeResponse("dGhlIHNhbXBsZSBub25jZQ==") ==
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "\r\n");
  std::printf("ok  handshake accept key (RFC 6455 section 1.3 example)\n");
}

static void testWsKeyValidation() {
  // §4.1: the key is the base64 of a 16-byte nonce - exactly 24 bytes,
  // 22 alphabet chars + "==" padding.
  CHECK(isValidWsKey("dGhlIHNhbXBsZSBub25jZQ=="));    // RFC 6455 §1.3 example
  CHECK(isValidWsKey("AAAAAAAAAAAAAAAAAAAAAA=="));
  CHECK(isValidWsKey("a1+/a1+/a1+/a1+/a1+/a1=="));    // alphabet incl. + and /
  CHECK(!isValidWsKey(""));                           // empty
  CHECK(!isValidWsKey("short"));                      // wrong length
  CHECK(!isValidWsKey("dGhlIHNhbXBsZSBub25jZQ="));    // 23 bytes
  CHECK(!isValidWsKey("dGhlIHNhbXBsZSBub25jZQ===")); // 25 bytes
  CHECK(!isValidWsKey("dGhlIHNhbXBsZSBub25jZQAA"));   // missing "==" padding
  CHECK(!isValidWsKey("dGhlIHNhbXBsZSBub2 jZQ=="));   // space mid-key
  CHECK(!isValidWsKey("dGhlIHNhbXBsZSBub25j-Q=="));   // '-' not in base64
  CHECK(!isValidWsKey("\001GhlIHNhbXBsZSBub25jZQ=="));  // control byte
  std::printf("ok  Sec-WebSocket-Key shape validation (section 4.1)\n");
}

// ---------------------------------------------------------------------------
// Encoder wire format (§5.2 length encodings)
// ---------------------------------------------------------------------------

static void testEncoderWireFormat() {
  // 7-bit length, FIN text frame.
  std::string f;
  encodeFrame(f, WsOpcode::Text, "Hello");
  CHECK(f.size() == 2 + 5);
  CHECK(uint8_t(f[0]) == 0x81);  // FIN | text
  CHECK(uint8_t(f[1]) == 0x05);  // no MASK bit, length 5
  CHECK(f.substr(2) == "Hello");

  // Boundary: 125 stays in the 7-bit field.
  f.clear();
  encodeFrame(f, WsOpcode::Binary, std::string(125, 'x'));
  CHECK(f.size() == 2 + 125 && uint8_t(f[1]) == 125);

  // 126 -> 16-bit extended length, big-endian.
  f.clear();
  encodeFrame(f, WsOpcode::Binary, std::string(126, 'x'));
  CHECK(f.size() == 4 + 126);
  CHECK(uint8_t(f[1]) == 126 && uint8_t(f[2]) == 0x00 && uint8_t(f[3]) == 0x7E);

  // Boundary: 65535 is the largest 16-bit length.
  f.clear();
  encodeFrame(f, WsOpcode::Binary, std::string(65535, 'x'));
  CHECK(f.size() == 4 + 65535 && uint8_t(f[1]) == 126);
  CHECK(uint8_t(f[2]) == 0xFF && uint8_t(f[3]) == 0xFF);

  // 65536 -> 64-bit extended length, big-endian, MSB clear (§5.2).
  f.clear();
  encodeFrame(f, WsOpcode::Binary, std::string(65536, 'x'));
  CHECK(f.size() == 10 + 65536 && uint8_t(f[1]) == 127);
  const uint8_t ext[8] = {0, 0, 0, 0, 0, 1, 0, 0};
  for (int j = 0; j < 8; ++j) CHECK(uint8_t(f[2 + j]) == ext[j]);

  // Non-final fragment has FIN clear (§5.4).
  f.clear();
  encodeFrame(f, WsOpcode::Text, "Hel", /*fin=*/false);
  CHECK(uint8_t(f[0]) == 0x01);

  std::printf("ok  encoder wire format (7/16/64-bit lengths)\n");
}

// ---------------------------------------------------------------------------
// Known masked vector (§5.7 example)
// ---------------------------------------------------------------------------

static void testKnownMaskedVector() {
  // RFC 6455 §5.7: a single-frame masked text message containing "Hello".
  // (Mutable: the zero-copy fast path unmasks the payload in this buffer.)
  uint8_t wire[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                    0x7f, 0x9f, 0x4d, 0x51, 0x58};
  WsParser p;
  Events ev;
  CHECK(p.consume(wire, sizeof(wire), ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 1);
  CHECK(!ev.items[0].isControl);
  CHECK(!ev.items[0].isBinary);
  CHECK(ev.items[0].payload == "Hello");
  // In-place contract: the wire buffer now holds the unmasked payload.
  CHECK(std::memcmp(wire + 6, "Hello", 5) == 0);
  std::printf("ok  masked decode (RFC 6455 section 5.7 \"Hello\" vector)\n");
}

// ---------------------------------------------------------------------------
// Encode -> mask -> decode round trips at all three length encodings
// ---------------------------------------------------------------------------

static void roundTripData(WsOpcode op, const std::string& payload) {
  WsParser p;
  Events ev;
  CHECK(feed(p, clientFrame(op, payload), ev));
  CHECK(ev.items.size() == 1);
  CHECK(!ev.items[0].isControl);
  CHECK(ev.items[0].isBinary == (op == WsOpcode::Binary));
  CHECK(ev.items[0].payload == payload);
}

static void roundTripControl(WsOpcode op, const std::string& payload) {
  WsParser p;
  Events ev;
  CHECK(feed(p, clientFrame(op, payload), ev));
  CHECK(ev.items.size() == 1);
  CHECK(ev.items[0].isControl);
  CHECK(ev.items[0].op == op);
  CHECK(ev.items[0].payload == payload);
}

static void testRoundTrips() {
  // Text at 7-, 16-, and 64-bit lengths (valid UTF-8 required, §5.6).
  // Delivered whole in one consume() call, these exercise the zero-copy
  // fast path (size 0 completes at the mask key, before any payload state).
  roundTripData(WsOpcode::Text, "");
  roundTripData(WsOpcode::Text, "a");
  roundTripData(WsOpcode::Text, "morojs");
  roundTripData(WsOpcode::Text, std::string(125, 't'));
  roundTripData(WsOpcode::Text, std::string(126, 't'));
  roundTripData(WsOpcode::Text, std::string(300, 't'));
  roundTripData(WsOpcode::Text, std::string(65535, 't'));
  roundTripData(WsOpcode::Text, std::string(65536, 't'));
  roundTripData(WsOpcode::Text, std::string(70000, 't'));

  // Multibyte UTF-8 content survives the trip intact.
  roundTripData(WsOpcode::Text, "caf\xC3\xA9 \xE2\x9C\x93 \xF0\x9F\x8C\x8D");

  // Binary at all three length encodings, with all byte values present.
  std::string bin;
  for (int j = 0; j < 300; ++j) bin += char(uint8_t(j & 0xFF));
  roundTripData(WsOpcode::Binary, "");
  roundTripData(WsOpcode::Binary, std::string(1, '\x80'));
  roundTripData(WsOpcode::Binary, bin);                       // 16-bit
  roundTripData(WsOpcode::Binary, std::string(80000, '\xFE'));  // 64-bit

  // Control frames (<= 125 bytes, §5.5).
  roundTripControl(WsOpcode::Ping, "");
  roundTripControl(WsOpcode::Ping, "keepalive");
  roundTripControl(WsOpcode::Pong, std::string(125, 'p'));
  std::string closeBody;
  encodeClosePayload(closeBody, 1000, "normal closure");
  roundTripControl(WsOpcode::Close, closeBody);

  std::printf("ok  encode/decode round trips (text/binary/ping/pong/close)\n");
}

// ---------------------------------------------------------------------------
// Close payload helpers (§5.5.1, §7.1.5)
// ---------------------------------------------------------------------------

static void testClosePayload() {
  std::string body;
  encodeClosePayload(body, 1002, "protocol error");
  CHECK(body.size() == 2 + 14);
  CHECK(uint8_t(body[0]) == 0x03 && uint8_t(body[1]) == 0xEA);  // 1002 BE
  CHECK(parseCloseCode(body) == 1002);
  CHECK(body.substr(2) == "protocol error");

  std::string bare;
  encodeClosePayload(bare, 1000, "");
  CHECK(bare.size() == 2 && parseCloseCode(bare) == 1000);

  // §7.1.5: an empty close payload means close code 1005.
  CHECK(parseCloseCode("") == 1005);
  std::printf("ok  close payload helpers (code 1005 on empty, section 7.1.5)\n");
}

// ---------------------------------------------------------------------------
// Fragmentation (§5.4) with an interleaved control frame
// ---------------------------------------------------------------------------

static void testFragmentationWithInterleavedPing() {
  std::string wire;
  wire += clientFrame(WsOpcode::Text, "Hel", /*fin=*/false);
  wire += clientFrame(WsOpcode::Ping, "mid");  // §5.4: allowed mid-message
  wire += clientFrame(WsOpcode::Continuation, "lo", /*fin=*/true);

  WsParser p;
  Events ev;
  CHECK(feed(p, wire, ev));
  CHECK(ev.items.size() == 2);
  // The ping surfaces immediately, BEFORE the reassembled message.
  CHECK(ev.items[0].isControl);
  CHECK(ev.items[0].op == WsOpcode::Ping);
  CHECK(ev.items[0].payload == "mid");
  CHECK(!ev.items[1].isControl);
  CHECK(!ev.items[1].isBinary);
  CHECK(ev.items[1].payload == "Hello");

  // A multi-byte UTF-8 sequence split across the fragment boundary is valid
  // once reassembled (validation runs on the complete message, §5.4/§8.1).
  std::string wire2;
  wire2 += clientFrame(WsOpcode::Text, "caf\xC3", /*fin=*/false);
  wire2 += clientFrame(WsOpcode::Continuation, "\xA9", /*fin=*/true);
  WsParser p2;
  Events ev2;
  CHECK(feed(p2, wire2, ev2));
  CHECK(ev2.items.size() == 1);
  CHECK(ev2.items[0].payload == "caf\xC3\xA9");

  std::printf("ok  fragmentation reassembly with interleaved ping\n");
}

// ---------------------------------------------------------------------------
// Byte-at-a-time incremental feeding of a full conversation
// ---------------------------------------------------------------------------

static void testByteAtATimeConversation() {
  std::string bigText(70000, 'a');            // 64-bit length frame
  std::string binPart(100, '\0');
  for (int j = 0; j < 100; ++j) binPart[j] = char(uint8_t(j));

  std::string wire;
  wire += clientFrame(WsOpcode::Text, "hello world");
  wire += clientFrame(WsOpcode::Binary, binPart, /*fin=*/false);
  wire += clientFrame(WsOpcode::Ping, "p1");  // interleaved mid-fragmentation
  wire += clientFrame(WsOpcode::Continuation, binPart, /*fin=*/false);
  wire += clientFrame(WsOpcode::Continuation, binPart, /*fin=*/true);
  wire += clientFrame(WsOpcode::Text, bigText);
  wire += clientFrame(WsOpcode::Pong, "p2");
  std::string closeBody;
  encodeClosePayload(closeBody, 1001, "going away");
  wire += clientFrame(WsOpcode::Close, closeBody);

  // Every header byte, extended length byte, mask byte, and payload byte
  // arrives in its own consume() call.
  WsParser p;
  Events ev;
  CHECK(feed(p, wire, ev, /*chunkSize=*/1));

  CHECK(ev.items.size() == 6);
  CHECK(!ev.items[0].isControl && !ev.items[0].isBinary &&
        ev.items[0].payload == "hello world");
  CHECK(ev.items[1].isControl && ev.items[1].op == WsOpcode::Ping &&
        ev.items[1].payload == "p1");
  CHECK(!ev.items[2].isControl && ev.items[2].isBinary &&
        ev.items[2].payload == binPart + binPart + binPart);
  CHECK(!ev.items[3].isControl && !ev.items[3].isBinary &&
        ev.items[3].payload == bigText);
  CHECK(ev.items[4].isControl && ev.items[4].op == WsOpcode::Pong &&
        ev.items[4].payload == "p2");
  CHECK(ev.items[5].isControl && ev.items[5].op == WsOpcode::Close);
  CHECK(parseCloseCode(ev.items[5].payload) == 1001);
  CHECK(ev.items[5].payload.substr(2) == "going away");

  // Same conversation in awkward mid-header chunk sizes.
  for (size_t chunk : {3, 7, 1021}) {
    WsParser pc;
    Events evc;
    CHECK(feed(pc, wire, evc, chunk));
    CHECK(evc.items.size() == 6);
    CHECK(evc.items[3].payload == bigText);
  }

  std::printf("ok  byte-at-a-time incremental conversation\n");
}

// ---------------------------------------------------------------------------
// Protocol error cases -> consume() returns false, parser stays failed
// ---------------------------------------------------------------------------

static void testErrors() {
  // §5.1: unmasked client-to-server frame.
  {
    std::string server;
    encodeFrame(server, WsOpcode::Text, "hi");
    CHECK(rejects(server));
  }

  // §5.5: control frame with payload > 125 bytes (needs extended length).
  CHECK(rejects(clientFrame(WsOpcode::Ping, std::string(126, 'x'))));

  // §5.5: fragmented control frame (FIN clear).
  CHECK(rejects(clientFrame(WsOpcode::Ping, "hi", /*fin=*/false)));

  // §5.2: RSV bits set with no extension negotiated.
  for (uint8_t rsv : {uint8_t(0x40), uint8_t(0x20), uint8_t(0x10)}) {
    std::string f = clientFrame(WsOpcode::Text, "hi");
    f[0] = char(uint8_t(f[0]) | rsv);
    CHECK(rejects(f));
  }

  // §5.2: reserved opcodes %x3-7 and %xB-F.
  for (uint8_t op : {uint8_t(0x3), uint8_t(0x7), uint8_t(0xB), uint8_t(0xF)}) {
    std::string f = clientFrame(WsOpcode::Text, "hi");
    f[0] = char(0x80 | op);
    CHECK(rejects(f));
  }

  // §5.6/§8.1: invalid UTF-8 in a text message fails the connection.
  CHECK(rejects(clientFrame(WsOpcode::Text, "\xFF")));          // invalid byte
  CHECK(rejects(clientFrame(WsOpcode::Text, "\xC0\xAF")));      // overlong '/'
  CHECK(rejects(clientFrame(WsOpcode::Text, "\xED\xA0\x80")));  // surrogate
  CHECK(rejects(clientFrame(WsOpcode::Text, "\xF4\x90\x80\x80")));  // >U+10FFFF
  CHECK(rejects(clientFrame(WsOpcode::Text, "ok\xC3")));        // truncated
  // ...including when the invalid sequence spans fragments.
  {
    std::string w = clientFrame(WsOpcode::Text, "a\xC3", false);
    w += clientFrame(WsOpcode::Continuation, "\xC3", true);
    CHECK(rejects(w));
  }
  // Same bytes as a binary message are fine (no UTF-8 requirement).
  {
    WsParser p;
    Events ev;
    CHECK(feed(p, clientFrame(WsOpcode::Binary, "\xFF\xC0\xAF"), ev));
    CHECK(ev.items.size() == 1 && ev.items[0].isBinary);
  }

  // §5.4: continuation with no message in progress.
  CHECK(rejects(clientFrame(WsOpcode::Continuation, "hi")));
  // ...also after a completed (FIN) message.
  {
    std::string w = clientFrame(WsOpcode::Text, "done");
    w += clientFrame(WsOpcode::Continuation, "more");
    CHECK(rejects(w));
  }

  // §5.4: new data frame while a fragmented message is in progress.
  {
    std::string w = clientFrame(WsOpcode::Text, "part", /*fin=*/false);
    w += clientFrame(WsOpcode::Text, "again");
    CHECK(rejects(w));
  }

  // §5.2: 64-bit length with the most significant bit set.
  {
    std::string w;
    w += char(0x82);  // FIN | binary
    w += char(0xFF);  // MASK | 127
    static const uint8_t bad[8] = {0x80, 0, 0, 0, 0, 0, 0, 1};
    w.append(reinterpret_cast<const char*>(bad), 8);
    CHECK(rejects(w));
  }

  // §5.2: extended lengths must use the minimal encoding.
  {
    std::string w;
    w += char(0x81);
    w += char(0xFE);  // MASK | 126 -> 16-bit length...
    w += char(0x00);
    w += char(0x05);  // ...of 5, which fits in 7 bits
    CHECK(rejects(w));
  }
  {
    std::string w;
    w += char(0x81);
    w += char(0xFF);  // MASK | 127 -> 64-bit length...
    static const uint8_t small[8] = {0, 0, 0, 0, 0, 0, 1, 0x2C};
    w.append(reinterpret_cast<const char*>(small), 8);  // ...of 300
    CHECK(rejects(w));
  }

  // §5.5.1: close body of exactly 1 byte cannot hold a status code.
  CHECK(rejects(clientFrame(WsOpcode::Close, "x")));
  // §5.5.1: close reason must be valid UTF-8.
  {
    std::string body;
    encodeClosePayload(body, 1000, "\xFF");
    CHECK(rejects(clientFrame(WsOpcode::Close, body)));
  }

  // Limits.maxMessageSize: single frame over the cap.
  CHECK(rejects(clientFrame(WsOpcode::Binary, std::string(17, 'x')),
                WsParser::Limits{.maxMessageSize = 16}));
  // Limits.maxMessageSize: enforced across reassembled fragments.
  {
    std::string w = clientFrame(WsOpcode::Binary, std::string(10, 'x'), false);
    w += clientFrame(WsOpcode::Continuation, std::string(10, 'x'), true);
    CHECK(rejects(w, WsParser::Limits{.maxMessageSize = 16}));
  }
  // ...and a message exactly at the cap is accepted.
  {
    WsParser p(WsParser::Limits{.maxMessageSize = 16});
    Events ev;
    CHECK(feed(p, clientFrame(WsOpcode::Binary, std::string(16, 'x')), ev));
    CHECK(ev.items.size() == 1 && ev.items[0].payload.size() == 16);
  }

  // failCode(): 1009 for an oversized message (§7.4.1 Message Too Big),
  // 1007 for invalid UTF-8 payload data, 1002 for other violations.
  {
    WsParser p(WsParser::Limits{.maxMessageSize = 16});
    Events ev;
    CHECK(!feed(p, clientFrame(WsOpcode::Binary, std::string(17, 'x')), ev));
    CHECK(p.failCode() == 1009);
  }
  {
    WsParser p;
    Events ev;
    CHECK(!feed(p, clientFrame(WsOpcode::Text, "\xFF"), ev));
    CHECK(p.failCode() == 1007);
  }
  {
    WsParser p;
    Events ev;
    std::string server;
    encodeFrame(server, WsOpcode::Text, "hi");  // unmasked = protocol error
    CHECK(!feed(p, server, ev));
    CHECK(p.failCode() == 1002);
  }

  std::printf("ok  protocol error cases (parser fails and stays failed)\n");
}

// ---------------------------------------------------------------------------
// Close code table (§7.4: wire validity of close frame status codes)
// ---------------------------------------------------------------------------

static void testCloseCodeTable() {
  // §7.4.1/§7.4.2: 0-999 are never used; 1004/1005/1006/1015 are reserved and
  // MUST NOT be set in a close frame; 1016-2999 are reserved for the protocol;
  // >4999 is outside the defined space. All fail the connection (1002).
  const uint16_t bad[] = {0,    1,    500,  999,  1004, 1005,
                          1006, 1015, 1016, 2000, 2999, 5000, 65535};
  for (uint16_t code : bad) {
    std::string body;
    encodeClosePayload(body, code, "");
    CHECK(rejects(clientFrame(WsOpcode::Close, body)));
  }
  {
    WsParser p;
    Events ev;
    std::string body;
    encodeClosePayload(body, 1005, "");
    CHECK(!feed(p, clientFrame(WsOpcode::Close, body), ev));
    CHECK(p.failCode() == 1002);  // protocol error, not 1007/1009
  }

  // §7.4.1 defined codes and §7.4.2 registered/private ranges are accepted
  // and surface unchanged through parseCloseCode.
  const uint16_t good[] = {1000, 1001, 1002, 1003, 1007, 1008,
                           1011, 1014, 3000, 4000, 4999};
  for (uint16_t code : good) {
    WsParser p;
    Events ev;
    std::string body;
    encodeClosePayload(body, code, "bye");
    CHECK(feed(p, clientFrame(WsOpcode::Close, body), ev));
    CHECK(ev.items.size() == 1);
    CHECK(ev.items[0].isControl && ev.items[0].op == WsOpcode::Close);
    CHECK(parseCloseCode(ev.items[0].payload) == code);
  }

  std::printf("ok  close code table (section 7.4 wire validity)\n");
}

// ---------------------------------------------------------------------------
// RSV1 with permessage-deflate negotiated (RFC 7692 §6)
// ---------------------------------------------------------------------------

static void testPmdNegotiatedRsv1() {
  const WsParser::Limits pmd{.maxMessageSize = 16 * 1024 * 1024,
                             .pmdNegotiated = true};

  // RSV1 on the first frame of a data message marks it compressed: accepted,
  // reported compressed, and the (still-deflated) payload skips the parser's
  // UTF-8 validation - the caller validates after inflating.
  {
    WsParser p(pmd);
    Events ev;
    std::string f = clientFrame(WsOpcode::Text, "\xFF\x01\x02");  // not UTF-8
    f[0] = char(uint8_t(f[0]) | 0x40);
    CHECK(feed(p, f, ev));
    CHECK(ev.items.size() == 1);
    CHECK(!ev.items[0].isControl && ev.items[0].compressed);
    CHECK(ev.items[0].payload == "\xFF\x01\x02");
  }

  // An uncompressed message under the same limits reports compressed=false.
  {
    WsParser p(pmd);
    Events ev;
    CHECK(feed(p, clientFrame(WsOpcode::Text, "plain"), ev));
    CHECK(ev.items.size() == 1 && !ev.items[0].compressed);
  }

  // A fragmented compressed message: RSV1 only on the first frame (§6.1);
  // the reassembled whole is reported compressed.
  {
    WsParser p(pmd);
    Events ev;
    std::string w = clientFrame(WsOpcode::Binary, "\xAB", /*fin=*/false);
    w[0] = char(uint8_t(w[0]) | 0x40);
    w += clientFrame(WsOpcode::Continuation, "\xCD", /*fin=*/true);
    CHECK(feed(p, w, ev));
    CHECK(ev.items.size() == 1);
    CHECK(ev.items[0].compressed && ev.items[0].payload == "\xAB\xCD");
  }

  // §6.1: RSV1 on a continuation frame fails the connection.
  {
    std::string w = clientFrame(WsOpcode::Text, "ab", /*fin=*/false);
    w[0] = char(uint8_t(w[0]) | 0x40);  // first frame compressed: fine
    std::string cont = clientFrame(WsOpcode::Continuation, "cd", /*fin=*/true);
    cont[0] = char(uint8_t(cont[0]) | 0x40);
    CHECK(rejects(w + cont, pmd));
  }

  // §6.1: RSV1 on a control frame fails the connection, negotiated or not.
  for (WsOpcode op : {WsOpcode::Ping, WsOpcode::Pong, WsOpcode::Close}) {
    std::string f = clientFrame(op, "");
    f[0] = char(uint8_t(f[0]) | 0x40);
    CHECK(rejects(f, pmd));
  }

  // §5.2: RSV2/RSV3 stay forbidden even with permessage-deflate negotiated.
  for (uint8_t rsv : {uint8_t(0x20), uint8_t(0x10)}) {
    std::string f = clientFrame(WsOpcode::Text, "hi");
    f[0] = char(uint8_t(f[0]) | rsv);
    CHECK(rejects(f, pmd));
  }

  std::printf("ok  RSV1 handling with permessage-deflate negotiated (RFC 7692)\n");
}

// ---------------------------------------------------------------------------
// Zero-copy receive fast path: in-place unmasking of the wire buffer
// ---------------------------------------------------------------------------

// Header + mask length of a client frame ('7-bit'=6, 16-bit=8, 64-bit=14).
static size_t clientHeaderLen(std::string_view frame) {
  const uint8_t len7 = uint8_t(frame[1]) & 0x7F;
  return 2 + (len7 == 126 ? 2 : (len7 == 127 ? 8 : 0)) + 4;
}

static void testFastPathInPlaceUnmask() {
  // Documents the in-place contract: after a fast-path emit the input buffer
  // holds the UNMASKED payload, and the emitted view points INTO the input
  // buffer (zero copies into message_).
  const std::string payload = "in-place unmask contract \xE2\x9C\x93";
  const std::string wire = clientFrame(WsOpcode::Text, payload);
  std::string buf = wire;  // mutable wire buffer, like the server's readBuf
  const size_t off = clientHeaderLen(wire);
  WsParser p;
  const char* viewData = nullptr;
  std::string got;
  bool ok = p.consume(
      reinterpret_cast<uint8_t*>(buf.data()), buf.size(),
      [&](std::string_view pl, bool bin, bool compressed) {
        viewData = pl.data();
        got.assign(pl);
        CHECK(!bin && !compressed);
      },
      [&](WsOpcode, std::string_view) { CHECK(false); });
  CHECK(ok);
  CHECK(got == payload);
  CHECK(viewData == buf.data() + off);        // the view is INTO the buffer
  CHECK(buf.substr(off) == payload);          // payload unmasked in place
  CHECK(buf.compare(0, off, wire, 0, off) == 0);  // header + mask untouched

  // Same contract when the header and mask key arrived in an EARLIER
  // consume() call: a whole payload in one later buffer still fast-paths
  // (message_ is empty, the frame just entered its payload).
  const std::string big(70000, '\x7E');
  const std::string wire2 = clientFrame(WsOpcode::Binary, big);
  const size_t off2 = clientHeaderLen(wire2);  // 64-bit length: 14
  std::string head = wire2.substr(0, off2);
  std::string body = wire2.substr(off2);
  WsParser p2;
  Events ev;
  CHECK(p2.consume(reinterpret_cast<uint8_t*>(head.data()), head.size(),
                   ev.onMessage(), ev.onControl()));
  CHECK(ev.items.empty());
  CHECK(p2.consume(reinterpret_cast<uint8_t*>(body.data()), body.size(),
                   ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 1);
  CHECK(ev.items[0].isBinary && ev.items[0].payload == big);
  CHECK(body == big);  // unmasked in place in the second buffer

  std::printf("ok  zero-copy fast path (in-place unmask, view into buffer)\n");
}

static void testFastPathBatchedFrames() {
  // [complete frame A][complete frame B][partial frame C] in one consume()
  // buffer: A and B are fast-pathed (unmasked in place, views emitted); C is
  // missing its final bytes, so it buffers via the copy path and completes
  // on the NEXT consume() call.
  const std::string aPayload = "alpha";
  std::string bPayload(300, '\0');
  for (int j = 0; j < 300; ++j) bPayload[j] = char(uint8_t(j));
  const std::string cPayload = "gamma delta";

  const std::string a = clientFrame(WsOpcode::Text, aPayload);
  const std::string b = clientFrame(WsOpcode::Binary, bPayload);
  const std::string cFrame = clientFrame(WsOpcode::Text, cPayload);
  const size_t cCut = cFrame.size() - 4;  // withhold C's last 4 payload bytes

  std::string buf = a + b + cFrame.substr(0, cCut);
  WsParser p;
  Events ev;
  CHECK(p.consume(reinterpret_cast<uint8_t*>(buf.data()), buf.size(),
                  ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 2);
  CHECK(!ev.items[0].isControl && !ev.items[0].isBinary &&
        ev.items[0].payload == aPayload);
  CHECK(!ev.items[1].isControl && ev.items[1].isBinary &&
        ev.items[1].payload == bPayload);

  // A and B were unmasked IN PLACE (fast path); C's partial payload buffered
  // into message_ instead (copy path), so its bytes in buf stay MASKED.
  CHECK(buf.substr(clientHeaderLen(a), aPayload.size()) == aPayload);
  CHECK(buf.substr(a.size() + clientHeaderLen(b), bPayload.size()) == bPayload);
  const size_t cOff = a.size() + b.size() + clientHeaderLen(cFrame);
  CHECK(buf.substr(cOff) ==
        cFrame.substr(clientHeaderLen(cFrame), cPayload.size() - 4));

  // The withheld tail arrives: C completes via the copy path.
  std::string rest = cFrame.substr(cCut);
  CHECK(p.consume(reinterpret_cast<uint8_t*>(rest.data()), rest.size(),
                  ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 3);
  CHECK(!ev.items[2].isControl && !ev.items[2].isBinary &&
        ev.items[2].payload == cPayload);

  std::printf("ok  batched frames: two fast-pathed + split tail copy-pathed\n");
}

static void testInterleavedPingSingleBuffer() {
  // Fragmented text with a Ping between the fragments, ALL in one consume()
  // buffer: the fragments take the copy path (no in-place unmasking - the
  // buffer is untouched), the ping surfaces between them, and the message
  // reassembles correctly.
  std::string buf = clientFrame(WsOpcode::Text, "Hel", /*fin=*/false);
  buf += clientFrame(WsOpcode::Ping, "mid");
  buf += clientFrame(WsOpcode::Continuation, "lo", /*fin=*/true);
  const std::string before = buf;

  WsParser p;
  Events ev;
  CHECK(p.consume(reinterpret_cast<uint8_t*>(buf.data()), buf.size(),
                  ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 2);
  CHECK(ev.items[0].isControl && ev.items[0].op == WsOpcode::Ping &&
        ev.items[0].payload == "mid");
  CHECK(!ev.items[1].isControl && !ev.items[1].isBinary &&
        ev.items[1].payload == "Hello");
  CHECK(buf == before);  // copy path throughout: wire bytes stay masked

  std::printf("ok  interleaved ping in one buffer (fragments copy-pathed)\n");
}

// ---------------------------------------------------------------------------
// Incremental UTF-8 validation (uncompressed text, §5.6/§8.1 fail-fast)
// ---------------------------------------------------------------------------

static void testIncrementalUtf8() {
  // Invalid UTF-8 in the FIRST fragment of a fragmented text message fails
  // 1007 immediately - the rest of the message is never fed.
  {
    WsParser p;
    Events ev;
    const std::string frag1 = "abc\xFF" + std::string(500, 'x');
    CHECK(!feed(p, clientFrame(WsOpcode::Text, frag1, /*fin=*/false), ev));
    CHECK(p.failCode() == 1007);
    CHECK(ev.items.empty());
  }

  // ...and per CHUNK within one large frame: consume() fails on the first
  // payload chunk carrying the invalid byte - the remaining ~100 KB of the
  // declared payload is never provided, let alone buffered.
  {
    std::string payload(100000, 'a');
    payload[5] = '\xFF';
    const std::string wire = clientFrame(WsOpcode::Text, payload, /*fin=*/false);
    std::string firstChunk = wire.substr(0, clientHeaderLen(wire) + 16);
    WsParser p;
    Events ev;
    CHECK(!p.consume(reinterpret_cast<uint8_t*>(firstChunk.data()),
                     firstChunk.size(), ev.onMessage(), ev.onControl()));
    CHECK(p.failCode() == 1007);
  }

  // Valid multi-byte sequences split across FRAGMENT boundaries at every
  // offset pass: 4-byte emoji split 1/3, 2/2, 3/1; 3- and 2-byte sequences
  // at every cut as well.
  const std::string emoji = "\xF0\x9F\x8C\x8D";  // U+1F30D
  const std::string mark = "\xE2\x9C\x93";       // U+2713
  const std::string eacute = "\xC3\xA9";         // U+00E9
  for (const std::string& seq : {emoji, mark, eacute}) {
    for (size_t cut = 1; cut < seq.size(); ++cut) {
      WsParser p;
      Events ev;
      std::string w =
          clientFrame(WsOpcode::Text, "ok" + seq.substr(0, cut), /*fin=*/false);
      w += clientFrame(WsOpcode::Continuation, seq.substr(cut) + "!",
                       /*fin=*/true);
      CHECK(feed(p, w, ev));
      CHECK(ev.items.size() == 1);
      CHECK(ev.items[0].payload == "ok" + seq + "!");
    }
  }

  // The same splits across CONSUME-CALL boundaries within a single frame
  // (chunk sizes that cut every sequence at every offset).
  {
    const std::string msg = "ok" + emoji + " caf" + eacute + " " + mark;
    const std::string w = clientFrame(WsOpcode::Text, msg);
    for (size_t chunk : {1, 2, 3, 5}) {
      WsParser p;
      Events ev;
      CHECK(feed(p, w, ev, chunk));
      CHECK(ev.items.size() == 1);
      CHECK(ev.items[0].payload == msg);
    }
  }

  // A dangling partial sequence at FIN fails 1007: single frame (whole
  // message via the fast path)...
  {
    WsParser p;
    Events ev;
    CHECK(!feed(p, clientFrame(WsOpcode::Text, "ok\xE2\x9C"), ev));
    CHECK(p.failCode() == 1007);
  }
  // ...and when the truncated sequence spans fragments (copy path): every
  // fragment's bytes are a valid PREFIX, but FIN lands mid-sequence.
  {
    WsParser p;
    Events ev;
    std::string w = clientFrame(WsOpcode::Text, "a\xF0\x9F", /*fin=*/false);
    w += clientFrame(WsOpcode::Continuation, "\x8C", /*fin=*/true);  // 1 short
    CHECK(!feed(p, w, ev));
    CHECK(p.failCode() == 1007);
    CHECK(ev.items.empty());
  }

  std::printf("ok  incremental UTF-8 (fail-fast 1007, split sequences)\n");
}

// ---------------------------------------------------------------------------

int main() {
  testSha1();
  testBase64();
  testHandshake();
  testWsKeyValidation();
  testEncoderWireFormat();
  testKnownMaskedVector();
  testRoundTrips();
  testClosePayload();
  testFragmentationWithInterleavedPing();
  testByteAtATimeConversation();
  testErrors();
  testCloseCodeTable();
  testPmdNegotiatedRsv1();
  testFastPathInPlaceUnmask();
  testFastPathBatchedFrames();
  testInterleavedPingSingleBuffer();
  testIncrementalUtf8();
  std::printf("\nall websocket unit tests passed (%d checks)\n", gChecks);
  return 0;
}
