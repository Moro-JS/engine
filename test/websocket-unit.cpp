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
static bool feed(WsParser& p, std::string_view bytes, Events& ev,
                 size_t chunkSize = size_t(-1)) {
  size_t i = 0;
  if (bytes.empty()) {
    return p.consume(nullptr, 0, ev.onMessage(), ev.onControl());
  }
  while (i < bytes.size()) {
    const size_t n = std::min(chunkSize, bytes.size() - i);
    if (!p.consume(reinterpret_cast<const uint8_t*>(bytes.data()) + i, n,
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
  const uint8_t zero = 0;
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
  static const uint8_t wire[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                                 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  WsParser p;
  Events ev;
  CHECK(p.consume(wire, sizeof(wire), ev.onMessage(), ev.onControl()));
  CHECK(ev.items.size() == 1);
  CHECK(!ev.items[0].isControl);
  CHECK(!ev.items[0].isBinary);
  CHECK(ev.items[0].payload == "Hello");
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
  roundTripData(WsOpcode::Text, "");
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

int main() {
  testSha1();
  testBase64();
  testHandshake();
  testEncoderWireFormat();
  testKnownMaskedVector();
  testRoundTrips();
  testClosePayload();
  testFragmentationWithInterleavedPing();
  testByteAtATimeConversation();
  testErrors();
  std::printf("\nall websocket unit tests passed (%d checks)\n", gChecks);
  return 0;
}
