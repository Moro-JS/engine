// Standalone unit test for the HTTP/1.1 parser.
//   clang++ -std=c++20 -O2 test/http-parser-unit.cpp -o /tmp/hptest && /tmp/hptest
#include "../src/http_parser.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

using namespace moro::engine;

static int tests = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    ++tests;                                                            \
    if (!(cond)) {                                                      \
      std::printf("FAIL line %d: %s\n", __LINE__, #cond);              \
      return 1;                                                         \
    }                                                                   \
  } while (0)

static ParseStatus feed(HttpParser& p, const std::string& s) {
  return p.parse(s.data(), s.size());
}

// Every allocation of this binary is seen here, so a test can ask how much
// the parser set aside for the bytes it was given (testDeclaredBodyReserve).
static size_t gLargestAlloc = 0;
static size_t gLargeAllocs = 0;  // allocations of 64 KiB and more
void* operator new(size_t n) {
  if (n > gLargestAlloc) gLargestAlloc = n;
  if (n >= 65536) ++gLargeAllocs;
  if (void* p = std::malloc(n ? n : 1)) return p;
  std::abort();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }

static bool hookStoredForReserve(void*, Method, const std::string&) { return false; }

// A Content-Length body's buffer follows what has arrived, not what the head
// declares: a peer that sends a head and one byte gets nothing near the
// declared length set aside. Both the in-place scan (a route hook installed)
// and the buffered path.
static int testDeclaredBodyReserve() {
  const size_t kSize = 8 * 1024 * 1024;
  std::string payload(kSize, '\0');
  for (size_t i = 0; i < kSize; ++i) payload[i] = char('a' + i % 23);
  const std::string head =
      "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: " + std::to_string(kSize) + "\r\n\r\n";
  for (int direct = 0; direct < 2; ++direct) {
    HttpLimits lim;
    lim.maxBodySize = 16 * 1024 * 1024;
    HttpParser p(lim);
    if (direct) p.routeHook = hookStoredForReserve;
    const std::string first = head + payload.substr(0, 1);
    gLargestAlloc = 0;
    CHECK(p.parse(first.data(), first.size()) == ParseStatus::NeedMore);
    CHECK(gLargestAlloc < 4096);

    // Up to a sixteenth of the body the buffer stays within a small multiple
    // of what was received (a string's own growth).
    size_t off = 1;
    const size_t kChunk = 16 * 1024;
    bool more = true, proportionate = true;
    while (off + kChunk < kSize / 16) {
      more = more && p.parse(payload.data() + off, kChunk) == ParseStatus::NeedMore;
      off += kChunk;
      proportionate = proportionate && gLargestAlloc <= 4 * off + 4096;
    }
    CHECK(more);
    CHECK(proportionate);

    // From there the rest is reserved once: no further growth.
    CHECK(p.parse(payload.data() + off, kChunk) == ParseStatus::NeedMore);
    off += kChunk;
    CHECK(gLargestAlloc >= kSize);
    gLargeAllocs = 0;
    ParseStatus st = ParseStatus::NeedMore;
    while (off < kSize) {
      const size_t n = std::min(kChunk, kSize - off);
      st = p.parse(payload.data() + off, n);
      off += n;
    }
    CHECK(st == ParseStatus::Complete);
    CHECK(gLargeAllocs == 0);
    CHECK(p.body == payload);
  }

  // A body that fits in sixteen reads is reserved at its first read, as
  // before: one allocation for the whole body.
  {
    const size_t kSmall = 512 * 1024;
    const std::string w = "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: " + std::to_string(kSmall) +
                          "\r\n\r\n" + std::string(kSmall, 'q');
    HttpParser q;
    q.routeHook = hookStoredForReserve;
    gLargeAllocs = 0;
    ParseStatus st = ParseStatus::NeedMore;
    for (size_t o = 0; o < w.size(); o += 65536) st = q.parse(w.data() + o, std::min<size_t>(65536, w.size() - o));
    CHECK(st == ParseStatus::Complete && q.body.size() == kSmall);
    CHECK(gLargeAllocs == 1);
  }
  std::printf("ok  a Content-Length body's buffer follows the bytes received, not the declared length\n");
  return 0;
}

// The header list: one copied head, names lowered a word at a time
// (lowerTokenInPlace), framing names recognised a word at a time
// (foldedNameIs), views that survive a swap, NUL-terminated values.
static int testHeaderStorage() {
  // Token bytes, as a field name may hold them.
  std::string tokens;
  for (int c = 0; c < 256; ++c)
    if (kTokenChar[c]) tokens.push_back(static_cast<char>(c));
  uint32_t rng = 12345;
  const auto next = [&]() { return rng = rng * 1103515245u + 12345u; };

  // lowerTokenInPlace: the table's answer for every length, and nothing
  // outside the name is touched.
  bool lowered = true;
  for (size_t n = 0; n <= 40; ++n) {
    for (int round = 0; round < 200; ++round) {
      std::string buf(n + 16, '\xff');
      for (size_t i = 0; i < n; ++i) buf[8 + i] = tokens[(next() >> 8) % tokens.size()];
      std::string want = buf;
      for (size_t i = 0; i < n; ++i) want[8 + i] = static_cast<char>(kLowercase[static_cast<unsigned char>(want[8 + i])]);
      lowerTokenInPlace(buf.data() + 8, n);
      lowered = lowered && buf == want;
    }
  }
  CHECK(lowered);

  // tokenRun: the table's answer - the first byte that is not a token byte -
  // for every byte value at every position of a run of name bytes, and for
  // random mixes of token and other bytes.
  bool runs = true;
  const auto tableRun = [](const std::string& b) {
    size_t i = 0;
    while (i < b.size() && kTokenChar[static_cast<unsigned char>(b[i])]) ++i;
    return i;
  };
  for (size_t n = 1; n <= 27; ++n) {
    for (size_t at = 0; at < n; ++at) {
      for (int c = 0; c < 256; ++c) {
        std::string b(n, 'a');
        for (size_t i = 0; i < n; ++i) b[i] = "aZ0-9zA"[i % 7];
        b[at] = static_cast<char>(c);
        runs = runs && tokenRun(reinterpret_cast<const unsigned char*>(b.data()), b.size()) == tableRun(b);
      }
    }
  }
  for (int round = 0; round < 20000; ++round) {
    std::string b((next() >> 8) % 40, 'a');
    for (char& ch : b) ch = ((next() >> 8) % 8) ? tokens[(next() >> 8) % tokens.size()] : static_cast<char>(next() >> 16);
    runs = runs && tokenRun(reinterpret_cast<const unsigned char*>(b.data()), b.size()) == tableRun(b);
  }
  CHECK(runs);

  // foldedNameIs: a framing name in any letter case is that name; a name
  // that differs from it in one byte (any other token byte) is not.
  bool folded = true;
  for (const char* lit : {"expect", "upgrade", "connection", "content-length", "transfer-encoding"}) {
    const size_t n = std::strlen(lit);
    for (int round = 0; round < 256; ++round) {
      std::string name(lit);
      for (size_t i = 0; i < n; ++i)
        if ((next() >> 9) & 1) name[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(name[i])));
      folded = folded && foldedNameIs(name.data(), lit, n);
      const size_t at = (next() >> 8) % n;
      for (char t : tokens) {
        if (std::tolower(static_cast<unsigned char>(t)) == lit[at]) continue;
        std::string other = name;
        other[at] = t;
        folded = folded && !foldedNameIs(other.data(), lit, n);
      }
    }
  }
  CHECK(folded);

  // The list itself, from the in-place scan and from the buffered path.
  const std::string head =
      "GET / HTTP/1.1\r\nHost: h\r\nX-Mixed-CASE-Name-Longer-Than-Sixteen:  v1 \r\nACCEPT:\t*/*\r\n"
      "Content-LENGTH: 0\r\nE:\r\n\r\n";
  for (int direct = 0; direct < 2; ++direct) {
    for (size_t split = 0; split < head.size(); split += (direct ? head.size() : 7)) {
      HttpParser p;
      if (direct) p.routeHook = hookStoredForReserve;
      ParseStatus st = ParseStatus::NeedMore;
      if (split == 0) {
        st = feed(p, head);
      } else {
        for (size_t o = 0; o < head.size(); o += split) st = p.parse(head.data() + o, std::min(split, head.size() - o));
      }
      CHECK(st == ParseStatus::Complete);
      CHECK(p.headers.size() == 5);
      CHECK(p.headers[0].name == "host" && p.headers[0].value == "h");
      CHECK(p.headers[1].name == "x-mixed-case-name-longer-than-sixteen" && p.headers[1].value == "v1");
      CHECK(p.headers[2].name == "accept" && p.headers[2].value == "*/*");
      CHECK(p.headers[3].name == "content-length" && p.headers[3].value == "0");
      CHECK(p.headers[4].name == "e" && p.headers[4].value.empty());
      CHECK(std::strcmp(p.findHeader("accept"), "*/*") == 0);
      CHECK(std::strcmp(p.findHeader("x-mixed-case-name-longer-than-sixteen"), "v1") == 0);
      CHECK(std::strcmp(p.findHeader("e"), "") == 0);
      // A view taken before a swap is good after it: the storage moves with
      // the list.
      const Header kept = p.headers[1];
      HeaderList other;
      other.swap(p.headers);
      CHECK(other.size() == 5 && p.headers.empty());
      CHECK(kept.name == "x-mixed-case-name-longer-than-sixteen" && kept.value == "v1");
      CHECK(other[1].name.data() == kept.name.data());
      // The parser starts its next request with an empty list.
      p.reset();
      CHECK(feed(p, "GET / HTTP/1.1\r\nHost: x\r\n\r\n") == ParseStatus::Complete);
      CHECK(p.headers.size() == 1 && p.headers[0].value == "x");
      CHECK(kept.value == "v1");
    }
  }

  // HTTP/2's way in: fields added one at a time, cut back with resize.
  {
    HeaderList l;
    l.add("a", "1");
    l.add("bb", "22");
    CHECK(l.size() == 2 && l[1].name == "bb" && l[1].value == "22" && l[1].value.data()[2] == '\0');
    l.resize(1);
    CHECK(l.size() == 1 && l[0].name == "a");
    l.resize(0);
    CHECK(l.empty());
  }
  std::printf("ok  header storage: one copied head, names lowered and matched a word at a time\n");
  return 0;
}

int main() {
  // --- basic GET ---
  {
    HttpParser p;
    auto st = feed(p, "GET /hello?x=1 HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.method == Method::GET);
    CHECK(p.path == "/hello");
    CHECK(p.query == "x=1");
    CHECK(p.minorVersion == 1);
    CHECK(p.keepAlive == true);
    CHECK(p.headers.size() == 1);
    CHECK(p.headers[0].name == "host");
    CHECK(p.headers[0].value == "a");
    CHECK(p.body.empty());
  }

  // --- header name lowercased, OWS trimmed ---
  {
    HttpParser p;
    feed(p, "GET / HTTP/1.1\r\nContent-Type:   text/plain  \r\nHost: a\r\n\r\n");
    CHECK(p.headers[0].name == "content-type");
    CHECK(p.headers[0].value == "text/plain");
  }

  // --- POST with Content-Length ---
  {
    HttpParser p;
    auto st = feed(p, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.method == Method::POST);
    CHECK(p.body == "hello");
  }

  // --- byte-at-a-time incremental feed ---
  {
    HttpParser p;
    std::string req = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    ParseStatus st = ParseStatus::NeedMore;
    for (size_t i = 0; i < req.size(); ++i) {
      st = p.parse(req.data() + i, 1);
      if (i < req.size() - 1) CHECK(st == ParseStatus::NeedMore);
    }
    CHECK(st == ParseStatus::Complete);
    CHECK(p.body == "abc");
  }

  // --- pipelining: two requests, second is leftover ---
  {
    HttpParser p;
    auto st = feed(p, "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.path == "/a");
    CHECK(p.leftover() == "GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
    p.reset();
    st = p.parse(nullptr, 0);  // parse the already-buffered leftover
    CHECK(st == ParseStatus::Complete);
    CHECK(p.path == "/b");
  }

  // --- chunked body ---
  {
    HttpParser p;
    auto st = feed(p,
                   "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.body == "hello world");
  }

  // --- chunked, byte-at-a-time ---
  {
    HttpParser p;
    std::string req =
        "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nabc\r\n0\r\n\r\n";
    ParseStatus st = ParseStatus::NeedMore;
    for (size_t i = 0; i < req.size(); ++i) st = p.parse(req.data() + i, 1);
    CHECK(st == ParseStatus::Complete);
    CHECK(p.body == "abc");
  }

  // --- smuggling: both CL and TE -> 400 ---
  {
    HttpParser p;
    auto st = feed(p,
                   "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }

  // --- smuggling: conflicting duplicate Content-Length -> 400 ---
  {
    HttpParser p;
    auto st = feed(p,
                   "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n"
                   "Content-Length: 6\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }

  // --- duplicate identical Content-Length is allowed ---
  {
    HttpParser p;
    auto st = feed(p,
                   "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n"
                   "Content-Length: 2\r\n\r\nhi");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.body == "hi");
  }

  // --- whitespace before colon rejected (smuggling) ---
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n");
    CHECK(st == ParseStatus::Error);
  }

  // --- Connection: close ---
  {
    HttpParser p;
    feed(p, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    CHECK(p.keepAlive == false);
  }

  // --- HTTP/1.0 defaults to close ---
  {
    HttpParser p;
    feed(p, "GET / HTTP/1.0\r\n\r\n");
    CHECK(p.minorVersion == 0);
    CHECK(p.keepAlive == false);
  }

  // --- HTTP/1.0 with keep-alive ---
  {
    HttpParser p;
    feed(p, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    CHECK(p.keepAlive == true);
  }

  // --- unsupported version -> 505 ---
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/2.0\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 505);
  }

  // --- body over limit -> 413 ---
  {
    HttpParser::Limits lim;
    lim.maxBodySize = 4;
    HttpParser p(lim);
    auto st = feed(p, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 413);
  }

  // --- Content-Length integer-overflow smuggling defense ---
  // A 26-digit length overflows size_t; must be rejected, never wrapped to a
  // small value that would slip past the limit and desync the body. It is
  // not a length at all, so it is malformed (400), not merely too large.
  {
    HttpParser p;  // default 10MB limit
    auto st = feed(p,
                   "POST / HTTP/1.1\r\nHost: a\r\n"
                   "Content-Length: 99999999999999999999999999\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
    // The largest value 64 bits hold is a length, and too large; one more is not.
    HttpParser fits;
    CHECK(feed(fits, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551615\r\n\r\n") == ParseStatus::Error);
    CHECK(fits.errorStatus == 413);
    HttpParser over;
    CHECK(feed(over, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n") == ParseStatus::Error);
    CHECK(over.errorStatus == 400);
    // A non-digit is malformed wherever it sits, also behind a value already too large.
    HttpParser junk;
    CHECK(feed(junk, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999x\r\n\r\n") == ParseStatus::Error);
    CHECK(junk.errorStatus == 400);
  }

  // --- a Content-Length of 2^64 is rejected, not wrapped to 0 ---
  {
    HttpParser p;
    auto st = feed(p, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }

  // --- oversized head -> 431 ---
  {
    HttpParser::Limits lim;
    lim.maxHeadSize = 64;
    HttpParser p(lim);
    std::string big = "GET / HTTP/1.1\r\nX-Long: ";
    big.append(200, 'a');
    auto st = feed(p, big);
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 431);
  }

  // --- non-standard method -> OTHER with methodStr ---
  {
    HttpParser p;
    auto st = feed(p, "PROPFIND / HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.method == Method::OTHER);
    CHECK(p.methodStr == "PROPFIND");
  }

  // --- leading CRLF tolerated ---
  {
    HttpParser p;
    auto st = feed(p, "\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.path == "/");
  }

  // --- findHeader lookup ---
  {
    HttpParser p;
    feed(p, "GET / HTTP/1.1\r\nX-Test: v\r\nHost: a\r\n\r\n");
    const char* h = p.findHeader("x-test");
    CHECK(h != nullptr && std::string(h) == "v");
    CHECK(p.findHeader("missing") == nullptr);
  }

  // --- configurable maxHeadSize: boundary at N / N+1 ---
  {
    std::string head = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ";
    std::string tail = "\r\n\r\n";
    std::string pad(64 - head.size() - tail.size(), 'p');
    HttpLimits lim;
    lim.maxHeadSize = 64;
    HttpParser p(lim);
    CHECK(feed(p, head + pad + tail) == ParseStatus::Complete);

    HttpParser q(lim);
    CHECK(feed(q, head + pad + "p" + tail) == ParseStatus::Error);
    CHECK(q.errorStatus == 431);
  }

  // --- head-size limit counts HEAD bytes only, not a body delivered in the
  // same parse() call (the pending-replay path hands a full pipelined request
  // to one parse(); its body must not trip the 431 guard) ---
  {
    HttpLimits lim;
    lim.maxHeadSize = 64;
    lim.maxBodySize = 1 << 20;
    std::string body(4096, 'b');  // body far larger than maxHeadSize
    std::string req = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\n\r\n" + body;
    HttpParser p(lim);
    CHECK(feed(p, req) == ParseStatus::Complete);
    CHECK(p.body == body);
  }

  // --- configurable maxHeaders: boundary at N / N+1 (Host counts) ---
  {
    HttpLimits lim;
    lim.maxHeaders = 3;
    HttpParser p(lim);
    CHECK(feed(p, "GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\n\r\n") ==
          ParseStatus::Complete);
    HttpParser q(lim);
    CHECK(feed(q, "GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n") ==
          ParseStatus::Error);
    CHECK(q.errorStatus == 431);
  }

  // --- Content-Length overflow regression: a 30-digit CL cannot wrap the
  // accumulator into an acceptable value; it is rejected as malformed (400),
  // before any body byte is consumed ---
  {
    HttpParser p;
    auto st = feed(p, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: " +
                          std::string(30, '9') + "\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }


  // --- Host discipline (RFC 9112 §3.2): HTTP/1.1 without Host -> 400 ---
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/1.1\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }

  // --- duplicate Host -> 400 (any version) ---
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }

  // --- HTTP/1.0 predates Host: absent Host is fine there ---
  {
    HttpParser p;
    CHECK(feed(p, "GET / HTTP/1.0\r\n\r\n") == ParseStatus::Complete);
  }

  // --- request-target hygiene: raw control bytes -> 400 ---
  {
    HttpParser p;  // C0 control in the path
    auto st = feed(p, "GET /a\001b HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }
  {
    HttpParser p;  // DEL
    auto st = feed(p, "GET /a\177b HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }
  {
    HttpParser p;  // bare CR mid-target (only the terminating CRLF is stripped)
    auto st = feed(p, "GET /a\rb HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }
  {
    HttpParser p;  // control byte in the query half too
    auto st = feed(p, "GET /a?x=\001 HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Error);
  }

  // --- high bytes (raw UTF-8 paths) are refused; allowNonAsciiTarget hands
  // them over undecoded, as every release before 1.2.2 did ---
  {
    HttpParser strict;
    CHECK(feed(strict, "GET /caf\303\251 HTTP/1.1\r\nHost: a\r\n\r\n") == ParseStatus::Error);
    CHECK(strict.errorStatus == 400);
    HttpLimits lim;
    lim.allowNonAsciiTarget = true;
    HttpParser p(lim);
    auto st = feed(p, "GET /caf\303\251 HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.path == "/caf\303\251");
  }

  // --- absolute-form target passes through opaquely (RFC 9112 §3.2.2) ---
  {
    HttpParser p;
    auto st = feed(p, "GET http://h/x?q=1 HTTP/1.1\r\nHost: h\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.path == "http://h/x");
    CHECK(p.query == "q=1");
  }

  // --- maxUriSize: boundary at N / N+1, over answers 414 ---
  {
    HttpLimits lim;
    lim.maxUriSize = 16;
    std::string at = "/" + std::string(15, 'a');   // exactly 16
    HttpParser p(lim);
    CHECK(feed(p, "GET " + at + " HTTP/1.1\r\nHost: a\r\n\r\n") ==
          ParseStatus::Complete);
    HttpParser q(lim);
    CHECK(feed(q, "GET " + at + "a HTTP/1.1\r\nHost: a\r\n\r\n") ==
          ParseStatus::Error);
    CHECK(q.errorStatus == 414);
  }

  // --- header-value byte discipline: C0 controls (other than HTAB) -> 400 ---
  {
    HttpParser p;
    auto st = feed(p, "GET / HTTP/1.1\r\nHost: a\r\nX-Bad: v\001v\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
  }
  {
    HttpParser p;  // bare CR inside a value
    auto st = feed(p, "GET / HTTP/1.1\r\nHost: a\r\nX-Bad: v\rv\r\n\r\n");
    CHECK(st == ParseStatus::Error);
  }
  {
    HttpParser p;  // HTAB inside a value is legal OWS
    auto st = feed(p, "GET / HTTP/1.1\r\nHost: a\r\nX-Ok: a\tb\r\n\r\n");
    CHECK(st == ParseStatus::Complete);
    CHECK(p.findHeader("x-ok") != nullptr);
  }

  // =====================================================================
  // The three ways a request is parsed. Without a route hook every byte goes
  // through the accumulation buffer. With one (as on every server
  // connection) a request that starts a read is scanned in place: stored
  // headers when the hook says JS will see it (parseDirectStored), a scan
  // that stores nothing when the hook says the engine answers it
  // (scanLightHeaders). All three must agree, however the bytes are split.
  // =====================================================================
  {
    struct Outcome {
      ParseStatus st = ParseStatus::NeedMore;
      int err = 0;
      Method method = Method::OTHER;
      std::string methodStr, path, query, body, rest;
      int minor = 1;
      bool keepAlive = true, expect = false, upgrade = false, light = false;
      size_t headerCount = 0;
      std::string headersFlat;
    };
    static HttpLimits lim = [] {
      HttpLimits l;
      l.maxHeadSize = 512;
      l.maxHeaders = 8;
      l.maxBodySize = 64;
      return l;
    }();
    auto run = [](const std::string& in, size_t split, HttpParser::RouteHook hook) {
      HttpParser p(lim);
      p.routeHook = hook;
      Outcome o;
      size_t off = 0;
      while (off < in.size()) {
        const size_t k = split == 0 ? in.size() - off : (split < in.size() - off ? split : in.size() - off);
        o.st = p.parse(in.data() + off, k);
        off += k;
        if (o.st != ParseStatus::NeedMore) break;
      }
      o.light = p.light();
      if (o.st == ParseStatus::Error) o.err = p.errorStatus;
      if (o.st == ParseStatus::Complete) {
        o.method = p.method;
        o.methodStr = p.methodStr;
        o.path = p.path;
        o.query = p.query;
        o.body = p.body;
        o.minor = p.minorVersion;
        o.keepAlive = p.keepAlive;
        o.expect = p.expectContinue();
        o.upgrade = p.hasUpgrade();
        if (!o.light) {
          o.headerCount = p.headers.size();
          for (const auto& h : p.headers) o.headersFlat += std::string(h.name) + "=" + std::string(h.value) + ";";
        }
        o.rest.assign(p.leftover());
        o.rest.append(in, off, std::string::npos);
      }
      return o;
    };
    auto same = [](const Outcome& a, const Outcome& b, bool headers) {
      if (a.st != b.st) return false;
      if (a.st == ParseStatus::Error) return a.err == b.err;
      if (a.st != ParseStatus::Complete) return true;
      if (a.method != b.method || a.methodStr != b.methodStr || a.path != b.path || a.query != b.query) return false;
      if (a.body != b.body || a.minor != b.minor || a.keepAlive != b.keepAlive) return false;
      if (a.expect != b.expect || a.upgrade != b.upgrade || a.rest != b.rest) return false;
      if (headers && (a.headerCount != b.headerCount || a.headersFlat != b.headersFlat)) return false;
      return true;
    };
    static auto hookNo = [](void*, Method, const std::string&) { return false; };
    static auto hookYes = [](void*, Method, const std::string&) { return true; };
    const HttpParser::RouteHook stored = +hookNo;
    const HttpParser::RouteHook light = +hookYes;

    // What each path reports for a plain request.
    {
      const std::string req = "GET /r?q=1 HTTP/1.1\r\nHost: h\r\nX-A: b\r\n\r\nNEXT";
      Outcome b = run(req, 0, nullptr), s = run(req, 0, stored), l = run(req, 0, light);
      CHECK(b.st == ParseStatus::Complete && s.st == ParseStatus::Complete && l.st == ParseStatus::Complete);
      CHECK(!b.light && !s.light && l.light);
      CHECK(s.headersFlat == "host=h;x-a=b;");
      CHECK(l.path == "/r" && l.query == "q=1" && l.rest == "NEXT");
      CHECK(l.headerCount == 0);  // scanned, not stored
    }
    // Framing and connection semantics are read in light mode too.
    {
      Outcome l = run("POST /r HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nConnection: close\r\nExpect: 100-continue\r\nUpgrade: x\r\n\r\nhelloNEXT", 0, light);
      CHECK(l.st == ParseStatus::Complete && l.light);
      CHECK(l.body == "hello" && l.rest == "NEXT");
      CHECK(!l.keepAlive && l.expect && l.upgrade);
      Outcome c = run("POST /r HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nNEXT", 0, light);
      CHECK(c.st == ParseStatus::Complete && c.body == "abc" && c.rest == "NEXT");
    }
    // A request that arrives whole on an idle parser leaves nothing buffered
    // but what follows it; idle() is what the server's fast lane asks.
    {
      for (HttpParser::RouteHook hook : {stored, light}) {
        HttpParser p(lim);
        p.routeHook = hook;
        CHECK(p.idle());
        const std::string one = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
        CHECK(p.parse(one.data(), one.size()) == ParseStatus::Complete);
        CHECK(p.buffered() == 0 && p.leftover().empty());
        p.reset();
        CHECK(p.idle() && !p.midRequest());
        const std::string two = one + "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
        CHECK(p.parse(two.data(), two.size()) == ParseStatus::Complete);
        CHECK(p.path == "/a" && p.leftover() == one.substr(0, 5) + "b" + one.substr(6));
        p.reset();
        CHECK(!p.idle() && p.midRequest());
        CHECK(p.parse(nullptr, 0) == ParseStatus::Complete);
        CHECK(p.path == "/b");
        // A Content-Length body that arrives after its head goes straight to `body`.
        p.reset();
        const std::string head = "POST /c HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\r\nab";
        CHECK(p.parse(head.data(), head.size()) == ParseStatus::NeedMore);
        CHECK(p.headParsed() && p.midRequest());
        CHECK(p.parse("cd", 2) == ParseStatus::NeedMore);
        CHECK(p.parse("efGET", 5) == ParseStatus::Complete);
        CHECK(p.body == "abcdef" && p.leftover() == "GET");
      }
    }
    // lightFresh(): the hook's answer still holds, because the request line
    // was parsed in the parse() call that completed the request. Once a call
    // has returned with the request unfinished the caller has run in between
    // (and may have changed its routes), and it is light but no longer fresh.
    {
      const std::string req = "POST /r HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
      const size_t lineEnd = req.find('\n') + 1;
      for (size_t split = 0; split < req.size(); ++split) {
        HttpParser p(lim);
        p.routeHook = light;
        if (split == 0) {
          CHECK(p.parse(req.data(), req.size()) == ParseStatus::Complete);
          CHECK(p.light() && p.lightFresh());
          continue;
        }
        CHECK(p.parse(req.data(), split) == ParseStatus::NeedMore);
        // The hook is asked once the request line is whole.
        CHECK(p.light() == (split >= lineEnd));
        CHECK(!p.lightFresh());
        CHECK(p.parse(req.data() + split, req.size() - split) == ParseStatus::Complete);
        CHECK(p.light() && p.body == "abc");
        CHECK(p.lightFresh() == (split < lineEnd));
        // The next request on the connection starts over.
        p.reset();
        CHECK(!p.light() && !p.lightFresh());
        CHECK(p.parse(req.data(), req.size()) == ParseStatus::Complete);
        CHECK(p.lightFresh());
      }
      // Pipelined behind another request in one read, and completed there: fresh.
      HttpParser p(lim);
      p.routeHook = light;
      const std::string two = "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\nGET /c HTTP/1.1\r\n";
      CHECK(p.parse(two.data(), two.size()) == ParseStatus::Complete && p.lightFresh());
      p.reset();
      CHECK(p.parse(nullptr, 0) == ParseStatus::Complete && p.path == "/b" && p.lightFresh());
      p.reset();
      CHECK(p.parse(nullptr, 0) == ParseStatus::NeedMore && p.light() && !p.lightFresh());
      CHECK(p.parse("Host: h\r\n\r\n", 11) == ParseStatus::Complete && p.path == "/c" && p.light() && !p.lightFresh());
      // A request JS will see is never light, whole or split.
      HttpParser q(lim);
      q.routeHook = stored;
      CHECK(q.parse(req.data(), 20) == ParseStatus::NeedMore && !q.light() && !q.lightFresh());
      CHECK(q.parse(req.data() + 20, req.size() - 20) == ParseStatus::Complete && !q.light() && !q.lightFresh());
    }
    // The same answer from all three paths, at every split, for requests
    // that are served and requests that are rejected.
    const std::string cases[] = {
        "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET /a?b HTTP/1.0\r\n\r\nREST",
        "GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
        "HEAD /a HTTP/1.1\nHost: h\nX-A:  v \n\n",
        "\r\n\r\nGET /lead HTTP/1.1\r\nHost: h\r\n\r\n",
        "PROPFIND /m HTTP/1.1\r\nHost: h\r\nConnection: Foo, Close\r\n\r\n",
        "POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello worldGET /n HTTP/1.1\r\n",
        "POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\nGET",
        "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: v\r\n\r\nGET /n",
        "POST /c HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
        "POST /c HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
        "POST /c HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        "GET /u HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        "GET /h HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
        // rejected
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: h\r\n\r\n",
        "GET /\r\nHost: h\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: h\r\nX A: b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: h\r\nX-A: a\001b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: h\r\n folded\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 65\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nnot a field\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\nF: 6\r\nG: 7\r\nH: 8\r\n\r\n",  // 9 headers > 8
        "GET /" + std::string(600, 'a') + " HTTP/1.1\r\nHost: h\r\n\r\n",                                    // head > 512
        "GET / HTTP/1.1\r\nHost: h\r\nX-Long: " + std::string(600, 'a') + "\r\n\r\n",
        // A head that is malformed and over the 512-byte limit, or malformed
        // with more than the limit behind it in the same read: one answer,
        // whichever the parser could have seen first.
        "BAD LINE\r\nHost: h\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n",             // short bad request line, a long read: 400
        "GET /\r\nHost: h\r\n\r\n" + std::string(700, 'x'),                                  // ... followed by anything: 400
        "GET / HTTP/2.0\r\nHost: h\r\n\r\n" + std::string(700, 'x'),                          // 505, not 431
        "BAD " + std::string(600, 'a') + "\r\nHost: h\r\n\r\n",                              // bad request line over the limit: 431
        "GET /" + std::string(600, 'a') + " HTTP/2.0\r\nHost: h\r\n\r\n",                    // unsupported version, line over the limit: 431
        "GET / HTTP/1.1\r\nHost: h\r\nX A: " + std::string(600, 'a') + "\r\n\r\n",           // bad header line that crosses the limit: 431
        "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + std::string(480, 'a') + "\r\nX A: b\r\n\r\n", // bad line wholly past the limit: 431
        "GET / HTTP/1.1\r\nHost: h\r\nX A: b\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n", // bad line before a line that crosses it: 400
        "GET / HTTP/1.1\r\nHost: a b\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n",        // bad Host before the limit: 400
        "GET / HTTP/1.1\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n",                     // no Host, and over the limit: 431
        "\r\n\r\n\r\nBAD LINE\r\n" + std::string(700, 'x'),                                  // leading empty lines count toward the head
        std::string(520, '\n') + "GET / HTTP/1.1\r\nHost: h\r\n\r\n",                         // ... and can take it over the limit: 431
        "GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\nF: 6\r\nG: 7\r\nH 8\r\n\r\n",  // ninth line malformed: the count comes first, 431
    };
    // What those answers are (the comparison below only says they agree).
    {
      auto status = [&](const std::string& in) {
        const Outcome o = run(in, 0, nullptr);
        return o.st == ParseStatus::Error ? o.err : 0;
      };
      CHECK(status("BAD LINE\r\nHost: h\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n") == 400);
      CHECK(status("GET / HTTP/2.0\r\nHost: h\r\n\r\n" + std::string(700, 'x')) == 505);
      CHECK(status("BAD " + std::string(600, 'a') + "\r\nHost: h\r\n\r\n") == 431);
      CHECK(status("GET /" + std::string(600, 'a') + " HTTP/2.0\r\nHost: h\r\n\r\n") == 431);
      CHECK(status("GET / HTTP/1.1\r\nHost: h\r\nX A: " + std::string(600, 'a') + "\r\n\r\n") == 431);
      CHECK(status("GET / HTTP/1.1\r\nHost: h\r\nX A: b\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n") == 400);
      CHECK(status("GET / HTTP/1.1\r\nX-Pad: " + std::string(600, 'a') + "\r\n\r\n") == 431);
      // The limit to the byte: a head of exactly 512 bytes is served, 513 is not.
      const std::string fixed = "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: \r\n\r\n";
      const std::string at = "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + std::string(512 - fixed.size(), 'a') + "\r\n\r\n";
      const std::string over = "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + std::string(513 - fixed.size(), 'a') + "\r\n\r\n";
      CHECK(at.size() == 512 && status(at) == 0);
      CHECK(status(over) == 431);
      for (HttpParser::RouteHook hook : {stored, light}) {
        CHECK(run(at, 0, hook).st == ParseStatus::Complete);
        CHECK(run(over, 0, hook).err == 431);
      }
    }
    for (const std::string& in : cases) {
      const Outcome ref = run(in, 0, nullptr);
      CHECK(ref.st != ParseStatus::NeedMore);
      for (size_t split = 0; split <= in.size() && split <= 80; ++split) {
        CHECK(same(ref, run(in, split, nullptr), true));
        CHECK(same(ref, run(in, split, stored), true));
        CHECK(same(ref, run(in, split, light), false));
      }
      for (const size_t split : {size_t(200), size_t(511), size_t(512), size_t(513), size_t(600)}) {
        CHECK(same(ref, run(in, split, nullptr), true));
        CHECK(same(ref, run(in, split, stored), true));
        CHECK(same(ref, run(in, split, light), false));
      }
    }
  }

  // --- a rejected request stays rejected: Error is final ---
  {
    HttpParser p;
    CHECK(feed(p, "GET /r HTTP/1.1\r\nX-A: b\r\n\r\n") == ParseStatus::Error);  // no Host
    CHECK(p.errorStatus == 400);
    const size_t held = p.buffered();
    // What arrives next is neither the rest of that request nor a new one.
    CHECK(feed(p, "Host: h\r\n\r\n") == ParseStatus::Error);
    CHECK(feed(p, "GET /ok HTTP/1.1\r\nHost: h\r\n\r\n") == ParseStatus::Error);
    CHECK(p.parse(nullptr, 0) == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
    CHECK(p.buffered() == held);  // and it is not kept
    HttpLimits lim;
    lim.maxBodySize = 4;
    HttpParser q(lim);
    CHECK(feed(q, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n") == ParseStatus::Error);
    CHECK(q.errorStatus == 413);
    CHECK(feed(q, "x") == ParseStatus::Error);
    CHECK(q.errorStatus == 413);
  }

  // --- Host = uri-host [ ":" port ] (RFC 9110 §7.2, RFC 9112 §3.2) ---
  {
    const char* good[] = {"example.test", "my_service:3000", "a-b.c", "127.0.0.1:8080", "[::1]", "[2001:db8::1]:443",
                          "[fe80::1%25en0]", "example.test.", "EXAMPLE.test", "localhost:", "a~b!$&'()*+;=c",
                          "caf%C3%A9.test"};
    for (const char* h : good) {
      CHECK(validHostValue(h));
      HttpParser p;
      CHECK(feed(p, std::string("GET / HTTP/1.1\r\nHost: ") + h + "\r\n\r\n") == ParseStatus::Complete);
      CHECK(std::string(p.findHeader("host")) == h);
    }
    const char* bad[] = {"a b", "a/b", "a, b", "u@a", "a:99x", "a?x", "a#x", "a\\b", "a:1:2", "::1", "[::1", "::1]",
                         "[]", "[::1]x", "[::1]:x", "[a[b]]", "a\"b", ("b\xc3\xbc" "cher.example"), "a\tb",
                         "", ":80", ":"};  // no host named
    for (const char* h : bad) {
      CHECK(!validHostValue(h));
      HttpParser p;
      CHECK(feed(p, std::string("GET / HTTP/1.1\r\nHost: ") + h + "\r\n\r\n") == ParseStatus::Error);
      CHECK(p.errorStatus == 400);
      HttpParser q;  // HTTP/1.0 may omit Host, but not send a malformed one
      CHECK(feed(q, std::string("GET / HTTP/1.0\r\nHost: ") + h + "\r\n\r\n") == ParseStatus::Error);
    }
  }

  // --- the Host value is judged on every request of a connection ---
  // (An accepted value is remembered, so that repeating it costs a compare;
  // nothing else may pass on its strength.)
  {
    auto req = [](const std::string& host) { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"; };
    static auto hookYes = [](void*, Method, const std::string&) { return true; };
    for (const bool light : {false, true}) {
      HttpParser p;
      if (light) p.routeHook = +hookYes;
      const std::string longHost = std::string(60, 'a') + ".example";   // longer than the remembered size
      const std::string host255 = std::string(255, 'b');
      for (const std::string& h : {std::string("example.test:8080"), std::string("example.test:8080"), std::string("a"),
                                   std::string("a"), longHost, longHost, host255, std::string("example.test:8081")}) {
        CHECK(feed(p, req(h)) == ParseStatus::Complete);
        p.reset();
      }
      // same length as the remembered one, one byte off
      CHECK(feed(p, req("example.test/8081")) == ParseStatus::Error);
      CHECK(p.errorStatus == 400);
      HttpParser q;
      if (light) q.routeHook = +hookYes;
      CHECK(feed(q, req("a b")) == ParseStatus::Error);  // a refused value is not remembered ...
      HttpParser r;
      if (light) r.routeHook = +hookYes;
      CHECK(feed(r, req("ok.test")) == ParseStatus::Complete);
      r.reset();
      CHECK(feed(r, req("ok.test") + req("ok test")) == ParseStatus::Complete);  // ... and pipelined ones are each checked
      r.reset();
      CHECK(r.parse(nullptr, 0) == ParseStatus::Error);
    }
  }

  // --- HTTP/1.0: Transfer-Encoding ends the connection, Expect is ignored ---
  {
    HttpParser p;
    CHECK(feed(p, "POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n") ==
          ParseStatus::Complete);
    CHECK(p.body == "abc");
    CHECK(p.keepAlive == false);  // RFC 9112 §6.1
    HttpParser k;
    CHECK(feed(k, "POST / HTTP/1.0\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc") == ParseStatus::Complete);
    CHECK(k.keepAlive == true);  // only Transfer-Encoding does that
    HttpParser e;
    CHECK(feed(e, "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n") == ParseStatus::NeedMore);
    CHECK(e.headParsed() && !e.expectContinue());  // RFC 9110 §10.1.1
    HttpParser f;
    CHECK(feed(f, "POST / HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n") == ParseStatus::NeedMore);
    CHECK(f.expectContinue());
  }

  // --- chunk framing ends its lines with CRLF; chunk-size = 1*HEXDIG ---
  {
    const std::string head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    const char* bad[] = {
        "3\nabc\r\n0\r\n\r\n",           // bare LF after the size
        "3;x\nabc\r\n0\r\n\r\n",         // ... after an extension
        "2;\nxx\r\n0\r\n\r\n",           // a bare LF inside what would be the extension
        "3\r\nabc\r\n0\n\r\n",           // bare LF after the last chunk
        "3\r\nabc\r\n0\r\n\n",           // bare LF as the final blank line
        "3\r\nabc\r\n0\r\nX-T: v\n\r\n", // bare LF after a trailer line
        " 3\r\nabc\r\n0\r\n\r\n",        // SP before the size
        "\t3\r\nabc\r\n0\r\n\r\n",       // HTAB before the size
        ";x\r\nabc\r\n0\r\n\r\n",        // no size at all
        "3 4\r\nabc\r\n0\r\n\r\n",       // something other than ";" after the size
        "3;a\001b\r\nabc\r\n0\r\n\r\n",  // a control byte in the extension
        "3;a\rb\r\nabc\r\n0\r\n\r\n",    // a bare CR in the extension
        "3\r\r\nabc\r\n0\r\n\r\n",       // a second CR before the LF
        "3 \r\nabc\r\n0\r\n\r\n",        // whitespace after the size and no ";" behind it
        "3\t\r\nabc\r\n0\r\n\r\n",
        "3;\r\nabc\r\n0\r\n\r\n",        // ";" and no extension name
        "3; \r\nabc\r\n0\r\n\r\n",
        "3;x;\r\nabc\r\n0\r\n\r\n",      // ... after a good one
        "3;bad[=x\r\nabc\r\n0\r\n\r\n",  // a name that is not a token
        "3;=x\r\nabc\r\n0\r\n\r\n",      // a value and no name
        "3;x=\r\nabc\r\n0\r\n\r\n",      // "=" and no value
        "3;x=a b\r\nabc\r\n0\r\n\r\n",   // a value that is neither a token nor quoted
        "3;x=\"a\r\nabc\r\n0\r\n\r\n",   // a quoted value that does not end
        "3;x=\"a\"b\r\nabc\r\n0\r\n\r\n", // something behind the closing quote
        "3;x \r\nabc\r\n0\r\n\r\n",      // whitespace at the end of the line
        "3;\xc3\xa9=1\r\nabc\r\n0\r\n\r\n", // obs-text in a name
        "10000000000000000\r\nabc\r\n0\r\n\r\n", // 17 hex digits: no 64-bit size
        "FFFFFFFFFFFFFFFF0\r\nabc\r\n0\r\n\r\n",
    };
    for (const char* b : bad) {
      HttpParser p;
      CHECK(feed(p, head + b) == ParseStatus::Error);
      CHECK(p.errorStatus == 400);
      HttpParser q;  // the same one byte at a time
      const std::string all = head + b;
      ParseStatus st = ParseStatus::NeedMore;
      for (size_t i = 0; i < all.size() && st == ParseStatus::NeedMore; ++i) st = q.parse(all.data() + i, 1);
      CHECK(st == ParseStatus::Error);
      CHECK(q.errorStatus == 400);
    }
    const char* good[] = {
        "3\r\nabc\r\n0\r\n\r\n",
        "3\t;x\r\nabc\r\n0 ; y=\"a b\"\r\n\r\n",   // BWS before ";", a quoted value with SP
        "3;a;b=c ; d = \"e\\\"f\"\r\nabc\r\n0\r\n\r\n", // several, BWS around "=", a quoted-pair
        "003;x=\"\xc3\xa9\"\r\nabc\r\n0\r\n\r\n",  // obs-text inside a quoted value
        "3\r\nabc\r\n0\r\nX-T: v\r\nX-U:\r\n\r\n", // trailers
    };
    for (const char* g : good) {
      HttpParser p;
      CHECK(feed(p, head + g) == ParseStatus::Complete);
      CHECK(p.body == "abc");
    }
  }

  // --- trailer lines are checked as field lines, then dropped ---
  {
    const std::string head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";
    const char* bad[] = {"garbage line", "GET /next HTTP/1.1", "X-T : v", " folded", ": v", "X-T: a\001b", "X\tT: v"};
    for (const char* line : bad) {
      HttpParser p;
      CHECK(feed(p, head + line + "\r\n\r\n") == ParseStatus::Error);
      CHECK(p.errorStatus == 400);
    }
    HttpParser p;
    CHECK(feed(p, head + "X-T: v\r\nHost: evil\r\nContent-Length: 9\r\n\r\n") == ParseStatus::Complete);
    CHECK(p.headers.size() == 2);  // host, transfer-encoding: no trailer joined them
    CHECK(std::string(p.findHeader("host")) == "h");
  }

  // --- the trailer bound is on the trailer section, not on what follows it ---
  {
    HttpLimits lim;
    lim.maxHeadSize = 256;
    const std::string chunkedReq = "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";
    const std::string next = "POST /n HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n" + std::string(1000, 'x');
    HttpParser p(lim);
    CHECK(feed(p, chunkedReq + "\r\n" + next) == ParseStatus::Complete);  // one read holds both requests
    CHECK(p.body == "abc");
    CHECK(p.leftover() == next);
    HttpParser t(lim);  // a trailer inside the bound, the big request behind it
    CHECK(feed(t, chunkedReq + "X-T: " + std::string(200, 'a') + "\r\n\r\n" + next) == ParseStatus::Complete);
    // The bound itself: 256 bytes of trailer section pass, 257 do not - whole,
    // split, and whatever follows.
    const std::string at = "X-T: " + std::string(256 - 5 - 2 - 2, 'a') + "\r\n\r\n";  // exactly 256 with the blank line
    HttpParser a(lim);
    CHECK(at.size() == 256);
    CHECK(feed(a, chunkedReq + at + next) == ParseStatus::Complete);
    const std::string over = "X-T: " + std::string(256 - 5 - 2 - 1, 'a') + "\r\n\r\n";  // 257
    HttpParser o(lim);
    CHECK(feed(o, chunkedReq + over + next) == ParseStatus::Error);
    CHECK(o.errorStatus == 431);
    HttpParser o2(lim);
    const std::string all = chunkedReq + over;
    ParseStatus st = ParseStatus::NeedMore;
    for (size_t i = 0; i < all.size() && st == ParseStatus::NeedMore; ++i) st = o2.parse(all.data() + i, 1);
    CHECK(st == ParseStatus::Error);
    CHECK(o2.errorStatus == 431);
    HttpParser many(lim);
    std::string lines;
    for (int i = 0; i < 40; ++i) lines += "X-T: aaaa\r\n";  // 440 bytes of short lines
    CHECK(feed(many, chunkedReq + lines + "\r\n") == ParseStatus::Error);
    CHECK(many.errorStatus == 431);
  }

  // --- one bound on a chunk-size line, however it is split ---
  {
    const std::string head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    const size_t max = HttpParser::kMaxChunkLine;
    for (const size_t lineLen : {size_t(100), size_t(2000), max - 1, max, max + 1, max * 3}) {
      // lineLen counts the line up to its LF: "3;" + extension + CR
      const std::string line = "3;" + std::string(lineLen - 3, 'e') + "\r\n";
      const std::string all = head + line + "abc\r\n0\r\n\r\n";
      const ParseStatus want = lineLen <= max ? ParseStatus::Complete : ParseStatus::Error;
      HttpParser whole;
      CHECK(feed(whole, all) == want);
      for (const size_t step : {size_t(1), size_t(7), size_t(1024), size_t(1025), size_t(4096)}) {
        HttpParser split;
        ParseStatus st = ParseStatus::NeedMore;
        for (size_t off = 0; off < all.size() && st == ParseStatus::NeedMore; off += step)
          st = split.parse(all.data() + off, step < all.size() - off ? step : all.size() - off);
        CHECK(st == want);
        if (want == ParseStatus::Error) CHECK(split.errorStatus == 400);
      }
    }
  }

  // --- a chunk that would take the body past maxBodySize is refused at its size line ---
  {
    HttpLimits lim;
    lim.maxBodySize = 1000;
    const std::string head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    HttpParser p(lim);
    CHECK(feed(p, head + "5\r\nhello\r\n") == ParseStatus::NeedMore);
    CHECK(feed(p, "3e4\r\n") == ParseStatus::Error);  // 996 more, 995 left: before a byte of it arrives
    CHECK(p.errorStatus == 413);
    HttpParser q(lim);
    CHECK(feed(q, head + "5\r\nhello\r\n3e3\r\n") == ParseStatus::NeedMore);  // 995 more, exactly what is left
    CHECK(feed(q, std::string(995, 'x') + "\r\n0\r\n\r\n") == ParseStatus::Complete);
    CHECK(q.body.size() == 1000);
    HttpParser r(lim);  // nothing collected yet: the whole budget, and one byte more
    CHECK(feed(r, head + "3e8\r\n") == ParseStatus::NeedMore);
    HttpParser t(lim);
    CHECK(feed(t, head + "3e9\r\n") == ParseStatus::Error);
    CHECK(t.errorStatus == 413);
    HttpParser z(lim);  // the last chunk is never over
    CHECK(feed(z, head + "3e8\r\n" + std::string(1000, 'x') + "\r\n0\r\n\r\n") == ParseStatus::Complete);
  }

  // --- the framing of a chunked body is not held for the length of the request ---
  {
    HttpLimits lim;
    lim.maxBodySize = 64 * 1024;
    const std::string head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    // 1-byte chunks, each behind a 1000-byte extension: ~1 KB on the wire per body byte.
    const std::string one = "1;" + std::string(1000, 'e') + "\r\nX\r\n";
    std::string block;
    for (int i = 0; i < 60; ++i) block += one;  // one ~60 KB read
    for (const bool hooked : {false, true}) {
      HttpParser p(lim);
      if (hooked) p.routeHook = +[](void*, Method, const std::string&) { return false; };
      CHECK(feed(p, head) == ParseStatus::NeedMore);
      size_t peak = 0;
      for (int i = 0; i < 500; ++i) {  // 30,000 body bytes, 30 MB of framing
        CHECK(feed(p, block) == ParseStatus::NeedMore);
        if (p.buffered() > peak) peak = p.buffered();
      }
      CHECK(p.body.size() == 30000);
      CHECK(peak <= 2 * block.size());  // about one read's worth, not 30 MB
      CHECK(feed(p, "0\r\n\r\nGET") == ParseStatus::Complete);
      CHECK(p.body.size() == 30000);
      CHECK(p.leftover() == "GET");
    }
    // Byte at a time, and with a chunk larger than the compaction threshold.
    HttpParser q(lim);
    std::string all = head;
    const std::string bigChunk(40000, 'b');
    all += "9c40\r\n" + bigChunk + "\r\n";
    for (int i = 0; i < 300; ++i) all += "1;" + std::string(200, 'e') + "\r\nY\r\n";
    all += "0\r\n\r\n";
    ParseStatus st = ParseStatus::NeedMore;
    size_t peak = 0;
    for (size_t i = 0; i < all.size() && st == ParseStatus::NeedMore; ++i) {
      st = q.parse(all.data() + i, 1);
      if (q.buffered() > peak) peak = q.buffered();
    }
    CHECK(st == ParseStatus::Complete);
    CHECK(q.body.size() == 40300);
    CHECK(q.body.compare(0, 40000, bigChunk) == 0 && q.body.back() == 'Y');
    CHECK(peak < 2 * 40000 + HttpParser::kChunkCompactAt);
  }

  // Field-value bytes are checked a word at a time (validValueBytes): for
  // every byte value at every offset of a value long enough to span several
  // words and a tail, the word-wise answer is the table's, and a header line
  // carrying the byte is accepted or refused accordingly.
  {
    using moro::engine::kValueChar;
    using moro::engine::validValueBytes;
    for (unsigned b = 0; b < 256; ++b) {
      bool same = true, parsed = true;
      for (size_t len = 1; len <= 27; ++len) {
        for (size_t pos = 0; pos < len; ++pos) {
          std::string v(len, 'a');
          v[pos] = static_cast<char>(b);
          same = same && validValueBytes(reinterpret_cast<const unsigned char*>(v.data()), v.size()) == kValueChar[b];
          // A second byte of the other kind in the same word must not hide it.
          if (pos + 1 < len) {
            v[pos + 1] = '\t';
            same = same && validValueBytes(reinterpret_cast<const unsigned char*>(v.data()), v.size()) == kValueChar[b];
          }
        }
      }
      for (size_t pos = 1; pos <= 20; ++pos) {
        std::string v(22, 'a');
        v[pos] = static_cast<char>(b);
        const std::string req = "GET / HTTP/1.1\r\nHost: a\r\nX-V: " + v + "\r\n\r\n";
        HttpParser q;
        const ParseStatus st = q.parse(req.data(), req.size());
        parsed = parsed && (st == ParseStatus::Error) == !kValueChar[b];
      }
      CHECK(same);
      CHECK(parsed);
    }
  }

  if (testDeclaredBodyReserve() != 0) return 1;
  if (testHeaderStorage() != 0) return 1;

  // A comma in a Host name is refused (docs/THREAT_MODEL.md, "Host
  // discipline": a comma-separated second host), with or without a space,
  // with a port, on HTTP/1.0 too; inside the brackets of an IP-literal it is
  // an IPvFuture byte as before.
  for (const char* h : {"a,b", "a,", ",a", "a,b:80", "a.example,b.example", "a~b!$&'()*+,;=c"}) {
    CHECK(!validHostValue(h));
    HttpParser p;
    CHECK(feed(p, std::string("GET / HTTP/1.1\r\nHost: ") + h + "\r\n\r\n") == ParseStatus::Error);
    CHECK(p.errorStatus == 400);
    HttpParser q;
    CHECK(feed(q, std::string("GET / HTTP/1.0\r\nHost: ") + h + "\r\n\r\n") == ParseStatus::Error);
  }
  CHECK(validHostValue("[v1.a,b]"));

  std::printf("OK - %d checks passed\n", tests);
  // --- the request line: asterisk-form, an over-long method, a non-ASCII target ---
  {
    const auto status = [](const std::string& req, int& code) {
      HttpParser p;
      const ParseStatus st = feed(p, req);
      code = p.errorStatus;
      return st;
    };
    int code = 0;
    // asterisk-form belongs to OPTIONS alone (RFC 9112 §3.2.4)
    CHECK(status("OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);
    for (const char* m : {"GET", "HEAD", "POST", "DELETE", "FOO", "options"}) {
      CHECK(status(std::string(m) + " * HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Error);
      CHECK(code == 400);
    }
    CHECK(status("GET /* HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);
    CHECK(status("GET ** HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);  // opaque, as before

    // A method token past kMaxMethodLen is 501 - whole, split, or never
    // finished, and however far past maxHeadSize the line runs.
    const size_t max = HttpParser::kMaxMethodLen;
    CHECK(status(std::string(max, 'A') + " / HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);
    for (const size_t len : {max + 1, size_t(1000), size_t(100000)}) {
      const std::string all = std::string(len, 'A') + " / HTTP/1.1\r\nHost: h\r\n\r\n";
      CHECK(status(all, code) == ParseStatus::Error);
      CHECK(code == 501);
      for (const size_t step : {size_t(1), size_t(7), size_t(4096)}) {
        HttpParser split;
        ParseStatus st = ParseStatus::NeedMore;
        size_t fed = 0;
        for (; fed < all.size() && st == ParseStatus::NeedMore; fed += step)
          st = split.parse(all.data() + fed, step < all.size() - fed ? step : all.size() - fed);
        CHECK(st == ParseStatus::Error);
        CHECK(split.errorStatus == 501);
        CHECK(fed <= max + 1 + step);  // refused as soon as the bound is passed
      }
    }
    // ... on a second request of a connection, behind a first one in the same read
    {
      HttpParser p;
      const std::string two = "GET / HTTP/1.1\r\nHost: h\r\n\r\n" + std::string(max + 5, 'B');
      CHECK(feed(p, two) == ParseStatus::Complete);
      p.reset();
      CHECK(p.parse(nullptr, 0) == ParseStatus::Error);
      CHECK(p.errorStatus == 501);
    }
    // A long line that is not a long method keeps its own answer.
    CHECK(status("GET /" + std::string(200, 'a') + " HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);
    CHECK(status(std::string(30, 'A') + "\x01" + std::string(100, 'A') + " / HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Error);
    CHECK(code == 400);

    // A request-target is ASCII: raw UTF-8, an overlong form, a lone high byte.
    for (const char* t : {"/caf\xc3\xa9", "/\xc0\xaf", "/a?b=\xff", "/\x80"}) {
      CHECK(status(std::string("GET ") + t + " HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Error);
      CHECK(code == 400);
      HttpLimits lim;
      lim.allowNonAsciiTarget = true;  // as before 1.2.2
      HttpParser p(lim);
      CHECK(feed(p, std::string("GET ") + t + " HTTP/1.1\r\nHost: h\r\n\r\n") == ParseStatus::Complete);
    }
    CHECK(status("GET /caf%C3%A9 HTTP/1.1\r\nHost: h\r\n\r\n", code) == ParseStatus::Complete);
  }

  return 0;
}
