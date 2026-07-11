// Standalone unit test for the HTTP/1.1 parser.
//   clang++ -std=c++20 -O2 test/http-parser-unit.cpp -o /tmp/hptest && /tmp/hptest
#include "../src/http_parser.h"

#include <cassert>
#include <cstdio>
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
  // A 26-digit length overflows size_t; must be rejected (413), never wrapped
  // to a small value that would slip past the limit and desync the body.
  {
    HttpParser p;  // default 10MB limit
    auto st = feed(p,
                   "POST / HTTP/1.1\r\nHost: a\r\n"
                   "Content-Length: 99999999999999999999999999\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 413);
  }

  // --- a Content-Length just over the default limit is rejected, not wrapped ---
  {
    HttpParser p;
    auto st = feed(p, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n");
    CHECK(st == ParseStatus::Error);  // 2^64, would wrap to 0
    CHECK(p.errorStatus == 413);
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
  // accumulator into an acceptable value; it is rejected as too large while
  // still parsing digits (413), before any body byte is consumed ---
  {
    HttpParser p;
    auto st = feed(p, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: " +
                          std::string(30, '9') + "\r\n\r\n");
    CHECK(st == ParseStatus::Error);
    CHECK(p.errorStatus == 413);
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

  // --- high bytes (raw UTF-8 paths) stay tolerated, matching Node ---
  {
    HttpParser p;
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

  std::printf("OK - %d checks passed\n", tests);
  return 0;
}
