// Differential libFuzzer harness for the HTTP/1.1 request parser.
//
// The parser has three ways through a request head, and a server connection
// uses all of them: the buffered state machine (anything that does not start
// a read, and every continuation), the in-place scan with stored headers
// (HttpParser::parseDirectStored - the route hook says JS will see the
// request) and the in-place scan that stores nothing (scanLightHeaders - the
// hook says the engine answers it). fuzz_http_parser.cc installs no route
// hook and so only ever runs the first.
//
// Here the same bytes go through all three, whole and split at an arbitrary
// width, and every run must agree with the buffered, unsplit one: the same
// status, the same error code, the same request (method, target, version,
// persistence, Expect/Upgrade, body, stored headers) and the same bytes left
// over for the next request. A difference is a request that means one thing
// or another depending on how TCP delivered it or on which route it names,
// and aborts the run with the input printed.
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     test/fuzz/fuzz_http_diff.cc -o /tmp/fuzz_http_diff && \
//   /tmp/fuzz_http_diff -max_total_time=60 -max_len=20000

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../../src/http_parser.h"

using namespace moro::engine;

namespace {

struct Result {
  ParseStatus st = ParseStatus::NeedMore;
  int err = 0;
  Method method = Method::OTHER;
  std::string methodStr, path, query, body, rest;
  int minor = 1;
  bool keepAlive = true, expect = false, upgrade = false, light = false;
  HeaderList headers;
};

bool hookStored(void*, Method, const std::string&) { return false; }
bool hookLight(void*, Method, const std::string&) { return true; }

const HttpLimits& limits() {
  static const HttpLimits l = [] {
    HttpLimits x;
    x.maxHeadSize = 16 * 1024;
    x.maxHeaders = 100;
    x.maxBodySize = 1 * 1024 * 1024;
    return x;
  }();
  return l;
}

// Parse the first request of `d`, fed `chunk` bytes at a time (0: all at
// once) through a parser with the given route hook.
Result run(const uint8_t* d, size_t n, size_t chunk, HttpParser::RouteHook hook) {
  HttpParser p(limits());
  p.routeHook = hook;
  Result r;
  size_t off = 0;
  while (off < n) {
    const size_t k = chunk == 0 ? n - off : (chunk < n - off ? chunk : n - off);
    r.st = p.parse(reinterpret_cast<const char*>(d + off), k);
    off += k;
    if (r.st != ParseStatus::NeedMore) break;
  }
  r.light = p.light();
  if (r.st == ParseStatus::Error) {
    r.err = p.errorStatus;
    return r;
  }
  if (r.st == ParseStatus::Complete) {
    r.method = p.method;
    r.methodStr = p.methodStr;
    r.path = p.path;
    r.query = p.query;
    r.body = p.body;
    r.minor = p.minorVersion;
    r.keepAlive = p.keepAlive;
    r.expect = p.expectContinue();
    r.upgrade = p.hasUpgrade();
    if (!r.light) r.headers = p.headers;
    // What the next request starts with: the parser's leftover plus the
    // input it was not handed yet.
    r.rest.assign(p.leftover());
    r.rest.append(reinterpret_cast<const char*>(d + off), n - off);
  }
  return r;
}

[[noreturn]] void mismatch(const char* what, const uint8_t* d, size_t n, const char* a, const char* b) {
  std::fprintf(stderr, "MISMATCH %s between %s and %s; input (%zu bytes): ", what, a, b, n);
  for (size_t i = 0; i < n; i++) {
    const unsigned char c = d[i];
    if (c == '\r') std::fputs("\\r", stderr);
    else if (c == '\n') std::fputs("\\n", stderr);
    else if (c < 0x20 || c >= 0x7f) std::fprintf(stderr, "\\x%02x", c);
    else std::fputc(c, stderr);
  }
  std::fputc('\n', stderr);
  std::abort();
}

// `headers`: compare the stored header list too (not for a light run, which
// stores none).
void same(const Result& a, const Result& b, const uint8_t* d, size_t n, const char* an, const char* bn,
          bool headers) {
  if (a.st != b.st) mismatch("status", d, n, an, bn);
  if (a.st == ParseStatus::Error) {
    if (a.err != b.err) mismatch("errorStatus", d, n, an, bn);
    return;
  }
  if (a.st != ParseStatus::Complete) return;
  if (a.method != b.method || a.methodStr != b.methodStr) mismatch("method", d, n, an, bn);
  if (a.path != b.path || a.query != b.query) mismatch("target", d, n, an, bn);
  if (a.body != b.body) mismatch("body", d, n, an, bn);
  if (a.minor != b.minor || a.keepAlive != b.keepAlive) mismatch("version/keepAlive", d, n, an, bn);
  if (a.expect != b.expect || a.upgrade != b.upgrade) mismatch("expect/upgrade", d, n, an, bn);
  if (a.rest != b.rest) mismatch("leftover", d, n, an, bn);
  if (headers) {
    if (a.headers.size() != b.headers.size()) mismatch("header count", d, n, an, bn);
    for (size_t i = 0; i < a.headers.size(); i++)
      if (a.headers[i].name != b.headers[i].name || a.headers[i].value != b.headers[i].value)
        mismatch("header", d, n, an, bn);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  // Byte 0 chooses the split width (1..31); the rest is the input.
  const size_t split = (data[0] % 31) + 1;
  const uint8_t* d = data + 1;
  const size_t n = size - 1;

  const Result bufWhole = run(d, n, 0, nullptr);
  const Result bufSplit = run(d, n, split, nullptr);
  const Result storedWhole = run(d, n, 0, hookStored);
  const Result storedSplit = run(d, n, split, hookStored);
  const Result lightWhole = run(d, n, 0, hookLight);
  const Result lightSplit = run(d, n, split, hookLight);

  same(bufWhole, bufSplit, d, n, "buffered/whole", "buffered/split", true);
  same(bufWhole, storedWhole, d, n, "buffered/whole", "direct-stored/whole", true);
  same(bufWhole, storedSplit, d, n, "buffered/whole", "direct-stored/split", true);
  same(bufWhole, lightWhole, d, n, "buffered/whole", "light/whole", false);
  same(bufWhole, lightSplit, d, n, "buffered/whole", "light/split", false);
  return 0;
}
