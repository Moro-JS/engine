// libFuzzer harness for the HTTP/2 session and HPACK (src/http2.h).
// Arbitrary bytes are fed as a client's side of a connection, in splits of a
// size the input chooses, to a session whose host behaves the way a server
// does: it takes each request, answers some at once, keeps some and answers
// them later, and lets some be. The session must never crash, read out of
// bounds or hang, whatever the peer sends and however the host interleaves
// its answers.
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     test/fuzz/fuzz_http2.cc -o /tmp/fuzz_http2 && \
//   /tmp/fuzz_http2 -max_total_time=60 test/fuzz/corpus/http2
//
// Byte 0: the split size. Byte 1: bit 0 prepends a valid preface and
// SETTINGS so the fuzzer spends its time past the handshake, bits 1-2 pick
// what the host does with a request. The rest is the wire.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../../src/http2.h"

using namespace moro::engine;
using namespace moro::engine::h2;

namespace {

struct FuzzHost {
  Session* session = nullptr;
  int mode = 0;
  std::vector<Stream*> held;
  uint64_t touched = 0;

  static void dispatch(void* user, Stream& st) {
    FuzzHost* h = static_cast<FuzzHost*>(user);
    // Read everything a server would.
    h->touched += st.path.size() + st.query.size() + st.methodStr.size() + st.body.size();
    for (const Header& hd : st.headers) h->touched += hd.name.size() + hd.value.size();
    switch (h->mode) {
      case 0:  // answer at once, with a body
        h->respond(st, std::string(3000, 'x'));
        break;
      case 1:  // keep, answer when the feed is over
        h->session->hold(st, &st);
        h->held.push_back(&st);
        break;
      case 2:  // answer at once, no body
        h->respond(st, std::string());
        break;
      default:  // keep and never answer
        h->session->hold(st, &st);
        break;
    }
  }
  static void aborted(void* user, void* held) {
    FuzzHost* h = static_cast<FuzzHost*>(user);
    for (size_t i = 0; i < h->held.size(); i++) {
      if (h->held[i] == held) {
        h->held.erase(h->held.begin() + static_cast<std::ptrdiff_t>(i));
        break;
      }
    }
  }
  static void writable(void*, void*) {}

  void respond(Stream& st, const std::string& body) {
    std::string block;
    encodeStatus(block, 200);
    encodeField(block, "content-type", "text/plain");
    session->release(st);
    session->sendHeaders(st, block, body.empty());
    if (!body.empty()) session->sendData(st, body.data(), body.size(), true);
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  const size_t chunk = (data[0] % 64) + 1;
  const uint8_t flags = data[1];
  data += 2;
  size -= 2;

  Settings settings;
  settings.maxBodySize = 64 * 1024;
  settings.maxHeaderListSize = 8 * 1024;
  settings.maxConcurrentStreams = 16;
  FuzzHost fh;
  fh.mode = (flags >> 1) & 3;
  Host host;
  host.user = &fh;
  host.dispatch = FuzzHost::dispatch;
  host.aborted = FuzzHost::aborted;
  host.writable = FuzzHost::writable;
  Session session(settings, host);
  fh.session = &session;
  session.start();

  uint64_t now = 1000;
  if (flags & 1) {
    std::string open(kPreface);
    appendFrameHeader(open, 0, kSettings, 0, 0);
    session.feed(open.data(), open.size(), now);
  }
  size_t off = 0;
  while (off < size && !session.dead()) {
    const size_t n = chunk < size - off ? chunk : size - off;
    session.feed(reinterpret_cast<const char*>(data + off), n, now);
    off += n;
    now += 1;
    session.out().clear();
    if (fh.mode == 1 && (off / chunk) % 4 == 0) {
      std::vector<Stream*> later;
      later.swap(fh.held);
      for (Stream* st : later) fh.respond(*st, std::string(70000, 'y'));
      session.out().clear();
    }
  }
  if (!session.dead()) {
    std::vector<Stream*> later;
    later.swap(fh.held);
    for (Stream* st : later) fh.respond(*st, "tail");
    session.shutdown();
  }
  return 0;
}
