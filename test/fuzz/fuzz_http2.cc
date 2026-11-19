// libFuzzer harness for the HTTP/2 session and HPACK (src/http2.h).
// Arbitrary bytes are fed as a client's side of a connection, in splits of a
// size the input chooses, to a session whose host behaves the way a server
// does: it takes each request, answers some at once, keeps some and answers
// them later, and lets some be; it writes an answer whole, in pieces with a
// wait for the peer's window in between, with a header block too large for
// one frame, or gives the stream up; and it stops the session part-way
// through its input, as a server does while its answers are not being read,
// and lets it go on later. The session must never crash, read out of bounds
// or hang, whatever the peer sends and however the host interleaves its
// answers - and stopping it must change nothing but when things happen.
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     test/fuzz/fuzz_http2.cc -o /tmp/fuzz_http2 && \
//   /tmp/fuzz_http2 -max_total_time=60 test/fuzz/corpus/http2
//
// Byte 0: the split size. Byte 1: bit 0 prepends a valid preface and
// SETTINGS so the fuzzer spends its time past the handshake, bits 1-2 pick
// what the host does with a request, bit 3 gives the session limits small
// enough for an input to reach (windows, body, header list, URI, streams),
// bit 4 has the host pause the session at every request, bits 5-6 pick how
// an answer is written, bit 7 has the host say GOAWAY half-way. The rest is
// the wire.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "../../src/http2.h"

using namespace moro::engine;
using namespace moro::engine::h2;

namespace {

struct FuzzHost {
  Session* session = nullptr;
  int mode = 0;
  int style = 0;
  bool pauses = false;
  std::vector<Stream*> held;       // kept, to be answered later
  std::vector<Stream*> streaming;  // answer begun, waiting for the peer's window
  std::vector<Stream*> ready;      // ...which has opened: to be finished after the feed
  uint64_t touched = 0;
  std::string seen;  // what the host was given and told, in order

  static void dispatch(void* user, Stream& st) {
    FuzzHost* h = static_cast<FuzzHost*>(user);
    // Read everything a server would.
    h->touched += st.path.size() + st.query.size() + st.methodStr.size() + st.body.size();
    for (const Header& hd : st.headers) h->touched += hd.name.size() + hd.value.size();
    h->seen += std::to_string(st.id) + ' ' + st.methodStr + ' ' + st.path + '?' + st.query + ' ' +
               std::to_string(st.headers.size()) + ' ' + std::to_string(st.body.size()) + '\n';
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
    if (h->pauses) h->session->pause();
  }
  static void forget(std::vector<Stream*>& list, void* held) {
    for (size_t i = 0; i < list.size(); i++) {
      if (list[i] == held) {
        list.erase(list.begin() + static_cast<std::ptrdiff_t>(i));
        return;
      }
    }
  }
  static void aborted(void* user, void* held) {
    FuzzHost* h = static_cast<FuzzHost*>(user);
    forget(h->held, held);
    forget(h->streaming, held);
    forget(h->ready, held);
    h->seen += "aborted\n";
  }
  // The stream the host was told to wait on has room. Like a server, which
  // tells its application later, the host finishes the answer after the feed.
  static void writable(void* user, void* held) {
    FuzzHost* h = static_cast<FuzzHost*>(user);
    const size_t before = h->streaming.size();
    forget(h->streaming, held);
    if (h->streaming.size() != before) h->ready.push_back(static_cast<Stream*>(held));
  }
  void finishReady() {
    std::vector<Stream*> now;
    now.swap(ready);
    for (Stream* st : now) finish(*st);
  }

  void finish(Stream& st) {
    session->release(st);
    session->sendData(st, "tail", 4, true);
  }

  void respond(Stream& st, const std::string& body) {
    std::string block;
    encodeStatus(block, 200);
    encodeField(block, "content-type", "text/plain");
    switch (style) {
      case 1: {  // in pieces: the head, a piece, and the rest when the peer has room
        session->hold(st, &st);
        session->sendHeaders(st, block, false);
        const size_t heldBack = session->sendData(st, body.data(), body.size(), false);
        if (heldBack != 0) {
          st.wantDrain = true;
          streaming.push_back(&st);
        } else {
          finish(st);
        }
        return;
      }
      case 2:  // a header block that takes CONTINUATION frames
        for (int i = 0; i < 40; i++) encodeField(block, "x-filler-" + std::to_string(i), std::string(1000, 'f'));
        break;
      case 3:  // the host gives the stream up
        session->reset(st, kInternalError);
        return;
      default:
        break;
    }
    session->release(st);
    session->sendHeaders(st, block, body.empty());
    if (!body.empty()) session->sendData(st, body.data(), body.size(), true);
  }
};

struct Outcome {
  std::string seen;
  std::string wire;
  bool dead = false;
};

// One connection: `data` as the client's bytes, in pieces of `chunk`. With
// `steady`, time stands still and nothing the host does depends on how far
// the session has got through its input, so two runs that differ only in
// pausing must agree.
Outcome run(const uint8_t* data, size_t size, size_t chunk, uint8_t flags, bool pauses, bool steady) {
  Settings settings;
  settings.maxBodySize = 64 * 1024;
  settings.maxHeaderListSize = 8 * 1024;
  settings.maxConcurrentStreams = 16;
  if (flags & 0x08) {
    settings.maxBodySize = 2048;
    settings.maxHeaderListSize = 512;
    settings.maxHeaders = 8;
    settings.maxUriSize = 48;
    settings.maxConcurrentStreams = 4;
    settings.headerTableSize = 256;
    settings.initialWindowSize = 1024;
    settings.connectionWindow = 512;
    settings.maxFrameSize = 32768;
  }
  FuzzHost fh;
  fh.mode = (flags >> 1) & 3;
  fh.style = (flags >> 5) & 3;
  fh.pauses = pauses;
  Host host;
  host.user = &fh;
  host.dispatch = FuzzHost::dispatch;
  host.aborted = FuzzHost::aborted;
  host.writable = FuzzHost::writable;
  Session session(settings, host);
  fh.session = &session;
  session.start();

  Outcome result;
  auto drain = [&] {
    result.wire += session.out();
    session.out().clear();
  };
  uint64_t now = 1000;
  if (flags & 1) {
    std::string open(kPreface);
    appendFrameHeader(open, 0, kSettings, 0, 0);
    session.feed(open.data(), open.size(), now);
  }
  size_t off = 0;
  size_t feeds = 0;
  while (off < size && !session.dead()) {
    const size_t n = chunk < size - off ? chunk : size - off;
    session.feed(reinterpret_cast<const char*>(data + off), n, now);
    off += n;
    feeds++;
    drain();
    // A paused session is let go on at every other feed, so that input also
    // arrives while it is stopped.
    if (session.paused() && feeds % 2 == 0) {
      session.resume();
      session.feed("", 0, now);
      drain();
    }
    if (steady) continue;
    now += 1;
    fh.finishReady();
    drain();
    if (fh.mode == 1 && feeds % 4 == 0) {
      std::vector<Stream*> later;
      later.swap(fh.held);
      for (Stream* st : later) fh.respond(*st, std::string(70000, 'y'));
      drain();
    }
    if ((flags & 0x80) && off >= size / 2 && !session.goawaySent()) {
      session.goaway();
      drain();
    }
  }
  // What a paused session still holds is gone through, a request at a time.
  while (session.paused() && !session.dead()) {
    session.resume();
    session.feed("", 0, now);
    drain();
  }
  if (!session.dead()) {
    std::vector<Stream*> later;
    later.swap(fh.held);
    for (Stream* st : later) fh.respond(*st, "tail");
    fh.finishReady();
    later.clear();
    later.swap(fh.streaming);
    for (Stream* st : later) fh.finish(*st);
    size_t stillHeld = 0;
    session.forEachHeld([&stillHeld](void*) { stillHeld++; });
    if (stillHeld != session.held()) abort();
    session.shutdown();
    drain();
  }
  result.seen.swap(fh.seen);
  result.dead = session.dead();
  return result;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  const size_t chunk = (data[0] % 64) + 1;
  const uint8_t flags = data[1];
  data += 2;
  size -= 2;

  if ((flags & 0x10) == 0) {
    run(data, size, chunk, flags, /*pauses=*/false, /*steady=*/false);
    return 0;
  }
  // The host stops the session at every request and lets it go on later:
  // the same requests, the same aborts and the same bytes on the wire as
  // with a host that never stops it.
  const Outcome plain = run(data, size, chunk, flags, /*pauses=*/false, /*steady=*/true);
  const Outcome paused = run(data, size, chunk, flags, /*pauses=*/true, /*steady=*/true);
  if (plain.seen != paused.seen || plain.dead != paused.dead || plain.wire != paused.wire) abort();
  return 0;
}
