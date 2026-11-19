// Unit tests for permessage-deflate negotiation + inflate/deflate roundtrips
// (src/ws_deflate.h). Compiled standalone by test/run-unit.sh (needs -lz).
//   clang++ -std=c++20 -O2 test/ws-deflate-unit.cpp -lz -o /tmp/pmdtest

#include "../src/ws_deflate.h"

#include <cstdio>
#include <string>

using namespace moro::engine;

static int gChecks = 0;
#define CHECK(cond)                                              \
  do {                                                           \
    ++gChecks;                                                   \
    if (!(cond)) {                                               \
      std::printf("FAIL line %d: %s\n", __LINE__, #cond);        \
      return 1;                                                  \
    }                                                            \
  } while (0)

static PmdOptions enabledOpts() {
  PmdOptions o;
  o.enabled = true;
  return o;
}

// Deflate a whole message as ONE raw DEFLATE stream ending in a BFINAL=1
// block (Z_FINISH) - the RFC 7692 §7.2.3.6 form a receiver must survive
// (no 0x00 0x00 0xFF 0xFF tail to strip; the stream simply ends).
static bool deflateBfinal(const std::string& in, std::string& out) {
  z_stream zs{};
  if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    return false;
  }
  out.resize(deflateBound(&zs, static_cast<uLong>(in.size())));
  zs.next_in = reinterpret_cast<unsigned char*>(const_cast<char*>(in.data()));
  zs.avail_in = static_cast<uInt>(in.size());
  zs.next_out = reinterpret_cast<unsigned char*>(out.data());
  zs.avail_out = static_cast<uInt>(out.size());
  int r = deflate(&zs, Z_FINISH);
  out.resize(out.size() - zs.avail_out);
  deflateEnd(&zs);
  return r == Z_STREAM_END;
}

int main() {
  // --- negotiation: a bare permessage-deflate offer is accepted ---
  {
    auto p = parsePmdOffer("permessage-deflate", enabledOpts());
    CHECK(p.has_value());
    CHECK(p->serverMaxWindowBits == 15 && p->clientMaxWindowBits == 15);
  }

  // --- disabled server never negotiates ---
  {
    PmdOptions off;  // enabled = false
    CHECK(!parsePmdOffer("permessage-deflate", off).has_value());
  }

  // --- client_no_context_takeover / server_no_context_takeover honored ---
  {
    auto p = parsePmdOffer(
        "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
        enabledOpts());
    CHECK(p.has_value());
    CHECK(p->clientNoContextTakeover && p->serverNoContextTakeover);
  }

  // --- server_max_window_bits caps our window (smaller wins) ---
  {
    auto p = parsePmdOffer("permessage-deflate; server_max_window_bits=10", enabledOpts());
    CHECK(p.has_value());
    CHECK(p->serverMaxWindowBits == 10);
  }

  // --- window bits out of range (7 or 16) declines the offer ---
  {
    CHECK(!parsePmdOffer("permessage-deflate; server_max_window_bits=7", enabledOpts()).has_value());
    CHECK(!parsePmdOffer("permessage-deflate; server_max_window_bits=16", enabledOpts()).has_value());
  }

  // --- window bits 8 declines the offer: zlib raw deflate can't honor an
  // 8-bit window, and echoing 9 would exceed the offer (§7.1.2.1) ---
  {
    CHECK(!parsePmdOffer("permessage-deflate; server_max_window_bits=8", enabledOpts()).has_value());
    CHECK(!parsePmdOffer("permessage-deflate; client_max_window_bits=8", enabledOpts()).has_value());
    auto p = parsePmdOffer("permessage-deflate; server_max_window_bits=9", enabledOpts());
    CHECK(p.has_value());
    CHECK(p->serverMaxWindowBits == 9);
  }

  // --- attacker-length digit strings decline the offer (no int overflow) ---
  {
    CHECK(!parsePmdOffer("permessage-deflate; server_max_window_bits=99999999999999999999",
                         enabledOpts())
               .has_value());
    CHECK(!parsePmdOffer("permessage-deflate; client_max_window_bits=4294967297",
                         enabledOpts())
               .has_value());
  }

  // --- an unknown parameter declines THAT offer, but a later valid offer wins ---
  {
    CHECK(!parsePmdOffer("permessage-deflate; bogus_param=1", enabledOpts()).has_value());
    auto p =
        parsePmdOffer("permessage-deflate; bogus_param, permessage-deflate", enabledOpts());
    CHECK(p.has_value());
  }

  // --- RFC 7692 §7: an offer is declined when it names a parameter twice,
  // gives a value to a parameter that takes none, or writes window bits with
  // a leading zero ("a decimal integer value without leading zeroes") ---
  {
    for (const char* offer : {
             "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
             "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
             "permessage-deflate; client_max_window_bits; client_max_window_bits",
             "permessage-deflate; client_max_window_bits=10; client_max_window_bits=12",
             "permessage-deflate; client_max_window_bits; client_max_window_bits=12",
             "permessage-deflate; server_max_window_bits=10; server_max_window_bits=12",
             "permessage-deflate; server_max_window_bits=10; server_max_window_bits=10",
             "permessage-deflate; server_no_context_takeover=1",
             "permessage-deflate; server_no_context_takeover=",
             "permessage-deflate; client_no_context_takeover=yes",
             "permessage-deflate; client_no_context_takeover=\"\"",
             "permessage-deflate; server_max_window_bits=010",
             "permessage-deflate; server_max_window_bits=09",
             "permessage-deflate; client_max_window_bits=012",
             "permessage-deflate; client_max_window_bits=\"012\"",
         }) {
      CHECK(!parsePmdOffer(offer, enabledOpts()).has_value());
    }
    // What stays acceptable: each parameter once, in any order, quoted or not.
    auto p = parsePmdOffer(
        "permessage-deflate; client_max_window_bits=\"12\"; server_no_context_takeover; "
        "server_max_window_bits=10; client_no_context_takeover",
        enabledOpts());
    CHECK(p.has_value());
    CHECK(p->clientMaxWindowBits == 12 && p->serverMaxWindowBits == 10);
    CHECK(p->serverNoContextTakeover && p->clientNoContextTakeover);
    // A declined offer does not take the next one down with it, and an offer
    // list handed over joined from several header lines reads the same.
    auto q = parsePmdOffer(
        "permessage-deflate; server_no_context_takeover=1, x-other, permessage-deflate; server_max_window_bits=11",
        enabledOpts());
    CHECK(q.has_value());
    CHECK(q->serverMaxWindowBits == 11 && !q->serverNoContextTakeover);
  }

  // --- client_max_window_bits as a bare flag is accepted ---
  {
    auto p = parsePmdOffer("permessage-deflate; client_max_window_bits", enabledOpts());
    CHECK(p.has_value());
  }

  // --- client_max_window_bits appears in the response ONLY when the offer
  // contained the parameter (§7.1.2.2): a configured preference below 15 is
  // dropped when the client never opted in ---
  {
    PmdOptions o = enabledOpts();
    o.clientMaxWindowBits = 12;

    auto p = parsePmdOffer("permessage-deflate", o);
    CHECK(p.has_value());
    CHECK(p->clientMaxWindowBits == 15);  // client will use a 15-bit window
    CHECK(buildPmdResponse(*p).find("client_max_window_bits") == std::string::npos);

    auto p2 = parsePmdOffer("permessage-deflate; client_max_window_bits", o);
    CHECK(p2.has_value());
    CHECK(p2->clientMaxWindowBits == 12);  // flag = client opted in
    CHECK(buildPmdResponse(*p2).find("client_max_window_bits=12") != std::string::npos);
  }

  // --- response header mirrors negotiated params ---
  {
    PmdParams p;
    p.serverMaxWindowBits = 12;
    p.clientNoContextTakeover = true;
    std::string r = buildPmdResponse(p);
    CHECK(r.find("permessage-deflate") == 0);
    CHECK(r.find("server_max_window_bits=12") != std::string::npos);
    CHECK(r.find("client_no_context_takeover") != std::string::npos);
  }

  std::printf("ok  permessage-deflate negotiation\n");

  // --- deflate -> inflate roundtrip (context takeover on) ---
  {
    PmdParams params;  // 15-bit windows, takeover on
    PmdContext server(params, 1 << 20);
    PmdContext client(params, 1 << 20);
    CHECK(server.valid() && client.valid());

    std::string msg(2000, 'A');
    std::string compressed, restored;
    CHECK(server.deflateMessage(msg, compressed));
    CHECK(compressed.size() < msg.size());  // it actually compressed
    CHECK(client.inflateMessage(compressed, restored));
    CHECK(restored == msg);
  }

  // --- two sequential messages with context takeover both roundtrip ---
  {
    PmdParams params;
    PmdContext server(params, 1 << 20);
    PmdContext client(params, 1 << 20);
    for (const char* text : {"hello world hello world", "second message here"}) {
      std::string in(text), c, out;
      CHECK(server.deflateMessage(in, c));
      CHECK(client.inflateMessage(c, out));
      CHECK(out == in);
    }
  }

  // --- no_context_takeover: reset between messages, still roundtrips ---
  {
    PmdParams params;
    params.serverNoContextTakeover = true;
    params.clientNoContextTakeover = true;
    PmdContext server(params, 1 << 20);
    PmdContext client(params, 1 << 20);
    for (int i = 0; i < 3; i++) {
      std::string in = "repeatable content " + std::to_string(i), c, out;
      CHECK(server.deflateMessage(in, c));
      CHECK(client.inflateMessage(c, out));
      CHECK(out == in);
    }
  }

  // --- a BFINAL=1 message must not poison the context for later messages
  // (RFC 7692 §7.2.3.6: a stream may end with the BFINAL bit set) ---
  {
    PmdParams params;  // context takeover on (the default mode)
    PmdContext client(params, 1 << 20);
    CHECK(client.valid());
    std::string first, second;
    CHECK(deflateBfinal("first message ends with BFINAL", first));
    CHECK(deflateBfinal("second message must still decode", second));
    std::string out;
    CHECK(client.inflateMessage(first, out));
    CHECK(out == "first message ends with BFINAL");
    CHECK(client.inflateMessage(second, out));
    CHECK(out == "second message must still decode");
  }

  // --- one message holding TWO back-to-back BFINAL streams decodes whole ---
  {
    PmdParams params;
    PmdContext client(params, 1 << 20);
    std::string a, b, out;
    CHECK(deflateBfinal("alpha ", a));
    CHECK(deflateBfinal("omega", b));
    CHECK(client.inflateMessage(a + b, out));
    CHECK(out == "alpha omega");
  }

  // --- zip-bomb defense: inflating past maxDecompressed fails, doesn't OOM ---
  {
    PmdParams params;
    PmdContext deflater(params, 1 << 30);
    std::string huge(200000, 'Z');  // compresses tiny, inflates large
    std::string compressed;
    CHECK(deflater.deflateMessage(huge, compressed));

    PmdContext capped(params, 1024);  // cap well below the real size
    std::string out;
    CHECK(!capped.inflateMessage(compressed, out));  // must refuse
    CHECK(out.size() <= 1024);                       // never exceeds the cap
  }

  // --- a zero cap would mean an uncapped inflate: refused at construction ---
  {
    PmdParams params;
    PmdContext uncapped(params, 0);
    CHECK(!uncapped.valid());
  }

  // --- corrupt compressed input fails cleanly ---
  {
    PmdParams params;
    PmdContext ctx(params, 1 << 20);
    std::string garbage = "\xff\xff\xff\xff\xff\xff", out;
    CHECK(!ctx.inflateMessage(garbage, out));
  }

  // --- why an inflate failed: over the cap (close 1009), or bytes that are
  // not a deflate stream (close 1007); cleared by the next success ---
  {
    PmdParams params;
    PmdContext deflater(params, 1 << 30);
    std::string big, small, out;
    CHECK(deflater.deflateMessage(std::string(200000, 'Z'), big));

    PmdContext capped(params, 1024);
    CHECK(!capped.inflateMessage(big, out));
    CHECK(capped.inflateOverCap());

    PmdContext ctx(params, 1024);
    CHECK(!ctx.inflateOverCap());
    // 0x07: BFINAL=1, BTYPE=3 - the reserved block type
    CHECK(!ctx.inflateMessage(std::string("\x07\xff\xff\xff", 4), out));
    CHECK(!ctx.inflateOverCap());

    PmdContext both(params, 1024);
    CHECK(!both.inflateMessage(big, out));
    CHECK(both.inflateOverCap());
    PmdContext fresh(params, 1024);
    PmdContext peer(params, 1 << 20);
    CHECK(peer.deflateMessage("fits", small));
    CHECK(fresh.inflateMessage(small, out));
    CHECK(out == "fits" && !fresh.inflateOverCap());
  }

  std::printf("ok  permessage-deflate inflate/deflate\n");

  // ==== SharedDeflator (wsDeflate.sharedCompressor) ====

  // --- reset-per-message semantics: two consecutive messages with IDENTICAL
  // repetitive content. With context takeover the second would compress as
  // back-references into the first's window; each must instead inflate on a
  // FRESH inflate stream (second first, to make any cross-reference fail) ---
  {
    SharedDeflator shared(15);
    CHECK(shared.valid());
    PmdParams params;
    std::string m1, m2;
    for (int i = 0; i < 40; i++) m1 += "shared-context-probe ";
    m2 = m1;  // identical: maximally tempting for cross-message references
    std::string c1, c2, out;
    CHECK(shared.deflateMessage(m1, c1));
    CHECK(shared.deflateMessage(m2, c2));
    {
      PmdContext fresh(params, 1 << 20);  // never saw c1
      CHECK(fresh.inflateMessage(c2, out));
      CHECK(out == m2);
    }
    {
      PmdContext fresh(params, 1 << 20);
      CHECK(fresh.inflateMessage(c1, out));
      CHECK(out == m1);
    }
  }

  // --- interleaved messages "from different connections": A and B alternate
  // through ONE shared stream; each message must inflate on its connection's
  // own inflate context (cross-connection contamination fails these) ---
  {
    SharedDeflator shared(15);
    PmdParams params;
    PmdContext inflA(params, 1 << 20), inflB(params, 1 << 20);
    CHECK(inflA.valid() && inflB.valid());
    for (int i = 0; i < 3; i++) {
      std::string a = "connection-A payload " + std::to_string(i) + " " + std::string(300, 'a');
      std::string b = "connection-B payload " + std::to_string(i) + " " + std::string(300, 'b');
      std::string ca, cb, out;
      CHECK(shared.deflateMessage(a, ca));
      CHECK(shared.deflateMessage(b, cb));
      CHECK(inflA.inflateMessage(ca, out));
      CHECK(out == a);
      CHECK(inflB.inflateMessage(cb, out));
      CHECK(out == b);
    }
  }

  // --- the deflateBound() reserve still holds for incompressible input
  // (stored blocks, deflate's worst case). deflateBound models a Z_FINISH
  // stream; Z_SYNC_FLUSH ends with an empty stored block instead (<= 5 bytes:
  // 3-bit header + byte alignment + LEN/NLEN), so the loop's raw output may
  // exceed the reserve by at most that constant - bounded, never unbounded
  // growth - and the message must still roundtrip whole (no truncation from
  // any sizing assumption) ---
  {
    SharedDeflator shared(15);
    std::string noise(100000, '\0');
    uint32_t seed = 0x12345678;
    for (auto& ch : noise) {
      seed = seed * 1664525u + 1013904223u;  // LCG: incompressible bytes
      ch = static_cast<char>(seed >> 24);
    }
    // A probe stream with the same params yields the same deflateBound the
    // reserve inside pmdDeflateMessage used.
    z_stream probe{};
    CHECK(deflateInit2(&probe, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
                       Z_DEFAULT_STRATEGY) == Z_OK);
    uLong bound = deflateBound(&probe, static_cast<uLong>(noise.size()));
    deflateEnd(&probe);
    std::string c, out;
    CHECK(shared.deflateMessage(noise, c));
    CHECK(c.size() + 4 <= bound + 5);  // +4 stripped tail, +5 sync-flush slack
    PmdParams params;
    PmdContext fresh(params, 1 << 20);
    CHECK(fresh.inflateMessage(c, out));
    CHECK(out == noise);
  }

  // --- PmdContext InflateOnly mode: valid with no deflate stream; a deflate
  // attempt refuses (shared connections must never compress here), while
  // inflate still roundtrips a SharedDeflator message ---
  {
    PmdParams params;
    PmdContext inflOnly(params, 1 << 20, PmdContext::Mode::InflateOnly);
    CHECK(inflOnly.valid());
    std::string c, out;
    CHECK(!inflOnly.deflateMessage("must refuse", c));
    SharedDeflator shared(15);
    std::string msg = "roundtrip through the shared stream";
    CHECK(shared.deflateMessage(msg, c));
    CHECK(inflOnly.inflateMessage(c, out));
    CHECK(out == msg);
  }

  // --- a message repeated back to back (a broadcast) gets the bytes the
  // stream itself produces for it, every time; a different message of the
  // same length in between is not mistaken for it; and a message too large
  // to be kept still goes through the stream each time ---
  {
    PmdParams params;
    std::string m;
    for (int i = 0; i < 60; i++) m += "{\"tick\":" + std::to_string(i * 7919 % 1000) + "},";
    std::string same = m;
    same[same.size() / 2] ^= 0x01;  // same length, one byte apart
    std::string want, wantSame;
    {
      SharedDeflator once(15);
      CHECK(once.deflateMessage(m, want));
    }
    {
      SharedDeflator once(15);
      CHECK(once.deflateMessage(same, wantSame));
    }
    CHECK(want != wantSame);
    SharedDeflator shared(15);
    std::string c, out;
    for (int i = 0; i < 4; i++) {
      CHECK(shared.deflateMessage(m, c));
      CHECK(c == want);
    }
    CHECK(shared.deflateMessage(same, c));
    CHECK(c == wantSame);
    CHECK(shared.deflateMessage(m, c));
    CHECK(c == want);
    CHECK(shared.deflateMessage(std::string_view(), c));
    CHECK(shared.deflateMessage(std::string_view(), c));
    {
      PmdContext fresh(params, 1 << 20);
      CHECK(fresh.inflateMessage(c, out));
      CHECK(out.empty());
    }
    std::string large(SharedDeflator::kMemoMax + 1, 'q');
    for (size_t i = 0; i < large.size(); i += 97) large[i] = static_cast<char>('a' + i % 23);
    std::string c1, c2;
    CHECK(shared.deflateMessage(large, c1));
    CHECK(shared.deflateMessage(large, c2));
    CHECK(c1 == c2);
    {
      PmdContext fresh(params, 1 << 20);
      CHECK(fresh.inflateMessage(c2, out));
      CHECK(out == large);
    }
    CHECK(shared.deflateMessage(m, c));
    CHECK(c == want);
  }

  // --- InflateOnly still refuses the uncapped (zero-cap) construction ---
  {
    PmdParams params;
    PmdContext uncapped(params, 0, PmdContext::Mode::InflateOnly);
    CHECK(!uncapped.valid());
  }

  std::printf("ok  shared deflator\n");

  // --- zlib counts its input in 32 bits, so a message goes to it in pieces
  // (a gigabyte each; a message of 4 GiB or more was cut to the low 32 bits
  // of its length when given whole). Here the pieces are small instead of
  // the message large: wherever they are cut - one byte, a size that leaves
  // a short last piece, exactly the message, more than the message - what
  // comes out inflates back to every byte that went in, and the inflater,
  // fed in pieces too, returns the same ---
  {
    std::string msg;
    uint32_t seed = 0x2545F491;
    while (msg.size() < 300000) {
      seed = seed * 1664525u + 1013904223u;
      msg += "{\"id\":" + std::to_string(seed % 100000) + ",\"side\":\"" +
             ((seed >> 20) & 1 ? "buy" : "sell") + "\"},";
    }
    PmdParams params;
    const size_t pieces[] = {1, 7, 4096, 65536, msg.size() - 1, msg.size(), msg.size() + 1};
    for (const size_t piece : pieces) {
      z_stream zs{};
      CHECK(deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) == Z_OK);
      std::string c, back;
      CHECK(pmdDeflateMessage(zs, msg, c, piece));
      // The stream goes on to a second message, as a connection's does.
      std::string c2, back2;
      CHECK(pmdDeflateMessage(zs, std::string_view(msg).substr(0, 1000), c2, piece));
      deflateEnd(&zs);
      CHECK(c.size() < msg.size() / 2);  // all of it was compressed, none of it stored or dropped
      PmdContext whole(params, 1 << 20);
      CHECK(whole.inflateMessage(c, back));
      CHECK(back == msg);
      CHECK(whole.inflateMessage(c2, back2));
      CHECK(back2 == msg.substr(0, 1000));
      PmdContext pieced(params, 1 << 20);
      back.clear();
      CHECK(pieced.inflateMessage(c, back, piece));
      CHECK(back == msg);
      CHECK(pieced.inflateMessage(c2, back2, piece));
      CHECK(back2 == msg.substr(0, 1000));
    }
    // The empty message is still one flush, and the output cap still holds
    // when the input arrives in pieces.
    {
      z_stream zs{};
      CHECK(deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) == Z_OK);
      std::string c, back;
      CHECK(pmdDeflateMessage(zs, std::string_view(), c, 1));
      CHECK(pmdDeflateMessage(zs, msg, c, 5000));
      deflateEnd(&zs);
      PmdContext capped(params, msg.size() - 1);
      CHECK(!capped.inflateMessage(c, back, 100));
      CHECK(capped.inflateOverCap());
    }
  }
  std::printf("ok  a message is deflated and inflated in pieces\n");

  std::printf("\nall ws-deflate unit tests passed (%d checks)\n", gChecks);
  return 0;
}
