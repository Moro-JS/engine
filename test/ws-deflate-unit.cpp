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

  // --- an unknown parameter declines THAT offer, but a later valid offer wins ---
  {
    CHECK(!parsePmdOffer("permessage-deflate; bogus_param=1", enabledOpts()).has_value());
    auto p =
        parsePmdOffer("permessage-deflate; bogus_param, permessage-deflate", enabledOpts());
    CHECK(p.has_value());
  }

  // --- client_max_window_bits as a bare flag is accepted ---
  {
    auto p = parsePmdOffer("permessage-deflate; client_max_window_bits", enabledOpts());
    CHECK(p.has_value());
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
    CHECK(out.size() <= 1024 + 16384);               // bounded, not the full 200k
  }

  // --- corrupt compressed input fails cleanly ---
  {
    PmdParams params;
    PmdContext ctx(params, 1 << 20);
    std::string garbage = "\xff\xff\xff\xff\xff\xff", out;
    CHECK(!ctx.inflateMessage(garbage, out));
  }

  std::printf("ok  permessage-deflate inflate/deflate\n");
  std::printf("\nall ws-deflate unit tests passed (%d checks)\n", gChecks);
  return 0;
}
