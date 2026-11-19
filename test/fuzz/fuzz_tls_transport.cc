// libFuzzer harness for the TLS transform (src/tls.h).
//
// OpenSSL's own record/handshake parsing is heavily fuzzed upstream; the
// fresh attack surface here is OUR pump state machine around it -
// TlsSession::onCiphertext's BIO_write/SSL_accept/SSL_read loop, drain logic,
// and fatal-latch behavior. Two phases per input:
//
//   1. Cold start: arbitrary bytes fed in input-derived chunk sizes exercise
//      the pre-handshake SSL_accept path.
//   2. Established: a real in-memory client SSL completes the handshake
//      against the session, then the input drives post-handshake traffic -
//      a mix of records the client actually encrypted (valid ciphertext) and
//      raw mutated bytes - so the established-state SSL_read loop, the
//      ZERO_RETURN/shutdown path, and writePlain all get coverage.
//
// The first input byte picks the handshake of phase 2: TLS 1.2 or 1.3, a
// server that asks for a client certificate and takes any
// (requestCert + rejectUnauthorized:false), a client that presents one - a
// good one, or one whose signature does not verify - and the size of the
// pieces the client's flights arrive in. Post-handshake the client also
// sends the records the library answers by itself: a TLS 1.3 KeyUpdate, a
// TLS 1.2 renegotiation request.
//
// The invariants are: no crash, no hang, the fatal latch sticks, outbound
// ciphertext stays bounded - in total and against what one call was fed -
// every handshake above completes however it was split, and no call into the
// session returns with an error left in the thread's OpenSSL error queue
// (the next SSL_get_error() on the thread, the engine's or node's own, would
// read it as a failure of its own connection).
//
// The server identity is an ephemeral self-signed cert generated at init -
// no file dependencies, so the harness runs from any cwd.
//
// Build (see run.sh): clang++ -fsanitize=fuzzer,address,undefined \
//   test/fuzz/fuzz_tls_transport.cc -lssl -lcrypto -o /tmp/moro_fuzz_tls

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "../../src/tls.h"

using moro::engine::SslConfig;
using moro::engine::TlsContext;
using moro::engine::TlsSession;

static TlsContext* g_ctx = nullptr;
static TlsContext* g_ctxAnyCert = nullptr;  // requestCert, rejectUnauthorized: false
static SSL_CTX* g_cliCtx = nullptr;
static SSL_CTX* g_cliCtxCert = nullptr;     // presents a certificate that verifies
static SSL_CTX* g_cliCtxBadCert = nullptr;  // presents one with a broken signature

// A call into the session must not leave an error behind on the thread.
static void expectQuietErrorQueue() {
  if (ERR_peek_error() != 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }
}

static std::string pemFromKey(EVP_PKEY* pkey) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(len));
  BIO_free(bio);
  return out;
}

static std::string pemFromCert(X509* x) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, x);
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(len));
  BIO_free(bio);
  return out;
}

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  // Ephemeral P-256 key + self-signed cert, valid around "now".
  EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  X509* x = X509_new();
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_get_notBefore(x), -3600);
  X509_gmtime_adj(X509_get_notAfter(x), 3600L * 24 * 365);
  X509_set_pubkey(x, pkey);
  X509_NAME* name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("fuzz"), -1, -1, 0);
  X509_set_issuer_name(x, name);
  X509_sign(x, pkey, EVP_sha256());

  SslConfig cfg;
  cfg.keyPem = pemFromKey(pkey);
  cfg.certPem = pemFromCert(x);

  g_ctx = new TlsContext();
  std::string err = g_ctx->init(cfg);
  if (!err.empty()) {
    fprintf(stderr, "fuzz init failed: %s\n", err.c_str());
    abort();
  }

  // The same identity on a server that asks for a client certificate and
  // goes on whatever it is shown.
  SslConfig any = cfg;
  any.requestCert = true;
  any.rejectUnauthorized = false;
  any.caPem = cfg.certPem;
  g_ctxAnyCert = new TlsContext();
  err = g_ctxAnyCert->init(any);
  if (!err.empty()) {
    fprintf(stderr, "fuzz init (client certificates) failed: %s\n", err.c_str());
    abort();
  }

  // A client certificate issued by the identity above, and a copy of it with
  // one byte of the signature flipped.
  EVP_PKEY* ckey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  X509* cx = X509_new();
  ASN1_INTEGER_set(X509_get_serialNumber(cx), 2);
  X509_gmtime_adj(X509_get_notBefore(cx), -3600);
  X509_gmtime_adj(X509_get_notAfter(cx), 3600L * 24 * 365);
  X509_set_pubkey(cx, ckey);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(cx), "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("fuzz client"), -1, -1, 0);
  X509_set_issuer_name(cx, name);
  X509_sign(cx, pkey, EVP_sha256());
  unsigned char* der = nullptr;
  const int derLen = i2d_X509(cx, &der);
  if (derLen < 16) abort();
  der[derLen - 5] ^= 0xff;
  const unsigned char* derIn = der;
  X509* broken = d2i_X509(nullptr, &derIn, derLen);
  OPENSSL_free(der);
  if (!broken) abort();
  X509_free(x);
  EVP_PKEY_free(pkey);

  // Client side for phase 2. No verification: the peer is the ephemeral
  // self-signed cert above; this phase fuzzes the transport, not X.509 path
  // building.
  g_cliCtx = SSL_CTX_new(TLS_client_method());
  g_cliCtxCert = SSL_CTX_new(TLS_client_method());
  g_cliCtxBadCert = SSL_CTX_new(TLS_client_method());
  if (!g_cliCtx || !g_cliCtxCert || !g_cliCtxBadCert) abort();
  SSL_CTX_set_verify(g_cliCtx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_verify(g_cliCtxCert, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_verify(g_cliCtxBadCert, SSL_VERIFY_NONE, nullptr);
  if (SSL_CTX_use_certificate(g_cliCtxCert, cx) != 1 || SSL_CTX_use_PrivateKey(g_cliCtxCert, ckey) != 1 ||
      SSL_CTX_use_certificate(g_cliCtxBadCert, broken) != 1 ||
      SSL_CTX_use_PrivateKey(g_cliCtxBadCert, ckey) != 1) {
    abort();
  }
  X509_free(cx);
  X509_free(broken);
  EVP_PKEY_free(ckey);
  ERR_clear_error();
  return 0;
}

// Phase 2: complete a real handshake between a mem-BIO client SSL and a
// fresh TlsSession, then replay the input as post-handshake traffic.
static void fuzzEstablished(const uint8_t* data, size_t size) {
  // The handshake this input gets (see the head of the file).
  const uint8_t shape = size ? data[0] : 0;
  const bool tls12 = (shape & 1) != 0;
  const bool anyCert = (shape & 2) != 0;
  const unsigned clientCert = (shape >> 2) % 3;  // none, good, broken signature
  const size_t piece = (shape & 0x10) ? 1 + (shape >> 5) * 37 : 4096;

  TlsSession session((anyCert ? g_ctxAnyCert : g_ctx)->ctx());
  SSL* cli = SSL_new(clientCert == 1 ? g_cliCtxCert : clientCert == 2 ? g_cliCtxBadCert : g_cliCtx);
  if (cli) SSL_set_max_proto_version(cli, tls12 ? TLS1_2_VERSION : TLS1_3_VERSION);
  BIO* crbio = BIO_new(BIO_s_mem());  // server -> client
  BIO* cwbio = BIO_new(BIO_s_mem());  // client -> server
  if (!cli || !crbio || !cwbio) abort();
  SSL_set_bio(cli, crbio, cwbio);  // ownership -> cli
  SSL_set_connect_state(cli);

  std::string plain;
  auto sink = [&](const char* d, size_t n) { plain.append(d, n); };

  // Pump handshake flights both ways. Against our own context this always
  // completes; a bounded round count converts any pump bug into an abort
  // instead of a hang. Server->client bytes include post-handshake session
  // tickets - they sit unread in crbio, which is harmless (the client only
  // writes from here on).
  bool established = false;
  for (int round = 0; round < 16 && !established; round++) {
    ERR_clear_error();
    (void)SSL_do_handshake(cli);
    ERR_clear_error();
    char buf[4096];
    int n;
    while ((n = BIO_read(cwbio, buf, static_cast<int>(piece))) > 0) {
      std::string flight;
      session.onCiphertext(buf, static_cast<size_t>(n), sink, flight);
      expectQuietErrorQueue();
      for (size_t off = 0; off < flight.size();) {
        int w = BIO_write(crbio, flight.data() + off,
                          static_cast<int>(flight.size() - off));
        if (w <= 0) abort();
        off += static_cast<size_t>(w);
      }
    }
    established = session.handshakeDone() && SSL_is_init_finished(cli);
  }
  if (!established) abort();

  // Post-handshake traffic: selector bit picks valid ciphertext (client
  // SSL_write output carrying an input-derived payload) or raw mutated bytes.
  size_t i = 0;
  bool alive = true;
  while (i < size && alive) {
    uint8_t sel = data[i++];
    size_t chunk = 1 + (sel % 97);
    if (chunk > size - i) chunk = size - i;
    if (chunk == 0) break;

    std::string cipherOut;
    size_t fed = 0;
    if (sel & 1) {
      // Every fourth of these, a record the server answers on its own
      // rides ahead of the payload: a KeyUpdate that asks for one back, or
      // (TLS 1.2) the ClientHello of a renegotiation.
      if ((sel & 6) == 6) {
        if (tls12) {
          (void)SSL_renegotiate(cli);
          (void)SSL_do_handshake(cli);
        } else {
          (void)SSL_key_update(cli, SSL_KEY_UPDATE_REQUESTED);
        }
      }
      (void)SSL_write(cli, data + i, static_cast<int>(chunk));
      ERR_clear_error();
      char rec[8 * 1024];
      int rn;
      while ((rn = BIO_read(cwbio, rec, sizeof(rec))) > 0) {
        fed += static_cast<size_t>(rn);
        if (!session.onCiphertext(rec, static_cast<size_t>(rn), sink, cipherOut))
          alive = false;
        expectQuietErrorQueue();
      }
    } else {
      fed = chunk;
      alive = session.onCiphertext(reinterpret_cast<const char*>(data) + i,
                                   chunk, sink, cipherOut);
      expectQuietErrorQueue();
    }
    i += chunk;
    // Same amplification bound as phase 1, and what the session wrote in
    // answer to the peer stays within what the peer sent plus an alert.
    if (cipherOut.size() > (1u << 20)) abort();
    if (cipherOut.size() > fed + 512) abort();
    // Established write path, including after mutated input landed.
    std::string out;
    session.writePlain("pong", 4, out);
    ERR_clear_error();  // a write refused by a session that has failed
  }

  if (alive) {
    // Clean teardown: client close_notify must surface as ZERO_RETURN
    // (onCiphertext returns false) and our answering shutdown() must not
    // produce unbounded output.
    SSL_shutdown(cli);
    ERR_clear_error();
    char rec[4096];
    int rn;
    while ((rn = BIO_read(cwbio, rec, sizeof(rec))) > 0) {
      std::string cipherOut;
      session.onCiphertext(rec, static_cast<size_t>(rn), sink, cipherOut);
      expectQuietErrorQueue();
      if (cipherOut.size() > (1u << 20)) abort();
    }
    std::string out;
    session.shutdown(out);
    expectQuietErrorQueue();
  } else {
    // The fatal latch must stick in the established state too.
    std::string after;
    if (session.onCiphertext("x", 1, [](const char*, size_t) {}, after)) abort();
  }
  SSL_free(cli);  // frees crbio/cwbio
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // ---- Phase 1: raw bytes from a cold start (pre-handshake paths) ----
  {
    TlsSession session(g_ctx->ctx());
    std::string cipherOut;
    std::string plain;

    size_t i = 0;
    while (i < size) {
      // Input-derived split sizes exercise every partial-record path.
      size_t chunk = 1 + (data[i] % 97);
      if (chunk > size - i) chunk = size - i;
      bool ok = session.onCiphertext(
          reinterpret_cast<const char*>(data) + i, chunk,
          [&](const char* d, size_t n) { plain.append(d, n); }, cipherOut);
      expectQuietErrorQueue();
      if (!ok) {
        // The fatal latch must stick: further input is refused without effect.
        std::string after;
        if (session.onCiphertext("x", 1, [](const char*, size_t) {}, after)) abort();
        break;
      }
      i += chunk;
      // Outbound ciphertext for garbage input must stay small (alerts /
      // handshake flights); unbounded growth would be an amplification bug.
      if (cipherOut.size() > (1u << 20)) abort();
      // Exercise the write path once established.
      if (session.handshakeDone()) {
        std::string out;
        session.writePlain("pong", 4, out);
      }
    }
  }

  // ---- Phase 2: real handshake, then mutated post-handshake records ----
  fuzzEstablished(data, size);
  return 0;
}
