// libFuzzer harness for the TLS transform (src/tls.h).
//
// OpenSSL's own record/handshake parsing is heavily fuzzed upstream; the
// fresh attack surface here is OUR pump state machine around it -
// TlsSession::onCiphertext's BIO_write/SSL_accept/SSL_read loop, drain logic,
// and fatal-latch behavior. Arbitrary bytes are fed in input-derived chunk
// sizes; the invariants are: no crash, no hang, the fatal latch sticks, and
// outbound ciphertext stays bounded.
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
  X509_free(x);
  EVP_PKEY_free(pkey);

  g_ctx = new TlsContext();
  std::string err = g_ctx->init(cfg);
  if (!err.empty()) {
    fprintf(stderr, "fuzz init failed: %s\n", err.c_str());
    abort();
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
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
  return 0;
}
