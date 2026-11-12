// TLS termination for @morojs/engine.
//
// Links against the OpenSSL that ships INSIDE the host Node binary: every
// Node release exports the full libssl/libcrypto surface (verified per-ABI in
// CI with an `nm` assert), and the per-ABI build compiles against that same
// Node's bundled `openssl/` headers, so header and library versions can never
// skew. No OpenSSL is vendored or shipped.
//
// Design: a memory-BIO pair per connection. libuv owns the socket and hands
// us ciphertext; we pump it through SSL_read into the same plaintext parsers
// the plaintext path uses, and SSL_write's ciphertext output goes back out
// through the same uv_write machinery. The TLS layer is a pure transform -
// it does no I/O and holds no libuv state, which keeps it independently
// fuzzable (test/fuzz/fuzz_tls_transport.cc).
//
//   wire -> onCiphertext(bytes)  -> [rbio -> SSL_read]  -> plainSink(bytes)
//   app  -> writePlain(bytes)    -> [SSL_write -> wbio] -> cipherOut (uv_write)
//
// No V8 here. Original-code policy applies (CONTRIBUTING.md),
// OpenSSL API usage per the official man pages.

#pragma once

#include <openssl/ssl.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/aead.h>
#include <openssl/hmac.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace moro {
namespace engine {

// Which TLS library this binary is built against. Two binaries ship per
// platform and ABI: one links the OpenSSL the host node exports, the other
// carries BoringSSL inside the addon (tools/boringssl.mjs pins and builds it).
// Both speak OpenSSL's API; the few places where they differ are marked
// OPENSSL_IS_BORINGSSL in this file, and nowhere else in the engine.
#ifdef OPENSSL_IS_BORINGSSL
#define MORO_TLS_STR2(x) #x
#define MORO_TLS_STR(x) MORO_TLS_STR2(x)
inline const char* tlsLibraryName() { return "boringssl"; }
// The upstream version tag the build was pinned to, `0.YYYYMMDD.N`: its date
// is how old the bundled TLS code is.
inline const char* tlsLibraryVersion() {
#ifdef MORO_BORINGSSL_VERSION
  return MORO_TLS_STR(MORO_BORINGSSL_VERSION);
#else
  return "";
#endif
}
#else
inline const char* tlsLibraryName() { return "openssl"; }
// The host's library, asked at run time: it is whatever this node carries.
inline const char* tlsLibraryVersion() { return OpenSSL_version(OPENSSL_VERSION_STRING); }
#endif

// TLS options accepted from JS (serve() options.ssl). Both MoroJS shapes are
// supported: file paths (key_file_name/cert_file_name) and inline
// PEM bytes (node-style key/cert/ca as string|Buffer). Inline wins when both
// are present for the same slot.
struct SslConfig {
  // File-path shape
  std::string keyFile;
  std::string certFile;
  std::string caFile;
  // Inline-PEM shape (raw bytes; may contain a full chain)
  std::string keyPem;
  std::string certPem;
  std::string caPem;

  std::string passphrase;   // decrypts an encrypted private key
  std::string ticketKeys;   // 48-byte session-ticket key material (Node layout)
  // Optional explicit cipher/group policy for compliance baselines
  // (PCI/FIPS/hardened profiles); empty = the engine's default order over the
  // TLS library's own set. Mirrors Node's tls.createSecureContext knobs of the
  // same names.
  std::string ciphers;      // TLS <= 1.2 cipher list (SSL_CTX_set_cipher_list)
  std::string ciphersuites; // TLS 1.3 suites by IANA name, colon-separated
  std::string ecdhCurve;    // key-share groups (SSL_CTX_set1_groups_list); "auto" = default
  int minVersion = TLS1_2_VERSION;
  bool requestCert = false;         // ask the client for a certificate
  bool rejectUnauthorized = true;   // fail the handshake when it doesn't verify
  bool alpnH2 = false;              // offer "h2" in ALPN (set once HTTP/2 lands)

  bool enabled() const { return !(keyPem.empty() && keyFile.empty()) ||
                                !(certPem.empty() && certFile.empty()); }
  bool complete() const { return !(keyPem.empty() && keyFile.empty()) &&
                                 !(certPem.empty() && certFile.empty()); }
};

// Empty the thread's OpenSSL error queue ahead of an SSL_* I/O call, which
// SSL_get_error() needs to tell a real failure from one left behind by
// something else on the thread. ERR_clear_error() resets all sixteen slots of
// the queue whether or not any is in use, three frees each - some fifty calls
// to release nothing, paid before every read and write. The queue is empty
// here in all but the rare case, and asking is one thread-local load.
inline void clearErrorQueue() {
  if (ERR_peek_error() != 0) ERR_clear_error();
}

// Last OpenSSL error as a human-readable string, prefixed with context.
inline std::string sslError(const char* what) {
  char buf[256];
  unsigned long e = ERR_get_error();
  if (e) {
    ERR_error_string_n(e, buf, sizeof(buf));
  } else {
    snprintf(buf, sizeof(buf), "unknown OpenSSL error");
  }
  ERR_clear_error();
  return std::string(what) + ": " + buf;
}

// Per-Server TLS context: certificate/key material, protocol floor, ALPN
// preference, and client-cert policy. Built once at serve(); every
// connection's TlsSession derives from it.
class TlsContext {
 public:
  TlsContext() = default;
  TlsContext(const TlsContext&) = delete;
  TlsContext& operator=(const TlsContext&) = delete;
  TlsContext(TlsContext&& other) noexcept { *this = std::move(other); }
  TlsContext& operator=(TlsContext&& other) noexcept {
    if (this != &other) {
      reset();
      ctx_ = other.ctx_;
      passphrase_ = std::move(other.passphrase_);
      ticketKeys_ = std::move(other.ticketKeys_);
      alpnH2_ = other.alpnH2_;
      other.ctx_ = nullptr;
      // The SSL_CTX callbacks captured the moved-from object: the passwd cb's
      // userdata is our passphrase_ string, the ALPN select cb's arg is
      // `this`, and the ticket-key cb reaches us via SSL_CTX app_data.
      // Re-aim all of them at the moved-to object, or a later handshake
      // dereferences the old (often stack-allocated) TlsContext — a
      // use-after-return.
      if (ctx_) {
        SSL_CTX_set_default_passwd_cb_userdata(ctx_, &passphrase_);
        SSL_CTX_set_alpn_select_cb(ctx_, alpnSelectCb, this);
        SSL_CTX_set_app_data(ctx_, this);
      }
    }
    return *this;
  }
  ~TlsContext() { reset(); }

  SSL_CTX* ctx() const { return ctx_; }
  bool valid() const { return ctx_ != nullptr; }
  const std::string& ticketKeys() const { return ticketKeys_; }
  bool alpnH2() const { return alpnH2_; }

  // Build the SSL_CTX from the config. Returns "" on success, else a
  // human-readable error - config errors must be LOUD (serve() throws), never
  // a silent plaintext server.
  std::string init(const SslConfig& cfg) {
    reset();
    ERR_clear_error();
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) return sslError("SSL_CTX_new");
    passphrase_ = cfg.passphrase;
    alpnH2_ = cfg.alpnH2;

    // Session-ID context is mandatory for resumption on verifying servers:
    // without a sid-ctx, servers with SSL_VERIFY_PEER fatally reject
    // session-resumption attempts (SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED)
    // instead of falling back to a full handshake.
    SSL_CTX_set_session_id_context(
        ctx_, reinterpret_cast<const unsigned char*>("moro-engine"), 11);

    // ---- session-ticket keys (Node tls.Server `ticketKeys` contract) ----
    // One 48-byte secret in Node's layout: 16-byte key name, 16-byte HMAC
    // secret, 16-byte AES key - the same buffer tls.Server's setTicketKeys()
    // accepts. Servers configured with identical keys (reusePort workers,
    // separate processes) can decrypt each other's tickets, so TLS sessions
    // resume across all of them. Static keys trade forward secrecy for that
    // portability; generating and ROTATING them is the caller's job (Node's
    // tls.Server makes the same trade). When absent, OpenSSL keeps its
    // per-context random keys (tickets stay process-local).
    //
    // NOTE: OpenSSL 3.x's own SSL_CTX_set_tlsext_ticket_keys wants 80 bytes
    // (16-byte name + 32-byte HMAC + 32-byte AES) and would reject Node's
    // 48-byte buffer, so - exactly like Node - we install a ticket-key
    // callback that implements the 16/16/16 layout with AES-128-CBC +
    // HMAC-SHA256. Tickets minted here are wire-compatible across any two
    // engine servers sharing the keys.
    // The callbacks that take no user-data argument (ticket keys, the
    // ClientHello look) find this TlsContext through SSL_CTX app_data,
    // re-aimed on move (see operator=).
    SSL_CTX_set_app_data(ctx_, this);

    if (!cfg.ticketKeys.empty()) {
      if (cfg.ticketKeys.size() != 48) {
        // The binding validates length before Server construction; this is a
        // defensive backstop for non-JS callers of TlsContext.
        return "ticketKeys must be exactly 48 bytes (16-byte key name + "
               "16-byte HMAC secret + 16-byte AES key, Node's layout)";
      }
      ticketKeys_ = cfg.ticketKeys;
#ifdef OPENSSL_IS_BORINGSSL
      // The same callback and the same ticket format (AES-128-CBC,
      // HMAC-SHA256); BoringSSL hands it an HMAC_CTX where OpenSSL 3 hands an
      // EVP_MAC_CTX.
      if (SSL_CTX_set_tlsext_ticket_key_cb(ctx_, ticketKeyCb) != 1) {
        return sslError("SSL_CTX_set_tlsext_ticket_key_cb");
      }
#else
      if (SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx_, ticketKeyCb) != 1) {
        return sslError("SSL_CTX_set_tlsext_ticket_key_evp_cb");
      }
#endif
    }

    // Hardening baseline: TLS >= 1.2 (configurable floor), no renegotiation
    // (client-initiated renegotiation is a DoS vector), no TLS-level
    // compression (CRIME), server picks the cipher.
    SSL_CTX_set_min_proto_version(ctx_, cfg.minVersion);
    SSL_CTX_set_options(ctx_, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION |
                                  SSL_OP_CIPHER_SERVER_PREFERENCE);
    // Release idle buffers between records (~34KB/conn saved when quiet) and
    // let SSL_write report partial progress so large responses never stall.
    // (1.1.15 kept the buffers between records to save the malloc/free pair
    // per reply; measured on the HttpArena TLS profiles it moved nothing
    // outside noise, so the memory goes back to being saved.)
    SSL_CTX_set_mode(ctx_, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE |
                               SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // Optional explicit cipher/group policy (ssl.ciphers / ssl.ciphersuites /
    // ssl.ecdhCurve). Unset, the default order below applies. Config
    // errors are LOUD, same as bad key material - a server that silently
    // ignored its compliance profile would be worse than one that won't boot.
    if (!cfg.ciphers.empty() &&
        SSL_CTX_set_cipher_list(ctx_, cfg.ciphers.c_str()) != 1) {
      return sslError(("ssl.ciphers '" + cfg.ciphers + "' selects no cipher").c_str());
    }
    if (!cfg.ciphersuites.empty()) {
      std::string err = setTls13Suites(cfg.ciphersuites);
      if (!err.empty()) return err;
    }
    // No explicit policy: the default set, with the 128-bit key first.
    if (cfg.ciphers.empty() && cfg.ciphersuites.empty()) preferAes128();
    // "auto" = OpenSSL's built-in group preference (Node accepts it too).
    if (!cfg.ecdhCurve.empty() && cfg.ecdhCurve != "auto" &&
        SSL_CTX_set1_groups_list(ctx_, cfg.ecdhCurve.c_str()) != 1) {
      return sslError(("ssl.ecdhCurve '" + cfg.ecdhCurve + "' is invalid").c_str());
    }

    SSL_CTX_set_default_passwd_cb(ctx_, passwdCb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx_, &passphrase_);

    // ---- certificate (leaf + optional chain) ----
    if (!cfg.certPem.empty()) {
      std::string err = useCertPem(cfg.certPem);
      if (!err.empty()) return err;
    } else if (SSL_CTX_use_certificate_chain_file(ctx_, cfg.certFile.c_str()) != 1) {
      return sslError(("loading certificate file '" + cfg.certFile + "'").c_str());
    }

    // ---- private key ----
    if (!cfg.keyPem.empty()) {
      BIO* bio = BIO_new_mem_buf(cfg.keyPem.data(), static_cast<int>(cfg.keyPem.size()));
      if (!bio) return sslError("BIO_new_mem_buf(key)");
      EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, passwdCb, &passphrase_);
      BIO_free(bio);
      if (!pkey) return sslError("parsing private key (wrong passphrase or malformed PEM?)");
      int ok = SSL_CTX_use_PrivateKey(ctx_, pkey);
      EVP_PKEY_free(pkey);  // SSL_CTX_use_PrivateKey up-refs
      if (ok != 1) return sslError("SSL_CTX_use_PrivateKey");
    } else if (SSL_CTX_use_PrivateKey_file(ctx_, cfg.keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
      return sslError(("loading private key file '" + cfg.keyFile +
                       "' (wrong passphrase or malformed PEM?)").c_str());
    }

    // Key/cert mismatch is a config error, not a per-handshake surprise.
    if (SSL_CTX_check_private_key(ctx_) != 1) {
      return sslError("private key does not match the certificate");
    }

    // ---- CA(s): trust anchors for client-certificate verification ----
    // Each CA feeds BOTH the trust store and the advertised client-CA list
    // (the CertificateRequest's certificate_authorities, RFC 8446 4.2.4 /
    // RFC 5246 7.4.4) - without the latter, clients cannot pick which
    // certificate to present. This mirrors Node's tls.Server contract.
    if (!cfg.caPem.empty()) {
      std::string err = addCaPem(cfg.caPem);
      if (!err.empty()) return err;
    } else if (!cfg.caFile.empty()) {
      if (SSL_CTX_load_verify_locations(ctx_, cfg.caFile.c_str(), nullptr) != 1) {
        return sslError(("loading CA file '" + cfg.caFile + "'").c_str());
      }
      // SSL_CTX_set_client_CA_list takes ownership of the stack.
      STACK_OF(X509_NAME)* names = SSL_load_client_CA_file(cfg.caFile.c_str());
      if (names) SSL_CTX_set_client_CA_list(ctx_, names);
    }

    if (cfg.requestCert) {
      int mode = SSL_VERIFY_PEER;
      if (cfg.rejectUnauthorized) mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      // With rejectUnauthorized=false the app still gets the handshake even
      // when verification fails (verifyAccept overrides the result) - the
      // Node tls.Server contract.
      SSL_CTX_set_verify(ctx_, mode, cfg.rejectUnauthorized ? nullptr : verifyAccept);
    }

    // ALPN: prefer h2 when enabled, else http/1.1. A client offering neither
    // proceeds without ALPN and is served HTTP/1.1.
    SSL_CTX_set_alpn_select_cb(ctx_, alpnSelectCb, this);

    return "";
  }

 private:
  static int passwdCb(char* buf, int size, int /*rwflag*/, void* userdata) {
    const std::string* pass = static_cast<const std::string*>(userdata);
    if (!pass || pass->empty() || size <= 0) return 0;
    size_t n = pass->size() > static_cast<size_t>(size) ? static_cast<size_t>(size)
                                                        : pass->size();
    memcpy(buf, pass->data(), n);
    return static_cast<int>(n);
  }

  static int verifyAccept(int /*preverifyOk*/, X509_STORE_CTX* /*store*/) {
    return 1;  // rejectUnauthorized=false: accept regardless of verification
  }

  // Session-ticket key callback implementing Node's setTicketKeys() layout
  // (16-byte key name | 16-byte HMAC-SHA256 secret | 16-byte AES-128-CBC key)
  // per SSL_CTX_set_tlsext_ticket_key_evp_cb(3). Used for both TLS 1.2
  // tickets and TLS 1.3 NewSessionTicket PSKs. Return contract:
  //   enc=1: 1 = ticket built with these keys, -1 = error (no ticket).
  //   enc=0: 1 = key name matched, decrypt; 0 = foreign key name, fall back
  //          to a FULL handshake (never a hard failure); -1 = error.
#ifdef OPENSSL_IS_BORINGSSL
  using TicketMacCtx = HMAC_CTX;
  static bool ticketMacInit(HMAC_CTX* hctx, const unsigned char* key) {
    return HMAC_Init_ex(hctx, key, 16, EVP_sha256(), nullptr) == 1;
  }
#else
  using TicketMacCtx = EVP_MAC_CTX;
  static bool ticketMacInit(EVP_MAC_CTX* hctx, const unsigned char* key) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         const_cast<char*>("sha256"), 0),
        OSSL_PARAM_construct_end(),
    };
    return EVP_MAC_init(hctx, key, 16, params) == 1;
  }
#endif

  static int ticketKeyCb(SSL* ssl, unsigned char* name, unsigned char* iv,
                         EVP_CIPHER_CTX* ectx, TicketMacCtx* hctx, int enc) {
    SSL_CTX* sslCtx = SSL_get_SSL_CTX(ssl);
    TlsContext* self =
        static_cast<TlsContext*>(sslCtx ? SSL_CTX_get_app_data(sslCtx) : nullptr);
    if (!self || self->ticketKeys_.size() != 48) return -1;
    const unsigned char* keys =
        reinterpret_cast<const unsigned char*>(self->ticketKeys_.data());
    const unsigned char* keyName = keys;        // [0,16)  ticket key name
    const unsigned char* hmacKey = keys + 16;   // [16,32) HMAC-SHA256 secret
    const unsigned char* aesKey = keys + 32;    // [32,48) AES-128-CBC key
    if (enc) {
      memcpy(name, keyName, 16);
      // iv is an EVP_MAX_IV_LENGTH buffer; AES-128-CBC uses 16 of it.
      if (RAND_bytes(iv, 16) <= 0) return -1;
      if (EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), nullptr, aesKey, iv) != 1)
        return -1;
      if (!ticketMacInit(hctx, hmacKey)) return -1;
      return 1;
    }
    if (memcmp(name, keyName, 16) != 0) return 0;  // not ours: full handshake
    if (!ticketMacInit(hctx, hmacKey)) return -1;
    if (EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), nullptr, aesKey, iv) != 1)
      return -1;
    return 1;
  }

  static int alpnSelectCb(SSL* /*ssl*/, const unsigned char** out,
                          unsigned char* outlen, const unsigned char* in,
                          unsigned int inlen, void* arg) {
    TlsContext* self = static_cast<TlsContext*>(arg);
    // Server preference list, RFC 7301 wire format (len-prefixed).
    static const unsigned char kH2Http11[] = {2, 'h', '2', 8, 'h', 't', 't', 'p',
                                              '/', '1', '.', '1'};
    static const unsigned char kHttp11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const unsigned char* server = self->alpnH2_ ? kH2Http11 : kHttp11;
    unsigned int serverLen = self->alpnH2_ ? sizeof(kH2Http11) : sizeof(kHttp11);
    unsigned char* selected = nullptr;
    // CVE-2024-5535 guard: `selected` is meaningful ONLY when the return is
    // OPENSSL_NPN_NEGOTIATED. On any other return (notably an empty client
    // list) it may point at stale memory - never read it, never copy it into
    // *out; keep the NOACK fallback below on every non-negotiated path.
    if (SSL_select_next_proto(&selected, outlen, server, serverLen, in, inlen) ==
        OPENSSL_NPN_NEGOTIATED) {
      *out = selected;
      return SSL_TLSEXT_ERR_OK;
    }
    // No overlap: continue the handshake without ALPN (-> HTTP/1.1) rather
    // than alerting - curl/browsers always offer http/1.1, so this only
    // affects exotic clients, which still get a working h1 connection.
    return SSL_TLSEXT_ERR_NOACK;
  }

  // The default cipher preference, applied when the app names none.
  //
  // The server picks the cipher (SSL_OP_CIPHER_SERVER_PREFERENCE), and
  // AES-128-GCM goes ahead of AES-256-GCM: fourteen AES rounds per block
  // where ten give a security level nothing is expected to reach. 128-bit
  // AES-GCM is what Go's crypto/tls chooses first and what TLS 1.3 makes
  // mandatory to implement, and on a reply of a few kilobytes the difference
  // is a measurable share of the cost of encrypting it.
  //
  // The set of ciphers is left exactly as the TLS library (and whatever policy
  // configured it: security level, a distribution's crypto policy) gives it.
  // Only the order changes, and a client that offers only the 256-bit suite
  // still gets it.
  //
  // ChaCha20-Poly1305 goes first for a client that lists it first: that order
  // is how a client without AES hardware says so, and for it ChaCha20 is the
  // faster and safer choice.
  //
  // An app that wants another order sets ssl.ciphersuites / ssl.ciphers, and
  // none of this runs.
#ifdef OPENSSL_IS_BORINGSSL
  void preferAes128() {
    // On a server without AES hardware BoringSSL already leads with ChaCha20,
    // which is the right call for that machine: its order stands.
    if (!EVP_has_aes_hardware()) return;
    // TLS 1.3. BoringSSL's own server default is one equal-preference group
    // (the client's order decides), which hands AES-256 to every client built
    // on OpenSSL. TLS 1.2 needs nothing: its default list already opens with
    // the ECDHE AES-128-GCM suites.
    static const uint16_t kAes128First[] = {SSL_CIPHER_AES_128_GCM_SHA256,
                                            SSL_CIPHER_AES_256_GCM_SHA384,
                                            SSL_CIPHER_CHACHA20_POLY1305_SHA256};
    if (SSL_CTX_set1_tls13_ciphers(ctx_, kAes128First, nullptr, 3) != 1) ERR_clear_error();
    SSL_CTX_set_select_certificate_cb(ctx_, chaChaLedClientCb);
  }

  // Runs on the ClientHello, before anything is negotiated. A client whose
  // first cipher suite is a ChaCha20 one is served ChaCha20: its TLS 1.3 list
  // is reordered and, for TLS 1.2, its own order is followed. Every other
  // client keeps the context's order. (OpenSSL does the same thing under
  // SSL_OP_PRIORITIZE_CHACHA.)
  static enum ssl_select_cert_result_t chaChaLedClientCb(const SSL_CLIENT_HELLO* hello) {
    const uint8_t* p = hello->cipher_suites;
    for (size_t i = 0; i + 1 < hello->cipher_suites_len; i += 2) {
      // GREASE (RFC 8701) values are placeholders, not a preference: 0x?A?A.
      if (p[i] == p[i + 1] && (p[i] & 0x0f) == 0x0a) continue;
      const uint16_t id = static_cast<uint16_t>((p[i] << 8) | p[i + 1]);
      if (id == SSL_CIPHER_CHACHA20_POLY1305_SHA256 ||
          id == SSL_CIPHER_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
          id == SSL_CIPHER_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) {
        static const uint16_t kChaChaFirst[] = {SSL_CIPHER_CHACHA20_POLY1305_SHA256,
                                                SSL_CIPHER_AES_128_GCM_SHA256,
                                                SSL_CIPHER_AES_256_GCM_SHA384};
        if (SSL_set1_tls13_ciphers(hello->ssl, kChaChaFirst, nullptr, 3) != 1) ERR_clear_error();
        SSL_clear_options(hello->ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
      }
      break;
    }
    return ssl_select_cert_success;
  }

  // ssl.ciphersuites: TLS 1.3 suites by IANA name, in the app's order.
  // BoringSSL takes them by number and implements exactly these three.
  std::string setTls13Suites(const std::string& list) {
    static const struct { const char* name; uint16_t id; } kSuites[] = {
        {"TLS_AES_128_GCM_SHA256", SSL_CIPHER_AES_128_GCM_SHA256},
        {"TLS_AES_256_GCM_SHA384", SSL_CIPHER_AES_256_GCM_SHA384},
        {"TLS_CHACHA20_POLY1305_SHA256", SSL_CIPHER_CHACHA20_POLY1305_SHA256},
    };
    std::vector<uint16_t> ids;
    size_t at = 0;
    while (at <= list.size()) {
      size_t end = list.find(':', at);
      if (end == std::string::npos) end = list.size();
      const std::string name = list.substr(at, end - at);
      at = end + 1;
      if (name.empty()) continue;
      uint16_t id = 0;
      for (const auto& suite : kSuites) {
        if (name == suite.name) id = suite.id;
      }
      if (id == 0) {
        return "ssl.ciphersuites '" + list + "' is invalid: '" + name +
               "' is not a TLS 1.3 suite of the bundled TLS library (BoringSSL), which has "
               "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256";
      }
      if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    }
    if (ids.empty()) return "ssl.ciphersuites '" + list + "' is invalid: it names no suite";
    if (SSL_CTX_set1_tls13_ciphers(ctx_, ids.data(), nullptr, ids.size()) != 1) {
      return sslError(("ssl.ciphersuites '" + list + "' is invalid").c_str());
    }
    return "";
  }
#else
  std::string setTls13Suites(const std::string& list) {
    if (SSL_CTX_set_ciphersuites(ctx_, list.c_str()) != 1) {
      return sslError(("ssl.ciphersuites '" + list + "' is invalid").c_str());
    }
    return "";
  }

  // OpenSSL's own order puts AES-256-GCM ahead of AES-128-GCM: each
  // AES-256-GCM suite moves behind the AES-128-GCM suite with the same key
  // exchange and authentication, when there is one; everything else keeps its
  // place. SSL_OP_PRIORITIZE_CHACHA serves the client that leads with ChaCha20.
  void preferAes128() {
    STACK_OF(SSL_CIPHER)* all = SSL_CTX_get_ciphers(ctx_);
    if (!all) return;
    std::vector<const SSL_CIPHER*> v13, v12;
    for (int i = 0; i < sk_SSL_CIPHER_num(all); i++) {
      const SSL_CIPHER* c = sk_SSL_CIPHER_value(all, i);
      (SSL_CIPHER_get_min_tls_version_compat(c) >= TLS1_3_VERSION ? v13 : v12).push_back(c);
    }
    const std::string suites = namesAes128First(v13);
    const std::string list = namesAes128First(v12);
    // A list OpenSSL will not take back (it took it from OpenSSL) leaves the
    // order it had: the preference is an optimisation, never a boot failure.
    if (!suites.empty() && SSL_CTX_set_ciphersuites(ctx_, suites.c_str()) != 1) ERR_clear_error();
    if (!list.empty() && SSL_CTX_set_cipher_list(ctx_, list.c_str()) != 1) ERR_clear_error();
    SSL_CTX_set_options(ctx_, SSL_OP_PRIORITIZE_CHACHA);
  }

  // SSL_CIPHER_get_min_tls_version is not exported by every OpenSSL the host
  // Node may carry; the version string is, and is what tells the two lists
  // apart (TLS 1.3 suites are configured through their own call).
  static int SSL_CIPHER_get_min_tls_version_compat(const SSL_CIPHER* c) {
    const char* v = SSL_CIPHER_get_version(c);
    return (v && strcmp(v, "TLSv1.3") == 0) ? TLS1_3_VERSION : TLS1_2_VERSION;
  }

  // The colon-separated names of `ciphers` in order, each AES-256-GCM suite
  // placed directly after its AES-128-GCM counterpart (same key exchange,
  // same authentication) when the list has one further down.
  static std::string namesAes128First(const std::vector<const SSL_CIPHER*>& ciphers) {
    std::vector<const SSL_CIPHER*> order;
    std::vector<bool> taken(ciphers.size(), false);
    for (size_t i = 0; i < ciphers.size(); i++) {
      if (taken[i]) continue;
      const SSL_CIPHER* c = ciphers[i];
      if (SSL_CIPHER_get_cipher_nid(c) == NID_aes_256_gcm) {
        for (size_t j = i + 1; j < ciphers.size(); j++) {
          const SSL_CIPHER* d = ciphers[j];
          if (!taken[j] && SSL_CIPHER_get_cipher_nid(d) == NID_aes_128_gcm &&
              SSL_CIPHER_get_kx_nid(d) == SSL_CIPHER_get_kx_nid(c) &&
              SSL_CIPHER_get_auth_nid(d) == SSL_CIPHER_get_auth_nid(c)) {
            order.push_back(d);
            taken[j] = true;
            break;
          }
        }
      }
      order.push_back(c);
      taken[i] = true;
    }
    std::string names;
    for (const SSL_CIPHER* c : order) {
      const char* name = SSL_CIPHER_get_name(c);
      if (!name) continue;
      if (!names.empty()) names += ':';
      names += name;
    }
    return names;
  }
#endif

  // Inline PEM: first cert = leaf, remainder = intermediate chain.
  std::string useCertPem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return sslError("BIO_new_mem_buf(cert)");
    X509* leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!leaf) {
      BIO_free(bio);
      return sslError("parsing certificate PEM");
    }
    int ok = SSL_CTX_use_certificate(ctx_, leaf);
    X509_free(leaf);  // SSL_CTX_use_certificate up-refs
    if (ok != 1) {
      BIO_free(bio);
      return sslError("SSL_CTX_use_certificate");
    }
    // Remaining certs form the chain, in order. add_extra_chain_cert takes
    // ownership on success, so no X509_free on the happy path.
    while (X509* extra = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
      if (SSL_CTX_add_extra_chain_cert(ctx_, extra) != 1) {
        X509_free(extra);
        BIO_free(bio);
        return sslError("SSL_CTX_add_extra_chain_cert");
      }
    }
    // NULL from PEM_read_bio_X509 is a benign EOF only when the queued error
    // is PEM_R_NO_START_LINE; anything else is a truncated/corrupt
    // intermediate and must fail init() loudly, not boot with a broken chain.
    {
      unsigned long e = ERR_peek_last_error();
      if (ERR_GET_LIB(e) == ERR_LIB_PEM && ERR_GET_REASON(e) == PEM_R_NO_START_LINE) {
        ERR_clear_error();
      } else {
        BIO_free(bio);
        return sslError("parsing certificate chain PEM");
      }
    }
    BIO_free(bio);
    return "";
  }

  std::string addCaPem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return sslError("BIO_new_mem_buf(ca)");
    X509_STORE* store = SSL_CTX_get_cert_store(ctx_);
    int added = 0;
    while (X509* ca = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
      int ok = X509_STORE_add_cert(store, ca);
      // Advertise the subject in the client-CA list too (see init());
      // SSL_CTX_add_client_CA copies the subject name, no ownership transfer.
      int adv = SSL_CTX_add_client_CA(ctx_, ca);
      X509_free(ca);  // X509_STORE_add_cert up-refs
      if (ok != 1) {
        BIO_free(bio);
        return sslError("X509_STORE_add_cert");
      }
      if (adv != 1) {
        BIO_free(bio);
        return sslError("SSL_CTX_add_client_CA");
      }
      added++;
    }
    // NULL from PEM_read_bio_X509 is a benign EOF only when the queued error
    // is PEM_R_NO_START_LINE; anything else is a truncated/corrupt CA cert
    // and must fail init() loudly, not boot a server with a broken store.
    {
      unsigned long e = ERR_peek_last_error();
      if (ERR_GET_LIB(e) == ERR_LIB_PEM && ERR_GET_REASON(e) == PEM_R_NO_START_LINE) {
        ERR_clear_error();
      } else {
        BIO_free(bio);
        return sslError("parsing ca PEM");
      }
    }
    BIO_free(bio);
    if (added == 0) return "ca contained no PEM certificates";
    return "";
  }

  void reset() {
    if (ctx_) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  SSL_CTX* ctx_ = nullptr;
  std::string passphrase_;
  std::string ticketKeys_;  // 48 bytes (name|hmac|aes) when configured, else empty
  bool alpnH2_ = false;
};

// Per-connection TLS transform. Pure: consumes/produces byte buffers, never
// touches the socket. The caller (server.h) owns all I/O and lifetimes.
//
// The BIOs are the engine's own. The read BIO is a view over the caller's
// buffer for the duration of one onCiphertext(): OpenSSL's record layer copies
// records out of it, and that is the only copy on the way in (BIO_s_mem put a
// second one, into its own buffer, ahead of it). The write BIO appends
// ciphertext straight into the string the caller passed: a record is one
// append, where BIO_s_mem grew its own buffer by copying, was copied out of
// again in drain(), and then zeroed its whole capacity on reset - three
// passes over a large body on top of the encryption, each paid again as fresh
// pages once the buffers were freed between replies.
class TlsSession {
 public:
  explicit TlsSession(SSL_CTX* ctx) {
    ssl_ = SSL_new(ctx);
    rbio_ = BIO_new(viewReadMethod());
    wbio_ = BIO_new(appendWriteMethod());
    if (!ssl_ || !rbio_ || !wbio_) {
      // Allocation failure. SSL_set_bio must only see valid BIOs, so
      // ownership never transferred - free each piece individually and latch
      // fatal_ so the caller sheds the connection instead of dereferencing
      // nulls (every member function early-outs on fatal_).
      if (rbio_) BIO_free(rbio_);
      if (wbio_) BIO_free(wbio_);
      if (ssl_) SSL_free(ssl_);
      ssl_ = nullptr;
      rbio_ = nullptr;
      wbio_ = nullptr;
      fatal_ = true;
      return;
    }
    BIO_set_data(rbio_, this);
    BIO_set_data(wbio_, this);
    // SSL_set_bio transfers BIO ownership to the SSL object; SSL_free frees all.
    SSL_set_bio(ssl_, rbio_, wbio_);
    SSL_set_accept_state(ssl_);
  }
  TlsSession(const TlsSession&) = delete;
  TlsSession& operator=(const TlsSession&) = delete;
  ~TlsSession() {
    if (ssl_) SSL_free(ssl_);
  }

  bool handshakeDone() const { return handshakeDone_; }

  // Whether ALPN settled on HTTP/2 (meaningful once the handshake is done).
  bool alpnIsH2() const {
    if (!ssl_) return false;
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &proto, &len);
    return proto != nullptr && len == 2 && proto[0] == 'h' && proto[1] == '2';
  }

  // Negotiated ALPN protocol ("h2" / "http/1.1"), or "" when none.
  std::string alpn() const {
    if (!ssl_) return std::string();
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &proto, &len);
    return proto ? std::string(reinterpret_cast<const char*>(proto), len) : std::string();
  }

  // Feed ciphertext from the wire. Decrypted bytes are handed to plainSink
  // (possibly multiple calls); outbound ciphertext (handshake flights, key
  // updates, alerts) is appended to cipherOut and must be written to the
  // socket by the caller even when this returns false. Returns false on a
  // fatal TLS error OR a clean close_notify - either way the connection is
  // done receiving.
  //
  // `data` is only read during this call: the record layer copies what it
  // needs into its own buffer, a partial record included, so the caller's
  // buffer is free again on return.
  //
  // plainSink may tear the connection down (doClose sets Connection.closing);
  // the caller re-checks that after this returns. The session itself stays
  // valid until destroyed.
  //
  // Ordering: ciphertext already in cipherOut when plainSink runs (a TLS 1.3
  // session ticket, sent on the heels of the handshake) precedes, in record
  // sequence, anything plainSink then encrypts with writePlain. A caller
  // that answers from inside plainSink must put cipherOut on the wire
  // first - server.h does, before every dispatch - or the peer sees records
  // out of sequence and fails the MAC.
  template <typename Sink>
  bool onCiphertext(const char* data, size_t len, Sink&& plainSink,
                    std::string& cipherOut) {
    if (fatal_) return false;
    // Bytes the record layer left unread last time (it never does; kept so a
    // future OpenSSL that stops short mid-buffer cannot lose them).
    if (!carry_.empty()) {
      carry_.append(data, len);
      in_ = carry_.data();
      inLen_ = carry_.size();
    } else {
      in_ = data;
      inLen_ = len;
    }
    inOff_ = 0;
    out_ = &cipherOut;
    flushStash();

    bool ok = true;
    if (!handshakeDone_) {
      clearErrorQueue();
      int r = SSL_accept(ssl_);
      if (r == 1) {
        handshakeDone_ = true;
      } else {
        int err = SSL_get_error(ssl_, r);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
          // Garbage, protocol mismatch, or a failed client-cert verify. The
          // alert (if any) is already in cipherOut - fail.
          ERR_clear_error();
          fatal_ = true;
          ok = false;
        }
        // Otherwise the handshake flight is in cipherOut; need more ciphertext.
        endIo(ok);
        return ok;
      }
    }

    // Established (possibly just now, with app data in the same flight):
    // drain every complete record.
    //
    // The loop ends without a last SSL_read once the view is used up and the
    // record layer holds nothing, processed or not: that call could only
    // report WANT_READ, and to find that out it allocated the record buffer
    // it had just released, asked the BIO, and released it again - once per
    // request on a connection whose requests arrive one record at a time.
    for (;;) {
      char buf[16 * 1024];
      clearErrorQueue();
      int n = SSL_read(ssl_, buf, sizeof(buf));
      if (n > 0) {
        plainSink(buf, static_cast<size_t>(n));
        if (inOff_ >= inLen_ && SSL_has_pending(ssl_) == 0) break;
        continue;
      }
      int err = SSL_get_error(ssl_, n);
      if (err == SSL_ERROR_WANT_READ) break;  // consumed everything available
      if (err == SSL_ERROR_ZERO_RETURN) {
        // Clean close_notify: answer with ours (best-effort) and report EOF.
        SSL_shutdown(ssl_);
        ok = false;
        break;
      }
      ERR_clear_error();
      fatal_ = true;
      ok = false;
      break;
    }
    endIo(ok);
    return ok;
  }

  // Encrypt plaintext, appending the ciphertext to cipherOut. Returns false
  // on error (e.g. called before the handshake completed - the engine only
  // responds to parsed requests, which implies an established session, so
  // this indicates a bug or a torn-down session).
  //
  // `more`: further plaintext of the same reply follows in another call (a
  // head ahead of its body). It only matters to a direct outlet, below.
  bool writePlain(const char* data, size_t len, std::string& cipherOut, bool more = false) {
    if (fatal_ || !handshakeDone_) return false;
    // Usually called from inside onCiphertext's plainSink (a request answered
    // synchronously): the outer call's target is put back afterwards.
    std::string* const outer = out_;
    out_ = &cipherOut;
    flushStash();
    // One record per 16 KiB of plaintext, a few dozen bytes of framing each
    // (TLS 1.3: 5-byte header, inner content type, 16-byte tag): reserved up
    // front so the appends never regrow the buffer mid-body. Not with a
    // direct outlet, where the buffer only ever holds what could not be sent.
    if (!direct_) cipherOut.reserve(cipherOut.size() + len + 64 + (len / 16384 + 1) * 32);
    // Cap each SSL_write at 1 MiB: a >= 2 GiB remainder would cast negative
    // (SSL_write takes int) and tear the connection down as a fake error.
    size_t off = 0;
    while (off < len) {
      clearErrorQueue();
      const int chunk = static_cast<int>(std::min<size_t>(len - off, 1u << 20));
      // A record carries at most 16 KiB of plaintext and SSL_write returns
      // after each (SSL_MODE_ENABLE_PARTIAL_WRITE), so this is whether
      // another record of the reply comes after the one about to be written.
      directMore_ = more || (len - off) > kMaxRecordPlain;
      int n = SSL_write(ssl_, data + off, chunk);
      if (n <= 0) {
        // The write BIO always accepts, so WANT_WRITE cannot happen; anything
        // else is fatal.
        fatal_ = true;
        out_ = outer;
        return false;
      }
      off += static_cast<size_t>(n);
    }
    out_ = outer;
    return true;
  }

  // A direct outlet for the ciphertext of the writePlain calls made until
  // endDirect(): each record is offered to `send` where OpenSSL produced it,
  // in its own record buffer, and only what the socket would not take is
  // appended to the caller's buffer. Without it a record is copied out of
  // that buffer into the caller's and from there into the kernel; with it,
  // only into the kernel. The session still does no I/O of its own: `send` is
  // the caller's, and the caller decides when a direct write is in order
  // (nothing queued ahead on the socket, the buffer it passes to writePlain
  // empty).
  //
  // send(user, held, heldLen, data, len, more) writes `held` then `data` and
  // returns the bytes taken (both pieces counted), or a negative value when
  // none were. `held` is what an earlier, small record of the same reply left
  // in the caller's buffer to leave together with this one - a response head
  // ahead of its body is one send, not two. `more` asks for the segment to be
  // held open for what follows (MSG_MORE where there is such a thing).
  //
  // The first short send ends the direct writes of this bracket: everything
  // after it is appended behind the remainder, in order.
  using DirectSend = long (*)(void* user, const char* held, size_t heldLen,
                              const char* data, size_t len, bool more);
  void beginDirect(DirectSend send, void* user) {
    direct_ = send;
    directUser_ = user;
    directBlocked_ = false;
  }
  void endDirect() {
    direct_ = nullptr;
    directUser_ = nullptr;
    directMore_ = false;
  }

  // Best-effort close_notify for a graceful teardown; appends the alert
  // ciphertext to cipherOut (empty when the handshake never completed).
  void shutdown(std::string& cipherOut) {
    if (fatal_ || !handshakeDone_) return;
    std::string* const outer = out_;
    out_ = &cipherOut;
    flushStash();
    clearErrorQueue();
    SSL_shutdown(ssl_);
    out_ = outer;
  }

 private:
  // The read view is over for this call: whatever the record layer did not
  // take is kept (never, in practice - it reads everything a BIO offers).
  void endIo(bool ok) {
    if (ok && inOff_ < inLen_) {
      std::string rest(in_ + inOff_, inLen_ - inOff_);
      carry_.swap(rest);
    } else {
      carry_.clear();
    }
    in_ = nullptr;
    inLen_ = inOff_ = 0;
    out_ = nullptr;
  }

  // Ciphertext OpenSSL produced while no caller buffer was set (it does not,
  // outside the calls above; stash_ is the safety net) goes to the next one.
  void flushStash() {
    if (!stash_.empty() && out_) {
      out_->append(stash_);
      stash_.clear();
    }
  }

  // ---- the BIO methods: built once per process, shared by every session ----

  static int bioCreate(BIO* b) {
    BIO_set_init(b, 1);
    return 1;
  }
  static int bioDestroy(BIO* b) {
    if (!b) return 0;
    BIO_set_data(b, nullptr);
    BIO_set_init(b, 0);
    return 1;
  }

  // Read side: records are copied out of the current view; an empty view is
  // "would block", which SSL_read reports as WANT_READ.
  static int rbioRead(BIO* b, char* out, int len) {
    auto* s = static_cast<TlsSession*>(BIO_get_data(b));
    BIO_clear_retry_flags(b);
    if (!s || !out || len <= 0) return 0;
    const size_t avail = s->inLen_ - s->inOff_;
    if (avail == 0) {
      BIO_set_retry_read(b);
      return -1;
    }
    const size_t n = std::min(avail, static_cast<size_t>(len));
    memcpy(out, s->in_ + s->inOff_, n);
    s->inOff_ += n;
    return static_cast<int>(n);
  }
  static int rbioWrite(BIO* b, const char*, int) {
    BIO_clear_retry_flags(b);
    return -1;  // the read BIO is never written
  }
  static long rbioCtrl(BIO* b, int cmd, long, void*) {
    switch (cmd) {
      case BIO_CTRL_FLUSH:
        return 1;
      case BIO_CTRL_PENDING: {
        auto* s = static_cast<TlsSession*>(BIO_get_data(b));
        return s ? static_cast<long>(s->inLen_ - s->inOff_) : 0;
      }
      default:
        return 0;  // EOF: no; WPENDING: 0; everything else: unsupported
    }
  }

  // Write side: every record is appended to the caller's buffer as it is
  // produced, never buffered here.
  static int wbioWrite(BIO* b, const char* in, int len) {
    auto* s = static_cast<TlsSession*>(BIO_get_data(b));
    BIO_clear_retry_flags(b);
    if (!s || len < 0) return -1;
    if (len == 0) return 0;
    std::string* out = s->out_ ? s->out_ : &s->stash_;
    const size_t n = static_cast<size_t>(len);
    if (s->direct_ && s->out_ && !s->directBlocked_) {
      // A small record with more of the reply behind it waits for the next
      // one, so the two leave in a single send.
      if (s->directMore_ && n <= kHoldRecord && out->size() + n <= kHoldTotal) {
        out->append(in, n);
        return len;
      }
      const size_t held = out->size();
      const long sent = s->direct_(s->directUser_, out->data(), held, in, n, s->directMore_);
      if (sent >= 0 && static_cast<size_t>(sent) == held + n) {
        out->clear();
        return len;
      }
      // Short or refused: what is left stays in the caller's buffer, in
      // order, and the rest of the reply is appended behind it.
      s->directBlocked_ = true;
      const size_t took = sent > 0 ? static_cast<size_t>(sent) : 0;
      if (took >= held) {
        out->clear();
        out->append(in + (took - held), n - (took - held));
      } else {
        out->erase(0, took);
        out->append(in, n);
      }
      return len;
    }
    out->append(in, n);
    return len;
  }
  static int wbioRead(BIO* b, char*, int) {
    BIO_clear_retry_flags(b);
    return -1;  // the write BIO is never read
  }
  static long wbioCtrl(BIO*, int cmd, long, void*) {
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
  }

  static BIO_METHOD* viewReadMethod() {
    static BIO_METHOD* method = [] {
      BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "moro-engine view");
      if (!m) return m;
      BIO_meth_set_read(m, rbioRead);
      BIO_meth_set_write(m, rbioWrite);
      BIO_meth_set_ctrl(m, rbioCtrl);
      BIO_meth_set_create(m, bioCreate);
      BIO_meth_set_destroy(m, bioDestroy);
      return m;
    }();
    return method;
  }
  static BIO_METHOD* appendWriteMethod() {
    static BIO_METHOD* method = [] {
      BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "moro-engine append");
      if (!m) return m;
      BIO_meth_set_read(m, wbioRead);
      BIO_meth_set_write(m, wbioWrite);
      BIO_meth_set_ctrl(m, wbioCtrl);
      BIO_meth_set_create(m, bioCreate);
      BIO_meth_set_destroy(m, bioDestroy);
      return m;
    }();
    return method;
  }

  SSL* ssl_ = nullptr;
  BIO* rbio_ = nullptr;  // wire -> SSL (owned by ssl_ after SSL_set_bio)
  BIO* wbio_ = nullptr;  // SSL -> wire (owned by ssl_)
  // The read view of the call in progress (onCiphertext).
  const char* in_ = nullptr;
  size_t inLen_ = 0;
  size_t inOff_ = 0;
  // Where ciphertext goes during the call in progress; stash_ between calls.
  std::string* out_ = nullptr;
  std::string stash_;
  std::string carry_;
  // The direct outlet of the reply being written, if any (beginDirect).
  static constexpr size_t kMaxRecordPlain = 16384;  // RFC 8446 5.1: a record's plaintext limit
  static constexpr size_t kHoldRecord = 2048;       // a record this small waits for the next one
  static constexpr size_t kHoldTotal = 8192;        // ...unless this much is already waiting
  DirectSend direct_ = nullptr;
  void* directUser_ = nullptr;
  bool directMore_ = false;
  bool directBlocked_ = false;
  bool handshakeDone_ = false;
  bool fatal_ = false;
};

}  // namespace engine
}  // namespace moro
