// HTTP/1.1 request parser for @morojs/engine.
//
// Incremental, allocation-light, and written from RFC 9110 (semantics) and
// RFC 9112 (syntax). No I/O, no dependencies beyond the C++ standard library
// so it can be unit-tested standalone. Original-code policy (CONTRIBUTING.md),
// RFC-cited; not derived from any existing parser.
//
// Security posture (RFC 9112 §6, §11.2): rejects request smuggling vectors
// (both Content-Length and Transfer-Encoding; conflicting duplicate
// Content-Length), bounds the request head and header count, and validates
// chunk framing.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "pmd_options.h"  // PmdOptions: plain, zlib-free struct

namespace moro {
namespace engine {

// Win32 <winnt.h> (pulled in transitively by the Node headers under MSVC)
// #defines DELETE as an access-right constant, which would textually mangle the
// Method::DELETE enumerator below. The engine never uses the Win32 macro.
#ifdef DELETE
#undef DELETE
#endif

// Method table shared with the JS binding (index -> name). Keep in sync with
// docs/API.md METHODS and the adapter's METHODS array.
enum class Method : uint8_t {
  GET = 0,
  POST = 1,
  PUT = 2,
  DELETE = 3,
  PATCH = 4,
  HEAD = 5,
  OPTIONS = 6,
  OTHER = 7,
};

struct Header {
  std::string name;   // lowercased (RFC 9110 §5.1: field names are case-insensitive)
  std::string value;  // trimmed of leading/trailing OWS (RFC 9112 §5)
};

// Result of feeding bytes to the parser.
enum class ParseStatus : uint8_t {
  NeedMore,   // incomplete - feed more bytes
  Complete,   // a full request (head + body) is available
  Error,      // malformed/unsafe - respond with errorStatus and close
};

struct HttpLimits {
  size_t maxHeadSize = 64 * 1024;  // request line + all headers
  size_t maxHeaders = 100;
  size_t maxBodySize = 10 * 1024 * 1024;
  // Dedicated request-target (URI) length cap, answered with 414 (RFC 9110
  // §15.5.15). 0 = no dedicated cap: maxHeadSize still bounds the whole head
  // (431), so this is opt-in RFC-accurate signaling, not a required defense.
  size_t maxUriSize = 0;
  // Close a connection after this many ms with no bytes received while not actively running a handler (slowloris defense + keep-alive reuse cap). 0 disables the idle timeout.
  size_t idleTimeoutMs = 120000;
  // Budget for receiving one complete request (head + body), measured from its first byte. Unlike idleTimeoutMs this does NOT reset on activity, so a slow-drip client trickling one byte per idle window is still bounded (slowloris defense; the equivalent of Node's server.requestTimeout, and the same 300s default). Expiry answers 408 and closes. 0 disables.
  size_t requestTimeoutMs = 300000;
  // Budget for DELIVERING queued outbound bytes: while uv writes are pending, sweep ticks accumulate but reset on any drain PROGRESS (the outbound queue shrank since the last sweep, or a write completed), so a steadily-reading slow client keeps its connection while a peer that stops reading (zero receive window) - making no progress for the whole budget - is closed (slow-read DoS defense, the response-side mirror of requestTimeoutMs). Progress is measured by queue shrinkage, not completion, because one large respond() is a single uv_write that only completes when the whole body has drained. 0 disables.
  size_t responseTimeoutMs = 300000;
  // Hard cap on a connection's not-yet-flushed HTTP outbound queue; exceeding it closes the connection immediately (the HTTP mirror of wsBackpressureLimit). 0 = unlimited - a single large respond() legitimately queues its whole body, so the cap is opt-in for deployments that bound response sizes.
  size_t responseBackpressureLimit = 0;
  // Max simultaneous connections; new accepts beyond this are dropped immediately (backpressure against connection floods). 0 = unlimited.
  size_t maxConnections = 0;
  // Cap on bytes buffered for a single connection while its response is in flight (pipelined-request flood defense). 0 = use maxHeadSize + maxBodySize.
  size_t maxPendingBytes = 0;
  // Bind with SO_REUSEPORT so several engine instances (worker threads or processes) can listen on one port and the kernel load-balances accepts. POSIX only; a no-op on Windows, which has no equivalent semantics.
  bool reusePort = false;
  // WebSocket: cap on a complete (reassembled) message payload.
  size_t wsMaxMessageSize = 16 * 1024 * 1024;
  // WebSocket send backpressure: if a slow consumer lets the write queue grow past this, the connection is shed with 1013 rather than buffering without bound (a send-backpressure defense). 0 = unlimited.
  size_t wsBackpressureLimit = 1024 * 1024;
  // Write-queue level above which write()/wsSend() report "not writable" and onWritable is armed (HTTP streaming and WS sends share it).
  size_t writeHighWaterMark = 256 * 1024;
  // TCP listen backlog handed to uv_listen.
  int backlog = 512;
  // WebSocket permessage-deflate (RFC 7692), opt-in. Off by default preserves the "compression declined" posture; enabling it is an app decision.
  PmdOptions wsDeflate{};
};

// Limits for a default-constructed parser. Servers pass their own HttpLimits,
// which the parser references (not copies) - see the constructor note.
inline const HttpLimits& defaultHttpLimits() {
  static const HttpLimits d{};
  return d;
}

class HttpParser {
 public:
  using Limits = HttpLimits;

  // Held by pointer, not value, so per-connection parsers don't each carry a
  // copy of the struct. The referenced limits must outlive the parser (the
  // Server's limits_ member does; the default lives for the process).
  explicit HttpParser(const HttpLimits& limits = defaultHttpLimits())
      : limits_(&limits) {}

  // Parsed request view, valid until reset().
  Method method = Method::OTHER;
  std::string methodStr;   // populated only when method == OTHER
  std::string path;        // request target up to '?'
  std::string query;       // request target after '?', or empty
  int minorVersion = 1;    // HTTP/1.<minorVersion>
  std::vector<Header> headers;
  std::string body;
  bool keepAlive = true;

  // When ParseStatus::Error is returned, the status to send back before closing the connection (400, 413, 414, 431, 505).
  int errorStatus = 400;

  // Feed newly received bytes. Consumes from an internal accumulation buffer; callers append to inbound() or pass data here. Returns the parse status; on Complete, bytesConsumed() tells how many bytes of the input formed this request (the remainder is a pipelined follow-up request).
  ParseStatus parse(const char* data, size_t len);

  size_t bytesConsumed() const { return consumed_; }

  // True once the request line + headers are fully parsed (body may still be pending). Used to answer Expect: 100-continue before the body arrives.
  bool headParsed() const {
    return state_ != State::RequestLine && state_ != State::Headers;
  }

  // True while a request is partially received (some bytes buffered or the head parsed but the body incomplete). Drives the request-timeout sweep: an idle keep-alive connection with no buffered bytes is NOT mid-request.
  bool midRequest() const { return headParsed() || buf_.size() > consumed_; }

  const char* findHeader(std::string_view lowercaseName) const;

  // Reset for the next request on a keep-alive connection, preserving any already-buffered pipelined bytes.
  void reset();

  // Remaining buffered bytes not yet consumed (the start of the next request).
  std::string_view leftover() const {
    return std::string_view(buf_).substr(consumed_);
  }

 private:
  enum class State : uint8_t {
    RequestLine,
    Headers,
    Body,
    ChunkSize,
    ChunkData,
    ChunkTrailer,
    Done,
  };

  bool parseRequestLine(std::string_view line);
  bool parseHeaderLine(std::string_view line);
  bool finalizeHeaders();  // resolve body framing (Content-Length vs chunked)

  const Limits* limits_;
  std::string buf_;
  size_t consumed_ = 0;
  size_t scanPos_ = 0;      // where line scanning resumes within buf_
  State state_ = State::RequestLine;
  // headers[0..headerCount_) belong to the CURRENT request; slots past it are retained from a previous request purely as assignment targets (their string capacities are reused - see parseHeaderLine). The vector is trimmed to headerCount_ when the head completes, before any consumer reads it.
  size_t headerCount_ = 0;

  // Body framing resolved after headers
  bool chunked_ = false;
  bool hasBody_ = false;
  size_t contentLength_ = 0;
  size_t bodyReceived_ = 0;
  size_t chunkRemaining_ = 0;
  size_t headEnd_ = 0;         // index in buf_ where headers ended (body starts)
  size_t chunkTrailerStart_ = 0;  // buf_ index where the chunk trailer began
};

// ---- small helpers (header-inline for the single-TU addon build) ----

inline bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
    if (ca != cb) return false;
  }
  return true;
}

inline std::string_view trimOWS(std::string_view s) {
  // RFC 9110 §5.6.3 OWS = *( SP / HTAB )
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
  return s.substr(b, e - b);
}

inline Method methodFrom(std::string_view m) {
  switch (m.size()) {
    case 3:
      if (m == "GET") return Method::GET;
      if (m == "PUT") return Method::PUT;
      break;
    case 4:
      if (m == "POST") return Method::POST;
      if (m == "HEAD") return Method::HEAD;
      break;
    case 5:
      if (m == "PATCH") return Method::PATCH;
      break;
    case 6:
      if (m == "DELETE") return Method::DELETE;
      break;
    case 7:
      if (m == "OPTIONS") return Method::OPTIONS;
      break;
  }
  return Method::OTHER;
}

// A token char per RFC 9110 §5.6.2 (used to validate method + header names)
inline bool isTokenChar(unsigned char c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9'))
    return true;
  switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|':
    case '~':
      return true;
    default:
      return false;
  }
}

// Byte lowercase table (identity except A-Z -> a-z), for the per-request
// header-name lowering: a table lookup instead of a per-char compare/branch.
inline constexpr std::array<unsigned char, 256> kLowercase = [] {
  std::array<unsigned char, 256> t{};
  for (size_t i = 0; i < 256; ++i) t[i] = static_cast<unsigned char>(i);
  for (size_t i = 'A'; i <= 'Z'; ++i)
    t[i] = static_cast<unsigned char>(i - 'A' + 'a');
  return t;
}();

inline void HttpParser::reset() {
  // Deferred compaction. erase(0, consumed_) here memmoved the ENTIRE
  // unparsed backlog once per request - across a pipelined batch of P
  // requests that is O(P^2) bytes moved. Every scan position and bounds
  // check is already relative to consumed_, so the consumed prefix can
  // simply stay in place as a dead region: drop it for free when the buffer
  // is fully consumed (the common case), and compact only when the dead
  // prefix has grown to at least the live remainder (bounding waste to
  // half the buffer while keeping amortized moves linear).
  if (consumed_ > 0) {
    if (consumed_ == buf_.size()) {
      buf_.clear();
      consumed_ = 0;
    } else if (consumed_ >= buf_.size() - consumed_) {
      buf_.erase(0, consumed_);
      consumed_ = 0;
    }
  }
  // A huge request's buffered bytes (e.g. a 10 MB upload) must not stay
  // pinned to an idle keep-alive connection (same policy as body/scratch,
  // but a higher 64 KiB watermark - pipelined leftovers live here);
  // only shrink when the remaining content is small. shrink_to_fit preserves
  // content, so a pipelined leftover survives.
  if (buf_.capacity() > 65536 && buf_.size() <= 65536) buf_.shrink_to_fit();
  scanPos_ = consumed_;
  state_ = State::RequestLine;
  method = Method::OTHER;
  methodStr.clear();
  path.clear();
  query.clear();
  minorVersion = 1;
  // Do NOT clear headers: keep the vector and its strings as assignment targets for the next request (parseHeaderLine reuses their capacities).
  headerCount_ = 0;
  body.clear();
  // A huge body's capacity must not stay pinned to an idle keep-alive connection; small (typical) bodies keep theirs for reuse.
  if (body.capacity() > 16384) body.shrink_to_fit();
  keepAlive = true;
  errorStatus = 400;
  chunked_ = false;
  hasBody_ = false;
  contentLength_ = 0;
  bodyReceived_ = 0;
  chunkRemaining_ = 0;
  headEnd_ = 0;
  chunkTrailerStart_ = 0;
}

inline const char* HttpParser::findHeader(std::string_view name) const {
  for (const auto& h : headers) {
    if (h.name == name) return h.value.c_str();
  }
  return nullptr;
}

inline bool HttpParser::parseRequestLine(std::string_view line) {
  // RFC 9112 §3: request-line = method SP request-target SP HTTP-version
  size_t sp1 = line.find(' ');
  if (sp1 == std::string_view::npos) return false;
  size_t sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos) return false;

  std::string_view m = line.substr(0, sp1);
  std::string_view t = line.substr(sp1 + 1, sp2 - sp1 - 1);
  std::string_view v = line.substr(sp2 + 1);

  if (m.empty() || t.empty()) return false;
  for (char c : m) {
    if (!isTokenChar(static_cast<unsigned char>(c))) return false;
  }

  // Request-target hygiene (RFC 9112 §3.2 / RFC 3986): reject raw control
  // bytes. Only the line-terminating CRLF is stripped by the caller, so a
  // bare CR, NUL, any other C0 byte, or DEL would otherwise reach the app
  // verbatim in path/query - log-injection and downstream-desync fodder.
  // Policy notes: high bytes (0x80+) are tolerated (raw UTF-8 paths, matching
  // Node), and absolute-form / authority-form targets pass through opaquely
  // (RFC 9112 §3.2.2 requires accepting absolute-form; routing on it is the
  // app's / fronting proxy's business, again matching Node).
  for (char c : t) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7f) return false;  // errorStatus stays 400
  }
  if (limits_->maxUriSize && t.size() > limits_->maxUriSize) {
    errorStatus = 414;
    return false;
  }

  method = methodFrom(m);
  if (method == Method::OTHER) methodStr.assign(m);

  // assign(), not =/substr(): assignment from a temporary would move, throwing
  // away the destination string's reused capacity on every request.
  size_t q = t.find('?');
  if (q == std::string_view::npos) {
    path.assign(t.data(), t.size());
    query.clear();
  } else {
    path.assign(t.data(), q);
    query.assign(t.data() + q + 1, t.size() - q - 1);
  }

  // HTTP-version = "HTTP/" DIGIT "." DIGIT  (RFC 9112 §2.3)
  if (v.size() != 8 || v.substr(0, 5) != "HTTP/" || v[6] != '.' ||
      v[5] < '0' || v[5] > '9' || v[7] < '0' || v[7] > '9') {
    errorStatus = 400;
    return false;
  }
  if (v[5] != '1') {
    errorStatus = 505;  // only HTTP/1.x
    return false;
  }
  minorVersion = v[7] - '0';
  // HTTP/1.0 defaults to close unless Connection: keep-alive (resolved later)
  keepAlive = (minorVersion >= 1);
  return true;
}

inline bool HttpParser::parseHeaderLine(std::string_view line) {
  // field-line = field-name ":" OWS field-value OWS   (RFC 9112 §5)
  size_t colon = line.find(':');
  if (colon == std::string_view::npos || colon == 0) return false;

  std::string_view name = line.substr(0, colon);
  // No whitespace allowed between field name and colon (RFC 9112 §5.1 - reject to prevent request smuggling / header injection)
  for (char c : name) {
    if (!isTokenChar(static_cast<unsigned char>(c))) return false;
  }

  std::string_view value = trimOWS(line.substr(colon + 1));
  // Field-value byte discipline (RFC 9110 §5.5: VCHAR / SP / HTAB /
  // obs-text). A bare CR, NUL, or other C0 byte in a value would be handed
  // to the app verbatim (only the line-terminating CRLF is stripped) - the
  // inbound twin of the response-side validHeaderValue filter. obs-text
  // (0x80+) stays allowed, matching Node.
  for (char c : value) {
    const unsigned char u = static_cast<unsigned char>(c);
    if ((u < 0x20 && u != '\t') || u == 0x7f) return false;
  }

  // Reuse a slot (and its strings' heap capacities) from a previous request when one is available - header parsing is allocation-free on a warm keep-alive connection.
  if (headerCount_ < headers.size()) {
    Header& h = headers[headerCount_];
    h.name.resize(name.size());
    for (size_t i = 0; i < name.size(); ++i)
      h.name[i] =
          static_cast<char>(kLowercase[static_cast<unsigned char>(name[i])]);
    h.value.assign(value.data(), value.size());
  } else {
    Header h;
    h.name.resize(name.size());
    for (size_t i = 0; i < name.size(); ++i)
      h.name[i] =
          static_cast<char>(kLowercase[static_cast<unsigned char>(name[i])]);
    h.value.assign(value);
    headers.push_back(std::move(h));
  }
  ++headerCount_;
  return true;
}

inline bool HttpParser::finalizeHeaders() {
  // One pass over the headers (they were four), dispatching on the lowercased
  // name's length then a memcmp. Error PRECEDENCE must match the old pass
  // order - Host discipline first, then Content-Length parse errors - so a
  // Content-Length failure is recorded in clError here and only reported
  // after the Host check below.
  size_t hostCount = 0;
  bool sawClose = false, sawKeepAlive = false;
  const char* te = nullptr;
  size_t teCount = 0;
  bool hasCL = false;
  size_t clCount = 0;
  size_t cl = 0;
  int clError = 0;
  for (const auto& h : headers) {
    const std::string& n = h.name;
    switch (n.size()) {
      case 4:
        if (memcmp(n.data(), "host", 4) == 0) ++hostCount;
        break;
      case 10:
        // Connection handling (RFC 9110 §7.6.1). The field is a comma-separated list of connection options; tokenize every Connection header so "keep-alive, close" or "close, foo" are honored. A "close" token anywhere wins over "keep-alive"; otherwise a "keep-alive" token overrides the version default.
        if (memcmp(n.data(), "connection", 10) == 0) {
          std::string_view c = h.value;
          size_t pos = 0;
          while (pos <= c.size()) {
            size_t comma = c.find(',', pos);
            std::string_view tok =
                trimOWS(c.substr(pos, comma == std::string_view::npos ? c.size() - pos : comma - pos));
            if (iequals(tok, "close")) sawClose = true;
            else if (iequals(tok, "keep-alive")) sawKeepAlive = true;
            if (comma == std::string_view::npos) break;
            pos = comma + 1;
          }
        }
        break;
      case 14:
        // clError == 0 guard: the old dedicated pass stopped at its FIRST bad
        // Content-Length; later CL headers must stay unparsed.
        if (memcmp(n.data(), "content-length", 14) == 0 && clError == 0) {
          clCount++;
          // Reject conflicting duplicate Content-Length (RFC 9112 §6.3.5)
          size_t parsed = 0;
          if (h.value.empty()) { clError = 400; break; }
          for (char c : h.value) {
            if (c < '0' || c > '9') { clError = 400; break; }
            parsed = parsed * 10 + static_cast<size_t>(c - '0');
            // Reject once the value exceeds the body limit, DURING accumulation.
            // A long digit string (allowed within maxHeadSize) would otherwise
            // overflow size_t, wrap to a small value, slip past the post-loop 413
            // check, and desync the body length -> request smuggling.
            if (parsed > limits_->maxBodySize) { clError = 413; break; }
          }
          if (clError) break;
          if (hasCL && parsed != cl) { clError = 400; break; }
          cl = parsed;
          hasCL = true;
        }
        break;
      case 17:
        // Count Transfer-Encoding headers: RFC 9112 §6.1 requires the FINAL coding to be chunked. The engine only supports a lone "chunked", so more than one TE header (e.g. "chunked" then "cow") is a smuggling vector and is rejected (below).
        if (memcmp(n.data(), "transfer-encoding", 17) == 0) {
          teCount++;
          te = h.value.c_str();
        }
        break;
    }
  }

  // Host discipline (RFC 9112 §3.2): an HTTP/1.1 request MUST carry exactly
  // one Host header - answer 400 to zero (1.1+ only; 1.0 predates Host) or
  // more than one (any version). Absent/duplicate Host is a building block
  // for host-confusion and cache-poisoning when the app or a fronting proxy
  // routes on it; the parser is the one place that can reject it before any
  // routing sees the request. Node's http server enforces the same
  // (requireHostHeader, default on).
  if (hostCount > 1 || (hostCount == 0 && minorVersion >= 1)) {
    errorStatus = 400;
    return false;
  }

  if (sawClose) keepAlive = false;
  else if (sawKeepAlive) keepAlive = true;

  if (clError) { errorStatus = clError; return false; }
  (void)clCount;

  if (te != nullptr) {
    // Request smuggling defense (RFC 9112 §6.1, §6.3.3): if both TE and CL are
    // present, reject. A sender MUST NOT send both.
    if (hasCL) { errorStatus = 400; return false; }
    // Multiple Transfer-Encoding headers can't be resolved to a single final
    // coding safely (a fronting proxy may honor a different one) — reject.
    if (teCount > 1) { errorStatus = 400; return false; }
    // Only "chunked" (as the sole/final encoding) is supported.
    std::string_view tev = trimOWS(std::string_view(te));
    if (iequals(tev, "chunked")) {
      chunked_ = true;
      hasBody_ = true;
    } else {
      errorStatus = 400;  // unsupported / non-final chunked
      return false;
    }
  } else if (hasCL) {
    contentLength_ = cl;
    hasBody_ = cl > 0;
    if (cl > limits_->maxBodySize) { errorStatus = 413; return false; }
  } else {
    hasBody_ = false;  // no body framing -> no body (RFC 9112 §6.3 point 6)
  }

  return true;
}

inline ParseStatus HttpParser::parse(const char* data, size_t len) {
  if (len) buf_.append(data, len);

  // --- head (request line + headers) ---
  while (state_ == State::RequestLine || state_ == State::Headers) {
    size_t nl = buf_.find('\n', scanPos_);
    if (nl == std::string::npos) {
      if (buf_.size() - consumed_ > limits_->maxHeadSize) {
        errorStatus = 431;  // Request Header Fields Too Large
        return ParseStatus::Error;
      }
      return ParseStatus::NeedMore;
    }
    // line is [scanPos_, nl), trimming a trailing '\r'
    size_t lineEnd = nl;
    if (lineEnd > scanPos_ && buf_[lineEnd - 1] == '\r') --lineEnd;
    std::string_view line(buf_.data() + scanPos_, lineEnd - scanPos_);
    size_t nextScan = nl + 1;

    if (state_ == State::RequestLine) {
      if (line.empty()) {  // tolerate leading CRLF (RFC 9112 §2.2)
        scanPos_ = nextScan;
        continue;
      }
      if (!parseRequestLine(line)) {
        // Relative to consumed_: with deferred compaction the buffer may
        // still carry a dead prefix from prior requests, which must not
        // count toward this request's head size.
        if (errorStatus == 400 && buf_.size() - consumed_ > limits_->maxHeadSize)
          errorStatus = 431;
        return ParseStatus::Error;
      }
      state_ = State::Headers;
      scanPos_ = nextScan;
    } else {  // Headers
      if (line.empty()) {  // blank line terminates the head
        headEnd_ = nextScan;
        scanPos_ = nextScan;
        // Final head-size check, including the terminating blank line. This
        // (not buf_.size()) is the complete head's true size: the buffer may
        // already hold the request's body when a buffered batch is replayed
        // in one parse() call, and those bytes must not count against the
        // head limit.
        if (headEnd_ - consumed_ > limits_->maxHeadSize) {
          errorStatus = 431;
          return ParseStatus::Error;
        }
        // Trim stale reuse-slots from a prior, larger request BEFORE any
        // consumer can iterate the vector.
        headers.resize(headerCount_);
        if (headerCount_ > limits_->maxHeaders) {
          errorStatus = 431;
          return ParseStatus::Error;
        }
        if (!finalizeHeaders()) return ParseStatus::Error;
        state_ = chunked_ ? State::ChunkSize : State::Body;
        break;
      }
      if (headerCount_ >= limits_->maxHeaders) {
        errorStatus = 431;
        return ParseStatus::Error;
      }
      if (!parseHeaderLine(line)) return ParseStatus::Error;
      scanPos_ = nextScan;
    }
    // Bound the HEAD bytes scanned so far (scanPos_), not the whole buffer:
    // buf_ may already hold the request's body (or pipelined follow-ups) when
    // a buffered batch is replayed in one parse() call, and counting those
    // bytes would 431 a valid request whose body exceeds maxHeadSize. The
    // no-newline branch above can keep using buf_.size(): body bytes are
    // always preceded by the blank line's '\n', so an un-terminated remainder
    // is head bytes by construction.
    if (scanPos_ - consumed_ > limits_->maxHeadSize && state_ != State::Body &&
        state_ != State::ChunkSize) {
      errorStatus = 431;
      return ParseStatus::Error;
    }
  }

  // --- fixed-length body (Content-Length) ---
  if (state_ == State::Body) {
    if (!hasBody_) {
      consumed_ = headEnd_;
      state_ = State::Done;
      return ParseStatus::Complete;
    }
    size_t available = buf_.size() - headEnd_;
    if (available < contentLength_) return ParseStatus::NeedMore;
    body.assign(buf_.data() + headEnd_, contentLength_);
    consumed_ = headEnd_ + contentLength_;
    state_ = State::Done;
    return ParseStatus::Complete;
  }

  // --- chunked body (RFC 9112 §7.1) ---
  while (state_ == State::ChunkSize || state_ == State::ChunkData ||
         state_ == State::ChunkTrailer) {
    if (state_ == State::ChunkSize) {
      size_t nl = buf_.find('\n', scanPos_);
      if (nl == std::string::npos) {
        if (buf_.size() - scanPos_ > 1024) { errorStatus = 400; return ParseStatus::Error; }
        return ParseStatus::NeedMore;
      }
      size_t lineEnd = nl;
      if (lineEnd > scanPos_ && buf_[lineEnd - 1] == '\r') --lineEnd;
      std::string_view sizeLine(buf_.data() + scanPos_, lineEnd - scanPos_);
      // chunk-size [ chunk-ext ] - ext (after ';') ignored
      size_t semi = sizeLine.find(';');
      std::string_view hex =
          semi == std::string_view::npos ? sizeLine : sizeLine.substr(0, semi);
      hex = trimOWS(hex);
      if (hex.empty()) { errorStatus = 400; return ParseStatus::Error; }
      size_t sz = 0;
      for (char c : hex) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else { errorStatus = 400; return ParseStatus::Error; }
        sz = sz * 16 + static_cast<size_t>(d);
        if (sz > limits_->maxBodySize) { errorStatus = 413; return ParseStatus::Error; }
      }
      chunkRemaining_ = sz;
      scanPos_ = nl + 1;
      if (sz == 0) {
        chunkTrailerStart_ = scanPos_;
        state_ = State::ChunkTrailer;
      } else {
        state_ = State::ChunkData;
      }
    } else if (state_ == State::ChunkData) {
      size_t available = buf_.size() - scanPos_;
      if (available < chunkRemaining_ + 2) return ParseStatus::NeedMore;  // + CRLF
      if (body.size() + chunkRemaining_ > limits_->maxBodySize) {
        errorStatus = 413;
        return ParseStatus::Error;
      }
      body.append(buf_.data() + scanPos_, chunkRemaining_);
      scanPos_ += chunkRemaining_;
      // Expect trailing CRLF
      if (buf_[scanPos_] != '\r' || buf_[scanPos_ + 1] != '\n') {
        errorStatus = 400;
        return ParseStatus::Error;
      }
      scanPos_ += 2;
      chunkRemaining_ = 0;
      state_ = State::ChunkSize;
    } else {  // ChunkTrailer - consume trailer field lines until blank line
      // Bound the CUMULATIVE trailer size, not just the current unfinished line:
      // without this, an attacker streams "X:y\r\n" forever — each line passes a
      // per-line check while buf_ grows without bound (never trimmed until
      // reset()), the request never Completes, and RSS climbs to OOM.
      if (buf_.size() - chunkTrailerStart_ > limits_->maxHeadSize) {
        errorStatus = 431;
        return ParseStatus::Error;
      }
      size_t nl = buf_.find('\n', scanPos_);
      if (nl == std::string::npos) {
        return ParseStatus::NeedMore;
      }
      size_t lineEnd = nl;
      if (lineEnd > scanPos_ && buf_[lineEnd - 1] == '\r') --lineEnd;
      bool blank = (lineEnd == scanPos_);
      scanPos_ = nl + 1;
      if (blank) {
        consumed_ = scanPos_;
        state_ = State::Done;
        return ParseStatus::Complete;
      }
      // else: ignore trailer field, keep scanning
    }
  }

  return ParseStatus::NeedMore;
}

}  // namespace engine
}  // namespace moro
