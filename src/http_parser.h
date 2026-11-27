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
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
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
  std::string_view name;   // lowercased (RFC 9110 §5.1: field names are case-insensitive)
  std::string_view value;  // trimmed of leading/trailing OWS (RFC 9112 §5)
};

// A request's header fields. Every name and value is a range of one buffer:
// for HTTP/1 the head's field lines copied in one piece once the head is
// complete, the names lowercased in place; for HTTP/2 each decoded field
// appended. A Header read from the list is a view into that buffer, good
// until the list is next changed (cleared, added to, assigned). A value is
// followed by a NUL in the buffer (findHeader hands out a C string).
// Swapping two lists exchanges their storage: views into either stay valid.
class HeaderList {
 public:
  size_t size() const { return fields_.size(); }
  bool empty() const { return fields_.empty(); }
  Header operator[](size_t i) const {
    const Field& f = fields_[i];
    const char* t = text_.data();
    return Header{std::string_view(t + f.name, f.nameLen), std::string_view(t + f.value, f.valueLen)};
  }

  class const_iterator {
   public:
    using value_type = Header;
    using reference = Header;
    using pointer = void;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::input_iterator_tag;
    const_iterator(const HeaderList* l, size_t i) : l_(l), i_(i) {}
    Header operator*() const { return (*l_)[i_]; }
    const_iterator& operator++() {
      ++i_;
      return *this;
    }
    bool operator==(const const_iterator& o) const { return i_ == o.i_; }
    bool operator!=(const const_iterator& o) const { return i_ != o.i_; }

   private:
    const HeaderList* l_;
    size_t i_;
  };
  const_iterator begin() const { return const_iterator(this, 0); }
  const_iterator end() const { return const_iterator(this, fields_.size()); }

  // Empty, keeping the storage for the next request. (What is worth keeping
  // is settled where the storage is filled again: one huge head does not
  // stay pinned to a connection past its next request.)
  void clear() {
    fields_.clear();
    text_.clear();
  }
  // Keep the first n fields (n <= size()).
  void resize(size_t n) {
    if (n == 0) clear();
    else if (n < fields_.size()) fields_.resize(n);
  }
  void swap(HeaderList& o) noexcept {
    fields_.swap(o.fields_);
    text_.swap(o.text_);
  }
  // The storage the list holds on to, used or not.
  size_t retained() const { return text_.capacity() + fields_.capacity() * sizeof(Field); }

  // One field whose name is lowercase already (HTTP/2).
  void add(std::string_view name, std::string_view value) {
    if (fields_.empty()) release();
    const size_t at = text_.size();
    text_.insert(text_.end(), name.begin(), name.end());
    text_.insert(text_.end(), value.begin(), value.end());
    text_.push_back('\0');
    fields_.push_back(Field{at, name.size(), at + name.size(), value.size()});
  }

  // HTTP/1. While a head is parsed each field is recorded as ranges of the
  // bytes being parsed (mark: offsets into the read buffer or the parser's
  // own buffer, whichever holds the head); once the head is complete,
  // commit() copies src[base, end) - every field line - into the list in one
  // piece, lowercases the names there and moves the ranges onto the copy.
  // Nothing may read the list between the first mark() and commit().
  void mark(size_t name, size_t nameLen, size_t value, size_t valueLen) {
    fields_.push_back(Field{name, nameLen, value, valueLen});
  }
  inline void commit(const char* src, size_t base, size_t end);

 private:
  struct Field {
    size_t name, nameLen, value, valueLen;
  };
  // Text storage past what a typical head needs is given back before the
  // list is filled again.
  static constexpr size_t kKeepText = 16 * 1024;
  void release() {
    if (text_.capacity() > kKeepText) std::vector<char>().swap(text_);
  }
  std::vector<char> text_;
  std::vector<Field> fields_;
};

// Result of feeding bytes to the parser.
enum class ParseStatus : uint8_t {
  NeedMore,   // incomplete - feed more bytes
  Complete,   // a full request (head + body) is available
  Error,      // malformed/unsafe - respond with errorStatus and close
};

// HTTP/2 (serve option `http2`). Off unless asked for: a server that enables
// it speaks h2 to a TLS client that negotiates it by ALPN and to a cleartext
// client that opens with the HTTP/2 preface (prior knowledge), and HTTP/1.1
// to everyone else on the same port. Zero means the engine's default.
struct Http2Options {
  bool enabled = false;
  uint32_t maxConcurrentStreams = 0;  // 256
  uint32_t initialWindowSize = 0;     // 1 MiB per stream
  uint32_t maxFrameSize = 0;          // 16,384
  uint32_t maxHeaderListSize = 0;     // maxHeadSize
  uint32_t headerTableSize = 0;       // 4,096
};

struct HttpLimits {
  size_t maxHeadSize = 64 * 1024;  // request line + all headers
  size_t maxHeaders = 100;
  size_t maxBodySize = 10 * 1024 * 1024;
  // Dedicated request-target (URI) length cap, answered with 414 (RFC 9110
  // §15.5.15). 0 = no dedicated cap: maxHeadSize still bounds the whole head
  // (431), so this is opt-in RFC-accurate signaling, not a required defense.
  size_t maxUriSize = 0;
  // A request-target is ASCII (RFC 3986 §2; RFC 9112 §3.2): a byte of 0x80 or
  // above in it is answered 400, as a control byte is. true takes such bytes
  // as before 1.2.2 and hands them to the application undecoded, for clients
  // that send UTF-8 paths without percent-encoding them.
  bool allowNonAsciiTarget = false;
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
  // What the process may hold in buffers for its peers, all connections of
  // all its servers together: requests still being received and responses
  // their peers have not taken (Server, "Buffer budget"). Every limit above
  // is per connection, and their sum over the connections a server accepts
  // is far more memory than a host has. 0 = an eighth of the memory the
  // process may use (its cgroup limit, or the machine's); SIZE_MAX = no
  // budget.
  size_t memoryBudget = 0;
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
  Http2Options http2{};
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
      : limits_(&limits), leanHead_(limits.maxHeadSize < kLeanHead ? limits.maxHeadSize : kLeanHead) {}

  // Parsed request view, valid until reset().
  Method method = Method::OTHER;
  std::string methodStr;   // populated only when method == OTHER
  std::string path;        // request target up to '?'
  std::string query;       // request target after '?', or empty
  int minorVersion = 1;    // HTTP/1.<minorVersion>
  HeaderList headers;
  std::string body;
  bool keepAlive = true;

  // When ParseStatus::Error is returned, the status to send back before closing the connection (400, 413, 414, 431, 505).
  int errorStatus = 400;

  // Route-first parsing. The server installs `routeHook`; after each request
  // line the parser asks whether this request will be answered inside the
  // engine (a static or parameter route with nothing queued ahead of it).
  // When it will, the headers are validated and the framing ones interpreted
  // exactly as always, but none are stored: nothing is recorded or copied,
  // and `headers` stays empty.
  // light() reports the mode of the request being parsed.
  // Body buffers shared by the parsers of one loop (the server's; optional).
  // A request's body is collected into a buffer taken from here when this
  // parser holds none, and the server puts it back when the request is done.
  // Bodies used to be collected into per-connection strings that kept their
  // capacity: three of them per connection in rotation (sixteen more with the
  // staged slots), so a server with many connections wrote every body into
  // memory it had not touched since that connection's last request, and held
  // all of it while the connections sat idle. A handful of buffers that every
  // connection takes its turn with stay in the cache, and an idle connection
  // holds none.
  std::vector<std::string>* bodyPool = nullptr;
  // A string with at least this much room is a buffer in its own right: the
  // parser keeps using it, and the server takes it for the pool afterwards.
  static constexpr size_t kOwnBodyCapacity = 64;
  // Longest chunk-size line accepted: the hex size and any chunk extensions,
  // counted up to the LF. One rule, applied to the bytes of the line whether
  // or not its end has arrived, so the answer does not depend on how the
  // line was split across reads. Extensions seen in practice are a few dozen
  // bytes (a signature per chunk at most).
  static constexpr size_t kMaxChunkLine = 16 * 1024;
  // Longest method token taken for a method at all. The longest registered
  // one has 17 bytes (UPDATEREDIRECTREF); a token past this bound is answered
  // 501 as soon as that many bytes of it have arrived, whatever follows and
  // however long the line turns out to be (RFC 9112 §3: a method longer than
  // any the server implements).
  static constexpr size_t kMaxMethodLen = 64;
  // Spent bytes of a chunked body are dropped from the buffer once there is
  // this much of them (dropSpent, and the chunk loop in parse()).
  static constexpr size_t kChunkCompactAt = 16 * 1024;
  // A head past this size is noted (largeHead()): the path, query and field
  // storage it was parsed into may have grown past what is worth keeping
  // between requests, and whoever keeps parsers for reuse looks at what this
  // one holds (retained()) before keeping it. The mark every other buffer
  // of a request is held to (16 KiB): a browser's head with its cookies is
  // well within it, and pays nothing for the note.
  static constexpr size_t kLeanHead = 16 * 1024;

  using RouteHook = bool (*)(void* user, Method m, const std::string& path);
  RouteHook routeHook = nullptr;
  void* routeHookUser = nullptr;
  bool light() const { return light_ != 0; }
  // Light, and the request line was parsed in the parse() call that is
  // returning or has just returned: what the route hook answered still
  // holds. False once a parse() call has returned with the request
  // unfinished - the caller ran, and may have changed its routes, since.
  bool lightFresh() const { return light_ == kLightFresh; }

  // Framing-relevant headers of the current request, recorded while the
  // header lines are scanned (in both modes), so no consumer walks the
  // header list again for them.
  bool expectContinue() const { return expectContinue_; }
  bool hasUpgrade() const { return hasUpgrade_; }

  // Feed newly received bytes. Consumes from an internal accumulation buffer; callers append to inbound() or pass data here. Returns the parse status; on Complete, bytesConsumed() tells how many bytes of the input formed this request (the remainder is a pipelined follow-up request).
  // Error is final: once a request has been rejected every later call
  // returns Error again (errorStatus unchanged) and takes no bytes, so
  // nothing that arrives afterwards can be read as the rest of that request.
  ParseStatus parse(const char* data, size_t len);

  size_t bytesConsumed() const { return consumed_; }

  // True once the request line + headers are fully parsed (body may still be pending). Used to answer Expect: 100-continue before the body arrives.
  // The request line refused last had no HTTP-version in it: whatever the
  // peer is speaking, it is not HTTP/1.
  bool notHttp() const { return (lineNote_ & kNotHttp) != 0; }
  // ... and it was the first line of its connection. expectFirstLine() is
  // called before a connection's first bytes are parsed; the next reset() -
  // the first request is complete, the peer has spoken HTTP/1 - ends it. A
  // line refused after that is an HTTP/1 peer's mistake and is answered as
  // one. (Kept in the byte reset() clears anyway: a request pays nothing for
  // it.)
  void expectFirstLine() { lineNote_ = kFirstLine; }
  bool firstLineNotHttp() const { return lineNote_ == (kFirstLine | kNotHttp); }

  bool headParsed() const {
    return state_ != State::RequestLine && state_ != State::Headers;
  }

  // True while a request is partially received (some bytes buffered or the head parsed but the body incomplete). Drives the request-timeout sweep: an idle keep-alive connection with no buffered bytes is NOT mid-request.
  bool midRequest() const { return headParsed() || buf_.size() > consumed_; }

  // Nothing buffered and no request in progress: the next read starts a
  // request at its first byte (what the server's fast lane needs).
  bool idle() const { return buf_.empty() && state_ == State::RequestLine; }
  // idle(), and no head past kLeanHead has completed since clearLargeHead():
  // the two bytes lie side by side, and one comparison answers for both.
  inline bool idleLean() const;
  bool largeHead() const { return largeHead_ != 0; }
  void clearLargeHead() { largeHead_ = 0; }
  // Heap storage this parser holds on to between requests: the buffers a
  // request is parsed into keep their capacity for the next one.
  size_t retained() const {
    return heapOf(buf_) + heapOf(methodStr) + heapOf(path) + heapOf(query) + heapOf(body) + headers.retained();
  }
  // The same without asking each string whether its text sits inside the
  // object: an upper estimate (fifteen bytes a string at the most), for the
  // one question it answers - is this state small enough to keep - which is
  // asked on the path of a request (Server::restLarge).
  size_t retainedAtMost() const {
    return buf_.capacity() + methodStr.capacity() + path.capacity() + query.capacity() + body.capacity() +
           headers.retained();
  }
  // A string's heap allocation (none while its text sits inside the object).
  static size_t heapOf(const std::string& s) { return s.capacity() >= sizeof(std::string) ? s.capacity() : 0; }

  // Bytes held in the accumulation buffer: input not parsed yet, plus what
  // has been parsed and not dropped yet (diagnostics and tests).
  size_t buffered() const { return buf_.size(); }
  // Heap storage of the request being received - the input buffer and the
  // body: what the peer has made this parser hold, as the server's buffer
  // budget counts it.
  size_t memory() const { return heapOf(buf_) + heapOf(body); }
  // The same by content: the bytes of the request being received - input
  // not yet parsed, and the body collected so far - whatever the capacity of
  // the buffers they are in (a pooled parser keeps what an earlier request
  // grew them to).
  size_t arriving() const { return buf_.size() - consumed_ + body.size(); }
  // The connection is being closed for what it holds: give that storage back
  // now, and parse nothing more.
  // The connection is closing: nothing more is parsed (parse() reports an
  // error from here on). Nothing is freed - a caller up the stack may still
  // be reading the request this parser holds.
  void stop() { failed_ = true; }
  void abandon() {
    std::string().swap(buf_);
    std::string().swap(body);
    consumed_ = 0;
    scanPos_ = 0;
    directBody_ = false;
    failed_ = true;
  }

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

  // A Content-Length body's buffer, before `incoming` more bytes are added
  // to it: reserved for the whole declared length once a sixteenth of that
  // has arrived (at once for a body of up to 64 KiB, and at the first read
  // for one up to sixteen reads long), growing with what arrives until
  // then. The declared length is only a claim until the bytes come: a peer
  // that sent a head declaring maxBodySize and one byte of body had all of
  // it set aside - address space, and committed memory where allocation
  // commits - for as long as it kept the request open.
  static constexpr size_t kBodyReserveShare = 16;
  static constexpr size_t kBodyReserveAtOnce = 64 * 1024;
  void reserveBody(size_t incoming) {
    if (body.capacity() >= contentLength_) return;
    if (contentLength_ <= kBodyReserveAtOnce ||
        body.size() + incoming >= contentLength_ / kBodyReserveShare) {
      body.reserve(contentLength_);
    }
  }
  // Called where a body's first bytes are about to be stored (`body` empty).
  void takeBody() {
    if (bodyPool != nullptr && !bodyPool->empty() && body.capacity() < kOwnBodyCapacity) {
      body.swap(bodyPool->back());
      bodyPool->pop_back();
    }
  }
  ParseStatus parseSome(const char* data, size_t len);
  // Drop buf_[0, upTo): the head has been stored and the chunks before
  // `upTo` are in `body`.
  void dropSpent(size_t upTo) {
    buf_.erase(0, upTo);
    scanPos_ -= upTo;
    chunkTrailerStart_ = chunkTrailerStart_ > upTo ? chunkTrailerStart_ - upTo : 0;
    consumed_ = 0;
    headEnd_ = 0;
  }
  bool parseRequestLine(std::string_view line);
  // A request-target that does not begin with "/" (see the definition).
  static bool targetFormOk(Method method, std::string_view methodStr, std::string_view target);
  // A complete head of `size` bytes, past leanHead_ (see the definition).
  bool headOver(size_t size);
  // `at`: where the line starts in the buffer that holds it (data for the
  // in-place scan, buf_ otherwise), so a stored field is marked as ranges of
  // that buffer until the head is complete (HeaderList::mark).
  bool parseHeaderLine(std::string_view line, size_t at);
  // Classification of a field whose name is not Host (classifyHeader), for
  // the name lengths a framing header can have; `name` in any letter case.
  void classifyField(const char* name, size_t n, std::string_view value);
  bool finalizeHeaders();  // resolve body framing (Content-Length vs chunked)
  // Interpret one header for framing / connection semantics; `lname` is the
  // lowercased field name. Runs as each line is parsed, in both modes.
  void classifyHeader(std::string_view lname, std::string_view value);
  // Zero-copy head scan for a request that arrives whole in one read and is
  // answered inside the engine (parse() tries it first; see the definitions).
  bool parseDirect(const char* data, size_t len, ParseStatus& st);
  bool parseDirectStored(const char* data, size_t len, size_t pos, ParseStatus& st);
  int scanLightHeaders(const unsigned char* d, size_t len, size_t& pos);

  const Limits* limits_;
  // The size a complete head is compared with: kLeanHead, or maxHeadSize
  // when that is the smaller. One comparison per request, where the
  // maxHeadSize check alone used to be; headOver() tells the two apart.
  size_t leanHead_;
  std::string buf_;
  size_t consumed_ = 0;
  size_t scanPos_ = 0;      // where line scanning resumes within buf_
  State state_ = State::RequestLine;
  uint8_t largeHead_ = 0;   // directly behind state_: idleLean() reads the two as one
  // Field lines of the current request seen so far (stored or, in light mode, only scanned).
  size_t headerCount_ = 0;
  // This request's headers are scanned, not stored: 0 no, kLightFresh since
  // its request line was parsed in the current parse() call, kLightSpanned
  // once a parse() call has returned NeedMore for it.
  static constexpr uint8_t kLightFresh = 1;
  static constexpr uint8_t kLightSpanned = 2;
  uint8_t light_ = 0;
  bool failed_ = false;  // parse() returned Error: the parser takes no more input
  // The request line was refused for its method token alone (kMaxMethodLen):
  // its status is not replaced by the head-size 431.
  bool methodRefused_ = false;
  // kNotHttp: the request line refused last had no HTTP-version in it.
  // kFirstLine: that line is the first of its connection (expectFirstLine).
  static constexpr uint8_t kFirstLine = 1;
  static constexpr uint8_t kNotHttp = 2;
  uint8_t lineNote_ = 0;
  void noteNotHttp(bool is) {
    lineNote_ = static_cast<uint8_t>((lineNote_ & kFirstLine) | (is ? kNotHttp : 0));
  }
  // The request line begins with more than kMaxMethodLen token bytes.
  static bool methodOverlong(const char* p, size_t n);

  // The Host value last accepted on this connection. A client repeats it on
  // every request of a keep-alive connection, and a value equal to one
  // already checked needs no second look: the Host line of every request
  // but the first costs a compare, which is less than the general value
  // check it replaces. Survives reset(); a value longer than the buffer is
  // simply checked each time. (SIZE_MAX: nothing accepted yet.)
  static constexpr size_t kHostSeenMax = 40;
  size_t hostSeenLen_ = SIZE_MAX;
  char hostSeen_[kHostSeenMax] = {};
  bool hostOk(std::string_view v) {
    if (v.size() == hostSeenLen_ && memcmp(v.data(), hostSeen_, v.size()) == 0) return true;
    return hostCheck(v);
  }
  bool hostCheck(std::string_view v);

  // Accumulated by classifyHeader(); finalizeHeaders() resolves them.
  size_t hostCount_ = 0;
  bool sawClose_ = false;
  bool sawKeepAlive_ = false;
  size_t teCount_ = 0;
  bool teChunked_ = false;
  bool hasCL_ = false;
  size_t cl_ = 0;
  int clError_ = 0;
  bool expectContinue_ = false;
  bool hasUpgrade_ = false;

  // Body framing resolved after headers
  bool chunked_ = false;
  bool hasBody_ = false;
  size_t contentLength_ = 0;
  size_t bodyReceived_ = 0;
  size_t chunkRemaining_ = 0;
  size_t headEnd_ = 0;         // index in buf_ where headers ended (body starts)
  size_t headBase_ = 0;        // where the current head's first field line starts (see HeaderList::mark)
  // A Content-Length body being collected straight into `body` from each
  // read: the head is parsed and buf_ holds nothing of this request past it.
  bool directBody_ = false;
  size_t chunkTrailerStart_ = 0;  // buf_ index where the chunk trailer began
};

// Read as one, in so many words: written as two tests joined, the two bytes
// were loaded one by one and put together before the comparison - four
// instructions for two, on every request that leaves its connection at rest.
inline bool HttpParser::idleLean() const {
  static_assert(offsetof(HttpParser, largeHead_) == offsetof(HttpParser, state_) + 1,
                "largeHead_ lies directly behind state_");
  uint16_t both;
  std::memcpy(&both, reinterpret_cast<const unsigned char*>(this) + offsetof(HttpParser, state_), sizeof both);
  return buf_.empty() && both == 0;
}

// ---- small helpers (header-inline for the single-TU addon build) ----

// Hot on every header line (trimOWS) and framing token (iequals): force the
// inline the optimizer otherwise declines for these call sites.
#if defined(__GNUC__)
#define MORO_ALWAYS_INLINE inline __attribute__((always_inline))
#define MORO_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define MORO_ALWAYS_INLINE inline
#define MORO_NOINLINE __declspec(noinline)
#else
#define MORO_ALWAYS_INLINE inline
#define MORO_NOINLINE
#endif

MORO_ALWAYS_INLINE bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
    if (ca != cb) return false;
  }
  return true;
}

MORO_ALWAYS_INLINE std::string_view trimOWS(std::string_view s) {
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

// A token char per RFC 9110 §5.6.2 (used to validate method + header names):
// one table lookup per byte.
inline constexpr std::array<bool, 256> kTokenChar = [] {
  std::array<bool, 256> t{};
  for (unsigned c = 'a'; c <= 'z'; ++c) t[c] = true;
  for (unsigned c = 'A'; c <= 'Z'; ++c) t[c] = true;
  for (unsigned c = '0'; c <= '9'; ++c) t[c] = true;
  for (unsigned char c : {'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'})
    t[c] = true;
  return t;
}();
inline bool isTokenChar(unsigned char c) { return kTokenChar[c]; }

// A byte allowed in a field value (RFC 9110 §5.5: VCHAR / SP / HTAB /
// obs-text): everything but C0 controls other than HTAB, and DEL.
inline constexpr std::array<bool, 256> kValueChar = [] {
  std::array<bool, 256> t{};
  for (unsigned c = 0; c < 256; ++c) t[c] = !((c < 0x20 && c != '\t') || c == 0x7f);
  return t;
}();

// The length of the run of token bytes (kTokenChar) at p, at most n: the
// index of the first byte that is not one. Eight bytes at a time while every
// byte of a word is a letter, a digit or '-', which is what field names are
// made of; in the first word that holds anything else (the colon after the
// name, or a rarer token byte) the scan moves straight to that byte and goes
// on from there byte by byte through the table. Each word test is exact per
// byte (no sum carries into the next byte, and '-' is matched without the
// borrow of the usual zero-byte trick), so the answer is the table's for
// every input.
MORO_ALWAYS_INLINE size_t tokenRun(const unsigned char* p, size_t n) {
  constexpr uint64_t kOnes = 0x0101010101010101ULL, kHigh = 0x8080808080808080ULL;
  constexpr uint64_t kLow7 = 0x7f7f7f7f7f7f7f7fULL;
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t w;
    memcpy(&w, p + i, 8);
    if (w & kHigh) break;
    const uint64_t l = w | (kOnes * 0x20);
    const uint64_t letter = (l + kOnes * (0x80 - 'a')) & ~(l + kOnes * (0x80 - 'z' - 1));
    const uint64_t digit = (w + kOnes * (0x80 - '0')) & ~(w + kOnes * (0x80 - '9' - 1));
    const uint64_t x = w ^ (kOnes * '-');
    const uint64_t dash = ~(((x & kLow7) + kLow7) | x);
    const uint64_t other = ~(letter | digit | dash) & kHigh;
    if (other != 0) {
      if constexpr (std::endian::native == std::endian::little) i += static_cast<size_t>(std::countr_zero(other)) / 8;
      break;
    }
  }
  while (i < n && kTokenChar[p[i]]) ++i;
  return i;
}

// Whether every byte of [p, p + n) is a field-value byte (kValueChar), eight
// bytes per step. A word in which no byte is below 0x20 and none is 0x7f
// holds only field-value bytes; a word that has such a byte (HTAB is the one
// of them that is allowed) is settled byte by byte against the table, as is
// the tail. The two word tests can flag a byte only when the word really
// holds one below 0x20 (or equal to 0x7f) at or below it, and never miss
// one, so the answer is the table's for every input.
MORO_ALWAYS_INLINE bool validValueBytes(const unsigned char* p, size_t n) {
  constexpr uint64_t kOnes = 0x0101010101010101ULL, kHigh = 0x8080808080808080ULL;
  size_t i = 0;
  const auto clean = [&](size_t at) {
    uint64_t w;
    memcpy(&w, p + at, 8);
    const uint64_t del = w ^ (kOnes * 0x7f);
    if ((((w - kOnes * 0x20) & ~w) | ((del - kOnes) & ~del)) & kHigh) {
      for (size_t k = at; k < at + 8; ++k) {
        if (!kValueChar[p[k]]) return false;
      }
    }
    return true;
  };
  for (; i + 8 <= n; i += 8) {
    if (!clean(i)) return false;
  }
  // A tail of a value at least eight bytes long is checked as the last eight
  // bytes (some of them a second time); a shorter value byte by byte.
  if (i < n && n >= 8) return clean(n - 8);
  for (; i < n; ++i) {
    if (!kValueChar[p[i]]) return false;
  }
  return true;
}

// Bytes of a Host field value (RFC 9110 §7.2: Host = uri-host [ ":" port ],
// uri-host per RFC 3986 §3.2.2). Bit 0: a reg-name byte - unreserved,
// sub-delims, and "%" of a pct-encoded triplet - except ",": a comma in a
// host name is two hosts to anything that reads the value as a list (a
// proxy that joined two Host lines, an application that splits it), and no
// DNS name has one. Bit 1: a byte that may stand between the brackets of an
// IP-literal - the reg-name set, the comma, and ":".
inline constexpr std::array<uint8_t, 256> kHostChar = [] {
  std::array<uint8_t, 256> t{};
  for (unsigned c = 'a'; c <= 'z'; ++c) t[c] = 3;
  for (unsigned c = 'A'; c <= 'Z'; ++c) t[c] = 3;
  for (unsigned c = '0'; c <= '9'; ++c) t[c] = 3;
  for (unsigned char c : {'-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ';', '=', '%'})
    t[c] = 3;
  t[static_cast<unsigned char>(',')] = 2;
  t[static_cast<unsigned char>(':')] = 2;
  return t;
}();

// Whether a Host field value has the shape uri-host [ ":" port ]: a reg-name
// (which covers IPv4 addresses and may be empty) or a bracketed IP-literal,
// then optionally ":" and a port of digits only (possibly none). Anything
// else - whitespace, "/", "?", "#", "@", "\", a second ":" outside brackets,
// a non-ASCII byte - is not a host, and a request carrying it is answered
// 400 (RFC 9112 §3.2). Names are not otherwise judged: underscores, a
// trailing dot and upper case all pass.
//
// Every byte this accepts is a legal field-value byte, so for the Host line
// it stands in for the general value check rather than following it: the
// value is read once (HttpParser::hostOk). Kept out of line: inlined into
// the header-line parser it made the general value loop, which every other
// header goes through, measurably slower.
MORO_NOINLINE inline bool validHostValue(std::string_view v) {
  const size_t n = v.size();
  size_t i = 0;
  // An empty value names no host. It is what a request for a URI without an
  // authority carries (RFC 9112 §3.2), and no such URI reaches an HTTP server.
  if (n == 0) return false;
  if (v[0] == '[') {
    i = 1;
    while (i < n && (kHostChar[static_cast<unsigned char>(v[i])] & 2)) ++i;
    if (i == 1 || i >= n || v[i] != ']') return false;
    ++i;
  } else {
    while (i < n && (kHostChar[static_cast<unsigned char>(v[i])] & 1)) ++i;
    if (i == 0) return false;  // a port and no host before it
  }
  if (i == n) return true;
  if (v[i] != ':') return false;
  for (++i; i < n; ++i) {
    if (v[i] < '0' || v[i] > '9') return false;
  }
  return true;
}

// Whether the four bytes at `name` spell "host" in any letter case. (0x20 is
// the case bit; no other byte ORs to one of these four letters.)
MORO_ALWAYS_INLINE bool isHostName(const char* name) {
  uint32_t got, want;
  memcpy(&got, name, 4);
  memcpy(&want, "host", 4);
  return (got | 0x20202020u) == want;
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

// Lowercase a field name in place, eight bytes per step. Every byte of a
// name is a token byte, below 0x80: adding 0x3f to such a byte sets its top
// bit exactly when it is at least 'A', adding 0x25 exactly when it is past
// 'Z', and neither sum carries into the next byte, so the bytes A-Z of a
// word are found together and given the 0x20 bit. The tail goes through the
// table.
// Lowering is idempotent, so a tail is done as the last word of the name,
// over bytes already lowered: a name of four bytes or more never goes byte by
// byte.
MORO_ALWAYS_INLINE void lowerTokenInPlace(char* p, size_t n) {
  constexpr uint64_t kOnes = 0x0101010101010101ULL, kHigh = 0x8080808080808080ULL;
  const auto lower8 = [&](size_t at) {
    uint64_t w;
    memcpy(&w, p + at, 8);
    w |= ((w + kOnes * (0x80 - 'A')) & ~(w + kOnes * (0x80 - 'Z' - 1)) & kHigh) >> 2;
    memcpy(p + at, &w, 8);
  };
  const auto lower4 = [&](size_t at) {
    constexpr uint32_t kOnes4 = 0x01010101u, kHigh4 = 0x80808080u;
    uint32_t w;
    memcpy(&w, p + at, 4);
    w |= ((w + kOnes4 * (0x80 - 'A')) & ~(w + kOnes4 * (0x80 - 'Z' - 1)) & kHigh4) >> 2;
    memcpy(p + at, &w, 4);
  };
  if (n >= 8) {
    size_t i = 0;
    for (; i + 8 <= n; i += 8) lower8(i);
    if (i < n) lower8(n - 8);
  } else if (n >= 4) {
    lower4(0);
    lower4(n - 4);
  } else {
    for (size_t i = 0; i < n; ++i) p[i] = static_cast<char>(kLowercase[static_cast<unsigned char>(p[i])]);
  }
}

// Whether a field name (token bytes, any letter case) is `lit`, a lowercase
// name of letters and '-' of the same length n >= 4. A token byte ORed with
// 0x20 equals a lowercase letter only when it is that letter in either case,
// and equals '-' only when it is '-' (0x0d, the other byte that would, is not
// a token byte), so whole words are compared at once.
MORO_ALWAYS_INLINE bool foldedNameIs(const char* name, const char* lit, size_t n) {
  if (n >= 8) {
    uint64_t a, b;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
      memcpy(&a, name + i, 8);
      memcpy(&b, lit + i, 8);
      if ((a | 0x2020202020202020ULL) != b) return false;
    }
    if (i == n) return true;
    memcpy(&a, name + n - 8, 8);
    memcpy(&b, lit + n - 8, 8);
    return (a | 0x2020202020202020ULL) == b;
  }
  uint32_t a, b, c, d;
  memcpy(&a, name, 4);
  memcpy(&b, lit, 4);
  memcpy(&c, name + n - 4, 4);
  memcpy(&d, lit + n - 4, 4);
  return ((a | 0x20202020u) == b) & ((c | 0x20202020u) == d);
}

inline void HeaderList::commit(const char* src, size_t base, size_t end) {
  if (fields_.empty()) {
    text_.clear();
    return;
  }
  if (end - base <= kKeepText) release();
  text_.assign(src + base, src + end);
  char* t = text_.data();
  for (Field& f : fields_) {
    f.name -= base;
    f.value -= base;
    lowerTokenInPlace(t + f.name, f.nameLen);
    // The byte after a value is the OWS, CR or LF that ended its line.
    t[f.value + f.valueLen] = '\0';
  }
}

// field-line syntax (RFC 9112 §5) of a line nothing stores: a token name up
// to the colon, then a value of VCHAR / SP / HTAB / obs-text. The checks
// parseHeaderLine applies, for the trailer section of a chunked body.
inline bool validFieldLine(std::string_view line) {
  size_t colon = 0;
  while (colon < line.size() && kTokenChar[static_cast<unsigned char>(line[colon])]) ++colon;
  if (colon == 0 || colon >= line.size() || line[colon] != ':') return false;
  for (size_t i = colon + 1; i < line.size(); ++i) {
    if (!kValueChar[static_cast<unsigned char>(line[i])]) return false;
  }
  return true;
}

// The Host value was not the one seen last: check it, and remember it if it
// passes and fits.
inline bool HttpParser::methodOverlong(const char* p, size_t n) {
  if (n <= kMaxMethodLen) return false;
  for (size_t i = 0; i <= kMaxMethodLen; ++i) {
    if (!kTokenChar[static_cast<unsigned char>(p[i])]) return false;
  }
  return true;
}

// What may follow the size on a chunk-size line (RFC 9112 §7.1.1):
//   chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
//   chunk-ext-name = token      chunk-ext-val = token / quoted-string
// Nothing is made of an extension, but the line is held to the grammar: a
// ";" with no name after it, a name or value that is not a token or a quoted
// string, and whitespace that is not followed by a ";" (so also whitespace
// at the end of the line) are refused. A recipient that takes such a line
// reads the chunk's size where an intermediary that refuses it, or reads it
// differently, does not, and the two then disagree about where the body
// ends.
inline bool chunkExtOk(const char* p, size_t n) {
  size_t i = 0;
  const auto bws = [&] {
    while (i < n && (p[i] == ' ' || p[i] == '\t')) ++i;
  };
  const auto token = [&] {
    const size_t start = i;
    while (i < n && kTokenChar[static_cast<unsigned char>(p[i])]) ++i;
    return i > start;
  };
  while (i < n) {
    bws();
    if (i >= n || p[i] != ';') return false;
    ++i;
    bws();
    if (!token()) return false;
    const size_t afterName = i;
    bws();
    if (i < n && p[i] == '=') {
      ++i;
      bws();
      if (i < n && p[i] == '"') {
        // quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
        ++i;
        for (;;) {
          if (i >= n) return false;
          const unsigned char c = static_cast<unsigned char>(p[i]);
          if (c == '"') { ++i; break; }
          if (c == '\\') {
            if (i + 1 >= n) return false;
            const unsigned char q = static_cast<unsigned char>(p[i + 1]);
            if (q != '\t' && (q < 0x20 || q == 0x7f)) return false;
            i += 2;
            continue;
          }
          if (c != '\t' && (c < 0x20 || c == 0x7f)) return false;
          ++i;
        }
      } else if (!token()) {
        return false;
      }
    } else {
      i = afterName;  // the whitespace belongs to the next ";" or is refused there
    }
  }
  return true;
}

MORO_NOINLINE inline bool HttpParser::hostCheck(std::string_view v) {
  if (!validHostValue(v)) return false;
  if (v.size() <= kHostSeenMax) {
    memcpy(hostSeen_, v.data(), v.size());
    hostSeenLen_ = v.size();
  }
  return true;
}

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
  directBody_ = false;
  method = Method::OTHER;
  methodStr.clear();
  path.clear();
  query.clear();
  minorVersion = 1;
  // `headers` is emptied when the next request turns out to store its
  // fields (at its request line), not here: an engine-answered request never
  // touches it.
  headerCount_ = 0;
  light_ = 0;
  failed_ = false;
  methodRefused_ = false;
  lineNote_ = 0;
  hostCount_ = 0;
  sawClose_ = sawKeepAlive_ = false;
  teCount_ = 0;
  teChunked_ = false;
  hasCL_ = false;
  cl_ = 0;
  clError_ = 0;
  expectContinue_ = hasUpgrade_ = false;
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
  for (const Header h : headers) {
    if (h.name == name) return h.value.data();  // NUL-terminated (HeaderList)
  }
  return nullptr;
}

inline bool HttpParser::parseRequestLine(std::string_view line) {
  // RFC 9112 §3: request-line = method SP request-target SP HTTP-version.
  // One pass per field: the method is scanned while it is validated (token
  // chars up to the SP), the target likewise (no C0 byte, no DEL, up to the
  // SP) - a byte that is neither valid nor the delimiter ends the scan short
  // of the delimiter and rejects the line, exactly as find-then-validate did.
  const size_t n = line.size();
  size_t i = 0;
  while (i < n && kTokenChar[static_cast<unsigned char>(line[i])]) ++i;
  if (i > kMaxMethodLen) {
    errorStatus = 501;
    methodRefused_ = true;
    return false;
  }
  if (i == 0 || i >= n || line[i] != ' ') {
    noteNotHttp(i >= n);  // the line ends inside its first token
    return false;
  }
  std::string_view m = line.substr(0, i);
  const size_t tStart = i + 1;
  // Request-target hygiene (RFC 9112 §3.2 / RFC 3986): reject raw control
  // bytes. Only the line-terminating CRLF is stripped by the caller, so a
  // bare CR, NUL, any other C0 byte, or DEL would otherwise reach the app
  // verbatim in path/query - log-injection and downstream-desync fodder.
  // So are bytes of 0x80 and above: a URI is ASCII (RFC 3986 §2), a client
  // that means a non-ASCII character percent-encodes it, and a raw one is
  // where an overlong UTF-8 form of "/" or "." hides from a path check that
  // runs before decoding. limits.allowNonAsciiTarget takes them as before.
  // Absolute-form / authority-form targets pass through opaquely (RFC 9112
  // §3.2.2 requires accepting absolute-form; routing on it is the app's /
  // fronting proxy's business, matching Node).
  size_t j = tStart;
  const unsigned char highLimit = limits_->allowNonAsciiTarget ? 0xff : 0x7f;
  while (j < n && line[j] != ' ') {
    const unsigned char u = static_cast<unsigned char>(line[j]);
    if (u < 0x20 || u == 0x7f || u > highLimit) return false;  // errorStatus stays 400
    ++j;
  }
  if (j >= n || j == tStart) {  // no second SP, or an empty target
    noteNotHttp(j >= n);
    return false;
  }
  std::string_view t = line.substr(tStart, j - tStart);
  std::string_view v = line.substr(j + 1);
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
  if (v.size() != 8 || memcmp(v.data(), "HTTP/", 5) != 0 || v[6] != '.' ||
      v[5] < '0' || v[5] > '9' || v[7] < '0' || v[7] > '9') {
    noteNotHttp(v.size() < 5 || memcmp(v.data(), "HTTP/", 5) != 0);
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
  // The target has one of four forms (RFC 9112 §3.2). Origin-form, which
  // begins with "/", is what a request to an origin server carries, and its
  // first byte settles it; the other three are told apart out of line.
  // Asked last: a line that is not HTTP/1.x at all (the HTTP/2 preface,
  // "PRI * HTTP/2.0") is answered for its version.
  if (t[0] != '/' && !targetFormOk(method, methodStr, t)) {
    errorStatus = 400;
    return false;
  }
  return true;
}

// A request-target that does not begin with "/" (RFC 9112 §3.2):
//  - asterisk-form (§3.2.4) is exactly "*" - nothing behind it, no query -
//    and the target of a server-wide OPTIONS and of no other method;
//  - authority-form (§3.2.3) is CONNECT's, and whatever CONNECT names is
//    handed over as it always was;
//  - absolute-form (§3.2.2) begins with a scheme (RFC 3986 §3.1) and "://",
//    and is passed through opaquely (routing on it is the application's or
//    the fronting proxy's business).
// Anything else is no request-target: "abc", "*x", "?q", "host:80/path".
// Such a target used to be handed over as the path, to code written for
// paths that begin with "/".
MORO_NOINLINE inline bool HttpParser::targetFormOk(Method method, std::string_view methodStr,
                                                   std::string_view t) {
  if (t.size() == 1 && t[0] == '*') return method == Method::OPTIONS;
  if (method == Method::OTHER && methodStr == "CONNECT") return true;
  const auto alpha = [](unsigned char c) { return static_cast<unsigned char>((c | 0x20) - 'a') < 26; };
  if (!alpha(static_cast<unsigned char>(t[0]))) return false;
  size_t i = 1;
  for (; i < t.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(t[i]);
    if (!alpha(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.') break;
  }
  return t.size() - i >= 3 && t[i] == ':' && t[i + 1] == '/' && t[i + 2] == '/';
}

// A complete head larger than leanHead_: refused when it is over maxHeadSize
// (431, the answer the comparison with maxHeadSize always gave), noted
// otherwise (kLeanHead). Returns true for the refusal.
MORO_NOINLINE inline bool HttpParser::headOver(size_t size) {
  if (size > limits_->maxHeadSize) {
    errorStatus = 431;
    return true;
  }
  largeHead_ = 1;
  return false;
}

inline bool HttpParser::parseHeaderLine(std::string_view line, size_t at) {
  // field-line = field-name ":" OWS field-value OWS   (RFC 9112 §5)
  // The name is scanned while it is validated: token chars up to the colon.
  // No whitespace (or any other non-token byte) may sit between the name and
  // the colon (RFC 9112 §5.1 - request smuggling / header injection); such a
  // byte ends the scan short of the colon and rejects the line.
  // The Host line, which every request has, is known by its first five
  // bytes without a scan.
  const size_t colon = (line.size() > 4 && line[4] == ':' && isHostName(line.data()))
                           ? 4
                           : tokenRun(reinterpret_cast<const unsigned char*>(line.data()), line.size());
  if (colon == 0 || colon >= line.size() || line[colon] != ':') return false;

  std::string_view value = trimOWS(line.substr(colon + 1));
  // Field-value byte discipline (RFC 9110 §5.5: VCHAR / SP / HTAB /
  // obs-text). A bare CR, NUL, or other C0 byte in a value would be handed
  // to the app verbatim (only the line-terminating CRLF is stripped) - the
  // inbound twin of the response-side validHeaderValue filter. obs-text
  // (0x80+) stays allowed, matching Node. The Host value is held to its own,
  // narrower grammar instead (hostOk, validHostValue): RFC 9112 §3.2.
  if (colon == 4 && isHostName(line.data())) {
    if (!hostOk(value)) return false;
    ++hostCount_;
  } else {
    if (!validValueBytes(reinterpret_cast<const unsigned char*>(value.data()), value.size())) return false;
    classifyField(line.data(), colon, value);
  }
  // An engine-answered request (light) stores nothing. Otherwise the field
  // is recorded where it lies; the head is copied, and the names lowered,
  // once it is complete (HeaderList::commit).
  if (!light_) headers.mark(at, colon, at + static_cast<size_t>(value.data() - line.data()), value.size());
  ++headerCount_;
  return true;
}

// Only a name the length of a framing header can be one (expect, upgrade,
// connection, content-length, transfer-encoding; host is taken by the
// caller): compared with that name in any letter case (foldedNameIs) and,
// when it is the one, handed to classifyHeader; any other name is skipped.
MORO_ALWAYS_INLINE void HttpParser::classifyField(const char* name, size_t n, std::string_view value) {
  const char* lname = nullptr;
  switch (n) {
    case 6: lname = "expect"; break;
    case 7: lname = "upgrade"; break;
    case 10: lname = "connection"; break;
    case 14: lname = "content-length"; break;
    case 17: lname = "transfer-encoding"; break;
    default: return;
  }
  if (foldedNameIs(name, lname, n)) classifyHeader(std::string_view(lname, n), value);
}

inline void HttpParser::classifyHeader(std::string_view n, std::string_view v) {
  switch (n.size()) {
    case 4:
      if (memcmp(n.data(), "host", 4) == 0) ++hostCount_;
      break;
    case 6:
      if (memcmp(n.data(), "expect", 6) == 0 && iequals(trimOWS(v), "100-continue")) expectContinue_ = true;
      break;
    case 7:
      if (memcmp(n.data(), "upgrade", 7) == 0) hasUpgrade_ = true;
      break;
    case 10:
      if (memcmp(n.data(), "connection", 10) == 0) {
        // The single-token values first: no comma scan for the common case.
        if (v.size() == 10 && iequals(v, "keep-alive")) { sawKeepAlive_ = true; break; }
        if (v.size() == 5 && iequals(v, "close")) { sawClose_ = true; break; }
        size_t pos = 0;
        while (pos <= v.size()) {
          size_t comma = v.find(',', pos);
          std::string_view tok =
              trimOWS(v.substr(pos, comma == std::string_view::npos ? v.size() - pos : comma - pos));
          if (iequals(tok, "close")) sawClose_ = true;
          else if (iequals(tok, "keep-alive")) sawKeepAlive_ = true;
          if (comma == std::string_view::npos) break;
          pos = comma + 1;
        }
      }
      break;
    case 14:
      if (memcmp(n.data(), "content-length", 14) == 0 && clError_ == 0) {
        if (v.empty()) { clError_ = 400; break; }
        // 1*DIGIT, read to its end before it is judged: a value with a
        // non-digit in it is malformed wherever the non-digit sits, and one
        // that no 64-bit length can hold is malformed too (400), not merely
        // larger than this server takes (413).
        size_t parsed = 0;
        bool tooLarge = false;
        for (char c : v) {
          if (c < '0' || c > '9') { clError_ = 400; break; }
          const size_t d = static_cast<size_t>(c - '0');
          if (parsed > (SIZE_MAX - d) / 10) { clError_ = 400; break; }
          parsed = parsed * 10 + d;
          if (parsed > limits_->maxBodySize) tooLarge = true;
        }
        if (clError_) break;
        if (tooLarge) { clError_ = 413; break; }
        if (hasCL_ && parsed != cl_) { clError_ = 400; break; }
        cl_ = parsed;
        hasCL_ = true;
      }
      break;
    case 17:
      if (memcmp(n.data(), "transfer-encoding", 17) == 0) {
        teCount_++;
        teChunked_ = iequals(trimOWS(v), "chunked");  // the last one decides, as before
      }
      break;
    default:
      break;
  }
}

inline bool HttpParser::finalizeHeaders() {
  // Every header was classified as its line was parsed (classifyHeader);
  // this resolves what they add up to. Exactly one Host line with a host in
  // it (RFC 9112 §3.2); an HTTP/1.0 request may come without one.
  if (hostCount_ > 1 || (hostCount_ == 0 && minorVersion >= 1)) {
    errorStatus = 400;
    return false;
  }

  if (sawClose_) keepAlive = false;
  else if (sawKeepAlive_) keepAlive = true;

  if (minorVersion == 0) {
    // An HTTP/1.0 client is never sent a 1xx response, so its Expect:
    // 100-continue is ignored (RFC 9110 §10.1.1, §15.2). And HTTP/1.0 has no
    // Transfer-Encoding: a 1.0 message that carries one has unreliable
    // framing, and the connection is closed once it has been answered
    // (RFC 9112 §6.1).
    expectContinue_ = false;
    if (teCount_ > 0) keepAlive = false;
  }

  if (clError_) { errorStatus = clError_; return false; }

  if (teCount_ > 0) {
    if (hasCL_) { errorStatus = 400; return false; }
    if (teCount_ > 1) { errorStatus = 400; return false; }
    if (teChunked_) {
      chunked_ = true;
      hasBody_ = true;
    } else {
      errorStatus = 400;  // unsupported / non-final chunked
      return false;
    }
  } else if (hasCL_) {
    contentLength_ = cl_;
    hasBody_ = cl_ > 0;
    if (cl_ > limits_->maxBodySize) { errorStatus = 413; return false; }
  } else {
    hasBody_ = false;  // no body framing -> no body (RFC 9112 §6.3 point 6)
  }

  return true;
}

// The header lines of an engine-answered request, scanned in place. Each
// line gets exactly the checks parseHeaderLine applies - a token field name
// up to the colon, a field value of VCHAR / SP / HTAB / obs-text, the header
// count and head-size limits - and, when its name has the length of a
// framing header, the same classification; nothing is stored. Returns 1
// with `pos` just past the blank line, 0 when the bytes end inside a line
// (`pos` at that line's start, where the buffered path resumes), -1 for a
// rejected line (errorStatus set, 400 unless a limit says 431).
inline int HttpParser::scanLightHeaders(const unsigned char* d, size_t len, size_t& pos) {
  for (;;) {
    if (pos >= len) return 0;
    const void* nlp = memchr(d + pos, '\n', len - pos);
    if (!nlp) return 0;  // a line is judged only once it is whole
    size_t lineEnd = static_cast<size_t>(static_cast<const unsigned char*>(nlp) - d);
    const size_t next = lineEnd + 1;
    if (lineEnd > pos && d[lineEnd - 1] == '\r') --lineEnd;
    if (lineEnd == pos) {  // the blank line ends the head
      pos = next;
      break;
    }
    if (headerCount_ >= limits_->maxHeaders) {
      errorStatus = 431;
      return -1;
    }
    // A malformed line is 400 - unless the head, up to and including that
    // line, is over maxHeadSize: then it is 431, as it is when the line
    // arrives in pieces and the limit is passed before its syntax can be
    // known (see parseDirect). Asked only when a line is refused; a head of
    // well-formed lines is measured once, at its end.
    const auto refused = [&]() {
      if (next > limits_->maxHeadSize) errorStatus = 431;
      return -1;
    };
    // field-line = field-name ":" OWS field-value OWS   (RFC 9112 §5)
    size_t i = (lineEnd - pos > 4 && d[pos + 4] == ':' && isHostName(reinterpret_cast<const char*>(d + pos)))
                   ? pos + 4  // the Host line, known without a scan (see parseHeaderLine)
                   : pos + tokenRun(d + pos, lineEnd - pos);
    if (i == pos || i >= lineEnd || d[i] != ':') return refused();
    const size_t nameLen = i - pos;
    ++i;
    while (i < lineEnd && (d[i] == ' ' || d[i] == '\t')) ++i;
    const size_t vs = i;
    size_t ve = lineEnd;
    while (ve > vs && (d[ve - 1] == ' ' || d[ve - 1] == '\t')) --ve;
    if (nameLen == 4 && isHostName(reinterpret_cast<const char*>(d + pos))) {
      // Host: its value is checked against the host grammar, which implies
      // the field-value check (see validHostValue), and counted.
      if (!hostOk(std::string_view(reinterpret_cast<const char*>(d + vs), ve - vs))) return refused();
      ++hostCount_;
    } else {
      if (!validValueBytes(d + vs, ve - vs)) return refused();
      // Only a name the length of a framing header can be one (host was
      // taken above): see classifyField.
      classifyField(reinterpret_cast<const char*>(d + pos), nameLen,
                    std::string_view(reinterpret_cast<const char*>(d + vs), ve - vs));
    }
    ++headerCount_;
    pos = next;
  }
  if (pos > leanHead_ && headOver(pos)) return -1;
  return 1;
}

// A request arriving on an idle connection, straight from the read buffer.
// The request line is parsed as always and the route hook asked; a request
// JS will see (the hook says no) is handed to the buffered path with its
// request line already parsed, so nothing is scanned twice. An
// engine-answered one has its headers scanned in place (scanLightHeaders)
// and, with no body to collect, completes without the bytes ever being
// copied: only a pipelined remainder is kept in buf_. Anything unfinished -
// a partial head, a body still to receive - goes to buf_ with the state
// machine positioned where the scan stopped, and the buffered path continues
// from there. Returns true when `st` is the result; false when the buffered
// path must run (buf_ then holds the bytes).
inline bool HttpParser::parseDirect(const char* data, size_t len, ParseStatus& st) {
  const void* nlp = memchr(data, '\n', len);
  if (!nlp) {  // no complete request line yet
    buf_.append(data, len);
    return false;
  }
  size_t lineEnd = static_cast<size_t>(static_cast<const char*>(nlp) - data);
  const size_t nextScan = lineEnd + 1;
  if (lineEnd > 0 && data[lineEnd - 1] == '\r') --lineEnd;
  if (lineEnd == 0) {  // leading CRLF: the buffered path tolerates it
    buf_.append(data, len);
    return false;
  }
  // Which status a refused head gets must not depend on how its bytes were
  // split across reads. A head that arrives in pieces is refused 431 as soon
  // as more than maxHeadSize of it is buffered, before the syntax of the
  // line still arriving can be known; so a line is 431 whenever the head, up
  // to and including that line, is over the limit - malformed or not - and a
  // malformed line is 400 (or 414, 505) only while the head is within it.
  // What a read holds behind the line does not count. Here and for every
  // header line, in all three paths, the size is therefore asked where a
  // line is refused, and once more where the head ends.
  if (!parseRequestLine(std::string_view(data, lineEnd))) {
    if (!methodRefused_ && nextScan > limits_->maxHeadSize) errorStatus = 431;
    buf_.append(data, len);
    st = ParseStatus::Error;
    return true;
  }
  light_ = routeHook(routeHookUser, method, path) ? kLightFresh : 0;
  state_ = State::Headers;
  headBase_ = nextScan;
  if (!light_) {
    headers.clear();
    return parseDirectStored(data, len, nextScan, st);
  }
  size_t pos = nextScan;
  const int r = scanLightHeaders(reinterpret_cast<const unsigned char*>(data), len, pos);
  if (r < 0) {
    buf_.append(data, len);
    st = ParseStatus::Error;
    return true;
  }
  if (r == 0) {  // head unfinished: resume from the incomplete line
    buf_.append(data, len);
    scanPos_ = pos;
    return false;
  }
  if (!finalizeHeaders()) {
    buf_.append(data, len);
    st = ParseStatus::Error;
    return true;
  }
  state_ = chunked_ ? State::ChunkSize : State::Body;
  if (hasBody_) {  // the body is collected from buf_ as always
    buf_.append(data, len);
    headEnd_ = pos;
    scanPos_ = pos;
    return false;
  }
  // Complete, nothing copied; buf_ holds only what follows this request.
  if (pos < len) buf_.assign(data + pos, len - pos);
  consumed_ = 0;
  scanPos_ = 0;
  headEnd_ = 0;
  state_ = State::Done;
  st = ParseStatus::Complete;
  return true;
}

// The stored-header twin of the light scan above: a request JS will see,
// arriving on an idle connection. Its header lines are parsed from the read
// buffer in place (parseHeaderLine stores them exactly as the buffered path
// does), so the head is never copied into buf_. A Content-Length body is
// collected straight into `body`: what arrived with the head is copied once,
// and every later read appends to `body` directly (parse() sees directBody_)
// instead of growing buf_ and copying the whole body out of it at the end.
// An unfinished head, a chunked body and every error hand over to the
// buffered path with the bytes in buf_, as before. Returns true when `st` is
// the result.
inline bool HttpParser::parseDirectStored(const char* data, size_t len, size_t pos,
                                          ParseStatus& st) {
  for (;;) {
    const void* nlp = memchr(data + pos, '\n', len - pos);
    if (!nlp) {  // head unfinished: the buffered path resumes from this line
      buf_.append(data, len);
      scanPos_ = pos;
      return false;
    }
    const size_t nl = static_cast<size_t>(static_cast<const char*>(nlp) - data);
    size_t lineEnd = nl;
    if (lineEnd > pos && data[lineEnd - 1] == '\r') --lineEnd;
    const std::string_view line(data + pos, lineEnd - pos);
    const size_t at = pos;
    pos = nl + 1;
    if (line.empty()) break;  // blank line terminates the head
    if (headerCount_ >= limits_->maxHeaders) {
      errorStatus = 431;
      buf_.append(data, len);
      st = ParseStatus::Error;
      return true;
    }
    if (!parseHeaderLine(line, at)) {
      if (pos > limits_->maxHeadSize) errorStatus = 431;  // see parseDirect
      buf_.append(data, len);
      st = ParseStatus::Error;
      return true;
    }
  }
  // The same checks the buffered path applies at the blank line, on the
  // head's true size.
  if (pos > leanHead_ && headOver(pos)) {
    buf_.append(data, len);
    st = ParseStatus::Error;
    return true;
  }
  headers.commit(data, headBase_, pos);
  if (!finalizeHeaders()) {
    buf_.append(data, len);
    st = ParseStatus::Error;
    return true;
  }
  consumed_ = 0;
  scanPos_ = 0;
  headEnd_ = 0;
  if (chunked_) {  // the chunk loop reads from buf_: only the body bytes go there
    buf_.assign(data + pos, len - pos);
    state_ = State::ChunkSize;
    return false;
  }
  if (!hasBody_) {  // complete, nothing copied; buf_ holds only what follows
    if (pos < len) buf_.assign(data + pos, len - pos);
    state_ = State::Done;
    st = ParseStatus::Complete;
    return true;
  }
  const size_t avail = len - pos;
  const size_t take = avail < contentLength_ ? avail : contentLength_;
  takeBody();
  reserveBody(take);
  body.assign(data + pos, take);
  if (take == contentLength_) {
    if (pos + take < len) buf_.assign(data + pos + take, len - pos - take);
    state_ = State::Done;
    st = ParseStatus::Complete;
    return true;
  }
  directBody_ = true;
  state_ = State::Body;
  st = ParseStatus::NeedMore;
  return true;
}

inline ParseStatus HttpParser::parse(const char* data, size_t len) {
  if (failed_) return ParseStatus::Error;
  const ParseStatus st = parseSome(data, len);
  if (st != ParseStatus::Complete) {
    if (st == ParseStatus::Error) failed_ = true;
    else if (light_) light_ = kLightSpanned;  // unfinished: the caller runs before the rest arrives
  }
  return st;
}

MORO_ALWAYS_INLINE ParseStatus HttpParser::parseSome(const char* data, size_t len) {
  // A Content-Length body collected straight into `body` (directBody_): the
  // head is parsed and nothing of this request sits in buf_ past it, so the
  // bytes go to `body` without a stop in buf_. What follows the body is the
  // next request and is buffered as always.
  if (directBody_) {
    const size_t need = contentLength_ - body.size();
    const size_t take = len < need ? len : need;
    if (take) {  // parse(nullptr, 0) is a legal re-entry
      reserveBody(take);
      body.append(data, take);
    }
    if (take < need) return ParseStatus::NeedMore;
    if (take < len) buf_.append(data + take, len - take);
    directBody_ = false;
    state_ = State::Done;
    return ParseStatus::Complete;
  }
  if (len) {
    // A fresh request with nothing buffered ahead of it: the zero-copy scan
    // first. When it hands the request over instead, it has appended the
    // bytes to buf_ and positioned the state machine itself.
    if (buf_.empty() && state_ == State::RequestLine && routeHook) {
      ParseStatus st;
      if (parseDirect(data, len, st)) return st;
    } else {
      buf_.append(data, len);
    }
  }

  // --- head (request line + headers) ---
  while (state_ == State::RequestLine || state_ == State::Headers) {
    size_t nl = buf_.find('\n', scanPos_);
    if (nl == std::string::npos) {
      // A method token already past its bound is refused without waiting for
      // the rest of the line (which may never end).
      if (state_ == State::RequestLine && methodOverlong(buf_.data() + scanPos_, buf_.size() - scanPos_)) {
        errorStatus = 501;
        return ParseStatus::Error;
      }
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
        // 431 when the head up to and including this line is over the limit
        // (see parseDirect). Relative to consumed_: with deferred compaction
        // the buffer may still carry a dead prefix from prior requests,
        // which must not count toward this request's head size.
        if (!methodRefused_ && nextScan - consumed_ > limits_->maxHeadSize) errorStatus = 431;
        return ParseStatus::Error;
      }
      light_ = (routeHook != nullptr && routeHook(routeHookUser, method, path)) ? kLightFresh : 0;
      state_ = State::Headers;
      scanPos_ = nextScan;
      headBase_ = nextScan;
      if (!light_) headers.clear();
    } else {  // Headers
      if (line.empty()) {  // blank line terminates the head
        headEnd_ = nextScan;
        scanPos_ = nextScan;
        // Final head-size check, including the terminating blank line. This
        // (not buf_.size()) is the complete head's true size: the buffer may
        // already hold the request's body when a buffered batch is replayed
        // in one parse() call, and those bytes must not count against the
        // head limit.
        if (headEnd_ - consumed_ > leanHead_ && headOver(headEnd_ - consumed_)) return ParseStatus::Error;
        // The fields are copied out of buf_ in one piece (a light request
        // stored nothing and has no consumer of `headers`).
        if (!light_) headers.commit(buf_.data(), headBase_, headEnd_);
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
      if (!parseHeaderLine(line, scanPos_)) {
        // The size asked is that of the head up to and including this line
        // (nextScan), never of the whole buffer: buf_ may already hold the
        // request's body (or pipelined follow-ups) when a buffered batch is
        // replayed in one parse() call. A head of well-formed lines that is
        // over the limit is refused where it ends (the blank line, above) or
        // where it stops (the no-newline branch, which can use buf_.size():
        // body bytes are always preceded by the blank line's '\n', so an
        // un-terminated remainder is head bytes by construction).
        if (nextScan - consumed_ > limits_->maxHeadSize) errorStatus = 431;
        return ParseStatus::Error;
      }
      scanPos_ = nextScan;
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
    if (available >= contentLength_) {
      takeBody();
      body.assign(buf_.data() + headEnd_, contentLength_);
      consumed_ = headEnd_ + contentLength_;
      state_ = State::Done;
      return ParseStatus::Complete;
    }
    // Partial: what has arrived moves to `body` now and the rest is appended
    // there by later reads (directBody_), so the body is copied once instead
    // of growing buf_ and being copied out of it whole at the end. The head
    // is consumed; buf_ keeps it (dead) until reset() compacts.
    takeBody();
    reserveBody(available);
    body.assign(buf_.data() + headEnd_, available);
    buf_.resize(headEnd_);
    consumed_ = headEnd_;
    directBody_ = true;
    return ParseStatus::NeedMore;
  }

  // --- chunked body (RFC 9112 §7.1) ---
  // Every line of the framing - a chunk-size line, the CRLF after a chunk's
  // data, the last chunk, each trailer line and the blank line that ends the
  // body - is terminated by CRLF. The bare LF a recipient may take for a line
  // end (§2.2) is an allowance for the start line and the header fields, not
  // for chunk framing: a server that also takes it here disagrees with every
  // intermediary that does not about where the body ends.
  //
  // Whenever the loop has to wait for more bytes, what it has consumed is
  // dropped from the buffer (dropSpent, once kChunkCompactAt of it has
  // accumulated): the head has been stored and each chunk's data is in
  // `body`, so the buffer then holds only what has not been parsed yet. Kept
  // until the request completed, it held every byte of the body's framing -
  // sizes, extensions, CRLFs - which maxBodySize does not count, so the
  // memory one request could occupy was set by what the peer chose to send.
  // Dropping at these points, and not after each chunk, moves only the
  // unparsed tail of a read - a partial line or a partial chunk - and moves
  // it once.
  while (state_ == State::ChunkSize || state_ == State::ChunkData ||
         state_ == State::ChunkTrailer) {
    if (state_ == State::ChunkSize) {
      const size_t nl = buf_.find('\n', scanPos_);
      // One bound on the line, counted up to its LF whether or not that has
      // arrived (kMaxChunkLine).
      if ((nl == std::string::npos ? buf_.size() : nl) - scanPos_ > kMaxChunkLine) {
        errorStatus = 400;
        return ParseStatus::Error;
      }
      if (nl == std::string::npos) {
        if (scanPos_ >= kChunkCompactAt) dropSpent(scanPos_);
        return ParseStatus::NeedMore;
      }
      if (nl == scanPos_ || buf_[nl - 1] != '\r') {  // bare LF
        errorStatus = 400;
        return ParseStatus::Error;
      }
      // chunk-size [ chunk-ext ]: chunk-size = 1*HEXDIG, at the very start
      // of the line, then the extensions and nothing else (chunkExtOk). A
      // size that no 64-bit length can hold is malformed (400); one that is
      // only larger than this server takes is 413, once the line has been
      // found well-formed.
      const char* const line = buf_.data() + scanPos_;
      const size_t lineLen = nl - 1 - scanPos_;
      size_t i = 0;
      size_t sz = 0;
      bool tooLarge = false;
      for (; i < lineLen; ++i) {
        const char c = line[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        if (sz > (SIZE_MAX >> 4)) { errorStatus = 400; return ParseStatus::Error; }
        sz = sz * 16 + static_cast<size_t>(d);
        if (sz > limits_->maxBodySize) tooLarge = true;
      }
      if (i == 0 || !chunkExtOk(line + i, lineLen - i)) {
        errorStatus = 400;
        return ParseStatus::Error;
      }
      // A chunk that would take the body past maxBodySize is refused here,
      // at its size line, not once its data has been received: until then
      // that data would sit in the buffer on top of the body collected so
      // far.
      if (tooLarge || sz > limits_->maxBodySize - body.size()) {
        errorStatus = 413;
        return ParseStatus::Error;
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
      if (available < chunkRemaining_ + 2) {  // + CRLF
        if (scanPos_ >= kChunkCompactAt) dropSpent(scanPos_);
        return ParseStatus::NeedMore;
      }
      if (body.empty()) takeBody();
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
    } else {  // ChunkTrailer - trailer field lines up to the blank line
      // The trailer section is bounded by maxHeadSize as a whole, not line by
      // line: a peer could otherwise send short lines for ever, each within a
      // per-line bound, while the request never completes. The bound is on
      // the section itself - the lines scanned so far, or a line still
      // unfinished - and never on what the buffer holds past it: those bytes
      // are the next pipelined request.
      const size_t nl = buf_.find('\n', scanPos_);
      if ((nl == std::string::npos ? buf_.size() : nl + 1) - chunkTrailerStart_ > limits_->maxHeadSize) {
        errorStatus = 431;
        return ParseStatus::Error;
      }
      if (nl == std::string::npos) {
        // The trailer section itself stays (its bound is counted from its start).
        if (chunkTrailerStart_ >= kChunkCompactAt) dropSpent(chunkTrailerStart_);
        return ParseStatus::NeedMore;
      }
      if (nl == scanPos_ || buf_[nl - 1] != '\r') {  // bare LF
        errorStatus = 400;
        return ParseStatus::Error;
      }
      const std::string_view line(buf_.data() + scanPos_, nl - 1 - scanPos_);
      scanPos_ = nl + 1;
      if (line.empty()) {
        consumed_ = scanPos_;
        state_ = State::Done;
        return ParseStatus::Complete;
      }
      // trailer-section = *( field-line CRLF ): each line is checked as a
      // header line is, and then dropped - trailers are not surfaced.
      if (!validFieldLine(line)) {
        errorStatus = 400;
        return ParseStatus::Error;
      }
    }
  }

  return ParseStatus::NeedMore;
}

}  // namespace engine
}  // namespace moro
