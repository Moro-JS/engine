// @morojs/engine - native HTTP engine for MoroJS
//
// Raw V8 binding: wires the Moro-shaped JS API (docs/API.md) to the C++
// HTTP/1.1 engine in server.h. Per-Node-ABI build (max perf).
//
// (see CONTRIBUTING.md policy) Protocol behavior cites RFCs in server.h / http_parser.h.

#include <node.h>
#include <node_version.h>
#include <uv.h>
#include <v8.h>

#include <climits>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "fast_api.h"
#include "server.h"
#include "text.h"
#include "v8_compat.h"
#include "win_delay_load_hook.h"

namespace moro {
namespace engine {

// Build-time fallback only. The published package version is authoritative:
// the JS loader (packages/engine/index.js) reads it from package.json and
// overrides this in probe() and on `.version`. Keep it roughly in step, but the
// loader is the source of truth, so this never has to be bumped by hand.
static const char* kEngineVersion = "1.1.6";

using v8::Array;
using v8::ArrayBuffer;
using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Global;
using v8::HandleScope;
using v8::Int32;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::String;
using v8::TryCatch;
using v8::Uint8Array;
using v8::Value;

// Per-serve() JS callback set + context, referenced by Server callbacks.
struct JsServer {
  Isolate* isolate;
  Global<Context> context;
  Global<Function> onRequest;
  Global<Function> onRequestBatch;
  Global<Function> onAborted;
  Global<Function> onWritable;
  Global<Function> onWsOpen;
  Global<Function> onWsMessage;
  Global<Function> onWsClose;
  Server* server;
  // The resource object of the Node callback scope every trampoline into JS
  // opens (CallbackScopeFor): one per server, no per-request allocation.
  Global<Object> asyncResource;
  uint32_t id = 0;
  // Set by the environment cleanup hook: the isolate is being torn down and
  // JS may no longer run, so every callback into JS becomes a no-op.
  bool tearingDown = false;
  // When the cleanup hook is waiting for this server to finish closing, it
  // points here so freeJsServer can report completion.
  bool* closedFlag = nullptr;
  // Interned per-path JS strings: real apps route a BOUNDED set of paths, so
  // the per-request String::NewFromUtf8 (allocation + GC pressure) is paid
  // once per unique path instead of once per request. Bounded: only paths
  // <= kPathCacheMaxLen are cached and at most kPathCacheMaxEntries live here
  // (past the cap, requests simply build the string per-call as before), so
  // an adversary spraying unique URLs can't grow it. Freed with the JsServer.
  std::unordered_map<std::string, Global<String>> pathCache;
  static constexpr size_t kPathCacheMaxEntries = 512;
  static constexpr size_t kPathCacheMaxLen = 128;
  // Same idea for request header NAMES (getHeaders/getHeader hot path when
  // apps read req.headers): a bounded set in practice (host, accept, ...),
  // so intern them instead of a String::NewFromUtf8 per name per request.
  // Values are never cached - they vary per request. Same lifetime story.
  std::unordered_map<std::string, Global<String>> headerNameCache;
  static constexpr size_t kHeaderNameCacheMaxEntries = 256;
  static constexpr size_t kHeaderNameCacheMaxLen = 64;

  // Batched dispatch (getBatchBuffers / onRequestBatch): one descriptor
  // triple (reqId, methodIdx, pathIdx) per slot, the control cell the engine
  // advances as slots complete (Server::setBatchControl), and the path table
  // JS indexes with pathIdx (the interned strings of pathCache; a path the
  // cache will not hold is kNoPathIdx and JS asks getPath(reqId)). V8-owned
  // ArrayBuffers: their storage never moves, so the raw pointers below stay
  // valid for the server's lifetime.
  Global<ArrayBuffer> batchDesc;
  Global<ArrayBuffer> batchCtl;
  Global<Array> batchPaths;
  uint32_t* desc = nullptr;
  uint32_t* ctl = nullptr;
  std::unordered_map<std::string, uint32_t> pathIndex;
  static constexpr uint32_t kNoPathIdx = 0xFFFFFFFFu;
};

// thread_local, not process-global: worker_threads + reusePort (see
// HttpLimits::reusePort) runs one engine per thread, each with its own uv loop
// and servers, and a serverId only ever crosses the JS<->C++ boundary on the
// thread that created it - per-thread registries are race-free without locks.
static thread_local std::unordered_map<uint32_t, JsServer*> g_servers;
static thread_local uint32_t g_serverIdCounter = 0;

// Notification delivery mode (see Server::setDeferredNotify). Read once from
// MORO_ENGINE_NOTIFY in Initialize; process-wide because the environment is.
static bool g_notifyDeferred = true;
// Batched pipelined dispatch (Server::dispatchBatch); MORO_ENGINE_BATCH=0
// turns it off (diagnostics kill switch; requests are then surfaced one by
// one exactly as in 1.1).
static bool g_batchEnabled = true;
// Fast-call install state (see fast_api.h and Initialize).
static bool g_fastCompiled = MORO_FAST_API_ENABLED != 0;
static bool g_fastInstalled = false;
static const char* g_fastReason = "not-initialised";
static bool g_countCalls = false;  // MORO_ENGINE_FASTCALL_STATS=1
static int g_runtimeV8Major = 0;
static int g_runtimeV8Minor = 0;

static void cleanupJsServer(void* arg);

#if defined(__linux__)
// Registered once per thread when the first io_uring server is created. It
// is added BEFORE that server's own hook (hooks run in reverse order), so
// every server closes and reaps its cancel/close completions through the
// ring first; then the ring's poll/prepare handles and mappings go.
static void cleanupUringLoop(void*) { Server::UringLoop::shutdownForThread(); }
static thread_local bool g_uringHookRegistered = false;
#endif

// Invoked by Server once it is fully closed and self-deleted. Releases the
// per-server JS state (the Global<> destructors Reset the handles, unpinning
// the callbacks/context for GC) and drops the registry entry - no leak across
// serve()/close() cycles. Must NOT touch js->server (already deleted).
static void freeJsServer(void* user) {
  JsServer* js = static_cast<JsServer*>(user);
  // A normal close() no longer needs the teardown hook; removing a hook that
  // is currently running (the teardown path) is a no-op in Node.
  node::RemoveEnvironmentCleanupHook(js->isolate, cleanupJsServer, js);
  if (js->closedFlag) *js->closedFlag = true;
  g_servers.erase(js->id);
  delete js;
}

// Environment teardown with a server still open: a worker thread terminated
// (worker.terminate(), process.exit() inside the worker, an uncaught error)
// or the main environment exiting. Node closes its own handles and then
// CHECK-aborts the whole process if the loop still holds any - which an
// addon-owned listener/connection would be. So: close the server here and
// spin the loop until its last uv handle is reaped and freeJsServer ran.
// uv_run never blocks in that state (closing handles keep the poll timeout
// at zero). JS execution is forbidden by Node during cleanup, hence
// tearingDown suppresses every callback into JS (nothing to route them to).
static void cleanupJsServer(void* arg) {
  JsServer* js = static_cast<JsServer*>(arg);
  js->tearingDown = true;
  Server* srv = js->server;
  if (!srv) return;
  uv_loop_t* loop = srv->loop();
  bool closed = false;
  js->closedFlag = &closed;
  // No-op if JS already called close(): that close's completion still runs
  // freeJsServer, which flips the flag.
  srv->close(freeJsServer, js);
  while (!closed) uv_run(loop, UV_RUN_ONCE);
}

// Reverse lookup for binding functions that only hold a Connection (e.g.
// getHeaders): g_servers is tiny (one entry per serve() on this thread), so
// a scan beats storing a back-pointer on every connection.
static JsServer* jsServerFor(const Server* srv) {
  for (auto& [id, js] : g_servers)
    if (js->server == srv) return js;
  return nullptr;
}

// ---- helpers ----

// ToLocal with an empty-string fallback, not ToLocalChecked: NewFromUtf8
// fails only past V8's string-length cap (~512MB, reachable when an operator
// raises a size limit that far) or under allocation pressure - degrade to an
// empty string instead of aborting the whole Node process.
static Local<String> str(Isolate* iso, const std::string& s) {
  Local<String> out;
  // NewFromUtf8's length is an int. A string past INT_MAX (reachable only when
  // an operator raises a size limit past 2 GiB) would cast negative - V8 then
  // treats the data as NUL-terminated and over-reads - or, just past 2^32,
  // wrap to a small positive length (silent truncation). Guard before the
  // cast; degrade to an empty string, the same fallback as a NewFromUtf8 fail.
  if (s.size() > static_cast<size_t>(INT_MAX)) return String::Empty(iso);
  if (String::NewFromUtf8(iso, s.c_str(), v8::NewStringType::kNormal,
                          static_cast<int>(s.size()))
          .ToLocal(&out))
    return out;
  return String::Empty(iso);
}
static Local<String> str(Isolate* iso, const char* s) {
  Local<String> out;
  if (String::NewFromUtf8(iso, s).ToLocal(&out)) return out;
  return String::Empty(iso);
}

// Read a JS string's bytes into out IF it is a one-byte string whose content
// is pure ASCII (where Latin-1 == UTF-8, so the copy is exact). Returns false
// - leaving out untouched - when the caller must fall back to Utf8Value
// (two-byte strings, or Latin-1 bytes >= 0x80 that UTF-8 encodes as two
// bytes). Compared to Utf8Value this is malloc-free: it writes into the
// caller's reused buffer instead of a fresh heap block per call.
// Bounded by maxLen so a huge non-ASCII string can't pay a full wasted copy
// before the fallback.
static bool readAsciiOneByte(Isolate* iso, Local<String> str8,
                             std::string& out, size_t maxLen) {
  if (!str8->IsOneByte()) return false;
  const int len = str8->Length();
  if (len < 0 || static_cast<size_t>(len) > maxLen) return false;
  out.resize(static_cast<size_t>(len));
  // v8compat picks WriteOneByte / WriteOneByteV2 per ABI (the API changed
  // shape in V8 13.6 and the old spelling is gone in 14.6).
  v8compat::writeOneByte(iso, str8, reinterpret_cast<uint8_t*>(out.data()),
                         static_cast<uint32_t>(len));
  return text::isAscii(reinterpret_cast<const uint8_t*>(out.data()), out.size());
}

// Reused header-block buffer for Respond/WriteHead - the block was a fresh
// std::string per response (heap-allocating past SSO for even one header).
// buildHeaders can run arbitrary JS (array index getters / valueOf), which
// can re-enter respond(); nested calls get a plain local so the outer block
// is never clobbered. thread_local by the same ownership rules as the
// registries. Plain std::string, so thread-exit destruction never touches V8.
static thread_local std::string g_headerBlock;
static thread_local bool g_headerBlockInUse = false;
class HeaderBlockLease {
 public:
  HeaderBlockLease() {
    if (!g_headerBlockInUse) {
      g_headerBlockInUse = true;
      owned_ = true;
      g_headerBlock.clear();
      block_ = &g_headerBlock;
    } else {
      block_ = &local_;
    }
  }
  ~HeaderBlockLease() {
    if (owned_) g_headerBlockInUse = false;
  }
  std::string& get() { return *block_; }

 private:
  std::string* block_ = nullptr;
  std::string local_;
  bool owned_ = false;
};

// Same pattern for the two small buildHeaders scratch strings (name/value
// per pair). These never hold state across a JS call within one pair, but
// buildHeaders itself nests via getters - the lease keeps nesting correct.
static thread_local std::string g_hdrKeyScratch;
static thread_local std::string g_hdrValScratch;
static thread_local bool g_hdrScratchInUse = false;

// Borrowed, zero-copy view of a JS value's bytes (string | ArrayBuffer |
// TypedArray | DataView). A string's UTF-8 lives in the owned Utf8Value
// member; ArrayBuffer backing stores are external allocations whose data
// pointer is stable while no JS runs (nothing can detach the buffer under
// the borrow). valid() is false for null/undefined (no byte content).
// Safe to pass into Server::respond/write/end/wsSend: those copy the bytes
// into engine-owned buffers (Connection::scratch / corkBuf / the TLS
// ciphertext buffer / a queued WriteReq - see respond/appendResponse/
// writeOutView in server.h) before any JS re-entry, so the borrow never
// outlives this stack frame. The HTTP response entry points reach JS through
// exactly two doors, both shut while a borrow is alive: onAborted/onWritable
// are deferred to a later loop turn (Server::queueNotify), and the next
// pipelined request is never surfaced from inside a response call
// (canFinishSync in transportWrite/writeOutView refuses to finish a terminal
// write synchronously while a backlog exists; the loop's completeWrite does
// it). Verified by test/notify-deferred.test.mjs and the fast-api suite.
// Reused body-bytes buffer for ByteSource's string path (a malloc+free per
// response via String::Utf8Value otherwise). A ByteSource borrow never spans
// a JS call (each binding entry point builds headers FIRST, then the body,
// then hands both to the server synchronously), but the in-use flag makes
// nesting fall back to Utf8Value rather than assume that.
static thread_local std::string g_byteScratch;
static thread_local bool g_byteScratchInUse = false;

class ByteSource {
 public:
  // `borrow`: take the zero-copy String::ValueView path. A ValueView pins the
  // V8 heap (no allocation, hence no JS) for its lifetime, so it is legal
  // only on entry points whose engine call cannot reach JS: the HTTP
  // response functions under deferred notification. Sync notification mode
  // (MORO_ENGINE_NOTIFY=sync) delivers onAborted re-entrantly from inside
  // respond()/write(), and wsSend() sheds a stalled consumer through the
  // synchronous onWsClose - both must copy instead.
  ByteSource(Isolate* iso, Local<Value> v, bool borrow = g_notifyDeferred) {
    if (v->IsString()) {
      Local<String> s = v.As<String>();
#if MORO_V8_HAS_VALUE_VIEW
      if (!borrow) {
        // Copy path (see above): the same malloc-free ASCII fast copy the
        // pre-ValueView V8s use, else Utf8Value.
        if (!g_byteScratchInUse && readAsciiOneByte(iso, s, g_byteScratch, 65536)) {
          g_byteScratchInUse = true;
          usedScratch_ = true;
          data_ = g_byteScratch.data();
          size_ = g_byteScratch.size();
          valid_ = true;
          return;
        }
        utf8_.emplace(iso, v);
        if (**utf8_) {
          data_ = **utf8_;
          size_ = static_cast<size_t>(utf8_->length());
        }
        valid_ = true;
        return;
      }
      // Zero-copy: borrow the flat one-byte string's bytes straight out of
      // the V8 heap (String::ValueView flattens a cons string first). ASCII
      // is UTF-8 already, so the view IS the body - no copy at any size. The
      // pointer is valid only while no JS runs and no GC moves the string:
      // every binding entry point takes this borrow AFTER buildHeaders (the
      // one place that can run JS) and hands it to the engine, which copies
      // before returning. Latin-1 bytes >= 0x80 are UTF-8-encoded into the
      // scratch buffer - the exact bytes Utf8Value would produce.
      if (s->IsOneByte()) {
        view_.emplace(iso, s);
        if (view_->is_one_byte()) {
          const uint8_t* p = view_->data8();
          const size_t n = view_->length();
          if (text::isAscii(p, n)) {
            data_ = reinterpret_cast<const char*>(p);
            size_ = n;
            valid_ = true;
            return;
          }
          if (!g_byteScratchInUse) {
            g_byteScratchInUse = true;
            usedScratch_ = true;
            text::latin1ToUtf8(p, n, g_byteScratch);
            view_.reset();
            data_ = g_byteScratch.data();
            size_ = g_byteScratch.size();
            valid_ = true;
            return;
          }
        }
        view_.reset();
      }
#else
      // Node 20/22 (V8 < 12.9, no ValueView): malloc-free copy for ASCII
      // one-byte strings up to 64 KiB; larger or non-ASCII take Utf8Value.
      if (!g_byteScratchInUse && readAsciiOneByte(iso, s, g_byteScratch, 65536)) {
        g_byteScratchInUse = true;
        usedScratch_ = true;
        data_ = g_byteScratch.data();
        size_ = g_byteScratch.size();
        valid_ = true;
        return;
      }
#endif
      // Two-byte strings (and a nested borrow): String::Utf8Value, stable
      // across every supported V8.
      utf8_.emplace(iso, v);
      if (**utf8_) {
        data_ = **utf8_;
        size_ = static_cast<size_t>(utf8_->length());
      }
      valid_ = true;
      return;
    }
    if (v->IsArrayBuffer()) {
      Local<ArrayBuffer> ab = v.As<ArrayBuffer>();
      // ab->Data() rather than GetBackingStore()->Data(): the latter
      // materializes a std::shared_ptr<BackingStore> whose control block was
      // created inside the Node binary, and UBSan's cross-DSO vptr check
      // trips on its destruction.
      data_ = static_cast<const char*>(ab->Data());
      size_ = ab->ByteLength();
      valid_ = true;
      return;
    }
    if (v->IsTypedArray() || v->IsDataView()) {
      Local<v8::ArrayBufferView> view = v.As<v8::ArrayBufferView>();
      data_ = static_cast<const char*>(view->Buffer()->Data()) + view->ByteOffset();
      size_ = view->ByteLength();
      valid_ = true;
    }
  }
  ~ByteSource() {
    if (usedScratch_) {
      // Don't let one huge non-ASCII body pin its capacity for the thread's
      // lifetime (same 64 KiB watermark as the engine's own scratch buffers).
      if (g_byteScratch.capacity() > 65536) std::string().swap(g_byteScratch);
      g_byteScratchInUse = false;
    }
  }
  ByteSource(const ByteSource&) = delete;
  ByteSource& operator=(const ByteSource&) = delete;

  bool valid() const { return valid_; }
  // data() is null only when size() == 0 (null/undefined, an empty
  // ArrayBuffer, or a string whose UTF-8 conversion failed) - callers may
  // pass (data(), size()) through unconditionally.
  const char* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  std::optional<String::Utf8Value> utf8_;
#if MORO_V8_HAS_VALUE_VIEW
  std::optional<String::ValueView> view_;
#endif
  const char* data_ = nullptr;
  size_t size_ = 0;
  bool valid_ = false;
  bool usedScratch_ = false;
};

// Copy the bytes of a JS value (string | ArrayBuffer | TypedArray) into out.
// Returns false if the value carries no byte content (null/undefined).
// Config-path convenience (ssl key/cert/ca); the request/WS hot paths borrow
// via ByteSource instead of copying.
static bool extractBytes(Isolate* iso, Local<Context> ctx, Local<Value> v,
                         std::string& out) {
  (void)ctx;
  ByteSource src(iso, v);
  if (!src.valid()) return false;
  if (src.size()) out.assign(src.data(), src.size());
  else out.clear();
  return true;
}

// RFC 9110 §5.1 token characters, the only bytes legal in a field name.
static bool validHeaderName(const char* s, int n) {
  if (n <= 0) return false;
  for (int i = 0; i < n; ++i) {
    const unsigned char ch = static_cast<unsigned char>(s[i]);
    const bool alnum = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') ||
                       (ch >= 'A' && ch <= 'Z');
    // ch must be checked against 0 first: strchr matches the set string's
    // terminating NUL, so a bare !strchr would accept a 0x00 byte in a
    // field name.
    if (!alnum && (ch == 0 || !strchr("!#$%&'*+-.^_`|~", ch))) return false;
  }
  return true;
}

// RFC 9110 §5.5 field-value bytes: VCHAR / SP / HTAB / obs-text. CR, LF and
// other control bytes are rejected - they would let a value split the
// response (header injection), which Node's http core also blocks.
static bool validHeaderValue(const char* s, int n) {
  for (int i = 0; i < n; ++i) {
    const unsigned char ch = static_cast<unsigned char>(s[i]);
    if (ch == 0x7f || (ch < 0x20 && ch != '\t')) return false;
  }
  return true;
}

// Build a header block ("Name: Value\r\n"...) from a flat JS array
// [k0,v0,k1,v1,...]. Response-splitting defense: entries with an invalid
// field name or control bytes in the value are dropped rather than emitted.
// A content-length entry is never copied into the block - its (last valid)
// numeric value is returned via customCL (-1 when absent/unparseable) so the
// server owns response framing.
// Case-insensitive ASCII compare of a header name (len bytes) against a
// lowercase literal.
static bool headerNameIs(const char* k, int len, const char* lower) {
  if (static_cast<size_t>(len) != std::char_traits<char>::length(lower)) return false;
  for (int j = 0; j < len; ++j) {
    char c = k[j];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (c != lower[j]) return false;
  }
  return true;
}

static void buildHeaders(Isolate* iso, Local<Context> ctx, Local<Value> v,
                         std::string& block, long long& customCL) {
  customCL = -1;
  if (v.IsEmpty() || !v->IsArray()) return;
  Local<Array> arr = v.As<Array>();
  uint32_t n = arr->Length();
  // Scratch lease: the Get()s below can run JS (element getters), which can
  // re-enter respond() and therefore this function - nested calls get plain
  // locals so the outer pair is never clobbered.
  std::string localK, localV;
  const bool ownScratch = !g_hdrScratchInUse;
  if (ownScratch) g_hdrScratchInUse = true;
  std::string& kbuf = ownScratch ? g_hdrKeyScratch : localK;
  std::string& vbuf = ownScratch ? g_hdrValScratch : localV;
  for (uint32_t i = 0; i + 1 < n; i += 2) {
    Local<Value> kv, vv;
    if (!arr->Get(ctx, i).ToLocal(&kv)) continue;
    if (!arr->Get(ctx, i + 1).ToLocal(&vv)) continue;
    // Malloc-free one-byte read for plain-ASCII strings (the overwhelmingly
    // common case for header names and values); String::Utf8Value otherwise,
    // which also preserves ToString coercion for non-string values. `kd`/`vd`
    // stay valid across the (possible) JS run inside the value's coercion:
    // nested buildHeaders calls use locals per the lease above.
    const char* kd = nullptr;
    int kn = 0;
    std::optional<String::Utf8Value> kFall;
    if (kv->IsString() && readAsciiOneByte(iso, kv.As<String>(), kbuf, 4096)) {
      kd = kbuf.data();
      kn = static_cast<int>(kbuf.size());
    } else {
      kFall.emplace(iso, kv);
      kd = **kFall;  // may be nullptr - checked below, after the value
      kn = kFall->length();  // conversion, matching the original ordering
    }
    const char* vd = nullptr;
    int vn = 0;
    std::optional<String::Utf8Value> vFall;
    if (vv->IsString() && readAsciiOneByte(iso, vv.As<String>(), vbuf, 65536)) {
      vd = vbuf.data();
      vn = static_cast<int>(vbuf.size());
    } else {
      vFall.emplace(iso, vv);
      vd = **vFall;  // may be nullptr (failed conversion) - same as before
      vn = vFall->length();
    }
    if (kd == nullptr) continue;
    if (!validHeaderName(kd, kn)) continue;
    if (vd && !validHeaderValue(vd, vn)) continue;
    // Drop headers the engine owns or that are hop-by-hop: letting an app emit
    // Transfer-Encoding/Connection/Date/Keep-Alive would duplicate or conflict
    // with the framing the server writes itself (a Transfer-Encoding from the
    // app alongside the engine's Content-Length is a smuggling-grade ambiguity).
    if (headerNameIs(kd, kn, "transfer-encoding") ||
        headerNameIs(kd, kn, "connection") ||
        headerNameIs(kd, kn, "keep-alive") ||
        headerNameIs(kd, kn, "date")) {
      continue;
    }
    // Case-insensitive check for content-length
    if (kn == 14) {
      bool match = headerNameIs(kd, kn, "content-length");
      if (match) {
        // Parse strictly as decimal digits; anything else is ignored and the
        // server computes the length itself.
        long long parsed = 0;
        bool ok = vd != nullptr && vn > 0 && vn <= 18;
        for (int j = 0; ok && j < vn; ++j) {
          const char d = vd[j];
          if (d < '0' || d > '9') ok = false;
          else parsed = parsed * 10 + (d - '0');
        }
        if (ok) customCL = parsed;
        continue;  // never copied into the block
      }
    }
    block.append(kd, static_cast<size_t>(kn));
    block.append(": ");
    if (vd) block.append(vd, static_cast<size_t>(vn));
    block.append("\r\n");
  }
  if (ownScratch) g_hdrScratchInUse = false;
}

// ---- Server-side callbacks that trampoline into JS ----

static void reportCaught(Isolate* iso, TryCatch& tc, const char* where);

// Every trampoline into JS runs inside a Node callback scope - the scope Node
// itself opens around its own I/O callbacks. When the OUTERMOST scope closes,
// Node runs the process.nextTick queue and drains V8's microtask queue.
// Without it, a continuation the handler queued - an `await` on an already
// settled promise, a `.then` chain, a framework's async not-found path - sat
// in the queue until some later Node-managed callback ran, which on a quiet
// server is whatever timer fires next: seconds. Nested scopes (a WS open
// delivered from inside upgradeToWebSocket(), an onAborted delivered from
// inside close()) drain nothing themselves; the outermost one does. Cost per
// call: an async-context push/pop and, with an empty queue, one cheap check.
struct CallbackScopeFor {
  node::CallbackScope scope;
  CallbackScopeFor(JsServer* js, Isolate* iso)
      : scope(iso,
              js->asyncResource.IsEmpty() ? Object::New(iso) : js->asyncResource.Get(iso),
              node::async_context{0, 0}) {}
};

static void invokeJs(JsServer* js, Global<Function>& fn, uint32_t reqId,
                     bool withExtra, int32_t methodIdx, const std::string& path) {
  if (fn.IsEmpty() || js->tearingDown) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope ctxScope(ctx);
  CallbackScopeFor cb(js, iso);
  TryCatch tryCatch(iso);

  Local<Function> f = fn.Get(iso);
  if (withExtra) {
    // Serve the path from the interned cache when possible (see JsServer).
    Local<String> pathStr;
    if (path.size() <= JsServer::kPathCacheMaxLen) {
      auto it = js->pathCache.find(path);
      if (it != js->pathCache.end()) {
        pathStr = it->second.Get(iso);
      } else {
        pathStr = str(iso, path);
        if (js->pathCache.size() < JsServer::kPathCacheMaxEntries) {
          js->pathCache.emplace(path, Global<String>(iso, pathStr));
        }
      }
    } else {
      pathStr = str(iso, path);
    }
    Local<Value> argv[3] = {
        Integer::NewFromUnsigned(iso, reqId),
        Integer::New(iso, methodIdx),
        pathStr,
    };
    if (f->Call(ctx, ctx->Global(), 3, argv).IsEmpty()) { /* threw: reported below */ }
  } else {
    Local<Value> argv[1] = {Integer::NewFromUnsigned(iso, reqId)};
    if (f->Call(ctx, ctx->Global(), 1, argv).IsEmpty()) { /* threw: reported below */ }
  }
  // Swallow handler exceptions - one bad request must not tear down the loop.
  if (tryCatch.HasCaught()) {
    // Report to stderr for diagnostics.
    String::Utf8Value msg(iso, tryCatch.Exception());
    if (*msg) fprintf(stderr, "[morojs-engine] handler threw: %s\n", *msg);
  }
}

static void cbOnRequest(void* user, Connection* c) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  // (Static routes were already answered by Server::surfaceRequest.)
  invokeJs(js, js->onRequest, c->reqId, true, static_cast<int32_t>(c->method), c->path);
}

// The batch buffers, created on first need (getBatchBuffers() or the first
// batch) and handed to the engine as its control cell.
static void ensureBatchBuffers(JsServer* js, Isolate* iso, Local<Context> ctx) {
  if (js->desc) return;
  Local<ArrayBuffer> d = ArrayBuffer::New(iso, 3 * Server::kMaxStaged * sizeof(uint32_t));
  Local<ArrayBuffer> c = ArrayBuffer::New(iso, sizeof(uint32_t));
  Local<Array> paths = Array::New(iso, static_cast<int>(JsServer::kPathCacheMaxEntries));
  js->batchDesc.Reset(iso, d);
  js->batchCtl.Reset(iso, c);
  js->batchPaths.Reset(iso, paths);
  js->desc = static_cast<uint32_t*>(d->Data());
  js->ctl = static_cast<uint32_t*>(c->Data());
  std::memset(js->desc, 0, 3 * Server::kMaxStaged * sizeof(uint32_t));
  *js->ctl = 0;
  if (js->server) js->server->setBatchControl(js->ctl);
  (void)ctx;
}

// Index of `path` in the JS path table (interning it on first sight, under
// the same bounds as pathCache), or kNoPathIdx when it is not cacheable.
static uint32_t pathIndexFor(JsServer* js, Isolate* iso, Local<Context> ctx, const std::string& path) {
  if (path.size() > JsServer::kPathCacheMaxLen) return JsServer::kNoPathIdx;
  auto it = js->pathIndex.find(path);
  if (it != js->pathIndex.end()) return it->second;
  if (js->pathIndex.size() >= JsServer::kPathCacheMaxEntries) return JsServer::kNoPathIdx;
  const uint32_t idx = static_cast<uint32_t>(js->pathIndex.size());
  Local<String> pathStr;
  auto cached = js->pathCache.find(path);
  if (cached != js->pathCache.end()) {
    pathStr = cached->second.Get(iso);
  } else {
    pathStr = str(iso, path);
    if (js->pathCache.size() < JsServer::kPathCacheMaxEntries) js->pathCache.emplace(path, Global<String>(iso, pathStr));
  }
  (void)js->batchPaths.Get(iso)->Set(ctx, idx, pathStr).FromMaybe(false);
  js->pathIndex.emplace(path, idx);
  return idx;
}

// One JS call for a batch: slot 0 is the connection's active request, slots
// 1..count-1 its staged ring in order. JS returns after answering the slots
// it could answer synchronously (the engine tracks that itself through the
// control cell and c->active, so the return value is not load-bearing).
static void cbOnRequestBatch(void* user, Connection* c, uint32_t count) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown || js->onRequestBatch.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope ctxScope(ctx);
  CallbackScopeFor cb(js, iso);
  ensureBatchBuffers(js, iso, ctx);
  if (count > Server::kMaxStaged) count = Server::kMaxStaged;
  uint32_t* d = js->desc;
  d[0] = c->reqId;
  d[1] = static_cast<uint32_t>(c->method);
  d[2] = pathIndexFor(js, iso, ctx, c->path);
  for (uint32_t k = 1; k < count; k++) {
    const StagedRequest& sr = c->staged[(c->stagedHead + k - 1) % Server::kMaxStaged];
    d[3 * k] = sr.reqId;
    d[3 * k + 1] = static_cast<uint32_t>(sr.method);
    d[3 * k + 2] = pathIndexFor(js, iso, ctx, sr.path);
  }
  TryCatch tryCatch(iso);
  Local<Value> argv[1] = {Integer::NewFromUnsigned(iso, count)};
  if (js->onRequestBatch.Get(iso)->Call(ctx, ctx->Global(), 1, argv).IsEmpty()) { /* threw: reported below */ }
  reportCaught(iso, tryCatch, "onRequestBatch");
}
// Delivered from Server::drainNotifications (a uv_async callback, or
// synchronously from close()), by reqId: the Connection may be gone already.
static void cbOnAborted(void* user, uint32_t reqId) {
  JsServer* js = static_cast<JsServer*>(user);
  invokeJs(js, js->onAborted, reqId, false, 0, std::string());
}
static void cbOnWritable(void* user, uint32_t reqId) {
  JsServer* js = static_cast<JsServer*>(user);
  invokeJs(js, js->onWritable, reqId, false, 0, std::string());
}

// Log (never rethrow) an exception left by a JS callback, so a throwing WS
// handler is surfaced for diagnostics rather than silently swallowed.
static void reportCaught(Isolate* iso, TryCatch& tc, const char* where) {
  if (!tc.HasCaught()) return;
  String::Utf8Value msg(iso, tc.Exception());
  if (*msg) fprintf(stderr, "[morojs-engine] %s threw: %s\n", where, *msg);
}

static void cbOnWsOpen(void* user, Connection* c, const std::string& path) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  if (js->onWsOpen.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  CallbackScopeFor cb(js, iso);
  TryCatch tc(iso);
  Local<Value> argv[2] = {Integer::NewFromUnsigned(iso, c->wsId), str(iso, path)};
  if (js->onWsOpen.Get(iso)->Call(ctx, ctx->Global(), 2, argv).IsEmpty()) { /* threw: reported below */ }
  reportCaught(iso, tc, "onWsOpen");
}

static void cbOnWsMessage(void* user, Connection* c, const char* data,
                          size_t len, bool isBinary) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  if (js->onWsMessage.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  CallbackScopeFor cb(js, iso);
  TryCatch tc(iso);
  // Binary -> ArrayBuffer, text -> string (already UTF-8 validated natively)
  Local<Value> payload;
  if (isBinary) {
    Local<ArrayBuffer> ab = ArrayBuffer::New(iso, len);
    if (len) memcpy(ab->Data(), data, len);
    payload = ab;
  } else {
    Local<String> text;
    // The len > INT_MAX check runs BEFORE the cast: a length past 2 GiB would
    // cast negative (V8 reads `data` as NUL-terminated and over-reads) or, just
    // past 2^32, wrap to a small positive length (silent truncation). Either
    // way it must never reach NewFromUtf8; take the drop-and-log path instead.
    if (len > static_cast<size_t>(INT_MAX) ||
        !String::NewFromUtf8(iso, data, v8::NewStringType::kNormal,
                             static_cast<int>(len))
             .ToLocal(&text)) {
      // Payload exceeds V8's string cap (an operator raised wsMaxMessageSize
      // past ~512MB) or allocation failed: drop the message rather than
      // abort the process (ToLocalChecked) or deliver a truncated lie.
      fprintf(stderr,
              "[morojs-engine] dropping %zu-byte text message: exceeds V8 "
              "string limits\n",
              len);
      return;
    }
    payload = text;
  }
  Local<Value> argv[3] = {Integer::NewFromUnsigned(iso, c->wsId), payload,
                          v8::Boolean::New(iso, isBinary)};
  if (js->onWsMessage.Get(iso)->Call(ctx, ctx->Global(), 3, argv).IsEmpty()) { /* threw: reported below */ }
  reportCaught(iso, tc, "onWsMessage");
}

static void cbOnWsClose(void* user, Connection* c, int code) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  if (js->onWsClose.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  CallbackScopeFor cb(js, iso);
  TryCatch tc(iso);
  Local<Value> argv[2] = {Integer::NewFromUnsigned(iso, c->wsId),
                          Integer::New(iso, code)};
  if (js->onWsClose.Get(iso)->Call(ctx, ctx->Global(), 2, argv).IsEmpty()) { /* threw: reported below */ }
  reportCaught(iso, tc, "onWsClose");
}

// ---- JS-exposed functions ----

// serve(callbacks, options?) -> serverId
static void Serve(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();

  if (args.Length() < 1 || !args[0]->IsObject()) {
    iso->ThrowException(str(iso, "serve(callbacks) requires a callbacks object"));
    return;
  }
  Local<Object> cbs = args[0].As<Object>();

  JsServer* js = new JsServer();
  js->isolate = iso;
  js->context.Reset(iso, ctx);
  js->asyncResource.Reset(iso, Object::New(iso));

  auto grab = [&](const char* name, Global<Function>& out) {
    Local<Value> v;
    if (cbs->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsFunction())
      out.Reset(iso, v.As<Function>());
  };
  grab("onRequest", js->onRequest);
  grab("onRequestBatch", js->onRequestBatch);
  grab("onAborted", js->onAborted);
  grab("onWritable", js->onWritable);
  grab("onWsOpen", js->onWsOpen);
  grab("onWsMessage", js->onWsMessage);
  grab("onWsClose", js->onWsClose);

  HttpLimits limits;
  if (args.Length() >= 2 && args[1]->IsObject()) {
    Local<Object> opts = args[1].As<Object>();
    // Numeric option -> size_t field. minValue guards fields where 0 (or a
    // negative after coercion) would be nonsense rather than a policy - e.g.
    // maxHeadSize 0 would 431 every request, writeHighWaterMark 0 would
    // report every write as backpressured. kMaxLimit is a defensive upper
    // clamp (2^48 ≈ 256 TiB, far past any real configuration): a double above
    // 2^64 is UNDEFINED to cast to size_t, and even representable huge values
    // would overflow limit sums like maxHeadSize + maxBodySize (server.h) or
    // body.size() + chunkRemaining_ (http_parser.h). NaN fails d >= minValue
    // and is ignored like any other non-value.
    constexpr double kMaxLimit = 281474976710656.0;  // 2^48
    auto getNum = [&](const char* name, size_t& out, double minValue) {
      Local<Value> v;
      if (opts->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsNumber()) {
        double d = v->NumberValue(ctx).FromMaybe(-1);
        if (d > kMaxLimit) d = kMaxLimit;
        if (d >= minValue) out = static_cast<size_t>(d);
      }
    };
    getNum("maxBodySize", limits.maxBodySize, 0);
    getNum("maxHeadSize", limits.maxHeadSize, 1);
    getNum("maxHeaders", limits.maxHeaders, 1);
    getNum("maxUriSize", limits.maxUriSize, 0);
    getNum("idleTimeoutMs", limits.idleTimeoutMs, 0);
    getNum("requestTimeoutMs", limits.requestTimeoutMs, 0);
    getNum("responseTimeoutMs", limits.responseTimeoutMs, 0);
    getNum("responseBackpressureLimit", limits.responseBackpressureLimit, 0);
    getNum("maxConnections", limits.maxConnections, 0);
    getNum("maxPendingBytes", limits.maxPendingBytes, 0);
    getNum("wsMaxMessageSize", limits.wsMaxMessageSize, 1);
    getNum("wsBackpressureLimit", limits.wsBackpressureLimit, 0);
    getNum("writeHighWaterMark", limits.writeHighWaterMark, 1);
    Local<Value> bl;
    if (opts->Get(ctx, str(iso, "backlog")).ToLocal(&bl) && bl->IsNumber()) {
      int v = bl->Int32Value(ctx).FromMaybe(0);
      if (v > 0) limits.backlog = v;
    }
    Local<Value> rp;
    if (opts->Get(ctx, str(iso, "reusePort")).ToLocal(&rp) && rp->IsBoolean()) {
      limits.reusePort = rp->BooleanValue(iso);
    }

    // options.wsDeflate: boolean (enable with defaults) or an options object.
    Local<Value> wd;
    if (opts->Get(ctx, str(iso, "wsDeflate")).ToLocal(&wd)) {
      if (wd->IsBoolean()) {
        limits.wsDeflate.enabled = wd->BooleanValue(iso);
      } else if (wd->IsObject()) {
        limits.wsDeflate.enabled = true;
        Local<Object> wo = wd.As<Object>();
        auto getBoolW = [&](const char* name, bool& out) {
          Local<Value> v;
          if (wo->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsBoolean())
            out = v->BooleanValue(iso);
        };
        auto getIntW = [&](const char* name, int& out) {
          Local<Value> v;
          if (wo->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsNumber())
            out = static_cast<int>(v->Int32Value(ctx).FromMaybe(out));
        };
        auto getSizeW = [&](const char* name, size_t& out) {
          Local<Value> v;
          if (wo->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsNumber()) {
            double d = v->NumberValue(ctx).FromMaybe(-1);
            if (d > kMaxLimit) d = kMaxLimit;  // same UB/overflow clamp as getNum
            if (d >= 0) out = static_cast<size_t>(d);
          }
        };
        getBoolW("serverNoContextTakeover", limits.wsDeflate.serverNoContextTakeover);
        getBoolW("clientNoContextTakeover", limits.wsDeflate.clientNoContextTakeover);
        getIntW("serverMaxWindowBits", limits.wsDeflate.serverMaxWindowBits);
        getIntW("clientMaxWindowBits", limits.wsDeflate.clientMaxWindowBits);
        getSizeW("threshold", limits.wsDeflate.threshold);
        getSizeW("maxDecompressedSize", limits.wsDeflate.maxDecompressedSize);
        getBoolW("sharedCompressor", limits.wsDeflate.sharedCompressor);
      }
    }
  }

  // options.ssl -> in-process TLS termination. Both MoroJS shapes are accepted: file paths (key_file_name/cert_file_name/ca_file_name) and inline PEM (key/cert/ca as string|Buffer|ArrayBuffer); inline wins when both are present. Config errors THROW from serve() - a misconfigured TLS server must never silently boot as plaintext.
  SslConfig ssl;
  bool sslRequested = false;
  if (args.Length() >= 2 && args[1]->IsObject()) {
    Local<Object> opts = args[1].As<Object>();
    Local<Value> sslVal;
    if (opts->Get(ctx, str(iso, "ssl")).ToLocal(&sslVal) && sslVal->IsObject()) {
      sslRequested = true;
      Local<Object> so = sslVal.As<Object>();
      auto getStr = [&](const char* name, std::string& out) {
        Local<Value> v;
        if (so->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsString()) {
          String::Utf8Value s(iso, v);
          if (*s) out.assign(*s, s.length());
        }
      };
      auto getBytes = [&](const char* name, std::string& out) {
        Local<Value> v;
        if (so->Get(ctx, str(iso, name)).ToLocal(&v) && !v->IsNullOrUndefined()) {
          extractBytes(iso, ctx, v, out);
        }
      };
      auto getBool = [&](const char* name, bool& out) {
        Local<Value> v;
        if (so->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsBoolean()) {
          out = v->BooleanValue(iso);
        }
      };
      getStr("key_file_name", ssl.keyFile);
      getStr("cert_file_name", ssl.certFile);
      getStr("ca_file_name", ssl.caFile);
      getBytes("key", ssl.keyPem);
      getBytes("cert", ssl.certPem);
      getBytes("ca", ssl.caPem);
      getBytes("ticketKeys", ssl.ticketKeys);
      if (!ssl.ticketKeys.empty() && ssl.ticketKeys.size() != 48) {
        iso->ThrowException(v8::Exception::Error(str(
            iso, "ssl.ticketKeys must be exactly 48 bytes (see Node's tls.Server ticketKeys)")));
        delete js;
        return;
      }
      getStr("passphrase", ssl.passphrase);
      // Optional cipher/group policy (compliance profiles); validated in
      // TlsContext::init, config errors throw from serve().
      getStr("ciphers", ssl.ciphers);
      getStr("ciphersuites", ssl.ciphersuites);
      getStr("ecdhCurve", ssl.ecdhCurve);
      std::string minVer;
      getStr("minVersion", minVer);
      if (minVer == "TLSv1.3") ssl.minVersion = TLS1_3_VERSION;
      // (default TLS1_2_VERSION; anything else is rejected below)
      if (!minVer.empty() && minVer != "TLSv1.2" && minVer != "TLSv1.3") {
        iso->ThrowException(v8::Exception::Error(
            str(iso, "ssl.minVersion must be 'TLSv1.2' or 'TLSv1.3'")));
        delete js;
        return;
      }
      getBool("requestCert", ssl.requestCert);
      getBool("rejectUnauthorized", ssl.rejectUnauthorized);
    }
  }

  // Validate the TLS material BEFORE constructing the Server, so a config error throws cleanly with nothing to tear down.
  TlsContext tlsCtx;
  if (sslRequested) {
    if (!ssl.complete()) {
      iso->ThrowException(v8::Exception::Error(str(iso,
          "ssl requires both a key (key or key_file_name) and a certificate "
          "(cert or cert_file_name)")));
      delete js;
      return;
    }
    std::string err = tlsCtx.init(ssl);
    if (!err.empty()) {
      iso->ThrowException(v8::Exception::Error(str(iso, ("ssl: " + err).c_str())));
      delete js;
      return;
    }
  }

  uv_loop_t* loop = node::GetCurrentEventLoop(iso);
  ServerCallbacks scb;
  scb.user = js;
  scb.onRequest = cbOnRequest;
  if (g_batchEnabled && !js->onRequestBatch.IsEmpty()) scb.onRequestBatch = cbOnRequestBatch;
  scb.onAborted = cbOnAborted;
  scb.onWritable = cbOnWritable;

  scb.onWsOpen = cbOnWsOpen;
  scb.onWsMessage = cbOnWsMessage;
  scb.onWsClose = cbOnWsClose;

  js->server = new Server(loop, scb, limits);
  js->server->setDeferredNotify(g_notifyDeferred);
  js->server->setBatchDispatch(g_batchEnabled);
#if defined(__linux__)
  if (js->server->transportKind() == TransportKind::Uring && !g_uringHookRegistered) {
    g_uringHookRegistered = true;
    node::AddEnvironmentCleanupHook(iso, cleanupUringLoop, nullptr);
  }
#endif
  if (tlsCtx.valid()) js->server->adoptTls(std::move(tlsCtx));
  uint32_t id = ++g_serverIdCounter;
  js->id = id;
  g_servers[id] = js;
  // Removed again in freeJsServer when JS closes the server itself.
  node::AddEnvironmentCleanupHook(iso, cleanupJsServer, js);
  args.GetReturnValue().Set(Integer::NewFromUnsigned(iso, id));
}

static JsServer* serverFrom(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  uint32_t id = args[0]->Uint32Value(iso->GetCurrentContext()).FromMaybe(0);
  auto it = g_servers.find(id);
  return it == g_servers.end() ? nullptr : it->second;
}

// listen(serverId, host, port) -> actual bound port (throws on failure)
static void Listen(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  JsServer* js = serverFrom(args);
  if (!js) { iso->ThrowException(str(iso, "invalid serverId")); return; }

  String::Utf8Value host(iso, args[1]);
  int port = args[2]->Int32Value(ctx).FromMaybe(0);
  int uvErr = 0;
  int bound = js->server->listen(*host ? *host : "0.0.0.0", port, &uvErr);
  if (bound == 0) {
    // Throw a real Error carrying a libuv-style .code (e.g. 'EADDRINUSE') and
    // .errno, so callers can `catch (e) { if (e.code === 'EADDRINUSE') ... }`
    // exactly as they would with Node's net server.
    const char* name = uvErr ? uv_err_name(uvErr) : "UNKNOWN";
    std::string msg = std::string("listen ") + name + " " +
                      (*host ? *host : "0.0.0.0") + ":" + std::to_string(port) +
                      " (" + (uvErr ? uv_strerror(uvErr) : "bind/listen failed") + ")";
    Local<Value> err = v8::Exception::Error(str(iso, msg));
    Local<Object> errObj = err.As<Object>();
    // FromMaybe, not Check: attaching diagnostic properties must never abort
    // the process (Check() hard-aborts if the Set fails, e.g. under
    // allocation pressure); the Error is thrown either way.
    (void)errObj->Set(ctx, str(iso, "code"), str(iso, name)).FromMaybe(false);
    (void)errObj->Set(ctx, str(iso, "errno"), Integer::New(iso, uvErr)).FromMaybe(false);
    iso->ThrowException(err);
    return;
  }
  args.GetReturnValue().Set(Integer::New(iso, bound));
}

// close(serverId)
static void Close(const FunctionCallbackInfo<Value>& args) {
  JsServer* js = serverFrom(args);
  // close() is idempotent and, once every uv handle is reaped, deletes the Server and invokes freeJsServer(js) to release this server's JS state.
  if (js && js->server) js->server->close(freeJsServer, js);
}

// stopListening(serverId) - stop accepting new connections while in-flight
// requests keep being served (graceful-shutdown drain phase; close() follows).
static void StopListening(const FunctionCallbackInfo<Value>& args) {
  JsServer* js = serverFrom(args);
  if (js && js->server) js->server->stopListening();
}

// ---- per-request data accessors (reqId is arg 0) ----

static Connection* connFrom(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  uint32_t reqId = args[0]->Uint32Value(iso->GetCurrentContext()).FromMaybe(0);
  return Server::lookup(reqId);
}

static void GetMethod(const FunctionCallbackInfo<Value>& args) {
  Connection* c = connFrom(args);
  if (!c) return;
  // methodStr is only populated for Method::OTHER (see parseRequestLine);
  // known methods answer from the canonical table, indexed by the Method
  // enum (keep in sync with it).
  static const char* const kMethodNames[] = {"GET",   "POST", "PUT",
                                             "DELETE", "PATCH", "HEAD",
                                             "OPTIONS"};
  if (c->method == Method::OTHER) {
    args.GetReturnValue().Set(str(args.GetIsolate(), c->methodStr));
  } else {
    args.GetReturnValue().Set(str(
        args.GetIsolate(), kMethodNames[static_cast<uint8_t>(c->method)]));
  }
}

static void GetQuery(const FunctionCallbackInfo<Value>& args) {
  Connection* c = connFrom(args);
  args.GetReturnValue().Set(str(args.GetIsolate(), c ? c->query : std::string()));
}

static void GetHeaders(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) { args.GetReturnValue().Set(Array::New(iso, 0)); return; }
  // Array::New's length is an int and is only a capacity hint (Set() below
  // grows the array by index regardless). Clamp the hint so headers.size()*2
  // can't cast negative if a config raised maxHeaders past 2 GiB.
  size_t hint = c->headers.size() * 2;
  if (hint > static_cast<size_t>(INT_MAX)) hint = static_cast<size_t>(INT_MAX);
  Local<Array> arr = Array::New(iso, static_cast<int>(hint));
  JsServer* js = jsServerFor(c->server);
  uint32_t idx = 0;
  for (const auto& h : c->headers) {
    // Names come from a small bounded set in practice - serve them from the
    // per-server interning cache (same pattern and lifetime as pathCache).
    Local<String> nameStr;
    if (js && h.name.size() <= JsServer::kHeaderNameCacheMaxLen) {
      auto it = js->headerNameCache.find(h.name);
      if (it != js->headerNameCache.end()) {
        nameStr = it->second.Get(iso);
      } else {
        nameStr = str(iso, h.name);
        if (js->headerNameCache.size() < JsServer::kHeaderNameCacheMaxEntries) {
          js->headerNameCache.emplace(h.name, Global<String>(iso, nameStr));
        }
      }
    } else {
      nameStr = str(iso, h.name);
    }
    // FromMaybe, not Check: a failed Set under allocation pressure yields a
    // hole in the array instead of aborting the whole Node process.
    (void)arr->Set(ctx, idx++, nameStr).FromMaybe(false);
    (void)arr->Set(ctx, idx++, str(iso, h.value)).FromMaybe(false);
  }
  args.GetReturnValue().Set(arr);
}

static void GetHeader(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c || args.Length() < 2) return;
  String::Utf8Value name(iso, args[1]);
  if (*name == nullptr) return;
  // The snapshot (c->headers) is the source of truth; the parser has already moved its fields out and may have been reset for the next request.
  for (const auto& h : c->headers) {
    if (h.name.size() == static_cast<size_t>(name.length()) &&
        iequals(h.name, std::string_view(*name, name.length()))) {
      args.GetReturnValue().Set(str(iso, h.value));
      return;
    }
  }
}

static void GetBody(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c || c->body.empty()) {
    args.GetReturnValue().SetNull();
    return;
  }
  Local<ArrayBuffer> ab = ArrayBuffer::New(iso, c->body.size());
  memcpy(ab->Data(), c->body.data(), c->body.size());
  args.GetReturnValue().Set(ab);
}

static void GetRemoteAddress(const FunctionCallbackInfo<Value>& args) {
  Connection* c = connFrom(args);
  if (!c) return;
  args.GetReturnValue().Set(str(args.GetIsolate(), c->server->remoteAddress(c)));
}

static void IsAborted(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kIsAborted];
  Connection* c = connFrom(args);
  args.GetReturnValue().Set(c == nullptr);  // gone from registry == aborted/ended
}

// respond(reqId, status, headersFlat|null, body|null)
static void Respond(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) return;
  int status = args[1]->Int32Value(ctx).FromMaybe(200);
  HeaderBlockLease headersLease;
  std::string& headers = headersLease.get();
  long long customCL = -1;
  buildHeaders(iso, ctx, args[2], headers, customCL);
  // The body borrow is taken AFTER buildHeaders: buildHeaders can run
  // arbitrary JS (array getters / valueOf), which could detach an ArrayBuffer
  // out from under an earlier borrow. Both stay on this stack through the
  // respond() call.
  ByteSource body(iso, args[3]);
  c->server->respond(c, status, headers, customCL, body.data(), body.size());
}

// writeHead(reqId, status, headersFlat|null)
static void WriteHead(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) return;
  int status = args[1]->Int32Value(ctx).FromMaybe(200);
  HeaderBlockLease headersLease;
  std::string& headers = headersLease.get();
  long long customCL = -1;
  buildHeaders(iso, ctx, args[2], headers, customCL);
  c->server->writeHead(c, status, headers, customCL);
}

// write(reqId, chunk) -> boolean backpressure
static void Write(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kWrite];
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) { args.GetReturnValue().Set(false); return; }
  ByteSource chunk(iso, args[1]);
  bool ok = true;
  if (chunk.valid()) ok = c->server->write(c, chunk.data(), chunk.size());
  args.GetReturnValue().Set(ok);
}

// end(reqId, chunk?)
static void End(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kEnd];
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) return;
  // A missing/null/undefined chunk borrows nothing: end(nullptr, 0).
  ByteSource chunk(iso, args[1]);
  c->server->end(c, chunk.data(), chunk.size());
}

// setStaticRoute(serverId, methodIdx, path, status, headersFlat|null, body|null)
//
// Registers a fixed response for one (method, path). The header block and body
// are materialised HERE, once, using the same buildHeaders() the JS respond()
// path uses - so a static route emits a byte-identical response, just without
// the JS round trip. Re-registering the same (method, path) replaces it.
static void SetStaticRoute(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  JsServer* js = serverFrom(args);
  if (!js || !js->server) return;
  if (args.Length() < 3 || !args[2]->IsString()) {
    iso->ThrowException(
        str(iso, "setStaticRoute(serverId, method, path, status, headers, body)"));
    return;
  }

  const int32_t method = args[1]->Int32Value(ctx).FromMaybe(0);
  ResponseTemplate tpl;
  tpl.status = args.Length() > 3 ? args[3]->Int32Value(ctx).FromMaybe(200) : 200;

  String::Utf8Value pathV(iso, args[2]);
  if (!*pathV) return;
  std::string path(*pathV, static_cast<size_t>(pathV.length()));

  // buildHeaders can run arbitrary JS (element getters). Take the body borrow
  // after it, for the same reason Respond() does.
  buildHeaders(iso, ctx, args.Length() > 4 ? args[4] : Local<Value>(), tpl.headers,
               tpl.customCL);
  std::string bodyBytes;
  if (args.Length() > 5) {
    ByteSource body(iso, args[5]);
    if (body.valid() && body.size()) bodyBytes.assign(body.data(), body.size());
  }
  js->server->setStaticRoute(method, std::move(path), std::move(tpl), std::move(bodyBytes));
}

// clearStaticRoutes(serverId) - drops every static route on this server.
static void ClearStaticRoutes(const FunctionCallbackInfo<Value>& args) {
  JsServer* js = serverFrom(args);
  if (js && js->server) js->server->clearStaticRoutes();
}

// ---- prepared response templates ----

// prepareResponse(serverId, status, headersFlat|null) -> tplId (>= 1)
//
// Materialises status + header block ONCE (same buildHeaders as respond(), so
// the wire bytes are identical); respondPrepared() replays it per request with
// a body and skips the per-request header walk. Ids are per server. Throws a
// RangeError when the store is full (TemplateStore::kMax) - registration is a
// setup-time act, so a full store is a caller bug, not a runtime condition.
static void PrepareResponse(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  JsServer* js = serverFrom(args);
  if (!js || !js->server) {
    iso->ThrowException(str(iso, "invalid serverId"));
    return;
  }
  ResponseTemplate tpl;
  tpl.status = args.Length() > 1 ? args[1]->Int32Value(ctx).FromMaybe(200) : 200;
  buildHeaders(iso, ctx, args.Length() > 2 ? args[2] : Local<Value>(), tpl.headers,
               tpl.customCL);
  const uint32_t id = js->server->prepareTemplate(std::move(tpl));
  if (id == 0) {
    iso->ThrowException(v8::Exception::RangeError(
        str(iso, "prepareResponse: template store is full (4096 per server); "
                 "releaseTemplates() or reuse ids")));
    return;
  }
  args.GetReturnValue().Set(Integer::NewFromUnsigned(iso, id));
}

// releaseTemplates(serverId) - invalidates every template id on this server.
static void ReleaseTemplates(const FunctionCallbackInfo<Value>& args) {
  JsServer* js = serverFrom(args);
  if (js && js->server) js->server->releaseTemplates();
}

// respondPrepared(reqId, tplId, body|null) - respond() with a template.
// An invalid tplId answers 500 (see Server::respondTemplate).
static void RespondPrepared(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kRespondPrepared];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) return;
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  ByteSource body(iso, args[2]);
  c->server->respondTemplate(c, tplId, body.data(), body.size());
}

// respondPreparedEmpty(reqId, tplId) - respond() with a template and no body.
static void RespondPreparedEmpty(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kRespondPreparedEmpty];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) return;
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  c->server->respondTemplate(c, tplId, nullptr, 0);
}

// writeHeadPrepared(reqId, tplId) - writeHead() with a template (streaming).
static void WriteHeadPrepared(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kWriteHeadPrepared];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) return;
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  c->server->writeHeadTemplate(c, tplId);
}

// endWith(reqId, chunk) - exactly end(reqId, chunk), as a fixed-arity twin so
// a call site that always passes a chunk has one shape (fast-call eligible).
static void EndWith(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::g_slowHits[fastcall::kEndWith];
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) return;
  ByteSource chunk(iso, args[1]);
  c->server->end(c, chunk.data(), chunk.size());
}

// ---- WebSocket (RFC 6455) ----

// upgradeToWebSocket(reqId) -> wsId | -1
static void UpgradeToWebSocket(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) { args.GetReturnValue().Set(Integer::New(iso, -1)); return; }
  uint32_t wsId = c->server->upgradeToWebSocket(c);
  if (wsId == 0) { args.GetReturnValue().Set(Integer::New(iso, -1)); return; }
  args.GetReturnValue().Set(Integer::NewFromUnsigned(iso, wsId));
}

static Connection* wsFrom(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  uint32_t wsId = args[0]->Uint32Value(iso->GetCurrentContext()).FromMaybe(0);
  return Server::lookupWs(wsId);
}

// wsSend(wsId, data, isBinary) -> boolean backpressure
static void WsSend(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = wsFrom(args);
  if (!c) { args.GetReturnValue().Set(false); return; }
  bool isBinary = args.Length() >= 3 && args[2]->BooleanValue(iso);
  // Never a borrow: wsSend() can shed the peer (wsBackpressureLimit) through
  // the synchronous onWsClose callback while `data` is alive.
  ByteSource data(iso, args[1], /*borrow=*/false);
  bool ok = true;
  if (data.valid()) ok = c->server->wsSend(c, data.data(), data.size(), isBinary);
  args.GetReturnValue().Set(ok);
}

// wsClose(wsId, code?, reason?)
static void WsClose(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = wsFrom(args);
  if (!c) return;
  uint16_t code = 1000;  // normal closure (§7.4.1)
  if (args.Length() >= 2 && args[1]->IsNumber())
    code = static_cast<uint16_t>(args[1]->Int32Value(ctx).FromMaybe(1000));
  std::string reason;
  if (args.Length() >= 3 && args[2]->IsString()) {
    String::Utf8Value r(iso, args[2]);
    if (*r) reason.assign(*r, r.length());
  }
  c->server->wsClose(c, code, reason.data(), reason.size());
}

// getBatchBuffers(serverId) -> { descriptors: Uint32Array(3*16), control:
// Uint32Array(1), paths: string[] } - the same objects every call.
static void GetBatchBuffers(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  uint32_t id = args[0]->Uint32Value(ctx).FromMaybe(0);
  auto it = g_servers.find(id);
  if (it == g_servers.end()) {
    iso->ThrowException(v8::Exception::RangeError(str(iso, "getBatchBuffers: unknown serverId")));
    return;
  }
  JsServer* js = it->second;
  ensureBatchBuffers(js, iso, ctx);
  Local<Object> out = Object::New(iso);
  (void)out->Set(ctx, str(iso, "descriptors"),
                 v8::Uint32Array::New(js->batchDesc.Get(iso), 0, 3 * Server::kMaxStaged)).FromMaybe(false);
  (void)out->Set(ctx, str(iso, "control"), v8::Uint32Array::New(js->batchCtl.Get(iso), 0, 1)).FromMaybe(false);
  (void)out->Set(ctx, str(iso, "paths"), js->batchPaths.Get(iso)).FromMaybe(false);
  args.GetReturnValue().Set(out);
}

// getPath(reqId) -> the active request's path (for a batch descriptor whose
// pathIdx is 0xFFFFFFFF: the path was not cacheable).
static void GetPath(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) {
    args.GetReturnValue().Set(str(iso, ""));
    return;
  }
  args.GetReturnValue().Set(str(iso, c->path));
}

// ---- diagnostics ----

static void Probe(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Local<Object> result = Object::New(iso);
  auto set = [&](const char* k, Local<Value> v) {
    (void)result->Set(ctx, str(iso, k), v).FromMaybe(false);
  };
  set("ok", v8::Boolean::New(iso, true));
  set("version", str(iso, kEngineVersion));
  set("abi", Integer::New(iso, NODE_MODULE_VERSION));
#if defined(__APPLE__)
  set("platform", str(iso, "darwin"));
#elif defined(_WIN32)
  set("platform", str(iso, "win32"));
#else
  set("platform", str(iso, "linux"));
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
  set("arch", str(iso, "arm64"));
#else
  set("arch", str(iso, "x64"));
#endif
  // Feature flags for consumers (MoroJS) to gate option passing on, instead of version-sniffing. Flip as each capability ships: tls (M3/E2), http2 (E4), wsDeflate (E5). "limits" = the full serve() limit surface (maxHeadSize/maxHeaders/ws*/writeHighWaterMark/backlog) is parsed.
  Local<Object> caps = Object::New(iso);
  auto setCap = [&](const char* k, bool v) {
    (void)caps->Set(ctx, str(iso, k), v8::Boolean::New(iso, v)).FromMaybe(false);
  };
  setCap("limits", true);
  setCap("tls", true);
  setCap("http2", false);
  setCap("wsDeflate", true);
  // Hardening surface: responseTimeoutMs / responseBackpressureLimit /
  // maxUriSize serve options are parsed.
  setCap("responseLimits", true);
  // ssl.ciphers / ssl.ciphersuites / ssl.ecdhCurve are parsed.
  setCap("tlsPolicy", true);
  // setStaticRoute()/clearStaticRoutes() are available.
  setCap("staticRoutes", true);
  // prepareResponse()/releaseTemplates()/respondPrepared()/
  // respondPreparedEmpty()/writeHeadPrepared()/endWith() are available.
  setCap("responseTemplates", true);
  // Every callback into JS runs inside a Node callback scope, so nextTicks
  // and microtasks queued during dispatch run when the callback returns
  // (an adapter needs no setImmediate-based drain of its own).
  setCap("callbackScope", true);
  // onAborted/onWritable are delivered on a later loop turn (never
  // re-entrantly from inside respond/write/end); false under
  // MORO_ENGINE_NOTIFY=sync.
  setCap("asyncNotify", g_notifyDeferred);
  // A server left open when its environment is torn down (worker.terminate(),
  // process.exit() inside a worker thread) is closed by a cleanup hook, so the
  // engine is safe to run inside worker_threads.
  setCap("workerThreads", true);
  // V8 fast API calls installed on the hot entry points (respondPrepared,
  // respondPreparedEmpty, writeHeadPrepared, write, end, endWith, isAborted).
  setCap("fastCalls", g_fastInstalled);
  // Batched pipelined dispatch: getBatchBuffers()/getPath() and the
  // onRequestBatch callback (Server::dispatchBatch).
  setCap("batchDispatch", g_batchEnabled);
  set("capabilities", caps);
  set("notify", str(iso, g_notifyDeferred ? "deferred" : "sync"));
  // I/O transport in use on this host: 'uring' (Linux, io_uring usable) or
  // 'uv' (libuv streams), with the reason when it is not uring.
  set("transport", str(iso, Server::transportName(Server::preferredTransport())));
  set("transportReason", str(iso, Server::transportReason()));
  // "uv", or the io_uring ring mode: "defer-taskrun" (task work batched
  // inside our own enter, woken through a registered eventfd) or
  // "coop-taskrun" (the 1.1.6 mode). MORO_ENGINE_URING_TASKRUN pins one.
  set("transportMode", str(iso, Server::transportModeName()));
  {
    Local<Object> fa = Object::New(iso);
    auto setFa = [&](const char* k, Local<Value> v) {
      (void)fa->Set(ctx, str(iso, k), v).FromMaybe(false);
    };
    setFa("compiled", v8::Boolean::New(iso, g_fastCompiled));
    setFa("installed", v8::Boolean::New(iso, g_fastInstalled));
    setFa("reason", str(iso, g_fastReason));
    setFa("compiledV8", str(iso, std::to_string(V8_MAJOR_VERSION) + "." + std::to_string(V8_MINOR_VERSION)));
    setFa("runtimeV8", str(iso, std::to_string(g_runtimeV8Major) + "." + std::to_string(g_runtimeV8Minor)));
    set("fastApi", fa);
  }
  if (g_countCalls) {
    // Per-thread fast/slow hit counters (MORO_ENGINE_FASTCALL_STATS=1 at load).
    Local<Object> stats = Object::New(iso);
    for (int i = 0; i < fastcall::kCount; ++i) {
      Local<Object> pair = Object::New(iso);
      (void)pair->Set(ctx, str(iso, "fast"), Number::New(iso, static_cast<double>(fastcall::g_fastHits[i]))).FromMaybe(false);
      (void)pair->Set(ctx, str(iso, "slow"), Number::New(iso, static_cast<double>(fastcall::g_slowHits[i]))).FromMaybe(false);
      (void)stats->Set(ctx, str(iso, fastcall::fnName(i)), pair).FromMaybe(false);
    }
    set("fastCallStats", stats);
  }
  args.GetReturnValue().Set(result);
}

// The native surface, in one table: name, the regular callback, and (for the
// hot entry points) the V8 fast-call target plus its counting variant. The
// export-drift gate (tools/check-exports.mjs) reads this table.
struct ExportDef {
  const char* name;
  v8::FunctionCallback slow;
  const v8::CFunction* fast;          // nullptr: regular callback only
  const v8::CFunction* fastCounting;  // installed under MORO_ENGINE_FASTCALL_STATS=1
};

#if MORO_FAST_API_ENABLED
#define MORO_FASTDEF(Name)                                                            \
  static const v8::CFunction kFast_##Name = v8::CFunction::Make(&fastcall::Name<false>); \
  static const v8::CFunction kFastC_##Name = v8::CFunction::Make(&fastcall::Name<true>);
MORO_FASTDEF(RespondPrepared)
MORO_FASTDEF(RespondPreparedEmpty)
MORO_FASTDEF(WriteHeadPrepared)
MORO_FASTDEF(Write)
MORO_FASTDEF(End)
MORO_FASTDEF(EndWith)
MORO_FASTDEF(IsAborted)
#undef MORO_FASTDEF
#define MORO_FAST(Name) &kFast_##Name, &kFastC_##Name
#else
#define MORO_FAST(Name) nullptr, nullptr
#endif

static const ExportDef kExports[] = {
    {"serve", Serve, nullptr, nullptr},
    {"listen", Listen, nullptr, nullptr},
    {"close", Close, nullptr, nullptr},
    {"stopListening", StopListening, nullptr, nullptr},
    {"getMethod", GetMethod, nullptr, nullptr},
    {"getBatchBuffers", GetBatchBuffers, nullptr, nullptr},
    {"getPath", GetPath, nullptr, nullptr},
    {"getQuery", GetQuery, nullptr, nullptr},
    {"getHeaders", GetHeaders, nullptr, nullptr},
    {"getHeader", GetHeader, nullptr, nullptr},
    {"getBody", GetBody, nullptr, nullptr},
    {"getRemoteAddress", GetRemoteAddress, nullptr, nullptr},
    {"isAborted", IsAborted, MORO_FAST(IsAborted)},
    {"respond", Respond, nullptr, nullptr},
    {"writeHead", WriteHead, nullptr, nullptr},
    {"write", Write, MORO_FAST(Write)},
    {"end", End, MORO_FAST(End)},
    {"setStaticRoute", SetStaticRoute, nullptr, nullptr},
    {"clearStaticRoutes", ClearStaticRoutes, nullptr, nullptr},
    {"prepareResponse", PrepareResponse, nullptr, nullptr},
    {"releaseTemplates", ReleaseTemplates, nullptr, nullptr},
    {"respondPrepared", RespondPrepared, MORO_FAST(RespondPrepared)},
    {"respondPreparedEmpty", RespondPreparedEmpty, MORO_FAST(RespondPreparedEmpty)},
    {"writeHeadPrepared", WriteHeadPrepared, MORO_FAST(WriteHeadPrepared)},
    {"endWith", EndWith, MORO_FAST(EndWith)},
    {"upgradeToWebSocket", UpgradeToWebSocket, nullptr, nullptr},
    {"wsSend", WsSend, nullptr, nullptr},
    {"wsClose", WsClose, nullptr, nullptr},
    {"probe", Probe, nullptr, nullptr},
};
#undef MORO_FAST

static void Initialize(Local<Object> exports, Local<Value> module,
                       Local<Context> context) {
  // Context::GetIsolate() was removed in V8 14 (Node 26); GetCurrent() is stable
  Isolate* iso = Isolate::GetCurrent();

  // Diagnostics-only: MORO_ENGINE_NOTIFY=sync restores re-entrant
  // onAborted/onWritable delivery (pre-1.1.6 behaviour) for bisecting.
  const char* notifyEnv = std::getenv("MORO_ENGINE_NOTIFY");
  const char* batchEnv = std::getenv("MORO_ENGINE_BATCH");
  g_batchEnabled = !(batchEnv && std::strcmp(batchEnv, "0") == 0);
  g_notifyDeferred = !(notifyEnv && std::strcmp(notifyEnv, "sync") == 0);

  // Fast calls are installed only when every precondition holds; otherwise
  // the plain callbacks are registered and probe().fastApi.reason says why.
  //   not-compiled: built without the fast-API header (--no-fast-api)
  //   env-disabled: MORO_ENGINE_FASTCALL=0 (diagnostics kill switch)
  //   sync-notify:  MORO_ENGINE_NOTIFY=sync - a binding call could re-enter
  //                 JS, which a fast target must never do
  //   v8-mismatch:  the host's V8 major.minor differs from the one this binary
  //                 was compiled against (the fast-call ABI is not stable
  //                 across V8 versions; plain callbacks are)
  const char* statsEnv = std::getenv("MORO_ENGINE_FASTCALL_STATS");
  g_countCalls = statsEnv && std::strcmp(statsEnv, "1") == 0;
  const char* fcEnv = std::getenv("MORO_ENGINE_FASTCALL");
  const bool fcDisabled = fcEnv && std::strcmp(fcEnv, "0") == 0;
  const bool v8Match = v8compat::runtimeVersionMatches(&g_runtimeV8Major, &g_runtimeV8Minor);
  g_fastReason = !g_fastCompiled   ? "not-compiled"
                 : fcDisabled      ? "env-disabled"
                 : !g_notifyDeferred ? "sync-notify"
                 : !v8Match        ? "v8-mismatch"
                                   : "ok";
  g_fastInstalled = std::strcmp(g_fastReason, "ok") == 0;

  for (const ExportDef& e : kExports) {
    const v8::CFunction* cf =
        g_fastInstalled ? (g_countCalls ? e.fastCounting : e.fast) : nullptr;
    if (cf == nullptr) {
      NODE_SET_METHOD(exports, e.name, e.slow);
      continue;
    }
    // Same recipe as NODE_SET_METHOD (FunctionTemplate -> GetFunction ->
    // SetName), plus the CFunction that optimised callers may dispatch to.
    Local<v8::FunctionTemplate> ft = v8::FunctionTemplate::New(
        iso, e.slow, Local<Value>(), Local<v8::Signature>(), 0,
        // V8 refuses a CFunction on a constructible template ("Fast API calls
        // are not supported for constructor functions"); these are plain
        // functions, never `new`ed.
        v8::ConstructorBehavior::kThrow, v8::SideEffectType::kHasSideEffect, cf);
    Local<Function> fn;
    if (!ft->GetFunction(context).ToLocal(&fn)) {
      NODE_SET_METHOD(exports, e.name, e.slow);
      continue;
    }
    Local<String> name = str(iso, e.name);
    fn->SetName(name);
    (void)exports->Set(context, name, fn).FromMaybe(false);
  }

  (void)exports->Set(context, str(iso, "version"), str(iso, kEngineVersion))
      .FromMaybe(false);
  (void)module;
}

NODE_MODULE_CONTEXT_AWARE(moro_engine, moro::engine::Initialize)

}  // namespace engine
}  // namespace moro
