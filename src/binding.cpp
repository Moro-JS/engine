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

#include <atomic>
#include <climits>
#include <cstdlib>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>  // _AddressOfReturnAddress
#endif
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(__GLIBC__)
#include <malloc.h>  // malloc_trim
#endif

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
static const char* kEngineVersion = "1.2.3";

using v8::Array;
using v8::ArrayBuffer;
using v8::BackingStore;
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
struct JsServer;

// A Node callback scope on the server's async resource: what every entry into
// JS from the engine opens, so async hooks and the microtask checkpoint see
// the call (defined after JsServer, which it reads).
struct CallbackScopeFor {
  node::CallbackScope scope;
  CallbackScopeFor(JsServer* js, Isolate* iso);
};

struct JsServer {
  Isolate* isolate;
  Global<Context> context;
  Global<Function> onRequest;
  Global<Function> onRequestBatch;
  // Depth of cbOnWsRead: while > 0 the context and Node callback scope of
  // the read are open on its stack, and cbOnWsMessage/cbOnWsClose add only
  // a handle scope per frame. Counted because a read can be fed from inside
  // a request dispatch, which has scopes of its own.
  int wsReadDepth = 0;
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
  // onRequest, onRequestBatch, onAborted and onWritable were handed to
  // serve() wrapped in the loader's trampolines (packages/engine/index.js,
  // "dispatch trampolines"): they catch and report what the application's
  // callback throws, and the batch one says when JS has left its loop, so
  // these are entered through node::MakeCallback (see invokeJs).
  bool viaTrampoline = false;
  // A dispatch that starts below this stack address starts deep in the
  // stack, far below where the event loop calls in (see
  // dispatchesFromDeepStack). Set by serve().
  uintptr_t deepDispatchBelow = 0;
  // When the cleanup hook is waiting for this server to finish closing, it
  // points here so freeJsServer can report completion.
  bool* closedFlag = nullptr;
  // Interned per-path JS strings: real apps route a BOUNDED set of paths, so
  // the per-request String::NewFromUtf8 (allocation + GC pressure) is paid
  // once per unique path instead of once per request. Bounded: only paths
  // <= kPathCacheMaxLen are cached and at most kPathCacheMaxEntries live here
  // (past the cap, requests simply build the string per-call as before), so
  // an adversary spraying unique URLs can't grow it. Freed with the JsServer.
  StringMap<Global<String>> pathCache;
  static constexpr size_t kPathCacheMaxEntries = 512;
  static constexpr size_t kPathCacheMaxLen = 128;
  // Same idea for request header NAMES (getHeaders/getHeader hot path when
  // apps read req.headers): a bounded set in practice (host, accept, ...),
  // so intern them instead of a String::NewFromUtf8 per name per request.
  // Values are never cached - they vary per request. Same lifetime story.
  StringMap<Global<String>> headerNameCache;
  static constexpr size_t kHeaderNameCacheMaxEntries = 256;
  static constexpr size_t kHeaderNameCacheMaxLen = 64;

  // Batched dispatch (getBatchBuffers / onRequestBatch): one descriptor
  // triple (reqId, methodIdx, pathIdx) per slot, the control cell the engine
  // advances as slots complete (Server::setBatchControl), and the path table
  // JS indexes with pathIdx (the interned strings of pathCache; a path the
  // cache will not hold is kNoPathIdx and JS asks getPath(reqId)). V8-owned
  // ArrayBuffers: their storage never moves, and the server holds it too
  // (batchDescStore/batchCtlStore), so the raw pointers below stay valid for
  // the server's lifetime.
  Global<ArrayBuffer> batchDesc;
  Global<ArrayBuffer> batchCtl;
  Global<Array> batchPaths;
  // The storage itself, held here as well: JS can take it away from the two
  // ArrayBuffers (ArrayBuffer.prototype.transfer, a transfer list), and the
  // pointers below must stay good for as long as the server writes through
  // them, whoever else still owns the bytes by then.
  std::shared_ptr<BackingStore> batchDescStore;
  std::shared_ptr<BackingStore> batchCtlStore;
  uint32_t* desc = nullptr;
  uint32_t* ctl = nullptr;
  StringMap<uint32_t> pathIndex;
  static constexpr uint32_t kNoPathIdx = 0xFFFFFFFFu;
};

// thread_local, not process-global: worker_threads + reusePort (see
// HttpLimits::reusePort) runs one engine per thread, each with its own uv loop
// and servers, and a serverId only ever crosses the JS<->C++ boundary on the
// thread that created it - per-thread registries are race-free without locks.
// The servers created on this thread and the id counter for them live in the
// thread's ThreadState (thread_state.h), with everything else per thread.

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
static void cleanupEpollLoop(void*) { Server::EpollLoop::shutdownForThread(); }
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
  threadState().servers.erase(js->id);
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
// getHeaders): the thread's servers are few (one entry per serve() on it), so
// a scan beats storing a back-pointer on every connection.
static JsServer* jsServerFor(const Server* srv) {
  for (auto& [id, js] : threadState().servers)
    if (js->server == srv) return js;
  return nullptr;
}

// ---- helpers ----

// ToLocal with an empty-string fallback, not ToLocalChecked: NewFromUtf8
// fails only past V8's string-length cap (~512MB, reachable when an operator
// raises a size limit that far) or under allocation pressure - degrade to an
// empty string instead of aborting the whole Node process.
static Local<String> str(Isolate* iso, std::string_view s) {
  Local<String> out;
  // NewFromUtf8's length is an int. A string past INT_MAX (reachable only when
  // an operator raises a size limit past 2 GiB) would cast negative - V8 then
  // treats the data as NUL-terminated and over-reads - or, just past 2^32,
  // wrap to a small positive length (silent truncation). Guard before the
  // cast; degrade to an empty string, the same fallback as a NewFromUtf8 fail.
  if (s.size() > static_cast<size_t>(INT_MAX)) return String::Empty(iso);
  if (String::NewFromUtf8(iso, s.data(), v8::NewStringType::kNormal,
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
// is never clobbered. Per thread (ThreadState) by the same ownership rules as
// the registries. Plain std::string, so thread-exit destruction never touches
// V8.
class HeaderBlockLease {
 public:
  HeaderBlockLease() {
    ThreadState& t = threadState();
    if (!t.headerBlockInUse) {
      t.headerBlockInUse = true;
      owned_ = true;
      t.headerBlock.clear();
      block_ = &t.headerBlock;
    } else {
      block_ = &local_;
    }
  }
  ~HeaderBlockLease() {
    if (owned_) threadState().headerBlockInUse = false;
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

class ByteSource {
 public:
  // `borrow`: take the zero-copy String::ValueView path. A ValueView pins the
  // V8 heap (no allocation, hence no JS) for its lifetime, so it is legal
  // only on entry points whose engine call cannot reach JS: the HTTP
  // response functions and wsSend() under deferred notification (wsSend's
  // shed of a stalled consumer is queued to a later turn since 1.1.16). Sync
  // notification mode (MORO_ENGINE_NOTIFY=sync) delivers onAborted
  // re-entrantly from inside respond()/write() and the shed from inside
  // wsSend() - it must copy instead.
  ByteSource(Isolate* iso, Local<Value> v, bool borrow = g_notifyDeferred) {
    if (v->IsString()) {
      Local<String> s = v.As<String>();
#if MORO_V8_HAS_VALUE_VIEW
      if (!borrow) {
        // Copy path (see above): the same malloc-free ASCII fast copy the
        // pre-ValueView V8s use, else Utf8Value.
        if (!threadState().byteScratchInUse && readAsciiOneByte(iso, s, threadState().byteScratch, 65536)) {
          threadState().byteScratchInUse = true;
          usedScratch_ = true;
          data_ = threadState().byteScratch.data();
          size_ = threadState().byteScratch.size();
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
          if (!threadState().byteScratchInUse) {
            threadState().byteScratchInUse = true;
            usedScratch_ = true;
            text::latin1ToUtf8(p, n, threadState().byteScratch);
            view_.reset();
            data_ = threadState().byteScratch.data();
            size_ = threadState().byteScratch.size();
            valid_ = true;
            return;
          }
        }
        view_.reset();
      }
#else
      // Node 20/22 (V8 < 12.9, no ValueView): malloc-free copy for ASCII
      // one-byte strings up to 64 KiB; larger or non-ASCII take Utf8Value.
      if (!threadState().byteScratchInUse && readAsciiOneByte(iso, s, threadState().byteScratch, 65536)) {
        threadState().byteScratchInUse = true;
        usedScratch_ = true;
        data_ = threadState().byteScratch.data();
        size_ = threadState().byteScratch.size();
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
      if (threadState().byteScratch.capacity() > 65536) std::string().swap(threadState().byteScratch);
      threadState().byteScratchInUse = false;
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
  // locals so the outer pair is never clobbered. Taken at the first pair
  // that needs it: the usual pair, below, is read straight into the block.
  std::string localK, localV;
  bool ownScratch = false;
  std::string* kbufp = nullptr;
  std::string* vbufp = nullptr;
  for (uint32_t i = 0; i + 1 < n; i += 2) {
    Local<Value> kv, vv;
    if (!arr->Get(ctx, i).ToLocal(&kv)) continue;
    if (!arr->Get(ctx, i + 1).ToLocal(&vv)) continue;
    // The usual pair - two one-byte strings, the value plain ASCII - is
    // written where it will stand in the block and checked there, by the
    // same rules as below with the same result: a name that is not a token
    // or a value with a control byte drops the pair, the headers the engine
    // owns are dropped, Content-Length is parsed and never copied. No JS
    // runs between the two reads. Anything else (a two-byte string, a value
    // with bytes to be encoded as UTF-8, a value that is not a string, a
    // length past what the scratch path takes) is left to the code below.
    if (kv->IsString() && vv->IsString() && kv.As<String>()->IsOneByte() &&
        vv.As<String>()->IsOneByte()) {
      const int kLen = kv.As<String>()->Length();
      const int vLen = vv.As<String>()->Length();
      if (kLen > 0 && kLen <= 4096 && vLen >= 0 && vLen <= 65536) {
        const size_t at = block.size();
        const size_t kn = static_cast<size_t>(kLen), vn = static_cast<size_t>(vLen);
        block.resize(at + kn + vn + 4);
        char* const name = &block[at];
        char* const value = name + kn + 2;
        v8compat::writeOneByte(iso, kv.As<String>(), reinterpret_cast<uint8_t*>(name),
                               static_cast<uint32_t>(kn));
        v8compat::writeOneByte(iso, vv.As<String>(), reinterpret_cast<uint8_t*>(value),
                               static_cast<uint32_t>(vn));
        if (text::isAscii(reinterpret_cast<const uint8_t*>(value), vn)) {
          bool keep = validValueBytes(reinterpret_cast<const unsigned char*>(value), vn);
          for (size_t j = 0; keep && j < kn; ++j) keep = isTokenChar(static_cast<unsigned char>(name[j]));
          if (keep) {
            switch (kn) {
              case 4: keep = !headerNameIs(name, kLen, "date"); break;
              case 10: keep = !headerNameIs(name, kLen, "connection") && !headerNameIs(name, kLen, "keep-alive"); break;
              case 17: keep = !headerNameIs(name, kLen, "transfer-encoding"); break;
              case 14:
                if (headerNameIs(name, kLen, "content-length")) {
                  long long parsed = 0;
                  bool ok = vn > 0 && vn <= 18;
                  for (size_t j = 0; ok && j < vn; ++j) {
                    const char d = value[j];
                    if (d < '0' || d > '9') ok = false;
                    else parsed = parsed * 10 + (d - '0');
                  }
                  if (ok) customCL = parsed;
                  keep = false;
                }
                break;
              default: break;
            }
          }
          if (keep) {
            name[kn] = ':';
            name[kn + 1] = ' ';
            value[vn] = '\r';
            value[vn + 1] = '\n';
          } else {
            block.resize(at);
          }
          continue;
        }
        block.resize(at);
      }
    }
    if (kbufp == nullptr) {
      ownScratch = !threadState().hdrScratchInUse;
      if (ownScratch) threadState().hdrScratchInUse = true;
      kbufp = ownScratch ? &threadState().hdrKeyScratch : &localK;
      vbufp = ownScratch ? &threadState().hdrValScratch : &localV;
    }
    std::string& kbuf = *kbufp;
    std::string& vbuf = *vbufp;
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
  if (ownScratch) threadState().hdrScratchInUse = false;
}

// ---- Server-side callbacks that trampoline into JS ----

static void reportCaught(Isolate* iso, TryCatch& tc, const char* where);

// Print "[morojs-engine] <where> threw: <the value as a string>". The string
// is the value's own (String(value)), unless producing it fails - a toString
// that throws, a Symbol, no stack left to call toString with - in which case
// it is V8's description of the value, made without running JavaScript.
// (Utf8Value catches what the conversion throws: nothing is left behind.)
static void printThrown(Isolate* iso, Local<Value> value, const char* where) {
  String::Utf8Value msg(iso, value);
  if (*msg != nullptr) {
    fprintf(stderr, "[morojs-engine] %s threw: %s\n", where, *msg);
    return;
  }
  if (iso->IsExecutionTerminating()) return;
  String::Utf8Value described(iso, v8::Exception::CreateMessage(iso, value)->Get());
  const char* s = *described != nullptr ? *described : "(unprintable value)";
  static constexpr char kUncaught[] = "Uncaught ";
  if (std::strncmp(s, kUncaught, sizeof(kUncaught) - 1) == 0) s += sizeof(kUncaught) - 1;
  fprintf(stderr, "[morojs-engine] %s threw: %s\n", where, s);
}

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
inline CallbackScopeFor::CallbackScopeFor(JsServer* js, Isolate* iso)
    : scope(iso,
            js->asyncResource.IsEmpty() ? Object::New(iso) : js->asyncResource.Get(iso),
            node::async_context{0, 0}) {}

// The path argument of onRequest: the interned string when the path is one
// the cache holds or can take (see JsServer).
static Local<String> pathStringFor(JsServer* js, Isolate* iso, const std::string& path) {
  if (path.size() > JsServer::kPathCacheMaxLen) return str(iso, path);
  if (Global<String>* cached = js->pathCache.find(path)) return cached->Get(iso);
  Local<String> pathStr = str(iso, path);
  if (js->pathCache.size() < JsServer::kPathCacheMaxEntries) {
    js->pathCache.insert(path, Global<String>(iso, pathStr));
  }
  return pathStr;
}

// A callback the loader wrapped in a trampoline (JsServer::viaTrampoline) is
// entered through node::MakeCallback: the same callback scope as
// CallbackScopeFor - the server's resource object, the nextTick queue and the
// microtasks drained when the outermost scope closes - kept on the stack,
// where node::CallbackScope allocates one per call. No TryCatch here: what
// the application's callback throws is caught and reported by the trampoline
// (JavaScript; ReportCaught prints it), before the scope closes, and what a
// nextTick callback or a microtask throws while the scope closes is the
// process's uncaught exception, as it is under a CallbackScope.
//
// That leaves one way for an exception to reach the code that called into the
// engine: the trampoline itself failing to start, for want of stack. Not
// possible from the event loop, which calls in near the top of the stack; it
// is from JavaScript running deep in it - a close(), say, that delivers
// onAborted in place from a deeply recursive caller. A dispatch that starts
// well below where the loop calls in therefore takes the path below,
// trampoline or not: its own callback scope and TryCatch around a plain call.
// "Well below" is measured from where serve() was called - JavaScript, so at
// or below the depth the event loop calls in from - and fixed then: the test
// is one load and a compare per dispatch.
static constexpr uintptr_t kDeepDispatchBytes = 64 * 1024;
// (The stack pointer itself where it can be read directly: taking the frame
// address instead makes the compiler set up the whole frame on entry to the
// function that asks, early returns included.)
static inline uintptr_t stackPosition() {
#if defined(_MSC_VER)
  return reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
#elif defined(__aarch64__)
  uintptr_t sp;
  __asm__("mov %0, sp" : "=r"(sp));
  return sp;
#elif defined(__x86_64__)
  uintptr_t sp;
  __asm__("mov %%rsp, %0" : "=r"(sp));
  return sp;
#else
  return reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
#endif
}
static inline bool dispatchesFromDeepStack(JsServer* js) {
  const bool deep = stackPosition() < js->deepDispatchBelow;  // stacks grow down on every target
#if defined(__GNUC__)
  return __builtin_expect(deep, 0);
#else
  return deep;
#endif
}

// A call inside the engine's own callback scope and TryCatch: every call
// when the callbacks are not the loader's trampolines, and a trampoline call
// that starts deep in the stack (see dispatchesFromDeepStack).
MORO_NOINLINE static void invokeUnderScope(JsServer* js, Global<Function>& fn, uint32_t reqId,
                                           bool withExtra, int32_t methodIdx, const std::string& path) {
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope ctxScope(ctx);
  CallbackScopeFor cb(js, iso);
  TryCatch tryCatch(iso);

  Local<Function> f = fn.Get(iso);
  if (withExtra) {
    Local<String> pathStr = pathStringFor(js, iso, path);
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
  // (Not an exception: the isolate being terminated under the handler, which
  // is how a worker thread ends. There is nothing to report then.)
  reportCaught(iso, tryCatch, "handler");
}

static void invokeJs(JsServer* js, Global<Function>& fn, uint32_t reqId,
                     bool withExtra, int32_t methodIdx, const std::string& path) {
  if (fn.IsEmpty() || js->tearingDown) return;
  if (!js->viaTrampoline || dispatchesFromDeepStack(js)) {
    invokeUnderScope(js, fn, reqId, withExtra, methodIdx, path);
    return;
  }
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Value> argv[3] = {Integer::NewFromUnsigned(iso, reqId), Local<Value>(), Local<Value>()};
  int argc = 1;
  if (withExtra) {
    argv[1] = Integer::New(iso, methodIdx);
    argv[2] = pathStringFor(js, iso, path);
    argc = 3;
  }
  (void)node::MakeCallback(iso, js->asyncResource.Get(iso), fn.Get(iso), argc, argv,
                           node::async_context{0, 0});
}

static void cbOnRequest(void* user, Connection* c) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  // (Static routes were already answered by Server::surfaceRequest.)
  invokeJs(js, js->onRequest, c->reqId, true, static_cast<int32_t>(c->rq->method), c->rq->path);
}

// The batch buffers, created on first need (getBatchBuffers() or the first
// batch) and handed to the engine as its control cell.
// (Out of line: every batch call asks, and only the first one per server
// comes here.)
MORO_NOINLINE static void createBatchBuffers(JsServer* js, Isolate* iso);
static inline void ensureBatchBuffers(JsServer* js, Isolate* iso, Local<Context> ctx) {
  (void)ctx;
  if (!js->desc) createBatchBuffers(js, iso);
}
MORO_NOINLINE static void createBatchBuffers(JsServer* js, Isolate* iso) {
  Context::Scope ctxScope(js->context.Get(iso));
  Local<ArrayBuffer> d = ArrayBuffer::New(iso, 3 * Server::kMaxStaged * sizeof(uint32_t));
  Local<ArrayBuffer> c = ArrayBuffer::New(iso, sizeof(uint32_t));
  Local<Array> paths = Array::New(iso, static_cast<int>(JsServer::kPathCacheMaxEntries));
  js->batchDesc.Reset(iso, d);
  js->batchCtl.Reset(iso, c);
  js->batchPaths.Reset(iso, paths);
  js->batchDescStore = d->GetBackingStore();
  js->batchCtlStore = c->GetBackingStore();
  js->desc = static_cast<uint32_t*>(js->batchDescStore->Data());
  js->ctl = static_cast<uint32_t*>(js->batchCtlStore->Data());
  std::memset(js->desc, 0, 3 * Server::kMaxStaged * sizeof(uint32_t));
  *js->ctl = 0;
  if (js->server) js->server->setBatchControl(js->ctl);
}

// Index of `path` in the JS path table (interning it on first sight, under
// the same bounds as pathCache), or kNoPathIdx when it is not cacheable.
static uint32_t pathIndexFor(JsServer* js, Isolate* iso, Local<Context> ctx, const std::string& path) {
  if (path.size() > JsServer::kPathCacheMaxLen) return JsServer::kNoPathIdx;
  if (const uint32_t* known = js->pathIndex.find(path)) return *known;
  if (js->pathIndex.size() >= JsServer::kPathCacheMaxEntries) return JsServer::kNoPathIdx;
  Context::Scope ctxScope(ctx);
  const uint32_t idx = static_cast<uint32_t>(js->pathIndex.size());
  Local<String> pathStr;
  if (Global<String>* cached = js->pathCache.find(path)) {
    pathStr = cached->Get(iso);
  } else {
    pathStr = str(iso, path);
    if (js->pathCache.size() < JsServer::kPathCacheMaxEntries) js->pathCache.insert(path, Global<String>(iso, pathStr));
  }
  (void)js->batchPaths.Get(iso)->Set(ctx, idx, pathStr).FromMaybe(false);
  js->pathIndex.insert(path, idx);
  return idx;
}

// One JS call for a batch: slot 0 is the connection's active request, slots
// 1..count-1 its staged ring in order. JS returns after answering the slots
// it could answer synchronously (the engine tracks that itself through the
// control cell and c->active, so the return value is not load-bearing).
// The batch descriptors of `c` and its staged requests (or of an HTTP/2
// batch), filled in for JS. Returns the count, capped at the ring's size.
static inline uint32_t fillBatchDescriptors(JsServer* js, Isolate* iso, Local<Context> ctx, Connection* c,
                                            uint32_t count) {
  ensureBatchBuffers(js, iso, ctx);
  if (count > Server::kMaxStaged) count = Server::kMaxStaged;
  uint32_t* d = js->desc;
  d[0] = c->reqId;
  d[1] = static_cast<uint32_t>(c->rq->method);
  d[2] = pathIndexFor(js, iso, ctx, c->rq->path);
  if (c->h2Parent != nullptr) {
    // An HTTP/2 batch: independent requests, each on its own Connection.
    for (uint32_t k = 1; k < count; k++) {
      const Connection* r = js->server->h2BatchAt(k);
      d[3 * k] = r->reqId;
      d[3 * k + 1] = static_cast<uint32_t>(r->rq->method);
      d[3 * k + 2] = pathIndexFor(js, iso, ctx, r->rq->path);
    }
  } else {
    for (uint32_t k = 1; k < count; k++) {
      const StagedRequest& sr = c->rq->staged[(c->stagedHead + k - 1) % Server::kMaxStaged];
      d[3 * k] = sr.reqId;
      d[3 * k + 1] = static_cast<uint32_t>(sr.method);
      d[3 * k + 2] = pathIndexFor(js, iso, ctx, sr.path);
    }
  }
  return count;
}

// A batch call inside the engine's own callback scope and TryCatch: every
// call when the callbacks are not the loader's trampolines, and a trampoline
// call that starts deep in the stack (see dispatchesFromDeepStack), whose
// _batchDone must then reach this server, not an outer batch's.
MORO_NOINLINE static void batchUnderScope(JsServer* js, Connection* c, uint32_t count) {
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope ctxScope(ctx);
  CallbackScopeFor cb(js, iso);
  count = fillBatchDescriptors(js, iso, ctx, c, count);
  Local<Value> argv[1] = {Integer::NewFromUnsigned(iso, count)};
  TryCatch tryCatch(iso);
  ThreadState& t = threadState();
  JsServer* const outer = t.batchJs;
  if (js->viaTrampoline) t.batchJs = js;
  if (js->onRequestBatch.Get(iso)->Call(ctx, ctx->Global(), 1, argv).IsEmpty()) { /* threw: reported below */ }
  t.batchJs = outer;
  // JS is out of its loop; the callback scope closing below runs microtasks
  // and nextTicks, which may still answer requests of this batch.
  js->server->batchLoopReturned();
  reportCaught(iso, tryCatch, "onRequestBatch");
}

static void cbOnRequestBatch(void* user, Connection* c, uint32_t count) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown || js->onRequestBatch.IsEmpty()) return;
  if (!js->viaTrampoline || dispatchesFromDeepStack(js)) {
    batchUnderScope(js, c, count);
    return;
  }
  // Through the trampoline: node::MakeCallback enters the context for the
  // call; what comes before it needs one only where it creates objects (the
  // first batch of a server, the first sight of a path), and opens it there.
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  count = fillBatchDescriptors(js, iso, ctx, c, count);
  Local<Value> argv[1] = {Integer::NewFromUnsigned(iso, count)};
  // The trampoline tells the engine that JS is out of its loop (BatchDone)
  // before it returns, which is before MakeCallback closes the scope and
  // runs the microtasks and nextTicks that may still answer requests of
  // this batch. A call that ends without it - the isolate terminated under
  // the handler - is covered here; batchLoopReturned() may run twice.
  ThreadState& t = threadState();
  JsServer* const outer = t.batchJs;
  t.batchJs = js;
  (void)node::MakeCallback(iso, js->asyncResource.Get(iso), js->onRequestBatch.Get(iso), 1, argv,
                           node::async_context{0, 0});
  t.batchJs = outer;
  js->server->batchLoopReturned();
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
  if (!tc.HasCaught() || tc.HasTerminated()) return;  // terminated: the thread is ending, no handler threw
  printThrown(iso, tc.Exception(), where);
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

// One WebSocket read: the context and Node callback scope are opened here,
// on this stack frame, around every frame the engine delivers from the
// buffer; cbOnWsMessage/cbOnWsClose then add only a handle scope and a
// TryCatch per frame. The microtask checkpoint runs once when the scope
// closes, after the last frame of the read, which is when Node's own 'data'
// callback would run it for the frames of one segment. A read fed from
// inside a request dispatch, or from inside another read, runs under the
// scopes already open.
static void cbOnWsRead(void* user, Connection* c, char* data, size_t len) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown || js->wsReadDepth > 0) {
    js->server->feedWebSocketFrames(c, data, len);
    return;
  }
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  CallbackScopeFor cb(js, iso);
  js->wsReadDepth++;
  js->server->feedWebSocketFrames(c, data, len);
  js->wsReadDepth--;
}

// Opens the per-call scopes a frame needs when it is not inside a read
// (cbOnWsRead) - a close fired from wsClose() by a timer, say.
struct WsCallScopes {
  std::optional<Context::Scope> ctx;
  std::optional<CallbackScopeFor> cb;
  WsCallScopes(JsServer* js, Isolate* iso, Local<Context> context) {
    if (js->wsReadDepth > 0) return;
    ctx.emplace(context);
    cb.emplace(js, iso);
  }
};

static void cbOnWsMessage(void* user, Connection* c, const char* data,
                          size_t len, bool isBinary) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  if (js->onWsMessage.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  WsCallScopes scopes(js, iso, ctx);
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
    // A pure-ASCII payload (the parser already validated the UTF-8) is built
    // as a one-byte string straight from the bytes, skipping the UTF-8
    // decode; anything else takes NewFromUtf8.
    const bool ascii = text::isAscii(reinterpret_cast<const uint8_t*>(data), len);
    if (len > static_cast<size_t>(INT_MAX) ||
        !(ascii ? String::NewFromOneByte(iso, reinterpret_cast<const uint8_t*>(data),
                                         v8::NewStringType::kNormal, static_cast<int>(len))
                : String::NewFromUtf8(iso, data, v8::NewStringType::kNormal,
                                      static_cast<int>(len)))
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

static void FreeBodyHolder(void*, size_t, void* hint);

// A large binary message, in the string the engine received it into: the
// ArrayBuffer is made over those bytes - the string becomes its backing
// store - where cbOnWsMessage allocates a buffer of the same size and copies
// them across. A plain V8 backing store, for the reason GetBody gives.
static void cbOnWsBinaryOwned(void* user, Connection* c, std::string& message) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->tearingDown) return;
  if (js->onWsMessage.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  WsCallScopes scopes(js, iso, ctx);
  TryCatch tc(iso);
  auto* holder = new std::string();
  holder->swap(message);
  Local<ArrayBuffer> ab = ArrayBuffer::New(
      iso, ArrayBuffer::NewBackingStore(holder->data(), holder->size(), FreeBodyHolder, holder));
  Local<Value> argv[3] = {Integer::NewFromUnsigned(iso, c->wsId), ab, v8::Boolean::New(iso, true)};
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
  WsCallScopes scopes(js, iso, ctx);
  TryCatch tc(iso);
  Local<Value> argv[2] = {Integer::NewFromUnsigned(iso, c->wsId),
                          Integer::New(iso, code)};
  if (js->onWsClose.Get(iso)->Call(ctx, ctx->Global(), 2, argv).IsEmpty()) { /* threw: reported below */ }
  reportCaught(iso, tc, "onWsClose");
}

// _reportCaught(which, error): what a dispatch trampoline (the loader's) does
// with an exception the application's callback threw - the line reportCaught
// prints. `which`: 0 a request, abort or drain callback, 1 onRequestBatch.
static void ReportCaught(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  if (args.Length() < 2) return;
  const bool batch = args[0]->IsInt32() && args[0].As<Int32>()->Value() == 1;
  printThrown(iso, args[1], batch ? "onRequestBatch" : "handler");
}

// _batchDone(): the batch trampoline's notice that the application's
// onRequestBatch has returned (or thrown): JS is out of its loop over the
// batch, and whatever answers a request of it from here on - a microtask, a
// nextTick - is outside it (Server::batchLoopReturned). Two stores, no V8:
// also a fast-call target.
static inline void batchDone() {
  JsServer* js = threadState().batchJs;
  if (js != nullptr && js->server != nullptr) js->server->batchLoopReturned();
}
static void BatchDone(const FunctionCallbackInfo<Value>&) { batchDone(); }
#if MORO_FAST_API_ENABLED
static void FastBatchDone(Local<Value>) { batchDone(); }
#endif

// ---- JS-exposed functions ----

// serve(callbacks, options?) -> serverId
// Parse a MoroJS-shaped ssl options object (file paths and/or inline PEM,
// passphrase, ticketKeys, policy, minVersion, client-cert flags) into an
// SslConfig. Shared by serve() and updateSsl(). Throws (and returns false)
// on a malformed value; validity of the material itself is TlsContext's job.
static bool parseSslOptions(Isolate* iso, Local<Context> ctx, Local<Object> so, SslConfig& ssl) {
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
  // A policy value of the wrong type is a configuration error, not "unset":
  // read as unset, `requestCert: 1` is a server that asks nobody for a
  // certificate and `minVersion: 1.3` one that still takes TLS 1.2, with
  // nothing said. undefined and null are "not given".
  auto typed = [&](const char* name, bool wantString) {
    Local<Value> v;
    if (!so->Get(ctx, str(iso, name)).ToLocal(&v)) return false;
    if (v->IsNullOrUndefined() || (wantString ? v->IsString() : v->IsBoolean())) return true;
    iso->ThrowException(v8::Exception::TypeError(str(
        iso, (std::string("ssl.") + name + (wantString ? " must be a string" : " must be a boolean")).c_str())));
    return false;
  };
  for (const char* name : {"passphrase", "ciphers", "ciphersuites", "ecdhCurve", "minVersion", "maxVersion"}) {
    if (!typed(name, /*wantString=*/true)) return false;
  }
  for (const char* name : {"requestCert", "rejectUnauthorized"}) {
    if (!typed(name, /*wantString=*/false)) return false;
  }
  getStr("key_file_name", ssl.keyFile);
  getStr("cert_file_name", ssl.certFile);
  getStr("ca_file_name", ssl.caFile);
  getBytes("key", ssl.keyPem);
  getBytes("cert", ssl.certPem);
  getBytes("ca", ssl.caPem);
  getBytes("crl", ssl.crlPem);
  getBytes("ticketKeys", ssl.ticketKeys);
  if (!ssl.ticketKeys.empty() && ssl.ticketKeys.size() != 48) {
    iso->ThrowException(v8::Exception::Error(str(
        iso, "ssl.ticketKeys must be exactly 48 bytes (see Node's tls.Server ticketKeys)")));
    return false;
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
    return false;
  }
  std::string maxVer;
  getStr("maxVersion", maxVer);
  if (maxVer == "TLSv1.2") ssl.maxVersion = TLS1_2_VERSION;
  if (maxVer == "TLSv1.3") ssl.maxVersion = TLS1_3_VERSION;
  if (!maxVer.empty() && ssl.maxVersion == 0) {
    iso->ThrowException(v8::Exception::Error(
        str(iso, "ssl.maxVersion must be 'TLSv1.2' or 'TLSv1.3'")));
    return false;
  }
  getBool("requestCert", ssl.requestCert);
  getBool("rejectUnauthorized", ssl.rejectUnauthorized);
  return true;
}

// Build and validate a TlsContext from a parsed config. Throws (and returns
// false) on incomplete or invalid material - a misconfigured TLS server must
// never silently boot as plaintext, and a bad update must never replace a
// working context.
static bool buildTlsContext(Isolate* iso, const SslConfig& ssl, TlsContext& out) {
  if (!ssl.complete()) {
    iso->ThrowException(v8::Exception::Error(str(iso,
        "ssl requires both a key (key or key_file_name) and a certificate "
        "(cert or cert_file_name)")));
    return false;
  }
  std::string err = out.init(ssl);
  if (!err.empty()) {
    iso->ThrowException(v8::Exception::Error(str(iso, ("ssl: " + err).c_str())));
    return false;
  }
  return true;
}

// Would this binary's TLS library take these ssl options? Returns "" when a
// context can be built from them, otherwise the message serve() would throw.
// The loader asks before it commits a thread to this binary: a configuration
// the bundled BoringSSL has no support for (a key type, a cipher suite, a
// group) is then served by the binary on node's OpenSSL instead of failing an
// app that ran on 1.1.19. Builds a context and throws it away; never throws.
// Not part of the API.
static void TlsCheck(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  std::string problem;
  if (args.Length() >= 1 && args[0]->IsObject()) {
    v8::TryCatch tc(iso);
    SslConfig ssl;
    TlsContext scratch;
    if (!parseSslOptions(iso, ctx, args[0].As<Object>(), ssl) ||
        !buildTlsContext(iso, ssl, scratch)) {
      problem = "the ssl options were not accepted";
      Local<Value> message;
      if (tc.HasCaught() && tc.Exception()->IsObject() &&
          tc.Exception().As<Object>()->Get(ctx, str(iso, "message")).ToLocal(&message) &&
          message->IsString()) {
        String::Utf8Value text(iso, message);
        if (*text) problem.assign(*text, text.length());
      }
      tc.Reset();
    }
  }
  args.GetReturnValue().Set(str(iso, problem));
}

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
  js->viaTrampoline = args.Length() >= 3 && args[2]->IsTrue();
  {
    const uintptr_t here = stackPosition();
    js->deepDispatchBelow = here > kDeepDispatchBytes ? here - kDeepDispatchBytes : 0;
  }
  // A getter or Proxy trap of the callbacks or options object that throws
  // fails serve() with that exception and nothing created. Carrying on would
  // build a server whose id the caller never receives, and so can never close.
  std::optional<TryCatch> optionErrors(std::in_place, iso);

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
    Local<Value> na;
    if (opts->Get(ctx, str(iso, "allowNonAsciiTarget")).ToLocal(&na) && na->IsBoolean()) {
      limits.allowNonAsciiTarget = na->BooleanValue(iso);
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

  // options.http2: true, or an object of HTTP/2 settings (camelCase, the
  // names Node's http2 uses). Unknown keys are ignored.
  if (args.Length() >= 2 && args[1]->IsObject()) {
    Local<Object> opts = args[1].As<Object>();
    Local<Value> h2v;
    if (opts->Get(ctx, str(iso, "http2")).ToLocal(&h2v)) {
      if (h2v->IsBoolean()) {
        limits.http2.enabled = h2v->BooleanValue(iso);
      } else if (h2v->IsObject()) {
        limits.http2.enabled = true;
        Local<Object> h2o = h2v.As<Object>();
        auto getU32 = [&](const char* name, uint32_t& out) {
          Local<Value> v;
          if (h2o->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsNumber()) {
            const double d = v->NumberValue(ctx).FromMaybe(-1);
            if (d >= 1 && d <= 2147483647.0) out = static_cast<uint32_t>(d);
          }
        };
        getU32("maxConcurrentStreams", limits.http2.maxConcurrentStreams);
        getU32("initialWindowSize", limits.http2.initialWindowSize);
        getU32("maxFrameSize", limits.http2.maxFrameSize);
        getU32("maxHeaderListSize", limits.http2.maxHeaderListSize);
        getU32("headerTableSize", limits.http2.headerTableSize);
      }
    }
  }

  if (optionErrors->HasCaught()) {
    delete js;
    optionErrors->ReThrow();
    return;
  }
  optionErrors.reset();

  // options.ssl -> in-process TLS termination. Both MoroJS shapes are accepted: file paths (key_file_name/cert_file_name/ca_file_name) and inline PEM (key/cert/ca as string|Buffer|ArrayBuffer); inline wins when both are present. Config errors THROW from serve() - a misconfigured TLS server must never silently boot as plaintext.
  SslConfig ssl;
  bool sslRequested = false;
  if (args.Length() >= 2 && args[1]->IsObject()) {
    Local<Object> opts = args[1].As<Object>();
    Local<Value> sslVal;
    if (opts->Get(ctx, str(iso, "ssl")).ToLocal(&sslVal) && sslVal->IsObject()) {
      sslRequested = true;
      TryCatch sslErrors(iso);  // a throwing getter of the ssl object, as above
      if (!parseSslOptions(iso, ctx, sslVal.As<Object>(), ssl) || sslErrors.HasCaught()) {
        delete js;
        sslErrors.ReThrow();
        return;
      }
      ssl.alpnH2 = limits.http2.enabled;  // offer "h2" ahead of "http/1.1"
    }
  }

  // Validate the TLS material BEFORE constructing the Server, so a config error throws cleanly with nothing to tear down.
  TlsContext tlsCtx;
  if (sslRequested && !buildTlsContext(iso, ssl, tlsCtx)) {
    delete js;
    return;
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
  scb.onWsBinaryOwned = cbOnWsBinaryOwned;
  scb.onWsClose = cbOnWsClose;
  scb.onWsRead = cbOnWsRead;

  js->server = new Server(loop, scb, limits);
  js->server->setDeferredNotify(g_notifyDeferred);
  js->server->setBatchDispatch(g_batchEnabled);
#if defined(__linux__)
  if (js->server->transportKind() == TransportKind::Uring && !threadState().uringHookRegistered) {
    threadState().uringHookRegistered = true;
    node::AddEnvironmentCleanupHook(iso, cleanupUringLoop, nullptr);
  }
  // A server that prefers io_uring runs on the epoll transport when its
  // thread cannot have a ring (Server::listen), or once its ring has died,
  // so that thread's epoll state needs its hook as well: the check handle
  // it owns would otherwise still be open when Node closes the loop.
  if ((js->server->transportKind() == TransportKind::Epoll ||
       js->server->transportKind() == TransportKind::Uring) &&
      !threadState().epollHookRegistered) {
    threadState().epollHookRegistered = true;
    node::AddEnvironmentCleanupHook(iso, cleanupEpollLoop, nullptr);
  }
#endif
  if (tlsCtx.valid()) js->server->adoptTls(std::move(tlsCtx));
  uint32_t id = ++threadState().serverIdCounter;
  js->id = id;
  threadState().servers[id] = js;
  // Removed again in freeJsServer when JS closes the server itself.
  node::AddEnvironmentCleanupHook(iso, cleanupJsServer, js);
  args.GetReturnValue().Set(Integer::NewFromUnsigned(iso, id));
}

static JsServer* serverFrom(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  uint32_t id = args[0]->Uint32Value(iso->GetCurrentContext()).FromMaybe(0);
  auto it = threadState().servers.find(id);
  return it == threadState().servers.end() ? nullptr : it->second;
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

// updateSsl(serverId, ssl) - certificate/key rotation without a restart.
// Builds and validates a NEW TLS context from a full ssl options object (the
// same shape serve() takes) and swaps it in for every handshake that starts
// afterwards. Connections that already handshaked keep the context they were
// created from (OpenSSL refcounts the SSL_CTX per SSL session), so in-flight
// requests and kept-alive sockets are untouched. Validation happens before
// the swap: a bad file, PEM or key/cert mismatch throws and the current
// context keeps serving. Session-ticket keys carry over when the update does
// not name new ones, so resumption survives a rotation. Throws for a server
// that was not started with ssl - TLS cannot be turned on after the fact.
static void UpdateSsl(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  JsServer* js = serverFrom(args);
  if (!js || !js->server) {
    iso->ThrowException(v8::Exception::Error(str(iso, "invalid serverId")));
    return;
  }
  if (!js->server->tlsEnabled()) {
    iso->ThrowException(v8::Exception::Error(
        str(iso, "updateSsl: this server was not started with ssl")));
    return;
  }
  if (args.Length() < 2 || !args[1]->IsObject()) {
    iso->ThrowException(v8::Exception::Error(
        str(iso, "updateSsl(serverId, ssl) requires an ssl options object")));
    return;
  }
  SslConfig ssl;
  if (!parseSslOptions(iso, ctx, args[1].As<Object>(), ssl)) return;
  const TlsContext& current = js->server->tls();
  if (ssl.ticketKeys.empty()) ssl.ticketKeys = current.ticketKeys();
  ssl.alpnH2 = current.alpnH2();
  TlsContext next;
  if (!buildTlsContext(iso, ssl, next)) return;
  js->server->adoptTls(std::move(next));
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
  if (c->rq->method == Method::OTHER) {
    args.GetReturnValue().Set(str(args.GetIsolate(), c->rq->methodStr));
  } else {
    args.GetReturnValue().Set(str(
        args.GetIsolate(), kMethodNames[static_cast<uint8_t>(c->rq->method)]));
  }
}

static void GetQuery(const FunctionCallbackInfo<Value>& args) {
  Connection* c = connFrom(args);
  args.GetReturnValue().Set(str(args.GetIsolate(), c ? c->rq->query : std::string()));
}

static void GetHeaders(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = connFrom(args);
  if (!c) { args.GetReturnValue().Set(Array::New(iso, 0)); return; }
  // Array::New's length is an int and is only a capacity hint (Set() below
  // grows the array by index regardless). Clamp the hint so headers.size()*2
  // can't cast negative if a config raised maxHeaders past 2 GiB.
  size_t hint = c->rq->headers.size() * 2;
  if (hint > static_cast<size_t>(INT_MAX)) hint = static_cast<size_t>(INT_MAX);
  Local<Array> arr = Array::New(iso, static_cast<int>(hint));
  JsServer* js = jsServerFor(c->server);
  uint32_t idx = 0;
  for (const Header h : c->rq->headers) {
    // Names come from a small bounded set in practice - serve them from the
    // per-server interning cache (same pattern and lifetime as pathCache).
    Local<String> nameStr;
    if (js && h.name.size() <= JsServer::kHeaderNameCacheMaxLen) {
      if (Global<String>* cached = js->headerNameCache.find(h.name)) {
        nameStr = cached->Get(iso);
      } else {
        nameStr = str(iso, h.name);
        if (js->headerNameCache.size() < JsServer::kHeaderNameCacheMaxEntries) {
          js->headerNameCache.insert(h.name, Global<String>(iso, nameStr));
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
  if (args.Length() < 2) return;
  // The name is read first: converting it can run JavaScript (toString),
  // which can end the request the lookup below would otherwise have found.
  String::Utf8Value name(iso, args[1]);
  if (*name == nullptr) return;
  Connection* c = connFrom(args);
  if (!c) return;
  // The snapshot (c->rq->headers) is the source of truth; the parser has already moved its fields out and may have been reset for the next request.
  for (const auto& h : c->rq->headers) {
    if (h.name.size() == static_cast<size_t>(name.length()) &&
        iequals(h.name, std::string_view(*name, name.length()))) {
      args.GetReturnValue().Set(str(iso, h.value));
      return;
    }
  }
}

// The body is handed over without a copy: the connection's string moves to a
// holder that becomes the ArrayBuffer's backing store, freed when JS lets go
// of it. A plain V8 backing store, deliberately not node::Buffer::New's
// free-callback form: that one books the bytes as external memory, and at
// 10 KB a request the 64 MB external budget forced a full mark-compact every
// few thousand requests (a tenth of the worker's CPU in marking). This way
// the buffer dies in the scavenge like any young object. The storage stays
// on the connection until the next request, so a second call returns the
// same bytes again - the same storage, not a snapshot.
static void FreeBodyHolder(void*, size_t, void* hint) { delete static_cast<std::string*>(hint); }

// A body on loan to JS (getBodyLent, below): the ArrayBuffer to detach when
// the request is done.
struct LentBody {
  Isolate* iso;
  v8::Global<ArrayBuffer> buffer;
  std::string* holder;  // the bytes; owned by the buffer's backing store
  Server* server;       // whose body-buffer pool they came from
};

static void GetBody(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) {
    args.GetReturnValue().SetNull();
    return;
  }
  if (c->rq->jsBody) {
    args.GetReturnValue().Set(
        ArrayBuffer::New(iso, std::static_pointer_cast<BackingStore>(c->rq->jsBody)));
    return;
  }
  if (c->rq->jsLent) {
    // The bytes are on loan (getBodyLent) and will be taken back with the
    // request: this caller, who asked for bytes to keep, gets its own copy.
    // Nothing is left to copy once JS has transferred the loan away.
    Local<ArrayBuffer> lent = static_cast<LentBody*>(c->rq->jsLent.get())->buffer.Get(iso);
    const size_t n = lent->ByteLength();
    if (n == 0) {
      args.GetReturnValue().SetNull();
      return;
    }
    Local<ArrayBuffer> copy = ArrayBuffer::New(iso, n);
    memcpy(copy->Data(), lent->Data(), n);
    args.GetReturnValue().Set(copy);
    return;
  }
  if (c->rq->body.empty()) {
    args.GetReturnValue().SetNull();
    return;
  }
  auto* holder = new std::string(std::move(c->rq->body));
  c->rq->body.clear();
  std::shared_ptr<BackingStore> store = ArrayBuffer::NewBackingStore(
      holder->data(), holder->size(), FreeBodyHolder, holder);
  c->rq->jsBody = std::static_pointer_cast<void>(store);
  args.GetReturnValue().Set(ArrayBuffer::New(iso, std::move(store)));
}

// getBodyType(reqId) -> the request's Content-Type, '' when it has a body but
// no such header, null when it has no body at all. What an adapter needs to
// decide how to read the body, in the one call it made for the header anyway.
static void GetBodyType(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c || (c->rq->body.empty() && !c->rq->jsBody && !c->rq->jsLent)) {
    args.GetReturnValue().SetNull();
    return;
  }
  for (const auto& h : c->rq->headers) {
    if (h.name.size() == 12 && iequals(h.name, std::string_view("content-type", 12))) {
      args.GetReturnValue().Set(str(iso, h.value));
      return;
    }
  }
  args.GetReturnValue().Set(String::Empty(iso));
}

// getBodyText(reqId) -> the body as a string when every byte of it is ASCII,
// null otherwise (the caller reads it with getBody). An ASCII body is its own
// text in UTF-8 and in Latin-1, so the one string serves both as the decoded
// text and, read back as Latin-1, as the exact bytes received.
//
// It is an ordinary heap string: allocated in the young generation and gone
// at the next scavenge. The ArrayBuffer getBody returns keeps its bytes
// outside the heap, and V8 counts external bytes against the old-generation
// limit from the moment they are allocated until a collection frees them; a
// server reading a few kilobytes of body per request therefore ran a full
// mark-compact every few thousand requests however short-lived each body
// was. A JSON or form body, which the adapter turns into a string before
// anything else, never needed to exist as a buffer at all.
static void GetBodyText(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c || c->rq->jsBody || c->rq->jsLent ||
      c->rq->body.size() > static_cast<size_t>(v8::String::kMaxLength) ||
      !text::isAscii(reinterpret_cast<const uint8_t*>(c->rq->body.data()), c->rq->body.size())) {
    args.GetReturnValue().SetNull();
    return;
  }
  Local<String> out;
  if (!String::NewFromOneByte(iso, reinterpret_cast<const uint8_t*>(c->rq->body.data()),
                              v8::NewStringType::kNormal, static_cast<int>(c->rq->body.size()))
           .ToLocal(&out)) {
    args.GetReturnValue().SetNull();
    return;
  }
  args.GetReturnValue().Set(out);
}

// getBodyLent(reqId) -> the body as an ArrayBuffer that is detached when the
// response is complete (or the request is aborted): its length becomes 0 and
// every view over it is empty. The bytes are the connection's own, moved into
// the buffer and never copied, and they are released at that moment rather
// than whenever a collection gets to them.
//
// That is the whole difference from getBody, and it is what matters under
// load. V8 counts an ArrayBuffer's bytes as external memory from the moment
// it is created until a collection frees it, and counts them against the
// old-generation limit; a server reading ten kilobytes of body per request
// ran a full mark-compact every few thousand requests, however short-lived
// each body was. A body released with its request never accumulates.
//
// It is the right read for a handler that relays, hashes or echoes a body
// and keeps none of it. Code that keeps the body past the response reads it
// with getBody (which, during a loan, returns a copy), or transfers the lent
// buffer (ArrayBuffer.prototype.transfer, a transfer list): the bytes then
// belong to the new owner and the engine's detach finds nothing left to take.
static void ReleaseLentBody(void* p) {
  LentBody* lent = static_cast<LentBody*>(p);
  if (!lent->buffer.IsEmpty()) {
    Isolate* iso = lent->iso;
    HandleScope scope(iso);
    Local<ArrayBuffer> buffer = lent->buffer.Get(iso);
    // Already detached when JS transferred it away: the bytes are the new
    // owner's. Otherwise the buffer gives up its reference here, and when
    // that leaves this one the only reference there is, their storage goes
    // back to the server's pool for the next body (the holder is freed
    // empty). Anything else that holds the store itself keeps the bytes for
    // as long as it needs them. That does not cover Node's own asynchronous
    // operations (an fs or socket write, a zlib or crypto job): they keep a
    // pointer into the memory and a reference to the JS object, not the
    // store, so one still running here goes on to read the next body. The
    // caller has to let them finish before it completes the response
    // (docs/API.md says so); nothing here can see them.
    if (!buffer->WasDetached()) {
      std::shared_ptr<BackingStore> store = buffer->GetBackingStore();
      (void)buffer->Detach(Local<Value>());
      if (store.use_count() == 1) lent->server->returnBodyBuffer(*lent->holder);
    }
    lent->buffer.Reset();
  }
  delete lent;
}

static void GetBodyLent(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) {
    args.GetReturnValue().SetNull();
    return;
  }
  if (c->rq->jsLent) {
    args.GetReturnValue().Set(static_cast<LentBody*>(c->rq->jsLent.get())->buffer.Get(iso));
    return;
  }
  if (c->rq->jsBody) {
    // Already handed over for keeps: the same bytes, and nothing to lend.
    args.GetReturnValue().Set(
        ArrayBuffer::New(iso, std::static_pointer_cast<BackingStore>(c->rq->jsBody)));
    return;
  }
  if (c->rq->body.empty()) {
    args.GetReturnValue().SetNull();
    return;
  }
  auto* holder = new std::string(std::move(c->rq->body));
  c->rq->body.clear();
  Local<ArrayBuffer> buffer = ArrayBuffer::New(
      iso, ArrayBuffer::NewBackingStore(holder->data(), holder->size(), FreeBodyHolder, holder));
  auto* lent = new LentBody{iso, v8::Global<ArrayBuffer>(iso, buffer), holder, c->server};
  c->rq->jsLent = std::shared_ptr<void>(static_cast<void*>(lent), ReleaseLentBody);
  args.GetReturnValue().Set(buffer);
}

static void GetRemoteAddress(const FunctionCallbackInfo<Value>& args) {
  Connection* c = connFrom(args);
  if (!c) return;
  args.GetReturnValue().Set(str(args.GetIsolate(), c->server->remoteAddress(c)));
}

static void IsAborted(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kIsAborted];
  Connection* c = connFrom(args);
  args.GetReturnValue().Set(c == nullptr);  // gone from registry == aborted/ended
}

// respond(reqId, status, headersFlat|null, body|null)
static void Respond(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  int status = args[1]->Int32Value(ctx).FromMaybe(200);
  HeaderBlockLease headersLease;
  std::string& headers = headersLease.get();
  long long customCL = -1;
  buildHeaders(iso, ctx, args[2], headers, customCL);
  // The request is looked up AFTER the status and the headers have been
  // read. Both can run arbitrary JS (valueOf, array getters, toString), and
  // that JS can answer this very request or close its connection: a
  // Connection found before it ran may by now be on its next request, or -
  // an HTTP/2 request - back in the pool with no socket behind it.
  Connection* c = connFrom(args);
  if (!c) return;
  // The body borrow is taken AFTER buildHeaders for the same reason: that JS
  // could detach an ArrayBuffer out from under an earlier borrow. Both stay
  // on this stack through the respond() call.
  ByteSource body(iso, args[3]);
  c->server->respond(c, status, headers, customCL, body.data(), body.size());
}

// writeHead(reqId, status, headersFlat|null)
static void WriteHead(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  int status = args[1]->Int32Value(ctx).FromMaybe(200);
  HeaderBlockLease headersLease;
  std::string& headers = headersLease.get();
  long long customCL = -1;
  buildHeaders(iso, ctx, args[2], headers, customCL);
  // Looked up after the arguments have been read (see Respond).
  Connection* c = connFrom(args);
  if (!c) return;
  c->server->writeHead(c, status, headers, customCL);
}

// write(reqId, chunk) -> boolean backpressure
static void Write(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kWrite];
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
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kEnd];
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

// setParamRoute(serverId, methodIdx, prefix, suffix, status, headersFlat|null)
//
// A route with one variable path segment whose body is that segment,
// answered inside the engine like a static route: `/user/:id` is prefix
// "/user/" and suffix "". The header block is materialised HERE, once, with
// the same buildHeaders() respond() uses, so the reply is byte-identical to
// respond(status, headersFlat, segment) without the JS round trip.
// Re-registering the same (method, prefix, suffix) replaces it.
static void SetParamRoute(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  JsServer* js = serverFrom(args);
  if (!js || !js->server) return;
  if (args.Length() < 4 || !args[2]->IsString() || !args[3]->IsString()) {
    iso->ThrowException(
        str(iso, "setParamRoute(serverId, method, prefix, suffix, status, headers)"));
    return;
  }

  const int32_t method = args[1]->Int32Value(ctx).FromMaybe(0);
  ResponseTemplate tpl;
  tpl.status = args.Length() > 4 ? args[4]->Int32Value(ctx).FromMaybe(200) : 200;

  String::Utf8Value prefixV(iso, args[2]);
  String::Utf8Value suffixV(iso, args[3]);
  if (!*prefixV || !*suffixV) return;
  std::string prefix(*prefixV, static_cast<size_t>(prefixV.length()));
  std::string suffix(*suffixV, static_cast<size_t>(suffixV.length()));

  buildHeaders(iso, ctx, args.Length() > 5 ? args[5] : Local<Value>(), tpl.headers,
               tpl.customCL);
  js->server->setParamRoute(method, std::move(prefix), std::move(suffix), std::move(tpl));
}

// clearParamRoutes(serverId) - drops every parameter route on this server.
static void ClearParamRoutes(const FunctionCallbackInfo<Value>& args) {
  JsServer* js = serverFrom(args);
  if (js && js->server) js->server->clearParamRoutes();
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
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kRespondPrepared];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  // The id first: its conversion can run JS (valueOf), see Respond.
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  Connection* c = connFrom(args);
  if (!c) return;
  ByteSource body(iso, args[2]);
  c->server->respondTemplate(c, tplId, body.data(), body.size());
}

// respondPreparedEmpty(reqId, tplId) - respond() with a template and no body.
static void RespondPreparedEmpty(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kRespondPreparedEmpty];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  Connection* c = connFrom(args);
  if (!c) return;
  c->server->respondTemplate(c, tplId, nullptr, 0);
}

// writeHeadPrepared(reqId, tplId) - writeHead() with a template (streaming).
static void WriteHeadPrepared(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kWriteHeadPrepared];
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  const uint32_t tplId = args[1]->Uint32Value(ctx).FromMaybe(0);
  Connection* c = connFrom(args);
  if (!c) return;
  c->server->writeHeadTemplate(c, tplId);
}

// endWith(reqId, chunk) - exactly end(reqId, chunk), as a fixed-arity twin so
// a call site that always passes a chunk has one shape (fast-call eligible).
static void EndWith(const FunctionCallbackInfo<Value>& args) {
  if (g_countCalls) ++fastcall::slowHits()[fastcall::kEndWith];
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
  // Borrowed under deferred notification, like the HTTP response bytes: the
  // one way wsSend() used to reach JS from inside the call - shedding a
  // stalled peer through onWsClose - is queued to a later loop turn now
  // (Server::kNotifyWsShed), so nothing can run JS or move the string while
  // the engine copies the payload into its frame. Sync mode still copies.
  ByteSource data(iso, args[1]);
  // A payload that is not a string or bytes (a number, an object, undefined)
  // cannot be sent, and the answer says so: false, as for any frame that
  // did not go out.
  bool ok = false;
  if (data.valid()) ok = c->server->wsSend(c, data.data(), data.size(), isBinary);
  args.GetReturnValue().Set(ok);
}

// wsClose(wsId, code?, reason?)
static void WsClose(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = wsFrom(args);
  if (!c) return;
  // Kept as the integer it is: narrowed to the 16 bits of the wire field
  // here, 70000 would turn into the unrelated 4464. Server::wsClose decides
  // what a value that may not be sent becomes.
  int code = 1000;  // normal closure (§7.4.1)
  if (args.Length() >= 2 && args[1]->IsNumber())
    code = args[1]->Int32Value(ctx).FromMaybe(1000);
  std::string reason;
  if (args.Length() >= 3 && args[2]->IsString()) {
    String::Utf8Value r(iso, args[2]);
    if (*r) reason.assign(*r, r.length());
  }
  c->server->wsClose(c, code, reason.data(), reason.size());
}

// setWsAutoUpgrade(serverId, on): the engine performs valid WebSocket
// upgrades itself (capabilities.wsAutoUpgrade). Re-applied by the caller
// after close() + serve(), like static routes.
static void SetWsAutoUpgrade(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  JsServer* js = serverFrom(args);
  if (!js || !js->server) return;
  js->server->setWsAutoUpgrade(args.Length() >= 2 && args[1]->BooleanValue(iso));
}

// wsGetHeaders(wsId) -> flat [name, value, ...] of the handshake request,
// names lowercased (the same shape getHeaders() gives a request), or
// undefined once the socket is gone.
static void WsGetHeaders(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Connection* c = wsFrom(args);
  if (!c) return;
  const auto& headers = c->server->wsHeaders(c);
  size_t hint = headers.size() * 2;
  if (hint > static_cast<size_t>(INT_MAX)) hint = static_cast<size_t>(INT_MAX);
  Local<Array> arr = Array::New(iso, static_cast<int>(hint));
  uint32_t idx = 0;
  for (const auto& h : headers) {
    (void)arr->Set(ctx, idx++, str(iso, h.name)).FromMaybe(false);
    (void)arr->Set(ctx, idx++, str(iso, h.value)).FromMaybe(false);
  }
  args.GetReturnValue().Set(arr);
}

// wsGetQuery(wsId) -> the handshake request's raw query string ('' when none).
static void WsGetQuery(const FunctionCallbackInfo<Value>& args) {
  Connection* c = wsFrom(args);
  if (!c) return;
  args.GetReturnValue().Set(str(args.GetIsolate(), c->server->wsQuery(c)));
}

// wsGetRemoteAddress(wsId) -> the peer's address, as getRemoteAddress() gives it.
// trimMemory(): give back what this thread's start-up left behind. V8 is
// told memory is low, which collects everything collectable and shrinks the
// heap to what is live (the young generation back to its smallest size, free
// pages unmapped); glibc is then asked to return the free pages of its
// arenas. A heap that has just loaded an application holds about as much
// committed-and-free as it holds live, and nothing gives that back while the
// process is quiet: a server waiting for requests keeps it for good, once
// per isolate. One synchronous collection, so it belongs after start-up and
// not on a request path; the heap grows again as load needs it.
static void TrimMemory(const FunctionCallbackInfo<Value>& args) {
  args.GetIsolate()->LowMemoryNotification();
#if defined(__GLIBC__)
  malloc_trim(0);
#endif
}

static void WsGetRemoteAddress(const FunctionCallbackInfo<Value>& args) {
  Connection* c = wsFrom(args);
  if (!c) return;
  args.GetReturnValue().Set(str(args.GetIsolate(), c->server->remoteAddress(c)));
}

// A batch buffer JS transferred away (ArrayBuffer.prototype.transfer,
// structuredClone or postMessage with a transfer list) is detached, and its
// storage belongs to whoever received it. The engine moves to new storage of
// its own - the current contents copied over, so a batch in flight reads on
// from the new views - and stops writing into the storage that was given
// away. Asked by getBatchBuffers() only, never per request.
static void renewTransferredBatchBuffers(JsServer* js, Isolate* iso) {
  constexpr size_t kDescBytes = 3 * Server::kMaxStaged * sizeof(uint32_t);
  if (js->batchDesc.Get(iso)->ByteLength() != kDescBytes) {
    Local<ArrayBuffer> d = ArrayBuffer::New(iso, kDescBytes);
    std::shared_ptr<BackingStore> store = d->GetBackingStore();
    std::memcpy(store->Data(), js->desc, kDescBytes);
    js->desc = static_cast<uint32_t*>(store->Data());
    js->batchDescStore = std::move(store);
    js->batchDesc.Reset(iso, d);
  }
  if (js->batchCtl.Get(iso)->ByteLength() != sizeof(uint32_t)) {
    Local<ArrayBuffer> c = ArrayBuffer::New(iso, sizeof(uint32_t));
    std::shared_ptr<BackingStore> store = c->GetBackingStore();
    *static_cast<uint32_t*>(store->Data()) = *js->ctl;
    js->ctl = static_cast<uint32_t*>(store->Data());
    js->batchCtlStore = std::move(store);
    js->batchCtl.Reset(iso, c);
    if (js->server) js->server->setBatchControl(js->ctl);
  }
}

// getBatchBuffers(serverId) -> { descriptors: Uint32Array(3*16), control:
// Uint32Array(1), paths: string[] }: views of the same storage every call
// (new storage once JS has transferred the old away).
static void GetBatchBuffers(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  uint32_t id = args[0]->Uint32Value(ctx).FromMaybe(0);
  auto it = threadState().servers.find(id);
  if (it == threadState().servers.end()) {
    iso->ThrowException(v8::Exception::RangeError(str(iso, "getBatchBuffers: unknown serverId")));
    return;
  }
  JsServer* js = it->second;
  ensureBatchBuffers(js, iso, ctx);
  renewTransferredBatchBuffers(js, iso);
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
  args.GetReturnValue().Set(str(iso, c->rq->path));
}

// ---- diagnostics ----

// True for the first caller in the process, false for every other (any
// thread). The loader uses it so the one notice about an old bundled TLS
// library is printed once, not once per worker thread. Not part of the API.
static void TlsAgeNoticeOnce(const FunctionCallbackInfo<Value>& args) {
  static std::atomic<bool> noticed{false};
  args.GetReturnValue().Set(!noticed.exchange(true, std::memory_order_relaxed));
}

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
  // serve() option `http2`: HTTP/2 by ALPN on a TLS listener and by prior
  // knowledge on a cleartext one, HTTP/1.1 beside it on the same port.
  setCap("http2", true);
  setCap("wsDeflate", true);
  // Hardening surface: responseTimeoutMs / responseBackpressureLimit /
  // maxUriSize serve options are parsed.
  setCap("responseLimits", true);
  // ssl.ciphers / ssl.ciphersuites / ssl.ecdhCurve are parsed.
  setCap("tlsPolicy", true);
  // updateSsl(serverId, ssl) swaps the certificate/key for new handshakes.
  setCap("tlsReload", true);
  // ssl.crl (client-certificate revocation lists) and ssl.maxVersion are
  // honoured; an engine without this flag reads neither.
  setCap("tlsCrl", true);
  // setStaticRoute()/clearStaticRoutes() are available.
  setCap("staticRoutes", true);
  // setParamRoute()/clearParamRoutes() are available: one variable path
  // segment echoed as the body, answered inside the engine.
  setCap("paramRoutes", true);
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
  // setWsAutoUpgrade(serverId, on): valid WebSocket handshakes are answered by
  // the engine itself (onWsOpen, never onRequest), with wsGetHeaders()/
  // wsGetQuery()/wsGetRemoteAddress() reading the handshake afterwards.
  setCap("wsAutoUpgrade", true);
  // A handshake the engine answers itself may sit behind pipelined requests
  // in a batch: it is upgraded once the onRequestBatch call has returned,
  // never from inside the response call that completed the request ahead of
  // it. Engines that report wsAutoUpgrade and batchDispatch without this
  // flag (1.1.15 to 1.1.21) must not be given both.
  setCap("wsAutoUpgradeBatch", true);
  // trimMemory() exists.
  setCap("memoryTrim", true);
  // A connection between requests holds no parser and no request buffers
  // (Server::rest): what a held keep-alive connection costs is its socket.
  setCap("restingConnections", true);
  // idleTimeoutMs does not close a connection whose response is still being
  // written to a peer that is reading it; responseTimeoutMs governs that
  // (Server::onSweep). Engines without this flag count a response answered
  // inside a batch as idle from the moment it is framed, so an idle timeout
  // shorter than a slow download cuts the download.
  setCap("idleSparesDrainingResponse", true);
  // getBodyType()/getBodyText(): the body's media type, and an all-ASCII
  // body as a heap string.
  setCap("bodyText", true);
  // getBodyLent(): the body as an ArrayBuffer released with the request.
  setCap("bodyLent", true);
  set("capabilities", caps);
  // The TLS library this binary terminates TLS with: "boringssl" (carried in
  // the addon; `version` is the upstream tag it was pinned to) or "openssl"
  // (the host node's; `version` is that library's own).
  {
    Local<Object> tls = Object::New(iso);
    (void)tls->Set(ctx, str(iso, "library"), str(iso, tlsLibraryName())).FromMaybe(false);
    (void)tls->Set(ctx, str(iso, "version"), str(iso, tlsLibraryVersion())).FromMaybe(false);
    set("tls", tls);
  }
  set("notify", str(iso, g_notifyDeferred ? "deferred" : "sync"));
#if defined(MORO_ENGINE_TEST_FAULTS)
  // A test build (tools/build.mjs --sanitize): the fault points of src/tls.h
  // are compiled in. Not a capability, and no shipped binary reports it.
  set("testFaults", v8::Boolean::New(iso, true));
#endif
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
  {
    // The connections this thread's servers hold, and how many of them are
    // at rest (between requests: no parser, no request buffers).
    size_t open = 0, resting = 0;
    for (const auto& entry : threadState().servers) {
      const JsServer* js = entry.second;
      if (js == nullptr || js->server == nullptr) continue;
      open += js->server->openConnections();
      resting += js->server->restingConnections();
    }
    Local<Object> conns = Object::New(iso);
    (void)conns->Set(ctx, str(iso, "open"), Number::New(iso, static_cast<double>(open))).FromMaybe(false);
    (void)conns->Set(ctx, str(iso, "resting"), Number::New(iso, static_cast<double>(resting))).FromMaybe(false);
    set("connections", conns);
  }
  if (g_countCalls) {
    // Per-thread fast/slow hit counters (MORO_ENGINE_FASTCALL_STATS=1 at load).
    Local<Object> stats = Object::New(iso);
    for (int i = 0; i < fastcall::kCount; ++i) {
      Local<Object> pair = Object::New(iso);
      (void)pair->Set(ctx, str(iso, "fast"), Number::New(iso, static_cast<double>(fastcall::fastHits()[i]))).FromMaybe(false);
      (void)pair->Set(ctx, str(iso, "slow"), Number::New(iso, static_cast<double>(fastcall::slowHits()[i]))).FromMaybe(false);
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
static const v8::CFunction kFast_BatchDone = v8::CFunction::Make(&FastBatchDone);
#define MORO_FAST_BATCH_DONE &kFast_BatchDone, &kFast_BatchDone
#else
#define MORO_FAST(Name) nullptr, nullptr
#define MORO_FAST_BATCH_DONE nullptr, nullptr
#endif

static const ExportDef kExports[] = {
    {"serve", Serve, nullptr, nullptr},
    {"listen", Listen, nullptr, nullptr},
    {"close", Close, nullptr, nullptr},
    {"stopListening", StopListening, nullptr, nullptr},
    {"updateSsl", UpdateSsl, nullptr, nullptr},
    {"getMethod", GetMethod, nullptr, nullptr},
    {"getBatchBuffers", GetBatchBuffers, nullptr, nullptr},
    {"getPath", GetPath, nullptr, nullptr},
    {"getQuery", GetQuery, nullptr, nullptr},
    {"getHeaders", GetHeaders, nullptr, nullptr},
    {"getHeader", GetHeader, nullptr, nullptr},
    {"getBody", GetBody, nullptr, nullptr},
    {"getBodyType", GetBodyType, nullptr, nullptr},
    {"getBodyText", GetBodyText, nullptr, nullptr},
    {"getBodyLent", GetBodyLent, nullptr, nullptr},
    {"getRemoteAddress", GetRemoteAddress, nullptr, nullptr},
    {"isAborted", IsAborted, MORO_FAST(IsAborted)},
    {"respond", Respond, nullptr, nullptr},
    {"writeHead", WriteHead, nullptr, nullptr},
    {"write", Write, MORO_FAST(Write)},
    {"end", End, MORO_FAST(End)},
    {"setStaticRoute", SetStaticRoute, nullptr, nullptr},
    {"clearStaticRoutes", ClearStaticRoutes, nullptr, nullptr},
    {"setParamRoute", SetParamRoute, nullptr, nullptr},
    {"clearParamRoutes", ClearParamRoutes, nullptr, nullptr},
    {"prepareResponse", PrepareResponse, nullptr, nullptr},
    {"releaseTemplates", ReleaseTemplates, nullptr, nullptr},
    {"respondPrepared", RespondPrepared, MORO_FAST(RespondPrepared)},
    {"respondPreparedEmpty", RespondPreparedEmpty, MORO_FAST(RespondPreparedEmpty)},
    {"writeHeadPrepared", WriteHeadPrepared, MORO_FAST(WriteHeadPrepared)},
    {"endWith", EndWith, MORO_FAST(EndWith)},
    {"upgradeToWebSocket", UpgradeToWebSocket, nullptr, nullptr},
    {"wsSend", WsSend, nullptr, nullptr},
    {"wsClose", WsClose, nullptr, nullptr},
    {"setWsAutoUpgrade", SetWsAutoUpgrade, nullptr, nullptr},
    {"wsGetHeaders", WsGetHeaders, nullptr, nullptr},
    {"wsGetQuery", WsGetQuery, nullptr, nullptr},
    {"wsGetRemoteAddress", WsGetRemoteAddress, nullptr, nullptr},
    {"trimMemory", TrimMemory, nullptr, nullptr},
    {"probe", Probe, nullptr, nullptr},
    // Loader-internal (leading underscore: not in NATIVE_API, not typed).
    {"_batchDone", BatchDone, MORO_FAST_BATCH_DONE},
    {"_reportCaught", ReportCaught, nullptr, nullptr},
    {"_tlsAgeNoticeOnce", TlsAgeNoticeOnce, nullptr, nullptr},
    {"_tlsCheck", TlsCheck, nullptr, nullptr},
};
#undef MORO_FAST

static void Initialize(Local<Object> exports, Local<Value> module,
                       Local<Context> context) {
  // Context::GetIsolate() was removed in V8 14 (Node 26); GetCurrent() is stable
  Isolate* iso = Isolate::GetCurrent();

  // The switches below are process-wide and every thread reads them on its
  // request path, so they are settled by the first load and never written
  // again: a worker thread loading the addon later runs this function too,
  // and by then the main thread may have changed the environment
  // (process.env writes through to it). Fast calls installed on one thread
  // rely on deferred notification staying what it was when they went in.
  static std::once_flag processSwitches;
  std::call_once(processSwitches, [] {
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
  });

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

// The same initialiser under the name Node looks up when loading the binary
// did not run the static registration above. That is the case when the
// library is still mapped from an earlier load that has been closed since: a
// worker thread loaded the engine and ended, nothing else in the process
// holds it, and the platform kept the image (macOS does, for a library with
// thread-local state). The next thread to load it was refused with "Module
// did not self-register"; with the symbol it is initialised like the first.
extern "C" NODE_MODULE_EXPORT void NODE_MODULE_INITIALIZER(v8::Local<v8::Object> exports,
                                                           v8::Local<v8::Value> module,
                                                           v8::Local<v8::Context> context) {
  moro::engine::Initialize(exports, module, context);
}
