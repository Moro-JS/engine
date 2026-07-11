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

#include <optional>
#include <string>
#include <unordered_map>

#include "server.h"
#include "win_delay_load_hook.h"

namespace moro {
namespace engine {

// Build-time fallback only. The published package version is authoritative:
// the JS loader (packages/engine/index.js) reads it from package.json and
// overrides this in probe() and on `.version`. Keep it roughly in step, but the
// loader is the source of truth, so this never has to be bumped by hand.
static const char* kEngineVersion = "1.1.2";

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
  Global<Function> onAborted;
  Global<Function> onWritable;
  Global<Function> onWsOpen;
  Global<Function> onWsMessage;
  Global<Function> onWsClose;
  Server* server;
  uint32_t id = 0;
  // Interned per-path JS strings: real apps route a BOUNDED set of paths, so
  // the per-request String::NewFromUtf8 (allocation + GC pressure) is paid
  // once per unique path instead of once per request. Bounded: only paths
  // <= kPathCacheMaxLen are cached and at most kPathCacheMaxEntries live here
  // (past the cap, requests simply build the string per-call as before), so
  // an adversary spraying unique URLs can't grow it. Freed with the JsServer.
  std::unordered_map<std::string, Global<String>> pathCache;
  static constexpr size_t kPathCacheMaxEntries = 512;
  static constexpr size_t kPathCacheMaxLen = 128;
};

// thread_local, not process-global: worker_threads + reusePort (see
// HttpLimits::reusePort) runs one engine per thread, each with its own uv loop
// and servers, and a serverId only ever crosses the JS<->C++ boundary on the
// thread that created it - per-thread registries are race-free without locks.
static thread_local std::unordered_map<uint32_t, JsServer*> g_servers;
static thread_local uint32_t g_serverIdCounter = 0;

// Invoked by Server once it is fully closed and self-deleted. Releases the
// per-server JS state (the Global<> destructors Reset the handles, unpinning
// the callbacks/context for GC) and drops the registry entry - no leak across
// serve()/close() cycles. Must NOT touch js->server (already deleted).
static void freeJsServer(void* user) {
  JsServer* js = static_cast<JsServer*>(user);
  g_servers.erase(js->id);
  delete js;
}

// ---- helpers ----

static Local<String> str(Isolate* iso, const std::string& s) {
  return String::NewFromUtf8(iso, s.c_str(), v8::NewStringType::kNormal,
                             static_cast<int>(s.size()))
      .ToLocalChecked();
}
static Local<String> str(Isolate* iso, const char* s) {
  return String::NewFromUtf8(iso, s).ToLocalChecked();
}

// Borrowed, zero-copy view of a JS value's bytes (string | ArrayBuffer |
// TypedArray | DataView). A string's UTF-8 lives in the owned Utf8Value
// member; ArrayBuffer backing stores are external allocations whose data
// pointer is stable while no JS runs (nothing can detach the buffer under
// the borrow). valid() is false for null/undefined (no byte content).
// Safe to pass into Server::respond/write/end/wsSend: those copy the bytes
// into engine-owned buffers (Connection::scratch / corkBuf / the TLS
// ciphertext buffer / a queued WriteReq - see respond/appendResponse/
// writeOutView in server.h) before any JS re-entry, so the borrow never
// outlives this stack frame.
class ByteSource {
 public:
  ByteSource(Isolate* iso, Local<Value> v) {
    if (v->IsString()) {
      // String::Utf8Value is stable across V8 versions (Node 20..26); the
      // direct Utf8Length/WriteUtf8 API changed shape in V8 14 (Node 26).
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
  bool valid() const { return valid_; }
  // data() is null only when size() == 0 (null/undefined, an empty
  // ArrayBuffer, or a string whose UTF-8 conversion failed) - callers may
  // pass (data(), size()) through unconditionally.
  const char* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  std::optional<String::Utf8Value> utf8_;
  const char* data_ = nullptr;
  size_t size_ = 0;
  bool valid_ = false;
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
  for (uint32_t i = 0; i + 1 < n; i += 2) {
    Local<Value> kv, vv;
    if (!arr->Get(ctx, i).ToLocal(&kv)) continue;
    if (!arr->Get(ctx, i + 1).ToLocal(&vv)) continue;
    String::Utf8Value k(iso, kv);
    String::Utf8Value val(iso, vv);
    if (*k == nullptr) continue;
    if (!validHeaderName(*k, k.length())) continue;
    if (*val && !validHeaderValue(*val, val.length())) continue;
    // Drop headers the engine owns or that are hop-by-hop: letting an app emit
    // Transfer-Encoding/Connection/Date/Keep-Alive would duplicate or conflict
    // with the framing the server writes itself (a Transfer-Encoding from the
    // app alongside the engine's Content-Length is a smuggling-grade ambiguity).
    if (headerNameIs(*k, k.length(), "transfer-encoding") ||
        headerNameIs(*k, k.length(), "connection") ||
        headerNameIs(*k, k.length(), "keep-alive") ||
        headerNameIs(*k, k.length(), "date")) {
      continue;
    }
    // Case-insensitive check for content-length
    if (k.length() == 14) {
      bool match = headerNameIs(*k, k.length(), "content-length");
      if (match) {
        // Parse strictly as decimal digits; anything else is ignored and the
        // server computes the length itself.
        long long parsed = 0;
        bool ok = *val != nullptr && val.length() > 0 && val.length() <= 18;
        for (int j = 0; ok && j < val.length(); ++j) {
          const char d = (*val)[j];
          if (d < '0' || d > '9') ok = false;
          else parsed = parsed * 10 + (d - '0');
        }
        if (ok) customCL = parsed;
        continue;  // never copied into the block
      }
    }
    block.append(*k, k.length());
    block.append(": ");
    if (*val) block.append(*val, val.length());
    block.append("\r\n");
  }
}

// ---- Server-side callbacks that trampoline into JS ----

static void invokeJs(JsServer* js, Global<Function>& fn, Connection* c,
                     bool withExtra, int32_t methodIdx, const std::string& path) {
  if (fn.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope ctxScope(ctx);
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
        Integer::NewFromUnsigned(iso, c->reqId),
        Integer::New(iso, methodIdx),
        pathStr,
    };
    (void)f->Call(ctx, ctx->Global(), 3, argv);
  } else {
    Local<Value> argv[1] = {Integer::NewFromUnsigned(iso, c->reqId)};
    (void)f->Call(ctx, ctx->Global(), 1, argv);
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
  invokeJs(js, js->onRequest, c, true, static_cast<int32_t>(c->method), c->path);
}
static void cbOnAborted(void* user, Connection* c) {
  JsServer* js = static_cast<JsServer*>(user);
  invokeJs(js, js->onAborted, c, false, 0, std::string());
}
static void cbOnWritable(void* user, Connection* c) {
  JsServer* js = static_cast<JsServer*>(user);
  invokeJs(js, js->onWritable, c, false, 0, std::string());
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
  if (js->onWsOpen.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  TryCatch tc(iso);
  Local<Value> argv[2] = {Integer::NewFromUnsigned(iso, c->wsId), str(iso, path)};
  (void)js->onWsOpen.Get(iso)->Call(ctx, ctx->Global(), 2, argv);
  reportCaught(iso, tc, "onWsOpen");
}

static void cbOnWsMessage(void* user, Connection* c, const char* data,
                          size_t len, bool isBinary) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->onWsMessage.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  TryCatch tc(iso);
  // Binary -> ArrayBuffer, text -> string (already UTF-8 validated natively)
  Local<Value> payload;
  if (isBinary) {
    Local<ArrayBuffer> ab = ArrayBuffer::New(iso, len);
    if (len) memcpy(ab->Data(), data, len);
    payload = ab;
  } else {
    payload = String::NewFromUtf8(iso, data, v8::NewStringType::kNormal,
                                  static_cast<int>(len))
                  .ToLocalChecked();
  }
  Local<Value> argv[3] = {Integer::NewFromUnsigned(iso, c->wsId), payload,
                          v8::Boolean::New(iso, isBinary)};
  (void)js->onWsMessage.Get(iso)->Call(ctx, ctx->Global(), 3, argv);
  reportCaught(iso, tc, "onWsMessage");
}

static void cbOnWsClose(void* user, Connection* c, int code) {
  JsServer* js = static_cast<JsServer*>(user);
  if (js->onWsClose.IsEmpty()) return;
  Isolate* iso = js->isolate;
  HandleScope scope(iso);
  Local<Context> ctx = js->context.Get(iso);
  Context::Scope cs(ctx);
  TryCatch tc(iso);
  Local<Value> argv[2] = {Integer::NewFromUnsigned(iso, c->wsId),
                          Integer::New(iso, code)};
  (void)js->onWsClose.Get(iso)->Call(ctx, ctx->Global(), 2, argv);
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

  auto grab = [&](const char* name, Global<Function>& out) {
    Local<Value> v;
    if (cbs->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsFunction())
      out.Reset(iso, v.As<Function>());
  };
  grab("onRequest", js->onRequest);
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
    // report every write as backpressured.
    auto getNum = [&](const char* name, size_t& out, double minValue) {
      Local<Value> v;
      if (opts->Get(ctx, str(iso, name)).ToLocal(&v) && v->IsNumber()) {
        double d = v->NumberValue(ctx).FromMaybe(-1);
        if (d >= minValue) out = static_cast<size_t>(d);
      }
    };
    getNum("maxBodySize", limits.maxBodySize, 0);
    getNum("maxHeadSize", limits.maxHeadSize, 1);
    getNum("maxHeaders", limits.maxHeaders, 1);
    getNum("idleTimeoutMs", limits.idleTimeoutMs, 0);
    getNum("requestTimeoutMs", limits.requestTimeoutMs, 0);
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
  scb.onAborted = cbOnAborted;
  scb.onWritable = cbOnWritable;

  scb.onWsOpen = cbOnWsOpen;
  scb.onWsMessage = cbOnWsMessage;
  scb.onWsClose = cbOnWsClose;

  js->server = new Server(loop, scb, limits);
  if (tlsCtx.valid()) js->server->adoptTls(std::move(tlsCtx));
  uint32_t id = ++g_serverIdCounter;
  js->id = id;
  g_servers[id] = js;
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
    errObj->Set(ctx, str(iso, "code"), str(iso, name)).Check();
    errObj->Set(ctx, str(iso, "errno"), Integer::New(iso, uvErr)).Check();
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
  args.GetReturnValue().Set(str(args.GetIsolate(), c->methodStr));
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
  Local<Array> arr = Array::New(iso, static_cast<int>(c->headers.size() * 2));
  uint32_t idx = 0;
  for (const auto& h : c->headers) {
    arr->Set(ctx, idx++, str(iso, h.name)).Check();
    arr->Set(ctx, idx++, str(iso, h.value)).Check();
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
  std::string headers;
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
  std::string headers;
  long long customCL = -1;
  buildHeaders(iso, ctx, args[2], headers, customCL);
  c->server->writeHead(c, status, headers, customCL);
}

// write(reqId, chunk) -> boolean backpressure
static void Write(const FunctionCallbackInfo<Value>& args) {
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
  Isolate* iso = args.GetIsolate();
  Connection* c = connFrom(args);
  if (!c) return;
  // A missing/null/undefined chunk borrows nothing: end(nullptr, 0).
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
  ByteSource data(iso, args[1]);
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

// ---- diagnostics ----

static void Probe(const FunctionCallbackInfo<Value>& args) {
  Isolate* iso = args.GetIsolate();
  Local<Context> ctx = iso->GetCurrentContext();
  Local<Object> result = Object::New(iso);
  auto set = [&](const char* k, Local<Value> v) {
    result->Set(ctx, str(iso, k), v).Check();
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
    caps->Set(ctx, str(iso, k), v8::Boolean::New(iso, v)).Check();
  };
  setCap("limits", true);
  setCap("tls", true);
  setCap("http2", false);
  setCap("wsDeflate", true);
  set("capabilities", caps);
  args.GetReturnValue().Set(result);
}

static void Initialize(Local<Object> exports, Local<Value> module,
                       Local<Context> context) {
  NODE_SET_METHOD(exports, "serve", Serve);
  NODE_SET_METHOD(exports, "listen", Listen);
  NODE_SET_METHOD(exports, "close", Close);
  NODE_SET_METHOD(exports, "stopListening", StopListening);
  NODE_SET_METHOD(exports, "getMethod", GetMethod);
  NODE_SET_METHOD(exports, "getQuery", GetQuery);
  NODE_SET_METHOD(exports, "getHeaders", GetHeaders);
  NODE_SET_METHOD(exports, "getHeader", GetHeader);
  NODE_SET_METHOD(exports, "getBody", GetBody);
  NODE_SET_METHOD(exports, "getRemoteAddress", GetRemoteAddress);
  NODE_SET_METHOD(exports, "isAborted", IsAborted);
  NODE_SET_METHOD(exports, "respond", Respond);
  NODE_SET_METHOD(exports, "writeHead", WriteHead);
  NODE_SET_METHOD(exports, "write", Write);
  NODE_SET_METHOD(exports, "end", End);
  NODE_SET_METHOD(exports, "upgradeToWebSocket", UpgradeToWebSocket);
  NODE_SET_METHOD(exports, "wsSend", WsSend);
  NODE_SET_METHOD(exports, "wsClose", WsClose);
  NODE_SET_METHOD(exports, "probe", Probe);

  // Context::GetIsolate() was removed in V8 14 (Node 26); GetCurrent() is stable
  Isolate* iso = Isolate::GetCurrent();
  exports->Set(context, str(iso, "version"), str(iso, kEngineVersion)).Check();
  (void)module;
}

NODE_MODULE_CONTEXT_AWARE(moro_engine, moro::engine::Initialize)

}  // namespace engine
}  // namespace moro
