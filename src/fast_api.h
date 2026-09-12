// V8 fast API call targets for the engine's hot binding entry points.
//
// A fast call lets optimised JS (Maglev/TurboFan) invoke one of these plain
// C++ functions DIRECTLY - no FunctionCallbackInfo, no HandleScope, no
// argument boxing - whenever the arguments already have the declared machine
// types (Smi reqIds, a sequential one-byte string body). Anything else (a
// two-byte or cons string, a Buffer, an unoptimised caller) silently takes
// the regular callback, which is why every fast function here has a slow twin
// in binding.cpp doing exactly the same work.
//
// Hard rules for a fast target (V8's contract): no V8 API calls, no JS heap
// allocation, no GC, no re-entry into JS, no exceptions. Every function below
// is pure C++: a registry lookup, then Server::respond/write/end/... - which
// after 1.2's deferred-notification change can no longer reach a JS callback
// synchronously (see Server::queueNotify). That is the precondition this file
// exists on; it is enforced at install time (fast calls are refused when
// MORO_ENGINE_NOTIFY=sync).
//
// The header this needs (v8-fast-api-calls.h) is not shipped in Node's
// headers tarball; tools/build.mjs fetches the exact per-tag copy
// (sha256-pinned) and defines MORO_FAST_API=1 when it is present. The only
// version-dependent piece of that header we would touch is
// FastApiCallbackOptions (its layout changed across V8 12/13), so it is not
// used at all: these functions never need a fallback.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#if defined(MORO_FAST_API) && MORO_FAST_API
#define MORO_FAST_API_ENABLED 1
#else
#define MORO_FAST_API_ENABLED 0
#endif

#include <cstdint>

namespace moro {
namespace engine {
namespace fastcall {

enum Fn : int {
  kRespondPrepared = 0,
  kRespondPreparedEmpty,
  kWriteHeadPrepared,
  kWrite,
  kEnd,
  kEndWith,
  kIsAborted,
  kCount
};

// Per-thread hit counters, exposed through probe().fastCallStats when
// MORO_ENGINE_FASTCALL_STATS=1 (the "Counting" instantiations are installed
// then). Proof, per ABI, that the fast path is actually taken.
inline thread_local uint64_t g_fastHits[kCount] = {};
inline thread_local uint64_t g_slowHits[kCount] = {};

inline const char* fnName(int i) {
  static const char* const names[kCount] = {
      "respondPrepared", "respondPreparedEmpty", "writeHeadPrepared", "write",
      "end",             "endWith",              "isAborted"};
  return (i >= 0 && i < kCount) ? names[i] : "?";
}

}  // namespace fastcall
}  // namespace engine
}  // namespace moro

#if defined(MORO_FAST_API) && MORO_FAST_API

#include <v8-fast-api-calls.h>

#include <cstdint>
#include <string>

#include "server.h"
#include "text.h"

namespace moro {
namespace engine {
namespace fastcall {

// A FastOneByteString is Latin-1. ASCII passes through untouched (it IS the
// UTF-8); bytes >= 0x80 are UTF-8-encoded into a per-thread scratch buffer -
// the exact bytes the slow path's ByteSource produces. The scratch is
// consumed by the Server call before this function returns (respond/write/end
// copy into engine-owned buffers), so one buffer per thread suffices.
inline thread_local std::string g_bodyScratch;

struct Bytes {
  const char* data;
  size_t size;
};

inline Bytes bytesOf(const v8::FastOneByteString& s) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(s.data);
  if (text::isAscii(p, s.length)) return Bytes{s.data, s.length};
  text::latin1ToUtf8(p, s.length, g_bodyScratch);
  return Bytes{g_bodyScratch.data(), g_bodyScratch.size()};
}

// The first parameter is the receiver (`this`), which V8 always passes to a
// fast target; the engine ignores it.

template <bool Counting>
void RespondPrepared(v8::Local<v8::Value>, uint32_t reqId, uint32_t tplId,
                     const v8::FastOneByteString& body) {
  if (Counting) ++g_fastHits[kRespondPrepared];
  Connection* c = Server::lookup(reqId);
  if (!c) return;
  const Bytes b = bytesOf(body);
  c->server->respondTemplate(c, tplId, b.data, b.size);
}

template <bool Counting>
void RespondPreparedEmpty(v8::Local<v8::Value>, uint32_t reqId, uint32_t tplId) {
  if (Counting) ++g_fastHits[kRespondPreparedEmpty];
  Connection* c = Server::lookup(reqId);
  if (!c) return;
  c->server->respondTemplate(c, tplId, nullptr, 0);
}

template <bool Counting>
void WriteHeadPrepared(v8::Local<v8::Value>, uint32_t reqId, uint32_t tplId) {
  if (Counting) ++g_fastHits[kWriteHeadPrepared];
  Connection* c = Server::lookup(reqId);
  if (!c) return;
  c->server->writeHeadTemplate(c, tplId);
}

template <bool Counting>
bool Write(v8::Local<v8::Value>, uint32_t reqId, const v8::FastOneByteString& chunk) {
  if (Counting) ++g_fastHits[kWrite];
  Connection* c = Server::lookup(reqId);
  if (!c) return false;
  const Bytes b = bytesOf(chunk);
  return c->server->write(c, b.data, b.size);
}

template <bool Counting>
void End(v8::Local<v8::Value>, uint32_t reqId) {
  if (Counting) ++g_fastHits[kEnd];
  Connection* c = Server::lookup(reqId);
  if (!c) return;
  c->server->end(c, nullptr, 0);
}

template <bool Counting>
void EndWith(v8::Local<v8::Value>, uint32_t reqId, const v8::FastOneByteString& chunk) {
  if (Counting) ++g_fastHits[kEndWith];
  Connection* c = Server::lookup(reqId);
  if (!c) return;
  const Bytes b = bytesOf(chunk);
  c->server->end(c, b.data, b.size);
}

template <bool Counting>
bool IsAborted(v8::Local<v8::Value>, uint32_t reqId) {
  if (Counting) ++g_fastHits[kIsAborted];
  return Server::lookup(reqId) == nullptr;
}

}  // namespace fastcall
}  // namespace engine
}  // namespace moro

#endif  // MORO_FAST_API
