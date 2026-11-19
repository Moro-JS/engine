// Per-thread state of the engine, reached through one thread_local pointer.
//
// glibc places a dlopen'ed library's thread-local block in each thread's
// static TLS only while it fits in what is left of a small surplus (512 bytes
// by default, shared by every library a process loads after start); a block
// that does not fit is reached through _dl_tlsdesc_dynamic on every access,
// some twenty instructions each. So the engine keeps everything that is per
// thread - the request and WebSocket registries, the event loops, the
// binding's servers and scratch buffers - in one struct, and its thread-local
// storage is the pointer to it (constant-initialised: no initialisation
// guard on the way in) and the owner that frees the struct when the thread
// ends. One engine runs per thread (worker_threads + reusePort), and an id
// only ever crosses the JS<->C++ boundary on the thread that created it, so
// nothing here needs a lock.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "flat_map.h"

namespace moro {
namespace engine {

struct Connection;
struct JsServer;

struct ThreadState {
  // Server (server.h): request ids and the registry that maps a reqId back
  // to its Connection, and the same for WebSocket ids.
  uint32_t reqCounter = 0;
  FlatMap<Connection*> requests;
  uint32_t wsCounter = 0;
  std::unordered_map<uint32_t, Connection*> webSockets;
  // The thread's event loops (Server::loopSlots): their slots are a type of
  // server.h's, made there at first use and freed here.
  void* loopSlots = nullptr;
  void (*freeLoopSlots)(void*) = nullptr;

  // binding.cpp: the servers created on this thread, and the reused scratch
  // buffers of respond() and friends (see HeaderBlockLease, ByteSource).
  std::unordered_map<uint32_t, JsServer*> servers;
  uint32_t serverIdCounter = 0;
  bool uringHookRegistered = false;
  bool epollHookRegistered = false;
  std::string headerBlock;
  bool headerBlockInUse = false;
  std::string byteScratch;
  bool byteScratchInUse = false;
  // buildHeaders' name/value scratch pair.
  std::string hdrKeyScratch;
  std::string hdrValScratch;
  bool hdrScratchInUse = false;
  // The server whose onRequestBatch call is on the stack (innermost), for
  // the batch trampoline's "JS has left its loop" notice (_batchDone).
  JsServer* batchJs = nullptr;

  // fast_api.h: the UTF-8 scratch of a Latin-1 body, and the call counters
  // probe().fastCallStats reports.
  static constexpr int kFastFns = 7;
  std::string fastBodyScratch;
  uint64_t fastHits[kFastFns] = {};
  uint64_t slowHits[kFastFns] = {};

  ThreadState() = default;
  ThreadState(const ThreadState&) = delete;
  ThreadState& operator=(const ThreadState&) = delete;
  ~ThreadState() {
    if (freeLoopSlots != nullptr) freeLoopSlots(loopSlots);
  }
};

inline ThreadState*& threadStateSlot() {
  static thread_local ThreadState* state = nullptr;
  return state;
}

// Frees the thread's state when the thread ends; the slot is emptied first.
struct ThreadStateOwner {
  ThreadState* state = nullptr;
  ~ThreadStateOwner() {
    if (state == nullptr) return;
    threadStateSlot() = nullptr;
    delete state;
  }
};

// The first use on a thread: kept out of the callers' way.
#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
inline ThreadState& makeThreadState() {
  static thread_local ThreadStateOwner owner;
  owner.state = new ThreadState();
  threadStateSlot() = owner.state;
  return *owner.state;
}

inline ThreadState& threadState() {
  ThreadState* state = threadStateSlot();
  if (state != nullptr) [[likely]] return *state;
  return makeThreadState();
}

}  // namespace engine
}  // namespace moro
