// Standalone unit test for the FlatMap registry container.
//   clang++ -std=c++20 -O2 test/flat-map-unit.cpp -o /tmp/fmtest && /tmp/fmtest
//
// Differential test: every operation is mirrored against std::unordered_map
// and the full contents compared, across deterministic PRNG workloads that
// exercise growth, heavy insert/erase churn (backward-shift deletion), and
// clustered keys (long probe chains).
#include "../src/flat_map.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

using moro::engine::FlatMap;

static int tests = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    ++tests;                                                            \
    if (!(cond)) {                                                      \
      std::printf("FAIL line %d: %s\n", __LINE__, #cond);               \
      return 1;                                                         \
    }                                                                   \
  } while (0)

// Deterministic xorshift PRNG - the test must not vary between runs
static uint32_t rngState = 0x12345678u;
static uint32_t rng() {
  uint32_t x = rngState;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return rngState = x;
}

// Value type: fake pointers derived from the key (distinct, non-null)
static int* val(uint32_t k) {
  return reinterpret_cast<int*>(static_cast<uintptr_t>(k) * 8 + 8);
}

static bool sameContents(const FlatMap<int*>& fm,
                         const std::unordered_map<uint32_t, int*>& ref) {
  if (fm.size() != ref.size()) return false;
  for (const auto& [k, v] : ref) {
    if (fm.find(k) != v) return false;
    if (!fm.contains(k)) return false;
  }
  return true;
}

int main() {
  // --- basics: insert/find/erase/overwrite, key 0 never used ---
  {
    FlatMap<int*> m;
    CHECK(m.size() == 0);
    CHECK(m.find(42) == nullptr);
    CHECK(!m.contains(42));
    m.insert(42, val(42));
    CHECK(m.size() == 1);
    CHECK(m.find(42) == val(42));
    m.insert(42, val(99));  // overwrite keeps size
    CHECK(m.size() == 1);
    CHECK(m.find(42) == val(99));
    m.erase(42);
    CHECK(m.size() == 0);
    CHECK(m.find(42) == nullptr);
    m.erase(42);  // double erase is a no-op
    CHECK(m.size() == 0);
  }

  // --- sequential ids (the registry's actual key pattern) + full drain ---
  {
    FlatMap<int*> m;
    std::unordered_map<uint32_t, int*> ref;
    for (uint32_t k = 1; k <= 20000; ++k) {  // forces several growths
      m.insert(k, val(k));
      ref[k] = val(k);
    }
    CHECK(sameContents(m, ref));
    // Erase evens, then verify; erase the rest, verify empty.
    for (uint32_t k = 2; k <= 20000; k += 2) {
      m.erase(k);
      ref.erase(k);
    }
    CHECK(sameContents(m, ref));
    for (uint32_t k = 1; k <= 20000; k += 2) {
      m.erase(k);
      ref.erase(k);
    }
    CHECK(m.size() == 0);
    CHECK(sameContents(m, ref));
  }

  // --- steady-state churn at low occupancy (the hot production shape:
  //     insert + erase per request, ids strictly increasing) ---
  {
    FlatMap<int*> m;
    std::unordered_map<uint32_t, int*> ref;
    uint32_t next = 1;
    std::vector<uint32_t> live;
    for (int step = 0; step < 200000; ++step) {
      if (live.size() < 32 || (rng() & 1)) {
        uint32_t k = next++;
        m.insert(k, val(k));
        ref[k] = val(k);
        live.push_back(k);
      } else {
        size_t idx = rng() % live.size();
        uint32_t k = live[idx];
        live[idx] = live.back();
        live.pop_back();
        m.erase(k);
        ref.erase(k);
      }
    }
    CHECK(sameContents(m, ref));
  }

  // --- adversarial clustering: keys crafted to share probe neighborhoods so
  //     backward-shift deletion has to relocate across long chains ---
  {
    FlatMap<int*> m;
    std::unordered_map<uint32_t, int*> ref;
    // Kernel of keys with colliding low hash bits plus random fill
    std::vector<uint32_t> keys;
    for (uint32_t i = 1; i <= 4000; ++i) keys.push_back(i * 4096 + 1);
    for (int i = 0; i < 4000; ++i) {
      uint32_t k = rng();
      if (k != 0) keys.push_back(k);
    }
    for (uint32_t k : keys) {
      m.insert(k, val(k));
      ref[k] = val(k);
    }
    CHECK(sameContents(m, ref));
    // Random interleaved erase/re-insert over the cluster
    for (int step = 0; step < 100000; ++step) {
      uint32_t k = keys[rng() % keys.size()];
      if (ref.count(k)) {
        m.erase(k);
        ref.erase(k);
      } else {
        m.insert(k, val(k));
        ref[k] = val(k);
      }
      // Spot-verify a random key every step (cheap), full compare periodically
      uint32_t probeKey = keys[rng() % keys.size()];
      auto it = ref.find(probeKey);
      if (it == ref.end()) {
        if (m.find(probeKey) != nullptr) {
          std::printf("FAIL step %d: ghost key %u\n", step, probeKey);
          return 1;
        }
      } else if (m.find(probeKey) != it->second) {
        std::printf("FAIL step %d: wrong value for %u\n", step, probeKey);
        return 1;
      }
      if (step % 10000 == 0) CHECK(sameContents(m, ref));
    }
    CHECK(sameContents(m, ref));
  }

  // --- insertNew: binds a key that is free, refuses one that is bound ---
  {
    FlatMap<int*> m;
    std::unordered_map<uint32_t, int*> ref;
    CHECK(!m.insertNew(0, val(1)));  // the empty-slot marker is never a key
    CHECK(m.size() == 0);
    CHECK(m.insertNew(7, val(7)));
    CHECK(m.find(7) == val(7));
    CHECK(!m.insertNew(7, val(8)));  // already bound: refused ...
    CHECK(m.find(7) == val(7));      // ... and the binding is the one it had
    CHECK(m.size() == 1);
    m.erase(7);
    CHECK(m.insertNew(7, val(8)));   // free again after erase
    CHECK(m.find(7) == val(8));
    m.erase(7);
    // Through growth and long probe chains, mirrored against the reference:
    // a key is accepted exactly when the reference does not hold it.
    for (int step = 0; step < 60000; ++step) {
      uint32_t k = 1 + (rng() % 20000);
      if (rng() % 3 == 0) {
        m.erase(k);
        ref.erase(k);
      } else {
        const bool fresh = ref.find(k) == ref.end();
        CHECK(m.insertNew(k, val(k + step)) == fresh);
        if (fresh) ref[k] = val(k + step);
      }
      if (step % 5000 == 0) CHECK(sameContents(m, ref));
    }
    CHECK(sameContents(m, ref));
  }

  // StringMap: every key found by a view of it, absent keys not found,
  // through the in-order scan of a small table and the hashed one past it;
  // keys of every length up to 40, many of them alike but for a few bytes.
  {
    moro::engine::StringMap<uint32_t> m;
    std::vector<std::string> keys;
    for (uint32_t i = 0; i < 512; ++i) keys.push_back("/nope" + std::to_string(i));
    for (size_t n = 0; n <= 40; ++n) keys.push_back(std::string(n, 'k') + std::to_string(n));
    bool found = true, absent = true;
    for (uint32_t i = 0; i < keys.size(); ++i) {
      absent = absent && m.find(keys[i]) == nullptr;
      m.insert(keys[i], i);
      for (uint32_t j = 0; j <= i; j += 1 + i / 16) {
        const std::string copy = keys[j];  // a different buffer, the same bytes
        const uint32_t* v = m.find(std::string_view(copy));
        found = found && v != nullptr && *v == j;
      }
      found = found && m.find("/nope") == nullptr && m.find("/nope5120") == nullptr && m.find("") == nullptr;
    }
    CHECK(found);
    CHECK(absent);
    CHECK(m.size() == keys.size());
  }

  // KeyHash spreads keys that differ in a few bytes over the low bits that
  // choose a slot (a table of 1024 slots holding 512 such keys).
  {
    std::vector<bool> used(1024, false);
    size_t distinct = 0;
    for (uint32_t i = 0; i < 512; ++i) {
      const size_t slot = moro::text::KeyHash{}("/nope" + std::to_string(i)) & 1023;
      if (!used[slot]) ++distinct;
      used[slot] = true;
    }
    CHECK(distinct >= 350);  // a random function gives about 403
  }

  std::printf("all flat-map unit tests passed (%d checks)\n", tests);
  return 0;
}
