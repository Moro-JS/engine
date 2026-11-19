// Flat open-addressing hash map: uint32_t keys, pointer-like values.
//
// Built for the per-thread reqId/wsId registries, which take one insert and
// one erase on EVERY request: std::unordered_map paid a node malloc on each
// insert and a free on each erase, plus pointer-chasing lookups. This is
// linear probing over two parallel arrays (no per-op allocation, cache-line
// friendly) with backward-shift deletion (no tombstones, so probe chains
// stay minimal under sustained insert/erase churn).
//
// Contract:
//  - Key 0 is reserved as the empty sentinel and must never be inserted
//    (the id counters skip 0).
//  - Values are trivially copyable (pointers).
//  - Not thread-safe; the registries are thread_local by design.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "text.h"

namespace moro {
namespace engine {

template <typename V>
class FlatMap {
 public:
  // `capacity` must be a power of two. The default suits the per-thread
  // request registry; a map that lives per connection asks for a small one.
  explicit FlatMap(size_t capacity = kInitialCap) : keys_(capacity, 0), vals_(capacity, V{}) {}

  V find(uint32_t k) const {
    size_t i = probe(k);
    return keys_[i] == k ? vals_[i] : V{};
  }
  bool contains(uint32_t k) const { return keys_[probe(k)] == k; }

  void insert(uint32_t k, V v) {
    if (k == 0) return;  // the empty-slot marker cannot be a key
    if ((size_ + 1) * 2 > keys_.size()) grow();
    size_t i = probe(k);
    if (keys_[i] != k) {
      keys_[i] = k;
      ++size_;
    }
    vals_[i] = v;
  }

  // insert() for a key that must not be bound yet: false, and the map as it
  // was, when it is. The same probe and the same stores as insert().
  bool insertNew(uint32_t k, V v) {
    if (k == 0) return false;
    if ((size_ + 1) * 2 > keys_.size()) grow();
    size_t i = probe(k);
    if (keys_[i] == k) return false;
    keys_[i] = k;
    ++size_;
    vals_[i] = v;
    return true;
  }

  void erase(uint32_t k) {
    // 0 is the empty-slot marker, never a key (see insert): erasing it would
    // "find" the first empty slot, shift live entries into it and decrement
    // size_ below the live count - after enough of those the table reports
    // itself empty while it is full and probe() never terminates.
    if (k == 0) return;
    size_t i = probe(k);
    if (keys_[i] != k) return;
    // Backward-shift deletion: walk the chain after the hole and pull back
    // any entry whose ideal slot lies cyclically at or before it, so lookups
    // never cross an artificial gap.
    const size_t mask = keys_.size() - 1;
    size_t j = i;
    for (;;) {
      j = (j + 1) & mask;
      if (keys_[j] == 0) break;
      size_t ideal = hash(keys_[j]) & mask;
      // Entry at j may move into the hole at i iff i lies within [ideal, j)
      // cyclically, i.e. dist(ideal->j) >= dist(i->j).
      if (((j - ideal) & mask) >= ((j - i) & mask)) {
        keys_[i] = keys_[j];
        vals_[i] = vals_[j];
        i = j;
      }
    }
    keys_[i] = 0;
    vals_[i] = V{};
    --size_;
  }

  size_t size() const { return size_; }

  // Calls fn(key, value) for every entry. The map must not be changed from
  // inside the call.
  template <typename Fn>
  void forEach(Fn&& fn) const {
    for (size_t i = 0; i < keys_.size(); ++i)
      if (keys_[i] != 0) fn(keys_[i], vals_[i]);
  }

 private:
  static constexpr size_t kInitialCap = 4096;  // power of two

  // Fibonacci multiplier scatters the sequential id counters across slots
  static size_t hash(uint32_t k) { return k * 2654435761u; }

  // First slot that is empty or holds k
  size_t probe(uint32_t k) const {
    const size_t mask = keys_.size() - 1;
    size_t i = hash(k) & mask;
    while (keys_[i] != 0 && keys_[i] != k) i = (i + 1) & mask;
    return i;
  }

  void grow() {
    std::vector<uint32_t> oldKeys = std::move(keys_);
    std::vector<V> oldVals = std::move(vals_);
    keys_.assign(oldKeys.size() * 2, 0);
    vals_.assign(oldVals.size() * 2, V{});
    size_ = 0;
    for (size_t i = 0; i < oldKeys.size(); ++i)
      if (oldKeys[i] != 0) insert(oldKeys[i], oldVals[i]);
  }

  std::vector<uint32_t> keys_;
  std::vector<V> vals_;
  size_t size_ = 0;
};

// String-keyed map for the binding's per-request lookups by the request's own
// path or a header name (interned JS strings, the batch path table). The
// tables are small and capped by their owner, entries are only ever added,
// and every request looks one key up: linear probing over (hash, entry)
// slots, entries in insertion order, keys compared only where the full hash
// matches. std::unordered_map, keyed by std::string, scanned the whole list
// with a string compare per entry while it held up to 20 and hashed byte by
// byte past that, and could not be asked with a view.
template <typename V>
class StringMap {
 public:
  V* find(std::string_view k) {
    // A table of a few keys is searched in order, by length first: cheaper
    // than hashing the key.
    if (entries_.size() <= kScan) {
      for (Entry& e : entries_)
        if (sameKey(e.key, k)) return &e.value;
      return nullptr;
    }
    const uint64_t h = text::KeyHash{}(k);
    const size_t mask = slots_.size() - 1;
    for (size_t i = h & mask;; i = (i + 1) & mask) {
      const Slot& s = slots_[i];
      if (s.entry == kEmpty) return nullptr;
      if (s.hash == h) {
        Entry& e = entries_[s.entry];
        if (sameKey(e.key, k)) return &e.value;
      }
    }
  }
  // `k` must not be present.
  V& insert(std::string_view k, V v) {
    if ((entries_.size() + 1) * 2 > slots_.size()) rehash(slots_.empty() ? 16 : slots_.size() * 2);
    const uint64_t h = text::KeyHash{}(k);
    place(h, static_cast<uint32_t>(entries_.size()));
    entries_.push_back(Entry{std::string(k), std::move(v)});
    return entries_.back().value;
  }
  size_t size() const { return entries_.size(); }

 private:
  static constexpr uint32_t kEmpty = UINT32_MAX;
  static constexpr size_t kScan = 4;
  struct Slot {
    uint64_t hash;
    uint32_t entry;
  };
  struct Entry {
    std::string key;
    V value;
  };
  // Keys are compared a word at a time, the last word overlapping the one
  // before it where the length is not a multiple of eight.
  static bool sameKey(const std::string& key, std::string_view k) {
    const size_t n = key.size();
    if (n != k.size()) return false;
    const char* a = key.data();
    const char* b = k.data();
    if (n >= 8) {
      uint64_t x, y;
      size_t i = 0;
      for (; i + 8 <= n; i += 8) {
        std::memcpy(&x, a + i, 8);
        std::memcpy(&y, b + i, 8);
        if (x != y) return false;
      }
      if (i == n) return true;
      std::memcpy(&x, a + n - 8, 8);
      std::memcpy(&y, b + n - 8, 8);
      return x == y;
    }
    if (n >= 4) {
      uint32_t x, y, u, v;
      std::memcpy(&x, a, 4);
      std::memcpy(&y, b, 4);
      std::memcpy(&u, a + n - 4, 4);
      std::memcpy(&v, b + n - 4, 4);
      return (x == y) & (u == v);
    }
    for (size_t i = 0; i < n; ++i)
      if (a[i] != b[i]) return false;
    return true;
  }
  void place(uint64_t h, uint32_t entry) {
    const size_t mask = slots_.size() - 1;
    size_t i = h & mask;
    while (slots_[i].entry != kEmpty) i = (i + 1) & mask;
    slots_[i] = Slot{h, entry};
  }
  void rehash(size_t n) {
    std::vector<Slot> old = std::move(slots_);
    slots_.assign(n, Slot{0, kEmpty});
    for (const Slot& s : old)
      if (s.entry != kEmpty) place(s.hash, s.entry);
  }
  std::vector<Slot> slots_;
  std::vector<Entry> entries_;
};

}  // namespace engine
}  // namespace moro
