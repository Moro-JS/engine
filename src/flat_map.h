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
#include <vector>

namespace moro {
namespace engine {

template <typename V>
class FlatMap {
 public:
  FlatMap() : keys_(kInitialCap, 0), vals_(kInitialCap, V{}) {}

  V find(uint32_t k) const {
    size_t i = probe(k);
    return keys_[i] == k ? vals_[i] : V{};
  }
  bool contains(uint32_t k) const { return keys_[probe(k)] == k; }

  void insert(uint32_t k, V v) {
    if ((size_ + 1) * 2 > keys_.size()) grow();
    size_t i = probe(k);
    if (keys_[i] != k) {
      keys_[i] = k;
      ++size_;
    }
    vals_[i] = v;
  }

  void erase(uint32_t k) {
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

}  // namespace engine
}  // namespace moro
