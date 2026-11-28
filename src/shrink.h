// Giving back the storage a buffer holds beyond its contents.
//
// std::string::shrink_to_fit and std::vector::shrink_to_fit are requests, and
// libstdc++ answers them only when exceptions are enabled: its body is inside
// `#if __cpp_exceptions`, because reallocating may throw and the call must
// not. The engine is compiled with -fno-exceptions, as an addon of Node is,
// so on Linux a shrink_to_fit in it compiles to nothing. (libc++ and MSVC's
// library do shrink, which is why nothing showed on macOS or Windows.) These
// do the same thing with a copy and a swap, which every library honours.
//
// Used where 1.2.5 gives queued writes' storage back (Server::queueWrite,
// epollCompactSent). The engine's older shrink_to_fit calls are as they
// were, inert on Linux: see docs/DESIGN.md before changing one - each sits
// on the path of every large request, response or message.
//
// Original-code policy applies (CONTRIBUTING.md).

#pragma once

#include <iterator>
#include <string>
#include <vector>

namespace moro {
namespace engine {

// (A library rounds a string's allocation up by a few bytes; a copy that
// could gain no more than that is not made.)
inline void shrinkToFit(std::string& s) {
  if (s.capacity() - s.size() < 64) return;
  std::string exact(s.data(), s.size());
  s.swap(exact);
}

template <class T>
inline void shrinkToFit(std::vector<T>& v) {
  if (v.capacity() == v.size()) return;
  std::vector<T> exact(std::make_move_iterator(v.begin()), std::make_move_iterator(v.end()));
  v.swap(exact);
}

}  // namespace engine
}  // namespace moro
