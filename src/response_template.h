// Prepared response templates for @morojs/engine.
//
// A template is the part of a response that never varies between requests:
// status, the app's header block (already validated, CRLF-terminated lines,
// never Content-Length - the binding strips that into customCL), and the
// app-supplied Content-Length for HEAD/bodyless replies. It is materialised
// ONCE (prepareResponse / setStaticRoute) with the same header builder the
// per-request respond() path uses, then replayed per request with a body:
// the bytes on the wire are identical to respond(status, headers, body), the
// per-request header walk is simply gone. Date, the actual Content-Length and
// the Connection header stay per response (appendResponse), which is why a
// template stores the header block and not a pre-rendered head.
//
// Ids are per Server, dense from 1 (0 = none/invalid). Original-code policy
// applies (CONTRIBUTING.md).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace moro {
namespace engine {

struct ResponseTemplate {
  int status = 200;
  long long customCL = -1;  // app-supplied Content-Length (honoured on HEAD/bodyless only)
  std::string headers;      // app header block; never contains Content-Length
};

class TemplateStore {
 public:
  // Hard cap per server: a template is registered at setup time, never per
  // request, so a store this size only ever fills through a caller bug (or a
  // caller that never releases) - and the cap turns that into an error at
  // prepare time instead of unbounded native memory.
  static constexpr uint32_t kMax = 4096;

  // Returns the new id (>= 1), or 0 when the store is full.
  uint32_t add(ResponseTemplate&& t) {
    if (items_.size() >= kMax) return 0;
    items_.push_back(std::move(t));
    return static_cast<uint32_t>(items_.size());
  }

  // nullptr for 0 and any id never issued (or released).
  const ResponseTemplate* get(uint32_t id) const {
    if (id == 0 || id > items_.size()) return nullptr;
    return &items_[id - 1];
  }

  // Invalidates every id; the next add() issues 1 again.
  void clear() {
    items_.clear();
    items_.shrink_to_fit();
  }

  size_t size() const { return items_.size(); }

 private:
  std::vector<ResponseTemplate> items_;
};

// A static route is a template plus its fixed body, keyed by (path, method)
// and answered by the engine before the request ever reaches JS.
struct StaticRoute {
  int32_t method;
  ResponseTemplate tpl;
  std::string body;
};

}  // namespace engine
}  // namespace moro
