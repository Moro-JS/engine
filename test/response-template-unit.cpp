// Unit test for src/response_template.h: dense ids from 1, the cap, lookups of
// 0 / never-issued / released ids, content stability while the store grows,
// and the static-route replace-on-duplicate contract (exercised through the
// same struct the Server stores).
#include <cstdio>
#include <string>
#include <vector>

#include "../src/response_template.h"

static int checks = 0;
static int failures = 0;
#define CHECK(cond)                                                          \
  do {                                                                       \
    ++checks;                                                                \
    if (!(cond)) {                                                           \
      ++failures;                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
    }                                                                        \
  } while (0)

using moro::engine::ResponseTemplate;
using moro::engine::TemplateStore;

static ResponseTemplate tpl(int status, const char* headers, long long cl = -1) {
  ResponseTemplate t;
  t.status = status;
  t.headers = headers;
  t.customCL = cl;
  return t;
}

int main() {
  TemplateStore store;
  CHECK(store.size() == 0);
  CHECK(store.get(0) == nullptr);
  CHECK(store.get(1) == nullptr);

  // Dense ids from 1, in insertion order.
  CHECK(store.add(tpl(200, "content-type: application/json\r\n")) == 1);
  CHECK(store.add(tpl(404, "content-type: text/plain\r\n", 7)) == 2);
  CHECK(store.size() == 2);
  const ResponseTemplate* a = store.get(1);
  const ResponseTemplate* b = store.get(2);
  CHECK(a && a->status == 200 && a->headers == "content-type: application/json\r\n" && a->customCL == -1);
  CHECK(b && b->status == 404 && b->headers == "content-type: text/plain\r\n" && b->customCL == 7);
  CHECK(store.get(3) == nullptr);

  // Content stays correct while the vector grows (pointers are re-fetched,
  // as the Server does per call).
  for (uint32_t i = 3; i <= 1000; ++i) {
    CHECK(store.add(tpl(static_cast<int>(200 + (i % 100)), "x-i: 1\r\n")) == i);
  }
  CHECK(store.get(1)->headers == "content-type: application/json\r\n");
  CHECK(store.get(2)->customCL == 7);
  CHECK(store.get(1000)->status == 200);
  CHECK(store.get(1001) == nullptr);

  // The cap: the 4096th add succeeds, the next returns 0 and changes nothing.
  for (uint32_t i = 1001; i <= TemplateStore::kMax; ++i) CHECK(store.add(tpl(204, "")) == i);
  CHECK(store.size() == TemplateStore::kMax);
  CHECK(store.add(tpl(200, "")) == 0);
  CHECK(store.size() == TemplateStore::kMax);
  CHECK(store.get(TemplateStore::kMax) != nullptr);
  CHECK(store.get(TemplateStore::kMax + 1) == nullptr);

  // clear() invalidates every id and restarts at 1.
  store.clear();
  CHECK(store.size() == 0);
  CHECK(store.get(1) == nullptr);
  CHECK(store.get(4096) == nullptr);
  CHECK(store.add(tpl(201, "")) == 1);
  CHECK(store.get(1)->status == 201);

  // StaticRoute replace-on-duplicate (the Server's per-path vector rule).
  std::vector<moro::engine::StaticRoute> routes;
  auto set = [&](int32_t method, ResponseTemplate&& t, std::string body) {
    for (auto& r : routes) {
      if (r.method == method) {
        r.tpl = std::move(t);
        r.body = std::move(body);
        return;
      }
    }
    routes.push_back(moro::engine::StaticRoute{method, std::move(t), std::move(body)});
  };
  set(0, tpl(200, ""), "first");
  set(1, tpl(200, ""), "post");
  set(0, tpl(200, ""), "second");
  CHECK(routes.size() == 2);
  CHECK(routes[0].method == 0 && routes[0].body == "second");
  CHECK(routes[1].method == 1 && routes[1].body == "post");

  if (failures) {
    std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
    return 1;
  }
  std::printf("all response-template unit tests passed (%d checks)\n", checks);
  return 0;
}
