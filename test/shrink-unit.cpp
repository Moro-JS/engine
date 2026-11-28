// shrinkToFit (src/shrink.h): a buffer's spare storage is given back, in a
// build without exceptions too. That is how the engine is compiled, and it is
// where the standard library's own shrink_to_fit does nothing on libstdc++ -
// so this file is compiled with -fno-exceptions (test/run-unit.sh).
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/shrink.h"

using moro::engine::shrinkToFit;

static int failures = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
      failures++;                                                       \
    }                                                                   \
  } while (0)

int main() {
  {  // a string that was large and is small again
    std::string s(300000, 'x');
    s.erase(1000);
    CHECK(s.capacity() >= 300000);
    shrinkToFit(s);
    CHECK(s.size() == 1000);
    CHECK(s.capacity() < 2000);
    CHECK(s == std::string(1000, 'x'));
  }
  {  // one whose front was sent
    std::string s;
    for (int i = 0; i < 50000; i++) s.push_back(static_cast<char>('a' + i % 26));
    const std::string tail = s.substr(48000);
    s.erase(0, 48000);
    shrinkToFit(s);
    CHECK(s == tail);
    CHECK(s.capacity() < 4000);
  }
  {  // an empty one gives everything back
    std::string s(100000, 'y');
    s.clear();
    shrinkToFit(s);
    CHECK(s.empty());
    CHECK(s.capacity() < 64);
  }
  {  // nothing to give back: untouched, the same storage
    std::string s(5000, 'z');
    shrinkToFit(s);
    const char* at = s.data();
    shrinkToFit(s);
    CHECK(s.data() == at);
    CHECK(s.size() == 5000);
  }
  {  // a vector, elements moved
    std::vector<std::string> v;
    v.reserve(1000);
    v.emplace_back(100, 'a');
    v.emplace_back(200, 'b');
    shrinkToFit(v);
    CHECK(v.size() == 2);
    CHECK(v.capacity() == 2);
    CHECK(v[0] == std::string(100, 'a') && v[1] == std::string(200, 'b'));
  }
  if (failures) {
    std::printf("shrink unit: %d failure(s)\n", failures);
    return 1;
  }
  std::printf("shrink unit: all passed\n");
  return 0;
}
