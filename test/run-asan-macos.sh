#!/bin/sh
# Run the node --test suites against an ASan/UBSan build of the addon on
# macOS (the CI sanitizer job is Linux: LD_PRELOAD, .github/workflows/ci.yml).
#
#   test/run-asan-macos.sh                      # every suite of `npm run test:suites`
#   test/run-asan-macos.sh test/http2.test.mjs  # the ones named
#
# The addon is built with `tools/build.mjs --sanitize` into build/asan-macos
# (never over the release binaries in build/), and the suites load it through
# MORO_ENGINE_BINARY. The sanitizer runtime has to be in the node process
# before the addon is: DYLD_INSERT_LIBRARIES for the suites, and
# test/asan-macos-preload.cjs for the child processes the suites start.
# tls-library is left out: it loads the release binaries by name.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
OUT="$ROOT/build/asan-macos"
cd "$ROOT"
node tools/build.mjs --sanitize --tls=openssl --out-dir "$OUT"

RT="$(clang++ -print-resource-dir)/lib/darwin/libclang_rt.asan_osx_dynamic.dylib"
export MORO_ASAN_RUNTIME="$RT"
export DYLD_INSERT_LIBRARIES="$RT"
export NODE_OPTIONS="--require \"$DIR/asan-macos-preload.cjs\" ${NODE_OPTIONS:-}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
export MORO_ENGINE_BINARY="$(ls "$OUT"/moro_engine_darwin_*.node | head -1)"

if [ $# -gt 0 ]; then
  SUITES="$*"
else
  SUITES="$(node -e "const s=require('./package.json').scripts['test:suites'];console.log(s.split('&&')[0].replace('node --test','').trim().split(/\s+/).filter(f=>!/tls-library/.test(f)).join(' '))")"
fi
failed=0
for f in $SUITES; do
  log="$OUT/$(basename "$f" .test.mjs).log"
  # One file per process, in this process (node --test would start a child
  # of its own for each file).
  if node "$f" > "$log" 2>&1; then rc=0; else rc=$?; failed=1; fi
  reports=$(grep -c 'AddressSanitizer\|runtime error:' "$log" || true)
  [ "$reports" = 0 ] || failed=1
  echo "$(basename "$f") rc=$rc $(grep -E '^ℹ (pass|fail|skipped)' "$log" | tr '\n' ' ')sanitizer-reports=$reports"
done
exit $failed
