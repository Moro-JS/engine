#!/bin/sh
# Compile and run the standalone C++ unit tests (parser + WebSocket protocol).
# Uses the system clang++ (Apple clang is fine here - no libFuzzer needed).
set -e

CXX="${CXX:-clang++}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "HTTP parser unit tests ..."
$CXX -std=c++20 -O2 "$DIR/http-parser-unit.cpp" -o /tmp/moro_hptest
/tmp/moro_hptest

echo "WebSocket unit tests ..."
$CXX -std=c++20 -O2 "$DIR/websocket-unit.cpp" -o /tmp/moro_wstest
/tmp/moro_wstest

# permessage-deflate: the only unit that links zlib (system -lz; a widely
# available dev header on macOS SDK / Linux zlib1g-dev).
echo "permessage-deflate unit tests ..."
$CXX -std=c++20 -O2 "$DIR/ws-deflate-unit.cpp" -lz -o /tmp/moro_pmdtest
/tmp/moro_pmdtest

echo "All C++ unit tests passed."
