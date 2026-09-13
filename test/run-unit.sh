#!/bin/sh
# Compile and run the standalone C++ unit tests (parser + WebSocket protocol).
# Uses the system clang++ (Apple clang is fine here - no libFuzzer needed).
set -e

CXX="${CXX:-clang++}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "FlatMap unit tests ..."
$CXX -std=c++20 -O2 "$DIR/flat-map-unit.cpp" -o /tmp/moro_fmtest
/tmp/moro_fmtest

echo "text helper unit tests ..."
$CXX -std=c++20 -O2 "$DIR/text-unit.cpp" -o /tmp/moro_texttest
/tmp/moro_texttest

echo "response-template unit tests ..."
$CXX -std=c++20 -O2 "$DIR/response-template-unit.cpp" -o /tmp/moro_tpltest
/tmp/moro_tpltest

case "$(uname -s)" in
  Linux|Darwin)
    echo "socket-option unit tests ..."
    $CXX -std=c++20 -O2 "$DIR/sockopt-unit.cpp" -o /tmp/moro_sockopttest
    /tmp/moro_sockopttest
    ;;
esac

echo "io_uring fake-kernel unit tests ..."
$CXX -std=c++20 -O2 "$DIR/uring-fake-unit.cpp" -o /tmp/moro_uringfaketest
/tmp/moro_uringfaketest

# Real-kernel io_uring unit: Linux only; self-skips where io_uring is
# unavailable (prints the probe reason), fails under
# MORO_ENGINE_REQUIRE_TRANSPORT=uring.
if [ "$(uname -s)" = "Linux" ]; then
  echo "io_uring real-kernel unit tests ..."
  $CXX -std=c++20 -O2 "$DIR/uring-unit.cpp" -o /tmp/moro_uringtest
  /tmp/moro_uringtest
fi

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
