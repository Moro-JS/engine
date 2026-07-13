#!/bin/sh
# Build and run the libFuzzer harnesses. Requires a clang with the libFuzzer
# runtime (Apple clang lacks it; use Homebrew LLVM: brew install llvm, then
# CXX=/opt/homebrew/opt/llvm/bin/clang++).
#
#   CXX=/opt/homebrew/opt/llvm/bin/clang++ FUZZ_SECONDS=60 sh test/fuzz/run.sh
#
# An optional positional argument selects one target so CI can matrix the
# fuzzers in parallel (fuzz.yml):
#   sh test/fuzz/run.sh          # all targets
#   sh test/fuzz/run.sh http     # HTTP/1.1 parser
#   sh test/fuzz/run.sh ws       # WebSocket parser
#   sh test/fuzz/run.sh tls      # TLS transform (needs OpenSSL dev headers:
#                                #   apt install libssl-dev / brew install openssl)
#   sh test/fuzz/run.sh pmd      # permessage-deflate inflate path (needs zlib: -lz)
#
# FUZZ_MODE=merge minimizes the target's corpus in place instead of fuzzing:
#   FUZZ_MODE=merge sh test/fuzz/run.sh pmd
#
# CI runs this on Linux where the stock clang ships the runtime.
# (The duration variable is deliberately NOT named SECONDS: when sh is bash —
# e.g. macOS — bash resets SECONDS to an elapsed-time counter, silently
# replacing the requested duration.)
set -e

CXX="${CXX:-clang++}"
FUZZ_SECONDS="${FUZZ_SECONDS:-60}"
# FUZZ_MODE=run (default) fuzzes for $FUZZ_SECONDS. FUZZ_MODE=merge instead
# minimizes the corpus in place (libFuzzer -merge=1 -reduce_inputs=1): it keeps
# only the smallest input per coverage feature and drops the rest. The nightly
# campaign grows the corpus; a periodic merge (fuzz.yml) keeps it from bloating
# unbounded and produces a minimized artifact that survives cache eviction.
FUZZ_MODE="${FUZZ_MODE:-run}"
TARGET="${1:-all}"
DIR="$(cd "$(dirname "$0")" && pwd)"
FLAGS="-std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all"

# run_target <name> <source.cc> [extra link flags]
# Seed corpora: libFuzzer treats a positional directory as the corpus (it
# replays every file in it, then mutates and writes new coverage-expanding
# inputs back into it). mkdir -p keeps this working when a corpus dir is
# absent or empty — an empty corpus just means libFuzzer starts from scratch.
run_target() {
  name="$1"
  src="$2"
  extra="${3:-}"
  corpus="$DIR/corpus/$name"
  mkdir -p "$corpus"
  echo "Building fuzz_$name with $CXX ..."
  # shellcheck disable=SC2086
  $CXX $FLAGS "$DIR/$src" $extra -o "/tmp/moro_fuzz_$name"
  if [ "$FUZZ_MODE" = merge ]; then
    # Minimize into a fresh dir, then swap it in — -merge is non-destructive to
    # the destination, so a crash mid-merge never truncates the live corpus.
    min="$corpus.min"
    rm -rf "$min"
    mkdir -p "$min"
    echo "Merging/minimizing $name corpus (corpus: $corpus) ..."
    "/tmp/moro_fuzz_$name" -merge=1 -reduce_inputs=1 -timeout=5 -rss_limit_mb=2048 "$min" "$corpus"
    rm -rf "$corpus"
    mv "$min" "$corpus"
    echo "Minimized $name corpus -> $corpus ($(find "$corpus" -type f | wc -l | tr -d ' ') inputs)"
    return
  fi
  echo "Fuzzing $name for ${FUZZ_SECONDS}s (corpus: $corpus) ..."
  "/tmp/moro_fuzz_$name" "$corpus" -max_total_time="$FUZZ_SECONDS" -timeout=5 -rss_limit_mb=2048 -print_final_stats=1
}

ran=0
if [ "$TARGET" = all ] || [ "$TARGET" = http ]; then
  run_target http fuzz_http_parser.cc
  ran=1
fi
if [ "$TARGET" = all ] || [ "$TARGET" = ws ]; then
  run_target ws fuzz_websocket.cc
  ran=1
fi
if [ "$TARGET" = all ] || [ "$TARGET" = tls ]; then
  # Homebrew OpenSSL on macOS (system LibreSSL ships no headers); plain
  # -lssl -lcrypto on Linux.
  TLS_EXTRA="-lssl -lcrypto"
  if [ -d /opt/homebrew/opt/openssl ]; then
    TLS_EXTRA="-I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto"
  fi
  run_target tls fuzz_tls_transport.cc "$TLS_EXTRA"
  ran=1
fi
if [ "$TARGET" = all ] || [ "$TARGET" = pmd ]; then
  run_target pmd fuzz_ws_deflate.cc "-lz"
  ran=1
fi

if [ "$ran" = 0 ]; then
  echo "unknown fuzz target: $TARGET (expected http|ws|tls|pmd|all)" >&2
  exit 2
fi

echo "Fuzzing complete - no crashes."
