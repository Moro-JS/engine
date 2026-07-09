#!/bin/sh
# Throughput bench driver: boots bench/raw.mjs in a mode, hammers it with
# autocannon (via npx, no local dep), takes the median of 3 runs, and hands
# the result to bench/compare.mjs.
#
#   sh bench/run.sh                    # bench 'engine' mode, report only
#   sh bench/run.sh --mode node        # bench the node:http baseline
#   sh bench/run.sh --gate             # fail (exit 1) if < 95% of baseline
#   sh bench/run.sh --record           # write result into baselines.json
#
# The perf gate is meaningful only on the recorded baseline machine (GH
# runners are too noisy for a hard gate - CI uses this advisory-only).
set -eu

MODE=engine
ACTION=report
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --gate) ACTION=gate; shift ;;
    --record) ACTION=record; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-18080}"
DURATION="${BENCH_DURATION:-10}"
CONNECTIONS="${BENCH_CONNECTIONS:-100}"

echo "Starting bench server: mode=$MODE port=$PORT"
PORT="$PORT" node "$DIR/raw.mjs" "$MODE" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait for LISTENING
i=0
until curl -sf "http://127.0.0.1:$PORT/" >/dev/null 2>&1; do
  i=$((i + 1))
  [ $i -gt 50 ] && { echo "server never came up" >&2; exit 1; }
  sleep 0.1
done

RESULTS=""
for run in 1 2 3; do
  echo "autocannon run $run/3 (${DURATION}s, $CONNECTIONS conns)..."
  RPS=$(npx --yes autocannon -d "$DURATION" -c "$CONNECTIONS" --json "http://127.0.0.1:$PORT/" \
    | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).requests.average))")
  RESULTS="$RESULTS $RPS"
done

kill $SERVER_PID 2>/dev/null || true
trap - EXIT

node "$DIR/compare.mjs" --mode "$MODE" --action "$ACTION" --results $RESULTS
