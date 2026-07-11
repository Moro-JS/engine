#!/bin/sh
# Throughput bench driver: boots bench/raw.mjs in a mode, hammers it with
# autocannon (via npx, no local dep), takes the median of 3 measured runs'
# `requests.average` (after one discarded warmup run), and hands the result
# to bench/compare.mjs.
#
#   sh bench/run.sh                    # bench 'engine' mode, report only
#   sh bench/run.sh --mode node        # bench the node:http baseline
#   sh bench/run.sh --gate             # fail (exit 1) if < 95% of baseline
#   sh bench/run.sh --record           # write result into baselines.json
#
# The perf gate is meaningful only on the recorded baseline machine (GH
# runners are too noisy for a hard gate). Runs locally; not wired into CI.
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
PORT="${PORT:-0}"
DURATION="${BENCH_DURATION:-10}"
WARMUP="${BENCH_WARMUP:-3}"
CONNECTIONS="${BENCH_CONNECTIONS:-100}"
# autocannon workers so the load generator itself isn't the bottleneck.
WORKERS="${BENCH_WORKERS:-4}"

echo "Starting bench server: mode=$MODE"
SERVER_OUT="$(mktemp)"
PORT="$PORT" node "$DIR/raw.mjs" "$MODE" >"$SERVER_OUT" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -f "$SERVER_OUT"' EXIT

# PORT=0 binds an ephemeral port; every raw.mjs mode prints the actual bound
# port as "LISTENING <port>". Wait for that line (and notice a dead server).
i=0
BENCH_PORT=""
while [ -z "$BENCH_PORT" ]; do
  BENCH_PORT="$(awk '/^LISTENING /{print $2; exit}' "$SERVER_OUT")"
  [ -n "$BENCH_PORT" ] && break
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "server exited before LISTENING" >&2; exit 1; }
  i=$((i + 1))
  [ $i -gt 100 ] && { echo "server never printed LISTENING" >&2; exit 1; }
  sleep 0.1
done
URL="http://127.0.0.1:$BENCH_PORT/"

# Belt-and-suspenders: confirm the port actually answers before measuring.
i=0
until curl -sf "$URL" >/dev/null 2>&1; do
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died during readiness check" >&2; exit 1; }
  i=$((i + 1))
  [ $i -gt 50 ] && { echo "server never came up" >&2; exit 1; }
  sleep 0.1
done
echo "Server ready on port $BENCH_PORT"

# One short discarded run to warm JIT/caches before measuring.
echo "warmup run (${WARMUP}s, discarded)..."
npx --yes autocannon -d "$WARMUP" -c "$CONNECTIONS" -w "$WORKERS" "$URL" >/dev/null

RESULTS=""
for run in 1 2 3; do
  echo "autocannon run $run/3 (${DURATION}s, $CONNECTIONS conns, $WORKERS workers)..."
  RPS=$(npx --yes autocannon -d "$DURATION" -c "$CONNECTIONS" -w "$WORKERS" --json "$URL" \
    | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).requests.average))")
  RESULTS="$RESULTS $RPS"
done

kill $SERVER_PID 2>/dev/null || true
rm -f "$SERVER_OUT"
trap - EXIT

node "$DIR/compare.mjs" --mode "$MODE" --action "$ACTION" --results $RESULTS
