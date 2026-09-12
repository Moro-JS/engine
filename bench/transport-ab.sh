#!/usr/bin/env bash
# A/B the two I/O transports of the SAME engine binary on Linux: libuv
# (MORO_ENGINE_TRANSPORT=uv, the default) vs io_uring (MORO_ENGINE_TRANSPORT=
# uring, opt-in; needs a 6.1+ kernel and a seccomp profile that allows it).
# Three load shapes, the-benchmarker's included:
#   keep-alive   oha -c {64,256,512} -z 15s
#   conn/req     oha --disable-keepalive -c {64,256,512} -z 15s
#   fixed rate   oha -q 20000 -c 100 -z 30s        (latency + CPU at a set load)
# Server CPU (user+system, every thread) is read from /proc/<pid>/stat around
# each run and divided by the requests oha counted -> CPU µs/req. Median of
# RUNS (default 3) after one discarded warm-up.
#
#   bench/transport-ab.sh [--runs N] [--duration S] [--rate N]
#
# The go/no-go (docs/DESIGN.md): uring must show fewer syscalls/req (see
# bench/syscalls.sh), >= 10% lower CPU µs/req at the fixed rate for every
# concurrency, p99 within +5% of uv in every cell, and no RSS growth.
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS=3; DURATION=15; RATE=20000
while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
command -v oha >/dev/null || { echo "oha is required (https://github.com/hatoo/oha)" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "Linux only (io_uring + /proc)" >&2; exit 1; }

cpu_ms() { # pid -> CPU ms (utime+stime of the process incl. all threads)
  local stat; stat="$(cat "/proc/$1/stat")"
  local rest="${stat##*) }"
  local ut st; ut="$(echo "$rest" | awk '{print $12}')"; st="$(echo "$rest" | awk '{print $13}')"
  echo $(( (ut + st) * 1000 / $(getconf CLK_TCK) ))
}

boot() { # transport -> prints "pid port"
  local out; out="$(mktemp)"
  MORO_ENGINE_TRANSPORT="$1" PORT=0 node bench/raw.mjs engine >"$out" 2>&1 &
  local pid=$!
  local port=""
  for _ in $(seq 1 100); do
    port="$(grep -m1 LISTENING "$out" | awk '{print $2}' || true)"
    [ -n "$port" ] && break
    sleep 0.1
  done
  [ -n "$port" ] || { echo "server did not start: $(cat "$out")" >&2; kill "$pid" 2>/dev/null; exit 1; }
  local actual
  actual="$(MORO_ENGINE_TRANSPORT="$1" node -e "console.log(require('./packages/engine').probe().transport || 'uv')")"
  echo "$pid $port $actual"
}

measure() { # pid port extra-oha-args... -> "rps p50 p99 cpu_us_per_req rss_mb"
  local pid="$1" port="$2"; shift 2
  local c0 c1 j
  c0="$(cpu_ms "$pid")"
  j="$(oha --no-tui --output-format json "$@" "http://127.0.0.1:$port/")"
  c1="$(cpu_ms "$pid")"
  local rss; rss="$(( $(awk '/VmRSS/ {print $2}' "/proc/$pid/status") / 1024 ))"
  echo "$j" | node -e '
    let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
      const j=JSON.parse(s); let n=0; for (const k in j.statusCodeDistribution) n+=j.statusCodeDistribution[k];
      const cpu=(process.argv[1]-process.argv[2]); // ms
      console.log([j.summary.requestsPerSec.toFixed(0), (j.latencyPercentiles.p50*1000).toFixed(2), (j.latencyPercentiles.p99*1000).toFixed(2), n?((cpu*1000)/n).toFixed(2):"-", process.argv[3]].join(" "));
    })' "$c1" "$c0" "$rss"
}

median() { sort -n | awk '{a[NR]=$1} END {print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }

printf "%-8s %-22s %-6s %10s %8s %8s %10s %8s\n" transport profile conc rps p50ms p99ms cpu_us/req rss_mb
for T in uv uring; do
  read -r PID PORT ACTUAL < <(boot "$T")
  if [ "$ACTUAL" != "$T" ]; then
    echo "transport '$T' requested but the engine reports '$ACTUAL' (seccomp/kernel?) - skipping" >&2
    kill "$PID"; wait "$PID" 2>/dev/null || true; continue
  fi
  sleep 1
  for PROFILE in keepalive conn-per-req rate; do
    for C in 64 256 512; do
      [ "$PROFILE" = rate ] && [ "$C" != 256 ] && continue
      case "$PROFILE" in
        keepalive) ARGS=(-z "${DURATION}s" -c "$C") ;;
        conn-per-req) ARGS=(-z "${DURATION}s" -c "$C" --disable-keepalive) ;;
        rate) ARGS=(-z "$((DURATION*2))s" -c 100 -q "$RATE" --latency-correction) ;;
      esac
      measure "$PID" "$PORT" "${ARGS[@]}" >/dev/null   # warm-up, discarded
      RESULTS=()
      for _ in $(seq 1 "$RUNS"); do RESULTS+=("$(measure "$PID" "$PORT" "${ARGS[@]}")"); sleep 2; done
      rps="$(printf "%s\n" "${RESULTS[@]}" | awk '{print $1}' | median)"
      p50="$(printf "%s\n" "${RESULTS[@]}" | awk '{print $2}' | median)"
      p99="$(printf "%s\n" "${RESULTS[@]}" | awk '{print $3}' | median)"
      cpu="$(printf "%s\n" "${RESULTS[@]}" | awk '{print $4}' | median)"
      rss="$(printf "%s\n" "${RESULTS[@]}" | awk '{print $5}' | median)"
      printf "%-8s %-22s %-6s %10s %8s %8s %10s %8s\n" "$T" "$PROFILE" "$C" "$rps" "$p50" "$p99" "$cpu" "$rss"
    done
  done
  kill "$PID"; wait "$PID" 2>/dev/null || true
done
