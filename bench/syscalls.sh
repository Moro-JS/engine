#!/usr/bin/env bash
# Syscalls per request for each transport (Linux): boots bench/raw.mjs engine,
# counts syscalls system-wide-for-that-pid during a fixed number of requests,
# and divides. perf stat when perf_event_paranoid allows tracepoints,
# otherwise strace -c -f (slower, changes absolute timings, counts still hold).
#
#   bench/syscalls.sh [--requests N] [--conc C] [--no-keepalive]
set -euo pipefail
cd "$(dirname "$0")/.."
REQUESTS=200000; CONC=64; KA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --requests) REQUESTS="$2"; shift 2 ;;
    --conc) CONC="$2"; shift 2 ;;
    --no-keepalive) KA=(--disable-keepalive); shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
command -v oha >/dev/null || { echo "oha is required" >&2; exit 1; }

for T in uv uring; do
  out="$(mktemp)"
  MORO_ENGINE_TRANSPORT="$T" PORT=0 node bench/raw.mjs engine >"$out" 2>&1 &
  pid=$!
  port=""; for _ in $(seq 1 100); do port="$(grep -m1 LISTENING "$out" | awk '{print $2}' || true)"; [ -n "$port" ] && break; sleep 0.1; done
  actual="$(MORO_ENGINE_TRANSPORT="$T" node -e "console.log(require('./packages/engine').probe().transport || 'uv')")"
  if [ "$actual" != "$T" ]; then echo "$T: engine reports $actual - skipping"; kill "$pid"; wait "$pid" 2>/dev/null || true; continue; fi
  oha --no-tui -n 2000 -c "$CONC" "${KA[@]}" "http://127.0.0.1:$port/" >/dev/null  # warm
  echo "== transport $T (pid $pid), $REQUESTS requests, -c $CONC ${KA[*]:-keep-alive}"
  if command -v perf >/dev/null && perf stat -e 'syscalls:sys_enter_read' -p "$pid" -- sleep 0.1 >/dev/null 2>&1; then
    perf stat -x, -e 'syscalls:sys_enter_read,syscalls:sys_enter_recvfrom,syscalls:sys_enter_write,syscalls:sys_enter_sendto,syscalls:sys_enter_writev,syscalls:sys_enter_epoll_wait,syscalls:sys_enter_epoll_pwait,syscalls:sys_enter_epoll_ctl,syscalls:sys_enter_accept4,syscalls:sys_enter_close,syscalls:sys_enter_io_uring_enter' -p "$pid" -o "$out.perf" -- \
      oha --no-tui -n "$REQUESTS" -c "$CONC" "${KA[@]}" "http://127.0.0.1:$port/" >/dev/null
    awk -F, -v n="$REQUESTS" '$1 ~ /^[0-9]/ {printf "  %-36s %12d  %8.3f /req\n", $3, $1, $1/n; total+=$1} END {printf "  %-36s %12d  %8.3f /req\n", "TOTAL (listed events)", total, total/n}' "$out.perf"
  else
    strace -c -f -p "$pid" -o "$out.strace" &
    spid=$!
    sleep 0.5
    oha --no-tui -n "$REQUESTS" -c "$CONC" "${KA[@]}" "http://127.0.0.1:$port/" >/dev/null
    kill -INT "$spid"; wait "$spid" 2>/dev/null || true
    awk -v n="$REQUESTS" 'NR>2 && $NF ~ /^[a-z_0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "  %-20s %12d  %8.3f /req\n", $NF, $4, $4/n}' "$out.strace" | sort -k2 -nr | head -15
  fi
  kill "$pid"; wait "$pid" 2>/dev/null || true
done
