#!/usr/bin/env bash
# Run uNetworking's h1spec HTTP/1.1 compliance driver (unmodified, pinned)
# against the engine built in build/ - the 33/33 bar, checked in this repo's
# CI per commit (the MoroJS benchmark repo runs the same driver weekly against
# the published packages and the full framework).
#
# h1spec has no license file (all rights reserved), so it is cloned at run
# time into test/h1spec/h1spec (gitignored) rather than vendored. Pinned so an
# upstream change can never move the bar under us; bump deliberately.
set -euo pipefail
cd "$(dirname "$0")"

H1SPEC_REPO=https://github.com/uNetworking/h1spec.git
H1SPEC_SHA=f0a5650a20c575fbea0f7179a3a9cfa50f20ba6e
PORT="${PORT:-8000}"

if [ ! -d h1spec/.git ]; then
  git clone -q "$H1SPEC_REPO" h1spec
fi
git -C h1spec fetch -q origin "$H1SPEC_SHA" 2>/dev/null || true
git -C h1spec checkout -q "$H1SPEC_SHA"

DENO="${DENO:-}"
if [ -z "$DENO" ]; then
  if command -v deno >/dev/null 2>&1; then
    DENO=deno
  else
    echo "deno is required for h1spec's driver: https://docs.deno.com/runtime/getting_started/installation/" >&2
    exit 1
  fi
fi

PORT="$PORT" node subject.mjs &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/" && break
  sleep 0.1
done

echo "=== h1spec vs @morojs/engine (127.0.0.1:$PORT) ==="
"$DENO" run --allow-net h1spec/http_test.ts 127.0.0.1 "$PORT"
