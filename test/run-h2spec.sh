#!/bin/sh
# Run h2spec (https://github.com/summerwind/h2spec), the HTTP/2 conformance
# suite, against the engine: 146 cases over RFC 9113 and RFC 7541.
#
#   test/run-h2spec.sh            # needs docker; pulls summerwind/h2spec
#   H2SPEC=/path/to/h2spec test/run-h2spec.sh   # or a local binary
#
# The TLS listener must pass every case. On the cleartext listener one case
# is expected to differ: "3.5/2 Sends invalid connection preface" wants the
# connection closed with GOAWAY, and a port that also speaks HTTP/1.1 answers
# bytes that are not the HTTP/2 preface as the HTTP/1 request they might be
# (400, then close) - the suite reads that as an unexpected reply.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-18080}"
TLS_PORT=$((PORT + 1))

PORT="$PORT" node "$DIR/h2spec/server.mjs" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1

if [ -n "$H2SPEC" ]; then
  RUN="$H2SPEC -h 127.0.0.1"
else
  RUN="docker run --rm --network host summerwind/h2spec:2.6.0 -h 127.0.0.1"
fi

echo "== h2spec over TLS (ALPN h2) =="
$RUN -p "$TLS_PORT" -t -k | tail -3
echo "== h2spec over cleartext (prior knowledge) =="
$RUN -p "$PORT" | tail -12 || true
