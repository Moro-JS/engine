#!/usr/bin/env bash
# Build and test the engine inside a Linux container from a macOS/Linux host
# with Docker: the way to exercise the io_uring transport, the glibc and musl
# toolchains, and the seccomp fallback without a CI round trip.
#
#   tools/dev-linux.sh [--musl] [--seccomp-default] [--] <command...>
#
#   tools/dev-linux.sh                       # build for the container's Node + full test
#   tools/dev-linux.sh --musl                # same on Alpine (musl, clang)
#   tools/dev-linux.sh --seccomp-default     # Docker's default seccomp (io_uring BLOCKED)
#   tools/dev-linux.sh -- npm run test:workers   # any command in the container
#
# By default the container runs with seccomp=unconfined so io_uring is
# available (Docker's default profile blocks it, which is exactly the
# fallback --seccomp-default exercises). The repo is bind-mounted; the Linux
# binaries land in build/ next to the host's (names carry the platform), and
# node_modules is not needed (the engine has no runtime dependencies).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=node:24-bookworm
SETUP='apt-get update -qq >/dev/null && apt-get install -y -qq clang lld llvm curl zlib1g-dev libssl-dev >/dev/null'
SECCOMP=(--security-opt seccomp=unconfined)
while [ $# -gt 0 ]; do
  case "$1" in
    --musl) IMAGE=node:24-alpine; SETUP='apk add --no-cache build-base clang lld llvm curl zlib-dev openssl-dev >/dev/null'; shift ;;
    --seccomp-default) SECCOMP=(); shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
CMD="${*:-node tools/build.mjs && npm test}"

# -t only when attached to a terminal (CI and scripted runs have none).
TTY=(); [ -t 0 ] && TTY=(-it)
# ${arr[@]+"${arr[@]}"}: an empty array is an unbound variable under set -u on
# bash < 4.4 (macOS ships 3.2).
exec docker run --rm ${TTY[@]+"${TTY[@]}"} ${SECCOMP[@]+"${SECCOMP[@]}"} \
  -v "$PWD:/repo" -w /repo \
  -e MORO_ENGINE_TRANSPORT="${MORO_ENGINE_TRANSPORT:-}" \
  -e MORO_ENGINE_REQUIRE_TRANSPORT="${MORO_ENGINE_REQUIRE_TRANSPORT:-}" \
  -e MORO_ENGINE_FASTCALL="${MORO_ENGINE_FASTCALL:-}" \
  -e MORO_ENGINE_NOTIFY="${MORO_ENGINE_NOTIFY:-}" \
  "$IMAGE" sh -c "$SETUP && uname -r && $CMD"
