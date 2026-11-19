#!/bin/sh
# The linux-gnu binaries are built inside a glibc 2.28 image (manylinux_2_28,
# AlmaLinux 8; release.yml and ci.yml pin it by digest), because a binary
# needs at least the glibc it was linked against: the statically linked
# libgcc unwinder, libstdc++ and every libc call bind to the newest symbol
# versions the build machine has. Built on Ubuntu 22.04 the engine needed
# glibc 2.35 (2.34 where the vendor backported _dl_find_object, as RHEL 9
# and Amazon Linux 2023 did) and did not load on Debian 11 or Ubuntu 20.04
# (2.31) or on RHEL 8 (2.28). Built here it needs at most 2.28, the floor of
# Node.js's own Linux binaries: wherever an official `node` runs, so does the
# engine.
#
# The compiler is unchanged: clang, lld and llvm-profdata 18.1.8 (AlmaLinux
# AppStream, signed packages), with gcc-toolset's libstdc++ linked statically
# as before. Flags, CPU baselines and BoringSSL's build are tools/build.mjs's
# and tools/boringssl.mjs's, as on every other platform.
#
#   docker run --rm -v "$PWD:/repo" -w /repo -v <node install dir>:/opt/node:ro \
#     quay.io/pypa/manylinux_2_28_<arch>@sha256:... sh tools/linux-gnu-build.sh <command...>
#
# Runs <command> (for example `node tools/pgo.mjs --all`) with that toolchain
# and the mounted Node.js (an official build: it needs glibc 2.28 too), then
# fails if any linux-gnu binary in build/ requires a glibc newer than 2.28 or
# a libstdc++ from the system, or has more thread-local data than glibc will
# place in a thread's static block.
#
# The last one is about speed, not loading. The addon is dlopen'ed, and glibc
# gives the thread_local variables of dlopen'ed modules a place in the static
# TLS block only while they fit a small budget shared by every module loaded
# that way (glibc.rtld.optional_static_tls, 512 bytes by default). A module
# that fits reaches a variable in two instructions; one that does not goes
# through the dynamic resolver, about twenty instructions per access - 180 per
# request when the block was 553 bytes. Half the budget is the limit here, so
# that another addon in the process does not push this one out.
set -eu

LLVM_VERSION=18.1.8
GLIBC_FLOOR=2.28
TLS_BUDGET=256

dnf -y -q --setopt=install_weak_deps=False install \
  "clang-$LLVM_VERSION" "lld-$LLVM_VERSION" "llvm-$LLVM_VERSION" "compiler-rt-$LLVM_VERSION" ninja-build
export PATH="/opt/node/bin:$PATH" CXX=clang++ LLVM_PROFDATA=llvm-profdata
echo "linux-gnu build: $(ldd --version | head -1); $(clang++ --version | head -1); node $(node --version)"

"$@"

status=0
for f in build/moro_engine_linux_*_gnu_*.node; do
  [ -e "$f" ] || continue
  needs=$(readelf -V --wide "$f" | sed -n 's/.*Name: \([A-Z]*_[0-9.]*\).*/\1/p' | sort -u)
  glibc=$(printf '%s\n' "$needs" | sed -n 's/^GLIBC_//p' | sort -V | tail -1)
  echo "$f: GLIBC_$glibc"
  if [ "$(printf '%s\n%s\n' "$glibc" "$GLIBC_FLOOR" | sort -V | tail -1)" != "$GLIBC_FLOOR" ]; then
    echo "  needs glibc $glibc, newer than the $GLIBC_FLOOR floor:"
    readelf --dyn-syms --wide "$f" | grep "@GLIBC_$glibc" | sed 's/^/    /'
    status=1
  fi
  # libstdc++ is linked in statically: a version needed from the system's
  # copy (GLIBCXX_*, CXXABI_*) would make the floor that copy's instead.
  if printf '%s\n' "$needs" | grep -q -E '^(GLIBCXX|CXXABI)_'; then
    echo "  needs the system libstdc++: $(printf '%s\n' "$needs" | grep -E '^(GLIBCXX|CXXABI)_' | tr '\n' ' ')"
    status=1
  fi
  # The PT_TLS segment's size in memory (0 when the binary has none).
  tls=$(( $(readelf -lW "$f" | awk '$1 == "TLS" { print $6; found = 1 } END { if (!found) print 0 }') ))
  if [ "$tls" -gt "$TLS_BUDGET" ]; then
    echo "  $tls bytes of thread-local data, over the $TLS_BUDGET-byte limit (see the head of this script); the largest:"
    readelf -sW "$f" | awk '$4 == "TLS" { print $3, $8 }' | sort -rn | head -8 | sed 's/^/    /'
    status=1
  fi
done
exit $status
