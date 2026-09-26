#!/usr/bin/env bash
# Build the k3sm path-rebase DYLD interpose shim.
#
# A plain C dylib (NOT Go cgo) with a __DATA,__interpose section. Loaded into a pod
# via DYLD_INSERT_LIBRARIES, it rewrites absolute paths under the pod's declared
# mount prefixes to "<rootfs><path>" so a standard absolute volume mount resolves to
# the materialized copy under the pod data volume (no chroot — see the .c header).
#
# Usage:
#   hack/build-pathshim.sh [output-dir]
# Output:
#   <output-dir>/libk3sm_pathrebase_shim.dylib   (default output-dir: build/)
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

SRC="shim/pathrebase_shim.c"
OUT_DIR="${1:-build}"
OUT="${OUT_DIR}/libk3sm_pathrebase_shim.dylib"

mkdir -p "$OUT_DIR"

# arm64 + arm64e + x86_64 universal (fat) dylib so it loads regardless of the pod
# binary's arch: dyld HARD-TERMINATES a process whose DYLD_INSERT_LIBRARIES library
# lacks a slice for that process's architecture, so an arm64-only shim would kill a
# darwin/amd64 pod payload running under Rosetta rather than merely skip path
# rebasing. The arm64e slice is for the node's re-signed shell copies: Apple ships
# /bin/bash, /bin/zsh, /bin/dash and /usr/bin/env as arm64e, an arm64e process
# refuses a plain arm64 inserted library ("missing compatible architecture (have
# 'x86_64,arm64', need 'arm64e')"), and it is precisely those processes this shim's
# exec rewrite exists to keep it loaded in. Apple does not promise a stable arm64e
# ABI for third-party code, so the slice is proven by a LIVE load, not by headers:
# pkg/runtime TestPathShimLoadsIntoArm64e. TestPathShimIsUniversalBinary asserts
# the other two slices -- assert the ARTIFACT, never these flags.
clang \
  -arch arm64 \
  -arch arm64e \
  -arch x86_64 \
  -dynamiclib \
  -fPIC \
  -O2 \
  -Wall -Wextra \
  -install_name "@rpath/$(basename "$OUT")" \
  -o "$OUT" \
  "$SRC"

echo "built $OUT"
