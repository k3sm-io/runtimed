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

clang \
  -arch arm64 \
  -dynamiclib \
  -fPIC \
  -O2 \
  -Wall -Wextra \
  -install_name "@rpath/$(basename "$OUT")" \
  -o "$OUT" \
  "$SRC"

echo "built $OUT"
