#!/usr/bin/env bash
# Key-trust primitives shared by the two kernel recipes that verify kernel.org
# signatures: hack/guest-kernel/build.sh and
# hack/spikes/containerhost/kernel/build-framework-config.sh.
#
# This file is SOURCED, never executed. It defines functions and one variable
# (KEYS_LIB_DIR), runs nothing, reads no network, and depends on nothing but
# gpg/gpgconf at call time. Each caller keeps its own fingerprint constants:
# those literals are the trust statements, and the key files beside this one
# are caches of the bytes they name (see README.md). A key file that fails its
# assertion fails the caller; there is no fallback. The one path that re-mints
# the files from a keyserver is `hack/guest-kernel/build.sh --refresh-keys`,
# which lives in that recipe alone.
#
# Callers are expected to define die (print and exit non-zero); a fallback is
# defined here only when none exists, so the primitives never fail open.

KEYS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! declare -F die >/dev/null; then
  die() { printf 'guest-kernel: %s\n' "$*" >&2; exit 1; }
fi

# key_file FPR prints the in-tree path of the public key pinned as FPR.
key_file() { printf '%s/%s.asc\n' "$KEYS_LIB_DIR" "$1"; }

# new_gnupg_home makes a throwaway GNUPGHOME under $TMPDIR, deliberately not
# under a repo cache: gpg's daemons put their sockets in the home, and a
# socket path longer than the 104-byte sun_path limit makes every gpg call that
# needs a daemon fail ("File name too long") in a deeply nested checkout.
new_gnupg_home() {
  local home
  home="$(mktemp -d)" || return 1
  chmod 700 "$home"
  printf '%s\n' "$home"
}

# gnupg_home_rm HOME stops every daemon HOME started, THEN removes HOME. The
# order is load-bearing: dirmngr (and gpg-agent, keyboxd) outlive the gpg that
# spawned them, and they are reached only through the sockets inside HOME, so a
# remove-first cleanup leaves them running with nothing able to stop them.
gnupg_home_rm() {
  local home="$1"
  [ -n "$home" ] || return 0
  gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
  rm -rf "$home"
}

# assert_sole_key HOME FPR dies unless HOME's keyring holds exactly one primary
# key and it is FPR. "Exactly one" matters as much as "FPR": a key file that
# carried the pinned key AND a second one would let a signature by the second
# verify as good, and gpg's exit status would not tell the two apart.
assert_sole_key() {
  local home="$1" fpr="$2" held
  held="$(gpg --batch --homedir "$home" --with-colons --list-keys 2>/dev/null \
    | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { printf "%s ", $10; p = 0 }')" || held=""
  [ "$held" = "$fpr " ] \
    || die "KEY FINGERPRINT MISMATCH: expected exactly $fpr, keyring holds: ${held:-nothing}"
}

# import_key_checked HOME FPR [FILE] imports the in-tree key file for FPR (or
# FILE) and ASSERTS the keyring now holds exactly that key. The file is a cache,
# not an anchor: whatever bytes it holds, only the fingerprint decides. There is
# no network fallback; a file that fails here fails the run.
import_key_checked() {
  local home="$1" fpr="$2" file="${3:-}"
  [ -n "$file" ] || file="$(key_file "$fpr")"
  [ -f "$file" ] || die "missing pinned key file $file (mint it with 'hack/guest-kernel/build.sh --refresh-keys' and review)"
  gpg --batch --homedir "$home" --import "$file" >/dev/null 2>&1 \
    || die "could not import key file $file"
  assert_sole_key "$home" "$fpr"
}

# stage_key_file FPR DIR copies the in-tree key for FPR into DIR as signer.asc,
# for a recipe that carries DIR into its toolchain (a pod stream or a bind
# mount). The toolchain side then imports it and asserts the fingerprint; the
# transport is never what makes it the pinned key.
stage_key_file() {
  local fpr="$1" dir="$2" file
  file="$(key_file "$fpr")"
  [ -f "$file" ] || die "missing pinned key file $file (mint it with 'hack/guest-kernel/build.sh --refresh-keys' and review)"
  cp "$file" "$dir/signer.asc" || die "could not stage $file"
}
