#!/usr/bin/env bash
#
# runtimed B394 acceptance gate: the container-vm spike kernel recipe
# (hack/spikes/containerhost/kernel/build-framework-config.sh) verifies kernel.org
# signatures with the guest-kernel recipe's in-tree keys, through the shared
# hack/guest-kernel/keys/lib.sh helpers, and has no keyserver path of its own.
#
#   (a) SOURCE-SAFE: sourcing the spike runs nothing (no docker, curl, gpg call,
#       no output). A copy with the executed-guard removed must go red.
#   (b) OFFLINE IMPORT: both pinned keys import through the spike's host path
#       (import_key_checked from the sourced spike) and through its in-container
#       import block, extracted from the docker heredocs and run on the host.
#   (c) TAMPER IS FATAL: a substituted key and a second primary key appended to
#       the real one die on both paths, as does the other pinned key.
#   (d) NO KEYSERVER: statically, no keyserver hostname, gpg network option,
#       KEYSERVERS list, or dirmngr install remains in the spike. An injected
#       keyserver call must go red.
#   (e) ONE TRUST STATEMENT, TWO COPIES: the spike's two fingerprint constant
#       lines are byte-equal to build.sh's. A drifted copy must go red.
#   (f) NO ORPHANED DAEMON: with a dirmngr running in the home, the spike's
#       import + gnupg_home_rm leaves nothing alive; the spike's own
#       host_verify_sums leaves no daemon and no home behind on its die path.
#   (g) build.sh still passes hack/acceptance/B392.sh after the extraction.
#
# ZERO NETWORK, NO DOCKER: every gpg call is an import, a list, a verify of a
# local file, or a local key generation. Requires host gpg + gpgconf.
#
# Usage:  hack/acceptance/B394.sh
set -euo pipefail
GATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$GATE_DIR/../.." && pwd)"
SPIKE="$REPO_ROOT/hack/spikes/containerhost/kernel/build-framework-config.sh"
BUILD="$REPO_ROOT/hack/guest-kernel/build.sh"
LIB="$REPO_ROOT/hack/guest-kernel/keys/lib.sh"
KEYS="$REPO_ROOT/hack/guest-kernel/keys"
SELF="$GATE_DIR/B394.sh"

# Restated on purpose, as in B392.sh: a rotation must change this line too.
AUTOSIGNER_FPR="B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
DEV_FPR="647F28654894E3BD457199BE38DBBDC86092693E"

if ! command -v gpg >/dev/null 2>&1 || ! command -v gpgconf >/dev/null 2>&1; then
  echo "B394: host gpg and gpgconf are required (brew install gnupg)" >&2
  exit 1
fi

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
HOMES=()
cleanup() {
  local h
  for h in "${HOMES[@]+"${HOMES[@]}"}"; do
    gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true
    pkill -f -- "--homedir $h" >/dev/null 2>&1 || true
    rm -rf "$h"
  done
  pkill -f -- "--homedir $SCRATCH/" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# new_home sets NEW_HOME and records it for the EXIT reaper (never in $(...)).
new_home() { NEW_HOME="$(mktemp -d)"; chmod 700 "$NEW_HOME"; HOMES+=("$NEW_HOME"); }

# in_spike CMD... runs CMD in a subshell that has sourced the spike, so a die
# ends only that subshell.
# shellcheck source=SCRIPTDIR/../spikes/containerhost/kernel/build-framework-config.sh
in_spike() { (source "$SPIKE"; "$@"); }

daemons_for() { pgrep -f -- "--homedir $1( |$)" 2>/dev/null || true; }
gone_within() {
  local i
  for ((i = 0; i < $1 * 10; i++)); do
    [ -z "$(daemons_for "$2")" ] && return 0
    sleep 0.1
  done
  return 1
}

echo "==> runtimed B394 acceptance (spike kernel recipe uses the shared pinned keys)"

# ---- b394.0 — sources parse; the shared helper and key files exist -----------
b0=ok
for f in "$SELF" "$SPIKE" "$BUILD" "$LIB"; do bash -n "$f" || b0=no; done
for f in "$KEYS/$AUTOSIGNER_FPR.asc" "$KEYS/$DEV_FPR.asc"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
# shellcheck disable=SC2016  # literal source lines matched in the recipes
grep -q 'source "\$HERE/../../../guest-kernel/keys/lib.sh"' "$SPIKE" || { echo "spike does not source keys/lib.sh" >&2; b0=no; }
# shellcheck disable=SC2016  # literal source line matched in build.sh
grep -q 'source "\$KEYS_DIR/lib.sh"' "$BUILD" || { echo "build.sh does not source keys/lib.sh" >&2; b0=no; }
ladder "$b0" "b394.0  scripts parse; both recipes source hack/guest-kernel/keys/lib.sh"

# ---- (a) sourcing the spike runs nothing -------------------------------------
# Stubs shadow every external the recipe would drive; each call is logged.
STUBS="$SCRATCH/stubs"; mkdir -p "$STUBS"
for t in docker curl gpg gpgconf shasum kubectl; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\nexit 0\n' "$t" "$SCRATCH" > "$STUBS/$t"
  chmod +x "$STUBS/$t"
done

# sourced_effects FILE prints what sourcing FILE did: its stdout+stderr, its
# exit status when non-zero, and any logged external call.
sourced_effects() {
  local f="$1" out rc=0
  : > "$SCRATCH/calls.log"
  out="$(PATH="$STUBS:$PATH" bash -c 'source "$1" && declare -F main >/dev/null && declare -F import_key_checked >/dev/null' _ "$f" 2>&1)" || rc=$?
  printf '%s' "$out"
  [ "$rc" -eq 0 ] || printf 'rc=%s\n' "$rc"
  cat "$SCRATCH/calls.log"
}
eff="$(sourced_effects "$SPIKE")"
if [ -z "$eff" ]; then
  ladder ok "b394.a  sourcing the spike runs nothing (no output, no external call) and defines its helpers"
else
  printf '%s\n' "$eff" >&2
  ladder no "b394.a  sourcing the spike runs nothing (no output, no external call) and defines its helpers"
fi
# Mutation: without the executed-guard, sourcing starts the build.
awk -v lib="$LIB" '
  /^if \[ "\$\{BASH_SOURCE\[0\]\}" = "\$0" \]; then$/ { print "main \"$@\""; skip = 2; next }
  skip > 0 { skip--; next }
  { sub(/"\$HERE\/\.\.\/\.\.\/\.\.\/guest-kernel\/keys\/lib\.sh"/, "\"" lib "\""); print }' \
  "$SPIKE" > "$SCRATCH/unguarded.sh"
if grep -q '^main "\$@"$' "$SCRATCH/unguarded.sh" && [ -n "$(sourced_effects "$SCRATCH/unguarded.sh")" ]; then
  ladder ok "b394.a  mutation: an unguarded copy does something when sourced (detected)"
else
  ladder no "b394.a  mutation: an unguarded copy does something when sourced (it did not)"
fi

# ---- (b) offline import through both of the spike's key paths ----------------
# The in-container block, extracted from each docker heredoc.
BEGIN_BLK='^# ---- in-container key import '
END_BLK='^# ---- end in-container key import$'
awk -v b="$BEGIN_BLK" -v e="$END_BLK" '
  $0 ~ b { n++; inb = 1 } inb { print > (dir "/block." n) } $0 ~ e { inb = 0 }
  END { print n + 0 > (dir "/block.count") }' dir="$SCRATCH" "$SPIKE"
bs=ok
[ "$(cat "$SCRATCH/block.count")" = 2 ] || { echo "expected 2 in-container import blocks, got $(cat "$SCRATCH/block.count")" >&2; bs=no; }
cmp -s "$SCRATCH/block.1" "$SCRATCH/block.2" || { echo "the two in-container import blocks differ" >&2; bs=no; }
# shellcheck disable=SC2016  # literal patterns matched in the spike's source
{ [ "$(grep -c 'stage_key_file "\$KERNEL_KEY_FPR" "\$work"' "$SPIKE")" = 1 ] \
  && [ "$(grep -c 'stage_key_file "\$KERNEL_DEV_KEY_FPR" "\$work"' "$SPIKE")" = 1 ] \
  && [ "$(grep -c -- '-e PINNED_FPR="\$KERNEL_KEY_FPR"' "$SPIKE")" = 1 ] \
  && [ "$(grep -c -- '-e PINNED_FPR="\$KERNEL_DEV_KEY_FPR"' "$SPIKE")" = 1 ]; } \
  || { echo "the two docker stages do not stage their own key and pass its fingerprint" >&2; bs=no; }
ladder "$bs" "b394.b  both docker stages stage the pinned key file and run one identical in-container import block"

# container_import DIR FPR runs the extracted block on the host against
# DIR/signer.asc in a fresh GNUPGHOME, exactly as the container would.
container_import() {
  local dir="$1" fpr="$2" rc=0
  new_home
  sed "s|/work/signer.asc|$dir/signer.asc|" "$SCRATCH/block.1" > "$dir/block.sh"
  GNUPGHOME="$NEW_HOME" PINNED_FPR="$fpr" bash -c 'set -euo pipefail; source "$1"' _ "$dir/block.sh" || rc=$?
  gpgconf --homedir "$NEW_HOME" --kill all >/dev/null 2>&1 || true
  return "$rc"
}

for fpr in "$AUTOSIGNER_FPR" "$DEV_FPR"; do
  b=ok
  new_home; h="$NEW_HOME"
  in_spike import_key_checked "$h" "$fpr" 2>"$SCRATCH/b.err" || { cat "$SCRATCH/b.err" >&2; b=no; }
  d="$SCRATCH/stage.$fpr"; mkdir -p "$d"
  in_spike stage_key_file "$fpr" "$d" 2>"$SCRATCH/b.err" || { cat "$SCRATCH/b.err" >&2; b=no; }
  container_import "$d" "$fpr" 2>"$SCRATCH/b.err" || { cat "$SCRATCH/b.err" >&2; b=no; }
  ladder "$b" "b394.b  key $fpr imports offline on the spike's host path and its in-container path"
done

# ---- (c) tamper dies on both paths -------------------------------------------
new_home; gen="$NEW_HOME"
gpg --batch --homedir "$gen" --passphrase '' --quick-gen-key \
  'B394 tamper <tamper@example.invalid>' ed25519 sign never >/dev/null 2>&1
gpg --batch --homedir "$gen" --armor --export > "$SCRATCH/attacker.asc"
gpgconf --homedir "$gen" --kill all >/dev/null 2>&1 || true
[ -s "$SCRATCH/attacker.asc" ] || { echo "B394: could not generate the stand-in key" >&2; exit 1; }
cat "$KEYS/$AUTOSIGNER_FPR.asc" "$SCRATCH/attacker.asc" > "$SCRATCH/appended.asc"

must_die() {
  local name="$1" file="$2" rc d
  rc=0; new_home
  in_spike import_key_checked "$NEW_HOME" "$AUTOSIGNER_FPR" "$file" 2>"$SCRATCH/c.err" || rc=$?
  if [ "$rc" -ne 0 ] && grep -q "KEY FINGERPRINT MISMATCH" "$SCRATCH/c.err"; then
    echo "      red as required (host, $name): $(head -1 "$SCRATCH/c.err")"
    ladder ok "b394.c  host path: $name dies"
  else
    echo "      rc=$rc stderr: $(cat "$SCRATCH/c.err")" >&2
    ladder no "b394.c  host path: $name dies"
  fi
  rc=0; d="$SCRATCH/tamper.$RANDOM"; mkdir -p "$d"; cp "$file" "$d/signer.asc"
  container_import "$d" "$AUTOSIGNER_FPR" 2>"$SCRATCH/c.err" || rc=$?
  if [ "$rc" -ne 0 ] && grep -q "KEY FINGERPRINT MISMATCH" "$SCRATCH/c.err"; then
    echo "      red as required (container block, $name): $(head -1 "$SCRATCH/c.err")"
    ladder ok "b394.c  in-container block: $name dies"
  else
    echo "      rc=$rc stderr: $(cat "$SCRATCH/c.err")" >&2
    ladder no "b394.c  in-container block: $name dies"
  fi
}
must_die "substituted key"             "$SCRATCH/attacker.asc"
must_die "second primary key appended" "$SCRATCH/appended.asc"
must_die "the other pinned key"        "$KEYS/$DEV_FPR.asc"

# ---- (d) no keyserver anywhere in the spike ----------------------------------
KS_HOST='keyserver\.[a-z0-9.-]+|[a-z0-9.-]+\.keyserver|pgp\.mit\.edu|openpgp\.org|pgpkeys\.|hkps?://|pks/lookup'
KS_OPT='--(recv-keys|keyserver|refresh-keys|fetch-keys|search-keys|locate-keys|auto-key-locate|auto-key-retrieve)'
KS_MISC='KEYSERVERS|dirmngr'
ks_hits() { grep -nEi -- "$KS_HOST|$KS_OPT|$KS_MISC" "$1" || true; }
hits="$(ks_hits "$SPIKE")"
if [ -z "$hits" ]; then
  ladder ok "b394.d  no keyserver hostname, gpg network option, KEYSERVERS list, or dirmngr in the spike"
else
  printf '%s\n' "$hits" >&2
  ladder no "b394.d  no keyserver hostname, gpg network option, KEYSERVERS list, or dirmngr in the spike"
fi
sed 's|^main() {$|probe() { gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys 0xDEAD; }\
main() {|' "$SPIKE" > "$SCRATCH/ks-mutant.sh"
[ -n "$(ks_hits "$SCRATCH/ks-mutant.sh")" ] && dm=ok || dm=no
ladder "$dm" "b394.d  mutation: an injected keyserver call goes red"

# ---- (e) the fingerprint constants are byte-equal to build.sh's --------------
const_line() { grep -E "^readonly $2=" "$1" || true; }
consts_equal() {
  local a="$1" b="$2" name la lb
  for name in KERNEL_KEY_FPR KERNEL_DEV_KEY_FPR; do
    la="$(const_line "$a" "$name")"; lb="$(const_line "$b" "$name")"
    [ -n "$la" ] && [ "$(printf '%s\n' "$la" | wc -l | tr -d ' ')" = 1 ] && [ "$la" = "$lb" ] || return 1
  done
}
e=ok
consts_equal "$SPIKE" "$BUILD" || e=no
[ "$(const_line "$SPIKE" KERNEL_KEY_FPR)" = "readonly KERNEL_KEY_FPR=\"$AUTOSIGNER_FPR\"" ] || e=no
[ "$(const_line "$SPIKE" KERNEL_DEV_KEY_FPR)" = "readonly KERNEL_DEV_KEY_FPR=\"$DEV_FPR\"" ] || e=no
ladder "$e" "b394.e  the spike's two fingerprint constants are byte-equal to build.sh's (and the pinned values)"
sed "s|^readonly KERNEL_DEV_KEY_FPR=\"$DEV_FPR\"|readonly KERNEL_DEV_KEY_FPR=\"${DEV_FPR%?}0\"|" "$SPIKE" > "$SCRATCH/fpr-mutant.sh"
consts_equal "$SCRATCH/fpr-mutant.sh" "$BUILD" && em=no || em=ok
ladder "$em" "b394.e  mutation: a one-character drift in a spike constant goes red"

# ---- (f) no daemon survives the spike's key path -----------------------------
new_home; home="$NEW_HOME"
gpgconf --homedir "$home" --launch dirmngr >/dev/null 2>&1 || true
if [ -z "$(daemons_for "$home")" ]; then
  ladder no "b394.f  precondition: a dirmngr is running in the throwaway home"
else
  f=ok
  in_spike import_key_checked "$home" "$AUTOSIGNER_FPR" 2>"$SCRATCH/f.err" || { cat "$SCRATCH/f.err" >&2; f=no; }
  in_spike gnupg_home_rm "$home" || f=no
  gone_within 5 "$home" || { echo "survivors: $(daemons_for "$home")" >&2; f=no; }
  [ ! -e "$home" ] || { echo "home not removed: $home" >&2; f=no; }
  ladder "$f" "b394.f  with a dirmngr running, the spike's import + gnupg_home_rm leaves no daemon and no home"
fi
# End to end: host_verify_sums over an unsigned file must die, and on that die
# path its throwaway home (under a dedicated TMPDIR) must leave nothing behind.
VTMP="$SCRATCH/vtmp"; mkdir -p "$VTMP"
printf 'not a signed file\n' > "$SCRATCH/bogus.asc"
rc=0
TMPDIR="$VTMP/" in_spike host_verify_sums "$SCRATCH/bogus.asc" >/dev/null 2>"$SCRATCH/f2.err" || rc=$?
f2=ok
if [ "$rc" -eq 0 ] || ! grep -q "PGP VERIFICATION FAILED" "$SCRATCH/f2.err"; then
  echo "rc=$rc $(cat "$SCRATCH/f2.err")" >&2; f2=no
fi
[ -z "$(pgrep -f -- "--homedir $VTMP/" 2>/dev/null || true)" ] || { echo "daemon survived under $VTMP" >&2; f2=no; }
[ -z "$(ls -A "$VTMP")" ] || { echo "home left behind: $(ls -A "$VTMP")" >&2; f2=no; }
ladder "$f2" "b394.f  the spike's host_verify_sums dies on a bad signature and leaves no daemon and no home"

# ---- (g) build.sh still passes B392 ------------------------------------------
if "$GATE_DIR/B392.sh" > "$SCRATCH/b392.out" 2>&1; then
  ladder ok "b394.g  hack/acceptance/B392.sh still green after the lib.sh extraction ($(tail -1 "$SCRATCH/b392.out"))"
else
  cat "$SCRATCH/b392.out" >&2
  ladder no "b394.g  hack/acceptance/B392.sh still green after the lib.sh extraction"
fi

echo
echo "B394: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
