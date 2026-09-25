#!/usr/bin/env bash
#
# runtimed B392 acceptance gate — the guest-kernel recipe's signing keys are
# pinned MATERIAL imported offline, their throwaway keyrings leave no daemon
# behind, and only the explicit --refresh-keys mode can reach a keyserver.
#
# What the item buys, and therefore what this gate must show:
#
#   (a) OFFLINE IMPORT — each in-tree key under hack/guest-kernel/keys/ imports
#       into a throwaway GNUPGHOME and passes build.sh's own fingerprint
#       assertion, with no network.
#   (b) TAMPER IS FATAL — the same helper, handed a substituted key, a second
#       key appended to the real one, the other pinned key, corrupted armor, or
#       a missing file, DIES. This is the red half: an assertion that cannot be
#       made to fail is not an assertion.
#   (c) NO ORPHANED DAEMON — with a dirmngr deliberately running in the
#       throwaway home, the import + cleanup helper leaves no process for that
#       home alive. The mutation leg removes the home FIRST and shows the
#       daemon then survives, so the check can see an orphan and the ordering
#       in gnupg_home_rm is load-bearing.
#   (d) ONE KEYSERVER PATH — statically, no keyserver hostname and no gpg
#       network option appears in build.sh outside the marked --refresh-keys
#       region. A copy with an injected keyserver call outside the region must
#       go red.
#
# The gate sources build.sh (its main runs only when executed) and calls the
# production helpers, so it tests the code the build runs rather than a copy.
#
# ZERO NETWORK: every gpg call here is an import, a list, or a local key
# generation. Requires host gpg + gpgconf (brew install gnupg).
#
# Usage:  hack/acceptance/B392.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$REPO_ROOT/hack/guest-kernel/build.sh"
KEYS="$REPO_ROOT/hack/guest-kernel/keys"
SELF="$HERE/B392.sh"

# The pinned values. The gate restates them on purpose: a change to either
# constant must also change this line, which puts the reviewed act in front of
# a second reader.
AUTOSIGNER_FPR="B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
DEV_FPR="647F28654894E3BD457199BE38DBBDC86092693E"

if ! command -v gpg >/dev/null 2>&1 || ! command -v gpgconf >/dev/null 2>&1; then
  echo "B392: host gpg and gpgconf are required (brew install gnupg)" >&2
  exit 1
fi

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# Throwaway homes live under $TMPDIR (mktemp -d): gpg daemons put their sockets
# in the home, and a long path overflows sun_path.
SCRATCH="$(mktemp -d)"
HOMES=()
cleanup() {
  local h
  for h in "${HOMES[@]+"${HOMES[@]}"}"; do
    gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true
    pkill -f -- "--homedir $h" >/dev/null 2>&1 || true
    rm -rf "$h"
  done
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# new_home sets NEW_HOME and records it for the EXIT reaper. It must not be
# called inside $(...): the record would land in a subshell's copy of HOMES.
new_home() { NEW_HOME="$(mktemp -d)"; chmod 700 "$NEW_HOME"; HOMES+=("$NEW_HOME"); }

# in_build CMD... runs CMD in a subshell that has sourced build.sh, so a die in
# the helper ends only that subshell. stderr is kept for the message asserts.
# shellcheck source=../guest-kernel/build.sh
in_build() { (source "$BUILD"; "$@"); }

# daemons_for HOME prints the pids of any process started with --homedir HOME.
daemons_for() { pgrep -f -- "--homedir $1( |$)" 2>/dev/null || true; }

# gone_within SECS HOME waits for every daemon of HOME to exit.
gone_within() {
  local i
  for ((i = 0; i < $1 * 10; i++)); do
    [ -z "$(daemons_for "$2")" ] && return 0
    sleep 0.1
  done
  return 1
}

echo "==> runtimed B392 acceptance (pinned guest-kernel signing keys)"

# ---- b392.0 — sources exist, parse, and the constants are the pinned values --
b0=ok
bash -n "$SELF" || b0=no
bash -n "$BUILD" || b0=no
for f in "$KEYS/$AUTOSIGNER_FPR.asc" "$KEYS/$DEV_FPR.asc" "$KEYS/README.md"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
got_auto="$(bash -c 'source "$1"; printf %s "$KERNEL_KEY_FPR"' _ "$BUILD")"
got_dev="$(bash -c 'source "$1"; printf %s "$KERNEL_DEV_KEY_FPR"' _ "$BUILD")"
[ "$got_auto" = "$AUTOSIGNER_FPR" ] || { echo "KERNEL_KEY_FPR is $got_auto" >&2; b0=no; }
[ "$got_dev" = "$DEV_FPR" ] || { echo "KERNEL_DEV_KEY_FPR is $got_dev" >&2; b0=no; }
ladder "$b0" "b392.0  build.sh + key files present; fingerprint constants are the pinned values"

# ---- (a) offline import passes the assertion --------------------------------
for fpr in "$AUTOSIGNER_FPR" "$DEV_FPR"; do
  if in_build check_key_file "$fpr" 2>"$SCRATCH/a.err"; then
    ladder ok "b392.a  in-tree key $fpr imports offline and passes the fingerprint assertion"
  else
    cat "$SCRATCH/a.err" >&2
    ladder no "b392.a  in-tree key $fpr imports offline and passes the fingerprint assertion"
  fi
done

# ---- (b) tampered key files die ---------------------------------------------
# A stand-in attacker key, generated locally (no network, no passphrase).
new_home; gen="$NEW_HOME"
gpg --batch --homedir "$gen" --passphrase '' --quick-gen-key \
  'B392 tamper <tamper@example.invalid>' ed25519 sign never >/dev/null 2>&1
gpg --batch --homedir "$gen" --armor --export > "$SCRATCH/attacker.asc"
gpgconf --homedir "$gen" --kill all >/dev/null 2>&1 || true
[ -s "$SCRATCH/attacker.asc" ] || { echo "B392: could not generate the stand-in key" >&2; exit 1; }

cat "$KEYS/$AUTOSIGNER_FPR.asc" "$SCRATCH/attacker.asc" > "$SCRATCH/appended.asc"
# Corrupt the armor: swap base64 characters in the first body line.
awk 'NR == 3 { gsub(/A/, "B"); gsub(/m/, "n") } { print }' \
  "$KEYS/$AUTOSIGNER_FPR.asc" > "$SCRATCH/corrupt.asc"
cmp -s "$SCRATCH/corrupt.asc" "$KEYS/$AUTOSIGNER_FPR.asc" \
  && { echo "B392: the corruption did not change the file" >&2; exit 1; }

# must_die NAME FILE PATTERN — check_key_file for the autosigner must exit
# non-zero with PATTERN on stderr.
must_die() {
  local name="$1" file="$2" pattern="$3" rc=0
  in_build check_key_file "$AUTOSIGNER_FPR" "$file" 2>"$SCRATCH/b.err" || rc=$?
  if [ "$rc" -ne 0 ] && grep -Eq "$pattern" "$SCRATCH/b.err"; then
    echo "      red as required ($name): $(head -1 "$SCRATCH/b.err")"
    ladder ok "b392.b  tampered key ($name) dies"
  else
    echo "      rc=$rc stderr: $(cat "$SCRATCH/b.err")" >&2
    ladder no "b392.b  tampered key ($name) dies"
  fi
}
must_die "substituted key"      "$SCRATCH/attacker.asc"  "KEY FINGERPRINT MISMATCH"
must_die "second key appended"  "$SCRATCH/appended.asc"  "KEY FINGERPRINT MISMATCH"
must_die "the other pinned key" "$KEYS/$DEV_FPR.asc"     "KEY FINGERPRINT MISMATCH"
must_die "corrupted armor"      "$SCRATCH/corrupt.asc"   "KEY FINGERPRINT MISMATCH|could not import key file"
must_die "missing file"         "$SCRATCH/absent.asc"    "missing pinned key file"

# ---- (c) no dirmngr survives the import + cleanup ---------------------------
new_home; home="$NEW_HOME"
gpgconf --homedir "$home" --launch dirmngr >/dev/null 2>&1 || true
if [ -z "$(daemons_for "$home")" ]; then
  ladder no "b392.c  precondition: a dirmngr is running in the throwaway home"
else
  ladder ok "b392.c  precondition: a dirmngr is running in the throwaway home"
  c=ok
  in_build import_key_checked "$home" "$AUTOSIGNER_FPR" 2>"$SCRATCH/c.err" \
    || { cat "$SCRATCH/c.err" >&2; c=no; }
  in_build gnupg_home_rm "$home" || c=no
  gone_within 5 "$home" || { echo "survivors: $(daemons_for "$home")" >&2; c=no; }
  [ ! -e "$home" ] || { echo "home not removed: $home" >&2; c=no; }
  ladder "$c" "b392.c  after import + gnupg_home_rm, no daemon for the home survives and the home is gone"
fi

# Mutation: the wrong order (remove, then kill) must leave the dirmngr running,
# or leg (c) could not tell the two orders apart.
new_home; home2="$NEW_HOME"
gpgconf --homedir "$home2" --launch dirmngr >/dev/null 2>&1 || true
if [ -n "$(daemons_for "$home2")" ]; then
  rm -rf "$home2"
  gpgconf --homedir "$home2" --kill all >/dev/null 2>&1 || true
  if gone_within 2 "$home2"; then
    ladder no "b392.c  mutation: remove-before-kill orphans the dirmngr (it did not)"
  else
    ladder ok "b392.c  mutation: remove-before-kill orphans the dirmngr (detected, then reaped)"
  fi
  pkill -f -- "--homedir $home2" >/dev/null 2>&1 || true
else
  ladder no "b392.c  mutation precondition: a dirmngr is running in the second home"
fi

# ---- (d) no keyserver outside the --refresh-keys region ---------------------
KS_HOST='keyserver\.[a-z0-9.-]+|[a-z0-9.-]+\.keyserver|pgp\.mit\.edu|openpgp\.org|pgpkeys\.|hkps?://|pks/lookup'
KS_OPT='gpg[^#]*--(recv-keys|keyserver|refresh-keys|fetch-keys|search-keys|locate-keys|auto-key-locate|auto-key-retrieve)'
BEGIN_MARK='^# ---- refresh-keys: '
END_MARK='^# ---- end refresh-keys$'

# outside_hits FILE prints the lines of FILE outside the marked region that name
# a keyserver or pass gpg a network option; exits 2 if the markers are not
# present exactly once each, in order.
outside_hits() {
  local f="$1" nb ne
  nb="$(grep -Ec "$BEGIN_MARK" "$f" || true)"; ne="$(grep -Ec "$END_MARK" "$f" || true)"
  [ "$nb" = 1 ] && [ "$ne" = 1 ] || return 2
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0 ~ b { inr = 1 } !inr { print NR": "$0 } $0 ~ e { inr = 0 }' "$f" \
    | grep -Ei -- "$KS_HOST|$KS_OPT" || true
}
inside_hits() {
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0 ~ b { inr = 1 } inr { print } $0 ~ e { inr = 0 }' "$1" \
    | grep -Eic -- "$KS_HOST|$KS_OPT" || true
}

rc=0; hits="$(outside_hits "$BUILD")" || rc=$?
if [ "$rc" -eq 0 ] && [ -z "$hits" ]; then
  ladder ok "b392.d  no keyserver hostname or gpg network option outside the --refresh-keys region"
else
  echo "rc=$rc hits:" >&2; printf '%s\n' "$hits" >&2
  ladder no "b392.d  no keyserver hostname or gpg network option outside the --refresh-keys region"
fi
n_in="$(inside_hits "$BUILD")"
[ "${n_in:-0}" -gt 0 ] && d1=ok || d1=no
ladder "$d1" "b392.d  the region itself is non-empty (it carries the keyserver path: $n_in lines)"

# Mutation: a keyserver call injected before main (outside the region) is caught.
sed 's|^main() {$|probe() { gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys 0xDEAD; }\
main() {|' "$BUILD" > "$SCRATCH/mutant.sh"
rc=0; hits="$(outside_hits "$SCRATCH/mutant.sh")" || rc=$?
[ "$rc" -eq 0 ] && [ -n "$hits" ] && dm=ok || dm=no
ladder "$dm" "b392.d  mutation: an injected keyserver call outside the region goes red"

# Supporting static facts: the in-pod imports read the streamed file and assert.
s=ok
[ "$(grep -c 'gpg --batch --import /work/signer.asc' "$BUILD")" = 2 ] || s=no
# shellcheck disable=SC2016  # the pattern matches a literal $KERNEL in build.sh
[ "$(grep -c 'stage_key_file "\$KERNEL' "$BUILD")" = 2 ] || s=no
grep -q 'KEYSERVERS' "$BUILD" && s=no
ladder "$s" "b392.s  both toolchain stages import the streamed key file; no KEYSERVERS list remains"

echo
echo "B392: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
