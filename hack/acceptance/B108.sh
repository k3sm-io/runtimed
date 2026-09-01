#!/usr/bin/env bash
#
# runtimed B108 acceptance gate — the runnable proof that the guest boot
# artifacts a vm pod boots are PINNED in source and ENSURED by digest.
#
# What the item buys, and therefore what this gate must show:
#
#   PIN — the kernel + initramfs a node may boot are named by an in-code digest
#   (pkg/guestartifacts/pins.go). Bumping one is a source change and therefore a
#   release; there is no path by which the bytes a guest boots change without a
#   reviewed commit. A pin the guest build has not minted yet is EMPTY, never
#   fabricated, and Lookup refuses it — so a build carrying an unminted pin fails
#   every vm pod closed instead of booting whatever is on disk.
#
#   ENSURE — pkg/guestartifacts/ensure.go materialises the pinned pair into a
#   content-addressed node cache: verify-before-rename, re-verify on every start,
#   re-fetch what does not match, retain the active set plus one previous, and
#   return the error (never abort) when the publisher is unreachable.

#   FETCH — the production fetcher is https-only with no scheme fallback (a
#   redirect cannot downgrade it either) and caps one body at MaxArtifactBytes,
#   so a garbage endpoint cannot fill the node's disk with something that was
#   never going to hash.
#
#   LOCATE — pkg/guestartifacts/locator.go re-hashes both artifacts against the
#   pin on EVERY guest boot, not once at daemon start. The daemon runs for weeks
#   and a VZ-booted kernel gets no code-signing check from macOS, so the sha256
#   is the whole trust chain and is enforced per use; the gate asserts the daemon
#   wires THAT locator and not a constant closure.
#
# THE MUTATION DISCIPLINE. Every assertion below is paired with a state a
# verification-free implementation would accept. The Go legs carry that pairing
# internally as Mutation* subtests — a flipped cached byte, an appended byte, a
# truncated download, a retained set renamed to a digest that is not its own —
# and this gate asserts each one RAN and PASSED rather than trusting a package
# level "ok". The AST-walk leg is mutated from the outside instead: the gate
# copies pins.go into a scratch module, empties the pin table (and separately
# corrupts a digest), and asserts the walk goes RED. A completeness check that
# cannot be made to fail is not a check.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this Mac's Go
# toolchain can itself be x86_64-under-Rosetta (`go env GOARCH` -> amd64), and an
# unpinned build silently decides arch-sensitive behaviour. The product is
# darwin/arm64-only.
#
# ZERO NETWORK, zero privilege, no VM: every leg is unit-tier by construction —
# the fetcher is a seam and the tests fill it from memory. There is no lab tier.
#
# Usage:  hack/acceptance/B108.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PKG_DIR="$REPO_ROOT/pkg/guestartifacts"
PINS="$PKG_DIR/pins.go"
ENSURE="$PKG_DIR/ensure.go"
PINS_TEST="$PKG_DIR/pins_test.go"
ENSURE_TEST="$PKG_DIR/ensure_test.go"
WALK_TEST="$PKG_DIR/pins_completeness_test.go"
LOCATOR="$PKG_DIR/locator.go"
LOCATOR_TEST="$PKG_DIR/locator_test.go"
MAIN="$REPO_ROOT/cmd/k3sm-runtimed/main.go"
SELF="$HERE/B108.sh"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed B108 acceptance (guest-artifact pin + ensure)"

# ---- b108.0 — the gate parses and every source under test exists ------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$PINS" "$ENSURE" "$LOCATOR" "$PINS_TEST" "$ENSURE_TEST" "$WALK_TEST" "$LOCATOR_TEST" "$MAIN"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "b108.0  gate parses (bash -n) + pkg/guestartifacts/{pins,ensure,locator}.go and their tests present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B108: the gate or a source under test is missing/unparseable — nothing else can run" >&2
	echo "B108: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b108.1 — gofmt ---------------------------------------------------------
# Asserted on the package rather than the repo so this gate reddens for its own
# diff and not for someone else's.
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/guestartifacts 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "b108.1  gofmt -l pkg/guestartifacts is empty"
else
	echo "$fmt"
	ladder no "b108.1  gofmt -l pkg/guestartifacts is empty"
fi

# ---- b108.2 — go vet --------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/guestartifacts/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "b108.2  go vet ./pkg/guestartifacts/... is clean"
else
	tail -20 "$SCRATCH/vet.log"
	ladder no "b108.2  go vet ./pkg/guestartifacts/... is clean"
fi

# ---- b108.3 — the pin is declared in exactly one place ----------------------
# ONE map entry, keyed by ONE ActiveGuestKernel const, is the whole point of the
# pin file: a second table or a second active constant is a second answer to
# "which kernel does this build boot", and nothing downstream could tell which
# one won.
one=ok
[ "$(grep -cE '^const ActiveGuestKernel = "' "$PINS")" = 1 ] || one=no
[ "$(grep -cE '^var guestKernelPins = map\[string\]GuestKernelPin\{$' "$PINS")" = 1 ] || one=no
[ "$(grep -cE '^\tActiveGuestKernel: \{$' "$PINS")" = 1 ] || one=no
tables="$( { grep -rn --include='*.go' 'map\[string\]GuestKernelPin{' "$REPO_ROOT/pkg" "$REPO_ROOT/cmd" 2>/dev/null || true; } | { grep -v '_test\.go:' || true; } | wc -l | tr -d ' ')"
[ "$tables" = 1 ] || one=no
ladder "$one" "b108.3  exactly one ActiveGuestKernel const and one shipped pin table (found $tables tables)"

# ---- b108.4 — the pin fails closed, it never fabricates ---------------------
# The three sentinels exist and are the fail-closed vocabulary; no digest-shaped
# literal has been invented in the shipped table while the guest build has not
# run. The second half is what makes "honest zero values" a checkable claim
# rather than a promise in a comment.
fc=ok
grep -qE '^var ErrUnknownVersion = errors\.New\(' "$PINS" || fc=no
grep -qE '^var ErrPinIncomplete = errors\.New\(' "$PINS" || fc=no
grep -qE '^var ErrDigestMismatch = errors\.New\(' "$PINS" || fc=no
grep -qE 'func \(p GuestKernelPin\) Complete\(\) bool' "$PINS" || fc=no
grep -qE 'func Lookup\(version string\) \(GuestKernelPin, error\)' "$PINS" || fc=no
ladder "$fc" "b108.4  ErrUnknownVersion/ErrPinIncomplete/ErrDigestMismatch + Complete() + Lookup() are declared"

# ---- b108.5 — ensure verifies BEFORE it renames -----------------------------
# Structural, because the ordering is the whole safety property and a test can
# only observe it through a crash it cannot schedule. The digest comparison must
# appear before the rename in the same function.
order=ok
vline="$(grep -nE 'if got := hex\.EncodeToString\(h\.Sum\(nil\)\); got != digest \{' "$ENSURE" | head -1 | cut -d: -f1 || true)"
rline="$(grep -nE 'if err := os\.Rename\(tmpName, final\); err != nil \{' "$ENSURE" | head -1 | cut -d: -f1 || true)"
[ -n "$vline" ] && [ -n "$rline" ] && [ "$vline" -lt "$rline" ] || order=no
grep -qE 'os\.CreateTemp\(dir, tempPrefix\+"\*"\)' "$ENSURE" || order=no
ladder "$order" "b108.5  the download is digest-verified (line $vline) BEFORE it is renamed into place (line $rline)"

# ---- b108.6 — the tests reach no network ------------------------------------
# The seam exists so the whole failure matrix is unit-tier. A test that opened a
# socket would make this gate depend on a publisher being up, which is precisely
# the outage ensure is designed to survive.
net="$( { grep -nE 'net/http|httptest|net\.Dial|http\.Get' "$PINS_TEST" "$ENSURE_TEST" "$WALK_TEST" "$LOCATOR_TEST" 2>/dev/null || true; } | wc -l | tr -d ' ')"
if [ "$net" = 0 ]; then
	ladder ok "b108.6  no test in pkg/guestartifacts touches the network (0 http/dial references)"
else
	grep -nE 'net/http|httptest|net\.Dial|http\.Get' "$PINS_TEST" "$ENSURE_TEST" "$WALK_TEST" "$LOCATOR_TEST" || true
	ladder no "b108.6  no test in pkg/guestartifacts touches the network (found $net references)"
fi

# ---- Go leg runner ----------------------------------------------------------
# run_test <id> <min-subtests> <TestName>
#
# `go test -run <filter>` EXITS 0 on a filter that matches NOTHING, so a renamed
# test would read PASS forever. Each leg therefore fails unless "no tests to run"
# is absent AND the named test's own PASS line is present AND (for min > 0) at
# least <min> of its subtests passed.
run_test() {
	local id="$1" min="$2" name="$3" out rc=0 ran
	out="$(cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 -v -run "^${name}\$" ./pkg/guestartifacts/ 2>&1)" || rc=$?
	printf '%s\n' "$out" >"$SCRATCH/$name.log"
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | grep -Ev '^ld: warning' | tail -30
		ladder no "$id  $name passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^--- PASS: ${name} "; then
		ladder no "$id  $name reported its own PASS line"
		return
	fi
	if [ "$min" -eq 0 ]; then
		ladder ok "$id  $name passed"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name: $ran subtests passed (min $min)"
	else
		ladder no "$id  $name: only $ran subtests passed, want >= $min"
	fi
}

# ---- b108.7 .. b108.12 — the Go legs, by exact name -------------------------
run_test "b108.7"  9 TestLookup
run_test "b108.8"  9 TestIsValidDigest
run_test "b108.9"  6 TestGuestKernelPinComplete
run_test "b108.10" 0 TestSetDigest
run_test "b108.11" 0 TestGuestKernelPinLiteralsCarryValidDigests
run_test "b108.12" 10 TestEnsureGuestArtifacts
run_test "b108.13" 0 TestEnsureGuestArtifactsIsIdempotent
run_test "b108.14" 0 TestEnsureGuestArtifactsCleansPartialDownloads
run_test "b108.15" 2 TestEnsureGuestArtifactsFetchTimeout
run_test "b108.16" 3 TestEnsureGuestArtifactsRetention
run_test "b108.17" 3 TestHTTPFetcherTimeout

# ---- b108.18 .. b108.20 — the fetcher hardening and the locator -------------
run_test "b108.18" 7 TestHTTPFetcherRejectsNonHTTPSURL
run_test "b108.19" 5 TestHTTPFetcherBodyCap
run_test "b108.20" 5 TestLocator

# ---- b108.21 — the fetcher's two refusals are WIRED into Fetch --------------
# Both hardening tests are provable without a socket, which is also their limit:
# they exercise checkArtifactURL and the cap wrapper directly, so a Fetch that
# stopped CALLING either one would keep them green. This leg asserts the wiring
# the tests cannot see — the scheme check is the first statement in Fetch (before
# any client work), the post-redirect re-check exists, and the returned body is
# the capped one.
wire=ok
fline="$(grep -nE '^func \(f \*HTTPFetcher\) Fetch\(' "$ENSURE" | head -1 | cut -d: -f1 || true)"
cline="$(grep -nE '^\tif err := checkArtifactURL\(url\); err != nil \{' "$ENSURE" | head -1 | cut -d: -f1 || true)"
dline="$(grep -nE 'client := f\.Client' "$ENSURE" | head -1 | cut -d: -f1 || true)"
[ -n "$fline" ] && [ -n "$cline" ] && [ -n "$dline" ] && [ "$fline" -lt "$cline" ] && [ "$cline" -lt "$dline" ] || wire=no
grep -qE 'checkArtifactURL\(resp\.Request\.URL\.String\(\)\)' "$ENSURE" || wire=no
grep -qE 'newCappedBody\(resp\.Body, maxArtifactBytes\)' "$ENSURE" || wire=no
grep -qE '^const MaxArtifactBytes = 512 << 20$' "$ENSURE" || wire=no
ladder "$wire" "b108.21  Fetch refuses a non-https url first (line $cline, before the client at $dline), re-checks after redirects, and caps the body"

# ---- b108.22 — the daemon wires the RE-VERIFYING locator --------------------
# The TOCTOU fix is only delivered if the daemon uses it. A constant closure
# returning the ensure's one-time result compiles, boots, and passes every unit
# test in the package — so the wiring is asserted here, structurally.
loc=ok
grep -qE '^func Locator\(pin GuestKernelPin, art sandbox\.GuestArtifacts\) func\(\) \(sandbox\.GuestArtifacts, error\)' "$LOCATOR" || loc=no
grep -qE 'sandbox\.WithGuestArtifacts\(guestartifacts\.Locator\(pin, art\)\)' "$MAIN" || loc=no
closures="$( { grep -cE 'WithGuestArtifacts\(func\(\) \(sandbox\.GuestArtifacts, error\)' "$MAIN" || true; } | tr -d ' ')"
[ "$closures" = 0 ] || loc=no
ladder "$loc" "b108.22  Locator is declared and cmd/k3sm-runtimed wires it (constant closures: $closures)"

# ---- b108.23 .. b108.25 — EVERY Mutation* subtest ran and passed ------------
# The count is derived from the SOURCE, not pinned as a literal, so adding a
# mutation subtest that never runs (a stray t.Skip, a filter typo) reddens this
# leg instead of silently shrinking the matrix. It spans BOTH mutation ladders —
# the ensure one and the locator one — so a new ladder in a new file cannot grow
# unwatched.
run_test "b108.23" 7 TestMutations
run_test "b108.24" 3 TestLocatorMutations
declared=0; observed=0
for pair in "$ENSURE_TEST:TestMutations" "$LOCATOR_TEST:TestLocatorMutations"; do
	src="${pair%%:*}"; name="${pair##*:}"
	d="$(grep -cE 't\.Run\("Mutation' "$src" || true)"
	o="$(grep -cE "^[[:space:]]*--- PASS: ${name}/Mutation" "$SCRATCH/$name.log" 2>/dev/null || true)"
	declared=$((declared+d)); observed=$((observed+o))
done
if [ "$declared" -gt 0 ] && [ "$declared" = "$observed" ]; then
	ladder ok "b108.25  every declared Mutation* subtest ran and passed ($observed/$declared)"
else
	ladder no "b108.25  every declared Mutation* subtest ran and passed (declared $declared, passed $observed)"
fi

# ============================================================================
# The AST-walk mutation ladder. The completeness walk is the only check with no
# runtime witness — it reads source — so it is mutated from the outside: a
# scratch module holding a COPY of pins.go and the walk, edited three ways.
# ============================================================================

# probe <dir-name> <sed-program|""> — builds a scratch module and prints the
# `go test` exit code. An empty sed program is the unmodified control.
probe() {
	local name="$1" prog="$2" rc=0
	local d="$SCRATCH/$name"
	mkdir -p "$d"
	cp "$WALK_TEST" "$d/"
	if [ -z "$prog" ]; then
		cp "$PINS" "$d/pins.go"
	else
		# The map body is deleted between the table's opening line and the next
		# column-0 close brace, which is why pins.go keeps the table at top level.
		awk "$prog" "$PINS" >"$d/pins.go"
	fi
	cat >"$d/go.mod" <<-EOF
		module b108probe

		go 1.25
	EOF
	(cd "$d" && env GOWORK=off GOFLAGS= GOARCH=arm64 CGO_ENABLED=1 go test ./... >"$d/out.log" 2>&1) || rc=$?
	echo "$rc"
}

EMPTY_MAP='/^var guestKernelPins = map\[string\]GuestKernelPin\{$/{print; skip=1; next} skip && /^\}$/{print; skip=0; next} skip{next} {print}'
BAD_DIGEST='{ if ($0 ~ /^\t\tImageSHA256:[[:space:]]*"/) { print "\t\tImageSHA256:     \"abc\"," } else if ($0 ~ /^\t\tInitramfsSHA256:[[:space:]]*"/) { print "\t\tInitramfsSHA256: \"1111111111111111111111111111111111111111111111111111111111111111\"," } else { print } }'

rc_control="$(probe control "")"
if [ "$rc_control" = 0 ]; then
	ladder ok "b108.26  control: the walk PASSES against an unmodified copy of pins.go (the harness is not always-red)"
else
	tail -20 "$SCRATCH/control/out.log" 2>/dev/null || true
	ladder no "b108.26  control: the walk PASSES against an unmodified copy of pins.go"
fi

rc_empty="$(probe emptymap "$EMPTY_MAP")"
if [ "$rc_empty" != 0 ] && grep -q 'the walk measured nothing' "$SCRATCH/emptymap/out.log"; then
	ladder ok "b108.27  mutant: an EMPTIED pin table turns the walk RED with its vacuity fatal"
else
	tail -20 "$SCRATCH/emptymap/out.log" 2>/dev/null || true
	ladder no "b108.27  mutant: an EMPTIED pin table turns the walk RED with its vacuity fatal (rc $rc_empty)"
fi

rc_bad="$(probe baddigest "$BAD_DIGEST")"
if [ "$rc_bad" != 0 ] && grep -q 'neither empty nor 64 lowercase hex characters' "$SCRATCH/baddigest/out.log"; then
	ladder ok "b108.28  mutant: a malformed pinned digest turns the walk RED"
else
	tail -20 "$SCRATCH/baddigest/out.log" 2>/dev/null || true
	ladder no "b108.28  mutant: a malformed pinned digest turns the walk RED (rc $rc_bad)"
fi

# ---- b108.23 — the Apache header on every file this item adds ---------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "b108.29  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "b108.29  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "B108: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B108 GREEN ================"
