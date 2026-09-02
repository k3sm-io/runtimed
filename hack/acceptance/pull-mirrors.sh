#!/usr/bin/env bash
#
# runtimed cluster-mirror pull acceptance gate — the runnable proof that a node
# whose OWN ingest registry misses a reference can pull the same digest-verified
# content from a peer's ingest registry over the mesh, and that it does so
# WITHOUT widening anything else.
#
# What the unit buys, and therefore what this gate must show:
#
#   THE SEAM IS CONSUMER-DEFINED AND OPTIONAL — image.MirrorSource is an
#   interface this repo consumes and never implements: k3sm supplies the peers,
#   because runtimed neither reads the apiserver nor speaks the mesh. A node with
#   no source behaves exactly as it did before the seam existed, which is what
#   keeps the standalone daemon (and every single-node cluster) unchanged.
#
#   THE FALLBACK IS NARROW, AND THE NARROWNESS IS THE SECURITY PROPERTY — it
#   fires only on a MISS or an UNREACHABLE primary, and only for a reference into
#   this node's own loopback ingest registry. An AUTH refusal must never be
#   re-asked of a peer that may not enforce the same policy (the confused-deputy
#   move), and a public reference must never be satisfied from cluster content.
#   Both are asserted as negatives, which is the only way a widening shows up.
#
#   A MIRROR IS TRANSPORT, NEVER IDENTITY OR TRUST — only the registry authority
#   of the reference is rewritten, the index records what the POD asked for, and
#   a peer serving content that fails the same digest verification is walked past
#   rather than trusted. The tamper leg drives exactly that.
#
#   THE WIRING IS REAL — the pkg/image legs fake both fetchers, so all of them
#   stay green against a runtime that threads the seam to nothing. The pkg/runtime
#   leg runs the daemon's OWN puller against two in-process registries, with a
#   no-mirrors negative control, so a mis-wiring is visible.
#
# ZERO EXTERNAL NETWORK, zero privilege, no VM: every leg is CI-tier by
# construction. The two registries in the runtime leg are httptest servers on
# loopback. The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this
# Mac's Go toolchain can itself be x86_64-under-Rosetta, and an unpinned build
# silently decides arch-sensitive behaviour.
#
# Usage:  hack/acceptance/pull-mirrors.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/pull-mirrors.sh"

MIRROR="$REPO_ROOT/pkg/image/mirror.go"
PULL="$REPO_ROOT/pkg/image/pull.go"
GATE="$REPO_ROOT/pkg/image/pullgate.go"
RUNTIME="$REPO_ROOT/pkg/runtime/runtime.go"
MIRROR_TEST="$REPO_ROOT/pkg/image/mirror_test.go"
WIRING_TEST="$REPO_ROOT/pkg/runtime/pullmirror_test.go"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed pull-mirrors acceptance (cluster-aware image pull fallback)"

# ---- pm.0 — the gate parses and every source under test exists -------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$MIRROR" "$PULL" "$GATE" "$RUNTIME" "$MIRROR_TEST" "$WIRING_TEST"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "pm.0  gate parses (bash -n) + every source under test is present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "pull-mirrors: the gate or a source under test is missing/unparseable" >&2
	echo "pull-mirrors: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- pm.1 — gofmt ----------------------------------------------------------
# Asserted on the two packages this unit touches rather than the repo, so the
# gate reddens for its own diff and not for someone else's.
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/image pkg/runtime 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "pm.1  gofmt -l pkg/image pkg/runtime is empty"
else
	echo "$fmt"
	ladder no "pm.1  gofmt -l pkg/image pkg/runtime is empty"
fi

# ---- pm.2 — go vet ---------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/image/... ./pkg/runtime/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "pm.2  go vet ./pkg/image/... ./pkg/runtime/... is clean"
else
	tail -20 "$SCRATCH/vet.log"
	ladder no "pm.2  go vet ./pkg/image/... ./pkg/runtime/... is clean"
fi

# ---- pm.3 — the seam is exactly the shape k3sm has to implement ------------
# Structural, and load-bearing: the consumer half of this unit ships in another
# repo, so the surface it codes against must not drift silently. A renamed
# method or a changed Mirror field is a compile break k3sm discovers late.
seam=ok
grep -qE '^type MirrorSource interface \{' "$MIRROR" || seam=no
grep -qE '^	Mirrors\(ref string\) \[\]Mirror$' "$MIRROR" || seam=no
grep -qE '^type Mirror struct \{' "$MIRROR" || seam=no
grep -qE '^	Host string$' "$MIRROR" || seam=no
grep -qE '^	PlainHTTP bool$' "$MIRROR" || seam=no
grep -qE '^type MirrorFetchFunc func\(ctx context\.Context, ref string, mirror Mirror, policy PlatformPolicy\) \(ggcrv1\.Image, error\)$' "$MIRROR" || seam=no
grep -qE '^func WithMirrors\(src MirrorSource, fetch MirrorFetchFunc\) PullerOption \{' "$MIRROR" || seam=no
grep -qE '^func RemoteMirrorFetch\(ctx context\.Context, ref string, mirror Mirror, policy PlatformPolicy\) \(ggcrv1\.Image, error\) \{' "$MIRROR" || seam=no
grep -qE '^	ImageMirrors image\.MirrorSource$' "$RUNTIME" || seam=no
ladder "$seam" "pm.3  the MirrorSource/Mirror/MirrorFetchFunc surface + Deps.ImageMirrors are exactly as k3sm must code against"

# ---- pm.4 — no credential can reach a peer ---------------------------------
# The imagePullSecret on this path was resolved for a LOOPBACK reference — this
# node's own registry. Replaying it to a peer would send a secret scoped to one
# host to a different one. The seam is shaped so it cannot: MirrorFetchFunc takes
# no RegistryCredential, and the production mirror fetcher passes nil through.
cred=ok
grep -qE 'MirrorFetchFunc func\(ctx context\.Context, ref string, mirror Mirror, policy PlatformPolicy\)' "$MIRROR" || cred=no
grep -q 'RegistryCredential' <(grep -A2 '^type MirrorFetchFunc' "$MIRROR") && cred=no
grep -qE 'return remoteFetch\(ctx, r, ref, nil, policy\)' "$MIRROR" || cred=no
ladder "$cred" "pm.4  MirrorFetchFunc carries NO credential and RemoteMirrorFetch fetches anonymously"

# ---- pm.5 — the mirror path reuses the ONE registry round trip -------------
# A second fetcher would be a second place go-containerregistry's implicit
# linux/amd64 default could re-enter, and a second platform story to keep
# correct. RemoteMirrorFetch must be RemoteFetch plus name.Insecure, nothing else.
one=ok
grep -qE '^func remoteFetch\(ctx context\.Context, r name\.Reference, ref string, cred \*RegistryCredential, policy PlatformPolicy\)' "$PULL" || one=no
grep -qE 'return remoteFetch\(ctx, r, ref, cred, policy\)' "$PULL" || one=no
[ "$(grep -c 'remote\.Get(' "$PULL")" = 2 ] || one=no
[ "$(grep -c 'remote\.Get(' "$MIRROR")" = 0 ] || one=no
grep -qE 'opts = append\(opts, name\.Insecure\)' "$MIRROR" || one=no
ladder "$one" "pm.5  RemoteMirrorFetch shares the one remoteFetch round trip (no second fetcher, no second platform story)"

# ---- pm.6 — the index records the pod's reference, structurally -------------
# Puller.ingest takes the reference it records as a PARAMETER and the mirror loop
# passes the ORIGINAL one. If the loop ever passed the rewritten reference, the
# peer would become the image's identity and a later IfNotPresent serve would
# miss.
idy=ok
grep -qE '^func \(p \*Puller\) ingest\(ctx context\.Context, ref string, img ggcrv1\.Image, want \[\]Platform\)' "$PULL" || idy=no
grep -qE 'res, err := p\.ingest\(ctx, ref, img, want\)' "$MIRROR" || idy=no
grep -qE 'mirrorRef, err := rewriteRegistryHost\(ref, m\.Host\)' "$MIRROR" || idy=no
ladder "$idy" "pm.6  the mirror loop ingests under the ORIGINAL reference (the rewritten one is only fetched with)"

# ---- Go leg runner ----------------------------------------------------------
# `go test -run <filter>` EXITS 0 on a filter that matches NOTHING, so a renamed
# test would read PASS forever. Each leg therefore fails unless "no tests to
# run" is absent AND the named test's own PASS line is present AND (for min > 0)
# at least <min> of its subtests passed.
run_test() {
	local id="$1" min="$2" pkg="$3" name="$4" out rc=0 ran
	out="$(cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
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

# ---- pm.7 .. pm.13 — the Go legs, by exact name ----------------------------
run_test "pm.7"  9 ./pkg/image/   TestPullFallsBackToClusterMirrors
run_test "pm.8"  2 ./pkg/image/   TestPullWithoutMirrorsIsUnchanged
run_test "pm.9"  3 ./pkg/image/   TestNewPullerRefusesAHalfWiredFallback
run_test "pm.10" 25 ./pkg/image/  TestMirrorFallbackEligibility
run_test "pm.11" 12 ./pkg/image/  TestClusterLocalRefGate
run_test "pm.12" 3 ./pkg/image/   TestRewriteRegistryHost
run_test "pm.13" 5 ./pkg/image/   TestMirrorReferenceSelectsItsScheme
# The daemon's OWN wiring, against two loopback registries, with the no-mirrors
# negative control that gives the positive case its meaning.
run_test "pm.14" 2 ./pkg/runtime/ TestDefaultPullerConsultsClusterMirrors

# ---- pm.15 — mutant: a widened eligibility rule must go RED ----------------
# The auth negatives are the load-bearing assertions of this unit, and an
# assertion that cannot be made to fail is not an assertion. Widen the rule to
# "any failure is eligible" and the suite must reject it.
mutant="$SCRATCH/mirror.go.orig"
cp "$MIRROR" "$mutant"
restore_mirror() { cp "$mutant" "$MIRROR"; }
trap 'restore_mirror; cleanup' EXIT
python3 - "$MIRROR" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "func mirrorFallbackEligible(err error) bool {\n\tif err == nil {\n\t\treturn false\n\t}"
new = old + "\n\treturn true // MUTANT"
if s.count(old) != 1:
    sys.exit("mutation anchor not found exactly once")
open(p, "w").write(s.replace(old, new))
PY
mrc=0
(cd "$REPO_ROOT" && "${GOENV[@]}" go test -count=1 -run '^TestPullFallsBackToClusterMirrors$' ./pkg/image/ >"$SCRATCH/mutant-elig.log" 2>&1) || mrc=$?
restore_mirror
if [ "$mrc" != 0 ]; then
	ladder ok "pm.15  mutant: an eligibility rule that admits ANY failure turns the auth negatives RED"
else
	tail -20 "$SCRATCH/mutant-elig.log"
	ladder no "pm.15  mutant: an eligibility rule that admits ANY failure turns the auth negatives RED (rc $mrc)"
fi

# ---- pm.16 — mutant: recording the MIRROR reference must go RED ------------
# The identity claim, attacked from the outside: make the loop ingest under the
# rewritten reference and the index/manifest assertions must reject it.
python3 - "$MIRROR" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "res, err := p.ingest(ctx, ref, img, want)"
new = "res, err := p.ingest(ctx, mirrorRef, img, want)"
if s.count(old) != 1:
    sys.exit("mutation anchor not found exactly once")
open(p, "w").write(s.replace(old, new))
PY
mrc=0
(cd "$REPO_ROOT" && "${GOENV[@]}" go test -count=1 -run '^TestPullFallsBackToClusterMirrors$' ./pkg/image/ >"$SCRATCH/mutant-ident.log" 2>&1) || mrc=$?
restore_mirror
if [ "$mrc" != 0 ]; then
	ladder ok "pm.16  mutant: recording the MIRROR reference turns the identity assertions RED"
else
	tail -20 "$SCRATCH/mutant-ident.log"
	ladder no "pm.16  mutant: recording the MIRROR reference turns the identity assertions RED (rc $mrc)"
fi

# ---- pm.17 — the Apache header on every file this unit adds ----------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "pm.17  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "pm.17  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "OWED (live rungs this CI-tier gate does NOT run):"
echo "  - the TWO-NODE leg: node A pulls a reference its own ingest registry"
echo "    has never seen, from node B's ingest registry over the live wireguard"
echo "    mesh (a real 100.64.0.0/10 peer). This gate's registries are loopback"
echo "    httptest servers, so it proves the RULE and the WIRING, never the mesh"
echo "    dial — and 100.64/10 is precisely the range go-containerregistry does"
echo "    NOT infer http for, so only a live leg proves the name.Insecure"
echo "    construction reaches a real socket."
echo "  - the k3sm half: the ConfigMap peer advertisement, the mesh relay, and"
echo "    Deps.ImageMirrors actually being populated on a running node. It lives"
echo "    in the k3sm repo; runtimed only defines the seam it plugs into."
echo "  - a peer FAILOVER leg: kill node B mid-cluster and prove node C serves"
echo "    the same reference, which needs three nodes and a live mesh."
echo "----------------------------------------"
echo "pull-mirrors: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "========= pull-mirrors GREEN ========="
