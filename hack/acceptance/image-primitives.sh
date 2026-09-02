#!/usr/bin/env bash
#
# runtimed image-primitives acceptance gate — the runnable proof that the five
# node image verbs (PullImage, TagImage, UntagImage, InspectImage, SaveImage)
# are implemented, SERVED, and provenance-correct.
#
# What the unit buys, and therefore what this gate must show:
#
#   SERVED — the verbs are on the SAME grpc.Server, and therefore the same unix
#   socket, as the Runtime service. images.proto records that obligation and
#   cannot enforce it: a proto file cannot observe what listener anything is
#   registered on. A daemon that quietly served the image verbs on a second,
#   world-dialable socket would satisfy every apis-scope test.
#
#   PULL THROUGH THE ONE PULLER — PullImage drives the daemon's OWN puller, so
#   it inherits that path's blob verification, disk-pressure gate and index
#   write rather than forking a second fetch path with its own (unread)
#   verification story.
#
#   PROVENANCE (the M12 images plan, Resolution 13) — edges are monotone, roots
#   are digest-pinned, and root removal is AUTHORIZED and LOCAL. A pull and a
#   tag each record an OPERATOR root; UntagImage is the only verb that removes
#   one. The gate asserts the consequence an operator sees: a tagged image
#   survives a prune and becomes collectable again after the untag.
#
#   DIGEST-STABLE EXPORT — SaveImage writes the manifest bytes the index
#   RETAINED, verbatim. The store commits config and layer blobs and never the
#   manifest, so an exporter that re-encoded the recorded descriptors would emit
#   a valid archive under a DIFFERENT image id — a silent rename nothing
#   downstream could detect. The load -> save -> load rows assert the digest,
#   not merely that the archive re-loads.
#
#   REMOVEIMAGE STILL REFUSES — the refusal is a design statement, not a gap
#   this unit filled. UntagImage is the removal that can be granted because it
#   names one operator-owned entry; RemoveImage names no root in particular and
#   still answers UNIMPLEMENTED.
#
# ZERO NETWORK, zero privilege, no VM: every leg is unit-tier by construction.
# The puller is faked at the runtime's own seam and every archive is built in
# memory. The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this
# Mac's Go toolchain can itself be x86_64-under-Rosetta, and an unpinned build
# silently decides arch-sensitive behaviour.
#
# Usage:  hack/acceptance/image-primitives.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/image-primitives.sh"

SERVICE="$REPO_ROOT/pkg/runtime/images.go"
INDEX="$REPO_ROOT/pkg/image/index.go"
EXPORT="$REPO_ROOT/pkg/image/export.go"
OPROOTS="$REPO_ROOT/pkg/image/operatorroots.go"
ROOTS="$REPO_ROOT/pkg/image/roots.go"
VERBS_TEST="$REPO_ROOT/pkg/runtime/imageverbs_test.go"
EXPORT_TEST="$REPO_ROOT/pkg/image/export_test.go"
OPROOTS_TEST="$REPO_ROOT/pkg/image/operatorroots_test.go"
ENTRY_TEST="$REPO_ROOT/pkg/image/indexentry_test.go"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed image-primitives acceptance (pull/tag/untag/inspect/save)"

# ---- ip.0 — the gate parses and every source under test exists --------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$SERVICE" "$INDEX" "$EXPORT" "$OPROOTS" "$ROOTS" \
	"$VERBS_TEST" "$EXPORT_TEST" "$OPROOTS_TEST" "$ENTRY_TEST"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "ip.0  gate parses (bash -n) + every source under test is present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "image-primitives: the gate or a source under test is missing/unparseable" >&2
	echo "image-primitives: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- ip.1 — gofmt ----------------------------------------------------------
# Asserted on the two packages this unit touches rather than the repo, so the
# gate reddens for its own diff and not for someone else's.
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/image pkg/runtime 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "ip.1  gofmt -l pkg/image pkg/runtime is empty"
else
	echo "$fmt"
	ladder no "ip.1  gofmt -l pkg/image pkg/runtime is empty"
fi

# ---- ip.2 — go vet ---------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/image/... ./pkg/runtime/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "ip.2  go vet ./pkg/image/... ./pkg/runtime/... is clean"
else
	tail -20 "$SCRATCH/vet.log"
	ladder no "ip.2  go vet ./pkg/image/... ./pkg/runtime/... is clean"
fi

# ---- ip.3 — the five verbs are methods on the ONE images service -----------
# Structural, and deliberately so: the generated server interface is satisfied
# for free by the embedded UnimplementedImagesServer, so "it compiles" proves
# nothing about whether a verb is implemented. The served-surface half is
# asserted at runtime by ip.6.
five=ok
for verb in PullImage TagImage UntagImage InspectImage SaveImage; do
	if [ "$(grep -cE "^func \(s \*imagesService\) $verb\(" "$SERVICE")" != 1 ]; then
		echo "imagesService.$verb is not implemented exactly once in $SERVICE" >&2
		five=no
	fi
done
ladder "$five" "ip.3  PullImage/TagImage/UntagImage/InspectImage/SaveImage are each implemented once on imagesService"

# ---- ip.4 — RemoveImage's refusal is UNTOUCHED ------------------------------
# The one verb this unit deliberately did NOT implement. A future edit that
# "completes the set" by making RemoveImage remove a root would be removing a
# per-pod record on an operator's say-so, which is the liveness violation the
# image GC exists to prevent.
rm_ok=ok
grep -qE '^func \(s \*imagesService\) RemoveImage\(context\.Context, \*runtimev1\.RemoveImageRequest\)' "$SERVICE" || rm_ok=no
grep -qE 'status\.Error\(codes\.Unimplemented,' "$SERVICE" || rm_ok=no
ladder "$rm_ok" "ip.4  RemoveImage still answers UNIMPLEMENTED (the refusal is a design statement, not a gap)"

# ---- ip.5 — the operator root reaches the GC's own enumerator --------------
# The provenance model only protects anything if Cache.Roots consults it. A
# correct operator record that the prune planner never reads would pass every
# record-level test and pin nothing.
gc=ok
grep -qE 'func \(c \*Cache\) OperatorImageRoots\(\)' "$OPROOTS" || gc=no
grep -qE 'func \(c \*Cache\) RecordOperatorImage\(' "$OPROOTS" || gc=no
grep -qE 'func \(c \*Cache\) RemoveOperatorImage\(' "$OPROOTS" || gc=no
grep -qE 'operator, err := c\.OperatorImageRoots\(\)' "$ROOTS" || gc=no
grep -qE 'return append\(out, operatorRootSet\(operator\)\.\.\.\), nil' "$ROOTS" || gc=no
ladder "$gc" "ip.5  Cache.Roots unions the operator record (the GC's own enumerator reads it)"

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

# ---- ip.6 .. ip.14 — the Go legs, by exact name -----------------------------
# ip.6 is the SERVED-surface leg: it asserts both services on one grpc.Server
# and every Images method — the five new ones included — present by name in the
# registration.
run_test "ip.6"  0 ./pkg/runtime/ TestImagesServedOnTheRuntimeListener
run_test "ip.7"  5 ./pkg/runtime/ TestPullImageDrivesTheDaemonsOwnPuller
run_test "ip.8"  5 ./pkg/runtime/ TestTagImageIsAdditiveOnly
run_test "ip.9"  5 ./pkg/runtime/ TestUntagImageRemovesOneName
run_test "ip.10" 5 ./pkg/runtime/ TestInspectImageIsLocalOnly
run_test "ip.11" 4 ./pkg/runtime/ TestSaveImageRoundTripsOverTheWire
run_test "ip.12" 0 ./pkg/image/   TestExportOCILayoutRoundTrips
run_test "ip.13" 3 ./pkg/image/   TestExportOCILayoutRefuses
run_test "ip.14" 3 ./pkg/image/   TestOperatorImageRootsAreKeyedByThePair
run_test "ip.15" 0 ./pkg/image/   TestOperatorRootsJoinTheReachabilitySet
run_test "ip.16" 3 ./pkg/image/   TestOperatorRootsFailClosed
run_test "ip.17" 5 ./pkg/image/   TestIndexRetainsTheManifest
run_test "ip.18" 5 ./pkg/image/   TestIndexResolveTargets
run_test "ip.19" 0 ./pkg/image/   TestIndexRemoveTakesOneEntry
run_test "ip.20" 4 ./pkg/image/   TestIndexEntryTotalSize
# The buildkit "./" root entry, which the same branch fixed: a standard
# debian-derived layer must materialize, and the carve-out must admit nothing
# adjacent to it.
run_test "ip.21" 5 ./pkg/image/   TestApplyLayerAcceptsTheRootEntry

# ---- ip.22 — the mutation discipline, applied from the outside -------------
# A round-trip assertion that cannot be made to fail is not an assertion. The
# gate re-exports with ONE byte appended to the retained manifest — the cheapest
# stand-in for "the exporter re-encoded the manifest instead of writing the
# recorded bytes" — and requires the round-trip leg to go RED.
mutant="$SCRATCH/export.go.orig"
cp "$EXPORT" "$mutant"
python3 - "$EXPORT" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "if err := writeTarFile(tw, manifestName, e.ManifestRaw); err != nil {"
new = "if err := writeTarFile(tw, manifestName, append(append([]byte{}, e.ManifestRaw...), ' ')); err != nil {"
if s.count(old) != 1:
    sys.exit("mutation anchor not found exactly once")
open(p, "w").write(s.replace(old, new))
PY
mrc=0
(cd "$REPO_ROOT" && "${GOENV[@]}" go test -count=1 -run '^TestExportOCILayoutRoundTrips$' ./pkg/image/ >"$SCRATCH/mutant.log" 2>&1) || mrc=$?
cp "$mutant" "$EXPORT"
if [ "$mrc" != 0 ]; then
	ladder ok "ip.22  mutant: a re-encoded manifest turns the load->save->load round trip RED"
else
	tail -20 "$SCRATCH/mutant.log"
	ladder no "ip.22  mutant: a re-encoded manifest turns the load->save->load round trip RED (rc $mrc)"
fi

# ---- ip.23 — the Apache header on every file this unit adds ----------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "ip.23  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "ip.23  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "OWED (live rungs this CI-tier gate does NOT run):"
echo "  - a real registry pull: PullImage against a live registry, proving the"
echo "    fetch/verify/index path end to end. Faked at the runtime's puller seam"
echo "    here, so this gate proves the WIRING and the provenance, not the fetch."
echo "  - the k3sm CLI legs: \`k3sm image pull|tag|untag|inspect|save\` over the"
echo "    daemon's unix socket, which live in the k3sm repo and prove these RPCs"
echo "    from the operator's side."
echo "  - a save/load interop check against \`docker load\` and \`skopeo copy\` on"
echo "    an exported archive — the claim that the OCI layout this daemon emits"
echo "    is not merely self-consistent."
echo "----------------------------------------"
echo "image-primitives: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "========= image-primitives GREEN ========="
