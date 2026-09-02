#!/usr/bin/env bash
#
# runtimed vm-phase acceptance gate — a vm pod reaches a TERMINAL phase when its
# containers finish.
#
# The defect this gate exists for, observed live on 2026-09-02: a
# restartPolicy:Never vm pod whose single container ran to completion showed
# `kubectl` STATUS Completed — the terminated container status was folded
# correctly — against `.status.phase: Pending`, forever. Nothing ever moved it.
#
# The cause was one missing line, and the shape is worth stating because it is
# the shape of every "status is right, phase is wrong" report: the guest agent's
# ContainerEvents fold (applyGuestContainerEvent) wrote the container's
# terminated state into p.guestContainers and STOPPED. The POD phase stayed
# whatever createVMPod had stamped at assembly — Running — because the vm spine
# had no counterpart to the host spine's recomputePhaseLocked, which cannot serve
# a vm pod at all (it walks p.containers, and a vm pod's containers are guest
# processes with no host containerProc).
#
# Downstream, the k3sm provider's derivePhase then did exactly what it is
# supposed to: it will not promote a non-terminal runtime verdict to a terminal
# one, and it saw no running container to hold the pod at Running, so it fell
# through to Pending. A Job never finished, a completed pod was never collected,
# and both ends of the seam were individually correct.
#
# What the gate asserts, therefore:
#
#   THE DERIVATION IS MAINS-ONLY AND DECLARED. It walks the pod's declared main
#   containers, not the folded status map, which is what keeps the two absent
#   cases apart: a main with no status yet has not started, while an INIT
#   container's exit must never conclude the pod. Init containers run to
#   completion before any main starts, so counting them would report Succeeded
#   for a pod whose real workload had not begun.
#
#   A SIGNAL IS A FAILURE, whatever the code reads. The derivation's test is
#   (ExitCode != 0 || Signal != 0) — the SAME test the provider applies — so the
#   two ends cannot disagree about what "completed" means.
#
#   IT NEVER LOWERS TO PENDING. Pending means "the pod has not started" and the
#   provider treats it as authoritative, short-circuiting on it. Synthesizing one
#   for a pod whose containers are merely half-reported would make a running pod
#   read as unstarted for the width of a stream fold. A partially-folded pod is a
#   fold in progress, not a verdict: the phase is left alone.
#
#   RESTART POLICY IS NOT READ, deliberately. PodBox carries no pod-level
#   restartPolicy (only the container-level KEP-753 field, which the vm path
#   refuses outright), and runtimed performs no exit-driven restarts on either
#   spine. The policy lives with the provider, whose derivePhase de-escalates a
#   restartable termination back to Running before it consults this verdict.
#
#   THE TRANSITION IS PUBLISHED. WatchPodStatus is the provider's only
#   event-driven notice that a pod moved; a terminal transition nothing publishes
#   is a completed pod only a resync would ever collect.
#
# TWO TIERS, marked. Everything above the LAB banner runs here, with no VM, no
# network and no privilege — the derivation and the event fold are pure Go
# reachable by `go test -race` on darwin. The leg below the banner needs a live
# vm pod on a lab host and is PRINTED, never faked.
#
# Usage:  hack/acceptance/vm-phase.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
RUNTIME_DIR="$REPO_ROOT/pkg/runtime"
EVENTS="$RUNTIME_DIR/vmevents.go"
POD="$RUNTIME_DIR/pod.go"
STATUS="$RUNTIME_DIR/podstatus.go"
SELF="$HERE/vm-phase.sh"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed vm-phase acceptance (a vm pod's phase follows its containers to terminal)"

# ---- vp.0 — the gate parses and every source under test exists -------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$EVENTS" "$POD" "$STATUS"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "vp.0  gate parses (bash -n) + vmevents/pod/podstatus present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "vm-phase: the gate or a source under test is missing/unparseable — nothing else can run" >&2
	echo "vm-phase: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- vp.1 — gofmt, scoped to this slice's package --------------------------
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/runtime 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "vp.1  gofmt -l pkg/runtime is empty"
else
	echo "$fmt"
	ladder no "vp.1  gofmt -l pkg/runtime is empty"
fi

# ---- vp.2 — go vet ---------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/runtime/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "vp.2  go vet ./pkg/runtime/... is clean"
else
	grep -Ev '^ld: warning' "$SCRATCH/vet.log" | tail -20
	ladder no "vp.2  go vet ./pkg/runtime/... is clean"
fi

# ---- vp.3 — the fold really re-derives the phase, and really publishes -----
# The whole defect was a missing call between the two statements this rung pins,
# so it is asserted structurally as well as behaviourally: a refactor that folds
# an event without re-deriving the phase reintroduces exactly the live bug, and
# one that publishes inside p.mu deadlocks (podStatus takes it again).
wiring=ok
grep -qE '^func recomputeVMPhaseLocked\(p \*pod\) \{$' "$EVENTS" || wiring=no
apply_start="$(grep -nE '^func \(r \*Runtime\) applyGuestContainerEvent\(' "$EVENTS" | head -1 | cut -d: -f1 || true)"
rec="$(awk -v s="$apply_start" 'NR>s && /^\trecomputeVMPhaseLocked\(p\)$/ {print NR; exit}' "$EVENTS" || true)"
unlock="$(awk -v s="$apply_start" 'NR>s && /^\tp\.mu\.Unlock\(\)$/ {print NR; exit}' "$EVENTS" || true)"
pub="$(awk -v s="$apply_start" 'NR>s && /^\tr\.publish\(runtimev1\.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r\.podStatus\(p\)\)$/ {print NR; exit}' "$EVENTS" || true)"
[ -n "$apply_start" ] && [ -n "$rec" ] && [ -n "$unlock" ] && [ -n "$pub" ] || wiring=no
if [ -n "$rec" ] && [ -n "$unlock" ] && [ -n "$pub" ]; then
	[ "$rec" -lt "$unlock" ] && [ "$unlock" -lt "$pub" ] || wiring=no
fi
# ...and the started arm no longer RETURNS out of the fold. It used to, which is
# how a start event skipped everything below it; with the recompute now living
# there, an early return would leave a pod that had only ever started a container
# unable to reach any phase at all. The arm must be an if/else.
grep -qE '^\tif started != nil \{$' "$EVENTS" || wiring=no
grep -qE '^\t\} else \{$' "$EVENTS" || wiring=no
ladder "$wiring" "vp.3  applyGuestContainerEvent recomputes ($rec) under p.mu, unlocks ($unlock), THEN publishes ($pub)"

# ---- vp.4 — the derivation is mains-only, declared, and signal-aware -------
# Each of these three is a distinct way to get the pod's verdict wrong, and none
# of them is visible in the phase value alone:
#   - walking p.guestContainers instead of box.GetContainers() counts a
#     succeeded INIT container and concludes a pod whose workload never began;
#   - an ExitCode-only test calls a SIGKILLed container a success, disagreeing
#     with the provider about what "completed" means;
#   - reading p.containers is the host spine's accounting, which is empty for a
#     vm pod and therefore silently derives nothing at all.
derive=ok
body="$(awk '/^func recomputeVMPhaseLocked\(p \*pod\) \{$/,/^}$/' "$EVENTS")"
printf '%s' "$body" | grep -qE 'mains := p\.box\.GetContainers\(\)' || derive=no
printf '%s' "$body" | grep -qE 'term\.GetExitCode\(\) != 0 \|\| term\.GetSignal\(\) != 0' || derive=no
printf '%s' "$body" | grep -qE 'p\.phase = runtimev1\.PodPhase_POD_PHASE_SUCCEEDED' || derive=no
printf '%s' "$body" | grep -qE 'p\.phase = runtimev1\.PodPhase_POD_PHASE_FAILED' || derive=no
printf '%s' "$body" | grep -qE 'p\.phase = runtimev1\.PodPhase_POD_PHASE_RUNNING' || derive=no
# it never synthesizes Pending, and never reads the host spine's container list
if printf '%s' "$body" | grep -qE 'POD_PHASE_PENDING|p\.containers'; then
	printf '%s' "$body" | grep -nE 'POD_PHASE_PENDING|p\.containers'
	derive=no
fi
ladder "$derive" "vp.4  the derivation walks DECLARED mains, treats a signal as failure, and never lowers to Pending"

# ---- Go leg runner ---------------------------------------------------------
# `go test -run <filter>` EXITS 0 on a filter that matches NOTHING, so a renamed
# test would read PASS forever. Each leg fails unless "no tests to run" is absent
# AND the named test's own PASS line is present AND at least <min> subtests
# passed.
run_test() {
	local id="$1" min="$2" pkg="$3" name="$4" out rc=0 ran
	out="$(cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 -v -run "^${name}\$" "./$pkg/" 2>&1)" || rc=$?
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
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name: $ran subtests passed (min $min)"
	else
		ladder no "$id  $name: only $ran subtests passed, want >= $min"
	fi
}

# ---- vp.5 .. vp.7 — the named legs, by exact name -------------------------
# The derivation table: running / completed-zero / completed-nonzero / signalled
# / multi-container mixed / the init exclusion / the partial fold / the
# pod-level-failure guard.
run_test "vp.5" 14 pkg/runtime TestVMPodPhaseFollowsItsContainers
# The DEFECT GATE proper, driven through the real fold: a terminated container
# status must yield a TERMINAL pod phase, published. Red before this slice.
run_test "vp.6"  2 pkg/runtime TestVMPodTerminalPhaseIsFoldedAndPublished
# The regression it must not cause: a dead hypervisor still fails a vm pod with
# its own, more specific reason, and the fold does not de-escalate that.
run_test "vp.7"  0 pkg/runtime TestVMHelperExitFailsTheRunningPod

# ---- vp.8 — the package under -race ---------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 ./pkg/runtime/ >"$SCRATCH/pkg.log" 2>&1); then
	ladder ok "vp.8  go test -race ./pkg/runtime/ is green"
else
	grep -Ev '^ld: warning' "$SCRATCH/pkg.log" | tail -30
	ladder no "vp.8  go test -race ./pkg/runtime/ is green"
fi

# ---- vp.9 — the Apache header on every file this slice adds ---------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "vp.9  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "vp.9  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "vm-phase (unit tier): $PASS passed, $FAIL failed"

# ============================================================================
# LAB TIER — NOT RUN HERE. These need a booted vm pod on a lab host with a live
# control plane, which this gate has neither the privilege nor the hardware to
# produce. They are the red -> green criteria for the slice and are printed in
# full so a human session can run them verbatim and paste the result.
# ============================================================================
cat <<'LAB'

======================= LAB TIER (human-run) =======================
lab.1 is the reproduction of the reported defect, verbatim. It was RED
before this slice: the pod's STATUS column read Completed while
.status.phase stayed Pending, indefinitely.

  lab.1  A restartPolicy:Never vm pod REACHES Succeeded after its
         container exits 0, within 60s of the exit
           kubectl run vm-exit0 --image=alpine:3.20 --restart=Never \
             --overrides='{"spec":{"runtimeClassName":"vm"}}' \
             --command -- sh -c 'exit 0'
           for i in $(seq 1 60); do
             p="$(kubectl get pod vm-exit0 -o jsonpath='{.status.phase}')"
             echo "${i}s phase=$p"
             [ "$p" = Succeeded ] && break
             sleep 1
           done
         want: phase=Succeeded, and the loop breaks well inside 60s.
         Cross-check the halves agree:
           kubectl get pod vm-exit0 \
             -o jsonpath='{.status.phase}{" "}{.status.containerStatuses[0].state.terminated.exitCode}'
         want: `Succeeded 0`. Before this slice: `Pending 0` — the
         container status was already right; only the phase was not.
         Teardown: kubectl delete pod vm-exit0 --now

  lab.2  A restartPolicy:Never vm pod that exits NON-ZERO reaches Failed
           kubectl run vm-exit7 --image=alpine:3.20 --restart=Never \
             --overrides='{"spec":{"runtimeClassName":"vm"}}' \
             --command -- sh -c 'exit 7'
           kubectl get pod vm-exit7 \
             -o jsonpath='{.status.phase}{" "}{.status.containerStatuses[0].state.terminated.exitCode}'
         want: `Failed 7`.
         Teardown: kubectl delete pod vm-exit7 --now

  lab.3  A JOB backed by a vm pod actually COMPLETES
         This is what the defect cost: a Job whose pod never leaves
         Pending never records a completion and never finishes.
           kubectl create job vm-job --image=alpine:3.20 -- sh -c 'exit 0'
           kubectl patch job vm-job --type=strategic -p \
             '{"spec":{"template":{"spec":{"runtimeClassName":"vm"}}}}'
           kubectl wait --for=condition=complete job/vm-job --timeout=120s
         want: the wait returns 0 (condition met), and
           kubectl get job vm-job -o jsonpath='{.status.succeeded}'
         reports 1.
         Teardown: kubectl delete job vm-job --now

  lab.4  A LONG-RUNNING vm pod is NOT concluded (the regression check)
           kubectl run vm-sleep --image=alpine:3.20 --restart=Never \
             --overrides='{"spec":{"runtimeClassName":"vm"}}' \
             --command -- sleep 600
           kubectl wait --for=condition=Ready pod/vm-sleep --timeout=180s
           sleep 30
           kubectl get pod vm-sleep -o jsonpath='{.status.phase}'
         want: Running, still. A derivation that counted a container
         with no folded status, or an init container, would have
         concluded this pod the moment it started.
         Teardown: kubectl delete pod vm-sleep --now

  lab.5  An INIT container does not conclude the pod
           kubectl apply -f - <<'YAML'
           apiVersion: v1
           kind: Pod
           metadata: {name: vm-init}
           spec:
             runtimeClassName: vm
             restartPolicy: Never
             initContainers:
             - {name: setup, image: 'alpine:3.20', command: ['sh','-c','exit 0']}
             containers:
             - {name: app, image: 'alpine:3.20', command: ['sleep','300']}
           YAML
           kubectl wait --for=condition=Ready pod/vm-init --timeout=180s
           kubectl get pod vm-init -o jsonpath='{.status.phase}'
         want: Running. A mains-only accounting is the only thing
         standing between a succeeded init and a Succeeded pod whose
         workload had not started.
         Teardown: kubectl delete pod vm-init --now

  lab.6  A DEAD HYPERVISOR still fails the pod with its own reason
         With a vm pod running, kill its host helper:
           pkill -f 'k3sm-vmhost.*<pod-id>'
           kubectl get pod <pod> -o jsonpath='{.status.phase}{" "}{.status.reason}'
         want: `Failed VMHostExited` — NOT a phase the container fold
         de-escalated back to Running, and not the generic verdict.
====================================================================
LAB

[ "$FAIL" -eq 0 ] || exit 1
echo "================ vm-phase UNIT TIER GREEN (6 lab rungs owed) ================"
