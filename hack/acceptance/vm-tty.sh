#!/usr/bin/env bash
#
# runtimed vm-tty acceptance gate — the guest can allocate a pseudo-terminal for
# a `kubectl exec`, and a vm container has a real /dev.
#
# What this slice buys, and therefore what the gate must show:
#
#   TTY — `kubectl exec -it` into a vm pod used to be REFUSED outright ("this
#   guest cannot allocate a pseudo-terminal for an exec yet"). It now allocates a
#   pty pair before the fork, hands the slave to the child as all three of its
#   descriptors with Setsid+Setctty, pumps the master onto the client's stdout,
#   and applies every terminal resize the client sends.
#
#   THE PTY'S ORIGIN — the pair comes from the TARGET CONTAINER's own devpts
#   instance, not the guest's. A slave's index only means something within the
#   instance it was allocated in, so a guest-allocated pty inside a container
#   with a private /dev/pts either has no name at all or has the name of a
#   DIFFERENT terminal. This is the subtle half of the slice and the reason
#   `tty(1)` is a lab rung below rather than an afterthought.
#
#   /dev — a vm container's chroot had an EMPTY /dev: `echo x > /dev/null`
#   created a REGULAR FILE and grew it forever, /dev/urandom was missing under
#   every runtime that seeds from it, and no terminal could exist. Each container
#   now gets the OCI runtime-spec default device set bound in, its own devpts, a
#   /dev/ptmx symlink into it, and a bounded /dev/shm that YIELDS to a
#   pod-declared mount at the same path.
#
#   THE ALLOWLIST IS A SECURITY BOUNDARY. /dev/vsock must never appear in a
#   container. The pod's guest agent is served over AF_VSOCK and the guest kernel
#   carries vsock loopback, so a container holding that node could dial its own
#   pod's agent — which starts processes in any container of the pod, reads every
#   container's logs, and stops the pod. The gate asserts its ABSENCE, in the
#   plan and on a live guest.
#
# TWO TIERS, marked. Everything above the LAB banner runs here, with no VM, no
# network and no privilege: the decisions all live in pure functions in
# pkg/guestinit precisely so they are reachable by `go test` on darwin. The legs
# below the banner need a live vm pod on a lab host and are PRINTED, never
# faked — a gate that pretends to have run a VM is worse than one that says it
# did not.
#
# Usage:  hack/acceptance/vm-tty.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PKG_DIR="$REPO_ROOT/pkg/guestinit"
TTYEXEC="$PKG_DIR/ttyexec.go"
PTY_LINUX="$PKG_DIR/pty_linux.go"
PTY_STUB="$PKG_DIR/pty_stub.go"
DEVICES="$PKG_DIR/devices.go"
PLAN="$PKG_DIR/plan.go"
AGENT="$REPO_ROOT/cmd/k3sm-guest-init/agent_linux.go"
MAIN="$REPO_ROOT/cmd/k3sm-guest-init/main_linux.go"
SELF="$HERE/vm-tty.sh"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed vm-tty acceptance (guest exec pty + per-container /dev)"

# ---- vt.0 — the gate parses and every source under test exists --------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$TTYEXEC" "$PTY_LINUX" "$PTY_STUB" "$DEVICES" "$PLAN" "$AGENT" "$MAIN"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "vt.0  gate parses (bash -n) + ttyexec/pty_linux/pty_stub/devices.go and their consumers present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "vm-tty: the gate or a source under test is missing/unparseable — nothing else can run" >&2
	echo "vm-tty: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- vt.1 — gofmt, scoped to this slice's packages --------------------------
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/guestinit cmd/k3sm-guest-init 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "vt.1  gofmt -l pkg/guestinit cmd/k3sm-guest-init is empty"
else
	echo "$fmt"
	ladder no "vt.1  gofmt -l pkg/guestinit cmd/k3sm-guest-init is empty"
fi

# ---- vt.2 — go vet ----------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/guestinit/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "vt.2  go vet ./pkg/guestinit/... is clean"
else
	tail -20 "$SCRATCH/vet.log"
	ladder no "vt.2  go vet ./pkg/guestinit/... is clean"
fi

# ---- vt.3 — the refusal is GONE from the tree -------------------------------
# The red state of this whole slice was one error return. It is asserted absent
# from the SOURCE rather than from behaviour, because the behaviour that replaced
# it is only observable on a booted guest (the LAB rungs below).
refusals="$( { grep -rn --include='*.go' 'cannot allocate a pseudo-terminal' "$REPO_ROOT" 2>/dev/null || true; } | wc -l | tr -d ' ')"
if [ "$refusals" = 0 ]; then
	ladder ok "vt.3  the 'cannot allocate a pseudo-terminal' refusal no longer exists in the tree"
else
	grep -rn --include='*.go' 'cannot allocate a pseudo-terminal' "$REPO_ROOT" || true
	ladder no "vt.3  the 'cannot allocate a pseudo-terminal' refusal no longer exists ($refusals sites)"
fi

# ---- vt.4 — the guest init cross-builds for the guest it ships in -----------
# The guest is linux/arm64 and CGO-free (it is the whole userspace of a pinned
# initramfs). This is the only compiler check the executor half ever gets, which
# is exactly why the decisions live in the darwin-tested package instead.
if (cd "$REPO_ROOT" && env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$SCRATCH/k3sm-guest-init" ./cmd/k3sm-guest-init >"$SCRATCH/cross.log" 2>&1); then
	ladder ok "vt.4  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
else
	tail -20 "$SCRATCH/cross.log"
	ladder no "vt.4  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
fi

# ---- vt.5 — the darwin stub keeps the pure half testable --------------------
# pty_linux.go is the one syscall-performing file in guestinit. If its !linux
# twin ever stops failing closed — or stops existing — the package silently
# becomes linux-only and every pure test above it becomes unreachable on the
# machine that actually runs CI.
stub=ok
head -1 "$PTY_STUB" | grep -q '^//go:build !linux$' || stub=no
head -1 "$PTY_LINUX" | grep -q '^//go:build linux$' || stub=no
grep -qE '^var ErrNoPTY = errors\.New\(' "$PTY_STUB" || stub=no
for fn in OpenPTY SetWinsize ChownTTY; do
	grep -qE "^func ${fn}\(" "$PTY_STUB" || stub=no
	grep -qE "^func ${fn}\(" "$PTY_LINUX" || stub=no
done
tagged="$( { grep -rlE '^//go:build linux$' "$PKG_DIR"/*.go 2>/dev/null || true; } | { grep -v '_test\.go$' || true; } | wc -l | tr -d ' ')"
[ "$tagged" = 1 ] || stub=no
ladder "$stub" "vt.5  pty_linux.go is the ONLY linux-tagged file in pkg/guestinit ($tagged) and pty_stub.go fails closed"

# ---- vt.6 — both pty descriptors are opened O_CLOEXEC -----------------------
# PID 1 forks every container in the pod. A master without FD_CLOEXEC is
# inherited by all of them, so (a) the kernel never returns EIO when the exec'd
# process exits — the exec hangs forever instead of ending — and (b) an unrelated
# container holds a live handle on another session's terminal.
cloexec="$( { grep -cE 'os\.OpenFile\([a-zA-Z]+, os\.O_RDWR\|unix\.O_NOCTTY\|unix\.O_CLOEXEC, 0\)' "$PTY_LINUX" || true; } | tr -d ' ')"
opens="$( { grep -cE 'os\.OpenFile\(' "$PTY_LINUX" || true; } | tr -d ' ')"
if [ "$opens" = 2 ] && [ "$cloexec" = 2 ]; then
	ladder ok "vt.6  both pty opens carry O_NOCTTY|O_CLOEXEC ($cloexec/$opens)"
else
	grep -nE 'os\.OpenFile\(' "$PTY_LINUX" || true
	ladder no "vt.6  both pty opens carry O_NOCTTY|O_CLOEXEC ($cloexec of $opens opens)"
fi

# ---- vt.7 — the executor is DRIVEN by the pure plan, not by its own copy ----
# The plan is only worth testing if the linux-only side actually performs it. A
# hard-coded Setctty/Ctty or an open-coded pump in the agent would keep every
# test above green while shipping different behaviour.
wire=ok
grep -qE 'guestinit\.PlanExecIO\(spec\.TTY,' "$AGENT" || wire=no
grep -qE 'Setctty:[[:space:]]+wiring\.Setctty' "$AGENT" || wire=no
grep -qE 'Ctty:[[:space:]]+wiring\.Ctty' "$AGENT" || wire=no
grep -qE 'Setsid:[[:space:]]+wiring\.Setsid' "$AGENT" || wire=no
grep -qE 'fds\.close\(wiring\.CloseAfterFork\.\.\.\)' "$AGENT" || wire=no
grep -qE 'fds\.close\(wiring\.CloseAfterWait\.\.\.\)' "$AGENT" || wire=no
grep -qE 'guestinit\.ExecPTYOrigin\(plan\)' "$AGENT" || wire=no
grep -qE 'guestinit\.TTYReader\(src\)' "$AGENT" || wire=no
grep -qE 'guestinit\.PumpResize\(' "$AGENT" || wire=no
hardcoded="$( { grep -cE 'Setctty:[[:space:]]*true' "$AGENT" || true; } | tr -d ' ')"
[ "$hardcoded" = 0 ] || wire=no
ladder "$wire" "vt.7  the agent drives PlanExecIO/ExecPTYOrigin/TTYReader/PumpResize (hard-coded Setctty: $hardcoded)"

# ---- vt.8 — the master is closed only AFTER the reaper wait and the drain ---
# Ordering is the whole teardown property and no test can schedule the crash that
# would expose it, so it is asserted structurally: the wait, then the drain, then
# the close, in that order in the same function.
order=ok
wline="$(grep -nE 'st, werr := e\.reaper\.Wait\(ctx, name\)' "$AGENT" | head -1 | cut -d: -f1 || true)"
dline="$(grep -nE '^\tpumps\.Wait\(\)$' "$AGENT" | head -1 | cut -d: -f1 || true)"
cline="$(grep -nE '^\tfds\.close\(wiring\.CloseAfterWait\.\.\.\)$' "$AGENT" | head -1 | cut -d: -f1 || true)"
fline="$(grep -nE '^\tfds\.close\(wiring\.CloseAfterFork\.\.\.\)$' "$AGENT" | head -1 | cut -d: -f1 || true)"
[ -n "$wline" ] && [ -n "$dline" ] && [ -n "$cline" ] && [ -n "$fline" ] || order=no
[ "$fline" -lt "$wline" ] && [ "$wline" -lt "$dline" ] && [ "$dline" -lt "$cline" ] || order=no
ladder "$order" "vt.8  teardown order: close-after-fork ($fline) < reaper wait ($wline) < pump drain ($dline) < close-after-wait ($cline)"

# ---- vt.9 — the symlink resolves its PARENT only ----------------------------
# mount(2) follows a symlink at its target and symlink(2) does not. Resolving the
# final component would make an image that already ships /dev/ptmx -> pts/ptmx
# cause the guest to replace the devpts multiplexer itself.
link=ok
grep -qE 'guestinit\.ResolveTarget\(l\.ResolveRoot, path\.Dir\(' "$MAIN" || link=no
grep -qE 'func applyLinks\(' "$MAIN" || link=no
grep -qE 'if err := applyLinks\(log, cp\.Links\); err != nil \{' "$MAIN" || link=no
aline="$(grep -nE 'if err := applyMounts\(log, cp\.Mounts\); err != nil \{' "$MAIN" | head -1 | cut -d: -f1 || true)"
lline="$(grep -nE 'if err := applyLinks\(log, cp\.Links\); err != nil \{' "$MAIN" | head -1 | cut -d: -f1 || true)"
[ -n "$aline" ] && [ -n "$lline" ] && [ "$aline" -lt "$lline" ] || link=no
ladder "$link" "vt.9  applyLinks resolves the parent only and runs AFTER the mounts ($aline < $lline)"

# ---- vt.10 — /dev/vsock is nowhere in the shipped device surface ------------
# The allowlist is additive by construction, so this is a second, blunter check
# of the same property from the outside: no shipped file may name a vsock device
# node as something a container gets.
vsock="$( { grep -rn --include='*.go' '/dev/vsock\|/dev/vhost-vsock' "$PKG_DIR" "$REPO_ROOT/cmd/k3sm-guest-init" 2>/dev/null || true; } | { grep -v '_test\.go:' || true; } | { grep -v '^.*//' || true; } | wc -l | tr -d ' ')"
allow="$(grep -E '^var DefaultDevices = ' "$DEVICES" || true)"
dev=ok
[ "$vsock" = 0 ] || dev=no
echo "$allow" | grep -q '"null", "zero", "full", "random", "urandom", "tty"' || dev=no
if echo "$allow" | grep -qiE 'vsock|kmem|kmsg|console|loop|mapper'; then dev=no; fi
ladder "$dev" "vt.10  DefaultDevices is exactly the OCI default set and no shipped file exposes /dev/vsock ($vsock)"

# ---- Go leg runner ----------------------------------------------------------
# `go test -run <filter>` EXITS 0 on a filter that matches NOTHING, so a renamed
# test would read PASS forever. Each leg fails unless "no tests to run" is absent
# AND the named test's own PASS line is present AND at least <min> subtests
# passed.
run_test() {
	local id="$1" min="$2" name="$3" out rc=0 ran
	out="$(cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 -v -run "^${name}\$" ./pkg/guestinit/ 2>&1)" || rc=$?
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

# ---- vt.11 .. vt.17 — the pure legs, by exact name --------------------------
run_test "vt.11" 9 TestPlanExecIOWiring
run_test "vt.12" 3 TestExecPTYOriginPrefersTheContainerInstance
run_test "vt.13" 3 TestPumpResizeAppliesEverySizeInOrder
run_test "vt.14" 3 TestTTYReaderTreatsEIOAsEndOfStream
run_test "vt.15" 5 TestContainerDevIsTheOCIDefaultSet
run_test "vt.16" 4 TestContainerDevYieldsToPodMounts
run_test "vt.17" 7 TestPlanWiresTheContainerDev

# ---- vt.18 — the whole package, under -race --------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 ./pkg/guestinit/ >"$SCRATCH/pkg.log" 2>&1); then
	ladder ok "vt.18  go test -race ./pkg/guestinit/ is green"
else
	grep -Ev '^ld: warning' "$SCRATCH/pkg.log" | tail -30
	ladder no "vt.18  go test -race ./pkg/guestinit/ is green"
fi

# ---- vt.19 — the Apache header on every file this slice adds ---------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "vt.19  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "vt.19  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "vm-tty (unit tier): $PASS passed, $FAIL failed"

# ============================================================================
# LAB TIER — NOT RUN HERE. These need a booted vm pod on a lab host with a live
# control plane, which this gate has neither the privilege nor the hardware to
# produce. They are the red -> green criteria for the slice and are printed in
# full so a human session can run them verbatim and paste the result.
#
# Setup (one vm-RuntimeClass pod, any small linux image):
#
#   kubectl run tty-probe --image=alpine:3.20 --restart=Never \
#     --overrides='{"spec":{"runtimeClassName":"vm"}}' -- sleep 3600
#   kubectl wait --for=condition=Ready pod/tty-probe --timeout=180s
#
# Teardown:  kubectl delete pod tty-probe --now
# ============================================================================
cat <<'LAB'

======================= LAB TIER (human-run) =======================
Run each rung against a Ready vm pod. Every one of these was RED before
this slice: the first four could not even be attempted, because a tty
exec was refused outright, and the /dev rungs failed because a vm
container's /dev was empty.

  lab.1  a tty is actually allocated
         kubectl exec -it tty-probe -- sh -c 'test -t 0 && test -t 1 && echo TTY-OK'
         want: TTY-OK, rc 0

  lab.2  the terminal has a size before the client's first resize
         kubectl exec -it tty-probe -- stty size
         want: two NON-ZERO numbers (rows cols). "0 0" means the pty was
         never sized and every curses program will lay itself out wrong.

  lab.3  a resize reaches the workload
         kubectl exec -it tty-probe -- sh -c 'stty size; sleep 5; stty size'
         want: the second line tracks the terminal window if it is resized
         during the sleep (SIGWINCH is delivered through the master).

  lab.4  THE DEVPTS-ORIGIN INVARIANT — the pty's name means something
         INSIDE the container
         kubectl exec -it tty-probe -- sh -c 'tty; test -c "$(tty)" && echo TTY-NAME-OK'
         want: /dev/pts/<n> and TTY-NAME-OK. A pty allocated from the
         GUEST's devpts instead of the container's fails here: the index
         either does not exist in the container's private instance, or
         names a DIFFERENT terminal.

  lab.5  the controlling terminal is reopenable by name
         kubectl exec -it tty-probe -- sh -c 'echo hi > /dev/tty && echo CTTY-OK'
         want: hi, then CTTY-OK.

  lab.6  the OCI default device set is present and is made of DEVICES
         kubectl exec tty-probe -- sh -c 'for d in null zero full random urandom tty; do test -c /dev/$d || { echo "MISSING /dev/$d"; exit 1; }; done; echo DEV-OK'
         want: DEV-OK. Before this slice /dev was empty and
         `echo x > /dev/null` created a REGULAR FILE that grew forever.

  lab.7  /dev/null is a sink, not a file
         kubectl exec tty-probe -- sh -c 'echo xxxxx > /dev/null; test ! -s /dev/null && echo NULL-OK'
         want: NULL-OK.

  lab.8  /dev/urandom yields entropy
         kubectl exec tty-probe -- sh -c 'head -c 16 /dev/urandom | wc -c'
         want: 16.

  lab.9  the container has its own devpts and a ptmx symlink into it
         kubectl exec tty-probe -- sh -c 'test -d /dev/pts && test -L /dev/ptmx && readlink /dev/ptmx'
         want: pts/ptmx (RELATIVE — an absolute link could be made to
         point at the guest's instance).

  lab.10 THE ALLOWLIST BOUNDARY — no vsock node reaches the container
         kubectl exec tty-probe -- sh -c 'test ! -e /dev/vsock && test ! -e /dev/vhost-vsock && echo NO-VSOCK'
         want: NO-VSOCK. A container that could open /dev/vsock could dial
         its own pod's guest agent over vsock loopback and exec into every
         container of the pod, read their logs, and stop it.

  lab.11 /dev/shm exists and is bounded
         kubectl exec tty-probe -- sh -c 'test -d /dev/shm && df -h /dev/shm'
         want: a tmpfs sized 64M for a pod that declared no Memory
         emptyDir at that path.

  lab.12 a pod-declared /dev/shm still WINS
         Run a second pod with a Memory emptyDir at /dev/shm sized 128Mi.
         want: df reports 128M, and there is exactly ONE mount at
         /dev/shm (`grep ' /dev/shm ' /proc/self/mountinfo | wc -l` = 1).

  lab.13 NON-TTY EXEC REGRESSION — the untouched path still carries an
         exit code and keeps its streams apart
         kubectl exec tty-probe -- sh -c 'exit 42'; echo "rc=$?"
         want: rc=42
         kubectl exec tty-probe -- sh -c 'echo out; echo err >&2' 2>/dev/null
         want: only "out" on stdout.

  lab.14 concurrent tty execs get DISTINCT terminals
         Run two `kubectl exec -it tty-probe -- tty` at once.
         want: two different /dev/pts/<n> values.
====================================================================
LAB

[ "$FAIL" -eq 0 ] || exit 1
echo "================ vm-tty UNIT TIER GREEN (14 lab rungs owed) ================"
