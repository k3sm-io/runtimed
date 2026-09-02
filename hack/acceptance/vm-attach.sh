#!/usr/bin/env bash
#
# runtimed vm-attach acceptance gate — a vm container can own a terminal and
# keep its stdin, and `kubectl attach` bridges a client to both.
#
# What this slice buys, and therefore what the gate must show:
#
#   THE CONTAINER'S OWN TERMINAL — a vm container declaring `tty: true` used to
#   get nothing of the sort: it was spawned on two pipes with PID 1's console as
#   its stdin, so `test -t 0` was false, `stty` had no terminal to talk to, and
#   any program that sizes itself laid out for a device that was not there. It
#   now runs on a pty allocated from its OWN devpts instance before the fork,
#   with Setsid+Setctty, sized 24x80, and owned by the container's identity.
#
#   THE RETAINED ENDPOINTS — a container's stdin write end and its pty master
#   used to be LOCALS in the spawn path that went out of scope at the fork. The
#   only process that could ever write to a running container was the one that
#   had started it, which is precisely why `kubectl attach` could not exist. Both
#   are now kept for the container's whole life in guestagent.AttachHub.
#
#   DETACH IS NOT KILL. This is the subtle half and the one worth the most care:
#   the attach handler's teardown unsubscribes from the output stream and does
#   NOTHING else. It never closes a hub endpoint, never signals the container,
#   and never forwards the client's stdin half-close as EOF. Each of those three
#   would turn "the operator pressed ^]" into "the workload died" — and the last
#   two would do it silently. AttachHub.Release is the exit watcher's, and
#   nobody else's.
#
#   CONCURRENT ATTACHES. Several clients may attach at once; each gets its own
#   output subscription and all of their input interleaves into the one endpoint
#   in arrival order. The agent arbitrates nothing, because the alternative is
#   dropping a client's keystrokes.
#
#   BYTE GRANULARITY. Attach streams from a bounded RAW buffer, not from the
#   line ring `kubectl logs` reads. A line source holds every newline-less
#   write — a shell prompt, a password query, and every keystroke a pty echoes
#   back — until a delimiter arrives that an interactive session may never send,
#   so a full-screen TUI attached to it looks wedged exactly when the user is
#   typing. The container's output pump tees each read into both rings; logs is
#   unchanged, and the gate asserts that contrast on ONE write.
#
#   SUBSCRIBE-THEN-SNAPSHOT. The raw ring snapshots and registers a subscriber
#   in ONE critical section, so a chunk is never lost AND never duplicated —
#   stricter than the line ring's two-step, because a duplicated log line is
#   harmless while a duplicated escape sequence is a corrupted screen. The gate
#   pins the counterfactual too: doing the two steps separately drops the chunk
#   that lands between them.
#
#   CAPABILITY NEGOTIATION. Compat is lockstep via the in-code initramfs sha256
#   pin, so the only reachable way to pair this daemon with an older guest is the
#   dev-lab --guest-artifacts-dir override. Such a pairing used to answer
#   `kubectl attach` with a bare "method Attach not implemented" — true, and
#   indistinguishable to the operator from a bug in the daemon. The guest now
#   advertises `attach` and `tty-exec` in Health, the host records them, and a
#   request against a guest that advertised neither is refused with a message
#   naming the fix.
#
# TWO TIERS, marked. Everything above the LAB banner runs here, with no VM, no
# network and no privilege: the hub, the attach handler, the ordering property
# and both host routes are pure Go reachable by `go test -race` on darwin,
# precisely so they are not lab-only. The legs below the banner need a live vm
# pod on a lab host and are PRINTED, never faked — a gate that pretends to have
# run a VM is worse than one that says it did not.
#
# Usage:  hack/acceptance/vm-attach.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
AGENT_DIR="$REPO_ROOT/pkg/guestagent"
RUNTIME_DIR="$REPO_ROOT/pkg/runtime"
HUB="$AGENT_DIR/attachhub.go"
BYTERING="$AGENT_DIR/bytering.go"
CAPTURE="$AGENT_DIR/capture.go"
SERVER="$AGENT_DIR/server.go"
VERSION="$AGENT_DIR/version.go"
GUEST="$RUNTIME_DIR/guest.go"
EXEC="$RUNTIME_DIR/exec.go"
LEASE="$RUNTIME_DIR/guestlease.go"
MAIN="$REPO_ROOT/cmd/k3sm-guest-init/main_linux.go"
SELF="$HERE/vm-attach.sh"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed vm-attach acceptance (container tty + retained stdio + kubectl attach)"

# ---- va.0 — the gate parses and every source under test exists -------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$HUB" "$BYTERING" "$CAPTURE" "$SERVER" "$VERSION" "$GUEST" "$EXEC" "$LEASE" "$MAIN"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "va.0  gate parses (bash -n) + attachhub/bytering/capture/server/version and their consumers present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "vm-attach: the gate or a source under test is missing/unparseable — nothing else can run" >&2
	echo "vm-attach: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- va.1 — gofmt, scoped to this slice's packages -------------------------
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/guestagent pkg/runtime cmd/k3sm-guest-init 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "va.1  gofmt -l pkg/guestagent pkg/runtime cmd/k3sm-guest-init is empty"
else
	echo "$fmt"
	ladder no "va.1  gofmt -l pkg/guestagent pkg/runtime cmd/k3sm-guest-init is empty"
fi

# ---- va.2 — go vet ---------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/guestagent/... ./pkg/runtime/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "va.2  go vet ./pkg/guestagent/... ./pkg/runtime/... is clean"
else
	grep -Ev '^ld: warning' "$SCRATCH/vet.log" | tail -20
	ladder no "va.2  go vet ./pkg/guestagent/... ./pkg/runtime/... is clean"
fi

# ---- va.3 — the guest init cross-builds for the guest it ships in ----------
# The guest is linux/arm64 and CGO-free (it is the whole userspace of a pinned
# initramfs). This is the only compiler check the spawn half ever gets, which is
# exactly why the decisions live in the darwin-tested packages instead.
if (cd "$REPO_ROOT" && env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$SCRATCH/k3sm-guest-init" ./cmd/k3sm-guest-init >"$SCRATCH/cross.log" 2>&1); then
	ladder ok "va.3  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
else
	tail -20 "$SCRATCH/cross.log"
	ladder no "va.3  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
fi

# ---- va.4 — the spawn path really wires a tty and really retains stdin -----
# Asserted structurally because the behaviour is only observable on a booted
# guest (the LAB rungs below): the fork/exec of a chrooted child on a devpts
# slave has no darwin analogue to test against.
spawn=ok
grep -qE 'func spawn\(cp guestinit\.ContainerPlan, capture \*guestagent\.Capture, hub \*guestagent\.AttachHub' "$MAIN" || spawn=no
grep -qE 'guestinit\.ExecPTYOrigin\(cp\)' "$MAIN" || spawn=no
grep -qE 'guestinit\.OpenPTY\(ptmx, pts\)' "$MAIN" || spawn=no
grep -qE 'guestinit\.SetWinsize\(master, guestinit\.DefaultWinSize\)' "$MAIN" || spawn=no
grep -qE 'guestinit\.ChownTTY\(slave, int\(cp\.Ident\.UID\), int\(cp\.Ident\.GID\)\)' "$MAIN" || spawn=no
grep -qE 'Setctty: cio\.tty,' "$MAIN" || spawn=no
grep -qE 'guestinit\.TTYReader\(c\.master\)' "$MAIN" || spawn=no
grep -qE 'hub\.Register\(cp\.Name, cio\.endpoints\(\)\)' "$MAIN" || spawn=no
ladder "$spawn" "va.4  spawn allocates the container's pty from its OWN devpts, sizes+chowns it, sets Setctty, and registers the endpoints"

# ---- va.5 — the tty pump is ONE, and it is the merged stream ---------------
# The line discipline merges stdout and stderr before either reaches the master,
# so a second pump would be reading a descriptor that does not exist. A tty
# container's output is framed as stdout, exactly as the tty exec path frames
# its own — the two must agree, or the same container's stderr would land on a
# different stream depending on which verb was used to watch it.
onepump=ok
ttypumps="$( { grep -cE 'go pumpOutput\(c\.master' "$MAIN" || true; } | tr -d ' ')"
[ "$ttypumps" = 1 ] || onepump=no
grep -qE 'go pumpOutput\(c\.master, guestinit\.TTYReader\(c\.master\),$' "$MAIN" || onepump=no
grep -qE 'capture\.Writer\(container, guestagent\.StreamStdout\),$' "$MAIN" || onepump=no
grep -qE 'raw, guestagent\.StreamStdout, os\.Stdout\)' "$MAIN" || onepump=no
ladder "$onepump" "va.5  a tty container gets exactly ONE output pump ($ttypumps) and it frames the merged stream as stdout"

# ---- va.5b — the pump TEES into both rings, and attach reads the byte one --
# The defect this rung exists for: `kubectl attach` served from the LINE ring
# holds every newline-less write — a shell prompt, a password query, and every
# keystroke a pty echoes back — until a delimiter that an interactive session
# may never send. A full-screen TUI attached to that source looks wedged exactly
# when the user is typing. So the pump tees each read into BOTH rings and the
# handler reads the byte one, while `kubectl logs` keeps the line one.
tee=ok
grep -qE '^\traw := capture\.Raw\(container\)$' "$MAIN" || tee=no
grep -qE '^\t\tt\.raw\.Append\(t\.kind, p\)$' "$MAIN" || tee=no
grep -qE 'raw     \*guestagent\.ByteRing' "$MAIN" || tee=no
# the handler's output half is the RAW seam, and the line seam is nowhere in it
grep -qE 's\.deps\.RawOutput\.RawStream\(container\)' "$SERVER" || tee=no
attachlogs="$(awk '/^func \(s \*Server\) Attach\(/,/^}$/' "$SERVER" | { grep -c 'deps\.Logs' || true; } | tr -d ' ')"
[ "$attachlogs" = 0 ] || tee=no
# ...and Logs still is the line seam
logsline="$(awk '/^func \(s \*Server\) Logs\(/,/^}$/' "$SERVER" | { grep -c 'deps\.Logs\.Stream' || true; } | tr -d ' ')"
[ "$logsline" = 1 ] || tee=no
# the caps are named constants with a doc comment, not magic numbers
grep -qE '^\tDefaultByteRingBytes  = 64 << 10$' "$BYTERING" || tee=no
grep -qE '^\tDefaultByteRingChunks = 4096$' "$BYTERING" || tee=no
grep -qE '^// DefaultByteRingBytes and DefaultByteRingChunks bound' "$BYTERING" || tee=no
ladder "$tee" "va.5b the pump tees into both rings; Attach reads RawOutput (deps.Logs sites in it: $attachlogs) and Logs still reads the line ring ($logsline)"

# ---- va.6 — DETACH IS NOT KILL, structurally ------------------------------
# The property no unit test can prove by absence alone: the ONLY caller of
# AttachHub.Release in shipped code is the guest's container-exit watcher. An
# attach handler that released — or closed an endpoint by any other route —
# would take every concurrently attached client's input with it, and on a tty
# would hang the container's session up with SIGHUP.
release=ok
# Scoped to the HUB's Release, by receiver: pkg/image and the vm-container path
# have their own unrelated lease.Release(), and a bare `.Release(` would sweep
# them in and make this rung meaningless.
releasers="$( { grep -rniE '[a-z]*hub\.Release\(' "$REPO_ROOT/pkg" "$REPO_ROOT/cmd" --include='*.go' 2>/dev/null || true; } | { grep -v '_test\.go:' || true; })"
relcount="$(printf '%s' "$releasers" | { grep -c . || true; } | tr -d ' ')"
[ "$relcount" = 1 ] || release=no
printf '%s' "$releasers" | grep -q 'cmd/k3sm-guest-init/main_linux.go' || release=no
# and the attach handler closes nothing of the container's. Written as an
# explicit if rather than `grep -q ... && release=no`: under `set -e` a
# short-circuited AND-list is exactly the shape that silently swallows or aborts
# a rung depending on the shell.
if grep -qE 'Release\(|Stdin\.Close\(\)' "$SERVER"; then
	grep -nE 'Release\(|Stdin\.Close\(\)' "$SERVER"
	release=no
fi
# and it is inside the reaper's exit callback, next to the capture close
grep -qE '^\t\t\tcapture\.Close\(ev\.Container\)$' "$MAIN" || release=no
grep -qE '^\t\t\tattachHub\.Release\(ev\.Container\)$' "$MAIN" || release=no
# the attach handler's teardown is its own unsubscribe and nothing else:
# ByteSubscription.Close ends THIS client's subscription, never the ring and
# never the container's endpoints.
grep -qE '^\tdefer sub\.Close\(\)$' "$SERVER" || release=no
if [ "$release" != ok ]; then printf '%s\n' "$releasers"; fi
ladder "$release" "va.6  AttachHub.Release has exactly ONE shipped caller ($relcount), the reaper's exit callback; attach teardown is the unsubscribe alone"

# ---- va.7 — the host route dispatches BEFORE the container lookup ---------
# A vm pod's containers are guest processes with no host containerProc, so a
# lookupContainer that ran first would refuse a container that is demonstrably
# running. Ordering, asserted by line number in the same function.
route=ok
aline="$(grep -nE '^func \(r \*Runtime\) Attach\(stream runtimev1\.Runtime_AttachServer\) error \{' "$EXEC" | head -1 | cut -d: -f1 || true)"
dline="$(grep -nE '^\t\treturn r\.attachGuest\(stream, p, first\)$' "$EXEC" | head -1 | cut -d: -f1 || true)"
lline="$(awk -v s="$aline" 'NR>s && /_, cp, err := r\.lookupContainer\(first\.GetPodId\(\), first\.GetContainer\(\)\)/ {print NR; exit}' "$EXEC" || true)"
[ -n "$aline" ] && [ -n "$dline" ] && [ -n "$lline" ] || route=no
[ -n "$aline" ] && [ -n "$dline" ] && [ -n "$lline" ] && [ "$aline" -lt "$dline" ] && [ "$dline" -lt "$lline" ] || route=no
grep -qE 'func \(r \*Runtime\) attachGuest\(' "$GUEST" || route=no
grep -qE 'func forwardAttachInput\(' "$GUEST" || route=no
grep -qE 'func relayAttachResponse\(' "$GUEST" || route=no
ladder "$route" "va.7  Attach resolves the pod ($dline) BEFORE lookupContainer ($lline) and the vm route is built from the guest.go trio"

# ---- va.8 — the capability tokens are wire, and both ends use the SAME ones -
# A token's spelling is wire: an old guest keeps advertising the old spelling
# forever, so a rename on either side silently refuses a guest that is in fact
# capable. This asserts one home for the constants and that the host reads them
# from it rather than re-spelling the literals.
caps=ok
grep -qE '^\tCapabilityTTYExec[[:space:]]+= "tty-exec"$' "$VERSION" || caps=no
grep -qE '^\tCapabilityAttach[[:space:]]+= "attach"$' "$VERSION" || caps=no
grep -qE '^func Capabilities\(\) \[\]string \{$' "$VERSION" || caps=no
grep -qE 'guestagent\.CapabilityTTYExec, guestagent\.CapabilityAttach' "$GUEST" || caps=no
grep -qE 'r\.requireGuestCapability\("attach", guestagent\.CapabilityAttach, p\)' "$GUEST" || caps=no
grep -qE 'r\.requireGuestCapability\("exec", guestagent\.CapabilityTTYExec, p\)' "$GUEST" || caps=no
grep -qE 'r\.setGuestCapabilities\(p, resp\.GetCapabilities\(\)\)' "$LEASE" || caps=no
# The host must never re-spell a token as a bare literal. "attach" alone is not
# a usable probe — it is also the verb name in every error message on the route
# — so the check is positional: every capability argument must be a
# guestagent.Capability* constant, and the unambiguous "tty-exec" literal must
# appear nowhere outside its one home.
calls="$( { grep -rnE 'requireGuestCapability\(' "$RUNTIME_DIR" --include='*.go' 2>/dev/null || true; } | { grep -v '_test\.go:' || true; } | { grep -v 'func (r \*Runtime) requireGuestCapability' || true; })"
callcount="$(printf '%s' "$calls" | { grep -c . || true; } | tr -d ' ')"
constcalls="$(printf '%s' "$calls" | { grep -cE 'requireGuestCapability\("[a-z]+", guestagent\.Capability' || true; } | tr -d ' ')"
[ "$callcount" -ge 2 ] && [ "$callcount" = "$constcalls" ] || caps=no
strays="$( { grep -rn --include='*.go' '"tty-exec"' "$REPO_ROOT/pkg" "$REPO_ROOT/cmd" 2>/dev/null || true; } | { grep -v "^$VERSION:" || true; } | { grep -v '_test\.go:' || true; } | wc -l | tr -d ' ')"
[ "$strays" = 0 ] || caps=no
if [ "$caps" != ok ]; then printf '%s\n' "$calls"; fi
ladder "$caps" "va.8  the tokens have ONE home in version.go, all $callcount negotiation sites use the constants ($constcalls), and the literal appears nowhere else ($strays strays)"

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

# ---- va.9 .. va.13 — the named legs, by exact name ------------------------
run_test "va.9"  6 pkg/guestagent TestAttachHubRetainsAndReleasesEndpoints
run_test "va.10" 3 pkg/guestagent TestAttachOutputSubscribesBeforeSnapshot
run_test "va.11" 9 pkg/guestagent TestAttachServesTheGuestContract
run_test "va.12" 2 pkg/guestagent TestAgentAdvertisesItsCapabilities
# The defect gate. Its first subtest is the CONTRAST — one newline-less write,
# tee'd into both rings, reaching an attach subscriber while the line ring is
# still holding it — and its third asserts `kubectl logs --tail` still counts
# LINES, so the fix cannot have been "make logs byte-granular too".
run_test "va.12a" 3 pkg/guestagent TestAttachSourceIsByteGranular
run_test "va.12b" 9 pkg/guestagent TestByteRingBoundsAndOrdering
run_test "va.13" 6 pkg/runtime    TestVMPodAttachRoutesToGuestAgent
run_test "va.14" 6 pkg/runtime    TestGuestCapabilityNegotiation
# The two halves joined: the daemon's attachGuest against the SHIPPED agent over
# a real gRPC connection. A contract asserted only against a fake of itself is
# not asserted.
run_test "va.15" 9 pkg/runtime    TestGuestAgentServesTheHostRoutes

# ---- va.16 — both packages, under -race -----------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 ./pkg/guestagent/ ./pkg/runtime/ >"$SCRATCH/pkg.log" 2>&1); then
	ladder ok "va.16  go test -race ./pkg/guestagent/ ./pkg/runtime/ is green"
else
	grep -Ev '^ld: warning' "$SCRATCH/pkg.log" | tail -30
	ladder no "va.16  go test -race ./pkg/guestagent/ ./pkg/runtime/ is green"
fi

# ---- va.17 — the Apache header on every file this slice adds --------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "va.17  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "va.17  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "vm-attach (unit tier): $PASS passed, $FAIL failed"

# ============================================================================
# LAB TIER — NOT RUN HERE. These need a booted vm pod on a lab host with a live
# control plane, which this gate has neither the privilege nor the hardware to
# produce. They are the red -> green criteria for the slice and are printed in
# full so a human session can run them verbatim and paste the result.
#
# Setup (a vm-RuntimeClass pod that keeps stdin AND a terminal — both flags are
# the point; a pod without them is the FailedPrecondition rung, lab.7):
#
#   kubectl run attach-probe --image=alpine:3.20 --restart=Never --stdin --tty \
#     --overrides='{"spec":{"runtimeClassName":"vm"}}' --command -- /bin/sh
#   kubectl wait --for=condition=Ready pod/attach-probe --timeout=180s
#
# Teardown:  kubectl delete pod attach-probe --now
# ============================================================================
cat <<'LAB'

======================= LAB TIER (human-run) =======================
Every rung below was RED before this slice: `kubectl attach` on a vm pod
failed in the host's container lookup, and a vm container declaring
tty: true was spawned on plain pipes with no terminal at all.

  lab.1  the CONTAINER (not an exec) owns a real terminal
         kubectl attach -it attach-probe
         then, at the shell:  test -t 0 && test -t 1 && echo CTR-TTY-OK
         want: CTR-TTY-OK. Before this slice a `tty: true` vm container
         ran on pipes and this was false.

  lab.2  the container's terminal is sized before anything resizes it
         at the attached shell:  stty size
         want: two NON-ZERO numbers (24 80 until the client resizes).
         "0 0" means the pty was never sized and every curses program
         lays itself out for a terminal with no cells.

  lab.3  a resize reaches the RUNNING container
         at the attached shell: run `stty size`, resize the terminal
         window, run `stty size` again.
         want: the second reading tracks the new window (SIGWINCH is
         delivered through the retained master).

  lab.4  ATTACH ECHO — typing reaches the running process
         at the attached shell:  echo hello-from-attach
         want: the line echoes and the command runs. This is the
         retained stdin endpoint; before it, nothing could write to a
         running container at all.

  lab.5  DETACH IS NOT KILL — the process survives, and reattach works
         detach with ^P^Q (or ^C then ^]), then:
           kubectl get pod attach-probe -o jsonpath='{.status.phase}'
         want: Running (NOT Succeeded/Failed — the container must not
         have seen EOF or a signal).
           kubectl attach -it attach-probe
         want: the SAME shell, with its history and its cwd. A new
         process here means the detach killed the old one.

  lab.6  CONCURRENT ATTACHES see the same output and both can type
         Run `kubectl attach -it attach-probe` in two terminals.
         In one:  echo from-A
         want: the line appears in BOTH. Then type in the other and
         confirm the same. Interleaving is expected and is the contract
         — the agent arbitrates nothing.

  lab.7  A CONTAINER WITHOUT STDIN REFUSES, and names the fix
         kubectl run no-stdin --image=alpine:3.20 --restart=Never \
           --overrides='{"spec":{"runtimeClassName":"vm"}}' -- sleep 3600
         kubectl attach -i no-stdin
         want: FailedPrecondition naming `stdin: true` and suggesting
         `kubectl exec -i`. NOT a hang, and NOT a silent attach that
         swallows every keystroke.

  lab.8  kubectl logs shows the MERGED stream for a tty container
         at the attached shell:  echo out; echo err >&2
         then, from another terminal:  kubectl logs attach-probe
         want: BOTH lines. A pty merges stdout and stderr before either
         reaches the master — this is `docker run -t` behaviour, and the
         same merge the tty exec path already performs.

  lab.9  THE EXIT FRAME — a container that exits ends the attach with
         its code
         at the attached shell:  exit 7
         want: the attach ends (not hangs), and
           kubectl get pod attach-probe -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}'
         reports 7.

  lab.10 CAPABILITY REFUSAL against an old guest
         Boot a pod with --guest-artifacts-dir pointed at an initramfs
         built BEFORE this slice (the unsupported dev-lab skew), then:
           kubectl attach -it <pod>
         want: FailedPrecondition naming the "attach" capability and
         telling the operator to recreate the pod on the pinned
         initramfs. NOT "method Attach not implemented", and NOT a
         crash. Repeat with `kubectl exec -it` for "tty-exec".

  lab.11 DAEMON RESTART MID-ATTACH — a clean reattach
         With an attach live:  sudo launchctl kickstart -k system/io.k3sm.runtimed
         want: the client's stream ends (the daemon it was talking to is
         gone), the POD keeps running, and a fresh
         `kubectl attach -it attach-probe` reaches the same shell. The
         endpoints live in the GUEST, so a host restart cannot cost them.

  lab.12 NON-TTY REGRESSION — a container with neither flag is unchanged
         kubectl run plain --image=alpine:3.20 --restart=Never \
           --overrides='{"spec":{"runtimeClassName":"vm"}}' -- \
           sh -c 'echo out; echo err >&2; sleep 300'
         kubectl logs plain
         want: both lines, still DEMULTIPLEXED (`kubectl logs` merges
         them for display, but the container ran on two pipes — a tty
         was not silently introduced).

  lab.13 EXEC REGRESSION — the exec paths are untouched
         kubectl exec attach-probe -- sh -c 'exit 42'; echo "rc=$?"
         want: rc=42
         kubectl exec -it attach-probe -- sh -c 'tty'
         want: /dev/pts/<n> — a DIFFERENT one from the container's own
         terminal (an exec gets its own pty; it does not join the
         container's).
====================================================================
LAB

[ "$FAIL" -eq 0 ] || exit 1
echo "================ vm-attach UNIT TIER GREEN (13 lab rungs owed) ================"
