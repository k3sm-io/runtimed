#!/usr/bin/env bash
#
# runtimed vm-builder-prereqs acceptance gate — a vm container has the two kernel
# filesystems an in-cluster runc-based build worker (buildkitd) needs, and does
# NOT have the loop devices that would widen every container's device surface.
#
# What this slice buys, and therefore what the gate must show:
#
#   /proc — a vm container's chroot had NO /proc: buildkitd's runc worker reads
#   /proc/self and mounts its own /proc inside each container it builds, and any
#   workload that reads /proc/self/status or /proc/meminfo failed. Each container
#   now gets a FRESH procfs (never a bind of the guest's). There is no pid
#   namespace — containers are chroot-only — so /proc shows guest-wide pids; that
#   is the honest state and it does not block runc, which mounts its own private
#   /proc inside the container it runs.
#
#   /sys/fs/cgroup — the chroot also had no cgroup2 hierarchy, so runc's cgroup
#   manager could not create the per-build sub-cgroups it writes. Each container
#   now gets a WRITABLE cgroup2 mount. cgroup2 is an independent filesystem and
#   attaches without a sysfs parent, so none is mounted and the container's /sys
#   is otherwise empty. Without a cgroup namespace the mount is a view of the
#   guest-wide unified hierarchy — a metering/build aid, not an isolation
#   boundary (the chroot-only ceiling the package doc records).
#
#   THE LOOP-DEVICE POSTURE. `mount -o loop` of an ext4 image needs loop devices,
#   which a build-class pod gets by mounting its OWN devtmpfs (the guest root
#   can). Loop nodes are deliberately NOT added to the default device set:
#   widening it would hand /dev/loop* to every workload, exactly the leak the
#   additive allowlist exists to prevent. The gate asserts their ABSENCE.
#
# TWO TIERS, marked. Everything above the LAB banner runs here, with no VM, no
# network and no privilege: the decisions all live in pure functions in
# pkg/guestinit precisely so they are reachable by `go test` on darwin. The legs
# below the banner need a live vm pod on a lab host and are PRINTED, never faked.
#
# Usage:  hack/acceptance/vm-builder-prereqs.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PKG_DIR="$REPO_ROOT/pkg/guestinit"
MOUNTS="$PKG_DIR/mounts.go"
DEVICES="$PKG_DIR/devices.go"
PLAN="$PKG_DIR/plan.go"
DOC="$PKG_DIR/doc.go"
KERNELFS_TEST="$PKG_DIR/kernelfs_test.go"
MAIN="$REPO_ROOT/cmd/k3sm-guest-init/main_linux.go"
SELF="$HERE/vm-builder-prereqs.sh"

GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

echo "==> runtimed vm-builder-prereqs acceptance (per-container /proc + cgroup2, loop-device posture)"

# ---- vp.0 — the gate parses and every source under test exists --------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$MOUNTS" "$DEVICES" "$PLAN" "$DOC" "$KERNELFS_TEST" "$MAIN"; do
	[ -f "$f" ] || { echo "missing: $f" >&2; b0=no; }
done
ladder "$b0" "vp.0  gate parses (bash -n) + mounts/devices/plan/doc.go and kernelfs_test.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "vm-builder-prereqs: the gate or a source under test is missing/unparseable" >&2
	echo "vm-builder-prereqs: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- vp.1 — gofmt, scoped to this slice's packages --------------------------
fmt="$(cd "$REPO_ROOT" && gofmt -l pkg/guestinit cmd/k3sm-guest-init 2>&1 || true)"
if [ -z "$fmt" ]; then
	ladder ok "vp.1  gofmt -l pkg/guestinit cmd/k3sm-guest-init is empty"
else
	echo "$fmt"
	ladder no "vp.1  gofmt -l pkg/guestinit cmd/k3sm-guest-init is empty"
fi

# ---- vp.2 — go vet ----------------------------------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go vet ./pkg/guestinit/... >"$SCRATCH/vet.log" 2>&1); then
	ladder ok "vp.2  go vet ./pkg/guestinit/... is clean"
else
	tail -20 "$SCRATCH/vet.log"
	ladder no "vp.2  go vet ./pkg/guestinit/... is clean"
fi

# ---- vp.3 — ContainerKernelFS exists and is WIRED into the per-container plan
# The plan is only worth testing if containerPlan actually appends it. A function
# nobody calls would keep every pure test green while shipping an empty /proc.
wire=ok
grep -qE '^func ContainerKernelFS\(name string, podMounts \[\]MountStep\) \[\]MountStep' "$MOUNTS" || wire=no
grep -qE 'mounts = append\(mounts, ContainerKernelFS\(c\.GetName\(\), podMounts\)\.\.\.\)' "$PLAN" || wire=no
# It must sit AFTER the /dev steps and BEFORE the pod-visible mounts, so a pod
# mount at /proc or /sys/fs/cgroup wins by the same yield rule /dev/shm uses.
dline="$(grep -nE 'mounts = append\(mounts, dev\.Mounts\.\.\.\)' "$PLAN" | head -1 | cut -d: -f1 || true)"
kline="$(grep -nE 'mounts = append\(mounts, ContainerKernelFS\(' "$PLAN" | head -1 | cut -d: -f1 || true)"
vline="$(grep -nE 'mounts = append\(mounts, containerVisibleMounts\(' "$PLAN" | head -1 | cut -d: -f1 || true)"
[ -n "$dline" ] && [ -n "$kline" ] && [ -n "$vline" ] || wire=no
[ "$dline" -lt "$kline" ] && [ "$kline" -lt "$vline" ] || wire=no
ladder "$wire" "vp.3  ContainerKernelFS is wired after dev ($dline) < kernelfs ($kline) < pod mounts ($vline)"

# ---- vp.4 — the mount set is a FRESH proc + a WRITABLE cgroup2, no sysfs -----
# Asserted from the source because the mounts themselves are only observable on a
# booted guest (the LAB rungs). A bind of the guest /proc, a read-only cgroup2,
# or a stray sysfs would each break a build worker while looking plausible.
# Scope the assertions to the ContainerKernelFS function body: PseudoMounts
# legitimately mounts the GUEST's sysfs and cgroup2, which are not what this gate
# is about.
body="$(awk '/^func ContainerKernelFS\(/{f=1} f{print} f&&/^}/{exit}' "$MOUNTS")"
set0=ok
printf '%s\n' "$body" | grep -qE 'Source: "proc", Target: path\.Join\(root, "proc"\), FSType: "proc"' || set0=no
printf '%s\n' "$body" | grep -qE 'Source: "cgroup2", Target: path\.Join\(root, "sys/fs/cgroup"\), FSType: "cgroup2"' || set0=no
# No OptionReadOnly anywhere in the per-container kernel FS (runc must create sub-cgroups).
if printf '%s\n' "$body" | grep -q 'OptionReadOnly'; then set0=no; fi
# No sysfs is mounted under the container by default (cgroup2 attaches without one).
if printf '%s\n' "$body" | grep -qE 'FSType: "sysfs"'; then set0=no; fi
ladder "$set0" "vp.4  the per-container set is a fresh procfs + a writable cgroup2, no sysfs"

# ---- vp.5 — the LOOP-DEVICE POSTURE: no loop node in the default set ---------
# The security posture, asserted from the shipped allowlist. Widening
# DefaultDevices would hand /dev/loop* to every container; a build pod mounts its
# own devtmpfs instead.
allow="$(grep -E '^var DefaultDevices = ' "$DEVICES" || true)"
loop=ok
echo "$allow" | grep -q '"null", "zero", "full", "random", "urandom", "tty"' || loop=no
if echo "$allow" | grep -qiE 'loop'; then loop=no; fi
# And no CODE line (comments/prose excluded — doc.go documents the posture) in
# the tree binds or exposes a loop node to the container device surface.
loopref="$( { grep -rn --include='*.go' '/dev/loop' "$PKG_DIR" "$REPO_ROOT/cmd/k3sm-guest-init" 2>/dev/null || true; } | { grep -v '_test\.go:' || true; } | { grep -vE ':[[:space:]]*//' || true; } | { grep -vE '^[^:]*doc\.go:' || true; } | wc -l | tr -d ' ')"
[ "$loopref" = 0 ] || loop=no
ladder "$loop" "vp.5  DefaultDevices names no loop device and no code line exposes one ($loopref refs)"

# ---- vp.6 — the guest init cross-builds for the guest it ships in ------------
if (cd "$REPO_ROOT" && env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$SCRATCH/k3sm-guest-init" ./cmd/k3sm-guest-init >"$SCRATCH/cross.log" 2>&1); then
	ladder ok "vp.6  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
else
	tail -20 "$SCRATCH/cross.log"
	ladder no "vp.6  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/k3sm-guest-init"
fi

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

# ---- vp.7 .. vp.10 — the pure legs, by exact name ---------------------------
run_test "vp.7"  4 TestContainerKernelFSMountsProcAndCgroup2
run_test "vp.8"  4 TestContainerKernelFSYieldsToPodMounts
run_test "vp.9"  2 TestNoLoopDevicesInDefaultSet
run_test "vp.10" 2 TestPlanWiresContainerKernelFS

# ---- vp.11 — the whole package, under -race --------------------------------
if (cd "$REPO_ROOT" && "${GOENV[@]}" go test -race -count=1 ./pkg/guestinit/ >"$SCRATCH/pkg.log" 2>&1); then
	ladder ok "vp.11  go test -race ./pkg/guestinit/ is green"
else
	grep -Ev '^ld: warning' "$SCRATCH/pkg.log" | tail -30
	ladder no "vp.11  go test -race ./pkg/guestinit/ is green"
fi

# ---- vp.12 — the Apache header on every file this slice adds ----------------
if (cd "$REPO_ROOT" && ./hack/verify-boilerplate.sh >"$SCRATCH/boilerplate.log" 2>&1); then
	ladder ok "vp.12  hack/verify-boilerplate.sh is green"
else
	tail -20 "$SCRATCH/boilerplate.log"
	ladder no "vp.12  hack/verify-boilerplate.sh is green"
fi

echo "----------------------------------------"
echo "vm-builder-prereqs (unit tier): $PASS passed, $FAIL failed"

# ============================================================================
# LAB TIER — NOT RUN HERE. These need a booted vm pod on a lab host with a live
# control plane, which this gate has neither the privilege nor the hardware to
# produce. They are the red -> green criteria for the slice and are printed in
# full so a human session can run them verbatim and paste the result.
#
# Setup (one vm-RuntimeClass pod, any small linux image):
#
#   kubectl run bld-probe --image=alpine:3.20 --restart=Never \
#     --overrides='{"spec":{"runtimeClassName":"vm"}}' -- sleep 3600
#   kubectl wait --for=condition=Ready pod/bld-probe --timeout=180s
#
# Teardown:  kubectl delete pod bld-probe --now
# ============================================================================
cat <<'LAB'

======================= LAB TIER (human-run) =======================
Run each rung against a Ready vm pod. Every one of these was RED before
this slice: a vm container's chroot had no /proc and no /sys/fs/cgroup.

  lab.1  /proc is mounted and /proc/self resolves
         kubectl exec bld-probe -- sh -c 'test -d /proc/self && cat /proc/self/comm && echo PROC-OK'
         want: a command name, then PROC-OK. Before this slice /proc was
         empty and buildkitd's runc worker could not read /proc/self.

  lab.2  /proc/meminfo is readable (the guest RAM a worker reads)
         kubectl exec bld-probe -- sh -c 'grep -q MemTotal /proc/meminfo && echo MEMINFO-OK'
         want: MEMINFO-OK.

  lab.3  /sys/fs/cgroup is a WRITABLE cgroup2 (the magic + a create probe)
         kubectl exec bld-probe -- sh -c 'test -f /sys/fs/cgroup/cgroup.controllers && mkdir /sys/fs/cgroup/probe-$$ && rmdir /sys/fs/cgroup/probe-$$ && echo CGROUP2-OK'
         want: CGROUP2-OK. cgroup.controllers proves it is cgroup2; the
         mkdir/rmdir proves runc can create the per-build sub-cgroups it
         writes. A read-only mount fails the mkdir.

  lab.4  the cgroup2 magic number, checked directly
         kubectl exec bld-probe -- sh -c 'stat -f -c %t /sys/fs/cgroup'
         want: 63677270 (the cgroup2 superblock magic 0x63677270 in hex).

  lab.5  THE LOOP-DEVICE POSTURE — no loop node is in the container by default
         kubectl exec bld-probe -- sh -c 'ls /dev/loop-control /dev/loop0 2>/dev/null; test ! -e /dev/loop-control && test ! -e /dev/loop0 && echo NO-LOOP'
         want: NO-LOOP. A build-class pod that needs `mount -o loop` mounts
         its OWN devtmpfs to get loop devices; they are never in the default
         device set.

  lab.6  a build-class pod CAN reach loop devices via its own devtmpfs
         (Run a privileged/build pod that mounts devtmpfs itself.)
         inside it:  mount -t devtmpfs dev /mnt/dev && test -e /mnt/dev/loop-control && echo LOOP-REACHABLE
         want: LOOP-REACHABLE — the guest root path is the sanctioned way to
         loop-mount, not a widened default /dev.

  lab.7  END-TO-END — buildkitd's runc worker starts in-cluster
         Deploy a buildkitd pod (runtimeClassName: vm) and run a trivial
         `buildctl build` (a COPY-only Dockerfile). want: the build reaches
         the runc worker without the "/proc", "cgroup" or "loop" self-mount
         workarounds the mudkitty bake prototype needed on 2026-09-02.
====================================================================
LAB

[ "$FAIL" -eq 0 ] || exit 1
echo "============ vm-builder-prereqs UNIT TIER GREEN (7 lab rungs owed) ============"
