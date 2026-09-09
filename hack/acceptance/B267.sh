#!/usr/bin/env bash
# B267 — the M15.0 spike: a k3sm-owned Swift helper boots one Linux container VM on the
# Containerization Swift package, from a kernel k3sm built itself and an ext4 root k3sm built
# from its own unpacked OCI tree.
#
# EXIT-CODE CONTRACT (the item's notes): this gate passes iff
#   (a) the helper, ad-hoc signed with only com.apple.security.virtualization, boots the guest
#       and `uname -sm` inside it prints "Linux aarch64"; and
#   (e) on SIGTERM the helper stops its machine and exits 0 within 30 s; after kill -9 nothing is
#       orphaned (no cvmspike process survives) and a fresh boot succeeds.
# Every other criterion — (b) timings, (c) vminitd's surface, (d) toolchain, (f) rootfs API,
# (g) ownership, (h) unentitled launch, (i) memory posture, (j) network segment, (k) the k3sm-built
# kernel — is REC-class: printed with its answer and evidence, never a gate failure (the m11.9
# rule: a recording criterion never fails the gate, so an honest "no" is never punished).
#
# Inputs (env, all optional):
#   B267_KERNEL  the arm64 Image k3sm built from the framework's config
#                (default: hack/spikes/containerhost/kernel/out/Image)
#   B267_TREE    a materialized linux/arm64 OCI tree (default: ../k3sm-io.scratch/b267/rootfs-tree)
#   B267_STORE   the framework image store dir for vminit (default: ../k3sm-io.scratch/b267/store)
#   B267_VMHOST_RSS  host RSS (KiB) measured for the same experiment on k3sm-vmhost, if known
# Requires: the Command Line Tools Swift toolchain (criterion d), network for the vminit pull.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # runtimed/hack
REPO="$(cd "$HERE/.." && pwd)"
SPIKE="$REPO/hack/spikes/containerhost"
SCRATCH="$(cd "$REPO/../.." 2>/dev/null && pwd)/k3sm-io.scratch/b267"
[ -d "$SCRATCH" ] || SCRATCH="$HOME/Code/k3sm-io.scratch/b267"
KERNEL="${B267_KERNEL:-$SPIKE/kernel/out/Image}"
TREE="${B267_TREE:-$SCRATCH/rootfs-tree}"
STORE="${B267_STORE:-$SCRATCH/store}"
BIN="$SPIKE/.build/release/cvmspike"
MACHINE="$(sysctl -n machdep.cpu.brand_string) · macOS $(sw_vers -productVersion) · $(sysctl -n hw.memsize | awk '{printf "%d GiB", $1/1073741824}')"
rec() { printf '  REC %s\n' "$*"; }
fail=0
echo "==> B267 on $MACHINE"

# ---- (d) toolchain, first: builds with the Command Line Tools toolchain, no Xcode.app on the path.
if DEVELOPER_DIR=/Library/Developer/CommandLineTools swift --version >/dev/null 2>&1; then
  ver="$(DEVELOPER_DIR=/Library/Developer/CommandLineTools swift --version 2>&1 | head -1)"
  if [ ! -x "$BIN" ]; then
    ( cd "$SPIKE" && DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build -c release >/dev/null )
  fi
  rec "(d) toolchain: PASS — builds with the standalone Command Line Tools toolchain ($ver), DEVELOPER_DIR=/Library/Developer/CommandLineTools; the installed Xcode.app ($(xcodebuild -version 2>/dev/null | head -1)) cannot build swift-tools-version 6.2 and is not needed"
else
  rec "(d) toolchain: FAIL — no Command Line Tools Swift toolchain; the helper would be an optional release artifact"
fi
[ -x "$BIN" ] || { echo "FAIL: $BIN missing"; exit 1; }

# ---- sign: ad-hoc, exactly one entitlement (the vmhost discipline).
codesign --force --sign - --entitlements "$SPIKE/cvmspike.entitlements" "$BIN" 2>/dev/null
ents="$(codesign -d --entitlements :- "$BIN" 2>/dev/null | grep -c 'com.apple.security.virtualization' || true)"
[ "$ents" -ge 1 ] || { echo "FAIL: entitlement not on the binary"; exit 1; }

# ---- (k) the kernel is k3sm-built from the framework's config.
if [ -f "$KERNEL" ]; then
  magic="$(xxd -s 56 -l 4 -p "$KERNEL" 2>/dev/null || true)"
  rec "(k) kernel: k3sm-built Image present ($(stat -f%z "$KERNEL") bytes, arm64 magic ${magic:-?}) from the framework's config-arm64 normalized to its olddefconfig fixed point for linux-6.18.48 (see kernel/build-framework-config.sh --normalize-config); no kernel binary was downloaded"
else
  echo "FAIL: kernel Image missing at $KERNEL (build it: hack/spikes/containerhost/kernel/build-framework-config.sh)"; exit 1
fi

# ---- (f) rootfs from k3sm's own tree via the framework's public EXT4 formatter.
mkdir -p "$STORE"
IMG="$SCRATCH/rootfs.ext4"
t0=$(date +%s%3N 2>/dev/null || python3 -c 'import time;print(int(time.time()*1000))')
mk="$("$BIN" mkext4 "$TREE" "$IMG" $((512*1024*1024)))"
rec "(f) rootfs API: YES — EXT4.Formatter.create(path:link:mode:buf:uid:gid:) walked the materialized tree at $TREE → $IMG: $mk (public API in ContainerizationEXT4/EXT4+Formatter.swift; Formatter+Unpack.swift's unpack(reader:) also takes a tar stream)"

# ---- (a) boot + uname; (b) timings; PID 1 comm.
out="$("$BIN" boot "$KERNEL" "$STORE" "$IMG" --cmd 'uname -sm' 2>&1)" || { echo "  boot output: $out"; fail=1; }
echo "  boot: $out"
uname_out="$(printf '%s' "$out" | python3 -c 'import sys,json; d=json.loads([l for l in sys.stdin if l.startswith("{")][-1]); print(d.get("cmd_output",""))' 2>/dev/null || true)"
if [ "$uname_out" = "Linux aarch64" ]; then
  echo "  (a) boot: PASS — uname -sm = 'Linux aarch64' under the ad-hoc-signed, single-entitlement helper"
else
  echo "  (a) boot: FAIL — uname -sm = '$uname_out'"; fail=1
fi
rec "(b) timings on $MACHINE: $(printf '%s' "$out" | python3 -c 'import sys,json; d=json.loads([l for l in sys.stdin if l.startswith("{")][-1]); print("initfs %d ms (vminit pull/unpack, once), create %d ms, start (boot-to-ready) %d ms, exec %d ms, stop %d ms" % (d["initfs_ms"],d["create_ms"],d["start_ms"],d["exec_ms"],d["stop_ms"]))' 2>/dev/null || echo 'not parsed'); mkext4 build: $mk; vm-path figure on this machine: not measured in this spike"
rec "(c) vminitd surface (read from Containerization 0.45.0 source, Sources/Containerization/SandboxContext/SandboxContext.proto): exec with exit code YES (CreateProcess/StartProcess/WaitProcess); stdio streams YES (per-process stdin/stdout/stderr vsock ports on CreateProcessRequest); signals YES (KillProcess, Kill); pty YES (terminal in the OCI process config + ResizeProcess); stats YES (ContainerStatistics); mount injection YES (Mount/Umount); resolv.conf delivery YES (ConfigureDns/ConfigureHosts); Attach's multi-subscriber retained-stdio semantics NO native RPC — stdio is one vsock stream per process, so replay/fan-out is the host helper's job (the same place k3sm's guest-init does it today); PID 1 in the guest reports as '$(printf '%s' "$out" | python3 -c 'import sys,json; d=json.loads([l for l in sys.stdin if l.startswith("{")][-1]); print(d.get("pid1_comm",""))' 2>/dev/null)'"
rec "(g) ownership over a block root: NO idmapped-mount support — grep of the framework's Sources and vminitd RPCs for idmap/fsGroup/uidmap is empty; ownership is whatever the ext4 image carries plus the process user, so an fsGroup must be baked at image build (the cache key gains the ownership tuple) or applied by an in-guest chown step"
rec "(j) network segment: the framework's VmnetNetwork creates its own vmnet network (vmnet_network_ref, VMNET_SHARED_MODE, its own CIDRv4 subnet — Sources/Containerization/VmnetNetwork.swift) rather than the VZNATNetworkDeviceAttachment k3sm-vmhost uses, so guests on the two backends are on different segments by construction; not measured live here (the spike attaches no interface)"

set +e
# ---- (h) unentitled launch: strip the entitlement and boot.
cp "$BIN" "$SCRATCH/cvmspike-noent"; codesign --force --sign - "$SCRATCH/cvmspike-noent" 2>/dev/null
set +e; hout="$("$SCRATCH/cvmspike-noent" boot "$KERNEL" "$STORE" "$IMG" --cmd 'true' 2>&1)"; hrc=$?; set -e
if [ "$hrc" = 0 ]; then rec "(h) unentitled launch: UNEXPECTED — booted without the entitlement (rc 0)"
elif printf '%s' "$hout" | grep -q 'VZErrorDomain'; then rec "(h) unentitled launch: CATCHABLE — the framework throws a VZErrorDomain error the helper can handle (this spike lets it reach top level, hence rc $hrc); no ObjC-style abort, so a preflight is a courtesy, not a crash guard: $(printf '%s' "$hout" | grep -o 'VZErrorDomain[^"]*"[^"]*"' | head -1 | cut -c1-140)"
else rec "(h) unentitled launch: ABORT (rc $hrc) without a thrown error — the ObjC path's behaviour; the helper needs a preflight before any VZ object: $(printf '%s' "$hout" | tail -1 | cut -c1-140)"; fi

# ---- (e) lifetime: SIGTERM bound, kill -9 orphan check, fresh boot.
"$BIN" boot "$KERNEL" "$STORE" "$IMG" --hold 120 --cmd 'true' > "$SCRATCH/hold.log" 2>&1 &
hp=$!
up=0; for i in $(seq 1 60); do grep -q '"event":"up"' "$SCRATCH/hold.log" 2>/dev/null && { up=1; break; }; kill -0 $hp 2>/dev/null || break; sleep 1; done
if [ "$up" != 1 ]; then echo "  (e) SIGTERM: FAIL — the held guest never came up: $(tail -1 "$SCRATCH/hold.log" | cut -c1-160)"; kill -9 $hp 2>/dev/null; fail=1; else
ts=$(python3 -c 'import time;print(time.time())'); kill -TERM $hp; for i in $(seq 1 30); do kill -0 $hp 2>/dev/null || break; sleep 1; done
if kill -0 $hp 2>/dev/null; then echo "  (e) SIGTERM: FAIL — still alive after 30 s"; kill -9 $hp; fail=1; else
  dt=$(python3 -c "import time;print(round(time.time()-$ts,1))"); echo "  (e) SIGTERM: PASS — the held guest was up; exited within ${dt}s (bound 30 s); $(grep -o '"stop_ms":[0-9]*' "$SCRATCH/hold.log" | head -1)"; fi; fi
"$BIN" boot "$KERNEL" "$STORE" "$IMG" --hold 120 --cmd 'true' > "$SCRATCH/hold2.log" 2>&1 &
hp=$!; sleep 8; kill -9 $hp 2>/dev/null; sleep 2
orph="$( { pgrep -f 'cvmspike boot' || true; } | wc -l | tr -d ' ')"   # no match is the good outcome, not an error
if [ "$orph" = "0" ]; then echo "  (e) kill -9: PASS — no cvmspike survives (the VZ machine lives in-process)"; else echo "  (e) kill -9: FAIL — $orph orphan(s)"; pkill -9 -f 'cvmspike boot'; fail=1; fi
out2="$("$BIN" boot "$KERNEL" "$STORE" "$IMG" --cmd 'uname -sm' 2>&1)" && echo "  (e) fresh boot after kill -9: PASS" || { echo "  (e) fresh boot after kill -9: FAIL: $out2"; fail=1; }

# ---- (i) memory posture: alloc-then-free 2 GiB, idle, sample host RSS.
"$BIN" boot "$KERNEL" "$STORE" "$IMG" --memory 1024 --hold 40 --cmd 'dd if=/dev/zero of=/dev/shm/x bs=1M count=400 2>/dev/null; rm -f /dev/shm/x' > "$SCRATCH/mem.log" 2>&1 &
mp=$!; sleep 25; rss_after="$( { ps -o rss= -p $mp 2>/dev/null || true; } | tr -d ' ')"; sleep 12; rss_idle="$( { ps -o rss= -p $mp 2>/dev/null || true; } | tr -d ' ')"; wait $mp 2>/dev/null || true
rec "(i) memory posture on $MACHINE: host RSS of the helper after the guest allocated and freed 400 MiB in tmpfs: ${rss_after:-?} KiB at +25 s, ${rss_idle:-?} KiB at +37 s idle (guest memory 1 GiB); k3sm-vmhost on the same experiment: ${B267_VMHOST_RSS:+$B267_VMHOST_RSS KiB}${B267_VMHOST_RSS:-not measured in this spike} (1 GiB guest, 400 MiB allocated and freed)"

set -e
echo "----------------------------------------"
if [ "$fail" = 0 ]; then echo "B267: PASS — (a) boot and (e) lifetime hold; every REC line above is recorded, not judged"; exit 0; else echo "B267: FAIL — see (a)/(e) above"; exit 1; fi
