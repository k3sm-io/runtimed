#!/usr/bin/env bash
# Reproducible build of the pinned Linux guest kernel for the k3sm vm backend.
#
# The artifact is an UNCOMPRESSED arm64 `Image`. VZLinuxBootLoader rejects a
# gzipped kernel outright, so `Image.gz` is not a smaller version of the answer
# — it is a non-answer, and the build asserts against it rather than trusting
# the make target's name.
#
# Three things make a rebuild re-derivable by someone who does not trust us:
#
#   1. the kernel tarball is pinned by sha256, and that pin was itself minted
#      from kernel.org's PGP-signed sha256sums.asc (see KERNEL_SHA256);
#   2. the toolchain is a digest-pinned Debian image, not a tag — the compiler
#      identity is embedded in the kernel's version string, so a floating tag
#      would silently change the artifact;
#   3. the config is committed, and the build FAILS on any drift between the
#      committed file and what `make olddefconfig` derives from it. The config
#      is identity: two kernels built from different configs are different
#      kernels however identical their version strings look.
#
# Usage:
#   hack/guest-kernel/build.sh                 build once into out/
#   hack/guest-kernel/build.sh --repro         build twice, byte-compare
#   hack/guest-kernel/build.sh --regen-config  regenerate the committed config
#
# Every toolchain stage runs inside a vm-RuntimeClass pod on the local k3sm
# cluster (see run_in_toolchain): nothing but curl, shasum, tar, kubectl and
# (for the provenance check) gpg is asked of the host, and no container daemon
# is involved at all. The toolchain image still comes from the library registry
# by digest, pulled by k3sm's own vm path.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
readonly HERE
readonly OUT_DIR="$HERE/out"
readonly CACHE_DIR="$HERE/.cache"
readonly CONFIG_FILE="$HERE/kernel.config"

# ---------------------------------------------------------------- the pins

readonly KERNEL_VERSION="6.18.53"
readonly KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
readonly KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TARBALL}"
readonly KERNEL_SUMS_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc"

# MINTED 2026-09-24, PGP-VERIFIED. sha256sums.asc was fetched and verified
# against the key below (GOODSIG + VALIDSIG B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1,
# signature made 2026-09-21), and this value is the linux-6.18.53.tar.xz line of
# the VERIFIED cleartext. It was NOT taken from an unverified sums file.
readonly KERNEL_SHA256="4d6fba95c2244b08a7b4144a4d38b9be4fb31abb5e7682ae40bb5cb11374cfe0"

# "Kernel.org checksum autosigner <autosigner@kernel.org>", rsa4096, created
# 2013-01-24. This is the PRIMARY key fingerprint; its long id 632D3A06589DA6B1
# is what gpg reports as the issuer of sha256sums.asc.
#
# keys.openpgp.org does NOT carry this key (verified 2026-08-31: HTTP 404 for
# op=get on the fingerprint), so keyserver.ubuntu.com leads the list. The order
# is a fallback chain, not a preference for one operator's honesty: the key is
# accepted only if it hashes to the fingerprint above, whoever served it.
readonly KERNEL_KEY_FPR="B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"

# Greg Kroah-Hartman's stable-release key — the SECOND, independent trust
# anchor. Its fingerprint is published on https://www.kernel.org/signature.html
# (fetched and matched 2026-08-31), so the two pins here have two distinct
# provenance chains: the autosigner fingerprint from gpg's issuer report over
# the signed sums, the developer fingerprint from kernel.org's own page. The
# developer signature (.tar.sign, over the UNCOMPRESSED tar) is the one
# kernel.org itself calls the "best assurance" — the autosigner sums are a
# mirror-integrity check, and this script requires BOTH to pass.
readonly KERNEL_DEV_KEY_FPR="647F28654894E3BD457199BE38DBBDC86092693E"
readonly KERNEL_SIGN_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.sign"
readonly KEYSERVERS="hkps://keyserver.ubuntu.com hkps://pgp.mit.edu hkps://keys.openpgp.org"

# debian:trixie-slim, linux/arm64/v8, resolved 2026-08-31. The digest is the
# reproducibility anchor; the apt package versions inside it deliberately are
# NOT pinned, because a kernel Image embeds the compiler identity and nothing
# else about the packages that produced it.
readonly TOOLCHAIN_IMAGE="debian@sha256:7215f78f35ffe58fe13f244fac9c4f21326d55187271fbb3e1a8aa5cc7e387ab"
readonly TOOLCHAIN_TAG="debian:trixie-slim"

# libarchive-tools supplies bsdtar for the source extraction; see the
# extraction line in build_one for why GNU tar cannot do it here.
readonly BUILD_DEPS="gcc make perl python3 flex bison bc libssl-dev libelf-dev xz-utils cpio libarchive-tools"

# ------------------------------------------------------------- the runner

# The kube context of the local k3sm cluster the toolchain pods run on. The
# cluster is this machine's own: `sudo k3sm install` makes one.
readonly KUBE_CONTEXT="k3sm"

# The pod's image is TOOLCHAIN_IMAGE fully qualified, so the digest above stays
# the one constant both the pin and the pull are made from.
readonly TOOLCHAIN_POD_IMAGE="docker.io/library/${TOOLCHAIN_IMAGE}"

# Guest sizing. On a vm pod the memory limit IS the guest's RAM and the CPU
# limit its vCPU count. 4Gi is chosen against the smallest supported host, an
# 8 GiB Mac whose node advertises 6Gi allocatable: it leaves the node ~2Gi and
# comfortably covers `make -j4` of this config (gcc peaks well under 1 GiB per
# job). The work tree does NOT live in this RAM: /work and /src are
# default-medium emptyDirs, which the vm backend serves from host disk.
readonly TOOLCHAIN_POD_CPU="4"
readonly TOOLCHAIN_POD_MEMORY="4Gi"

# The work emptyDir's ceiling. It holds the extracted tree and the objects of
# one build (the tarball arrives separately, on /src), and it lives on the
# host's disk, so the bound is what keeps a runaway stage from filling the
# disk under the cluster that is running it.
readonly TOOLCHAIN_WORK_LIMIT="5Gi"

# One namespace per invocation, torn down with everything in it on exit. A
# dedicated namespace means the teardown can never reach a pod this script did
# not create.
readonly RUN_NAMESPACE="guest-kernel-build-$$"

# Reproducibility: the three values the kernel would otherwise take from the
# clock and the builder's account, each of which alone defeats a byte-compare.
readonly KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970"
readonly KBUILD_BUILD_USER="k3sm"
readonly KBUILD_BUILD_HOST="k3sm.io"

# ------------------------------------------------------------- the config

# CONFIG_* symbols forced on before olddefconfig — the guest's required option set.
# EVERYTHING is built in: the initramfs carries no module tree, so a `=m` here
# is a boot failure that presents as a missing device.
readonly KCONFIG_ENABLE="
BLK_DEV_INITRD
VIRTIO VIRTIO_MENU VIRTIO_PCI VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES
VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE VIRTIO_BALLOON
HW_RANDOM HW_RANDOM_VIRTIO
FUSE_FS VIRTIO_FS
VSOCKETS VSOCKETS_DIAG VIRTIO_VSOCKETS
EXT4_FS
OVERLAY_FS OVERLAY_FS_METACOPY OVERLAY_FS_REDIRECT_DIR
TMPFS TMPFS_XATTR TMPFS_POSIX_ACL
DEVTMPFS DEVTMPFS_MOUNT
PROC_FS PROC_SYSCTL SYSFS FS_POSIX_ACL
UNIX98_PTYS
BINFMT_ELF BINFMT_SCRIPT BINFMT_MISC
NET UNIX INET IPV6 PACKET TUN
CGROUPS MEMCG CPUSETS CGROUP_SCHED FAIR_GROUP_SCHED CFS_BANDWIDTH
CGROUP_PIDS CGROUP_CPUACCT CGROUP_DEVICE CGROUP_FREEZER
NAMESPACES UTS_NS IPC_NS PID_NS NET_NS USER_NS
SERIAL_CORE SERIAL_CORE_CONSOLE SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE
RTC_CLASS RTC_HCTOSYS RTC_DRV_PL031
"

# Forced off. MODULES is the load-bearing one: with no module loader in the
# guest there is nothing to load a `.ko`, and leaving it on would let a later
# defconfig refresh quietly demote a driver to `=m`.
#
# 9p is off because virtiofs is the share transport; carrying a
# second, unused one only widens the guest kernel's attack surface.
# LOCALVERSION_AUTO is off because it derives a suffix from the source tree's
# git state, which a tarball does not have and a build must not depend on.
readonly KCONFIG_DISABLE="
MODULES
NET_9P NET_9P_VIRTIO 9P_FS
LOCALVERSION_AUTO
"

# The subset asserted `=y` after olddefconfig. A dependency that silently drops
# one of these produces a kernel that boots and then fails at the device — the
# most expensive shape of failure to diagnose, so it is caught at config time.
readonly KCONFIG_REQUIRED="
BLK_DEV_INITRD
VIRTIO VIRTIO_PCI VIRTIO_MMIO VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE
HW_RANDOM_VIRTIO FUSE_FS VIRTIO_FS VSOCKETS VIRTIO_VSOCKETS
EXT4_FS OVERLAY_FS OVERLAY_FS_METACOPY
TMPFS TMPFS_XATTR TMPFS_POSIX_ACL DEVTMPFS DEVTMPFS_MOUNT
PROC_FS SYSFS UNIX98_PTYS
BINFMT_ELF BINFMT_MISC
UNIX INET TUN
CGROUPS MEMCG NAMESPACES PID_NS NET_NS USER_NS
SERIAL_AMBA_PL011_CONSOLE RTC_CLASS
"

# ------------------------------------------------------------------ helpers

die() { printf 'guest-kernel: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

# scratch_dir makes a work directory UNDER the repo's gitignored cache rather
# than in $TMPDIR, so everything a build leaves on the host sits in one place
# that `rm -rf hack/guest-kernel/.cache` clears.
scratch_dir() {
  mkdir -p "$CACHE_DIR"
  mktemp -d "$CACHE_DIR/work.$$.XXXXXXXX"
}

usage() {
  cat <<'USAGE'
usage: hack/guest-kernel/build.sh [--repro | --regen-config]

  (no flag)        verify provenance, build once, write out/Image
  --repro          build twice into separate trees and byte-compare them
  --regen-config   regenerate hack/guest-kernel/kernel.config from defconfig
                   plus the required option set, inside the pinned toolchain
USAGE
}

# preflight asserts the host tools this script cannot proceed without, all of
# them up front: a missing tool twenty minutes into a kernel build is a much
# worse failure than the same tool missing in the first second.
preflight() {
  local missing=0
  command -v kubectl >/dev/null || { echo "PREFLIGHT FAIL: kubectl not found"; missing=1; }
  command -v curl    >/dev/null || { echo "PREFLIGHT FAIL: curl not found"; missing=1; }
  command -v shasum  >/dev/null || { echo "PREFLIGHT FAIL: shasum not found"; missing=1; }
  command -v tar     >/dev/null || { echo "PREFLIGHT FAIL: tar not found"; missing=1; }
  [ "$missing" -eq 0 ] || exit 1
  cluster_preflight
  [ -f "$CONFIG_FILE" ] || die "PREFLIGHT FAIL: $CONFIG_FILE is missing (run --regen-config)"
  echo "preflight ok: k3sm context $KUBE_CONTEXT, node $(cluster_node), toolchain $TOOLCHAIN_IMAGE"
}

# cluster_preflight asserts the three facts run_in_toolchain depends on: the
# context answers, it serves the vm RuntimeClass, and a node is Ready. Each
# failure names the remedy, because the likeliest cause on a fresh Mac is that
# no local cluster was ever installed.
cluster_preflight() {
  local remedy="(install the local cluster with 'sudo k3sm install' and retry)"
  kube get --raw /readyz >/dev/null 2>&1 \
    || die "PREFLIGHT FAIL: kube context '$KUBE_CONTEXT' is not reachable $remedy"
  kube get runtimeclass vm >/dev/null 2>&1 \
    || die "PREFLIGHT FAIL: the cluster serves no 'vm' RuntimeClass $remedy"
  [ -n "$(cluster_node)" ] \
    || die "PREFLIGHT FAIL: the cluster has no Ready node $remedy"
}

# cluster_node prints the name of the first Ready node, or nothing.
cluster_node() {
  kube get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>/dev/null \
    | awk '$2 == "True" { print $1; exit }'
}

kube() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# ------------------------------------------------------ run_in_toolchain

# run_in_toolchain WORK SRC [NAME=VALUE ...] < SCRIPT
#
# Runs SCRIPT with bash in the digest-pinned toolchain, inside a fresh
# vm-RuntimeClass pod on the local k3sm cluster, with:
#   - /work holding WORK's top-level regular files (the working directory),
#   - /src holding SRC's top-level regular files (omitted when SRC is ""),
#   - each NAME=VALUE in the environment,
# and on success copies /work's top-level regular files back into WORK. A
# directory the stage builds under /work (the extracted kernel tree) stays in
# the guest and dies with the pod: the only outputs are the files a stage
# deliberately leaves at the top of /work.
#
# The guest cannot see the host filesystem (hostPath is sealed for vm guests
# by design), so every input and output crosses as a tar stream over kubectl
# exec — and every file of every stream is sha256-hashed on BOTH ends and
# compared, so the transport is not a party the build has to trust. One pod per
# stage, as one container per stage: no stage inherits another's state.
run_in_toolchain() {
  local work="$1" src="$2"; shift 2
  local script; script="$(cat)"
  # BASH_SUBSHELL keeps a stage started from a command substitution (whose
  # counter is a copy) from reusing a name the parent will use later.
  local pod="stage-$((++POD_SEQ))-${BASH_SUBSHELL}"

  toolchain_pod_up "$pod"

  # BOOTSTRAP SHIM for the guest-artifact lag. Guests booted from artifacts
  # older than v6.18.53-k3sm.1 do not apply the image's ownership and mode
  # sidecar, so the Debian rootfs arrives with /tmp and /var/tmp at 0755 rather
  # than the image's 1777, and apt (which drops to _apt to check signatures)
  # cannot create its temp files. The Docker toolchain this runner replaced had
  # a correct /tmp, so this RESTORES that environment rather than departing
  # from it; every stage of a build and of --repro gets it alike.
  # REMOVE once the shipped guest artifacts are >= v6.18.53-k3sm.1, the first
  # release whose initramfs carries the in-guest ownership apply.
  kube -n "$RUN_NAMESPACE" exec "$pod" -c toolchain -- chmod 1777 /tmp /var/tmp \
    || die "bootstrap shim: could not restore /tmp and /var/tmp to 1777 in $pod"

  stream_in "$pod" "$work" /work
  [ -z "$src" ] || stream_in "$pod" "$src" /src

  local status=0
  kube -n "$RUN_NAMESPACE" exec -i "$pod" -c toolchain -- \
    env "$@" bash -c 'cd /work && exec bash -s' <<<"$script" || status=$?

  [ "$status" -ne 0 ] || stream_out "$pod" /work "$work"
  kube -n "$RUN_NAMESPACE" delete pod "$pod" --wait=true --timeout=180s >/dev/null 2>&1 || true
  return "$status"
}

POD_SEQ=0

# teardown deletes this run's namespace, and with it every pod and emptyDir
# the run created, plus this run's host scratch directories (a stage that dies
# skips its own cleanup). It is the top-level shell's EXIT trap, so a failed or
# interrupted stage leaves no guest behind; a stage that dies inside a command
# substitution takes the whole script down with it (set -e), which fires this.
teardown() {
  rm -rf "$CACHE_DIR"/work.$$.*
  kube delete namespace "$RUN_NAMESPACE" --wait=false >/dev/null 2>&1 || true
}

# open_namespace creates the run's namespace and arms its teardown. Called once,
# from the top-level shell, before the first stage: a subshell must not own the
# namespace, or its exit would delete it from under the parent's later stages.
open_namespace() {
  kube create namespace "$RUN_NAMESPACE" >/dev/null \
    || die "could not create namespace $RUN_NAMESPACE"
  trap teardown EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  echo "  runner: namespace $RUN_NAMESPACE on context $KUBE_CONTEXT"
}

# toolchain_pod_up creates one stage pod and waits for it to run. The pod is
# nothing but the pinned image sleeping: every stage command arrives by exec.
toolchain_pod_up() {
  local pod="$1"
  echo "  runner: pod $RUN_NAMESPACE/$pod (vm, ${TOOLCHAIN_POD_CPU} vCPU, ${TOOLCHAIN_POD_MEMORY})" >&2
  kube -n "$RUN_NAMESPACE" create -f - >/dev/null <<EOF || die "could not create pod $pod"
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  labels:
    app.kubernetes.io/name: k3sm-guest-kernel-build
spec:
  runtimeClassName: vm
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  terminationGracePeriodSeconds: 1
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: toolchain
      image: $TOOLCHAIN_POD_IMAGE
      command: ["sleep", "infinity"]
      workingDir: /work
      resources:
        requests: {cpu: "$TOOLCHAIN_POD_CPU", memory: "$TOOLCHAIN_POD_MEMORY"}
        limits:   {cpu: "$TOOLCHAIN_POD_CPU", memory: "$TOOLCHAIN_POD_MEMORY"}
      volumeMounts:
        - {name: work, mountPath: /work}
        - {name: src, mountPath: /src}
  volumes:
    - {name: work, emptyDir: {sizeLimit: $TOOLCHAIN_WORK_LIMIT}}
    - {name: src, emptyDir: {}}
EOF
  if ! kube -n "$RUN_NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=600s >/dev/null 2>&1; then
    kube -n "$RUN_NAMESPACE" get pod "$pod" -o wide >&2 || true
    kube -n "$RUN_NAMESPACE" get events --field-selector "involvedObject.name=$pod" >&2 || true
    die "toolchain pod $pod did not become Ready"
  fi
}

# top_files DIR prints DIR's top-level regular file names, one per line, sorted.
top_files() {
  (cd "$1" && find . -maxdepth 1 -type f | sed 's|^\./||' | LC_ALL=C sort)
}

# safe_name dies on a name the tar/hash plumbing would have to quote. Called
# from the consuming loop (never inside a pipeline, where die would only end a
# subshell).
safe_name() {
  [[ "$1" =~ ^[A-Za-z0-9._+-]+$ ]] || die "refusing to stream a file with an unsafe name: $1"
}

# guest_sums POD DIR FILE... prints sha256sum lines for the files in-guest.
guest_sums() {
  local pod="$1" dir="$2"; shift 2
  kube -n "$RUN_NAMESPACE" exec "$pod" -c toolchain -- \
    sh -c 'cd "$1" && shift && sha256sum -- "$@"' sh "$dir" "$@" \
    || die "could not hash $pod:$dir in-guest"
}

# host_sums DIR FILE... prints the same line shape for the files on the host.
host_sums() {
  local dir="$1"; shift
  (cd "$dir" && shasum -a 256 -- "$@") || die "could not hash $dir on the host"
}

# compare_sums DIRECTION HOST GUEST dies unless the two hash listings agree
# line for line, and prints each verified file as evidence.
compare_sums() {
  local what="$1" host="$2" guest="$3"
  if [ "$host" != "$guest" ]; then
    printf '  STREAM HASH MISMATCH (%s)\n  host:\n%s\n  guest:\n%s\n' "$what" "$host" "$guest" >&2
    die "a streamed file hashed differently on the two ends ($what)"
  fi
  printf '%s\n' "$host" | while read -r sum name; do
    echo "  stream $what: $name sha256=$sum (host == guest)" >&2
  done
}

# stream_in POD HOSTDIR GUESTDIR copies HOSTDIR's top-level files into the
# guest and verifies them there.
stream_in() {
  local pod="$1" dir="$2" dest="$3" files=() listing f
  listing="$(top_files "$dir")" || die "could not list $dir"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    safe_name "$f"; files+=("$f")
  done <<<"$listing"
  [ "${#files[@]}" -gt 0 ] || return 0
  (cd "$dir" && COPYFILE_DISABLE=1 tar --format ustar -cf - -- "${files[@]}") \
    | kube -n "$RUN_NAMESPACE" exec -i "$pod" -c toolchain -- tar -C "$dest" --no-same-owner -xf - \
    || die "streaming $dir into $pod:$dest failed"
  compare_sums "in $dest" "$(host_sums "$dir" "${files[@]}")" "$(guest_sums "$pod" "$dest" "${files[@]}")"
}

# stream_out POD GUESTDIR HOSTDIR copies GUESTDIR's top-level files out of the
# guest and verifies them on the host.
stream_out() {
  local pod="$1" src="$2" dir="$3" files=() listing f
  listing="$(kube -n "$RUN_NAMESPACE" exec "$pod" -c toolchain -- find "$src" -maxdepth 1 -type f -printf '%f\n')" \
    || die "could not list $pod:$src"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    safe_name "$f"; files+=("$f")
  done <<<"$(printf '%s\n' "$listing" | LC_ALL=C sort)"
  [ "${#files[@]}" -gt 0 ] || return 0
  local guest; guest="$(guest_sums "$pod" "$src" "${files[@]}")"
  kube -n "$RUN_NAMESPACE" exec "$pod" -c toolchain -- tar -C "$src" --format ustar -cf - -- "${files[@]}" \
    | tar -C "$dir" -xf - \
    || die "streaming $pod:$src out to $dir failed"
  compare_sums "out $src" "$(host_sums "$dir" "${files[@]}")" "$guest"
}

# gpg_cmd echoes how to run gpg. The host's own gpg is preferred; when it is
# absent the pinned toolchain image supplies one. Both paths VERIFY — there is
# no path that skips the signature, because a sha256 nobody signed is a pin on
# whatever the CDN served, which is exactly the thing being defended against.
gpg_available() { command -v gpg >/dev/null 2>&1; }

# verify_provenance proves KERNEL_SHA256 is the value kernel.org signed, not a
# value someone typed. It runs on EVERY invocation, not just the first mint:
# the pin is only worth what its last verification is worth.
verify_provenance() {
  note "provenance — verifying the sha256 pin against kernel.org's signed sums"
  mkdir -p "$CACHE_DIR"
  local signed="$CACHE_DIR/sha256sums.asc"
  curl -fsSL -o "$signed" "$KERNEL_SUMS_URL" \
    || die "could not fetch $KERNEL_SUMS_URL"

  local extracted
  if gpg_available; then
    extracted="$(host_verify_sums "$signed")"
  else
    echo "  host gpg not found; verifying inside the pinned toolchain image instead"
    echo "  (install one with 'brew install gnupg' to verify without a toolchain pod)"
    extracted="$(container_verify_sums "$signed")"
  fi

  [ -n "$extracted" ] || die "no sha256 for $KERNEL_TARBALL in the verified sums"
  [ "$extracted" = "$KERNEL_SHA256" ] || die \
    "PIN MISMATCH: kernel.org signs $extracted for $KERNEL_TARBALL, this script pins $KERNEL_SHA256"
  echo "  verified: $KERNEL_TARBALL sha256=$extracted signed by $KERNEL_KEY_FPR"
}

# host_verify_sums verifies with the host's gpg into a throwaway GNUPGHOME, so
# the operator's own keyring is neither read nor written.
host_verify_sums() {
  local signed="$1"
  local home; home="$(mktemp -d)"
  # shellcheck disable=SC2064  # $home must expand now, not at trap time
  trap "rm -rf '$home'" RETURN
  chmod 700 "$home"

  import_key_checked "$home" "$KERNEL_KEY_FPR"
  gpg --batch --homedir "$home" --output "$home/sums.txt" --verify "$signed" >/dev/null 2>&1 \
    || die "PGP VERIFICATION FAILED for $KERNEL_SUMS_URL"
  awk -v f="$KERNEL_TARBALL" '$2 == f { print $1; exit }' "$home/sums.txt"
}

# import_key_checked fetches one key by full fingerprint and then ASSERTS the
# keyring really holds a key of that fingerprint. Modern gpg is expected to
# reject a substituted keyserver response itself, but that expectation lives in
# gpg's internals; this check makes it a property of THIS script, for whatever
# gpg version the host or the unpinned apt archive supplies.
import_key_checked() {
  local home="$1" fpr="$2" got=0 ks
  for ks in $KEYSERVERS; do
    if gpg --batch --homedir "$home" --keyserver "$ks" --recv-keys "0x$fpr" >/dev/null 2>&1; then
      got=1; break
    fi
  done
  [ "$got" -eq 1 ] || die "could not fetch key $fpr from any of: $KEYSERVERS"
  gpg --batch --homedir "$home" --fingerprint --with-colons 2>/dev/null \
    | grep -q "^fpr:::::::::${fpr}:$" \
    || die "keyring does not hold a key with fingerprint $fpr after import"
}

# container_verify_sums does the same inside the digest-pinned toolchain, for a
# host with no gpg. The image is already trusted by digest to compile the
# kernel, so trusting it to run gpg adds no new party.
container_verify_sums() {
  local signed="$1"
  local work; work="$(scratch_dir)"
  # shellcheck disable=SC2064  # $work must expand now, not at trap time
  trap "rm -rf '$work'" RETURN
  cp "$signed" "$work/sha256sums.asc"

  run_in_toolchain "$work" "" \
    KERNEL_KEY_FPR="$KERNEL_KEY_FPR" \
    KEYSERVERS="$KEYSERVERS" \
    KERNEL_TARBALL="$KERNEL_TARBALL" \
    >/dev/null <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends gnupg dirmngr ca-certificates >/dev/null
export GNUPGHOME=/tmp/gnupg; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
fetch_key() {
  fpr="$1"; got=0
  for ks in $KEYSERVERS; do
    if gpg --batch --keyserver "$ks" --recv-keys "0x$fpr" >/dev/null 2>&1; then got=1; break; fi
  done
  [ "$got" -eq 1 ] || { echo "could not fetch key $fpr" >&2; exit 1; }
  gpg --batch --fingerprint --with-colons 2>/dev/null | grep -q "^fpr:::::::::${fpr}:$" \
    || { echo "keyring does not hold a key with fingerprint $fpr after import" >&2; exit 1; }
}
fetch_key "$KERNEL_KEY_FPR"
gpg --batch --output /tmp/sums.txt --verify /work/sha256sums.asc >/dev/null 2>&1 \
  || { echo "PGP VERIFICATION FAILED" >&2; exit 1; }
awk -v f="$KERNEL_TARBALL" '$2 == f { print $1; exit }' /tmp/sums.txt > /work/pinned
INNER

  cat "$work/pinned"
}

# verify_dev_signature verifies the DEVELOPER signature (.tar.sign, over the
# UNCOMPRESSED tar) against the stable-release key — the second, independent
# trust anchor beside the autosigner sums. Runs inside the pinned toolchain so
# xz+gpg versions are the image's, not the host's. Requires the tarball to be
# in the cache already (call after fetch_pinned).
verify_dev_signature() {
  note "provenance — verifying the developer signature over the uncompressed tar"
  local sign="$CACHE_DIR/$KERNEL_TARBALL.sign"
  curl -fsSL -o "$sign" "$KERNEL_SIGN_URL" || die "could not fetch $KERNEL_SIGN_URL"

  local work; work="$(scratch_dir)"
  # shellcheck disable=SC2064  # $work must expand now, not at trap time
  trap "rm -rf '$work'" RETURN
  cp "$sign" "$work/tar.sign"
  cp "$CACHE_DIR/$KERNEL_TARBALL" "$work/$KERNEL_TARBALL"

  run_in_toolchain "$work" "" \
    KERNEL_DEV_KEY_FPR="$KERNEL_DEV_KEY_FPR" \
    KEYSERVERS="$KEYSERVERS" \
    KERNEL_TARBALL="$KERNEL_TARBALL" \
    >/dev/null <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends gnupg dirmngr ca-certificates xz-utils >/dev/null
export GNUPGHOME=/tmp/gnupg; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
got=0
for ks in $KEYSERVERS; do
  if gpg --batch --keyserver "$ks" --recv-keys "0x$KERNEL_DEV_KEY_FPR" >/dev/null 2>&1; then got=1; break; fi
done
[ "$got" -eq 1 ] || { echo "could not fetch key $KERNEL_DEV_KEY_FPR" >&2; exit 1; }
gpg --batch --fingerprint --with-colons 2>/dev/null | grep -q "^fpr:::::::::${KERNEL_DEV_KEY_FPR}:$" \
  || { echo "keyring does not hold a key with fingerprint $KERNEL_DEV_KEY_FPR after import" >&2; exit 1; }
xz -cd "/work/$KERNEL_TARBALL" | gpg --batch --verify /work/tar.sign - >/dev/null 2>&1 \
  || { echo "DEVELOPER SIGNATURE VERIFICATION FAILED" >&2; exit 1; }
INNER

  echo "  verified: $KERNEL_TARBALL developer signature by $KERNEL_DEV_KEY_FPR"
}

# fetch_pinned fetches once and verifies EVERY time: a cached tarball is not a
# trusted tarball, and re-hashing it costs a second.
fetch_pinned() {
  mkdir -p "$CACHE_DIR"
  local dest="$CACHE_DIR/$KERNEL_TARBALL" got
  if [ ! -f "$dest" ]; then
    note "fetching $KERNEL_URL"
    curl -fSL --progress-bar -o "$dest" "$KERNEL_URL" || die "fetch failed: $KERNEL_URL"
  fi
  got="$(shasum -a 256 "$dest" | awk '{print $1}')"
  [ "$got" = "$KERNEL_SHA256" ] || die \
    "sha256 mismatch for $dest (pinned $KERNEL_SHA256, got $got)"
  echo "  tarball ok: $dest sha256=$got"
}

# toolchain_run pipes a script into the pinned toolchain with the verified
# kernel tarball at /src and a work directory at /work. Only the tarball is
# staged, not the whole cache: the cache also holds this run's other scratch
# directories, which the guest has no business receiving.
toolchain_run() {
  local work="$1"
  local src; src="$(scratch_dir)"
  ln "$CACHE_DIR/$KERNEL_TARBALL" "$src/$KERNEL_TARBALL" 2>/dev/null \
    || cp "$CACHE_DIR/$KERNEL_TARBALL" "$src/$KERNEL_TARBALL"
  local status=0
  run_in_toolchain "$work" "$src" \
    KERNEL_VERSION="$KERNEL_VERSION" \
    KERNEL_TARBALL="$KERNEL_TARBALL" \
    BUILD_DEPS="$BUILD_DEPS" \
    KCONFIG_ENABLE="$KCONFIG_ENABLE" \
    KCONFIG_DISABLE="$KCONFIG_DISABLE" \
    KCONFIG_REQUIRED="$KCONFIG_REQUIRED" \
    KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" \
    KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
    KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" || status=$?
  rm -rf "$src"
  return "$status"
}

# build_one builds the Image into "$1"/Image. The caller owns the directory;
# --repro calls this twice into two of them.
build_one() {
  local dest="$1"
  local work; work="$(scratch_dir)"
  mkdir -p "$dest"
  cp "$CONFIG_FILE" "$work/kernel.config"

  toolchain_run "$work" <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
# shellcheck disable=SC2086  # BUILD_DEPS is a deliberate word-split list
apt-get -qq install -y --no-install-recommends $BUILD_DEPS >/dev/null
echo "  toolchain: $(gcc --version | head -1)"

# WORKAROUND, not a preference: bsdtar, not GNU tar. /work is a vm-RuntimeClass
# emptyDir, a virtiofs share that refuses to create a file with mode 0000 even
# for root (the filed vm-share mode-0000 create refusal). GNU tar extracts
# every absolute or ".." symlink via exactly such a placeholder file, so it
# fails on this tree's 61 such links; bsdtar creates the symlinks directly.
bsdtar -xf "/src/$KERNEL_TARBALL" -C /work
cd "/work/linux-$KERNEL_VERSION"

# Config is identity. The committed file must survive olddefconfig unchanged;
# if it does not, the tree being built is not the tree that was reviewed.
cp /work/kernel.config .config
make ARCH=arm64 olddefconfig >/dev/null
if ! diff -u /work/kernel.config .config > /work/config.drift; then
  echo "FAIL: kernel.config drifts under olddefconfig for linux-$KERNEL_VERSION" >&2
  cat /work/config.drift >&2
  exit 1
fi
echo "  config: no drift under olddefconfig"

grep -qx '# CONFIG_MODULES is not set' .config \
  || { echo "FAIL: CONFIG_MODULES is set; the guest has no module loader" >&2; exit 1; }
for sym in $KCONFIG_REQUIRED; do
  grep -qx "CONFIG_$sym=y" .config \
    || { echo "FAIL: CONFIG_$sym is not built in" >&2; exit 1; }
done
echo "  config: every required symbol is built in"

make -j"$(nproc)" ARCH=arm64 Image >/dev/null
IMG=arch/arm64/boot/Image
[ -f "$IMG" ] || { echo "FAIL: $IMG was not produced" >&2; exit 1; }

# VZLinuxBootLoader rejects a compressed kernel, so a gzip magic here is a
# non-artifact however plausible its size looks. The positive check is the
# arm64 Image header magic 'ARM\x64' at offset 56.
MAGIC=$(od -An -tx1 -N2 "$IMG" | tr -d ' \n')
[ "$MAGIC" != "1f8b" ] || { echo "FAIL: $IMG is gzip-compressed" >&2; exit 1; }
ARM64=$(od -An -tx1 -j56 -N4 "$IMG" | tr -d ' \n')
[ "$ARM64" = "41524d64" ] || { echo "FAIL: $IMG lacks the arm64 Image magic (got $ARM64)" >&2; exit 1; }

cp "$IMG" /work/Image
echo "  built: $(stat -c%s /work/Image) bytes, uncompressed arm64 Image"
INNER

  cp "$work/Image" "$dest/Image"
  rm -rf "$work"
}

# report prints the facts a human pins a digest on.
report() {
  local image="$1"
  local size sha configver
  size="$(wc -c < "$image" | tr -d ' ')"
  sha="$(shasum -a 256 "$image" | awk '{print $1}')"
  configver="$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')"
  cat <<EOF

  kernel version   : $KERNEL_VERSION
  Image path       : $image
  Image size       : $size bytes
  Image sha256     : $sha
  configver sha256 : $configver
  toolchain image  : $TOOLCHAIN_IMAGE ($TOOLCHAIN_TAG)
EOF
}

# regen_config regenerates the committed config from defconfig plus the required
# option set. It exists so the config's provenance is a runnable procedure
# rather than a story about one: build.sh's drift check is only meaningful if
# the file it checks can be re-derived.
regen_config() {
  note "regenerating kernel.config from linux-$KERNEL_VERSION defconfig"
  local work; work="$(scratch_dir)"

  toolchain_run "$work" <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
# shellcheck disable=SC2086  # BUILD_DEPS is a deliberate word-split list
apt-get -qq install -y --no-install-recommends $BUILD_DEPS >/dev/null

# WORKAROUND, not a preference: bsdtar, not GNU tar. /work is a vm-RuntimeClass
# emptyDir, a virtiofs share that refuses to create a file with mode 0000 even
# for root (the filed vm-share mode-0000 create refusal). GNU tar extracts
# every absolute or ".." symlink via exactly such a placeholder file, so it
# fails on this tree's 61 such links; bsdtar creates the symlinks directly.
bsdtar -xf "/src/$KERNEL_TARBALL" -C /work
cd "/work/linux-$KERNEL_VERSION"

make ARCH=arm64 defconfig >/dev/null
# MODULES goes off FIRST: olddefconfig turns every surviving `=m` into `=n`, so
# an option enabled before the loader is removed can be silently dropped.
for sym in $KCONFIG_DISABLE; do scripts/config --file .config --disable "$sym"; done
for sym in $KCONFIG_ENABLE;  do scripts/config --file .config --enable  "$sym"; done
make ARCH=arm64 olddefconfig >/dev/null

grep -qx '# CONFIG_MODULES is not set' .config \
  || { echo "FAIL: CONFIG_MODULES survived the disable" >&2; exit 1; }
for sym in $KCONFIG_REQUIRED; do
  grep -qx "CONFIG_$sym=y" .config \
    || { echo "FAIL: CONFIG_$sym could not be built in (unmet dependency?)" >&2; exit 1; }
done

# The second olddefconfig proves the file is a FIXED POINT: build.sh's drift
# check reruns olddefconfig over the committed file and fails on any diff, so a
# config that is not already stable would fail every build.
cp .config /work/kernel.config
make ARCH=arm64 olddefconfig >/dev/null
diff -u /work/kernel.config .config >/dev/null \
  || { echo "FAIL: the generated config is not a fixed point of olddefconfig" >&2; exit 1; }
echo "  generated a stable config: $(grep -c '=y$' .config) built-in symbols"
INNER

  cp "$work/kernel.config" "$CONFIG_FILE"
  rm -rf "$work"
  echo "  wrote $CONFIG_FILE (sha256 $(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}'))"
}

# repro builds twice into separate trees and compares the bytes. Anything less
# than byte equality means the digest this repo pins cannot be independently
# re-derived, which is the entire point of pinning it.
repro() {
  note "reproducibility — building twice into separate trees"
  rm -rf "$OUT_DIR/repro-a" "$OUT_DIR/repro-b"
  build_one "$OUT_DIR/repro-a"
  build_one "$OUT_DIR/repro-b"
  if cmp -s "$OUT_DIR/repro-a/Image" "$OUT_DIR/repro-b/Image"; then
    report "$OUT_DIR/repro-a/Image"
    echo
    echo "  reproducible: IDENTICAL"
    return 0
  fi
  report "$OUT_DIR/repro-a/Image"
  echo "  second build sha256: $(shasum -a 256 "$OUT_DIR/repro-b/Image" | awk '{print $1}')"
  die "reproducible: DIFFER — the two builds are not byte-identical"
}

main() {
  local mode="build"
  case "${1-}" in
    "")             mode="build" ;;
    --repro)        mode="repro" ;;
    --regen-config) mode="regen" ;;
    -h|--help)      usage; exit 0 ;;
    *)              usage >&2; die "unknown argument: $1" ;;
  esac

  if [ "$mode" = "regen" ]; then
    # The config file is regen's OUTPUT, so preflight's check for it would be a
    # chicken-and-egg refusal; everything else preflight asserts still applies.
    command -v kubectl >/dev/null || die "PREFLIGHT FAIL: kubectl not found"
    cluster_preflight
    open_namespace
    verify_provenance
    fetch_pinned
    verify_dev_signature
    regen_config
    return 0
  fi

  preflight
  open_namespace
  verify_provenance
  fetch_pinned
  verify_dev_signature

  if [ "$mode" = "repro" ]; then
    repro
    return 0
  fi

  note "building linux-$KERNEL_VERSION arm64 Image"
  rm -rf "${OUT_DIR:?}/Image"
  build_one "$OUT_DIR"
  report "$OUT_DIR/Image"
}

main "$@"
