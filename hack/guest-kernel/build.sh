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
# The build runs entirely inside Docker: nothing but curl, shasum and (for the
# provenance check) gpg is asked of the host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
readonly HERE
readonly OUT_DIR="$HERE/out"
readonly CACHE_DIR="$HERE/.cache"
readonly CONFIG_FILE="$HERE/kernel.config"

# ---------------------------------------------------------------- the pins

readonly KERNEL_VERSION="6.18.48"
readonly KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
readonly KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TARBALL}"
readonly KERNEL_SUMS_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc"

# FIRST MINT: 2026-08-31, PGP-VERIFIED. sha256sums.asc was fetched and verified
# against the key below (GOODSIG + VALIDSIG B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1,
# signature made 2026-08-28), and this value is the linux-6.18.48.tar.xz line of
# the VERIFIED cleartext. It was NOT taken from an unverified sums file.
readonly KERNEL_SHA256="5ebdadb10a4b5708fc6b1c457764a110bc49f8150cc3502c59b921ead8c6fc8c"

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

readonly BUILD_DEPS="gcc make perl python3 flex bison bc libssl-dev libelf-dev xz-utils cpio"

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

# scratch_dir makes a work directory UNDER the repo rather than in $TMPDIR.
# Docker Desktop shares an explicit list of host paths, and macOS's per-user
# /var/folders TMPDIR is not on the default list: a bind mount of a mktemp -d
# silently presents as an EMPTY directory in the container, which reads as a
# missing file rather than as a sharing problem. A path under the checkout is
# reachable because the checkout is what the operator is working in.
scratch_dir() {
  mkdir -p "$CACHE_DIR"
  mktemp -d "$CACHE_DIR/work.XXXXXXXX"
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
  command -v docker >/dev/null || { echo "PREFLIGHT FAIL: docker not found (install Docker Desktop)"; missing=1; }
  command -v curl   >/dev/null || { echo "PREFLIGHT FAIL: curl not found"; missing=1; }
  command -v shasum >/dev/null || { echo "PREFLIGHT FAIL: shasum not found"; missing=1; }
  [ "$missing" -eq 0 ] || exit 1
  docker info >/dev/null 2>&1 \
    || die "PREFLIGHT FAIL: the Docker daemon is not answering (start Docker Desktop and retry)"
  [ -f "$CONFIG_FILE" ] || die "PREFLIGHT FAIL: $CONFIG_FILE is missing (run --regen-config)"
  echo "preflight ok: docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), toolchain $TOOLCHAIN_IMAGE"
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
    echo "  (install one with 'brew install gnupg' to verify without Docker)"
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

  docker run --rm -i --platform linux/arm64 \
    -v "$work:/work" -w /work \
    -e KERNEL_KEY_FPR="$KERNEL_KEY_FPR" \
    -e KEYSERVERS="$KEYSERVERS" \
    -e KERNEL_TARBALL="$KERNEL_TARBALL" \
    "$TOOLCHAIN_IMAGE" bash -s >/dev/null <<'INNER'
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

  docker run --rm -i --platform linux/arm64 \
    -v "$work:/work" -w /work \
    -e KERNEL_DEV_KEY_FPR="$KERNEL_DEV_KEY_FPR" \
    -e KEYSERVERS="$KEYSERVERS" \
    -e KERNEL_TARBALL="$KERNEL_TARBALL" \
    "$TOOLCHAIN_IMAGE" bash -s >/dev/null <<'INNER'
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

# toolchain_run pipes a script into the pinned image with the kernel source and
# a work directory bind-mounted at /work.
toolchain_run() {
  local work="$1"
  docker run --rm -i --platform linux/arm64 \
    -v "$work:/work" -v "$CACHE_DIR:/src:ro" -w /work \
    -e KERNEL_VERSION="$KERNEL_VERSION" \
    -e KERNEL_TARBALL="$KERNEL_TARBALL" \
    -e BUILD_DEPS="$BUILD_DEPS" \
    -e KCONFIG_ENABLE="$KCONFIG_ENABLE" \
    -e KCONFIG_DISABLE="$KCONFIG_DISABLE" \
    -e KCONFIG_REQUIRED="$KCONFIG_REQUIRED" \
    -e KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" \
    -e KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
    -e KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
    "$TOOLCHAIN_IMAGE" bash -s
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

tar -xf "/src/$KERNEL_TARBALL" -C /work
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

tar -xf "/src/$KERNEL_TARBALL" -C /work
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
    command -v docker >/dev/null || die "PREFLIGHT FAIL: docker not found"
    docker info >/dev/null 2>&1 || die "PREFLIGHT FAIL: the Docker daemon is not answering"
    verify_provenance
    fetch_pinned
    verify_dev_signature
    regen_config
    return 0
  fi

  preflight
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
