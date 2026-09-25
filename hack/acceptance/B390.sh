#!/usr/bin/env bash
#
# runtimed B390 acceptance gate (LAB tier) — a vm pod's writable emptyDir share
# refuses a mode-0000 file create, leaves a removable entry behind, and differs
# from the guest overlay root in exactly that one operation.
#
# The share is served by the Virtualization framework's own in-process virtiofs
# server (pkg/vmhost/vz_darwin.go); k3sm has no code in the create path, so the
# resolution is a documented limitation (docs/vm-shares.md), and this gate pins
# the documented behaviour on a live pod:
#
#   (a) CREATE REFUSED — `umask 0777; touch /vol/f0` on the emptyDir share
#       fails, AND leaves an f0 entry in the directory listing.
#   (b) RECOVERY — `rm -f /vol/f0` returns 0, the entry is gone, and the name
#       is immediately reusable (a normal-umask create of f0 then succeeds).
#   (c) CONTRAST — the same umask-0777 create succeeds on the guest overlay
#       root. This is what makes (a) non-vacuous: the same command, same pod,
#       same uid, and only the filesystem differs.
#   (d) NARROWNESS — `chmod 0000` on an EXISTING share file succeeds, so the
#       refusal is the create, not the mode.
#
# GREEN = all four hold: the limitation is present and still exactly as the
# note describes it. RED = any leg differs from the note.
#
# A RED (a) MAY START HAPPENING ON A FUTURE macOS. The refusal belongs to the
# platform's server, and a release that drops it turns (a) red. That is NOT a
# regression in k3sm: it is a platform improvement, and it is the doc
# (docs/vm-shares.md) and the bsdtar workaround in hack/guest-kernel/build.sh
# that then need updating, not this gate's expectation flipped blindly.
#
# LAB PREREQUISITES: kubectl on PATH; a reachable k3sm kube context (default
# "k3sm", override with KUBE_CONTEXT); the cluster serves the "vm"
# RuntimeClass; a Ready darwin node. The gate dies with the remedy if any is
# missing. It creates one pod in NAMESPACE (default "default") and always
# deletes it on exit.
#
# The vm path serves no logs after the pod terminates, so the pod's command
# ends in a long sleep and the gate reads the probe output while it is alive.
#
# Usage:  hack/acceptance/B390.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B390.sh"
DOC="$REPO_ROOT/docs/vm-shares.md"
VZ="$REPO_ROOT/pkg/vmhost/vz_darwin.go"

KUBE_CONTEXT="${KUBE_CONTEXT:-k3sm}"
NAMESPACE="${NAMESPACE:-default}"
POD="vmshare-mode0-probe-$$"
# The same digest hack/guest-kernel/build.sh pins for its toolchain pods.
IMAGE="docker.io/library/debian@sha256:7215f78f35ffe58fe13f244fac9c4f21326d55187271fbb3e1a8aa5cc7e387ab"
READY_TIMEOUT="${READY_TIMEOUT:-600s}"
PROBE_TIMEOUT_S="${PROBE_TIMEOUT_S:-120}"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
die() { echo "B390: $*" >&2; exit 1; }
kube() { kubectl --context "$KUBE_CONTEXT" "$@"; }

echo "==> runtimed B390 acceptance (vm share mode-0000 create limitation)"

# ---- s.0 — the gate parses and the note it enforces exists ------------------
s0=ok
bash -n "$SELF" || s0=no
[ -f "$DOC" ] || s0=no
grep -q 'docs/vm-shares.md' "$VZ" || s0=no
ladder "$s0" "s.0  gate parses; docs/vm-shares.md exists; vz_darwin.go points at it"
[ "$s0" = ok ] || die "static preconditions failed; not booting a pod"

# ---- preflight: every lab fact, each with its remedy ------------------------
remedy="(this is a LAB gate: install a local cluster with 'sudo k3sm install', or set KUBE_CONTEXT)"
command -v kubectl >/dev/null 2>&1 || die "PREFLIGHT FAIL: kubectl not found on PATH $remedy"
kube get --raw /readyz >/dev/null 2>&1 \
  || die "PREFLIGHT FAIL: kube context '$KUBE_CONTEXT' is not reachable $remedy"
kube get runtimeclass vm >/dev/null 2>&1 \
  || die "PREFLIGHT FAIL: context '$KUBE_CONTEXT' serves no 'vm' RuntimeClass $remedy"
ready="$(kube get nodes -l kubernetes.io/os=darwin \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>/dev/null \
  | awk '$2 == "True" { print $1; exit }')"
[ -n "$ready" ] || die "PREFLIGHT FAIL: context '$KUBE_CONTEXT' has no Ready darwin node $remedy"
echo "  preflight ok: context $KUBE_CONTEXT, node $ready, namespace $NAMESPACE"

cleanup() {
  kube -n "$NAMESPACE" delete pod "$POD" --ignore-not-found --now --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- the in-guest probe -----------------------------------------------------
# Every result is a KEY=VALUE line; EVIDENCE lines are printed for the reader
# and never parsed. PROBE-DONE marks the end, then the pod sleeps so its log
# stays readable.
read -r -d '' PROBE <<'EOF' || true
set +e
mkdir -p /overlay-probe
( umask 0777; touch /vol/f0 ) 2>/dev/null; echo "SHARE_CREATE_RC=$?"
if ls -A /vol | grep -qx f0; then echo "SHARE_ENTRY_LEFT=1"; else echo "SHARE_ENTRY_LEFT=0"; fi
ls -la /vol 2>&1 | sed 's/^/EVIDENCE share after create: /'
rm -f /vol/f0; echo "SHARE_RM_RC=$?"
if ls -A /vol | grep -qx f0; then echo "SHARE_ENTRY_AFTER_RM=1"; else echo "SHARE_ENTRY_AFTER_RM=0"; fi
touch /vol/f0; echo "SHARE_REUSE_RC=$?"
rm -f /vol/f0
( umask 0777; touch /overlay-probe/f0 ) 2>/dev/null; echo "ROOT_CREATE_RC=$?"
echo x > /vol/g0; echo "SHARE_SEED_RC=$?"
chmod 0000 /vol/g0; echo "SHARE_CHMOD_RC=$?"
rm -f /vol/g0
echo "PROBE_UID=$(id -u)"
echo PROBE-DONE
exec sleep 3600
EOF
probe_yaml="$(printf '%s\n' "$PROBE" | sed 's/^/          /')"

kube -n "$NAMESPACE" create -f - >/dev/null <<EOF || die "could not create pod $NAMESPACE/$POD"
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  labels:
    app.kubernetes.io/name: k3sm-vmshare-mode0-probe
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
    - name: probe
      image: $IMAGE
      command: ["sh", "-c"]
      args:
        - |
$probe_yaml
      volumeMounts:
        - {name: vol, mountPath: /vol}
  volumes:
    - {name: vol, emptyDir: {}}
EOF
echo "  pod $NAMESPACE/$POD created (vm, emptyDir at /vol)"

if ! kube -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD" --timeout="$READY_TIMEOUT" >/dev/null 2>&1; then
  kube -n "$NAMESPACE" get pod "$POD" -o wide >&2 || true
  kube -n "$NAMESPACE" get events --field-selector "involvedObject.name=$POD" >&2 || true
  die "pod $POD did not become Ready within $READY_TIMEOUT"
fi

out=""
deadline=$((SECONDS + PROBE_TIMEOUT_S))
while [ "$SECONDS" -lt "$deadline" ]; do
  out="$(kube -n "$NAMESPACE" logs "$POD" -c probe 2>/dev/null || true)"
  printf '%s\n' "$out" | grep -qx 'PROBE-DONE' && break
  sleep 2
done
printf '%s\n' "$out" | grep -qx 'PROBE-DONE' \
  || { printf '%s\n' "$out" >&2; die "probe did not finish within ${PROBE_TIMEOUT_S}s (no PROBE-DONE in the pod log)"; }

printf '%s\n' "$out" | grep '^EVIDENCE ' | sed 's/^EVIDENCE /  /' || true
val() { printf '%s\n' "$out" | sed -n "s/^$1=//p" | head -1; }

create_rc="$(val SHARE_CREATE_RC)"; left="$(val SHARE_ENTRY_LEFT)"
rm_rc="$(val SHARE_RM_RC)"; after_rm="$(val SHARE_ENTRY_AFTER_RM)"; reuse_rc="$(val SHARE_REUSE_RC)"
root_rc="$(val ROOT_CREATE_RC)"
seed_rc="$(val SHARE_SEED_RC)"; chmod_rc="$(val SHARE_CHMOD_RC)"
uid="$(val PROBE_UID)"

# The contrast is only meaningful as root: a non-root guest uid could be refused
# on the share for ordinary permission reasons.
if [ "$uid" = 0 ]; then p0=ok; else p0=no; fi
ladder "$p0" "p.0  probe ran as guest root (uid ${uid:-?})"

a=ok
[ -n "$create_rc" ] && [ "$create_rc" != 0 ] || a=no
[ "$left" = 1 ] || a=no
ladder "$a" "(a)  umask-0777 create on the share fails (rc ${create_rc:-?}) AND leaves an entry (left=${left:-?})"
if [ "$a" != ok ] && [ "$create_rc" = 0 ]; then
  echo "      NOTE: the share accepted a mode-0000 create. On a newer macOS this is a platform" >&2
  echo "      improvement, not a regression: update docs/vm-shares.md and revisit the bsdtar" >&2
  echo "      workaround in hack/guest-kernel/build.sh." >&2
fi

b=ok
[ "$rm_rc" = 0 ] || b=no
[ "$after_rm" = 0 ] || b=no
[ "$reuse_rc" = 0 ] || b=no
ladder "$b" "(b)  rm -f clears it (rc ${rm_rc:-?}, left=${after_rm:-?}) and the name is reusable (rc ${reuse_rc:-?})"

c=ok
[ "$root_rc" = 0 ] || c=no
ladder "$c" "(c)  the same umask-0777 create succeeds on the overlay root (rc ${root_rc:-?})"

d=ok
[ "$seed_rc" = 0 ] || d=no
[ "$chmod_rc" = 0 ] || d=no
ladder "$d" "(d)  chmod 0000 on an existing share file succeeds (seed rc ${seed_rc:-?}, chmod rc ${chmod_rc:-?})"

echo "----------------------------------------"
echo "B390: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
