# vm pod shares: who serves them, and the mode-0000 create limitation

How a `vm`-RuntimeClass pod's volumes reach the guest, which process serves
them, and one limitation of that server that a workload can hit: a file created
with mode 0000 on a writable share fails with `EPERM`, even for guest root. This
is the design note the share-construction code points back to
(`pkg/vmhost/vz_darwin.go`, the share loop in the VM configuration). The share
plan itself (which volumes become which share, and how they bind into each
container) lives in `pkg/mount/shareplan.go`.

## The pooled shares and their server

A `vm` pod's non-rootfs volumes are pooled into two virtiofs shares, one per
volume class, each holding one subdirectory per volume:

| Tag | Holds | Access |
|---|---|---|
| `k3sm.proj` | projected-class volumes: `configMap`, `secret`, `projected`, `downwardAPI` | read-only |
| `k3sm.vols` | default-medium `emptyDir` volumes | writable |

(`emptyDir` with `medium: Memory` is a guest tmpfs, not a share. Each PVC gets
its own `k3sm.pvc<i>` share, built by the same code path.)

**k3sm does not implement a virtiofs server.** `pkg/vmhost/vz_darwin.go`
builds each share with `vz.NewVirtioFileSystemDeviceConfiguration` and
`vz.NewSharedDirectory`, which hand the host directory to the Virtualization
framework's built-in virtiofs server. That server runs in-process inside
`k3sm-vmhost`, which is unprivileged. The only knob the binding exposes is
read-only; there is no uid/gid mapping and no mode policy to configure. The
read-only flag is applied at the device, where the guest cannot reach it. No
k3sm code runs in the path of a guest file create on a share.

## Limitation: a mode-0000 create on a writable share fails

A file created on `k3sm.vols` with a mode that grants nothing (for example
`umask 0777; touch f`, or any `open(path, O_CREAT, 0)`) fails with `EPERM`, and
it leaves a half-created entry behind.

Observed on a `vm` pod's `emptyDir` mounted at `/vol`, as guest root:

| Operation | On the share (`/vol`) | On the guest overlay root |
|---|---|---|
| `umask 0777; touch /vol/f0` | **fails, `EPERM`**; `ls -l` then shows `f0` as `----------?` (stat through the server fails) | succeeds |
| `rm -f` on that entry | succeeds (rc 0); the directory is empty and the name is immediately reusable | n/a |
| `chmod 0000` on an existing file | succeeds | succeeds |
| symlink / hardlink create, including `..` targets | succeeds | succeeds |

So the refusal is narrow: creating a file whose initial mode is 0000. Taking an
existing file to 0000 works, and links work.

### Mechanism (hypothesized, not confirmed)

The following explains the table, but it has not been confirmed against the
framework's internals. The host-side server, running as an unprivileged user,
creates the file and then re-opens it. With mode 0000 the reopen is denied even
to the file's owner. Guest root would bypass that check inside the guest, but
the check that fails is on the host, where the server is not root. The entry
exists on disk by then, which is why the create leaves it behind.

### Recovery

`rm -f <name>` removes the leftover entry and returns 0. The name can be reused
at once. Nothing else needs cleaning.

### Who hits it

- **GNU tar.** When GNU tar extracts a symlink whose target is absolute or
  contains `..`, it first writes a mode-0000 placeholder file and replaces it
  with the link at the end of extraction. On a share, every such placeholder
  fails, so `tar -x` of a tree that carries those links fails once per link.
  A Linux kernel source tarball, for example, fails 61 times.
  **bsdtar** creates symlinks directly and does not hit this.
  `hack/guest-kernel/build.sh` extracts with `bsdtar` for exactly this reason.
- **Any direct `open(O_CREAT)` with mode 0.**

### Writing onto a share from k3sm code

Create with owner bits that let the creator reopen the file, then set the
final mode with a separate `chmod`. `pkg/image/tarapply.go` already follows
this discipline, for its own reasons:

- `applyDir` creates the directory and then re-modes the leaf with an explicit
  `Chmod`, so the applied mode is the header's rather than the process umask's.
- `applyRegular` creates with `entryPerm`, which floors the owner bits at
  `0o600`. The true recorded mode is left to the in-guest ownership sidecar,
  which re-applies it inside the guest.

Workloads with the same need can use the same shape: create writable, then
`chmod`. Or put the data somewhere other than a share (the overlay root, or a
`medium: Memory` `emptyDir`).

### If a future macOS relaxes this

The refusal comes from the platform's server, so a macOS release may drop it.
The lab acceptance gate `hack/acceptance/B390.sh` reproduces the probe table
above on a scratch `vm` pod. If its "the create fails" leg goes red on a newer
macOS, the platform has improved. That is not a regression. This note, and the
bsdtar workaround, are what then need revisiting.
