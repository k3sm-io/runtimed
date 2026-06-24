# runtimed — k3sm native macOS runtime

`k3sm.io/runtimed` is the native-Darwin container runtime for
[k3sm](https://github.com/k3sm-io/k3sm) — the rough analog of containerd. It turns a Kubernetes Pod
spec into isolated, resource-limited **native arm64 processes** (no Linux, **no chroot**):

- **pkg/sandbox** — default-deny Seatbelt/SBPL profiles with swappable, OS-version-gated backends
  (`seatbelt-exec` → `seatbelt-inproc` via `libsandbox` → `uidjail` → `vm`), plus a CI symbol-canary
  for the private/deprecated `libsandbox` SPI.
- **supervisor** — `posix_spawn` + `kqueue` lifecycle; **userspace** memory enforcement
  (`proc_pid_rusage(ri_phys_footprint)` → SIGKILL → `OOMKilled`); QoS / rlimits for CPU.
- **image** — OCI-artifact pull → APFS `clonefile` pod roots → ad-hoc `codesign` on pull.

It exposes a gRPC runtime API defined in [`k3sm.io/apis`](https://github.com/k3sm-io/apis).
See [DESIGN.md §5a](https://github.com/k3sm-io/k3sm/blob/main/docs/DESIGN.md).
