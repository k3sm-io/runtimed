# runtimed — k3sm native macOS runtime

`k3sm.io/runtimed` is the native-Darwin container runtime for
[k3sm](https://github.com/k3sm-io/k3sm) — the rough analog of containerd. It turns a Kubernetes Pod
spec into isolated, resource-limited **native arm64 processes** (no Linux, **no chroot**):

- **pkg/sandbox** — default-deny Seatbelt/SBPL generator + a swappable, OS-version-gated `Backend`.
  The M1 backend is a NON-PLATFORM exec-shim (`cmd/k3sm-execshim` + `internal/execshim`): it applies
  the profile in-process via the private `libsandbox` SPI then `execve`s the pod **preserving the
  environment** — so `DYLD_INSERT_LIBRARIES` (darwin-net's DNS shim) survives, which Apple's
  `/usr/bin/sandbox-exec` would strip. A CI symbol-canary (`internal/spicanary`) guards the SPI.
- **pkg/supervisor** — `posix_spawn` (own session/process group) + `kqueue(EVFILT_PROC)` as the sole
  reaper, with a combined-log pipe and a consumer-side `PodNetwork` seam. (Userspace memory
  enforcement / QoS land in M2.)
- **pkg/image** — OCI-artifact pull → content-addressed cache → APFS `clonefile` materialization
  (`golang.org/x/sys/unix.Clonefile`) → ad-hoc `codesign -s - -f` on pull + a `SignaturePolicy` gate.
- **pkg/runtime** — the in-process `apis runtime/v1` `RuntimeServer` wiring the three above
  (`var _ runtimev1.RuntimeServer = (*Runtime)(nil)`); the M2 daemon split registers this same type
  with a gRPC server.

It exposes a gRPC runtime API defined in [`k3sm.io/apis`](https://github.com/k3sm-io/apis).
See [DESIGN.md §5a](https://github.com/k3sm-io/k3sm/blob/main/docs/DESIGN.md).

CGO is required (`CGO_ENABLED=1`). Integration tests are build-tagged: `go test -tags integration ./...`
(some need root; they `t.Skip` otherwise).
