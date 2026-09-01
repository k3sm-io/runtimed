# runtimed

`runtimed` is the native container runtime for [k3sm](https://github.com/k3sm-io/k3sm), a
Kubernetes distribution for Apple Silicon Macs. It plays the role that containerd plays in a
Linux distribution: it is the component that actually turns a Pod spec into running processes.
Where it differs from containerd is the target. macOS has no container primitives — no
namespaces, no cgroups, no OverlayFS — so `runtimed` runs each Pod as a **native Darwin
process** at its real host paths, confined by a generated Seatbelt (sandbox) profile instead of
a Linux-style mount namespace. It pulls OCI images, unpacks them with APFS `clonefile`
copy-on-write, ad-hoc signs the resulting binaries so they pass Apple's code-signing checks, and
supervises each Pod's processes with `posix_spawn` and `kqueue`. For Pods that need an actual
Linux environment, `runtimed` also hosts a per-Pod Linux micro-VM on top of the Virtualization
framework; that path is experimental and is described below.

## Where this repo sits

k3sm is split across four repositories, built in this order:

```
apis  →  runtimed, darwin-net  →  k3sm
```

[`apis`](https://github.com/k3sm-io/apis) holds the shared gRPC and CRD contracts that every
other repository imports and depends on nothing else. `runtimed` and
[`darwin-net`](https://github.com/k3sm-io/darwin-net) build on `apis` independently of each
other — `runtimed` owns process execution and sandboxing, `darwin-net` owns Pod networking and
DNS. [`k3sm`](https://github.com/k3sm-io/k3sm) is the distribution itself: it assembles a
Virtual Kubelet node, a control plane, and a CLI around `runtimed` and `darwin-net`, and ships as
one signed binary. `runtimed` is dialed by that binary over a gRPC contract defined in `apis`; it
never talks to the control plane directly.

## Repository layout

### `pkg/`

- **`image`** — pulls OCI image artifacts into a content-addressed cache and materializes them
  into a Pod's root filesystem as native files at host paths. Handles multi-platform manifest
  selection, APFS `clonefile` copy-on-write materialization with a byte-copy fallback, and
  ad-hoc code signing gated by a signature policy.
- **`mount`** — materializes a Pod's volume sources (ConfigMap, Secret, emptyDir, downward API,
  projected volumes, and `subPath` selection) into the Pod's on-disk directory. Because there is
  no mount namespace, a "mount" here is real files written under the Pod's writable data volume.
- **`runtime`** — the in-process runtime server that implements the `apis` runtime gRPC contract.
  It wires together `image`, `sandbox`, and `supervisor` behind the Pod-level API a caller
  actually talks to.
- **`sandbox`** — generates default-deny Seatbelt profiles from a Pod's declared security
  requirements and applies them through a swappable backend interface. Also owns the Linux
  micro-VM backend: composing a guest machine description, driving `k3sm-vmhost`, and bridging
  exec/log/stats calls to the in-guest agent.
- **`supervisor`** — spawns and reaps native Pod processes. Each Pod is a process group:
  containers are `posix_spawn`ed into their own session, logs are captured over a combined
  stdout/stderr pipe, and `kqueue(EVFILT_PROC)` is the single reaper so process exit status is
  never read twice.
- **`volume`** — materializes APFS-backed persistent volumes for a Pod. Unlike `mount`, a
  persistent volume lives at a stable path outside the Pod's own directory tree and survives Pod
  restarts and deletion.
- **`vmhost`** — the library used by the `k3sm-vmhost` helper process: turns a machine
  description into a running Virtualization-framework guest, proxies one control socket to it,
  and stops it. It makes no policy decisions of its own; every choice arrives already made in the
  machine description it is handed.
- **`guestagent`** — the in-guest half of the micro-VM boundary: a small gRPC-like service,
  reachable only over a virtio-vsock socket, that answers health, exec, log, and stats requests
  for the one Pod its guest booted.
- **`guestinit`** — pure, unit-tested logic that turns a guest specification into the ordered
  steps a Linux guest's PID 1 must execute (mounts, hostname, container start order, the
  reap-and-stop state machine). It performs no syscalls itself; a small Linux-only executor
  applies the steps it produces.

### `cmd/`

- **`k3sm-runtimed`** — the root daemon. It hosts the runtime server behind a gRPC endpoint on a
  Unix domain socket that the k3sm node provider dials.
- **`k3sm-execshim`** — a small, ad-hoc-signed helper that the supervisor `posix_spawn`s in place
  of a container's own binary. It drops privileges to the container's declared identity, applies
  the generated Seatbelt profile to itself, and then `execve`s the real container binary.
- **`k3sm-vmhost`** — the one k3sm binary that carries the Virtualization entitlement. It builds
  and runs a single Pod's Linux micro-VM and is spawned by the daemon as a separate,
  narrowly-scoped process rather than linked into it.
- **`k3sm-guest-init`** — PID 1 inside the micro-VM guest, built for Linux. It is a thin executor
  over the plans `pkg/guestinit` produces; almost none of its own logic is guest-boot policy.

## Isolation model

A Pod under the native process path runs as a real Darwin process at its real filesystem paths —
there is no chroot and no mount namespace, both of which macOS's integrity protections make
impractical to use here. Confinement instead comes from a per-Pod Seatbelt profile: a
default-deny sandbox policy that denies filesystem and network access outside what the Pod
declares. This gives strong filesystem and network confinement, but it does not isolate at the
kernel level the way Linux containers do: **there is no per-Pod uid isolation**, and processes
running under different Pods' profiles still share the same kernel. Workloads that need stronger
isolation, or that need an actual Linux environment, run instead in the per-Pod Linux micro-VM
backend described above. That backend is **experimental**: it is functional, but it has not yet
had the same production hardening as the native process path.

## Building and testing

CGO is required. `runtimed` isolates its use of private and deprecated Darwin interfaces —
`libsandbox` for Seatbelt, `memorystatus` for memory pressure, `clonefile` for copy-on-write —
behind `*_darwin.go` files and plain Go interfaces, and a symbol canary test
(`internal/spicanary`) fails the build loudly if one of those symbols stops resolving on a given
macOS release. The repository targets darwin/arm64 on macOS 26 and later, and Go 1.25.

```sh
gofmt -l .                  # must print nothing
go vet ./...
CGO_ENABLED=1 go build ./...
CGO_ENABLED=1 go test ./...
go mod tidy
hack/verify-boilerplate.sh  # every .go file carries the license header
```

`hack/ci.sh` runs the full commit gate above in one command, and additionally cross-builds
`k3sm-guest-init` for `linux/arm64` and `linux/amd64` (that binary never builds as part of the
main darwin build, since it ships inside a guest's own initramfs). Some tests require hardware
this environment may not have — a Rosetta-capable Mac, an entitled build for the Virtualization
framework, a discrete GPU — and use `t.Skip` to fail open when that hardware or entitlement is
absent rather than failing the whole suite.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow and commit conventions,
[LICENSE](LICENSE) for licensing terms (Apache License 2.0), and [DCO](DCO) for the Developer
Certificate of Origin every commit must be signed off against. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[GOVERNANCE.md](GOVERNANCE.md), [MAINTAINERS.md](MAINTAINERS.md), and [SECURITY.md](SECURITY.md)
round out the project's governance documents.
