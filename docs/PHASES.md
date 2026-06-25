---
repo: runtimed
schema: phases/v1
current_phase: M1
updated: 2026-06-24
updated_by: human

phases:
  - id: M0
    title: Walking skeleton — validated Seatbelt host-path prototype
    status: done
    completed: 2026-06-24
    depends_on: []
    subphases:
      - id: M0.1
        title: Default-deny Seatbelt at host paths, no chroot
        status: done
        deliverables:
          - id: M0.1-d1
            done: true
            desc: prototypes/seatbelt-hostpath — default-deny SBPL profile running a Foundation-linked arm64 binary at its real host path
        acceptance:
          - id: M0.1-a1
            met: true
            check: the confined process sees /System and links the dyld cache, is denied /Users, and can write only its pod dir
            method: manual

  - id: M1
    title: Native image runtime (library form) — OCI pull, clonefile, ad-hoc sign, Seatbelt confine
    status: todo
    depends_on:
      - apis:M1.1
    subphases:
      - id: M1.1
        title: OCI pull → content-addressed cache → clonefile materialize → ad-hoc sign
        status: todo
        deliverables:
          - id: M1.1-d1
            done: false
            desc: pkg/image — OCI artifact pull into a content-addressed cache under /var/lib/k3sm
          - id: M1.1-d2
            done: false
            desc: pkg/image — clonefile(2) copy-on-write materialization into the pod rootfs dir (cgo *_darwin.go behind a Go interface)
          - id: M1.1-d3
            done: false
            desc: pkg/image — ad-hoc codesign (codesign -s - -f) on pull + a signature-policy gate (adhoc-ok | require-signed | require-notarized)
        acceptance:
          - id: M1.1-a1
            met: false
            check: pulling a test OCI artifact populates the cache and a second pull is a cache hit
            method: integration
          - id: M1.1-a2
            met: false
            check: materialization is an APFS clone (not a byte copy) and is idempotent
            method: integration
          - id: M1.1-a3
            met: false
            check: an unsigned arm64 binary execs under AMFI after ad-hoc sign; require-signed mode rejects it
            method: integration
      - id: M1.2
        title: SBPL generation + in-process spawn under Seatbelt confinement
        status: todo
        deliverables:
          - id: M1.2-d1
            done: false
            desc: pkg/sandbox — default-deny SBPL generator that always imports system.sb (allow read /System, /usr/lib, dyld cryptex, pod dir; write only pod data vol; deny /Users)
          - id: M1.2-d2
            done: false
            desc: pkg/sandbox — a swappable Backend interface with a seatbelt-exec implementation (OS-version-gated; the seam for the later libsandbox in-proc backend)
          - id: M1.2-d3
            done: false
            desc: pkg/supervisor — posix_spawn a pod process at host paths under the generated profile, in its own process group, with combined-log + status capture
        acceptance:
          - id: M1.2-a1
            met: false
            check: a process spawned under a generated profile reads /System but is denied /Users (golden-SBPL table test + a live confinement integration test)
            method: integration
          - id: M1.2-a2
            met: false
            check: the generator always emits an import of system.sb and rejects a profile lacking it (golden file)
            method: unit
          - id: M1.2-a3
            met: false
            check: no sandbox-exec call leaks outside pkg/sandbox (one Go interface)
            method: build

  - id: M2
    title: Daemon split (root gRPC) + userspace OOMKill + QoS + Summary API + symbol-canary
    status: todo
    depends_on:
      - apis:M2.1
    subphases: []

  - id: M3
    title: (no runtimed-specific work)
    status: todo
    depends_on: []
    subphases: []

  - id: M4
    title: uidjail fallback backend + packaging hooks + cgo macOS CI
    status: todo
    depends_on: []
    subphases: []
---

# runtimed — Phase roadmap

> Per-repo slice of the k3sm milestones (workspace matrix: `../../ROADMAP.md`; product design:
> `../../k3sm/docs/DESIGN.md` §5a). The YAML frontmatter above is **authoritative**; this prose
> mirrors it. Status: ✅ done · 🟡 in-progress · ⛔ blocked · ⬜ todo.

`runtimed` is **Wave 2** (with `darwin-net`): it imports `apis` and is imported by `k3sm`.

## M0 — Walking skeleton ✅
runtimed's M0 contribution is the **validated Seatbelt host-path prototype**
(`prototypes/seatbelt-hostpath/`): a Foundation-linked arm64 binary runs at its real host path under
a default-deny SBPL profile — sees `/System`, links the dyld cache, is denied `/Users`, writes only
its pod dir. This is the load-bearing proof for the no-chroot runtime model (DESIGN §3, §5a). No
`pkg/` code yet — M0 execution used the provider's in-process HostProcess runtime in the `k3sm` repo.

## M1 — Native image runtime (library form) ⬜

**Cross-repo deps:** `apis:M1.1` (runtime gRPC proto + image-manifest type + `PodBox` spec) must
exist before runtimed implements against it. (In M1 runtimed is still imported by `k3sm` as a
library; the gRPC *daemon split* is M2 — but it implements against the M1 proto so M2 is a
relocation, not a redesign.)

### M1.1 — OCI pull → cache → clonefile + ad-hoc sign ⬜
**Deliverables**
- ⬜ `M1.1-d1` `pkg/image`: OCI artifact pull into a content-addressed cache under `/var/lib/k3sm`.
- ⬜ `M1.1-d2` `pkg/image`: `clonefile(2)` CoW materialization into the pod rootfs dir (cgo `*_darwin.go` behind a Go interface).
- ⬜ `M1.1-d3` `pkg/image`: ad-hoc `codesign -s - -f` on pull + signature-policy gate.

**Acceptance (exit gate)**
- ⬜ `M1.1-a1` pull populates the cache; second pull is a cache hit — *method: integration*
- ⬜ `M1.1-a2` materialization is APFS-CoW and idempotent — *method: integration*
- ⬜ `M1.1-a3` unsigned arm64 binary execs after ad-hoc sign; `require-signed` rejects it — *method: integration*

### M1.2 — SBPL generation + confined spawn ⬜
**Deliverables**
- ⬜ `M1.2-d1` `pkg/sandbox`: default-deny SBPL generator (always `(import "system.sb")`).
- ⬜ `M1.2-d2` `pkg/sandbox`: swappable `Backend` interface + `seatbelt-exec` impl (OS-version-gated).
- ⬜ `M1.2-d3` `pkg/supervisor`: `posix_spawn` at host paths under the profile, own process group, log/status capture.

**Acceptance (exit gate)**
- ⬜ `M1.2-a1` spawned process reads `/System`, denied `/Users` (golden SBPL + live confinement test) — *method: integration*
- ⬜ `M1.2-a2` generated SBPL always imports `system.sb`; generator rejects a profile without it — *method: unit*
- ⬜ `M1.2-a3` no `sandbox-exec` call leaks outside `pkg/sandbox` — *method: build*

## M2 — Daemon split + resources + canary ⬜
Decomposed when M1 closes. Headline: split `k3sm-runtimed` (root, gRPC per `apis:M2.1`); userspace
memory kill (`proc_pid_rusage(ri_phys_footprint)` ~1 Hz → SIGKILL → `OOMKilled`); QoS via
`taskpolicy`; Summary API via `proc_pid_rusage` → `kubectl top`; CI **symbol-canary** re-verifying
`libsandbox` / `memorystatus` / `clonefile` exports (scaffold lives at `internal/spicanary/`).

## M3 — (no runtimed-specific work) ⬜
Multi-node join + mesh is `k3sm` (join/token) + `darwin-net` (wireguard). runtimed's only multi-node
touch — binding pod processes to their lo0 IP — lands in M2 via `darwin-net`'s `PodNetwork` seam.

## M4 — Hardening + packaging hooks ⬜
Headline: `uidjail` fallback `Backend` impl; participate in the codesign/notarize entitlement set;
macOS-arm64 CI for the cgo build; node-conformance-subset hooks.

## Next
M1.1 — start with `pkg/image` OCI pull + the `clonefile` cgo shim, against the `apis:M1.1` types.
