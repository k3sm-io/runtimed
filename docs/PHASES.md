---
repo: runtimed
schema: phases/v1
current_phase: M1
updated: 2026-06-24
updated_by: agent

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
    status: done
    completed: 2026-06-24
    depends_on:
      - apis:M1.1
    subphases:
      - id: M1.1
        title: OCI pull → content-addressed cache → clonefile materialize → ad-hoc sign
        status: done
        deliverables:
          - id: M1.1-d1
            done: true
            desc: pkg/image — OCI artifact pull into a content-addressed cache under /var/lib/k3sm (pkg/image/pull.go + cache.go; go-containerregistry; FetchFunc seam)
          - id: M1.1-d2
            done: true
            desc: pkg/image — clonefile copy-on-write materialization into the pod rootfs dir (pkg/image/clone_darwin.go via golang.org/x/sys/unix.Clonefile behind the Cloner interface; EXDEV/ENOTSUP byte-copy fallback; quarantine-xattr assertion)
          - id: M1.1-d3
            done: true
            desc: pkg/image — ad-hoc codesign (codesign -s - -f, hardened-runtime/library-validation stripped) on pull + a signature-policy gate consuming runtimev1.SignaturePolicy (fail-closed on UNSPECIFIED) enforced before exec
        acceptance:
          - id: M1.1-a1
            met: true
            check: pulling a test OCI artifact populates the cache and a second pull is a cache hit
            method: integration
            test: pkg/image.TestPullCachesAndHits
          - id: M1.1-a2
            met: true
            check: materialization is an APFS clone (not a byte copy) and is idempotent
            method: integration
            test: pkg/image.TestIntegrationClonefileCoW + TestIntegrationMaterializeIdempotent
          - id: M1.1-a3
            met: true
            check: an unsigned arm64 binary execs under AMFI after ad-hoc sign; require-signed mode rejects it
            method: integration
            test: pkg/image.TestIntegrationAdHocSignAMFI
      - id: M1.2
        title: SBPL generation + in-process spawn under Seatbelt confinement
        status: done
        deliverables:
          - id: M1.2-d1
            done: true
            desc: pkg/sandbox — default-deny SBPL generator (pkg/sandbox/sbpl.go) that always (deny default)+(import "system.sb"), tightens the prototype (denies /private/var/db except dyld cache, denies the shared pods root, scopes file-write* to the pod data volume), and adds the CoreDNS-VIP network-outbound + mach-lookup
          - id: M1.2-d2
            done: true
            desc: pkg/sandbox — a swappable Backend interface (pkg/sandbox/backend.go) with the NON-PLATFORM exec-shim impl (cmd/k3sm-execshim + internal/execshim libsandbox cgo); OS-version-gated and fail-closed; the seam for the later in-proc backend
          - id: M1.2-d3
            done: true
            desc: pkg/supervisor — posix_spawn a pod process at host paths under the profile (POSIX_SPAWN_SETSID own process group), kqueue(EVFILT_PROC) as the sole reaper, combined-log pipe + status capture; consumer-side PodNetwork seam (node-IP no-op M1 impl)
        acceptance:
          - id: M1.2-a1
            met: true
            check: a process spawned under a generated profile reads /System but is denied /Users (golden-SBPL table test + a live confinement integration test)
            method: integration
            test: pkg/sandbox.TestGenerateDenySet (golden/deny-set) + TestIntegrationConfinement (live)
          - id: M1.2-a2
            met: true
            check: the generator always emits an import of system.sb and rejects a profile lacking it (golden file)
            method: unit
            test: pkg/sandbox.TestGenerateGolden + TestValidate
          - id: M1.2-a3
            met: true
            check: no sandbox-exec call leaks outside pkg/sandbox (one Go interface)
            method: build
            test: sandbox.Backend single interface; no /usr/bin/sandbox-exec call anywhere

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

## M1 — Native image runtime (library form) ✅

**Cross-repo deps:** `apis:M1.1` (runtime gRPC proto + image-manifest type + `PodBox` spec) must
exist before runtimed implements against it. (In M1 runtimed is still imported by `k3sm` as a
library; the gRPC *daemon split* is M2 — but it implements against the M1 proto so M2 is a
relocation, not a redesign.) The in-process `RuntimeServer` (`pkg/runtime`) implements the full
`apis runtime/v1` surface (`var _ runtimev1.RuntimeServer = (*Runtime)(nil)`), so M2 is a
relocation. Streaming RPCs `Exec`/`Attach`/`PortForward` are stubbed `Unimplemented` (M2).

### M1.1 — OCI pull → cache → clonefile + ad-hoc sign ✅
**Deliverables**
- ✅ `M1.1-d1` `pkg/image`: OCI artifact pull into a content-addressed cache under `/var/lib/k3sm`
  (`pull.go`+`cache.go`; go-containerregistry; a `FetchFunc` seam keeps pull testable offline).
- ✅ `M1.1-d2` `pkg/image`: `clonefile` CoW materialization into the pod rootfs dir
  (`clone_darwin.go` via `golang.org/x/sys/unix.Clonefile` behind the `Cloner` interface;
  EXDEV/ENOTSUP byte-copy fallback; post-materialize `com.apple.quarantine` assertion).
- ✅ `M1.1-d3` `pkg/image`: ad-hoc `codesign -s - -f` on pull (hardened-runtime + library-validation
  stripped so a later DYLD insert loads) + a signature-policy gate consuming
  `runtimev1.SignaturePolicy`, enforced before exec, fail-closed on `UNSPECIFIED`.

**Acceptance (exit gate)**
- ✅ `M1.1-a1` pull populates the cache; second pull is a cache hit — `pkg/image.TestPullCachesAndHits`
- ✅ `M1.1-a2` materialization is APFS-CoW and idempotent — `TestIntegrationClonefileCoW` + `TestIntegrationMaterializeIdempotent`
- ✅ `M1.1-a3` unsigned arm64 binary execs after ad-hoc sign; `require-signed` rejects it — `TestIntegrationAdHocSignAMFI`

### M1.2 — SBPL generation + confined spawn ✅
**Deliverables**
- ✅ `M1.2-d1` `pkg/sandbox`: default-deny SBPL generator (`sbpl.go`) — always `(deny default)` +
  `(import "system.sb")`, tightens the prototype (denies `/private/var/db` except the dyld cache,
  denies the shared pods root, scopes `file-write*` to the pod data volume) + CoreDNS-VIP egress.
- ✅ `M1.2-d2` `pkg/sandbox`: swappable `Backend` interface + the NON-PLATFORM exec-shim impl
  (`cmd/k3sm-execshim` + `internal/execshim` libsandbox cgo), OS-version-gated and fail-closed.
- ✅ `M1.2-d3` `pkg/supervisor`: `posix_spawn` (`POSIX_SPAWN_SETSID` own process group) under the
  profile, `kqueue(EVFILT_PROC)` as the sole reaper, combined-log pipe + status; `PodNetwork` seam.

**Acceptance (exit gate)**
- ✅ `M1.2-a1` spawned process reads `/System`, denied `/Users` — `TestGenerateDenySet` (golden) + `TestIntegrationConfinement` (live)
- ✅ `M1.2-a2` generated SBPL always imports `system.sb`; rejects a profile without it — `TestGenerateGolden` + `TestValidate`
- ✅ `M1.2-a3` no `sandbox-exec` call leaks outside `pkg/sandbox` — one `sandbox.Backend` interface; no `/usr/bin/sandbox-exec` call

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
M1 is complete (library form: `pkg/image`, `pkg/sandbox`, `pkg/supervisor`, `pkg/runtime`
implementing `apis runtime/v1` in-process; exec-shim Seatbelt confinement with `DYLD_INSERT_LIBRARIES`
preserved — the darwin-net DNS-shim enabler). M2 — split `k3sm-runtimed` into a root gRPC daemon
(register the existing `*runtime.Runtime` with a gRPC server — a relocation), add userspace
OOMKill + QoS + Summary API, and grow `internal/spicanary` to the `memorystatus` symbol.
