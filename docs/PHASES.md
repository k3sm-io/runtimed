---
repo: runtimed
schema: phases/v1
current_phase: M2
updated: 2026-06-25
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
    title: Daemon split (root gRPC) + mounts + privilege drop + grace + OOMKill/QoS/Summary + canary
    status: done
    completed: 2026-06-25
    depends_on:
      - apis:M2.1
    subphases:
      - id: M2.1
        title: Split k3sm-runtimed into a root gRPC daemon + grow the SPI symbol-canary
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M2.1-d1
            done: true
            desc: cmd/k3sm-runtimed + pkg/runtime/grpcserver.go — register the existing *runtime.Runtime with a gRPC server (runtime.NewServer) over the root unix socket (runtime.Listen, 0600 in a 0700 dir) per apis:M2.1; a relocation, not a redesign (var _ runtimev1.RuntimeServer already satisfied). The api_version negotiation surface is STRUCK — provider and its node's runtimed are the SAME k3sm build restarted together (same-binary, same-node hard cut), so there is no skew window; GetRuntimeInfo reports identity/health for diagnostics only. Lifecycle is ctx-driven (Serve → GracefulStop on ctx-cancel, no goroutine/fd leak; sender closes the stop channel). The in-process path (k3sm imports pkg/runtime as a library) is unchanged.
          - id: M2.1-d2
            done: true
            desc: internal/spicanary — grew the CI symbol-canary from libsandbox/clonefile to also re-verify the memorystatus_control (private jetsam SPI) / proc_pid_rusage (public <libproc.h>, load-bearing for the M2.5 sampler) export set; both resolve from libSystem. VZ is a PUBLIC framework and is explicitly NOT a canary case.
        acceptance:
          - id: M2.1-a1
            met: true
            check: the root daemon serves the full runtime/v1 surface over the unix socket (Listen → register → Serve → client roundtrip; CreatePod/GetPodStatus/GetLogs/GetRuntimeInfo) with clean ctx-driven start/stop. No api_version negotiation (handshake struck — same-binary same-node). Real-root gRPC over the production socket is the m2.sh e2e on a capable host; the unit seam uses a non-root unix socket + bufconn.
            method: unit
            test: pkg/runtime.TestServerServesRuntimeSurfaceOverUnixSocket + TestServerServesOverBufconn + TestServerStopUnblocksServe + TestListenRemovesStaleSocket
          - id: M2.1-a2
            met: true
            check: the symbol-canary fails the BUILD (hard link error) if libsandbox / memorystatus_control / proc_pid_rusage exports the runtime depends on disappear; clonefile is covered via golang.org/x/sys/unix.Clonefile
            method: build
            test: spicanary.TestSymbolsResolve + TestResourceSymbolsResolve
      - id: M2.2
        title: Volume-mount materialization into the pod dir + validated SBPL extra-path injection
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.1
        deliverables:
          - id: M2.2-d1
            done: true
            desc: pkg/mount — Materialize renders configMap / secret / emptyDir / downwardAPI / projected-serviceAccountToken sources into the pod dir via a consumer-side Resolver seam (the proto carries only the source reference, not the data; provider supplies the apiserver-backed Resolver, tests a fake). k3sm has no mount namespace, so every mount path is REBASED under the pod data volume (filepath.Join), guaranteeing materialized volumes live inside it; a "../" escape is rejected. Wired into pkg/runtime.createPod
          - id: M2.2-d2
            done: true
            desc: pkg/sandbox — Generate VALIDATES every caller-supplied extra read/write path (and the credential paths) against a protected deny-set (/Users, /private/var/db, the pods-root, the dyld cryptex), rejecting with ErrProtectedPath (the pod's own data volume is carved out); the protected (deny ...) blocks are emitted AFTER the extra-path allows and the pod's own data-volume re-allow is emitted after the pods-root deny (SBPL last-match-wins). hostPath roots outside the data volume are the provider's SandboxProfile.extra_*_paths, validated here
          - id: M2.2-d3
            done: true
            desc: pkg/sandbox — secrets + the projected SA-token get a read-only sub-scope (granted file-read*, explicitly denied file-write*) emitted LAST so the write-deny wins even inside the writable data volume; pkg/mount marks them as credentials, pkg/runtime passes them as GenerateOptions.ReadOnlyPaths
        acceptance:
          - id: M2.2-a1
            met: true
            check: each source (configMap / secret / emptyDir / downwardAPI / projected-SA-token) materializes at its mount path inside the pod data volume with the resolved content (materialization is unit-testable per-task; the live read-by-pod is the m2.sh e2e under root)
            method: unit
            test: pkg/mount.TestMaterializeAllSources + pkg/mount.TestMaterializeSelectedKeysAndMode + pkg/runtime.TestCreatePodMaterializesVolumesAndDrops
          - id: M2.2-a2
            met: true
            check: an extra write/read path inside the protected deny-set is rejected; an allowed extra path does NOT override the protected denies, and the pod's own data-volume re-allow follows the pods-root deny (SBPL last-match-wins ordering)
            method: unit
            test: pkg/sandbox.TestGenerateRejectsProtectedExtraPath + pkg/sandbox.TestGenerateProtectedDeniesAfterExtraAllows
          - id: M2.2-a3
            met: true
            check: a pod's mounted secret / SA-token gets a read-only sub-scope in the generated SBPL (file-read* + a file-write* deny emitted last so it wins inside the writable data volume); the live sandbox write-deny is the m2.sh e2e
            method: unit
            test: pkg/sandbox.TestGenerateSecretReadOnlySubScope + pkg/runtime.TestCreatePodMaterializesVolumesAndDrops
      - id: M2.3
        title: securityContext privilege drop (runAsUser/runAsGroup/fsGroup) before sandbox_apply
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.1
        deliverables:
          - id: M2.3-d1
            done: true
            desc: pkg/supervisor — NET-NEW privilege drop. supervisor.RunLaunchSequence drives the mandated irreversible order setgid → initgroups → setuid → sandbox_apply → exec via a LaunchSeam (pure-Go, unit-testable); the syscalls are isolated in privdrop_darwin.go (UnixDropper; setgid/setuid/setgroups via x/sys/unix — no initgroups(3) binding, so the supplemental-group list incl. fsGroup is set explicitly). The drop runs in the exec-shim (internal/execshim.RunPodLaunch), a fresh single-purpose process — never the multi-threaded daemon. Credential resolved in pkg/runtime (container.securityContext > pod_security_context > PodBox.uid/gid) and carried into the shim argv
          - id: M2.3-d2
            done: true
            desc: pkg/supervisor — ChownForFSGroup chowns the writable pod data volume to fsGroup (group rwx + setgid on dirs), run ROOT-SIDE in pkg/runtime.createPod BEFORE posix_spawn → the exec-shim drop (a uid-dropped/sandboxed process can no longer chown)
          - id: M2.3-d3
            done: true
            desc: docs — the root-in-Seatbelt fallback and the drop ordering are documented at the call site (cmd/k3sm-execshim/main.go package doc, supervisor.RunLaunchSequence, pkg/runtime credential resolution): a pod without a securityContext drop runs as the daemon uid confined only by Seatbelt; untrusted tenancy routes to the M5 vm backend
        acceptance:
          - id: M2.3-a1
            met: true
            check: the credential drop happens in the exact order setgid → initgroups → setuid → sandbox_apply → exec, and the drop/sandbox precede exec (fail-closed if any step errors); the run-as uid/gid reaches the spawned exec-shim. Unit-tested via a recording syscall seam (no real uid change); the live uid drop is the m2.sh e2e under root
            method: unit
            test: pkg/supervisor.TestRunLaunchSequenceOrder + pkg/supervisor.TestRunLaunchSequenceFailClosed + pkg/runtime.TestCreatePodMaterializesVolumesAndDrops
          - id: M2.3-a2
            met: true
            check: with fsGroup set, the writable mount root is group-owned by fsGroup and group-accessible (setgid on dirs), set ROOT-SIDE before the privilege drop. Root-free unit test chowns to the test's own gid; the live arbitrary-gid chown is the m2.sh e2e under root
            method: unit
            test: pkg/supervisor.TestChownForFSGroup + pkg/supervisor.TestChownForFSGroupRejectsRootGid
      - id: M2.4
        title: terminationGracePeriodSeconds — SIGTERM → grace timer raced against the reaper → SIGKILL
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.1
        deliverables:
          - id: M2.4-d1
            done: true
            desc: pkg/supervisor — NET-NEW graceful stop. supervisor.GracefulStop (pure Go, signals injected) sends SIGTERM then RACES a per-PID grace timer against the kqueue reaper via Process.Done() — an early voluntary exit stops the timer (no leak) and SKIPS the SIGKILL; the deadline (or ctx cancel) escalates to SIGKILL; grace 0 is an immediate SIGKILL (no SIGTERM). The kqueue reaper stays the SOLE reaper (GracefulStop only OBSERVES Done, never wait4s). Wired into pkg/runtime.DeletePod (was a hardwired SIGKILL ignoring grace_period_seconds) via the runtime signalGroup seam; resolveGrace uses DeletePodRequest.grace_period_seconds, falling back to PodBox.termination_grace_period_seconds (0 = immediate; the k8s 30s default for UNSET is applied provider-side since proto3 can't distinguish unset from explicit 0)
        acceptance:
          - id: M2.4-a1
            met: true
            check: a pod that exits on SIGTERM within the grace period is reaped without a SIGKILL; a pod that ignores SIGTERM is SIGKILLed after grace_period_seconds; grace 0 is an immediate SIGKILL. Proven root-free with fake signal/reaper seams (SIGTERM-first, early-exit-skips-SIGKILL + timer stopped, deadline→SIGKILL, ctx-cancel→SIGKILL, grace0→immediate); the live real-signal kill is the m2.sh e2e under root
            method: unit
            test: pkg/supervisor.TestGracefulStop + pkg/runtime.TestDeletePodGracefulStop
      - id: M2.5
        title: proc_pid_rusage memory sampler → OOMKilled + Summary API (best-effort CPU QoS)
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.1
        deliverables:
          - id: M2.5-d1
            done: true
            desc: pkg/supervisor — NET-NEW cgo subsystem. rusage_darwin.go binds proc_pid_rusage(RUSAGE_INFO_V2) → ri_phys_footprint behind the Footprinter Go interface (PhysFootprinter; rusage_other.go stub off darwin), re-verified by the M2.1 symbol-canary. MemorySampler (pure Go) samples the pod's summed footprint at ~1 Hz, fires onBreach ONCE on a memory-limit breach, exposes Last() for metering, and stops on ctx cancel (Done closes — no goroutine leak). pkg/runtime.oomKill SIGKILLs the pod on breach and watchContainerExit records the OOMKilled termination reason. The memory limit is carried by the k3sm.io/memory-limit-bytes annotation (interim, until the apis:M2.2 typed PodBox field lands; the proto reserves the band but has not defined it)
          - id: M2.5-d2
            done: true
            desc: pkg/runtime — Runtime.PodMetrics surfaces the sampled footprint (WorkingSetBytes from ri_phys_footprint) as the kubectl-top / Summary-API source the provider wires to the kubelet Summary endpoint (Wave 3). CPU limits are best-effort QoS (taskpolicy / setpriority), explicitly documented as NOT CFS millicores; QoS APPLICATION is deferred with the apis:M2.2 CPU-limit field (no proto field to read a CPU limit from yet)
          - id: M2.5-d3
            done: true
            desc: docs/resources.md — documents that ri_phys_footprint is NOT RSS (resident + compressed + wired + IOKit-mapped, the jetsam/memorystatus figure), that the memory limit + kubectl-top working set are compared/reported in those units, that child PIDs aren't summed in M2, and that CPU is best-effort QoS not CFS millicores. Referenced from the PhysFootprinter / MemorySampler / PodMetrics doc comments
        acceptance:
          - id: M2.5-a1
            met: true
            check: a pod that exceeds its memory limit is SIGKILLed and its ContainerStatus reports OOMKilled. Proven root-free with a fake rusage source + a fake signalGroup driving the full breach→SIGKILL→reaper→OOMKilled-reason chain (and the sampler-stops-on-exit / breach-fires-once / no-leak mechanics); the real-proc_pid_rusage binding is exercised on self, and the live OOM under a real limit is the m2.sh e2e
            method: unit
            test: pkg/supervisor.TestMemorySamplerOOMBreachFiresOnce + pkg/supervisor.TestPhysFootprinterSelf + pkg/runtime.TestCreatePodOOMKilled
          - id: M2.5-a2
            met: true
            check: the Summary API (Runtime.PodMetrics) returns a non-zero working-set for a metered running pod sourced from ri_phys_footprint (the kubectl top path); the live number under load is the m2.sh e2e
            method: unit
            test: pkg/supervisor.TestMemorySamplerMetersWorkingSet + pkg/runtime.TestPodMetricsSurfacesFootprint
      - id: M2.6
        title: imagePullSecrets — registry auth confined to the pull client, signature policy before ad-hoc-sign
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.1
        deliverables:
          - id: M2.6-d1
            done: true
            desc: pkg/image — RegistryCredential is consumed ONLY inside the pull client (go-containerregistry authn via remote.WithAuth on the fetch transport); the FetchFunc/RemoteFetch/Puller.Pull seam carries it, it is never written to the cache or pod dir. The proto carries only a LocalObjectReference list; the actual docker-config credential is supplied by the consumer-side CredentialResolver seam (pkg/runtime; the provider resolves the Secret, runtimed never reads the apiserver) — mirroring the mount.Resolver pattern. nil resolver / empty list / ok=false ⇒ anonymous pull
          - id: M2.6-d2
            done: true
            desc: pkg/runtime — gateSignature enforces the SignaturePolicy in the correct order relative to ad-hoc signing. ADHOC_OK signs then checks; REQUIRE_SIGNED / REQUIRE_NOTARIZED check the AS-PULLED binary and NEVER ad-hoc sign it (codesign -s - -f would strip notarization / replace a real authority — a silent downgrade); UNSPECIFIED fails closed. Replaces the prior unconditional sign-then-check in startContainer
        acceptance:
          - id: M2.6-a1
            met: true
            check: a private image pulls with the imagePullSecret credential and the credential never appears on disk in the pod dir. Proven with a fake CredentialResolver + a fake Puller recording the received cred + a pod-dir walk asserting the secret bytes are absent; the live private-registry pull is the m2.sh e2e
            method: unit
            test: pkg/runtime.TestCreatePodImagePullSecretConfinedToPuller + pkg/image.TestPullPassesCredentialToFetch
          - id: M2.6-a2
            met: true
            check: require-notarized / require-signed reject BEFORE (and instead of) the ad-hoc-sign step (no silent downgrade); adhoc-ok proceeds to ad-hoc sign then check. Asserted on a fake signer recording the Sign/Check call order; the live codesign/spctl behavior is the m2.sh e2e
            method: unit
            test: pkg/runtime.TestGateSignatureOrdering
      - id: M2.7
        title: serve Exec/Attach/PortForward RPCs — live kubectl exec/port-forward
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M1.1
        deliverables:
          - id: M2.7-d1
            done: true
            desc: pkg/runtime/exec.go — Exec runs the requested argv INSIDE the pod's existing confinement domain by reusing the M2.3 exec-shim seam (sandbox.Backend.WrapCommand → supervisor.RunLaunchSequence confine → setgid/initgroups/setuid → sandbox_apply → execve the user's argv instead of the pod entrypoint), so an exec is a fresh equally-confined process and cannot escape the sandbox. Spawned via os/exec (transient, NOT the kqueue-reaped pod-supervision path; the reaper is per-pid so no double-reap), stdin/stdout/stderr streamed over the bidi gRPC stream (Send serialized), tty honored via an in-tree darwin pty (pty_darwin.go: /dev/ptmx + TIOCPTYGRANT/UNLK/GNAME via x/sys/unix; pty_other.go fails closed) with terminal-resize (TIOCSWINSZ); exit code returned as ExecResult (signal → 128+signo). The container's securityContext/env/workingDir are re-resolved from the retained containerProc.spec
          - id: M2.7-d2
            done: true
            desc: pkg/runtime/exec.go — PortForward dials the pod's lo0 pod IP (darwin-net M2.1 alias; loopback on-node) at the requested port and proxies bytes both directions over the stream, multiplexing connections by connection_id; clean teardown closes all conns + reader goroutines on stream end / ctx cancel. Attach follows a RUNNING container's combined output live (logBuffer gains a bounded follower seam, drop-on-slow so the supervisor log pump never blocks) + delivers the exit code; interactive stdin/tty attach is reported Unimplemented (native pods are posix_spawn'd with stdin NOT retained — documented limitation, kubectl exec is the interactive path) rather than faked
        acceptance:
          - id: M2.7-a1
            met: true
            check: exec a trivial command via the real spawn/stream path (root-free, non-dropping) streams stdout + returns exit code 0, a command exiting N returns N, stdin piped to the command reaches it, and the exec goes through the WrapCommand confinement seam with the SAME pod SBPL profile (so a future profile change covers exec); the live Seatbelt-enforced exec is the m2.sh root e2e
            method: unit
            test: pkg/runtime.TestExecRunsAndReturnsExitCode + pkg/runtime.TestExecStreamsStdin + pkg/runtime.TestOpenPTYAllocatesTTY
          - id: M2.7-a2
            met: true
            check: port-forward proxies bytes both ways through a local listener standing in for the pod port; attach streams a running container's live output and rejects interactive stdin (documented M2 limitation)
            method: unit
            test: pkg/runtime.TestPortForwardProxiesBytes + pkg/runtime.TestAttachStreamsContainerOutput + pkg/runtime.TestAttachRejectsStdin

  - id: M3
    title: APFS-backed persistent volume (PV/PVC) — stable same-volume dir, seed-once, lifecycle-decoupled
    status: todo
    depends_on:
      - apis:M3.1
    subphases:
      - id: M3.1
        title: APFS-backed PV/PVC volume materialization
        status: todo
        deliverables:
          - id: M3.1-d1
            done: false
            desc: pkg/volume (or pkg/mount) — a stable per-PVC directory on the SAME APFS volume as /var/lib/k3sm (a cross-volume clonefile silently byte-copies, defeating CoW + the same-fs assumption), EMPTY-CREATED on the hot path
          - id: M3.1-d2
            done: false
            desc: pkg/volume — clonefile is used ONLY to SEED a PVC from a StorageClass template, NEVER on the empty-PVC hot path
          - id: M3.1-d3
            done: false
            desc: pkg/volume + pkg/runtime — the PV lifecycle is DECOUPLED from pod-dir teardown (do NOT RemoveAll the PV on pod restart); the PV mount root is added to the pod's SBPL write-scope
        acceptance:
          - id: M3.1-a1
            met: false
            check: a PVC-backed dir is created empty on the same APFS volume as /var/lib/k3sm and is writable by the pod within its SBPL scope
            method: integration
          - id: M3.1-a2
            met: false
            check: data written to the PV survives a pod restart (the PV is not removed with the pod dir); a template-seeded PVC is a clone, an unseeded one is empty
            method: integration

  - id: M4
    title: uidjail fallback backend + packaging hooks + cgo macOS CI
    status: todo
    depends_on: []
    subphases: []

  - id: M5
    title: vm sandbox backend — Virtualization.framework Linux micro-VM behind sandbox.Backend
    status: todo
    depends_on:
      - apis:M5.1
    subphases:
      - id: M5.1
        title: Virtualization.framework Linux micro-VM backend
        status: todo
        deliverables:
          - id: M5.1-d1
            done: false
            desc: pkg/sandbox — a vm Backend impl backed by Virtualization.framework (a Linux micro-VM), implementing the existing swappable sandbox.Backend interface and gated by Backend.Available() (VZ + the com.apple.security.virtualization entitlement). VZ is a PUBLIC framework — it is NOT a libsandbox/memorystatus SPI symbol-canary case (do not add it to the canary set)
          - id: M5.1-d2
            done: false
            desc: pkg/sandbox (or pkg/image) — Linux rootfs handling for the guest (the OCI payload is a Linux rootfs, not arm64 Mach-O, so codesign/ad-hoc-sign is N/A inside the VM; digest-pin tenant images)
        acceptance:
          - id: M5.1-a1
            met: false
            check: Backend.Available() reports the vm backend present only when VZ + the entitlement are available; a Linux image runs under the vm backend on a capable host
            method: integration
          - id: M5.1-a2
            met: false
            check: the SPI symbol-canary set is unchanged by M5 (VZ is public, not an SPI)
            method: build
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
relocation. Streaming RPCs `Exec`/`Attach`/`PortForward` are stubbed `Unimplemented` here and served in M2.7.

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

## M2 — Daemon split + mounts + privilege drop + grace + resources + canary ✅
**Cross-repo dep:** `apis:M2.1` (the additive `PodBox`/`Container` fields — volumes, volumeMounts,
securityContext, terminationGracePeriodSeconds, imagePullSecret — plus the matching `ContainerStatus`
mirror fields, and the `GetRuntimeInfoResponse.api_version` handshake for the provider↔runtimed
daemon split). All M2 sub-phases below are NET-NEW capabilities (not "wire an existing field"). Decomposed when M1 closes.

### M2.1 — Daemon split + grow the SPI symbol-canary ✅
**Deliverables**
- ✅ `M2.1-d1` `cmd/k3sm-runtimed` + `pkg/runtime/grpcserver.go`: register the existing `*runtime.Runtime`
  with a gRPC server (`runtime.NewServer`) over the root unix socket (`runtime.Listen` — `0600` in a `0700`
  dir, stale-socket removal) per `apis:M2.1` — a **relocation** (`var _ runtimev1.RuntimeServer` already
  satisfied). The `api_version` negotiation surface is **struck**: the provider and its node's runtimed are
  the **same `k3sm` build restarted together** (same-binary, same-node hard cut), so there is no skew window
  — `GetRuntimeInfo` reports identity/health for diagnostics only. Lifecycle is ctx-driven (`Serve` →
  `GracefulStop` on ctx-cancel; no goroutine/fd leak; the sender closes the stop channel). The in-process
  path (k3sm imports `pkg/runtime` as a library) is unchanged — the provider selects in-proc vs daemon.
- ✅ `M2.1-d2` `internal/spicanary`: grew the CI symbol-canary from `libsandbox`/`clonefile` to also
  re-verify `memorystatus_control` (private jetsam SPI) / `proc_pid_rusage` (public `<libproc.h>`,
  load-bearing for the M2.5 sampler) — both resolve from libSystem. **VZ is a PUBLIC framework and is
  explicitly NOT a canary case.**

**Acceptance (exit gate)**
- ✅ `M2.1-a1` the root daemon serves the full `runtime/v1` surface over the socket with clean ctx-driven
  start/stop (no `api_version` negotiation — handshake struck) — `pkg/runtime.TestServerServesRuntimeSurfaceOverUnixSocket`
  + `TestServerServesOverBufconn` + `TestServerStopUnblocksServe` + `TestListenRemovesStaleSocket` (non-root
  unix socket + bufconn; real-root gRPC over the production socket is `m2.sh` on a capable host).
- ✅ `M2.1-a2` the symbol-canary fails the **build** (hard link error) if the `libsandbox` /
  `memorystatus_control` / `proc_pid_rusage` exports disappear (`clonefile` is covered via
  `golang.org/x/sys/unix.Clonefile`) — `spicanary.TestSymbolsResolve` + `TestResourceSymbolsResolve`.

### M2.2 — Volume-mount materialization + validated SBPL extra-path injection ✅
**Deliverables**
- ✅ `M2.2-d1` `pkg/mount`: `Materialize` renders configMap / secret / emptyDir / downwardAPI /
  projected-serviceAccountToken sources into the pod dir via a consumer-side `Resolver` seam (the proto
  carries only the source *reference*; the provider wires the apiserver-backed `Resolver`, tests a fake).
  No mount namespace ⇒ every mount path is **rebased under the pod data volume** (a `../` escape is
  rejected). Wired into `pkg/runtime.createPod`.
- ✅ `M2.2-d2` `pkg/sandbox`: `Generate` **validates** every extra read/write path (and credential paths)
  against a protected deny-set (`/Users`, `/private/var/db`, the pods-root, the dyld cryptex) →
  `ErrProtectedPath` (the pod's own data volume carved out); the protected `(deny ...)` blocks are emitted
  **after** the extra-path allows and the pod's own data-volume re-allow follows the pods-root deny
  (**SBPL last-match-wins**). hostPath roots outside the data volume are the provider's
  `extra_*_paths`, validated here.
- ✅ `M2.2-d3` `pkg/sandbox`: secrets + the projected SA-token get a **read-only sub-scope** (`file-read*`
  + an explicit `file-write*` deny) emitted **last** so the deny wins inside the writable data volume.

**Acceptance (exit gate)**
- ✅ `M2.2-a1` each source materializes at its mount path inside the pod data volume with the resolved
  content — `pkg/mount.TestMaterializeAllSources` + `TestMaterializeSelectedKeysAndMode` +
  `pkg/runtime.TestCreatePodMaterializesVolumesAndDrops` (live read-by-pod is the `m2.sh` e2e).
- ✅ `M2.2-a2` an extra path inside the protected deny-set is rejected; an allowed extra path does **not**
  override the protected denies (last-match-wins) — `pkg/sandbox.TestGenerateRejectsProtectedExtraPath` +
  `TestGenerateProtectedDeniesAfterExtraAllows`.
- ✅ `M2.2-a3` the mounted secret/SA-token gets the read-only sub-scope in the generated SBPL —
  `pkg/sandbox.TestGenerateSecretReadOnlySubScope` (live write-deny is the `m2.sh` e2e).

### M2.3 — securityContext privilege drop (runAsUser/runAsGroup/fsGroup) before `sandbox_apply` ✅
**Deliverables**
- ✅ `M2.3-d1` `pkg/supervisor`: **NET-NEW** privilege drop. `RunLaunchSequence` drives the irreversible
  order `setgid → initgroups → setuid → sandbox_apply → exec` via a `LaunchSeam` (pure-Go, unit-testable);
  syscalls isolated in `privdrop_darwin.go` (`UnixDropper` via `x/sys/unix`; no `initgroups(3)` binding, so
  the supplemental-group list incl. `fsGroup` is set with `setgroups`). The drop runs in the exec-shim
  (`internal/execshim.RunPodLaunch`), never the daemon. Credential resolved in `pkg/runtime`.
- ✅ `M2.3-d2` `pkg/supervisor`: `ChownForFSGroup` chowns the writable data volume to `fsGroup`, run
  **root-side** in `createPod` **before** `posix_spawn` → the exec-shim drop.
- ✅ `M2.3-d3` docs: the root-in-Seatbelt fallback + the drop ordering are documented at the call site
  (`cmd/k3sm-execshim/main.go` package doc, `supervisor.RunLaunchSequence`); untrusted tenancy routes to
  the **M5 `vm` backend**.

**Acceptance (exit gate)**
- ✅ `M2.3-a1` the drop happens in the order `setgid → initgroups → setuid → sandbox_apply → exec` (fail-
  closed if any step errors) and the run-as uid/gid reaches the spawned shim —
  `pkg/supervisor.TestRunLaunchSequenceOrder` + `TestRunLaunchSequenceFailClosed` +
  `pkg/runtime.TestCreatePodMaterializesVolumesAndDrops` (live uid drop is the `m2.sh` e2e).
- ✅ `M2.3-a2` with `fsGroup` set the writable mount root is group-owned by `fsGroup` and group-accessible,
  set before the drop — `pkg/supervisor.TestChownForFSGroup` (live arbitrary-gid chown is the `m2.sh` e2e).

### M2.4 — terminationGracePeriodSeconds — SIGTERM → grace timer raced against the reaper → SIGKILL ✅
**Deliverables**
- ✅ `M2.4-d1` `pkg/supervisor`: **NET-NEW** graceful stop. `supervisor.GracefulStop` (pure Go, signals
  injected) sends `SIGTERM` then **races a per-PID grace timer against the `kqueue(EVFILT_PROC)` reaper**
  via `Process.Done()` — an early voluntary exit stops the timer (no leak) and **skips the SIGKILL**; the
  deadline (or ctx cancel) escalates to `SIGKILL`; grace 0 is an immediate `SIGKILL`. The kqueue reaper
  stays the **sole reaper** (GracefulStop only *observes* `Done`). Wired into `pkg/runtime.DeletePod` (was a
  hardwired SIGKILL) via the `signalGroup` seam; `resolveGrace` reads `DeletePodRequest.grace_period_seconds`
  → falls back to `PodBox.termination_grace_period_seconds` (0 = immediate; the k8s 30s default for *unset*
  is applied provider-side, since proto3 can't tell unset from an explicit 0).

**Acceptance (exit gate)**
- ✅ `M2.4-a1` SIGTERM-first; early exit within grace → no SIGKILL + timer stopped; deadline → SIGKILL;
  grace 0 → immediate SIGKILL — `pkg/supervisor.TestGracefulStop` + `pkg/runtime.TestDeletePodGracefulStop`
  (root-free fake signal/reaper seams; the live real-signal kill is the `m2.sh` e2e under root).

### M2.5 — `proc_pid_rusage` memory sampler → OOMKilled + Summary API (best-effort CPU QoS) ✅
**Deliverables**
- ✅ `M2.5-d1` `pkg/supervisor`: **NET-NEW** cgo subsystem. `rusage_darwin.go` binds
  `proc_pid_rusage(RUSAGE_INFO_V2)` → `ri_phys_footprint` behind the `Footprinter` interface
  (`PhysFootprinter`; `rusage_other.go` stub off darwin), re-verified by the M2.1 symbol-canary.
  `MemorySampler` (pure Go) sums the pod footprint ~1 Hz, fires `onBreach` **once**, exposes `Last()`, and
  stops on ctx cancel (`Done` closes — no leak). `pkg/runtime.oomKill` SIGKILLs on breach;
  `watchContainerExit` records the **`OOMKilled`** reason. The limit rides the `k3sm.io/memory-limit-bytes`
  annotation (interim, pending the `apis:M2.2` typed field).
- ✅ `M2.5-d2` `pkg/runtime`: `Runtime.PodMetrics` surfaces the footprint (`WorkingSetBytes`) as the
  **Summary-API / kubectl top** source the provider wires to the kubelet Summary endpoint (Wave 3). CPU is
  **best-effort QoS** (`taskpolicy`/`setpriority`), **NOT CFS millicores**; QoS *application* is deferred
  with the `apis:M2.2` CPU-limit field.
- ✅ `M2.5-d3` `docs/resources.md`: `ri_phys_footprint` **≠ RSS** (resident + compressed + wired +
  IOKit-mapped; the jetsam figure) — the limit + working set are in those units; CPU best-effort, not CFS.

**Acceptance (exit gate)**
- ✅ `M2.5-a1` a pod over its memory limit is SIGKILLed and its `ContainerStatus` reports `OOMKilled` —
  `pkg/supervisor.TestMemorySamplerOOMBreachFiresOnce` + `TestPhysFootprinterSelf` +
  `pkg/runtime.TestCreatePodOOMKilled` (fake rusage source; the live OOM under a real limit is the `m2.sh` e2e).
- ✅ `M2.5-a2` the Summary API (`PodMetrics`) returns a non-zero working-set sourced from `ri_phys_footprint`
  — `pkg/supervisor.TestMemorySamplerMetersWorkingSet` + `pkg/runtime.TestPodMetricsSurfacesFootprint`.

### M2.6 — imagePullSecrets — registry auth confined to the pull client, policy before ad-hoc-sign ✅
**Deliverables**
- ✅ `M2.6-d1` `pkg/image`: `RegistryCredential` is consumed **only** in the pull client
  (go-containerregistry `remote.WithAuth` on the fetch transport) — the `FetchFunc`/`Pull` seam carries it,
  it is **never** written to the cache or pod dir. The proto carries a `LocalObjectReference` list; the
  docker-config credential comes from the consumer-side `CredentialResolver` seam (the provider resolves
  the Secret; runtimed never reads the apiserver), mirroring `mount.Resolver`.
- ✅ `M2.6-d2` `pkg/runtime`: `gateSignature` enforces the `SignaturePolicy` in the correct order —
  `adhoc-ok` signs then checks; `require-signed`/`require-notarized` check the **as-pulled** binary and
  **never** ad-hoc sign it (`codesign -s - -f` would strip notarization / downgrade a real authority);
  `UNSPECIFIED` fails closed.

**Acceptance (exit gate)**
- ✅ `M2.6-a1` a private image pulls with the `imagePullSecret` and the credential never lands on disk in
  the pod dir — `pkg/runtime.TestCreatePodImagePullSecretConfinedToPuller` +
  `pkg/image.TestPullPassesCredentialToFetch` (the live private-registry pull is the `m2.sh` e2e).
- ✅ `M2.6-a2` `require-notarized`/`require-signed` reject **before** (and instead of) ad-hoc signing;
  `adhoc-ok` proceeds to sign-then-check — `pkg/runtime.TestGateSignatureOrdering` (fake signer, call-order).

### M2.7 — serve `Exec`/`Attach`/`PortForward` RPCs (live `kubectl exec`/`port-forward`) ✅
The three bidi streaming RPCs (stubbed `Unimplemented` since M1) are implemented in
`pkg/runtime/exec.go`, closing the last gap for live `kubectl exec`/`port-forward` (the `k3sm`
provider side was already fake-proven in M2.5).
**Deliverables**
- ✅ `M2.7-d1` `Exec` runs the requested argv **inside the pod's existing confinement domain** by
  **reusing the M2.3 exec-shim seam** — `sandbox.Backend.WrapCommand` → `supervisor.RunLaunchSequence`
  (confine → `setgid`/`initgroups`/`setuid` → `sandbox_apply` → `execve` the user's argv instead of the
  pod entrypoint), so an exec is a fresh, equally-confined process and **cannot escape** the sandbox. The
  transient process is spawned via `os/exec` (NOT the kqueue-reaped pod-supervision path; the reaper is
  per-pid so there is no double-reap), stdin/stdout/stderr stream over the bidi stream (`Send` serialized),
  **tty** is honored via an in-tree darwin pty (`pty_darwin.go`: `/dev/ptmx` + `TIOCPTYGRANT`/`UNLK`/
  `GNAME` via `x/sys/unix`; `pty_other.go` fails closed) with terminal-resize (`TIOCSWINSZ`), and the exit
  code returns as `ExecResult` (signal → `128+signo`).
- ✅ `M2.7-d2` `PortForward` dials the pod's **lo0 pod IP** (darwin-net M2.1 alias; loopback on-node) at
  the requested port and proxies bytes both ways, multiplexing by `connection_id` with clean teardown.
  `Attach` follows a **running** container's live combined output (a bounded `logBuffer` follower seam,
  drop-on-slow so the supervisor's log pump never blocks) and delivers the exit code; interactive
  **stdin/tty attach is `Unimplemented`** (native pods are `posix_spawn`'d with stdin **not retained** —
  a documented limitation, `kubectl exec` is the interactive path) rather than faked.

**Acceptance (exit gate)**
- ✅ `M2.7-a1` exec streams stdout + returns exit code 0, a command exiting N returns N, piped stdin
  reaches the command, and the exec goes through the `WrapCommand` confinement seam with the **same** pod
  SBPL profile — `pkg/runtime.TestExecRunsAndReturnsExitCode` + `TestExecStreamsStdin` +
  `TestOpenPTYAllocatesTTY` (the live Seatbelt-enforced exec is the `m2.sh` e2e).
- ✅ `M2.7-a2` port-forward proxies bytes both ways through a local listener; attach streams a running
  container's output and rejects interactive stdin — `pkg/runtime.TestPortForwardProxiesBytes` +
  `TestAttachStreamsContainerOutput` + `TestAttachRejectsStdin`.

## M3 — APFS-backed persistent volume (PV/PVC) ⬜
**Cross-repo dep:** `apis:M3.1` (the PV/PVC volume source on `PodBox`; **NodePort needs no `apis`
change**). The multi-node join/mesh work is `k3sm` (join/token) + `darwin-net` (wireguard); runtimed's
M3 contribution is the **APFS-backed persistent volume**.

### M3.1 — APFS-backed PV/PVC volume materialization ⬜
**Deliverables**
- ⬜ `M3.1-d1` a **stable per-PVC directory on the SAME APFS volume** as `/var/lib/k3sm` (a cross-volume
  `clonefile` silently byte-copies, defeating CoW + the same-fs assumption), **empty-created** on the hot path.
- ⬜ `M3.1-d2` `clonefile` is used **only to seed** a PVC from a StorageClass template — **never** on the
  empty-PVC hot path.
- ⬜ `M3.1-d3` the PV lifecycle is **decoupled from pod-dir teardown** (do **not** `RemoveAll` the PV on
  pod restart); the PV mount root is added to the pod's SBPL write-scope.

**Acceptance (exit gate)**
- ⬜ `M3.1-a1` a PVC-backed dir is created empty on the same APFS volume as `/var/lib/k3sm` and is
  writable by the pod within its SBPL scope.
- ⬜ `M3.1-a2` data written to the PV survives a pod restart (the PV is not removed with the pod dir); a
  template-seeded PVC is a clone, an unseeded one is empty.

## M4 — Hardening + packaging hooks ⬜
Headline: `uidjail` fallback `Backend` impl; participate in the codesign/notarize entitlement set;
macOS-arm64 CI for the cgo build; node-conformance-subset hooks.

## M5 — `vm` sandbox backend (Virtualization.framework Linux micro-VM) ⬜
**Cross-repo dep:** `apis:M5.1` (the `runtime.k3sm.io` handler-config mapping `runtimeClassName: vm` →
`SANDBOX_BACKEND_VM`). The committed direction for the Linux-only components stockkitty needs
(Postgres/pgvector and the amd64 images): a Virtualization.framework Linux micro-VM behind the
**existing swappable `sandbox.Backend` interface**.

### M5.1 — Virtualization.framework Linux micro-VM backend ⬜
**Deliverables**
- ⬜ `M5.1-d1` `pkg/sandbox`: a `vm` `Backend` impl backed by **Virtualization.framework** (a Linux
  micro-VM), implementing the existing swappable `sandbox.Backend` interface, gated by
  `Backend.Available()` (VZ + the `com.apple.security.virtualization` entitlement). **VZ is a PUBLIC
  framework — it is NOT a `libsandbox`/`memorystatus` SPI symbol-canary case; do not add it to the canary set.**
- ⬜ `M5.1-d2` Linux **rootfs handling** for the guest (the OCI payload is a Linux rootfs, not arm64
  Mach-O, so codesign/ad-hoc-sign is N/A inside the VM; digest-pin tenant images).

**Acceptance (exit gate)**
- ⬜ `M5.1-a1` `Backend.Available()` reports the `vm` backend present only when VZ + the entitlement are
  available; a Linux image runs under the `vm` backend on a capable host.
- ⬜ `M5.1-a2` the SPI symbol-canary set is **unchanged** by M5 (VZ is public, not an SPI).

## Next
M1 and M2 are complete at the **runtimed unit-provable level**. M2 (the **stockkitty-readiness**
milestone, `../../docs/stockkitty-readiness.md`) split `k3sm-runtimed` into a root gRPC daemon + grew
`internal/spicanary` (M2.1); volume-mount materialization + validated SBPL extra-path injection (M2.2);
the `setgid→initgroups→setuid` drop + `fsGroup` chown before `sandbox_apply` (M2.3); SIGTERM/grace-timer/
SIGKILL graceful stop raced against the reaper (M2.4); the `proc_pid_rusage` memory sampler → `OOMKilled`
+ `PodMetrics` Summary source (M2.5); imagePullSecret auth confined to the pull client + signature
policy before ad-hoc sign (M2.6); and served the `Exec`/`Attach`/`PortForward` streaming RPCs by reusing
the exec-shim confinement seam — live `kubectl exec`/`port-forward` (M2.7).

**Two milestone-gate items remain outside runtimed's per-repo `status: done`** (ROADMAP §phase-gate #2/#3,
the orchestrator's responsibility): the workspace `k3sm/hack/acceptance/m2.sh` **root e2e** (real
signals/uid/registry/OOM under a real memory limit), and the **Wave-3 `k3sm` provider wiring** — map
`Runtime.PodMetrics` to the kubelet Summary endpoint, implement the `CredentialResolver` (docker-config
Secret → `image.RegistryCredential`) and the `mount.Resolver`, derive `DeletePodRequest.grace_period_seconds`
(applying the k8s 30s default), and set the `k3sm.io/memory-limit-bytes` annotation. **apis follow-up:**
`apis:M2.2` should add the first-class `PodBox` memory-limit field + a Summary/pod-stats message + the
`ContainerStatus.resources` mirror; until then the limit rides the annotation and `PodMetrics` is a
runtimed-internal type.

M3 adds the APFS-backed PV/PVC (stable same-volume dir, seed-once, lifecycle-decoupled); M5 adds the
Virtualization.framework `vm` backend for Linux images.
