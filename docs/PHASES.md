---
repo: runtimed
schema: phases/v1
current_phase: M5
updated: 2026-08-31
updated_by: orchestrator

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
      - id: M2.8
        title: consume the apis:M2.2 typed resource contract (replace the annotation seam) + serve RestartContainer/ListPodStats
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M2.2
        deliverables:
          - id: M2.8-d1
            done: true
            desc: pkg/runtime/metrics.go — podMemoryLimitBytes now reads the typed PodBox.memory_limit_bytes (apis:M2.2) and the typed field WINS when set; it falls back to the legacy k3sm.io/memory-limit-bytes annotation ONLY when the typed field is unset (0). The fallback is TRANSITIONAL (documented as such) so there is NO transition window regardless of land order — the k3sm provider starts writing the typed field in a sibling PR. qos_class and rlimits ride the same PodBox resource band but their ENFORCEMENT is deferred and documented (docs/resources.md): qos_class CPU-QoS application (taskpolicy/setpriority) needs a contention-policy decision, and rlimits via setrlimit(2) must extend the M2.3 security-critical RunLaunchSequence (a setrlimit step ordered before setuid) with its own ordering test — neither is bolted on untested here
          - id: M2.8-d2
            done: true
            desc: pkg/runtime/restart.go — serve RestartContainer: terminate the named container's process group within the grace window (reuses the M2.4 supervisor.GracefulStop SIGTERM→grace→SIGKILL escalation), wait for the kqueue reaper to collect it, then RE-SPAWN FROM THE SAME SPEC via the existing startContainer path (so the replacement gets the SAME already-generated SBPL profile, the SAME M2.3 exec-shim setgid/initgroups/setuid drop, and the SAME mounts). restart_count is incremented and the prior run recorded in last_termination_state; a per-container `restarting` guard keeps the transient termination from flipping the pod phase or cancelling the memory sampler; the re-spawn supervision is detached from the RPC ctx (context.WithoutCancel) so it outlives the call. Unknown pod/container return a structured NOT_FOUND. restart_count + last_termination_state are added to the ContainerStatus status mirror (containerStatusOf, shared with podStatus)
          - id: M2.8-d3
            done: true
            desc: pkg/runtime/stats.go — serve ListPodStats: map the M2.5 sampler's ri_phys_footprint working set onto the apis PodStats/ContainerStats/MemoryStats wire types (replacing the runtimed-internal-only PodMetrics path). Pod-level working_set_bytes comes from PodMetrics (the sampler, the same value OOMKilled is judged against); per-container working sets are sampled from the same proc_pid_rusage Footprinter seam at request time (each M2 container is one process). Empty pod_id returns ALL metered pods (the Summary shape); a pod with no memory sampler (unmetered in M2) or an unknown/gone pod_id is OMITTED (empty list, not an error); CPU is left unset (best-effort QoS, no accounting)
        acceptance:
          - id: M2.8-a1
            met: true
            check: the memory limit is read from the typed PodBox.memory_limit_bytes; it falls back to the annotation when the typed field is unset; the typed field wins when both are set. The typed limit also drives the OOM sampler end-to-end (no annotation required)
            method: unit
            test: pkg/runtime.TestMemoryLimitFromTypedField + pkg/runtime.TestCreatePodOOMKilledTypedLimit
          - id: M2.8-a2
            met: true
            check: RestartContainer stops the old process group and relaunches the container through the startContainer path (a new spawn) and bumps restart_count; an unknown pod or container is NOT_FOUND. The live Seatbelt-confined re-exec under a real liveness restart is the m2.sh e2e
            method: unit
            test: pkg/runtime.TestRestartContainerReExecs
          - id: M2.8-a3
            met: true
            check: a sampled (metered) pod's footprint maps onto PodStats.containers[].memory.working_set_bytes; empty pod_id returns all metered pods; an unsampled (unmetered) pod is omitted
            method: unit
            test: pkg/runtime.TestListPodStatsMapsFootprint

  - id: M3
    title: APFS-backed persistent volume (PV/PVC) — stable same-volume dir, seed-once, lifecycle-decoupled
    status: done
    completed: 2026-06-25
    depends_on:
      - apis:M3.1
    subphases:
      - id: M3.1
        title: APFS-backed PV/PVC volume materialization
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M3.1-d1
            done: true
            desc: pkg/volume — NET-NEW. A volume.Binder materializes a PVC-backed volume as a STABLE per-claim dir at storagev1.LocalPathClass.DataDir(namespace, claimName) on the SAME APFS volume as /var/lib/k3sm — the production Binder roots BasePath at <Config.Root>/storage, a sibling of the pods root (so it shares the APFS volume kine's SQLite uses but is NOT under the pod dir removePodDir tears down). The dir is EMPTY-CREATED (os.MkdirAll, never a clonefile) on the hot path; the claim is keyed by (namespace, claimName) so the same claim is stable across pods/restarts. Bind symlinks each container mount of the claim into the pod rootfs (k3sm has no mount namespace) so the confined pod reaches the persistent dir at its mount path. PVC capacity is NOT enforced vs APFS free space (over-commit → write-time ENOSPC; documented in pkg/volume/doc.go + storagev1). pkg/mount.Materialize SKIPS PVC sources (they are not pod-ephemeral)
          - id: M3.1-d2
            done: true
            desc: pkg/volume — clonefile (via the pkg/image Cloner → image.MaterializeTree CoW seam) is used ONLY to SEED a fresh PVC from a StorageClass template, gated by a consumer-side TemplateResolver seam (nil/ok=false ⇒ empty-create; runtimed never reads the apiserver, so the provider supplies the template, tests fake it). Seeding is SEED-ONCE: a reused (already-present) dir is never re-seeded, and the clonefile path is NEVER reached on the empty-PVC hot path
          - id: M3.1-d3
            done: true
            desc: pkg/volume + pkg/runtime — the PV lifecycle is DECOUPLED from pod-dir teardown. The PV dir lives under <Root>/storage, a sibling of <Root>/pods, so DeletePod's removePodDir (which only removes <Root>/pods/<id>) never touches it (ReclaimPolicy Retain — there is NO volume-delete RPC and root-rmdir would bypass the SBPL deny-set, so neither is implemented); the pod-side symlink is removed but os.RemoveAll unlinks it without following, so the target survives pod stop/restart/delete. createPod adds each PV mount root to the pod's SBPL scope via the NET-NEW sandbox.GenerateOptions.WritePaths (read+write) / ReadPaths (read-only), validated against the M2.2 protected deny-set
        acceptance:
          - id: M3.1-a1
            met: true
            check: a PVC-backed dir is created empty on the same APFS volume as /var/lib/k3sm (the <Root>/storage sibling), stable across calls for the same (namespace, claim), and the PV mount root is granted file-write* in the pod's SBPL scope (a read-only PVC gets read but not write) while the protected denies still win. Root-free unit-provable; the live Seatbelt-confined write is the m3.sh e2e
            method: unit
            test: pkg/volume.TestPVCMaterializeStableDir + pkg/sandbox.TestPVCInSBPLWriteScope
          - id: M3.1-a2
            met: true
            check: data written to the PV survives the pod-teardown path (the PV dir is NOT removed with the pod dir), while the pod rootfs IS removed; a fresh pod for the same claim reuses the dir with prior data intact; a template-seeded PVC is a clone (seed-once), an unseeded one is empty. Root-free with the real Binder + a temp root; the live clonefile seed is the m3.sh e2e
            method: unit
            test: pkg/runtime.TestPVCSurvivesPodTeardown + pkg/volume.TestPVCSeedOnce

  - id: M4
    title: uidjail fallback backend + packaging hooks + cgo macOS CI
    status: todo
    depends_on: []
    subphases: []

  - id: M5
    title: vm sandbox backend — Virtualization.framework Linux micro-VM behind sandbox.Backend
    status: in-progress
    depends_on:
      - apis:M5.1
    subphases:
      - id: M5.1
        title: Virtualization.framework Linux micro-VM backend
        status: in-progress
        strategy: hard cut
        strategy_rationale: the vm backend is additive behind the existing swappable sandbox.Backend ladder; the host-process Seatbelt path is byte-unchanged (golden SBPL + existing tests stay green); one signed binary. No proto/CRD/datastore change beyond apis:M5.1 (already landed). The live VM boot is lab-gated, not phased.
        deliverables:
          - id: M5.1-d1
            done: true
            desc: pkg/sandbox — a vm Backend cgo SCAFFOLD backed by Virtualization.framework, implementing the existing swappable sandbox.Backend interface and gated by a SAFE Backend.Available() probe. Available() = darwin OS-gate AND +[VZVirtualMachine isSupported] AND a com.apple.security.virtualization static-code-entitlement check (read via Security.framework SecCodeCopySigningInformation), both wrapped in @try/@catch + @autoreleasepool in the isolated Obj-C shim (vm_darwin.m / vm_darwin.h); it NEVER constructs/boots a VM (that raises an uncaught NSException → SIGABRT on a non-entitled host). vm_darwin.go (//go:build darwin && cgo) links -framework Virtualization/Foundation/CoreFoundation/Security; vm_other.go (//go:build !(darwin && cgo)) stubs the probes false so the pure-Go (CGO_ENABLED=0) lane is unbroken. CreateVM is a documented LAB-GATED stub (ErrVMBootNotImplemented). Registered as the consumer-side runtime.VMBackend so pod.go/SelectBackend query it. VZ is a PUBLIC framework — internal/spicanary is deliberately UNCHANGED (NOT a libsandbox/memorystatus SPI canary case)
          - id: M5.1-d2
            done: false
            desc: pkg/sandbox (or pkg/image) — LAB-GATED remainder (needs a VZ-capable, entitled Mac): the live VM boot (VZVirtualMachineConfiguration driven on a per-VM SERIAL dispatch queue behind an opaque handle, VZ-delegate→exit / SIGTERM→ACPI requestStop); the cmd/k3sm-vmhost helper-process lifecycle; the OCI-Linux-rootfs→bootable-root builder (the OCI payload is a Linux rootfs, not arm64 Mach-O, so codesign/ad-hoc-sign is N/A inside the VM; digest-pin tenant images); and VM metering (the memory limit → VZ memorySize; working set from a guest agent, NOT proc_pid_rusage which only sees the host/vmnet task)
          - id: M5.1-d3
            done: true
            desc: pkg/sandbox + pkg/runtime — FAIL-CLOSED backend dispatch (the verifiable safety fix). sandbox.SelectBackend now takes the REQUESTED backend (SandboxProfile.backend): a requested vm backend that is UNavailable returns the typed ErrBackendUnavailable (FAIL CLOSED — NEVER downgrades to the weaker Seatbelt rung, on which a Linux image cannot even exec); UNSPECIFIED (the host-process default) walks the existing host-OS-gated Seatbelt ladder (degrade-UP-only, unchanged); an explicit Seatbelt pin is honored-or-refused. pkg/runtime.createPod threads sp.GetBackend() and queries the registered vm backend's Available() (was hardcoded vmAvailable=false, discarding the selected rung) and ROUTES a selected vm rung to createVMPod, which bypasses the host-process Mach-O steps (resolveBinary / gateSignature+ad-hoc-codesign / SBPL SandboxApply / lo0 networking) — meaningless for a Linux guest. The host-process path is byte-unchanged
        acceptance:
          - id: M5.1-a1
            met: false
            check: a Linux image runs under the vm backend on a capable, entitled host (Backend.Available() reports present only when VZ + the entitlement are available) — the live boot
            method: integration
          - id: M5.1-a2
            met: true
            check: the SPI symbol-canary set is unchanged by M5 (VZ is public, not an SPI) — internal/spicanary is byte-unchanged; the canary still links + passes
            method: build
            test: internal/spicanary unchanged; spicanary.TestSymbolsResolve + TestResourceSymbolsResolve
          - id: M5.1-a3
            met: true
            check: the fail-closed dispatch + vm routing are unit-proven — SelectBackend honors the requested backend and fails a vm-requested pod CLOSED when the vm backend is unavailable (never downgrades to Seatbelt); UNSPECIFIED uses the ladder; a vm-routed pod bypasses the host-process Mach-O steps while a host-process pod still drives them (byte-unchanged)
            method: unit
            test: pkg/sandbox.TestSelectBackendVMRequestedUnavailableFailsClosed + TestSelectBackendVMRequestedAvailable + TestSelectBackendUnspecifiedUsesLadder + pkg/runtime.TestCreatePodVMRoutingBypassesHostProcessSteps
          - id: M5.1-a4
            met: true
            check: VMBackend.Available() reports false on a host WITHOUT the com.apple.security.virtualization entitlement and does NOT crash (the safe probe never constructs/boots a VM); the CGO_ENABLED=0 lane builds via the vm_other.go stub
            method: unit
            test: pkg/sandbox.TestVMBackendAvailableFalseWithoutEntitlement + TestVMBackendAvailableComposition

  - id: M7
    title: Public CI workflow + SkipUnless conversions (release-engineering slice)
    status: todo
    depends_on:
      - apis:M7.2
    subphases:
      - id: M7.1
        title: public CI workflow + SkipUnless conversions
        status: todo
        size: M
        strategy: hard cut
        strategy_rationale: release infrastructure is additive — a new thin GitHub Actions workflow wrapping the existing hack/ci.sh, a mechanical raw-t.Skip→SkipUnless conversion, and a README header; no runtime, proto, or datastore change. One signed binary, one deploy.
        deliverables:
          - id: M7.1-d1
            done: false
            desc: .github/workflows/ci.yml — a THIN wrapper over the existing hack/ci.sh (no logic duplication) on macos-15 arm64 runners, CGO_ENABLED=1; runs unit + -race + the internal/spicanary symbol-canary on EVERY matrix image (the canary is the runner-macOS-15-vs-target-macOS-26 skew tripwire)
          - id: M7.1-d2
            done: false
            desc: convert this repo's raw t.Skip integration sites to the apis-hosted k3smtest.SkipUnless(t, cap) helper over the owned capability taxonomy (root/lo0/utun/pf/clang/apple-gpu/macos-26/network); the lint scope is integration ∥ e2e tags and no raw t.Skip remains in those files
          - id: M7.1-d3
            done: false
            desc: README.md — a "part of k3sm" front-door header (badges, the one-line pitch, a pointer to the workspace) refreshing the pre-launch scaffold copy
        acceptance:
          - id: M7.1-a1
            met: false
            check: the PR CI workflow runs green on GitHub Actions (macos-15 arm64, CGO_ENABLED=1) with the internal/spicanary symbol-canary executing on every matrix image
            method: integration
          - id: M7.1-a2
            met: false
            check: no raw t.Skip remains in -tags integration (∥ e2e) files — every integration skip routes through the apis-hosted k3smtest.SkipUnless (the lint)
            method: build

  - id: M8
    title: MLX — native Apple-Silicon ML serving (runtimed slice — Metal SBPL + egress + tree signing + GPUFacts; consumes the M11.2-d7 unpacker)
    status: done
    completed: 2026-08-29
    depends_on:
      - apis:M8.1
    subphases:
      - id: M8.2
        title: Metal SBPL + egress branch + tree signing + GPUFacts (consumes the M11.2-d7 unpacker)
        status: done
        completed: 2026-08-30
        size: L
        depends_on: [runtimed:M11.2-d7]
        strategy: hard cut
        strategy_rationale: additive — the new SandboxProfile booleans (allow_gpu, allow_internet_egress) default false so an old runtimed ignores them and an old provider never sets them (no provider↔runtimed phased exception); the proto fields are carved from the reserved bands in apis:M8.1; the host-process Seatbelt path and existing golden SBPL fixtures stay byte-green. One signed binary. RE-HOME NOTE (2026-07-11): the OCI-layer unpacker (formerly the M8.2-d0 deliverable here) moved to runtimed M11.2-d7 with the Linux-layer re-sequencing — this sub-phase CONSUMES it via the depends edge above; edge NARROWED 2026-08-29 to the d7 deliverable ONLY (operator-directed re-sequencing, m11-plan R25) — d1–d5 need only d7's output, so M8.2 does NOT wait on the rest of the M11.2 wave; its materialize-then-exec acceptance moved with it (now M11.2-a6).
        deliverables:
          - id: M8.2-d1
            done: true  # orchestrate/M8.2 wave, 2026-08-29
            desc: >-
              pkg/sandbox/metal.go — the Metal SBPL allow-set behind allow_gpu. PRIMARY (m8-plan R22,
              amended 2026-08-29, operator-directed): Apple's own practice — a single prefix rule
              (iokit-registry-entry-class-prefix "AGXAcceleratorG") plus the S1-derived mach-lookup +
              shader-cache scope, covering AGX user-client class variation M1→M4 WITHOUT a per-family
              table; golden fixture — ONE prefix-rule golden. FALLBACK (S1-evaluated, adopted only if the
              prefix rule under- or over-scopes on the lab rig): the per-chip-family data table (AGX
              user-client class names vary M1→M4) with per-family golden SBPL fixtures in
              pkg/sandbox/testdata, launch families SCOPED to the dev-mac's own family for v1 (Resolution
              15). Res. 14's fail-closed control SURVIVES as the OPERATIVE control: metal.go's per-family
              Go-side data + the sandbox_gpu_supported advertisement gate remain the gate for whether a
              family's GPU surface is reachable; the SBPL prefix is a static ceiling, not a family
              approximation — an unknown/absent family FAILS CLOSED (sandbox_gpu_supported=false +
              metal.go errors on a family miss on the fallback path; on the prefix-rule path fail-closed
              keys on the functional probe of M8.2-d4). The shader-cache write scope stays
              CONTRACT-BOUNDED (per-pod redirect or an enumerated narrow subpath) NOT denial-log-derived
              (Resolution 11). Emitted in the existing rule order (allows → protected denies → narrow
              re-allows)
          - id: M8.2-d2
            done: true  # orchestrate/M8.2 wave, 2026-08-29
            desc: >-
              pkg/sandbox — the egress branch behind allow_internet_egress, RE-FOUNDED 2026-08-29 (m8-plan
              R21, operator-directed) as the API contract, NOT an SBPL filter: per-IP SBPL scoping does not
              compile on macOS 26 (probe-verified through the real execshim/libsandbox path —
              sbpl.go:382-411, where network filters accept only localhost/* hosts). runtimed CONSUMES
              allow_internet_egress (which IMPLIES allow_network — the pairing is enforced in
              translate/Validate) and emits the documented unfiltered-but-compilable network stanza — the
              same stanza allow_network emits, golden-pinned byte-for-byte and matching sbpl.go's ceiling
              comment; a DOCUMENTED CEILING, stated in limitations.md / privilege-model.md. sandbox.Validate
              is RE-SCOPED to what is expressible — network forms appear ONLY when allow_network ∨
              allow_internet_egress is set, the implies-pairing holds, and the emitted stanza matches the
              golden and COMPILES (the TestIntegrationNetworkStanzaCompiles pattern). The range-based deny
              set, the tier-3 re-allows, and the kine-loopback deny are RETIRED from M8 (the SBPL half of
              Resolution 12/13 is superseded): network-layer (PF) enforcement is a FILED FUTURE item (B188,
              darwin-net-owned), NOT an M8 deliverable; Seatbelt is never claimed as network isolation
          - id: M8.2-d3
            done: true  # orchestrate/M8.2 wave, 2026-08-29
            desc: pkg/image — AdHocSignTree beside AdHocSign, run ONCE at pull/materialize time over the M11.2-d7 content-addressed tree (policy-keyed variant; the unpacker re-homed 2026-07-11); in-process Mach-O magic detection, signs only invalid/unsigned Mach-Os (ad-hoc signatures are content-addressed and survive clonefile — never de-CoW a clean file); CONTAINMENT-CHECKED (lstat, never follow symlinks/hardlinks, every candidate resolves under the rootfs) and STRUCTURALLY UNREACHABLE under REQUIRE_SIGNED/REQUIRE_NOTARIZED. gateSignature (pkg/runtime/pod.go) becomes check-then-sign-only-if-invalid — no unconditional -f re-sign, which would de-CoW argv[0] every start (Resolution 13) — and keeps verifying argv[0] only per start
          - id: M8.2-d4
            done: true  # orchestrate/M8.2 wave, 2026-08-29
            desc: pkg/sandbox (or pkg/runtime) — GPUFacts population for GetRuntimeInfoResponse.gpu (field 100, apis:M8.1). Sysctls + a FUNCTIONAL Metal compile+dispatch probe (cgo-isolated in *_darwin.go), NOT a nil-check — the probe DISCRIMINATES the VZ paravirtual Metal device (MTLCreateSystemDefaultDevice is non-nil in VZ guests incl. GitHub macOS runners, so a VM node must never advertise GPU); populates iogpu_wired_limit_bytes with the explicit 0-sentinel (kernel default, not "unknown"), recommended_max_working_set_bytes (the MTLDevice working-set ceiling), and sandbox_gpu_supported scoped to the currently selected backend
          - id: M8.2-d5
            done: true  # orchestrate/M8.2 wave, 2026-08-29
            desc: pkg/supervisor — CONTINGENT / PRE-AUTHORIZED (Resolution 18, default NOT built). Spike S3(5) verifies the S5-engine winner's process model against the sampler's leader-PID-only coverage (pod.go containerPIDs); IF the engine forks, a proc_listpids(PROC_PGRP_ONLY, …) pgid-enumeration deliverable (public libproc, the rusage_darwin.go pattern + an internal/spicanary entry) is pre-authorized. Default disposition — pin the winner single-process at M8.4
        acceptance:
          - id: M8.2-a1
            met: true  # 2026-08-29 — orchestrator-verified (goldens + mutations)
            check: golden SBPL tests assert the generated profile — allow_gpu on/off (the prefix-rule allow-set; per-family goldens only on the R22 fallback path), the egress/network stanza byte-pinned (documented-ceiling form), and adversarially-formatted profiles rejected by the s-expression-aware Validate
            method: unit
          - id: M8.2-a2
            met: true  # 2026-08-29 — orchestrator-verified (goldens + mutations)
            check: AdHocSignTree table test with a fake signer — hardlink/symlink escape cases rejected (containment), non-Mach-O skipped, already-signed skipped, policy gating (unreachable under REQUIRE_SIGNED/REQUIRE_NOTARIZED)
            method: unit
          - id: M8.2-a3
            met: true  # 2026-08-29 — orchestrator-verified (goldens + mutations)
            check: GPUFacts population is unit-proven over a fake probe seam — the VZ-paravirtual discrimination (functional-probe verdict false ⇒ metal_available=false and the node-facing fields cleared), the iogpu_wired_limit_bytes 0-sentinel, recommended_max_working_set_bytes pass-through, and sandbox_gpu_supported scoped to the currently selected backend
            method: unit
          - id: M8.2-a4
            met: true  # 2026-08-30 run5 on the apple-gpu rig: TestIntegrationMetalMatmulUnderProfile RAN fatal-not-skip (K3SM_CI_REQUIRE) — matmul MATMUL_OK + denied_without_allow_gpu + the full generation leg (GENERATE_OK 69 tok); absence counterfactual FAILs as designed
            check: a real MLX matmul (full inference round-trip) runs under the generated allow_gpu profile on a GPU dev-mac (integration tier, k3smtest.SkipUnless(t, "apple-gpu"))
            method: integration

  - id: M10
    title: Kubernetes conformance hardening (runtimed slice — per-pod-IP podnet adapter + workload-execution fidelity)
    status: done
    completed: 2026-07-06
    updated_by: orchestrator
    depends_on:
      - apis:M10.2
    subphases:
      - id: M10.1
        title: per-pod-IP — podnet adapter over the NodeNetwork no-op seam (converge on the runtimed path)
        status: done
        size: M
        strategy: phased (named exception: VK provider ↔ runtimed gRPC contract)
        strategy_rationale: >-
          M10.1 is real cross-repo adapter wiring, not a hardcode deletion: today
          runtime.go:280 wires supervisor.NodeNetwork{} (a no-op seam that returns the node IP, so
          translate.go:877 reads back ≈nodeIP), and the HostProcess os/exec path is REJECTED for
          per-pod IP (no bind discipline → a cosmetic /32 the server never binds). Converging the
          pod-IP path on runtimed likely flips the DEFAULT runtime to runtimed (HostProcess → an
          explicit rootless-dev opt-in) — a provider↔runtimed contract change rolled per the named
          exception; the DEFAULT runtime flipped to runtimed (M10.1, operator-decided) with a
          fail-fast preflight. CORRECTION (probe-verified macOS 26.5.1): the prior per-IP SBPL
          network stanza — (local ip "<PodIP>:*") + VIP-scoped egress — does NOT compile
          (libsandbox: "host must be * or localhost"); it never applied, so networked confined
          pods could not spawn. The stanza is now unfiltered-but-compilable (network allowed under
          (deny default); per-IP scoping is a documented macOS ceiling — only localhost/* hosts +
          per-PORT scoping compile) and the golden was REGENERATED (not byte-green); a real
          libsandbox compile-and-apply integration test (TestIntegrationNetworkStanzaCompiles)
          guards it. Per-pod IP is addressing/identity, never Seatbelt network isolation.
        deliverables:
          - id: M10.1-d1
            done: true
            desc: pkg/supervisor + pkg/runtime — replace supervisor.NodeNetwork{} (runtime.go:280 — the no-op seam whose Setup returns the node IP) with an ADAPTER over darwin-net's podnet.Network, bridging the two PodNetwork interfaces (supervisor's Setup returns string, podnet's returns netip.Addr) through a NAMED seam — an adapter type, not open-coded per call site — so translate.go:877 reads back a distinct per-pod /32 instead of ≈nodeIP
          - id: M10.1-d2
            done: true
            desc: pkg/supervisor — IPAM ownership is a PASS-THROUGH — darwin-net stays the sole node-/24 IPAM owner (253/node via podnet.Network); runtimed's seam allocates nothing and adds no second allocator. The existing SBPL bind-scope (sbpl.go:290 `(allow network-bind (local ip "<PodIP>:*"))`) already consumes the real /32, so it is byte-unchanged and now scopes the pod to its own distinct address rather than the node IP
          - id: M10.1-d3
            done: true
            desc: docs — record the load-bearing decision that converging per-pod IP on the runtimed path likely makes runtimed the DEFAULT runtime (HostProcess → an explicit rootless-dev opt-in), documented at the adapter seam; the HostProcess os/exec per-pod-IP option is REJECTED (INADDR_ANY wildcard bind → a Potemkin /32 the server never binds; two same-node pods collide on shared lo0)
        acceptance:
          - id: M10.1-a1
            met: true
            check: a pod created through the runtimed path is assigned a DISTINCT per-pod /32 from the podnet adapter (not ≈nodeIP), read back via the pod-status path; two pods on the same node get different IPs. Golden/table test over the adapter seam plus a materialize-then-exec integration test proving the podnet adapter allocates and binds a real /32 end-to-end
            method: unit
            test: pkg/runtime.TestCreatePodAssignsDistinctPodIP (golden/table) + pkg/supervisor.TestPodNetAdapterMaterializeThenExec (integration)
          - id: M10.1-a2
            met: true
            check: the podnet seam is a pass-through — runtimed allocates no IP itself (darwin-net's podnet.Network is the sole allocator) and the network stanza is unfiltered-but-compilable (per-IP SBPL scoping does not compile on macOS 26 — golden REGENERATED, guarded by TestIntegrationNetworkStanzaCompiles)
            method: unit
            test: pkg/runtime.TestNetworkReconcileStartup + pkg/sandbox.TestGenerateGolden (regenerated) + pkg/sandbox.TestIntegrationNetworkStanzaCompiles (real libsandbox apply)
      - id: M10.2
        title: workload-execution fidelity — native sidecar lifecycle + subPath volume materialization
        status: done
        size: L
        strategy: phased (named exception: apis CRD/proto change (consumer-first))
        strategy_rationale: >-
          The sidecar signal (initContainer restartPolicy:Always) cannot cross the
          provider↔runtimed gRPC contract today: the Container proto has no restart_policy field and
          translate.go:507 drops it. The field is added in apis:M10.2 (wave 1, consumer-first: runtimed
          ships the tolerant reader first), NEVER a k3sm.io/* annotation. subPath is a self-contained
          hard-cut materialization addition (B77). One signed binary.
        depends_on:
          - apis:M10.2
        deliverables:
          - id: M10.2-d1
            done: true
            desc: pkg/supervisor + pkg/runtime — native sidecar process lifecycle keyed on the new apis Container.restart_policy field (apis:M10.2): a long-running initContainer with restartPolicy:Always is STARTED before the main containers and STAYS RUNNING during them (rather than run-to-completion), and pod teardown stops sidecars in REVERSE start order after the main containers exit. Consumer-first tolerant reader — a container with restart_policy unset behaves exactly as an M2 init/regular container (no behavior change until the provider sets the field)
          - id: M10.2-d2
            done: true
            desc: pkg/mount — subPath volume materialization (B77) — volumeMounts[].subPath mounts a SUB-DIRECTORY of the source volume at the mount path (not the whole volume), rebased under the pod data volume like every other mount (no mount namespace), with the same "../" escape rejection as M2.2 Materialize so a subPath cannot climb out of its source
        acceptance:
          - id: M10.2-a1
            met: true
            check: an initContainer with restartPolicy:Always (native sidecar) is started before the main containers, STAYS RUNNING while they run, and is torn down in reverse order after they exit; a container with restart_policy unset is unchanged from M2. Root-free with fake spawn/reaper seams
            method: unit
            test: pkg/runtime.TestNativeSidecarStaysRunning + pkg/supervisor.TestSidecarReverseOrderTeardown
          - id: M10.2-a2
            met: true
            check: a volumeMount with subPath materializes only the named sub-directory of the source volume at the mount path (inside the pod data volume), and a subPath attempting a "../" escape is rejected
            method: unit
            test: pkg/mount.TestVolumeSubPathMaterialization + pkg/mount.TestVolumeSubPathRejectsEscape

  - id: M11
    title: Linux containers & multi-arch (runtimed slice — platform selection, Linux rootfs, k3sm-vmhost, guest init/agent)
    status: in-progress  # 2026-08-30 ledger repair: M11.2 has been in-progress with d1/d4/d6/d7 landed (and d0/d5 written back the same day); a todo top-level contradicted its own sub-phase
    depends_on: []
    notes: >-
      The XL heart of M11 (docs/m11-plan.md — authoritative). ABSORBS AND SUPERSEDES the
      M5.1-d2 lab remainder (live VM boot, k3sm-vmhost, the OCI-Linux-rootfs→bootable-root
      builder, VM metering, entitlement split). Hard cut: everything is additive beside
      the fail-closed SANDBOX_BACKEND_VM fork; the host-process spine stays byte-green.
      Dependency hygiene: github.com/Code-Hex/vz/v3 is confined to pkg/vmhost +
      cmd/k3sm-vmhost — the shipped k3sm product binary NEVER links it, enforced by a
      go-list-deps canary in hack/ci.sh (the symbol-canary precedent);
      internal/spicanary stays byte-unchanged (VZ is public — the M5.1-d1 statement).
      RE-SEQUENCED PRE-LAUNCH (2026-07-11, docs/m11-plan.md R16): this wave ships
      functional-EXPERIMENTAL at v0.1; run out of ledger order with recorded rationale —
      the M10 remainder is hardware-gated and not a dependency. The OCI-layer unpacker is
      OWNED HERE as M11.2-d7 (re-homed from the MLX milestone; built FIRST within this
      wave — d1 extends it in-wave; the MLX slice consumes it via its depends edge).
      Lifecycle invariant that keeps hard cut truthful: vmhost children die with
      io.k3sm.server — no VM outlives the binary version that booted it.
    subphases:
      - id: M11.2
        title: platform selection + OCI-layer unpacker + Linux rootfs builder + vmhost + guest init + vsock agent + volumes + metering
        status: in-progress
        depends_on: [apis:M11.1]
        deliverables:
          - id: M11.2-d0
            done: true  # 2026-07-23, B99 (runtimed#38) — platform selection + ErrNoPlatformMatch shipped; ledger write-back 2026-08-30
            desc: "Image platform selection (B99 — /go-drainable now): pure PlatformPolicy{Backend, HostRosetta, GuestRosetta, Override} → ordered Candidates() in pkg/image/platform.go (native: darwin/arm64 [+darwin/amd64 iff host Rosetta]; vm: linux/arm64 variant \"\"≡v8 [+linux/amd64 iff guest Rosetta]; Override ⇒ exactly that platform). RemoteFetch becomes candidate-aware: remote.Get → explicit index traversal in candidate order (skip attestation manifests) → single-manifest os/arch verified → sentinel ErrNoPlatformMatch carrying the image's available platforms. Structurally removes ggcr's implicit linux/amd64 default (the latent bug at pull.go:86). Resolved platform recorded via ImageManifest.platform/index_digest. Deliberate divergence registered: upstream runs a mismatched single-manifest image to an exec-format crash; k3sm refuses at pull (divergent-by-design)."
          - id: M11.2-d1
            done: true  # 2026-08-30, B100 (runtimed#76) — Linux dialect over the d7 substrate; whiteouts/collision-fail-closed/ChainID snapshots/ownership sidecar/MergeRunSpec
            desc: "Linux rootfs builder (B100; EXTENDS the M11.2-d7 unpacker in-wave — d7 builds first): OCI whiteouts (.wh.*/.wh..wh..opq), hardlink safety (os.Root.Link, in-root targets), per-layer diffID re-verification before a ChainID-keyed snapshot commit (snapshots/<algo>/<chainid>/rootfs + meta.json, staged+os.Rename), PAX xattrs dropped by default (documented loss: security.capability), device/FIFO/socket skip+count, FAIL-CLOSED case/normalization-collision detection, ownership SIDECAR (path→uid,gid,mode,xattrs; guest apply order chown→chmod→setxattr — chown clears setuid). Snapshot store + vm pod rootfs dirs on a DEDICATED CASE-SENSITIVE APFS VOLUME, co-located (cross-volume clonefile degrades to byte-copy) — m11-plan Resolution 8. MergeRunSpec (image config merged per the k8s four-quadrant table + $(VAR) expansion; kubelet-verbatim runAsNonRoot numeric-USER rule) with the DISCRIMINATOR: absolute-path image ⇒ M0 host-binary convention; OCI ref ⇒ pull+unpack+merge — replaces the resolveBinary M1 placeholder (shippable native-path increment)."
          - id: M11.2-d2
            done: true  # 2026-08-31, B227+B228 (runtimed#90) — pkg/vmhost + cmd/k3sm-vmhost + pkg/guestagent + the vsock listener; CreateVM still returns ErrVMBootNotImplemented by design (the boot wiring is the hardware-gated wave)
            desc: "pkg/vmhost + cmd/k3sm-vmhost (one per VM pod, dumb by design): reads vmhost.spec.json (guest/v1 proto-JSON), pure-Go MachineConfig assembly (table-tested anywhere) realized by a one-way vz_darwin.go translator — VZLinuxBootLoader (pinned kernel + initramfs), virtiofs root (all rootfs shares READ-ONLY AT THE VZ DEVICE; guest composes writability via overlay), NAT-only virtio-net (deterministic MAC from pod_id; never bridged), one vsock device, Rosetta share when enabled, virtio console → size-capped console.log (deleted with the pod), entropy, balloon attached-unused. Proxies the RUNTIMED-PRIVATE run/vm/<pod>/agent.sock (NOT the poddir; no pod SBPL ever allows any agent.sock — table-tested invariant) ↔ guest vsock; vmhost never parses the gRPC. machineRunner fake for -race lifecycle tests (TestMachineConfigFromSpec, TestLifecycleStateMachine, TestProxyRelayShutdown — named, not say-so). ENTITLEMENT: only vmhost carries com.apple.security.virtualization (dev = ad-hoc codesign --entitlements; release = human-gated B110). Available() retarget is ADDITIVE: macOS≥26 ∧ vzSupported ∧ vmhost present ∧ statically entitled ∧ SecStaticCodeCheckValidity — one probe, both consumers (SelectBackend + the B1 condition). Seatbelt confinement of vmhost itself decided by spike S1(4)/S3(6), else documented residual."
          - id: M11.2-d3
            done: false
            desc: "Guest artifacts (B108 mechanism / B111 human-gated producer): EnsureGuestArtifacts — INSTALL-TIME/daemon-start ensure, never lazy-on-first-pod (the M7.1-d1 no-runtime-fetch posture; divergence from full bundling named — kernel+initramfs out of the bottle for size, verify-then-use at install; air-gap = pre-seed); sha256 PINNED IN CODE, verify-then-delete-on-mismatch; sha-keyed retention of prior versions (offline rollback); VMArtifactsAvailable condition. initramfs = cpio-wrapped k3sm-guest-init (pure-Go newc writer, BYTE-DETERMINISTIC: zeroed mtimes/uid/gid, sorted entries — golden-tested); composed at RELEASE TIME (goreleaser member; B108's pin covers the released pair). --guest-artifacts-dir is DEV-MODE-ONLY: refused fail-fast under launchd, argv-only, node condition while active."
          - id: M11.2-d4
            done: true  # 2026-08-30, B102 (runtimed#75) — pkg/guestinit plan producers + cmd/k3sm-guest-init + the portable PID1 reaper (-race suite); linux cross-build in repo ci
            desc: "pkg/guestinit + cmd/k3sm-guest-init (B102): pure plan producers (mount plans incl. per-container /etc bind set + musl-safe search list, Rosetta binfmt line — flags POCF, F-rationale recorded, user resolution, sidecar apply, tmpfs-upper size bound) darwin-testable; the PID1 reaper + Stop(grace) state machine GOOS-PORTABLE behind a proc seam with a NAMED -race suite (the milestone's most concurrency-sensitive code); cmd/ is the thin GOOS=linux CGO=0 executor. Boot: mounts → guest-spec.json → per-container overlay (virtiofs lower RO + bounded tmpfs upper, metacopy=on) → sidecar → binfmt → hostname → /etc binds into EVERY container rootfs (chroot shadows guest /etc — kubelet contract) → eth0 DHCP (pure-Go; the agent-Health lease is the SINGLE live-address authority — the 'runtimed reconciles from the attachment' comments in vm.go/guest.go are retired; closes darwin-net M5.2 caveat (a)) → init then main containers (cgroup2 leaf, chroot, workdir, k8s uid/gid precedence, fsGroup supplemental + idmapped volume mounts) → reap → Stop: TERM→grace→KILL→sync→poweroff. Guest link MTU ≤1380 if cross-node is ever claimed. Cross-build + vet lane wired into runtimed's per-CI gate."
          - id: M11.2-d5
            done: true  # 2026-07-29, B106 (runtimed#40) — virtiofs share plans + share-set invariants; ledger write-back 2026-08-30 (fsGroup/idmap request plumbing only; the guest-side apply stays S3(2)-contingent)
            desc: "Volumes into guests (B106): hybrid share model — projected/Secret/ConfigMap/downwardAPI via the EXISTING mount.Materialize → dedicated READ-ONLY k3sm.proj share (RO at the VZ device); emptyDir default under the RW k3sm.vols share; medium:Memory = guest tmpfs with sizeLimit (never crosses virtiofs). Share-set invariants table-tested: per-pod roots inside the owning pod dir; pairwise-disjoint (k3sm.vols never an ancestor of the projected tree); per-container bind visibility; credentials never on a RW share. fsGroup = guest-side idmapped mounts (mount_setattr MOUNT_ATTR_IDMAP: host _k3sm owner → effective container uid/fsGroup — zero chown anywhere; fsGroupChangePolicy moot) CONTINGENT on spike S3(2) — Apple's virtiofs device must advertise FUSE idmap support; kernel ≥6.12 is necessary-not-sufficient; NO chmod fallback is encoded (banned dual path — if S3 disproves idmap, a human-reviewed re-plan). ALL guest hostPath (Directory shares AND File snapshots) FAIL-CLOSED REJECTED until human-gated B98 lands; /var/lib/k3sm denied unconditionally."
          - id: M11.2-d6
            done: true  # 2026-08-30, B101 (runtimed#74) + B107 (runtimed#77) — vm Exec/Logs bridge over the private agent.sock + the stats/kill-reason fork (agent truth, no ticker)
            desc: "vm-pod verbs + metering (B101/B107): Exec/GetLogs/ListPodStats route vm pods to a guest/v1 client on the private agent.sock behind an injectable transport seam (bufconn — full RPC round-trips, no VM); Exec asserts exit-code round-trip + stream demux/close. Stats ON DEMAND at ListPodStats (or ≥30s heartbeat), NEVER the 1 Hz supervisor tick (no OOM race — VZ memorySize is the hypervisor-enforced ceiling); agent unreachable ⇒ stats omitted + condition, never zeros-as-data; agent responses are UNTRUSTED guest data (bounded reads, no host transitions beyond that pod's status). OOMKilled derives from agent ContainerEvents ONLY — the host rusage sampler never emits it for a vm pod; vmhost proc_pid_rusage feeds node-level accounting only (the B24 three-figures doctrine extended). LIFECYCLE-ACROSS-RESTART contract (m11-plan Resolution 5): vmhost dies with the daemon; Stop(grace) clamped inside the plist ExitTimeOut:45 (+Warn); the startup reconcile sweeps orphaned vmhosts + stale VM pod dirs; boot deadline (VM created → Health within N s else legible pod failure); RestartContainer on a vm pod → typed UNIMPLEMENTED (provider recreates the pod under CrashLoopBackOff); PGDATA crash-consistency documented (WAL recovery)."
          - id: M11.2-d7
            done: true  # runtimed#72, 2026-08-29 — a6 green unprivileged (materialize-then-exec)
            desc: "OCI-layer unpacker (the SUBSTRATE — built FIRST within this wave; re-homed here 2026-07-11 from the MLX slice, verbatim scope; m11-plan R17): pkg/image — a per-image unpacked content-addressed tree (digest+policy-keyed), applied via a containment-checked tar apply (symlink/hardlink-safe, com.apple.quarantine-xattr discipline per clone.go, same-APFS-volume placement per cache.go), wired into pkg/runtime.createPod via MaterializeTree. Today only compressed layer blobs exist under blobs/<algo>/<hex> and resolveBinary is the M1 materialization placeholder — this is the substrate d1 (Linux rootfs builder) extends in-wave, the MLX tree-signing walks (that slice consumes it via its depends edge), and the images milestone's native semantics consume."
          - id: M11.2-d8
            done: true  # 2026-08-31 — GuestNetworker seam landed; the netcfg parameter was REMOVED from createPod/createVMPod so the type assertion is the sole production source (two authorities for one value had no stated precedence)
            desc: "Guest-network consumer seam (the runtimed half of B6; filed 2026-08-30 — the deliverable M11.4-d4 has nothing to plug into, which is exactly what re-blocked B6): pkg/runtime.Deps.Network gains an OPTIONAL consumer interface mirroring the existing NetworkReconciler pattern — GuestNetworker{ GuestNetwork(podID string) (sandbox.GuestNetworkConfig, bool) } — type-asserted at createPod so the vm branch fetches the provider-produced config instead of server.go's literal sandbox.GuestNetworkConfig{}. NO new proto field (m11-plan R3 honored: the provider is the producer/mapper), NO new Deps field, fake on both sides. sandbox.GuestNetworkConfig additionally gains STRUCTURED Nameservers/Searches/Options alongside the rendered ResolvConf: guest/v1 GuestSpec.resolv_conf is structured precisely so the guest can render it musl-safely (alpine ignores options ndots), and a rendered-string-only carrier would force the host to re-parse its own output — the round-trip the proto exists to prevent. Teardown stays PROVIDER-side via releasePodNetwork (M10.1's no-auto-release rule: runtimed must not release what it did not allocate; two owners is how double-release ships)."
        acceptance:
          - id: M11.2-a1
            met: false
            check: "platform selection table green incl. the NEGATIVE no-linux/amd64-default regression; rootfs builder fixtures green (whiteout/opaque, hardlink escape, setuid re-mode, capability-tagged documented-loss, case-collision fail-closed); MergeRunSpec four-quadrant + discriminator table; all -race"
            method: unit
            test: pkg/image.TestManifestListPlatformSelection + pkg/image.TestLinuxRootfsWhiteoutOpaqueApply
          - id: M11.2-a2
            met: false
            check: "vmhost MachineConfig golden + lifecycle state machine (machineRunner fake) + proxy relay shutdown races under -race; Available() additive-conjunction table incl. broken-signature ⇒ unavailable; artifact ensure: corrupted-byte mismatch-reject, retention, launchd-mode --guest-artifacts-dir refusal (fake fetcher, zero network)"
            method: unit
            test: pkg/vmhost.TestMachineConfigFromSpec + pkg/vmhost.TestLifecycleStateMachine + pkg/sandbox.TestVMAvailableRequiresEntitledHelper
          - id: M11.2-a3
            met: false
            check: "guest-init plan tables + the PID1 reaper -race suite green on darwin; GOOS=linux GOARCH=arm64 CGO_ENABLED=0 build+vet lane green in per-repo CI; cpio writer golden byte-deterministic"
            method: unit
            test: pkg/guestinit.TestMountPlan + pkg/guestinit.TestPID1ReapAndForward
          - id: M11.2-a4
            met: false
            check: "createVMPod spine with fake vmhost + fake agent: volume share-set invariants (per-pod roots, disjoint, device-RO, per-container visibility, credentials-never-RW, medium:Memory-not-shared, hostPath fail-closed rejected), exec exit-code round-trip, stats no-ticker + omit-with-condition, OOMKilled-from-events-only"
            method: unit
            test: pkg/runtime.TestCreateVMPodVolumeSharePlan + pkg/runtime.TestVMPodExecRoutesToGuestAgent + pkg/supervisor.TestVMPodStatsFromGuestAgentNotRusage
          - id: M11.2-a5
            met: false
            check: "the k3sm product binary's PACKAGE and LINK graphs exclude github.com/Code-Hex/vz: go list -deps ./cmd/k3sm carries neither vz nor runtimed/pkg/vmhost, go mod why -m github.com/Code-Hex/vz/v3 reports does-not-need, and otool -L on the built binary links no Virtualization framework (canaries in k3sm/hack/ci.sh); a runtimed-side go list -deps guard over pkg/{runtime,sandbox,image,mount,supervisor} fires in the PR that adds a bad import. RECORDED EXCEPTION: k3sm/go.sum carries a /go.mod-only hash line for Code-Hex/vz (module-graph pruning loads runtimed's go.mod), asserted to carry no bare h1: zip line. CORRECTED 2026-08-30: the prior text said module graph, but go list -deps is a PACKAGE-graph tool and the literal module graph cannot be kept clean while vmhost lives in the runtimed module (a deliberate siting decision — one version pin with apis/guest/v1, not two). internal/spicanary byte-unchanged; live VM boot / Rosetta / virtiofs-attach legs are the M11.5 lab gate (hack/lab/m11.sh), never auto-greened"
            method: build
          - id: M11.2-a6
            met: true  # 2026-08-29 — runs unprivileged on the dev host; layer-order-sensitive fixture
            check: "materialize-then-exec integration test — the d7 unpacker produces an unpacked tree that createPod materializes via MaterializeTree and execs argv[0] out of a multi-layer image (the acceptance re-homed with the deliverable, 2026-07-11)"
            method: integration
          - id: M11.2-a7
            met: true  # 2026-08-31 — FILED WITH THE DELIVERABLE: d8 previously had no acceptance criterion at all (a1-a6 name no guest-network test), so it had no gate that could honestly flip it done. Non-vacuity mutation-checked: forcing the type assertion to miss, and ignoring the comma-ok, each turn a named test red.
            check: "guest-network consumer seam: a Deps.Network implementing the optional GuestNetworker has its config reach the VM backend verbatim — asserted on the VMSpec the backend RECEIVES, never on the fake's own input; a Network that does not implement the seam, and one reporting no config for this pod, both fall back to the inert zero value and log a DISTINCT reason; a host-process pod never consults the producer; all -race"
            method: unit
            test: pkg/runtime.TestCreateVMPodUsesGuestNetworkerWhenPresent + pkg/runtime.TestCreateVMPodFallsBackWhenGuestNetworkerAbsent

  - id: M12
    title: Images & build engine (runtimed slice — local image index, pull-policy honor, policy-gated tree signing)
    status: todo
    depends_on: []
    notes: >-
      docs/m12-plan.md is authoritative (Phase C encoded from it). CONSUMES M11.2-d7 (the
      OCI-layer unpacker — re-homed 2026-07-11) + the MLX slice's tree signing + queue items
      B99 (platform selection) and B100
      (snapshot store + MergeRunSpec + the OCI-ref discriminator) — those surfaces are
      owned THERE; an M12 builder finding itself editing them stops and reports. Hard cut.
    subphases:
      - id: M12.1
        title: local image index + imagePullPolicy honor + pull-failure classification + policy-gated tree signing
        status: todo
        depends_on: [runtimed:M8.2, apis:M12.1]
        deliverables:
          - id: M12.1-d1
            done: false
            desc: "Local image index: ref→resolved-digest keyed (reference × platform, per ImageManifest.platform/index_digest); self-authenticating on read-through. Serves IfNotPresent/Never decisions, the image CLI's ls (queue item B117 links this package in-process), and the cache GC's refcounting. RE-SCOPED 2026-07-30 (operator ratification): this deliverable owns the IMAGE BUCKET SCHEMA only, not the whole store. The store itself is a context-neutral pkg/metastore (queue item B128) exporting transaction plumbing; the pod bucket is written exclusively by a pkg/runtime-owned writer, because pkg/runtime PRODUCES pod facts and the GC consumes them — owning the store here would force pkg/runtime to import pkg/image, an inversion. PREREQUISITE, previously unfiled: the declared key does not exist — runtime.proto still reserves the 100-149 band and ImageManifest has no platform/index_digest fields (queue item B127 carves them). COMMIT MECHANISM SUBSTITUTED: bbolt, not staged+os.Rename — the GC's reachability walk may span a pull commit and needs a stable snapshot, which a whole-file rewrite cannot give a concurrent reader. Note bbolt grows monotonically without returning freed pages, on the volume kine's state.db shares. The store is root-owned 0700 with an SBPL directory deny single-sourced from pkg/sandbox (a pod that can write GC roots re-introduces attacker-controlled provenance). B100's per-snapshot meta.json + ownership sidecar stay PER-TREE and do not merge in — they ride a separate case-sensitive APFS volume, so one bbolt file cannot sit beside both."
          - id: M12.1-d2
            done: false
            desc: "Puller honors the stamped policy: Always=re-resolve; IfNotPresent=index-hit with ZERO registry traffic (a warm cache runs offline); Never=fail-if-absent with NO pull attempt; UNSPECIFIED=legacy pull-through. Pull failures are CLASSIFIED for the provider's waiting-reason taxonomy (invalid ref / auth / not-found / platform mismatch) and NEVER fail CreatePod wholesale — the container parks Waiting (queue item B119 consumes the classification)."
          - id: M12.1-d3
            done: false
            desc: "Tree signing is ADHOC_OK-gated exactly like the single-binary gate (under require-signed/require-notarized: NEVER sign, check as-pulled — no silent signature downgrade); the per-binary gate fires on the post-merge argv[0]; signature policy becomes pod-selectable with ADHOC_OK the default. SBPL invariant: the per-pod clonefiled rootfs lives UNDER the pod's data volume (covered by the existing re-allow) — never a read-allow over the shared snapshot store."
        acceptance:
          - id: M12.1-a1
            met: false
            check: "policy×cache-state table green incl. UNSPECIFIED=legacy and an offline IfNotPresent warm-cache row (fake fetcher counts zero registry calls); presence-by-reference decidable offline via the index"
            method: unit
          - id: M12.1-a2
            met: false
            check: "policy-gated tree-sign table: ADHOC_OK signs the materialized tree; require-signed/require-notarized never sign and verify as-pulled; the live materialize-then-exec-under-profile leg rides the M8.2 integration gate"
            method: unit
---

# runtimed — Phase roadmap

> Per-repo slice of the k3sm milestones. The YAML frontmatter above is **authoritative**; this prose
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

### M2.8 — consume the `apis:M2.2` typed resource contract + serve `RestartContainer`/`ListPodStats` ✅
The runtimed half of the M2.2 consumer swap: replace the M2.5 annotation seam with the typed `PodBox`
fields and serve the two RPCs `apis:M2.2` appended.
**Deliverables**
- ✅ `M2.8-d1` `pkg/runtime/metrics.go`: `podMemoryLimitBytes` reads the typed **`PodBox.memory_limit_bytes`**
  (the typed field **wins** when set) and falls back to the legacy `k3sm.io/memory-limit-bytes` annotation
  **only** when it is unset — a **transitional** fallback so there is **no transition window** regardless of
  land order (the `k3sm` provider starts writing the typed field in a sibling PR). `qos_class`/`rlimits` ride
  the same band but their **enforcement is deferred + documented** (`docs/resources.md`): CPU-QoS application
  needs a contention-policy decision, and `setrlimit` must extend the M2.3 security-critical
  `RunLaunchSequence` (a step ordered before `setuid`) with its own ordering test — neither is bolted on
  untested here.
- ✅ `M2.8-d2` `pkg/runtime/restart.go`: serve **`RestartContainer`** — terminate the named container's
  process group within the grace window (reuses the M2.4 `supervisor.GracefulStop`), wait for the kqueue
  reaper, then **re-spawn from the same spec via the existing `startContainer` path** (same SBPL profile +
  M2.3 exec-shim uid drop + mounts), incrementing `restart_count` and recording `last_termination_state`. A
  per-container `restarting` guard keeps the transient termination from flipping the pod phase / cancelling
  the sampler; the re-spawn supervision is detached from the RPC ctx so it outlives the call. Unknown
  pod/container → structured `NOT_FOUND`. `restart_count` + `last_termination_state` join the
  `ContainerStatus` mirror.
- ✅ `M2.8-d3` `pkg/runtime/stats.go`: serve **`ListPodStats`** — map the M2.5 sampler's `ri_phys_footprint`
  onto the apis `PodStats`/`ContainerStats`/`MemoryStats` (pod-level from `PodMetrics`, per-container from the
  `Footprinter` at request time). Empty `pod_id` = all **metered** pods (the Summary shape); unmetered/unknown
  omitted; CPU left unset (best-effort QoS).

**Acceptance (exit gate)**
- ✅ `M2.8-a1` limit read from the typed field; annotation fallback when unset; typed wins when both set (and
  the typed limit drives the OOM path) — `pkg/runtime.TestMemoryLimitFromTypedField` +
  `TestCreatePodOOMKilledTypedLimit`.
- ✅ `M2.8-a2` `RestartContainer` stops+relaunches via the `startContainer` path and bumps `restart_count`;
  `NOT_FOUND` for an unknown pod/container (the live confined re-exec is the `m2.sh` e2e) —
  `pkg/runtime.TestRestartContainerReExecs`.
- ✅ `M2.8-a3` a sampled pod's footprint maps onto `PodStats.containers[].memory.working_set_bytes`; empty
  `pod_id` returns all metered pods; an unsampled pod is omitted — `pkg/runtime.TestListPodStatsMapsFootprint`.

## M3 — APFS-backed persistent volume (PV/PVC) ✅
**Cross-repo dep:** `apis:M3.1` (the PV/PVC volume source on `PodBox` —
`Volume.persistent_volume_claim` + the plain-Go `k3sm.io/apis/storage/v1` provisioner contract;
**NodePort needs no `apis` change**). The multi-node join/mesh work is `k3sm` (join/token) +
`darwin-net` (wireguard); runtimed's M3 contribution is the **APFS-backed persistent volume**.

### M3.1 — APFS-backed PV/PVC volume materialization ✅
**Deliverables**
- ✅ `M3.1-d1` `pkg/volume` (NET-NEW): a `volume.Binder` materializes a PVC-backed volume as a **stable
  per-claim dir** at `storagev1.LocalPathClass.DataDir(namespace, claimName)` on the **same APFS volume** as
  `/var/lib/k3sm` — the production Binder roots `BasePath` at `<Config.Root>/storage`, a **sibling of the
  pods root** (shares the volume kine's SQLite uses, but is **not** under the pod dir). **Empty-created**
  (`os.MkdirAll`, never `clonefile`) on the hot path; keyed by `(namespace, claimName)` so the claim is
  stable across pods/restarts. `Bind` **symlinks** each container mount into the pod rootfs (no mount
  namespace) so the confined pod reaches the dir at its mount path. Capacity is **not** enforced vs APFS
  free space (over-commit → write-time `ENOSPC`). `pkg/mount.Materialize` **skips** PVC sources.
- ✅ `M3.1-d2` `clonefile` (via the `pkg/image` `Cloner` → `image.MaterializeTree` CoW seam) is used
  **only to seed** a fresh PVC from a StorageClass template, gated by a consumer-side `TemplateResolver`
  seam (nil / `ok=false` ⇒ empty-create; the provider supplies the template, tests fake it). **Seed-once**:
  a reused dir is never re-seeded and the `clonefile` path is **never** on the empty-PVC hot path.
- ✅ `M3.1-d3` the PV lifecycle is **decoupled from pod-dir teardown**: the PV dir lives under
  `<Root>/storage` (sibling of `<Root>/pods`), so `DeletePod`'s `removePodDir` (which only removes
  `<Root>/pods/<id>`) never touches it (**ReclaimPolicy Retain** — no volume-delete RPC, no root-`rmdir`).
  The pod-side symlink is removed but `os.RemoveAll` unlinks it **without following**, so the target
  survives. `createPod` adds each PV mount root to the pod's SBPL scope via the NET-NEW
  `sandbox.GenerateOptions.WritePaths` (read+write) / `ReadPaths` (read-only), validated against the M2.2
  protected deny-set.

**Acceptance (exit gate)**
- ✅ `M3.1-a1` a PVC-backed dir is created empty on the same APFS volume as `/var/lib/k3sm` (the
  `<Root>/storage` sibling), stable across calls for the same `(namespace, claim)`, and the PV mount root
  is granted `file-write*` in the pod's SBPL scope (a read-only PVC gets read but not write) while the
  protected denies still win — `pkg/volume.TestPVCMaterializeStableDir` + `pkg/sandbox.TestPVCInSBPLWriteScope`
  (the live Seatbelt-confined write is the `m3.sh` e2e).
- ✅ `M3.1-a2` data written to the PV survives the pod-teardown path (the PV dir is **not** removed with
  the pod dir) while the pod rootfs **is** removed; a fresh pod for the same claim reuses the dir with prior
  data intact; a template-seeded PVC is a clone (seed-once), an unseeded one is empty —
  `pkg/runtime.TestPVCSurvivesPodTeardown` + `pkg/volume.TestPVCSeedOnce` (the live `clonefile` seed is the
  `m3.sh` e2e).

## M4 — Hardening + packaging hooks ⬜
Headline: `uidjail` fallback `Backend` impl; participate in the codesign/notarize entitlement set;
macOS-arm64 CI for the cgo build; node-conformance-subset hooks.

## M5 — `vm` sandbox backend (Virtualization.framework Linux micro-VM) 🟡
**Cross-repo dep:** `apis:M5.1` (the `runtime.k3sm.io` handler-config mapping `runtimeClassName: vm` →
`SANDBOX_BACKEND_VM`, **landed** — the provider stamps `SandboxProfile.backend` + the `vm_vcpus` /
`vm_memory_bytes` sizing fields). The committed direction for the Linux-only components stockkitty needs
(Postgres/pgvector and the amd64 images): a Virtualization.framework Linux micro-VM behind the
**existing swappable `sandbox.Backend` interface**.

### M5.1 — Virtualization.framework Linux micro-VM backend 🟡
**Strategy: hard cut** — the `vm` backend is additive behind the existing swappable `sandbox.Backend`
ladder; the host-process Seatbelt path is **byte-unchanged** (golden SBPL + existing tests stay green);
one signed binary, no proto/CRD/datastore change beyond the already-landed `apis:M5.1`. The live VM boot
is **lab-gated** (needs a VZ-capable, entitled Mac), not phased.

This chunk delivers the **verifiable foundation + the VZ scaffold**; the live boot is the lab remainder.
**Deliverables**
- ✅ `M5.1-d1` `pkg/sandbox`: a `vm` `Backend` **cgo SCAFFOLD** behind the swappable `sandbox.Backend`
  interface, gated by a **SAFE** `Available()` probe — darwin OS-gate **AND** `+[VZVirtualMachine
  isSupported]` **AND** a `com.apple.security.virtualization` static-code-entitlement check (via
  `Security.framework` `SecCodeCopySigningInformation`), both wrapped in `@try/@catch` + `@autoreleasepool`
  in the isolated Obj-C shim (`vm_darwin.m`/`vm_darwin.h`). It **NEVER** constructs/boots a VM (that raises
  an uncaught `NSException` → SIGABRT on a non-entitled host). `vm_darwin.go` (`darwin && cgo`) links
  `-framework Virtualization/Foundation/CoreFoundation/Security`; `vm_other.go` (`!(darwin && cgo)`) stubs
  the probes false so the **pure-Go (`CGO_ENABLED=0`) lane is unbroken**. `CreateVM` is a documented
  **lab-gated stub** (`ErrVMBootNotImplemented`). Registered as the consumer-side `runtime.VMBackend` so
  `pod.go`/`SelectBackend` query it. **VZ is a PUBLIC framework — `internal/spicanary` is deliberately
  UNCHANGED** (not a `libsandbox`/`memorystatus` SPI canary case).
- ⬜ `M5.1-d2` **LAB-GATED remainder** (needs a VZ-capable, entitled Mac): the live VM boot
  (`VZVirtualMachineConfiguration` on a per-VM **serial dispatch queue** behind an opaque handle,
  VZ-delegate→exit / SIGTERM→ACPI `requestStop`); the `cmd/k3sm-vmhost` helper-process lifecycle; the
  OCI-Linux-rootfs→bootable-root builder (the payload is a Linux rootfs, not arm64 Mach-O — codesign is
  N/A; digest-pin tenant images); and VM metering (the memory limit → VZ `memorySize`; working set from a
  **guest agent**, NOT `proc_pid_rusage`).
- ✅ `M5.1-d3` `pkg/sandbox` + `pkg/runtime`: **FAIL-CLOSED backend dispatch** (the verifiable safety fix).
  `sandbox.SelectBackend` now takes the **requested** backend (`SandboxProfile.backend`): a requested `vm`
  backend that is **unavailable** returns the typed **`ErrBackendUnavailable`** (FAIL CLOSED — **never**
  downgrades to the weaker Seatbelt rung, on which a Linux image cannot even exec); `UNSPECIFIED` (the
  host-process default) walks the existing host-OS-gated Seatbelt ladder (degrade-UP-only, unchanged); an
  explicit Seatbelt pin is honored-or-refused. `pkg/runtime.createPod` threads `sp.GetBackend()` + queries
  the registered `vm` backend's `Available()` (**was hardcoded `vmAvailable=false`, discarding the selected
  rung**) and **routes** a selected `vm` rung to `createVMPod`, which **bypasses** the host-process Mach-O
  steps (`resolveBinary` / `gateSignature`+ad-hoc-codesign / SBPL `SandboxApply` / lo0 networking).

**Acceptance (exit gate)**
- ⬜ `M5.1-a1` a Linux image runs under the `vm` backend on a **capable, entitled host** (`Available()`
  reports present only when VZ + the entitlement are available) — the **live boot** (lab-gated).
- ✅ `M5.1-a2` the SPI symbol-canary set is **unchanged** by M5 (VZ is public, not an SPI) —
  `internal/spicanary` is byte-unchanged; `spicanary.TestSymbolsResolve` + `TestResourceSymbolsResolve` green.
- ✅ `M5.1-a3` the fail-closed dispatch + `vm` routing are **unit-proven** — `SelectBackend` honors the
  requested backend and fails a `vm`-requested pod **closed** when the `vm` backend is unavailable (never
  downgrades); `UNSPECIFIED` uses the ladder; a `vm`-routed pod **bypasses** the host-process steps while a
  host-process pod still drives them (byte-unchanged) —
  `pkg/sandbox.TestSelectBackendVMRequestedUnavailableFailsClosed` + `TestSelectBackendVMRequestedAvailable`
  + `TestSelectBackendUnspecifiedUsesLadder` + `pkg/runtime.TestCreatePodVMRoutingBypassesHostProcessSteps`.
- ✅ `M5.1-a4` `VMBackend.Available()` is **false** on a host without the entitlement and does **not** crash
  (the safe probe never constructs/boots a VM); the `CGO_ENABLED=0` lane builds via the `vm_other.go` stub —
  `pkg/sandbox.TestVMBackendAvailableFalseWithoutEntitlement` + `TestVMBackendAvailableComposition`.

## M7 — Public CI workflow + SkipUnless conversions ⬜
**Cross-repo dep:** `apis:M7.2` (the DAG-legal home for the shared `k3smtest.SkipUnless(t, cap)` helper +
its owned capability taxonomy — `runtimed`, `darwin-net`, and `k3sm` all import it; a leaf copy would
drift or force a sideways import). runtimed's M7 slice is the **release-engineering
plumbing**: a public CI workflow + the skip-site conversion, not a runtime change.

### M7.1 — public CI workflow + SkipUnless conversions ⬜
**Strategy: hard cut** — additive release infrastructure (a thin workflow, a mechanical conversion, a
README header); no runtime/proto/datastore change. One signed binary.
**Deliverables**
- ⬜ `M7.1-d1` `.github/workflows/ci.yml`: a **thin** wrapper over the existing `hack/ci.sh` (no logic
  duplication) on **macos-15 arm64** runners, `CGO_ENABLED=1`; unit + `-race` + the `internal/spicanary`
  **symbol-canary on every matrix image** (the canary is the runner-macOS-15-vs-target-macOS-26 skew
  tripwire).
- ⬜ `M7.1-d2` convert this repo's raw `t.Skip` integration sites to the **apis-hosted**
  `k3smtest.SkipUnless(t, cap)` helper over the owned capability taxonomy
  (`root`/`lo0`/`utun`/`pf`/`clang`/`apple-gpu`/`macos-26`/`network`); the lint scope is `integration ∥ e2e`
  tags and **no raw `t.Skip`** remains in those files.
- ⬜ `M7.1-d3` `README.md`: a **"part of k3sm"** front-door header (badges, one-line pitch, a workspace
  pointer) refreshing the pre-launch scaffold copy.

**Acceptance (exit gate)**
- ⬜ `M7.1-a1` the PR CI workflow runs **green** on GitHub Actions (macos-15 arm64, `CGO_ENABLED=1`) with the
  symbol-canary executing on every matrix image.
- ⬜ `M7.1-a2` **no raw `t.Skip`** in `-tags integration` (∥ `e2e`) files — every integration skip routes
  through the apis-hosted `k3smtest.SkipUnless` (the lint).

## M8 — MLX: native Apple-Silicon ML serving (runtimed slice) ⬜
**Cross-repo dep:** `apis:M8.1` (the `SandboxProfile` booleans `allow_gpu = 102` / `allow_internet_egress
= 103` and the `GetRuntimeInfoResponse.gpu = 100` `GPUFacts` message, all carved from the reserved bands).
DAG: `M8.1 apis → M8.2 runtimed`. runtimed owns **M8.2 (size L)** — the heaviest M8 sub-phase; product
design `k3sm/docs/DESIGN.md` §5a/§5c, security posture `docs/privilege-model.md`.
**Entry (amended 2026-08-29, operator-directed):** the M11.2 edge is **narrowed to the
`runtimed:M11.2-d7` deliverable only** (d1–d5 need only d7's output — m11-plan R25), so M8.2 does not wait
on the rest of the M11.2 wave; entry is **additionally gated on the recorded S1/S2/S3 findings**
(`k3sm:M8.0`, lab-run).

### M8.2 — Metal SBPL + egress branch + tree signing + GPUFacts ⬜ (L; consumes the M11.2-d7 unpacker)
**Strategy: hard cut** — the new `SandboxProfile` booleans default false (an old runtimed ignores them, an
old provider never sets them — **no** provider↔runtimed phased exception), the proto fields ride the
reserved bands (`apis:M8.1`), and the host-process Seatbelt path + existing golden SBPL fixtures stay
**byte-green**. One signed binary. **RE-HOME (2026-07-11):** the unpacker below moved to
`M11.2-d7` with the Linux-layer re-sequencing (`depends_on: [runtimed:M11.2-d7]` in the frontmatter,
narrowed 2026-08-29);
the spec text is preserved here for the historical record only.
**Deliverables**
- ⬜ ~~`M8.2-d0`~~ → **`M11.2-d7`** **(PREREQUISITE, re-homed)** `pkg/image`: an **OCI-layer unpacker** →
  per-image **unpacked content-addressed tree** (digest+policy-keyed), applied via a **containment-checked
  tar apply** (symlink/hardlink-safe, `com.apple.quarantine`-xattr discipline per `clone.go`, same-APFS-
  volume placement per `cache.go`), wired into `pkg/runtime.createPod` via `MaterializeTree`. Today only
  **compressed** layer blobs exist (`blobs/<algo>/<hex>`) and `resolveBinary` is the M1 materialization
  placeholder, so the **whole M8 product path is blocked on this substrate**; `d3` `AdHocSignTree` walks
  and clonefiles from it.
- ⬜ `M8.2-d1` `pkg/sandbox/metal.go`: the Metal SBPL allow-set behind `allow_gpu`.
  **PRIMARY (R22 — amended 2026-08-29, operator-directed):** Apple's own practice — a single **prefix
  rule** (`(iokit-registry-entry-class-prefix "AGXAcceleratorG")`) plus the S1-derived **mach-lookup +
  shader-cache scope**, covering AGX user-client class variation M1→M4 **without** a per-family table;
  **one prefix-rule golden** fixture. **FALLBACK (S1-evaluated, adopted only if the prefix rule under- or
  over-scopes on the lab rig):** the **per-chip-family data table** (AGX user-client class names vary
  M1→M4) with **per-family goldens** in `pkg/sandbox/testdata`, launch families **scoped to the dev-mac's
  own** for v1 (**Res. 15**). **Res. 14's fail-closed control SURVIVES as the OPERATIVE control:**
  `metal.go`'s per-family Go-side data + the `sandbox_gpu_supported` advertisement gate remain the gate for
  whether a family's GPU surface is reachable; the SBPL prefix is a **static ceiling, not a family
  approximation** — an **unknown/absent family fails closed** (`sandbox_gpu_supported=false` + `metal.go`
  errors on a family miss on the **fallback** path; on the **prefix-rule** path fail-closed keys on the
  **functional probe** of `M8.2-d4`). The shader-cache write scope stays **contract-bounded** (per-pod
  redirect or an enumerated narrow subpath), **not** denial-log-derived (**Res. 11**). Emitted in the
  existing rule order (allows → protected denies → narrow re-allows).
- ⬜ `M8.2-d2` `pkg/sandbox`: the egress branch behind `allow_internet_egress` — **RE-FOUNDED 2026-08-29
  (m8-plan R21, operator-directed) as the API contract, not an SBPL filter.** Per-IP SBPL scoping **does
  not compile on macOS 26** (probe-verified through the real execshim/`libsandbox` path —
  `sbpl.go:382-411`, where network filters accept only `localhost`/`*` hosts). runtimed **consumes**
  `allow_internet_egress` (which **implies `allow_network`** — the pairing is enforced in
  translate/`Validate`) and **emits the documented unfiltered-but-compilable network stanza** — the same
  stanza `allow_network` emits, **golden-pinned** byte-for-byte and matching `sbpl.go`'s ceiling comment;
  a **documented ceiling**, stated in `limitations.md` / `privilege-model.md`. `sandbox.Validate` is
  **re-scoped** to what is expressible — network forms appear **only** when `allow_network ∨
  allow_internet_egress` is set, the implies-pairing holds, and the emitted stanza matches the golden
  **and compiles** (the `TestIntegrationNetworkStanzaCompiles` pattern). The range-based deny set, the
  tier-3 re-allows, and the kine-loopback deny are **retired from M8** (the SBPL half of **Res. 12**/
  **Res. 13** is superseded): **network-layer (PF) enforcement is a FILED FUTURE item (B188,
  darwin-net-owned), NOT an M8 deliverable**; Seatbelt is never claimed as network isolation.
- ⬜ `M8.2-d3` `pkg/image`: **`AdHocSignTree`** beside `AdHocSign`, run **once at materialize time** over
  the **`M11.2-d7`** content-addressed tree; **containment-checked** (lstat, never follow symlinks/hardlinks) and
  **structurally unreachable** under `REQUIRE_SIGNED`/`REQUIRE_NOTARIZED`. `gateSignature`
  (`pkg/runtime/pod.go`) becomes **check-then-sign-only-if-invalid** (no unconditional `-f` re-sign — it
  would de-CoW `argv[0]` every start) and keeps verifying `argv[0]` only per start (**Res. 13**).
- ⬜ `M8.2-d4` **`GPUFacts`** population (field `100`): sysctls + a **functional** Metal compile+dispatch
  probe that **discriminates the VZ paravirtual device** (`MTLCreateSystemDefaultDevice` is non-nil in VZ
  guests incl. GitHub macOS runners — a VM node must never advertise GPU; a **functional compile+dispatch,
  not a nil-check**), the `iogpu` **0-sentinel** + `recommendedMaxWorkingSetSize`, and
  `sandbox_gpu_supported` scoped to the **currently selected backend**.
- ⬜ `M8.2-d5` **contingent / pre-authorized** (`pkg/supervisor`, **Res. 18**, default **not** built): spike
  `S3(5)` verifies the S5-engine process model against the sampler's **leader-PID-only** coverage; a
  **pgid-enumeration** deliverable (`proc_listpids(PROC_PGRP_ONLY, …)`) is **pre-authorized** if the engine
  forks (default — pin the winner single-process at M8.4).

**Acceptance (exit gate)**
- ⬜ `M8.2-a1` **golden SBPL tests** — `allow_gpu` on/off (the prefix-rule allow-set; per-family goldens
  only on the R22 fallback path), the **egress/network stanza byte-pinned** (documented-ceiling form), and
  adversarial formatting rejected by the s-expr-aware `Validate`.
- ⬜ `M8.2-a2` **`AdHocSignTree` table test** with a fake signer + hardlink/symlink escape cases (non-Mach-O
  skip, already-signed skip, policy gating).
- ⬜ `M8.2-a3` **`GPUFacts` fake-seam unit test** — population is unit-proven over a **fake probe seam**:
  the VZ-paravirtual discrimination (functional-probe verdict false ⇒ `metal_available=false` and the
  node-facing fields cleared), the `iogpu_wired_limit_bytes` **0-sentinel**,
  `recommended_max_working_set_bytes` pass-through, and `sandbox_gpu_supported` scoped to the **currently
  selected backend**. (The materialize-then-exec integration acceptance moved to `M11.2-a6` with the
  unpacker re-home — 2026-07-11.)
- ⬜ `M8.2-a4` a **real MLX matmul** (full inference round-trip) under the generated `allow_gpu` profile on a
  GPU dev-mac (integration tier, `k3smtest.SkipUnless(t, "apple-gpu")`).

## Next
M1, M2, and M3 are complete at the **runtimed unit-provable level**. M2 (the reference-workload readiness
milestone) split `k3sm-runtimed` into a root gRPC daemon + grew
`internal/spicanary` (M2.1); volume-mount materialization + validated SBPL extra-path injection (M2.2);
the `setgid→initgroups→setuid` drop + `fsGroup` chown before `sandbox_apply` (M2.3); SIGTERM/grace-timer/
SIGKILL graceful stop raced against the reaper (M2.4); the `proc_pid_rusage` memory sampler → `OOMKilled`
+ `PodMetrics` Summary source (M2.5); imagePullSecret auth confined to the pull client + signature
policy before ad-hoc sign (M2.6); served the `Exec`/`Attach`/`PortForward` streaming RPCs by reusing
the exec-shim confinement seam — live `kubectl exec`/`port-forward` (M2.7); and **consumed the
`apis:M2.2` typed resource contract** — `podMemoryLimitBytes` reads `PodBox.memory_limit_bytes` (annotation
fallback only, transitional), `RestartContainer` re-execs a container via the `startContainer` path
(liveness restart), and `ListPodStats` maps the sampler footprint onto the `PodStats` wire types (M2.8).

**Two milestone-gate items remain outside runtimed's per-repo `status: done`** (ROADMAP §phase-gate #2/#3,
the orchestrator's responsibility): the workspace `k3sm/hack/acceptance/m2.sh` **root e2e** (real
signals/uid/registry/OOM under a real memory limit), and the **Wave-3 `k3sm` provider wiring** — serve the
kubelet Summary endpoint from `ListPodStats`, drive `RestartContainer` from the liveness-probe runner,
implement the `CredentialResolver` (docker-config Secret → `image.RegistryCredential`) and the
`mount.Resolver`, derive `DeletePodRequest.grace_period_seconds` (applying the k8s 30s default), and
**write the typed `PodBox.memory_limit_bytes`/`qos_class`/`rlimits`** (the `k3sm.io/memory-limit-bytes`
annotation is now only runtimed's transitional fallback). **apis follow-up landed:** `apis:M2.2` added the
typed `PodBox` resource fields + the `PodStats`/`ContainerStats`/`MemoryStats` Summary messages + the
`ContainerStatus.resources` mirror + the `RestartContainer`/`ListPodStats` RPCs, all consumed here.
**Deferred runtimed follow-ups** (own sub-phase + acceptance test): `rlimits` via `setrlimit(2)` in the
M2.3 launch sequence, and `qos_class` best-effort CPU-QoS application.

**M3 is complete** (runtimed slice): `pkg/volume` materializes a PVC-backed volume as a **stable per-claim
dir** on the `<Root>/storage` APFS sibling (empty-create, **seed-once** from a StorageClass template via
the `clonefile` Cloner), symlinks it into the pod rootfs, and the dir is **lifecycle-decoupled** from
pod-dir teardown (`removePodDir` only touches `<Root>/pods/<id>` — ReclaimPolicy Retain); `createPod` adds
the PV mount root to the pod's SBPL scope via the new `sandbox.GenerateOptions.WritePaths`/`ReadPaths`,
validated against the M2.2 protected deny-set (M3.1). **Outside runtimed's per-repo `status: done`** (the
orchestrator's milestone gate): the multi-node join/mesh/NodePort/provisioner work in `k3sm` +
`darwin-net`, the workspace `k3sm/hack/acceptance/m3.sh` root/lab e2e (live Seatbelt-confined PV write +
real `clonefile` seed), and the Wave-3 `k3sm` provider wiring (the local-path provisioner that creates the
PV/PVC objects + the `TemplateResolver`, if a class carries a seed template). M5 adds the
Virtualization.framework `vm` backend for Linux images.

## M11 — Linux containers & multi-arch (runtimed slice) 🔩⬜
The XL heart of M11 (`docs/m11-plan.md` is authoritative; encoded 2026-07-10). **Absorbs and
supersedes the `M5.1-d2` lab remainder** (live VM boot, `k3sm-vmhost`, the OCI-rootfs→bootable-root
builder, VM metering, entitlement split). **Hard cut** — additive beside the fail-closed
`SANDBOX_BACKEND_VM` fork; the host-process spine stays byte-green; **no VM outlives the binary
version that booted it** (vmhost children die with `io.k3sm.server` — the invariant that keeps hard
cut truthful for the two new cross-process contracts). `Code-Hex/vz` confined to `pkg/vmhost`
(go-list-deps canary — the k3sm product binary never links it); `internal/spicanary` byte-unchanged.

### M11.2 — platform selection + unpacker + Linux rootfs + vmhost + guest init/agent + volumes + metering ⬜ (XL)
**Cross-repo dep:** `apis:M11.1` (guest/v1 + platform fields). The OCI-layer unpacker is
**owned here as `M11.2-d7`** (re-homed 2026-07-11; built FIRST in-wave — d1 extends it; the MLX
slice consumes it via its `depends_on: [runtimed:M11.2]` edge). RE-SEQUENCED PRE-LAUNCH per the
authoritative plan doc — ships functional-EXPERIMENTAL at v0.1.
**Deliverables** — see the frontmatter `M11.2-d0…d7` for the binding detail: d0 platform selection
(B99, drainable now — fixes the silent linux/amd64 default); d1 Linux rootfs builder + ownership
sidecar + case-sensitive-APFS snapshot volume + `MergeRunSpec` (B100 — also completes the native
image path); d2 `pkg/vmhost`/`cmd/k3sm-vmhost` (Code-Hex/vz; entitled helper; additive `Available()`
retarget incl. `SecStaticCodeCheckValidity`; private `agent.sock`); d3 guest artifacts (install-time
ensure, sha-in-code, retention, `VMArtifactsAvailable`; dev-only `--guest-artifacts-dir` refused
under launchd; producer = human-gated B111); d4 `pkg/guestinit` + `cmd/k3sm-guest-init` (GOOS-portable
`-race`'d PID1 reaper; per-container /etc binds; Rosetta binfmt; DHCP with agent-Health as the single
live-address authority); d5 volumes (share-set invariants; fsGroup via idmapped mounts contingent on
S3(2); **guest hostPath fail-closed until B98**); d6 vm-pod exec/logs/stats + the
lifecycle-across-restart contract (Stop ≤ ExitTimeOut, orphan sweep, boot deadline,
OOMKilled-from-events-only, restart = whole-pod recreate).
**Packaging deliverables** (with k3sm M11.4, m11-plan Resolution 9): goreleaser second build entry
(`dir:`-based; `cmd/k3sm-vmhost` stays here), archive membership + install path, the bidirectional
entitlement assert ("vmhost carries exactly `com.apple.security.virtualization`, never the
code-running trio"), the brew source-build entitlement step, release-time initramfs composition.
`doc.go` for `pkg/vmhost` + `pkg/guestinit`.
**Acceptance (exit gate)** — frontmatter `M11.2-a1…a5`; the live boot/Rosetta/virtiofs legs are the
M11.5 lab gate (`hack/lab/m11.sh`), never auto-greened.
