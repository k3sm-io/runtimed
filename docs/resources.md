# runtimed resource accounting & limits (M2.5, B7)

How runtimed meters pod memory, enforces a memory limit (OOMKilled), applies
explicit rlimits and the best-effort QoS band, and what it does — and
deliberately does **not** — promise for CPU. This is the note the PHASES
`M2.5-d3` deliverable points to; the code at the call sites (`pkg/supervisor`
`PhysFootprinter` / `MemorySampler` / `RunLaunchSequence`, `pkg/runtime`
`PodMetrics` / `resolveRlimitPlan` / `resolveBgQoS`) references it.

## Memory: `ri_phys_footprint`, NOT RSS

The sampler reads **`ri_phys_footprint`** from `proc_pid_rusage(pid,
RUSAGE_INFO_V2, …)` (`pkg/supervisor/rusage_darwin.go`), at ~1 Hz per metered pod.

`ri_phys_footprint` is the kernel's **phys_footprint ledger** for the task. It is
**not** RSS (`ri_resident_size`). It counts, in bytes:

- resident (uncompressed) anonymous + IOKit/graphics-mapped memory,
- **compressed** memory the VM compressor holds for the task (memory that has been
  squeezed but is still *charged* to the process — RSS does not count this), and
- wired memory attributed to the task.

It is the **same figure `jetsam`/`memorystatus` compares against a task's memory
limit**, which is exactly why it is the right number to gate an OOM kill on: it is
the number the OS itself would use to decide memory pressure. A process can have a
modest RSS but a large phys_footprint (lots of compressed pages), and it is the
phys_footprint that matters for "is this pod over its limit".

**Consequences a reader must keep straight:**

- The pod memory **limit is compared in phys_footprint units** — so a limit set
  from a Kubernetes `resources.limits.memory` is interpreted as a phys_footprint
  ceiling, not an RSS ceiling. These differ; phys_footprint is the conservative
  (larger) one.
- The **`kubectl top` / Summary-API "working set"** runtimed surfaces
  (`runtime.PodMetrics.WorkingSetBytes`) is phys_footprint, not the cgroup
  `working_set_bytes` a Linux node reports. The number is honest but is a
  *different* measurement than Linux; do not compare them 1:1.
- runtimed samples the **tracked container PID's** footprint (summed across a
  multi-container pod). Children a container forks are separate tasks and are **not**
  summed in M2 — full process-group accounting (`proc_listpids` over the pgid) is
  future work. A fork-heavy workload can therefore under-report; the limit still
  catches the common single-process-tree case.

## OOMKilled

When a metered pod's summed phys_footprint first exceeds its limit, the sampler
fires once: the runtime SIGKILLs every container process group and sets the
terminated reason to **`OOMKilled`** (`pkg/runtime/pod.go` `oomKill` +
`watchContainerExit`). The kqueue reaper stays the sole reaper — the sampler only
triggers the signal; it never `wait4`s.

The memory limit is read from the typed **`PodBox.memory_limit_bytes`** field
(`apis:M2.2`, allocated from the reserved `100..199` band) — the provider converts
the pod's `resources.limits.memory`. `podMemoryLimitBytes` (`pkg/runtime/metrics.go`,
M2.8) prefers that typed field and falls back to the legacy
`k3sm.io/memory-limit-bytes` annotation **only** when it is unset, so OOM
enforcement holds in either land order while the provider switches to writing the
typed field; the annotation fallback is transitional and removable once every
provider writes the typed field. `0` means no limit (BestEffort → no sampler).

## CPU: best-effort QoS, NOT CFS millicores

k3sm has **no CFS / cgroup CPU controller** — pods are native Darwin processes.
Any CPU shaping is **best-effort QoS** only: it can *deprioritize* a greedy pod
under contention, but it **cannot** enforce a hard "500m = half a core"
guarantee the way Linux CFS quotas do. runtimed therefore does **not** claim a
CPU limit is honored as millicores. **CPU is best-effort, memory is enforced
(in phys_footprint units).**

### QoS application (B7): BestEffort → the darwin background band

Since B7 the launch sequence *applies* **`PodBox.qos_class`** (the apis enum
mirroring corev1 `PodQOSClass`), pre-exec in the exec-shim
(`supervisor.RunLaunchSequence` `StepSetpriority`, before the sandbox is
applied so a default-deny SBPL cannot block it and every descendant inherits
it):

- **`BestEffort` (and an unspecified class) →
  `setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG)`.** This is the
  **deliberate contention policy**: a BestEffort pod yields to everything else
  on the node.
- **`Guaranteed` and `Burstable` → untouched.** No `setpriority` call is made
  at all — the policy is **downward-only**; the default band is the *absence*
  of the call, never an explicit reset-to-0.

**Honesty notes a reader must keep straight:**

- **Darwin BG is a COUPLED band, unlike Linux `cpu.shares`.** `PRIO_DARWIN_BG`
  throttles CPU scheduling **and** moves the process's disk I/O to the
  throttled tier **and** marks its network traffic background class, together.
  A BestEffort pod is deprioritized on all three axes at once; there is no
  per-axis knob here.
- **It is COOPERATIVE, not enforcement.** `setpriority(2)` is public API, and
  the pod process can **self-revert** the band with its own
  `setpriority(PRIO_DARWIN_PROCESS, 0, 0)` call. This is best-effort QoS by
  construction — a malicious/greedy pod is not contained by it (untrusted
  tenancy routes to the vm backend, as everywhere else in the privilege
  model).
- **BG'd pods will legitimately report LOW CPU** once CPU accounting lands: a
  throttled pod's low usage is the policy working, not an accounting bug. Do
  not "fix" it by unthrottling.
- **jetsam/memorystatus interaction is B46's lane.** Darwin couples the BG
  band with jetsam/memorystatus behavior; how the band shifts a pod's
  memory-pressure treatment (and whether it fights the M2.5 sampler) is
  explicitly **not** decided here — the B7 lab leg measures the band's effect
  before/after BG and feeds B46.

## Explicit rlimits (B7): applied, with darwin caveats

**`PodBox.rlimits`** (OCI-style `setrlimit(2)` caps, `apis:M2.2`) are applied
since B7: the daemon resolves the EXPLICIT entries to a numeric plan
(`runtime.resolveRlimitPlan` — nothing is ever synthesized from
`memory_limit_bytes` or a cpu quota), threads it through the one
`sandbox.Backend.WrapCommand` choke-point (container starts AND `kubectl exec`
sessions — an exec gets the **pod's** limits, one code path), and the exec-shim
applies it FIRST in the launch sequence, before the privilege drop. The
argv codec and its fail-closed decode contract are documented on
`cmd/k3sm-execshim` and `supervisor.EncodeRlimits`/`ParseRlimits`.

**Darwin-specific behavior at the apply site
(`supervisor.setrlimitClamped`):**

- **`RLIMIT_NOFILE`**: darwin `setrlimit(2)` returns **EINVAL** — it does NOT
  clamp — for `rlim_cur = RLIM_INFINITY` on `RLIMIT_NOFILE` (man-page
  COMPATIBILITY section), so an infinite/oversized soft limit is pre-clamped
  to `min(OPEN_MAX 10240, hard)`; and a too-tight soft limit is **floored up
  to 256** (`minNOFILESoft`) with a warning, because a starved descriptor
  budget breaks `sandbox_compile`'s profile read and the exec'd image's dyld
  (+ the DYLD-inserted DNS shim) AFTER confinement, with misleading errors.
  The lab leg confirms the floor's sufficiency on hardware.
- **`RLIMIT_NPROC` counts per-UID, not per-pod.** In the no-drop posture every
  pod runs as the shared `_k3sm` uid, so a pod-level nproc limit **measures
  the whole node's `_k3sm` process count, not the pod** — one pod's fork load
  can trip another pod's limit. It is honored verbatim because it is explicit,
  but treat it as a node-wide brake unless the pod uses a per-pod uid drop.
- **`RLIMIT_AS` / `RLIMIT_DATA` are accepted but effectively INERT on
  darwin.** Mach VM allocations bypass the BSD data/address-space ledgers, so
  these caps do not bound a real workload's memory. **Memory enforcement
  remains the phys_footprint sampler + OOMKilled** (above); do not expect an
  AS/DATA cap to fire first.
- **EPERM hard-raise clamps are logged, not surfaced.** In the unprivileged
  posture a hard-limit raise above the inherited ceiling is clamped down with
  a `slog` warning; surfacing that clamp to `PodStatus`/events is
  **DEFERRED** (not in the B7 diff) — today the operator sees it only in the
  daemon log.
