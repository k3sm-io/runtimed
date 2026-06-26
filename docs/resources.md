# runtimed resource accounting & limits (M2.5)

How runtimed meters pod memory, enforces a memory limit (OOMKilled), and what it
does — and deliberately does **not** — promise for CPU. This is the note the
PHASES `M2.5-d3` deliverable points to; the code at the call sites
(`pkg/supervisor` `PhysFootprinter` / `MemorySampler`, `pkg/runtime` `PodMetrics`)
references it.

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
Any CPU shaping is **best-effort QoS** only (`taskpolicy` / `setpriority` /
Darwin QoS classes): it can *deprioritize* a greedy pod under contention, but it
**cannot** enforce a hard "500m = half a core" guarantee the way Linux CFS quotas
do. runtimed therefore does **not** claim a CPU limit is honored as millicores.

`apis:M2.2` added **`PodBox.qos_class`** (an enum mirroring corev1 `PodQOSClass`),
but CPU-QoS *application* (`taskpolicy` / `setpriority`) is **still deferred**: a
QoS class is not a CPU millicore request, and wiring `setpriority` to a class
without a contention-policy decision would over-promise. When the best-effort QoS
knob is built it attaches at the same spawn/launch seam as the memory sampler and
reads `qos_class`. Until then this file is the standing honesty note: **CPU is
best-effort, memory is enforced (in phys_footprint units).**

`apis:M2.2` also added **`PodBox.rlimits`** (OCI-style `setrlimit(2)` caps, e.g.
`RLIMIT_NOFILE`). Applying them is **deferred to a follow-up** because `setrlimit`
must run in the exec-shim *before* exec and is ordered relative to the M2.3
privilege drop (the hard-limit raise needs privilege, so it precedes `setuid`) —
extending the security-critical `RunLaunchSequence` deserves its own ordering test
(mirroring `TestRunLaunchSequenceOrder`) rather than being bolted on untested.
