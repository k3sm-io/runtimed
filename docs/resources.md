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

The memory limit is carried (interim) by the `k3sm.io/memory-limit-bytes` pod
annotation until `apis` defines the first-class `PodBox` memory-limit field
(`apis:M2.2`, reserved band `100..199`). The provider sets the annotation from the
pod's summed container limits; when the typed field lands, `podMemoryLimitBytes`
reads it instead.

## CPU: best-effort QoS, NOT CFS millicores

k3sm has **no CFS / cgroup CPU controller** — pods are native Darwin processes.
Any CPU shaping is **best-effort QoS** only (`taskpolicy` / `setpriority` /
Darwin QoS classes): it can *deprioritize* a greedy pod under contention, but it
**cannot** enforce a hard "500m = half a core" guarantee the way Linux CFS quotas
do. runtimed therefore does **not** claim a CPU limit is honored as millicores.

CPU-QoS *application* is deferred with the `apis` CPU-limit field (`apis:M2.2`):
there is no proto field to read a CPU request/limit from yet, and wiring an
unconfigurable `setpriority` would over-promise. When the field lands, the
best-effort QoS knob attaches at the same spawn/launch seam as the memory sampler.
Until then this file is the standing honesty note: **CPU is best-effort, memory is
enforced (in phys_footprint units).**
