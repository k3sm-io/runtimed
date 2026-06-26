package runtime

import (
	"strconv"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// memoryLimitAnnotation carried the pod's memory limit in BYTES before apis:M2.2
// defined the first-class PodBox.memory_limit_bytes field. It is now the
// TRANSITIONAL FALLBACK only: podMemoryLimitBytes prefers the typed field and
// reads this annotation solely when the typed field is unset, so OOM enforcement
// holds regardless of land order while the k3sm provider switches to writing the
// typed field (a sibling PR). Once every provider writes the typed field this
// fallback (and the annotation) can be deleted. The value is in ri_phys_footprint
// units (NOT RSS); see docs/resources.md.
const memoryLimitAnnotation = "k3sm.io/memory-limit-bytes"

// podMemoryLimitBytes returns the pod's memory limit in bytes, or 0 for unlimited
// (no OOM enforcement, no sampler). It reads the typed PodBox.memory_limit_bytes
// (apis:M2.2) first; the typed field WINS whenever it is set (> 0). When it is
// unset (0) the legacy memoryLimitAnnotation is consulted as a transitional
// fallback (see memoryLimitAnnotation) so there is no transition window in either
// land order. An unparseable annotation is treated as unlimited (the provider is
// the trusted producer of both carriers).
//
// qos_class and rlimits also ride apis:M2.2's PodBox resource band. qos_class is
// informational for runtimed today (CPU is best-effort QoS, not CFS millicores —
// the taskpolicy/setpriority application is deferred, see docs/resources.md and
// PodBox.qos_class); rlimits are applied via setrlimit(2) in the exec-shim before
// exec — deferred to a follow-up that extends the M2.3 security-critical launch
// sequence (a setrlimit step ordered before the uid drop) with its own ordering
// test, rather than bolted on here untested.
func podMemoryLimitBytes(box *runtimev1.PodBox) uint64 {
	if typed := box.GetMemoryLimitBytes(); typed > 0 {
		return uint64(typed)
	}
	// Transitional fallback: the legacy annotation, until the provider writes the
	// typed field everywhere.
	v := box.GetAnnotations()[memoryLimitAnnotation]
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// PodMetrics is a point-in-time resource sample for a pod — the source the k3sm
// provider maps to the kubelet Summary API / kubectl top (Wave 3 wires it to the
// Summary endpoint). WorkingSetBytes is ri_phys_footprint (NOT RSS — see
// docs/resources.md and the supervisor MemorySampler doc). It is a
// runtimed-internal type until apis defines the Summary message (apis:M2.2), at
// which point PodMetrics maps onto it.
type PodMetrics struct {
	// PodID is the pod the sample belongs to.
	PodID string
	// WorkingSetBytes is the pod's latest physical-memory footprint
	// (ri_phys_footprint, summed across container PIDs).
	WorkingSetBytes uint64
	// Timestamp is when the snapshot was taken.
	Timestamp time.Time
}

// PodMetrics returns the latest memory sample for podID. ok is false when the pod
// is unknown or has no memory sampler (no memory limit set — only limited pods are
// metered in M2; broadening to all pods awaits the apis Summary message so the
// metering posture and the wire type land together).
func (r *Runtime) PodMetrics(podID string) (PodMetrics, bool) {
	r.mu.Lock()
	p, found := r.pods[podID]
	r.mu.Unlock()
	if !found {
		return PodMetrics{}, false
	}
	p.mu.Lock()
	s := p.memSampler
	p.mu.Unlock()
	if s == nil {
		return PodMetrics{}, false
	}
	return PodMetrics{
		PodID:           podID,
		WorkingSetBytes: s.Last(),
		Timestamp:       time.Now(),
	}, true
}
