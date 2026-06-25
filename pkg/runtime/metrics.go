package runtime

import (
	"strconv"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// memoryLimitAnnotation carries the pod's memory limit in BYTES. It is the interim
// carrier for the OOM threshold + kubectl-top metering trigger until apis defines
// the first-class PodBox memory-limit field (apis:M2.2): the proto RESERVES the
// band (PodBox 100..199, "resource limits") but has not defined the field yet, so
// — exactly as the DYLD-insert dylib path rides k3sm.io/dyld-insert-libraries —
// the provider sets this from the pod's summed container memory limits. The value
// is in ri_phys_footprint units (NOT RSS); see docs/resources.md. When apis:M2.2
// lands the typed field, podMemoryLimitBytes switches to reading it.
const memoryLimitAnnotation = "k3sm.io/memory-limit-bytes"

// podMemoryLimitBytes returns the pod's memory limit in bytes, or 0 for unlimited
// (no OOM enforcement, no sampler). Parsed from memoryLimitAnnotation; an
// unparseable value is treated as unlimited (the provider is the trusted producer
// of this annotation).
func podMemoryLimitBytes(box *runtimev1.PodBox) uint64 {
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
