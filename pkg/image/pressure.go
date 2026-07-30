/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package image

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultMinFreeBytes is the free-space floor (in ABSOLUTE bytes on the cache
// volume) under which the puller refuses to start new blob writes. The
// embedding server overrides it at construction via WithMinFreeBytes — never an
// env var.
//
// This gate is deliberately absolute-bytes where k3sm's node-condition surface
// (k3sm/pkg/provider/nodeconditions.go, diskPressureFreePercent) is
// percentage-based: a percentage of an APFS container is fiction under APFS
// space-sharing (every volume in the container reports the same shared free
// pool, so "5% of the volume" moves as siblings grow), while an absolute floor
// states the real invariant — leave kine's WAL and the control plane this many
// bytes of headroom on the shared volume. Surfacing this state as a k8s
// NodeCondition is B27's separately-tracked deliverable, not this gate's.
const DefaultMinFreeBytes uint64 = 5 << 30 // 5 GiB

// pressureSampleInterval bounds how often the gate re-samples free space: at
// most once per interval, so a pull of a many-layer image costs one statfs, not
// one per blob, and the transition log cannot flap faster than this.
const pressureSampleInterval = 15 * time.Second

// ErrDiskPressure is the sentinel for a pull refused because writing the blob
// would take the cache volume's free space under the configured floor. The
// wrapped message names the observed free bytes and the threshold. It flows
// through the ordinary pull-error path, so the runtime surfaces it as
// FAILURE_REASON_IMAGE_PULL with the numbers in the message.
var ErrDiskPressure = errors.New("image pull refused: disk pressure")

// ErrDiskSpaceUnknown is the sentinel for a pull refused because free space
// could not be SAMPLED (statfs failed). Distinct from ErrDiskPressure: the
// refusal is fail-closed on ignorance, not on a measured shortage.
//
// This deliberately INVERTS nodeconditions.go's no-pressure-on-unsampled
// posture: a node condition that flapped on a sampling hiccup would be noise,
// but failing OPEN here would delete the protection exactly when the disk is
// dying (statfs on a failing volume is the first thing to break), and the cost
// of failing closed is only new pulls — running pods are untouched.
var ErrDiskSpaceUnknown = errors.New("image pull refused: free disk space unknown")

// ErrOversizeBlob is the sentinel for a blob stream that exceeded its
// manifest-declared size. Digest verification already guards content
// integrity; this guards BYTES ON DISK — a lying registry cannot stream more
// than the size the manifest declared and reserve space it never disclosed.
var ErrOversizeBlob = errors.New("blob stream exceeds manifest-declared size")

// FreeBytesFunc samples the free bytes on the volume holding path. The
// production implementation is StatfsFreeBytes (unix.Statfs); tests inject a
// fake. It is the seam BELOW the pure decision (shouldStopPulls), so the
// decision logic is testable with no syscall at all.
type FreeBytesFunc func(path string) (uint64, error)

// StatfsFreeBytes is the production FreeBytesFunc: unix.Statfs on path,
// f_bavail × f_bsize (the bytes available to the unprivileged daemon, not the
// root-reserved f_bfree).
func StatfsFreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// shouldStopPulls is the pure disk-pressure decision: refuse when writing a
// blob of the manifest-declared size would leave fewer than threshold free
// bytes (free − declared < threshold, in unsigned-underflow-safe form).
func shouldStopPulls(free, declared, threshold uint64) bool {
	if free < threshold {
		return true
	}
	return free-threshold < declared
}

// pressureGate is the per-Puller disk-pressure stop-new-pulls gate. It is
// consulted per blob, BEFORE any bytes stream, against a cached free-space
// sample (re-sampled at most once per interval).
//
// Locking: mu guards the sample fields and the transition state; admit holds it
// across sample+decide so a transition is logged exactly once.
type pressureGate struct {
	root      string
	threshold uint64
	freeBytes FreeBytesFunc
	interval  time.Duration
	now       func() time.Time
	log       *slog.Logger

	mu         sync.Mutex
	sampledAt  time.Time
	free       uint64
	sampleErr  error
	inPressure bool
}

// admit decides whether a blob write of declared bytes may proceed. Refusals
// log at Debug; ONLY a state transition (ok→pressure, pressure→ok) logs loudly,
// so a storm of refused pulls cannot flood the log.
func (g *pressureGate) admit(declared int64) error {
	if declared < 0 {
		return fmt.Errorf("blob declares negative size %d", declared)
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if g.sampledAt.IsZero() || now.Sub(g.sampledAt) >= g.interval {
		g.free, g.sampleErr = g.freeBytes(g.root)
		g.sampledAt = now
	}

	// Gate STATE (for transition logging) is declared-independent: unknown free
	// space counts as pressure (fail-closed).
	pressured := g.sampleErr != nil || g.free < g.threshold
	if pressured != g.inPressure {
		if pressured {
			g.log.Error("image pulls stopped: disk pressure on cache volume",
				"root", g.root, "free_bytes", g.free, "threshold_bytes", g.threshold, "sample_err", g.sampleErr)
		} else {
			g.log.Info("image pulls resumed: cache volume free space recovered",
				"root", g.root, "free_bytes", g.free, "threshold_bytes", g.threshold)
		}
		g.inPressure = pressured
	}

	if g.sampleErr != nil {
		g.log.Debug("refusing pull: free space unknown", "root", g.root, "err", g.sampleErr)
		return fmt.Errorf("%w: sampling %s failed: %v", ErrDiskSpaceUnknown, g.root, g.sampleErr)
	}
	if shouldStopPulls(g.free, uint64(declared), g.threshold) {
		g.log.Debug("refusing pull: disk pressure",
			"root", g.root, "free_bytes", g.free, "threshold_bytes", g.threshold, "declared_bytes", declared)
		return fmt.Errorf("%w: %d bytes free on %s, threshold %d bytes, blob declares %d bytes",
			ErrDiskPressure, g.free, g.root, g.threshold, declared)
	}
	return nil
}

// PullerOption configures optional Puller behavior at construction.
type PullerOption func(*pullerOptions)

// pullerOptions collects the option-set state NewPuller applies.
type pullerOptions struct {
	minFreeBytes uint64
	freeBytes    FreeBytesFunc
	log          *slog.Logger
}

// WithMinFreeBytes overrides the disk-pressure free-space floor (see
// DefaultMinFreeBytes) for this Puller.
func WithMinFreeBytes(n uint64) PullerOption {
	return func(o *pullerOptions) { o.minFreeBytes = n }
}

// WithFreeBytesFunc overrides the free-space sampler (production:
// StatfsFreeBytes). It is the test seam for the disk-pressure gate.
func WithFreeBytesFunc(fn FreeBytesFunc) PullerOption {
	return func(o *pullerOptions) { o.freeBytes = fn }
}

// WithPressureLogger sets the logger for disk-pressure state transitions. The
// default discards (a library never grabs the process-global logger); the
// daemon wires its own.
func WithPressureLogger(l *slog.Logger) PullerOption {
	return func(o *pullerOptions) { o.log = l }
}
