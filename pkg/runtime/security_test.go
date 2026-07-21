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

package runtime

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestResolveRlimitPlan is the pure daemon-side resolver table: it maps the
// EXPLICIT PodBox.rlimits[] to a []supervisor.PlannedRlimit and ONLY those —
// every recognized type resolves to its darwin RLIMIT_* selector, soft/hard are
// carried verbatim, "unlimited" sentinels collapse to RLIM_INFINITY, and an
// unknown type is skipped. The NEGATIVE case is load-bearing: a pod with a memory
// limit and a cpu quota (Guaranteed QoS) but no explicit rlimits[] yields an EMPTY
// plan — runtimed never synthesizes RLIMIT_AS/DATA/CPU from those bands.
func TestResolveRlimitPlan(t *testing.T) {
	cases := []struct {
		name string
		box  *runtimev1.PodBox
		want []supervisor.PlannedRlimit
	}{
		{
			name: "explicit-nofile-soft-hard-verbatim",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 4096},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}},
			},
		},
		{
			// Every recognized type maps to the correct selector. RLIMIT_CPU is
			// included ONLY because it is explicitly named here (the zero-value trap).
			name: "all-recognized-types-map-correctly",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NPROC", Soft: 64, Hard: 128},
				{Type: "RLIMIT_AS", Soft: 1 << 20, Hard: 1 << 21},
				{Type: "RLIMIT_CORE", Soft: 0, Hard: 0},
				{Type: "RLIMIT_STACK", Soft: 8 << 20, Hard: 16 << 20},
				{Type: "RLIMIT_DATA", Soft: 1, Hard: 2},
				{Type: "RLIMIT_FSIZE", Soft: 3, Hard: 4},
				{Type: "RLIMIT_CPU", Soft: 10, Hard: 20},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NPROC, Lim: unix.Rlimit{Cur: 64, Max: 128}},
				{Resource: unix.RLIMIT_AS, Lim: unix.Rlimit{Cur: 1 << 20, Max: 1 << 21}},
				{Resource: unix.RLIMIT_CORE, Lim: unix.Rlimit{Cur: 0, Max: 0}},
				{Resource: unix.RLIMIT_STACK, Lim: unix.Rlimit{Cur: 8 << 20, Max: 16 << 20}},
				{Resource: unix.RLIMIT_DATA, Lim: unix.Rlimit{Cur: 1, Max: 2}},
				{Resource: unix.RLIMIT_FSIZE, Lim: unix.Rlimit{Cur: 3, Max: 4}},
				{Resource: unix.RLIMIT_CPU, Lim: unix.Rlimit{Cur: 10, Max: 20}},
			},
		},
		{
			name: "unlimited-sentinels-map-to-rlim-infinity",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: ^uint64(0), Hard: uint64(unix.RLIM_INFINITY)},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}},
			},
		},
		{
			// (c) NEGATIVE: a memory limit + a cpu quota (Guaranteed QoS) but NO
			// explicit rlimits[] yields an EMPTY plan — nothing is synthesized.
			name: "memory-and-cpu-quota-without-explicit-rlimits-is-empty",
			box: &runtimev1.PodBox{
				MemoryLimitBytes: 512 << 20,
				QosClass:         runtimev1.QOSClass_QOS_CLASS_GUARANTEED,
			},
			want: nil,
		},
		{
			// (d) an unknown type is skipped, never applied as the zero-value
			// resource (RLIMIT_CPU on darwin); the recognized sibling still maps.
			name: "unknown-type-skipped-recognized-kept",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_BOGUS", Soft: 1, Hard: 2},
				{Type: "RLIMIT_NOFILE", Soft: 100, Hard: 200},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 100, Max: 200}},
			},
		},
		{
			// An unknown type ALONE yields an empty plan — proof it was skipped, not
			// mapped to resource 0 (RLIMIT_CPU).
			name: "unknown-type-only-is-empty",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "NOT_A_RLIMIT", Soft: 1, Hard: 2},
			}},
			want: nil,
		},
		{
			name: "no-rlimits-is-empty",
			box:  &runtimev1.PodBox{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRlimitPlan(tc.box)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resolveRlimitPlan = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestResolveBgQoS pins the B7 QoS mapping decision (apis QOSClass → the
// supervisor-local background flag), made HERE in the runtime layer so the
// supervisor stays decoupled from apis: BEST_EFFORT and UNSPECIFIED map to the
// darwin background band (PRIO_DARWIN_BG via the launch sequence); GUARANTEED,
// BURSTABLE, and any UNKNOWN/future enum value map to NO setpriority call at all
// (downward-only — the default band is the absence of the call, never an
// explicit reset-to-0). The unknown-value case is load-bearing: backgrounding
// must be the explicitly-enumerated branch, so a future additive apis QOSClass
// value is never silently BG-throttled by a stale runtimed.
func TestResolveBgQoS(t *testing.T) {
	cases := []struct {
		name string
		qos  runtimev1.QOSClass
		want bool
	}{
		{"besteffort-backgrounds", runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT, true},
		{"unspecified-backgrounds", runtimev1.QOSClass_QOS_CLASS_UNSPECIFIED, true},
		{"guaranteed-untouched", runtimev1.QOSClass_QOS_CLASS_GUARANTEED, false},
		{"burstable-untouched", runtimev1.QOSClass_QOS_CLASS_BURSTABLE, false},
		{"unknown-future-enum-value-untouched", runtimev1.QOSClass(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveBgQoS(&runtimev1.PodBox{QosClass: tc.qos}); got != tc.want {
				t.Fatalf("resolveBgQoS(%v) = %v, want %v", tc.qos, got, tc.want)
			}
		})
	}
}

// TestResolveRlimitPlan_UnknownTypeWarnsAndSkips proves the comma-ok contract:
// an unrecognized type is SKIPPED with a slog.Warn and is NEVER applied as the
// zero-value resource — which on darwin is RLIMIT_CPU (0x0), a cumulative
// CPU-seconds killer. The empty plan is the proof it did not fall through to 0.
func TestResolveRlimitPlan_UnknownTypeWarnsAndSkips(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	box := &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
		{Type: "RLIMIT_BOGUS", Soft: 1, Hard: 2},
	}}
	got := resolveRlimitPlan(box)
	if len(got) != 0 {
		t.Fatalf("unknown rlimit type must be skipped (empty plan), got %+v", got)
	}
	if !strings.Contains(buf.String(), "unknown rlimit type") {
		t.Errorf("expected a warning for the unknown type, slog output = %q", buf.String())
	}
}
