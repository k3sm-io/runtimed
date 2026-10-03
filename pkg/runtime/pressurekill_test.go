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
	"context"
	"errors"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestDefaultSpawnerMarkedPressureKill pins the default pod spawner's
// pressure-kill wiring in New: a passing self-check yields a marked spawner and
// no extra condition; a failing one yields an UNMARKED spawner for the daemon's
// life plus a PressureKillMark=false condition; an injected spawner is never
// probed. The probe is a fake, so no process is spawned here.
func TestDefaultSpawnerMarkedPressureKill(t *testing.T) {
	cases := []struct {
		name       string
		inject     bool
		probeErr   error
		wantProbed bool
		wantMarked bool
		wantCond   bool
	}{
		{name: "self-check-passes", wantProbed: true, wantMarked: true},
		{name: "self-check-fails", probeErr: errors.New("probe says no"), wantProbed: true, wantCond: true},
		{name: "injected-spawner-not-probed", inject: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probed := 0
			d := testDeps(t, Deps{PressureKillProbe: func(context.Context) error {
				probed++
				return tc.probeErr
			}})
			if !tc.inject {
				d.Spawner = nil
			}
			r, err := New(Config{Root: t.TempDir()}, d)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := probed == 1; got != tc.wantProbed || probed > 1 {
				t.Errorf("probe ran %d times, want probed=%v (at most once)", probed, tc.wantProbed)
			}
			if !tc.inject {
				ps, ok := r.spawner.(supervisor.PosixSpawner)
				if !ok {
					t.Fatalf("default spawner = %T, want supervisor.PosixSpawner", r.spawner)
				}
				if ps.PressureKill != tc.wantMarked {
					t.Errorf("default spawner PressureKill = %v, want %v", ps.PressureKill, tc.wantMarked)
				}
			}
			resp, err := r.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
			if err != nil {
				t.Fatalf("GetRuntimeInfo: %v", err)
			}
			c := findCondition(resp, ConditionPressureKillMark)
			if (c != nil) != tc.wantCond {
				t.Fatalf("PressureKillMark condition present = %v, want %v; conditions = %v", c != nil, tc.wantCond, resp.GetConditions())
			}
			if c != nil {
				if c.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_FALSE {
					t.Errorf("condition status = %v, want FALSE", c.GetStatus())
				}
				if c.GetReason() == "" || !strings.Contains(c.GetMessage(), "probe says no") {
					t.Errorf("condition reason/message = %q/%q, want a reason and the probe error", c.GetReason(), c.GetMessage())
				}
			}
		})
	}
}
