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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

type zeroWaiter struct{}

func (zeroWaiter) WaitExit(context.Context, int) (int, int, error) { return 0, 0, nil }

// TestKilledExternallyReason checks that a SIGKILL this daemon did not send
// reaches the terminated state as KilledExternally with the crash-report
// pointer, and that an OOM kill the sampler issued keeps OOMKilled.
func TestKilledExternallyReason(t *testing.T) {
	dir := t.TempDir()
	rec, _ := json.Marshal(supervisor.ExitRecord{ExitCode: 137, Signal: 9})
	if err := os.WriteFile(filepath.Join(dir, supervisor.ShimExitFile), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	proc, err := supervisor.AdoptShimByRecord(context.Background(), zeroWaiter{},
		supervisor.ShimIdentity{Pid: 4242, Dir: dir}, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, sig, werr := proc.Wait(context.Background())
	if werr != nil || !proc.ExternalKill() {
		t.Fatalf("Wait = (%d, %d, %v), ExternalKill = %v", code, sig, werr, proc.ExternalKill())
	}
	for _, tc := range []struct {
		name       string
		oom        bool
		wantReason string
	}{
		{"external", false, KilledExternallyReason},
		{"oom-wins", true, "OOMKilled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &pod{oomKilled: tc.oom}
			term := terminatedLocked(p, &containerProc{proc: proc}, code, sig, nil)
			if term.GetReason() != tc.wantReason {
				t.Fatalf("reason = %q, want %q", term.GetReason(), tc.wantReason)
			}
			if !tc.oom && !strings.Contains(term.GetMessage(), supervisor.DiagnosticReportsDir) {
				t.Fatalf("message %q does not point at %s", term.GetMessage(), supervisor.DiagnosticReportsDir)
			}
		})
	}
}
