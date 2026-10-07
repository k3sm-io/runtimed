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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestContainerEnvShimReport pins K3SM_SHIM_REPORT as runtime-owned: a spec
// value is dropped, and the runtime sets it, to the per-container file in the
// derived pod data volume, only when the path shim rebases mounts.
func TestContainerEnvShimReport(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim
	rt.cfg.ShadowBinDir = t.TempDir()

	t.Run("set with mounts, spec value dropped", func(t *testing.T) {
		box, c := mountingBox(t, rt, "pod-rep1", "/mnt/sec")
		c.Env = append(c.Env, &runtimev1.EnvVar{Name: supervisor.ChildReportEnv, Value: "/etc/passwd"})
		env := mustEnv(t, rt, box, c)
		want := filepath.Join(derivedRootfs(t, rt, "pod-rep1"), ".k3sm-shim-report-"+c.GetName())
		n := 0
		for _, e := range env {
			if k, v, _ := strings.Cut(e, "="); k == supervisor.ChildReportEnv {
				n++
				if v != want {
					t.Errorf("%s = %q, want %q", k, v, want)
				}
			}
		}
		if n != 1 {
			t.Fatalf("%s appears %d times, want once (the runtime's): %v", supervisor.ChildReportEnv, n, env)
		}
	})

	t.Run("unset without mounts, spec value dropped", func(t *testing.T) {
		box, c := mountingBox(t, rt, "pod-rep2")
		c.Env = append(c.Env, &runtimev1.EnvVar{Name: supervisor.ChildReportEnv, Value: "/etc/passwd"})
		if v, ok := envValue(mustEnv(t, rt, box, c), supervisor.ChildReportEnv); ok {
			t.Fatalf("%s = %q set with no mounts", supervisor.ChildReportEnv, v)
		}
	})
}

// TestShimConditionRestrictedChild pins the reason, its rank (lowest) and the
// message for reported platform-binary children.
func TestShimConditionRestrictedChild(t *testing.T) {
	at := time.Unix(1000, 0)
	child := &containerProc{name: "app", childShim: shimChildLoss{names: []string{"/bin/cat", "/bin/ls"}, at: at}}
	want := "container app: a platform binary it ran (/bin/cat, /bin/ls) cannot load the pod shim: " +
		"absolute paths under the pod's volume mounts resolve to host paths in it, and " +
		"per-namespace DNS precedence and bind/connect source discipline are unavailable to it " +
		"(advisory: reported from inside the pod)"

	t.Run("child only", func(t *testing.T) {
		cond := shimInactiveConditionLocked(&pod{containers: []*containerProc{child}})
		if cond == nil || cond.GetReason() != ShimInactiveRestrictedChildReason || cond.GetMessage() != want {
			t.Fatalf("condition = %v", cond)
		}
		if cond.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_TRUE || cond.GetType() != ShimInactiveConditionType {
			t.Fatalf("condition = %v", cond)
		}
	})

	t.Run("ranked below every main-process reason", func(t *testing.T) {
		for _, r := range []string{ShimInactiveUnknownReason, ShimInactiveLibraryValidationReason, ShimInactiveHardenedReason, ShimInactiveReason} {
			if shimReasonRank[ShimInactiveRestrictedChildReason] >= shimReasonRank[r] {
				t.Errorf("rank(%s) >= rank(%s)", ShimInactiveRestrictedChildReason, r)
			}
			main := &containerProc{name: "web", shim: shimInactive{inactive: true, reason: r, message: "m", at: at}}
			cond := shimInactiveConditionLocked(&pod{containers: []*containerProc{child, main}})
			if cond.GetReason() != r {
				t.Errorf("pod reason with %s beside a child report = %q", r, cond.GetReason())
			}
		}
		if shimReasonRank[ShimInactiveRestrictedChildReason] <= 0 {
			t.Errorf("the child reason must outrank no reason")
		}
	})

	t.Run("main-process verdict keeps its reason, child clause appended", func(t *testing.T) {
		both := &containerProc{name: "app",
			shim:      shimInactive{inactive: true, reason: ShimInactiveReason, message: "main msg", at: at},
			childShim: child.childShim}
		cond := shimInactiveConditionLocked(&pod{containers: []*containerProc{both}})
		if cond.GetReason() != ShimInactiveReason || cond.GetMessage() != "main msg; "+want {
			t.Fatalf("condition = %v", cond)
		}
	})

	t.Run("nothing reported", func(t *testing.T) {
		if cond := shimInactiveConditionLocked(&pod{containers: []*containerProc{{name: "app"}}}); cond != nil {
			t.Fatalf("condition = %v", cond)
		}
	})
}

// TestChildReportReachesPodStatus drives the wiring: a stale report from a
// previous instance is removed at start, a report the container writes is
// read on the poll and published as the condition, and an unrestricted name
// is ignored.
func TestChildReportReachesPodStatus(t *testing.T) {
	rt := newTestRuntimeCfg(t, Config{PathShimPath: testShim}, Deps{Spawner: &fakeSpawner{}})
	rt.childRestricted = func(p string) bool { return p == "/bin/cat" }
	box, c := mountingBox(t, rt, "pod-rep3", "/mnt/sec")
	dataVol := derivedRootfs(t, rt, "pod-rep3")
	report := filepath.Join(dataVol, ".k3sm-shim-report-"+c.GetName())
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("/bin/cat\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCreatePod(t, rt, box)

	rt.mu.Lock()
	p := rt.pods["pod-rep3"]
	rt.mu.Unlock()
	if _, err := os.Lstat(report); !os.IsNotExist(err) {
		t.Fatalf("stale report survived the start: %v", err)
	}
	cond := func() *runtimev1.PodCondition {
		resp, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-rep3"})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range resp.GetStatus().GetConditions() {
			if c.GetType() == ShimInactiveConditionType {
				return c
			}
		}
		return nil
	}
	if got := cond(); got != nil {
		t.Fatalf("condition before any report: %v", got)
	}
	if err := os.WriteFile(report, []byte("/usr/bin/nope\n/bin/cat\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt.pollChildReports(p)
	got := cond()
	if got == nil || got.GetReason() != ShimInactiveRestrictedChildReason {
		t.Fatalf("condition after the report = %v", got)
	}
	if want := childShimMessage(c.GetName(), []string{"/bin/cat"}); got.GetMessage() != want {
		t.Fatalf("message = %q, want %q", got.GetMessage(), want)
	}
}

// TestChildReportPollerLifetime pins the off-sampler poller: a kick polls,
// and cancelling its context ends the goroutine.
func TestChildReportPollerLifetime(t *testing.T) {
	rt := newTestRuntimeCfg(t, Config{}, Deps{})
	rt.childRestricted = func(p string) bool { return p == "/bin/cat" }
	dir := t.TempDir()
	name, err := supervisor.ChildReportName("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("/bin/cat\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := &containerProc{name: "app", childReport: supervisor.NewChildReport(dir, name, rt.childRestricted)}
	p := &pod{box: &runtimev1.PodBox{PodId: "pod-poller"}, containers: []*containerProc{cp}}

	ctx, cancel := context.WithCancel(context.Background())
	kick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		rt.childReportPoller(ctx, p, kick)
		close(done)
	}()
	kick <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		n := len(cp.childShim.names)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the kick never polled the report")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the poller outlived its context")
	}
}
