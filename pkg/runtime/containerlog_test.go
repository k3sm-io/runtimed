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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/crilog"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// criLine is one parsed line of a CRI log file.
type criLine struct {
	at      string
	stream  string
	tag     string
	payload string
}

// readCRILog parses a CRI log file into its lines, failing the test on any line
// that does not have the four fields.
//
// It parses rather than substring-matches on purpose: the file's format is the
// contract with the node's reader, so a test that only asked "does the payload
// appear somewhere" would pass against a file no reader could parse.
func readCRILog(t *testing.T, path string) []criLine {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []criLine
	for _, raw := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if raw == "" {
			continue
		}
		f := strings.SplitN(raw, " ", 4)
		if len(f) != 4 {
			t.Fatalf("malformed CRI log line %q in %s", raw, path)
		}
		if _, perr := time.Parse(time.RFC3339Nano, f[0]); perr != nil {
			t.Fatalf("line %q does not start with an RFC3339Nano timestamp: %v", raw, perr)
		}
		out = append(out, criLine{at: f[0], stream: f[1], tag: f[2], payload: f[3]})
	}
	return out
}

// TestCreatePodRequiresLogDirectory pins the fail-closed half of the writer's
// contract: runtimed will not start a container without being told where its
// output goes. A default would put every container on a mis-wired node's output
// somewhere nobody reads, and the symptom would be empty logs rather than an
// error anyone can act on.
func TestCreatePodRequiresLogDirectory(t *testing.T) {
	cases := []struct {
		name string
		dir  string
	}{
		{"empty", ""},
		{"relative", "var/log/pods/ns_pod_uid"},
		{"unclean", "/var/log/pods//ns_pod_uid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newBlockingWaiter()
			rt := newTestRuntime(t, Deps{Waiter: w})
			box := hostBinBox(rt, "pod-nolog")
			box.LogDirectory = tc.dir

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() == nil {
				t.Fatal("CreatePod succeeded without a usable log_directory")
			}
			if got := codes.Code(resp.GetError().GetCode()); got != codes.InvalidArgument {
				t.Errorf("code = %v, want InvalidArgument", got)
			}
			if !strings.Contains(resp.GetError().GetMessage(), "log_directory") {
				t.Errorf("message %q does not name the field", resp.GetError().GetMessage())
			}
		})
	}
}

// TestContainerStatusCarriesLogPaths asserts the status publishes where a
// container's output is — the value the node resolves `kubectl logs` through,
// and rotates, and prunes. Three facts, and all three are load-bearing:
// a running container's current file, a NEVER-STARTED container's EMPTY path
// (there is no instance, so there is no file), and, after a restart, the
// previous instance's file on last_termination_state, which is what
// `kubectl logs --previous` resolves.
func TestContainerStatusCarriesLogPaths(t *testing.T) {
	t.Run("running-container-names-its-file", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		box := hostBinBox(rt, "pod-lp")
		mustCreatePod(t, rt, box)
		defer w.release(1001)

		st, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-lp"})
		if err != nil {
			t.Fatal(err)
		}
		cs := st.GetStatus().GetContainerStatuses()
		if len(cs) != 1 {
			t.Fatalf("container_statuses = %d, want 1", len(cs))
		}
		want := filepath.Join(box.GetLogDirectory(), "main", "0.log")
		if got := cs[0].GetLogPath(); got != want {
			t.Errorf("log_path = %q, want %q", got, want)
		}
		if _, serr := os.Stat(want); serr != nil {
			t.Errorf("the published log file does not exist: %v", serr)
		}
	})

	t.Run("never-started-container-has-no-file", func(t *testing.T) {
		// A container whose image cannot be resolved is tracked as Waiting with
		// no process — and so with no instance and no file. An empty log_path is
		// the node's signal that there is nothing on disk, which is a different
		// answer from a path that exists and holds nothing.
		cp := (&Runtime{}).waitingContainerProc("pod-w", &runtimev1.Container{Name: "main"}, false,
			runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "", "boom")
		if cp.logw != nil {
			t.Error("a never-started container opened a log file")
		}
		if got := cp.state.GetLogPath(); got != "" {
			t.Errorf("log_path = %q, want empty", got)
		}
	})

	t.Run("restart-records-the-previous-instances-file", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		box := hostBinBox(rt, "pod-lpr")
		mustCreatePod(t, rt, box)

		go w.release(1001) // the old instance exits when RestartContainer stops it
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: "pod-lpr", Container: "main",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer failed: %v", resp.GetError())
		}
		defer w.release(1002) // the replacement

		st := resp.GetStatus()
		if got, want := st.GetRestartCount(), int32(1); got != want {
			t.Errorf("restart_count = %d, want %d", got, want)
		}
		wantNew := filepath.Join(box.GetLogDirectory(), "main", "1.log")
		if got := st.GetLogPath(); got != wantNew {
			t.Errorf("log_path = %q, want %q (a restart writes the NEXT instance's file)", got, wantNew)
		}
		wantPrev := filepath.Join(box.GetLogDirectory(), "main", "0.log")
		if got := st.GetLastTerminationState().GetTerminated().GetLogPath(); got != wantPrev {
			t.Errorf("last_termination_state.log_path = %q, want %q", got, wantPrev)
		}
		if _, serr := os.Stat(wantPrev); serr != nil {
			t.Errorf("the replaced instance's file was deleted; runtimed never deletes a log file: %v", serr)
		}
	})
}

// TestContainerLogFileNumberingSurvivesDaemonRestart is the cold-start recovery
// gate (upstream's calcRestartCountByLogDir, performed by the writer because on
// k3sm the writer picks the file name).
//
// A daemon restart re-creates every pod from scratch with restart_count 0. If
// the instance number came from that count alone, the new instance would open
// the file the PREVIOUS run already wrote — appending a second run's output onto
// the first's, so `kubectl logs --previous` would serve a file holding two runs
// and the status count would disagree with the disk. The number is taken from
// the log directory instead.
func TestContainerLogFileNumberingSurvivesDaemonRestart(t *testing.T) {
	t.Run("restart-count-from-dir", func(t *testing.T) {
		dir := t.TempDir()
		if got, err := restartCountFromLogDir(filepath.Join(dir, "absent")); err != nil || got != 0 {
			t.Errorf("absent dir = (%d, %v), want (0, nil) — a container that never ran is instance 0", got, err)
		}
		for _, name := range []string{
			"0.log",
			"1.log.20260913-103000.gz", // rotated and compressed: still instance 1
			"2.log.20260913-104000",    // rotated, not yet compressed
			"notes.txt",                // not an instance file
			"x.log",                    // not a number
		} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := restartCountFromLogDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != 3 {
			t.Errorf("restartCountFromLogDir = %d, want 3 (one past the highest, counting ROTATED files)", got)
		}
	})

	t.Run("a-second-daemon-run-does-not-clobber-the-first", func(t *testing.T) {
		// Two runtimes over ONE root and one log tree: the second is the daemon
		// after a `launchctl kickstart -k`, re-creating the pod it found.
		root := t.TempDir()
		logs := filepath.Join(root, "podlogs")

		w1 := newBlockingWaiter()
		rt1 := newTestRuntimeCfg(t, Config{Root: root, PodLogsDir: logs}, Deps{Waiter: w1})
		box := hostBinBox(rt1, "pod-rs")
		mustCreatePod(t, rt1, box)
		firstPath := filepath.Join(box.GetLogDirectory(), "main", "0.log")
		p := rt1.pods["pod-rs"]
		if err := p.containers[0].logw.Write(crilog.StreamStdout, []byte("run-one"), false); err != nil {
			t.Fatalf("write run-one: %v", err)
		}
		w1.release(1001)

		w2 := newBlockingWaiter()
		rt2 := newTestRuntimeCfg(t, Config{Root: root, PodLogsDir: logs}, Deps{Waiter: w2})
		mustCreatePod(t, rt2, hostBinBox(rt2, "pod-rs"))
		defer w2.release(1001)

		st, err := rt2.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-rs"})
		if err != nil {
			t.Fatal(err)
		}
		cs := st.GetStatus().GetContainerStatuses()[0]
		wantSecond := filepath.Join(box.GetLogDirectory(), "main", "1.log")
		if got := cs.GetLogPath(); got != wantSecond {
			t.Errorf("after a daemon restart the container opened %q, want %q — it clobbered the previous run's file",
				got, wantSecond)
		}
		if got, want := cs.GetRestartCount(), int32(1); got != want {
			t.Errorf("restart_count = %d, want %d (the count continues from the files on disk)", got, want)
		}
		if lines := readCRILog(t, firstPath); len(lines) != 1 || lines[0].payload != "run-one" {
			t.Errorf("the first run's file now holds %v; the second run appended into it", lines)
		}
	})
}

// TestGetLogsIsUnimplemented pins the reader/writer split at the RPC boundary.
// runtimed writes log files and does not read them, so GetLogs answers with the
// one thing a caller can act on — where the bytes are. An empty stream would
// look like a container that said nothing, which is the single answer a log
// reader must never be given wrongly.
func TestGetLogsIsUnimplemented(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-gl"))
	defer w.release(1001)

	for _, podID := range []string{"pod-gl", "pod-absent"} {
		stream := newFakeLogStream(context.Background())
		err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: podID, Container: "main"}, stream)
		if status.Code(err) != codes.Unimplemented {
			t.Errorf("GetLogs(%s) code = %v, want Unimplemented", podID, status.Code(err))
		}
		if !strings.Contains(err.Error(), "log_path") {
			t.Errorf("GetLogs(%s) = %v; the message must point at ContainerStatus.log_path", podID, err)
		}
		if len(stream.entries) != 0 {
			t.Errorf("GetLogs(%s) sent %d entries; a refusal must produce no output", podID, len(stream.entries))
		}
	}
}

// TestReopenContainerLogRotatesTheFile drives the runtime half of rotation: the
// node renames the live file aside and calls the verb, and the writer must then
// be writing into a fresh file at the original path — with the pre-rotation
// output intact in the renamed one.
func TestReopenContainerLogRotatesTheFile(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	box := hostBinBox(rt, "pod-rot")
	mustCreatePod(t, rt, box)
	defer w.release(1001)

	path := filepath.Join(box.GetLogDirectory(), "main", "0.log")
	cp := rt.pods["pod-rot"].containers[0]
	if err := cp.logw.Write(crilog.StreamStdout, []byte("before-rotation"), false); err != nil {
		t.Fatal(err)
	}

	rotated := path + ".20260913-103000"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.ReopenContainerLog(context.Background(),
		&runtimev1.ReopenContainerLogRequest{PodId: "pod-rot", Container: "main"}); err != nil {
		t.Fatalf("ReopenContainerLog: %v", err)
	}
	if err := cp.logw.Write(crilog.StreamStdout, []byte("after-rotation"), false); err != nil {
		t.Fatal(err)
	}

	if lines := readCRILog(t, rotated); len(lines) != 1 || lines[0].payload != "before-rotation" {
		t.Errorf("the rotated file holds %v, want the pre-rotation output alone", lines)
	}
	if lines := readCRILog(t, path); len(lines) != 1 || lines[0].payload != "after-rotation" {
		t.Errorf("the reopened file holds %v, want the post-rotation output alone", lines)
	}

	t.Run("unknown-container-is-not-found", func(t *testing.T) {
		_, err := rt.ReopenContainerLog(context.Background(),
			&runtimev1.ReopenContainerLogRequest{PodId: "pod-rot", Container: "ghost"})
		if status.Code(err) != codes.NotFound {
			t.Errorf("code = %v, want NotFound", status.Code(err))
		}
	})
}

// TestReopenContainerLogRefusesANonRunningContainer pins containerd's rule: a
// container that is not running has a closed, complete file, and reopening it
// would create an empty one at a path the node is about to prune.
func TestReopenContainerLogRefusesANonRunningContainer(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	box := hostBinBox(rt, "pod-notrun")
	p := &pod{box: box, containers: []*containerProc{{
		name:  "main",
		state: &runtimev1.ContainerStatus{Name: "main", State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{}}},
	}}}
	rt.mu.Lock()
	rt.pods["pod-notrun"] = p
	rt.mu.Unlock()

	_, err := rt.ReopenContainerLog(context.Background(),
		&runtimev1.ReopenContainerLogRequest{PodId: "pod-notrun", Container: "main"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(err.Error(), "container is not running") {
		t.Errorf("message = %v, want containerd's wording", err)
	}
}
