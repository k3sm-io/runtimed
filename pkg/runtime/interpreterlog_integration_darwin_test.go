//go:build integration && darwin

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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// cltPython is the Command Line Tools interpreter. Its stdout is block-buffered
// when it is a pipe, which is what makes it the interesting case: everything it
// prints sits in the interpreter's buffer until exit flushes it.
const cltPython = "/Library/Developer/CommandLineTools/usr/bin/python3"

// bufferedPrologue fails the script (exit 3) unless stdout really is a
// block-buffered pipe, so the test cannot pass vacuously against a line-buffered
// or unbuffered interpreter.
const bufferedPrologue = "import os, sys\n" +
	"if sys.stdout.isatty() or sys.stdout.line_buffering or sys.stdout.write_through or 'PYTHONUNBUFFERED' in os.environ:\n" +
	"    sys.stderr.write('stdout is not block-buffered\\n'); sys.exit(3)\n"

// TestNativePodStdoutFromAnInterpreterReachesTheCRILog runs a native pod whose
// container is a block-buffered python, lets it exit cleanly, and asserts the
// bytes it buffered reach the container's CRI log.
//
// This is a REGRESSION PIN: it is green before and after the change that added
// it. The original report (stdout missing from an interpreter's log) was CPython
// block buffering under SIGTERM, which drops the unflushed buffer exactly as it
// does upstream; it was not the capture path. What the test pins is the resident
// shim's drain: the shim writes the exit record only after both output pumps
// have drained (bounded by drainGrace), so a container the runtime reports
// terminated has its final flush already in the log, and the log is read once.
//
// The first two subtests pin the end-to-end outcome only (an interpreter's
// buffered stdout reaches the CRI log on a clean exit, a 64 KiB write arrives
// whole, nothing is dropped). Removing the post-exit drain wait did not turn
// them red in 40 runs on an M2: the interpreter flushes into the pipe before it
// exits, and the pump has written those bytes before the reap returns.
//
// The descendant subtest is the one that guards the drain. The container's
// leader forks and exits at once without writing; its child, still holding the
// inherited stdout pipe, writes a marker about 0.5 s later. That output reaches
// the log only because run() waits for the pumps to reach EOF (bounded by
// drainGrace, 5 s) before writing the exit record. The mutation that turns it
// red is dropping that wait (the select on drained) in internal/execshim's
// run(): the record, and so the terminated state, then precedes the marker.
//
// The prologue keeps every case honest about buffering: the script exits 3
// unless its stdout is a block-buffered pipe, and it runs before the fork, so
// the child inherits the same checked stream.
//
// The container's environment comes only from the spec, which sets none, so no
// PYTHONUNBUFFERED is present, and the command carries no -u.
func TestNativePodStdoutFromAnInterpreterReachesTheCRILog(t *testing.T) {
	if _, err := os.Stat(cltPython); err != nil {
		t.Skipf("Command Line Tools python3 is absent (%s: %v); install the Command Line Tools to run this test", cltPython, err)
	}
	root := shortRoot(t)

	shim := filepath.Join(root, sandbox.ExecShimName)
	build := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shim: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("sign shim: %v\n%s", err, out)
	}
	backend, err := sandbox.NewExecShimBackend(shim, root)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.Available() {
		t.Skip("exec-shim backend unavailable on this host")
	}

	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{Root: root, RuntimeVersion: "test", PodLogsDir: filepath.Join(root, "podlogs")}, Deps{
		Cache:   cache,
		Backend: backend,
		Spawner: supervisor.PosixSpawner{},
		Waiter:  supervisor.KqueueReaper{},
		Network: supervisor.NodeNetwork{IP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("print-then-exit", func(t *testing.T) {
		const marker = "k3sm-interpreter-log-marker"
		recs := runInterpreterPod(t, rt, "pod-interp-print", bufferedPrologue+"print('"+marker+"')\n")
		found := false
		for _, r := range recs {
			if r.stream == "stdout" && r.tag == "F" && r.msg == marker {
				found = true
			}
		}
		if !found {
			t.Errorf("CRI log has no %q line; records: %v", "stdout F "+marker, recs)
		}
	})

	t.Run("64KiB-buffered-write-then-exit", func(t *testing.T) {
		const n = 65536
		recs := runInterpreterPod(t, rt, "pod-interp-bulk",
			bufferedPrologue+"sys.stdout.write('y'*65536 + '\\nEND')\n")
		var lines []string
		var cur strings.Builder
		var last criRecord
		for _, r := range recs {
			if strings.Contains(r.msg, "bytes of stdout were dropped") {
				t.Errorf("the log reports dropped stdout: %q", r.msg)
			}
			if r.stream != "stdout" {
				continue
			}
			last = r
			cur.WriteString(r.msg)
			if r.tag == "F" {
				lines = append(lines, cur.String())
				cur.Reset()
			}
		}
		if len(lines) != 1 || lines[0] != strings.Repeat("y", n) {
			lens := make([]int, len(lines))
			for i, l := range lines {
				lens[i] = len(l)
			}
			t.Errorf("reassembled full stdout lines: %d (lengths %v), want exactly one line of %d 'y' bytes", len(lines), lens, n)
		}
		if cur.String() != "END" || last.tag != "P" || last.msg != "END" {
			t.Errorf("trailing stdout = %q, last record = %+v; want the unterminated chunk \"END\" tagged P", cur.String(), last)
		}
	})

	t.Run("descendant-buffered-write-after-leader-exit", func(t *testing.T) {
		const marker = "k3sm-descendant-log-marker"
		// The parent exits through os._exit so it flushes nothing; the child
		// writes into the inherited buffer and flushes it after the leader is gone.
		script := bufferedPrologue + "import time\n" +
			"if os.fork() == 0:\n" +
			"    time.sleep(0.5)\n" +
			"    sys.stdout.write('" + marker + "\\n')\n" +
			"    sys.stdout.flush()\n" +
			"    os._exit(0)\n" +
			"os._exit(0)\n"
		recs := runInterpreterPod(t, rt, "pod-interp-fork", script)
		found := false
		for _, r := range recs {
			if r.stream == "stdout" && r.tag == "F" && r.msg == marker {
				found = true
			}
		}
		if !found {
			t.Errorf("CRI log has no %q line once the container reported terminated; records: %v", "stdout F "+marker, recs)
		}
	})
}

// criRecord is one parsed CRI log line: "<timestamp> <stream> <P|F> <message>".
type criRecord struct {
	stream, tag, msg string
}

// runInterpreterPod runs script under the CLT python in a fresh native pod,
// waits for its container to terminate with exit 0, and returns the parsed CRI
// log records. Terminated implies the shim wrote the exit record, which it does
// only after the output pumps drained, so the log is read exactly once.
func runInterpreterPod(t *testing.T, rt *Runtime, podID, script string) []criRecord {
	t.Helper()
	box := &runtimev1.PodBox{
		PodId:        podID,
		Namespace:    "default",
		Name:         "interp",
		LogDirectory: testPodLogDir(rt, podID),
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: derivedRootfs(t, rt, podID),
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			{Name: "main", Image: NativeImage, Command: []string{cltPython, "-c", script}},
		},
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	t.Cleanup(func() {
		_, _ = rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID})
	})

	var cs *runtimev1.ContainerStatus
	deadline := time.Now().Add(30 * time.Second)
	for {
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		if s := gs.GetStatus().GetContainerStatuses(); len(s) == 1 && s[0].GetState().GetTerminated() != nil {
			cs = s[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("container did not terminate within 30s: %v", gs.GetStatus())
		}
		time.Sleep(50 * time.Millisecond)
	}
	term := cs.GetState().GetTerminated()
	logPath := cs.GetLogPath()
	if logPath == "" {
		logPath = term.GetLogPath()
	}
	if logPath == "" {
		t.Fatalf("terminated container status carries no log path: %v", cs)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read CRI log: %v", err)
	}
	recs := parseCRILog(t, string(raw))
	if term.GetExitCode() != 0 {
		t.Fatalf("container exit = %d (%s), want 0; log: %v", term.GetExitCode(), term.GetMessage(), recs)
	}
	return recs
}

// parseCRILog splits a CRI log into records; a malformed line fails the test.
func parseCRILog(t *testing.T, raw string) []criRecord {
	t.Helper()
	var recs []criRecord
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, " ", 4)
		if len(f) < 3 {
			t.Fatalf("malformed CRI log line %q", line)
		}
		r := criRecord{stream: f[1], tag: f[2]}
		if len(f) == 4 {
			r.msg = f[3]
		}
		recs = append(recs, r)
	}
	return recs
}
