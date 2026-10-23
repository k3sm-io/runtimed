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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/guestagent"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// markVMContainerRunning folds a running state for a test vm container, as the
// event watch does on its Started event.
func markVMContainerRunning(p *pod, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.guestContainers == nil {
		p.guestContainers = map[string]*runtimev1.ContainerStatus{}
	}
	p.guestContainers[name] = &runtimev1.ContainerStatus{
		Name:  name,
		State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}},
	}
}

// guestCaptureRuntime is a vm pod whose container "app" writes into a real guest
// agent's capture, followed by the host the way a running vm pod is.
func guestCaptureRuntime(t *testing.T, podID string) (*Runtime, *pod, io.WriteCloser) {
	t.Helper()
	capture := guestagent.NewCapture(0, 0, 0)
	dial := startRealGuestAgent(t, podID, guestagent.Deps{
		Runner: stubRunner{names: []string{"app"}},
		Logs:   capture,
		Events: guestagent.NewEvents(0),
	})
	rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
	p := addVMPod(t, rt, podID, "app")
	markVMContainerRunning(p, "app")
	return rt, p, capture.Writer("app", guestagent.StreamStdout)
}

// waitPayloads waits until the files at paths together hold want lines.
func waitPayloads(t *testing.T, want int, paths ...string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		n := 0
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				n += len(readCRILog(t, path))
			}
		}
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log files hold %d lines, want %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReopenVMContainerLogRotates is the gate: the node's rotation of a vm
// container's log works the way it does for a native one. The node renames
// 0.log aside and calls ReopenContainerLog while the container is writing; the
// follower must then be writing into a fresh 0.log, the renamed file must end
// on a whole line, and the two files together must hold every line exactly
// once, in order. Before the fix the verb answered Unimplemented, the node
// undid its rename, and the file grew past its cap forever.
func TestReopenVMContainerLogRotates(t *testing.T) {
	const (
		podID  = "pod-vm-rotate"
		before = 400
		total  = 1200
	)
	rt, p, out := guestCaptureRuntime(t, podID)
	path := startVMLogFollower(t, rt, p, "app")

	// The container writes continuously, across the rename and the reopen.
	var wrote atomic.Int64
	writeErr := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			if _, err := fmt.Fprintf(out, "line %06d\n", i); err != nil {
				writeErr <- err
				return
			}
			wrote.Add(1)
			if i >= before {
				time.Sleep(50 * time.Microsecond)
			}
		}
		writeErr <- nil
	}()
	waitPayloads(t, before, path)

	// The node's rotateLatestLog: rename, then reopen.
	rotated := path + ".20261016-120000"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.ReopenContainerLog(context.Background(),
		&runtimev1.ReopenContainerLogRequest{PodId: podID, Container: "app"}); err != nil {
		t.Fatalf("ReopenContainerLog: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no fresh file at the configured path once the reopen returned: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the fresh file's mode = %o, want 0600", mode)
	}
	// What the container writes from here on must reach the fresh file.
	writtenAtReopen := int(wrote.Load())
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	waitPayloads(t, total, rotated, path)

	raw, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Errorf("the renamed file does not end on a whole line: %q", raw[max(0, len(raw)-40):])
	}
	old, fresh := readCRILog(t, rotated), readCRILog(t, path)
	if len(fresh) == 0 {
		t.Fatal("nothing reached the fresh file after the reopen")
	}
	if len(fresh) < total-writtenAtReopen {
		t.Errorf("the fresh file holds %d lines, want at least the %d written after the reopen", len(fresh), total-writtenAtReopen)
	}
	union := append(old, fresh...)
	if len(union) != total {
		t.Fatalf("the two files hold %d lines, want %d (renamed %d, fresh %d)", len(union), total, len(old), len(fresh))
	}
	for i, l := range union {
		if want := fmt.Sprintf("line %06d", i); l.payload != want || l.tag != "F" {
			t.Fatalf("line %d is %q (tag %s), want %q: an entry was lost, duplicated or split across the switch",
				i, l.payload, l.tag, want)
		}
	}
}

// TestReopenVMContainerLogWithoutAFollower pins the reopen of a running vm
// container whose follower is not running (between a follower's end and the next
// one's start): it succeeds, creates the fresh file, and the next follower
// writes into that file rather than into the renamed one.
func TestReopenVMContainerLogWithoutAFollower(t *testing.T) {
	const podID = "pod-vm-reopen-idle"
	rt, p, out := guestCaptureRuntime(t, podID)
	path := filepath.Join(t.TempDir(), "0.log")
	w, err := crilog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.guestLogs = map[string]*crilog.Writer{"app": w}
	p.mu.Unlock()
	if err := w.Write(crilog.StreamStdout, []byte("before-rotation"), false); err != nil {
		t.Fatal(err)
	}

	rotated := path + ".20261016-120000"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.ReopenContainerLog(context.Background(),
		&runtimev1.ReopenContainerLogRequest{PodId: podID, Container: "app"}); err != nil {
		t.Fatalf("ReopenContainerLog with no follower: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no fresh file at the configured path: %v", err)
	}

	if _, err := fmt.Fprintln(out, "after-rotation"); err != nil {
		t.Fatal(err)
	}
	rt.startGuestLogFollower(p, "app")
	waitPayloads(t, 1, path)
	if lines := readCRILog(t, path); len(lines) != 1 || lines[0].payload != "after-rotation" {
		t.Errorf("the fresh file holds %v, want the next follower's output alone", lines)
	}
	if raw, _ := os.ReadFile(rotated); !bytes.HasSuffix(raw, []byte(" stdout F before-rotation\n")) || bytes.Count(raw, []byte("\n")) != 1 {
		t.Errorf("the renamed file holds %q, want the pre-rotation line alone", raw)
	}
}

// TestReopenVMContainerLogRefusals pins the answers that are not a reopen: an
// unknown container is NotFound and a container that is not running is
// FailedPrecondition, as on the native route.
func TestReopenVMContainerLogRefusals(t *testing.T) {
	rt := newTestRuntime(t, Deps{VMBackend: &fakeVMBackend{available: true}})
	p := addVMPod(t, rt, "pod-vm-reopen-refuse", "app")
	path := filepath.Join(t.TempDir(), "0.log")
	w, err := crilog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	p.mu.Lock()
	p.guestLogs = map[string]*crilog.Writer{"app": w}
	p.mu.Unlock()

	for _, tc := range []struct {
		name      string
		container string
		want      codes.Code
	}{
		{name: "unknown-container", container: "ghost", want: codes.NotFound},
		{name: "not-running", container: "app", want: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rt.ReopenContainerLog(context.Background(),
				&runtimev1.ReopenContainerLogRequest{PodId: "pod-vm-reopen-refuse", Container: tc.container})
			if status.Code(err) != tc.want {
				t.Errorf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
		})
	}
}
