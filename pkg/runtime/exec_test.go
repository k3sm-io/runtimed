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
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- exec/attach/portforward fakes ---------------------------------------

// recordingExecBackend records every WrapCommand call (so a test can assert exec
// reuses the pod's confinement seam) and PASSES through the argv unchanged, so
// the test runs the command directly — root-free, no k3sm-execshim binary or
// libsandbox. Production WrapCommand returns the shim invocation that runs
// supervisor.RunLaunchSequence (confine → drop → exec); the live Seatbelt-enforced
// exec is the m2.sh root e2e.
type recordingExecBackend struct {
	mu       sync.Mutex
	profiles []string
	argvs    [][]string
	specs    []supervisor.LaunchSpec
}

func (b *recordingExecBackend) Available() bool { return true }
func (b *recordingExecBackend) Name() string    { return "recording-exec" }
func (b *recordingExecBackend) WrapCommand(_ context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.profiles = append(b.profiles, profile)
	b.argvs = append(b.argvs, append([]string{}, argv...))
	b.specs = append(b.specs, spec)
	b.mu.Unlock()
	return argv[0], append([]string{}, argv...), func() error { return nil }, nil
}

func (b *recordingExecBackend) lastSpec() supervisor.LaunchSpec {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.specs[len(b.specs)-1]
}

func (b *recordingExecBackend) lastProfile() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.profiles[len(b.profiles)-1]
}

func (b *recordingExecBackend) lastArgv() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.argvs[len(b.argvs)-1]
}

// fakeExecStream is a grpc.BidiStreamingServer[ExecRequest, ExecResponse]: feed
// pushes client frames, closeSend half-closes (io.EOF), and out buffers responses.
type fakeExecStream struct {
	grpc.ServerStream
	ctx  context.Context
	in   chan *runtimev1.ExecRequest
	out  chan *runtimev1.ExecResponse
	once sync.Once
}

func newFakeExecStream(ctx context.Context) *fakeExecStream {
	return &fakeExecStream{ctx: ctx, in: make(chan *runtimev1.ExecRequest, 16), out: make(chan *runtimev1.ExecResponse, 256)}
}

func (s *fakeExecStream) Context() context.Context { return s.ctx }
func (s *fakeExecStream) Send(resp *runtimev1.ExecResponse) error {
	select {
	case s.out <- resp:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *fakeExecStream) Recv() (*runtimev1.ExecRequest, error) {
	select {
	case req, ok := <-s.in:
		if !ok {
			return nil, io.EOF
		}
		return req, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *fakeExecStream) feed(req *runtimev1.ExecRequest) { s.in <- req }
func (s *fakeExecStream) closeSend()                      { s.once.Do(func() { close(s.in) }) }

// collect drains responses until the terminal Exit frame, accumulating stdout.
func (s *fakeExecStream) collect(t *testing.T) (stdout []byte, exit int32) {
	t.Helper()
	for {
		select {
		case resp := <-s.out:
			stdout = append(stdout, resp.GetStdout()...)
			if resp.GetExit() != nil {
				return stdout, resp.GetExit().GetExitCode()
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out collecting exec output")
			return
		}
	}
}

// TestExecRunsAndReturnsExitCode execs a trivial command through the real spawn/
// stream path (root-free, non-dropping) and asserts stdout streams back, the exit
// code is reported, and the exec went through the confinement seam (WrapCommand)
// with the same SBPL profile as the pod's containers.
func TestExecRunsAndReturnsExitCode(t *testing.T) {
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Backend: be, Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-exec"))
	defer w.release(1001)

	rt.mu.Lock()
	profile := rt.pods["pod-exec"].profile
	rt.mu.Unlock()

	t.Run("stdout-and-exit-0", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-exec", Command: []string{"/bin/echo", "hello"}})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec: %v", err)
		}
		out, code := st.collect(t)
		if !strings.Contains(string(out), "hello") {
			t.Errorf("stdout = %q, want it to contain %q", out, "hello")
		}
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		// Confinement wiring: exec re-used WrapCommand with the pod's profile + the
		// requested argv, so a future SBPL change covers exec too.
		if got := be.lastProfile(); got != profile {
			t.Errorf("exec did not reuse the pod profile via WrapCommand (confinement seam)")
		}
		if argv := be.lastArgv(); len(argv) == 0 || argv[0] != "/bin/echo" {
			t.Errorf("exec argv through WrapCommand = %v, want it to start with /bin/echo", argv)
		}
	})

	t.Run("nonzero-exit-propagates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-exec", Command: []string{"/bin/sh", "-c", "exit 7"}})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec: %v", err)
		}
		_, code := st.collect(t)
		if code != 7 {
			t.Errorf("exit code = %d, want 7", code)
		}
	})

	t.Run("unknown-pod-not-found", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "nope", Command: []string{"/bin/echo"}})
		st.closeSend()
		err := rt.Exec(st)
		if status.Code(err) != codes.NotFound {
			t.Errorf("Exec(unknown pod) code = %v, want NotFound", status.Code(err))
		}
	})
}

// TestExecCarriesPodLaunchSpec pins the B7 one-code-path decision: an exec
// session re-enters the pod's full confinement domain — not just profile + uid
// drop but the pod's explicit rlimits and its qos class too — because Exec goes
// through the same WrapCommand choke-point as startContainer with the same
// resolved supervisor.LaunchSpec.
func TestExecCarriesPodLaunchSpec(t *testing.T) {
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Backend: be, Waiter: w})

	box := hostBinBox(rt, "pod-exec-spec")
	box.Rlimits = []*runtimev1.ResourceLimit{{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 4096}}
	box.QosClass = runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT
	mustCreatePod(t, rt, box)
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeExecStream(ctx)
	st.feed(&runtimev1.ExecRequest{PodId: "pod-exec-spec", Command: []string{"/bin/echo", "hi"}})
	st.closeSend()
	if err := rt.Exec(st); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	st.collect(t)

	spec := be.lastSpec()
	want := []supervisor.PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}}}
	if !reflect.DeepEqual(spec.Rlimits, want) {
		t.Errorf("exec WrapCommand spec.Rlimits = %+v, want the POD's plan %+v", spec.Rlimits, want)
	}
	if !spec.BgQoS {
		t.Error("exec WrapCommand spec.BgQoS = false, want true (the pod's BestEffort class)")
	}
}

// TestExecStreamsStdin pipes stdin to the command and asserts it reaches it (cat
// echoes its stdin back to stdout).
func TestExecStreamsStdin(t *testing.T) {
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Backend: be, Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-stdin"))
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeExecStream(ctx)
	st.feed(&runtimev1.ExecRequest{PodId: "pod-stdin", Command: []string{"/bin/cat"}, Stdin: true})
	st.feed(&runtimev1.ExecRequest{StdinData: []byte("ping\n")})
	st.closeSend() // EOF so cat flushes and exits

	if err := rt.Exec(st); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	out, code := st.collect(t)
	if !strings.Contains(string(out), "ping") {
		t.Errorf("stdin did not reach the command: stdout = %q, want it to contain %q", out, "ping")
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// --- attach --------------------------------------------------------------

// fakeAttachStream is a grpc.BidiStreamingServer[AttachRequest, AttachResponse].
type fakeAttachStream struct {
	grpc.ServerStream
	ctx  context.Context
	in   chan *runtimev1.AttachRequest
	out  chan *runtimev1.AttachResponse
	once sync.Once
}

func newFakeAttachStream(ctx context.Context) *fakeAttachStream {
	return &fakeAttachStream{ctx: ctx, in: make(chan *runtimev1.AttachRequest, 16), out: make(chan *runtimev1.AttachResponse, 256)}
}

func (s *fakeAttachStream) Context() context.Context { return s.ctx }
func (s *fakeAttachStream) Send(resp *runtimev1.AttachResponse) error {
	select {
	case s.out <- resp:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *fakeAttachStream) Recv() (*runtimev1.AttachRequest, error) {
	select {
	case req, ok := <-s.in:
		if !ok {
			return nil, io.EOF
		}
		return req, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *fakeAttachStream) feed(req *runtimev1.AttachRequest) { s.in <- req }
func (s *fakeAttachStream) recv(t *testing.T, d time.Duration) *runtimev1.AttachResponse {
	t.Helper()
	select {
	case resp := <-s.out:
		return resp
	case <-time.After(d):
		t.Fatal("timed out waiting for attach output")
		return nil
	}
}

// TestAttachStreamsContainerOutput attaches to a running container (no stdin) and
// asserts it follows the container's live combined output.
func TestAttachStreamsContainerOutput(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-attach"))
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeAttachStream(ctx)
	st.feed(&runtimev1.AttachRequest{PodId: "pod-attach", Stdout: true})

	done := make(chan error, 1)
	go func() { done <- rt.Attach(st) }()

	// Simulate container output landing in the combined-log buffer.
	rt.mu.Lock()
	p := rt.pods["pod-attach"]
	rt.mu.Unlock()
	// Give Attach a moment to subscribe, then write a line.
	time.Sleep(50 * time.Millisecond)
	p.mu.Lock()
	p.containers[0].logs.write([]byte("hello-from-container"))
	p.mu.Unlock()

	resp := st.recv(t, 3*time.Second)
	if !strings.Contains(string(resp.GetStdout()), "hello-from-container") {
		t.Errorf("attach stdout = %q, want it to contain %q", resp.GetStdout(), "hello-from-container")
	}

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Errorf("Attach returned %v, want nil/context.Canceled", err)
	}
}

// TestAttachRejectsStdin documents the M2 limitation: interactive (stdin) attach
// to an already-running native process is Unimplemented (stdin is not retained at
// posix_spawn); kubectl exec is the supported interactive path.
func TestAttachRejectsStdin(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-attach-stdin"))
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeAttachStream(ctx)
	st.feed(&runtimev1.AttachRequest{PodId: "pod-attach-stdin", Stdin: true})
	err := rt.Attach(st)
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("Attach(stdin) code = %v, want Unimplemented", status.Code(err))
	}
}

// --- port-forward --------------------------------------------------------

// fakePFStream is a grpc.BidiStreamingServer[PortForwardRequest, PortForwardResponse].
type fakePFStream struct {
	grpc.ServerStream
	ctx  context.Context
	in   chan *runtimev1.PortForwardRequest
	out  chan *runtimev1.PortForwardResponse
	once sync.Once
}

func newFakePFStream(ctx context.Context) *fakePFStream {
	return &fakePFStream{ctx: ctx, in: make(chan *runtimev1.PortForwardRequest, 16), out: make(chan *runtimev1.PortForwardResponse, 256)}
}

func (s *fakePFStream) Context() context.Context { return s.ctx }
func (s *fakePFStream) Send(resp *runtimev1.PortForwardResponse) error {
	select {
	case s.out <- resp:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *fakePFStream) Recv() (*runtimev1.PortForwardRequest, error) {
	select {
	case req, ok := <-s.in:
		if !ok {
			return nil, io.EOF
		}
		return req, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *fakePFStream) feed(req *runtimev1.PortForwardRequest) { s.in <- req }
func (s *fakePFStream) recv(t *testing.T, d time.Duration) *runtimev1.PortForwardResponse {
	t.Helper()
	select {
	case resp := <-s.out:
		return resp
	case <-time.After(d):
		t.Fatal("timed out waiting for port-forward response")
		return nil
	}
}

// TestPortForwardProxiesBytes stands a local listener in for the pod port and
// asserts bytes proxy both directions: client→pod (the listener reads "ping") and
// pod→client (the stream receives the listener's "pong").
func TestPortForwardProxiesBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	gotPing := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		n, _ := io.ReadFull(conn, buf)
		gotPing <- string(buf[:n])
		_, _ = conn.Write([]byte("pong"))
	}()

	// The pod IP is loopback so the proxy dial reaches the local listener.
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w, Network: supervisor.NodeNetwork{IP: "127.0.0.1"}})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-pf"))
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakePFStream(ctx)
	st.feed(&runtimev1.PortForwardRequest{PodId: "pod-pf", Port: int32(port), ConnectionId: 1, Data: []byte("ping")})

	done := make(chan error, 1)
	go func() { done <- rt.PortForward(st) }()

	// pod→client: the listener's "pong" comes back over the stream.
	resp := st.recv(t, 3*time.Second)
	if string(resp.GetData()) != "pong" {
		t.Errorf("pod→client data = %q, want %q", resp.GetData(), "pong")
	}
	if resp.GetConnectionId() != 1 {
		t.Errorf("connection_id = %d, want 1", resp.GetConnectionId())
	}

	// client→pod: the listener received "ping".
	select {
	case ping := <-gotPing:
		if ping != "ping" {
			t.Errorf("listener received %q, want %q", ping, "ping")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener never received client bytes")
	}

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Errorf("PortForward returned %v, want nil/context.Canceled", err)
	}
}
