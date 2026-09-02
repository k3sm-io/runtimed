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

package guestinit

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"syscall"
	"testing"
)

// TestPlanExecIOWiring walks all four (tty, stdin) combinations. Each subtest
// pins one property that, if wrong, produces a hang or a silently wrong terminal
// rather than a compile error — which is exactly why the decision lives in a
// pure function on the darwin-testable side.
func TestPlanExecIOWiring(t *testing.T) {
	t.Parallel()

	t.Run("a tty exec runs the child on the slave three times over", func(t *testing.T) {
		w := PlanExecIO(true, true)
		if !w.TTY {
			t.Fatal("PlanExecIO(true, …).TTY is false")
		}
		want := [3]ExecFD{FDPTYSlave, FDPTYSlave, FDPTYSlave}
		if w.ChildFiles != want {
			t.Errorf("child files = %v, want %v (a tty has one descriptor, not three)", w.ChildFiles, want)
		}
		if got := strings.Join(execFDStrings(w.Open), ","); got != "pty-master,pty-slave" {
			t.Errorf("opened = %s, want the pty pair only", got)
		}
	})

	t.Run("a tty exec takes a controlling terminal at child fd 0", func(t *testing.T) {
		w := PlanExecIO(true, false)
		if !w.Setsid || !w.Setctty {
			t.Errorf("Setsid=%v Setctty=%v, want both (no session, no job control)", w.Setsid, w.Setctty)
		}
		if w.Ctty != 0 {
			t.Errorf("Ctty = %d, want 0: it indexes the CHILD's descriptors and the slave is fd 0", w.Ctty)
		}
		if w.ChildFiles[w.Ctty] != FDPTYSlave {
			t.Errorf("ChildFiles[Ctty] = %q, want the pty slave", w.ChildFiles[w.Ctty])
		}
	})

	t.Run("a tty exec has ONE output pump, on stdout, with the EIO rule", func(t *testing.T) {
		w := PlanExecIO(true, true)
		if len(w.Outputs) != 1 {
			t.Fatalf("%d output pumps, want 1: the line discipline merged stderr into stdout", len(w.Outputs))
		}
		p := w.Outputs[0]
		if p.Source != FDPTYMaster || p.Stream != StreamStdout || !p.TTYEOF {
			t.Errorf("pump = %+v, want master -> stdout with the EIO-is-EOF rule", p)
		}
	})

	t.Run("a non-tty exec keeps stdout and stderr demultiplexed", func(t *testing.T) {
		w := PlanExecIO(false, true)
		if len(w.Outputs) != 2 {
			t.Fatalf("%d output pumps, want 2", len(w.Outputs))
		}
		if w.Outputs[0].Source != FDStdoutRead || w.Outputs[0].Stream != StreamStdout {
			t.Errorf("first pump = %+v, want stdout", w.Outputs[0])
		}
		if w.Outputs[1].Source != FDStderrRead || w.Outputs[1].Stream != StreamStderr {
			t.Errorf("second pump = %+v, want stderr", w.Outputs[1])
		}
		for _, p := range w.Outputs {
			if p.TTYEOF {
				t.Errorf("pump %+v applies the EIO rule; a pipe reports EOF properly and EIO would be a real error", p)
			}
		}
		if w.Setctty {
			t.Error("a non-tty exec asked for a controlling terminal")
		}
		if w.InitialSize != (WinSize{}) {
			t.Errorf("a non-tty exec carries an initial window size %+v", w.InitialSize)
		}
		if w.Resize {
			t.Error("a non-tty exec asked for a resize consumer")
		}
	})

	t.Run("a fresh pty is sized before the fork", func(t *testing.T) {
		w := PlanExecIO(true, true)
		if w.InitialSize != DefaultWinSize {
			t.Errorf("initial size = %+v, want %+v", w.InitialSize, DefaultWinSize)
		}
		if w.InitialSize.Rows == 0 || w.InitialSize.Cols == 0 {
			t.Error("the default window size has a zero dimension; `stty size` would report 0 0")
		}
		if !w.Resize {
			t.Error("a tty exec runs no resize consumer; SIGWINCH would never reach the workload")
		}
	})

	t.Run("client stdin reaches the right sink, and the tty sink is never closed", func(t *testing.T) {
		tty := PlanExecIO(true, true)
		if tty.StdinSink != FDPTYMaster {
			t.Errorf("tty stdin sink = %q, want the pty master", tty.StdinSink)
		}
		if tty.CloseStdinSinkOnEOF {
			t.Error("closing a pty master on client EOF hangs the child up; ^D is how a tty signals EOF")
		}
		pipes := PlanExecIO(false, true)
		if pipes.StdinSink != FDStdinWrite || !pipes.CloseStdinSinkOnEOF {
			t.Errorf("pipe stdin = %q close-on-eof %v, want the write end, closed", pipes.StdinSink, pipes.CloseStdinSinkOnEOF)
		}
	})

	t.Run("an exec that was not given stdin never leaves a writer open", func(t *testing.T) {
		w := PlanExecIO(false, false)
		if w.StdinSink != FDNone {
			t.Errorf("stdin sink = %q, want none", w.StdinSink)
		}
		if !containsFD(w.CloseAfterFork, FDStdinWrite) {
			t.Error("the unused stdin write end is not closed after the fork; a command reading stdin would block forever")
		}
	})

	t.Run("teardown closes the child's ends at the fork and the pumps' sources after the wait", func(t *testing.T) {
		tty := PlanExecIO(true, true)
		if !containsFD(tty.CloseAfterFork, FDPTYSlave) {
			t.Error("the parent keeps the pty slave open; the master would never see EIO and the exec would hang")
		}
		if containsFD(tty.CloseAfterFork, FDPTYMaster) {
			t.Error("the pty master is closed at the fork; the terminal would be gone before the child ran")
		}
		if !containsFD(tty.CloseAfterWait, FDPTYMaster) {
			t.Error("the pty master is never closed")
		}

		pipes := PlanExecIO(false, true)
		for _, fd := range []ExecFD{FDStdinRead, FDStdoutWrite, FDStderrWrite} {
			if !containsFD(pipes.CloseAfterFork, fd) {
				t.Errorf("%q is not closed after the fork", fd)
			}
		}
		for _, fd := range []ExecFD{FDStdoutRead, FDStderrRead} {
			if containsFD(pipes.CloseAfterFork, fd) {
				t.Errorf("%q is closed at the fork, racing its own pump for the command's last output", fd)
			}
			if !containsFD(pipes.CloseAfterWait, fd) {
				t.Errorf("%q is never closed", fd)
			}
		}
	})

	t.Run("every descriptor a plan opens is closed exactly once", func(t *testing.T) {
		for _, c := range []struct{ tty, stdin bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
			name := fmt.Sprintf("tty=%v/stdin=%v", c.tty, c.stdin)
			w := PlanExecIO(c.tty, c.stdin)
			closed := map[ExecFD]int{}
			for _, fd := range append(append([]ExecFD{}, w.CloseAfterFork...), w.CloseAfterWait...) {
				closed[fd]++
			}
			if w.CloseStdinSinkOnEOF {
				closed[w.StdinSink]++
			} else if w.StdinSink != FDNone && !w.TTY {
				t.Errorf("%s: a pipe stdin sink that is not closed on EOF leaks", name)
			}
			for _, fd := range w.Open {
				if closed[fd] != 1 {
					t.Errorf("%s: %q is closed %d times, want exactly 1", name, fd, closed[fd])
				}
			}
			for fd := range closed {
				if !containsFD(w.Open, fd) {
					t.Errorf("%s: the plan closes %q, which it never opened", name, fd)
				}
			}
		}
	})
}

// TestExecPTYOriginPrefersTheContainerInstance pins the invariant PTYOrigin
// documents: a container with its own devpts allocates there, and only a
// container without one falls back to the guest's.
func TestExecPTYOriginPrefersTheContainerInstance(t *testing.T) {
	t.Parallel()
	root := ContainerRootDir("app")

	t.Run("a container with a private devpts allocates from its own ptmx", func(t *testing.T) {
		o := ExecPTYOrigin(ContainerPlan{Name: "app", Root: root, DevPtsDir: path.Join(root, "dev/pts")})
		if !o.Container {
			t.Fatal("origin is not the container's")
		}
		if o.Root != root {
			t.Errorf("Root = %q, want %q: the paths are container-absolute and must be resolved inside it", o.Root, root)
		}
		if o.Ptmx != "/dev/pts/ptmx" {
			t.Errorf("Ptmx = %q, want /dev/pts/ptmx (the instance's own multiplexer, not /dev/ptmx)", o.Ptmx)
		}
		if o.Pts != "/dev/pts" {
			t.Errorf("Pts = %q, want /dev/pts", o.Pts)
		}
	})

	t.Run("a container whose /dev a pod mount covers falls back to the guest", func(t *testing.T) {
		o := ExecPTYOrigin(ContainerPlan{Name: "app", Root: root})
		if o.Container {
			t.Fatal("origin claims to be the container's, but the container has no devpts")
		}
		if o.Root != "" {
			t.Errorf("Root = %q, want empty: the guest paths are already guest paths", o.Root)
		}
		if o.Ptmx != GuestPtmxPath || o.Pts != GuestPtsDir {
			t.Errorf("origin = %s / %s, want %s / %s", o.Ptmx, o.Pts, GuestPtmxPath, GuestPtsDir)
		}
	})

	t.Run("the ptmx the plan mounts and the ptmx an exec opens are the same node", func(t *testing.T) {
		// The devpts mount, the /dev/ptmx symlink and the exec's origin are
		// three statements of one path. A drift between them is invisible until
		// a lab run, so it is pinned here.
		dev := ContainerDev("app", nil)
		if dev.PtsDir != path.Join(root, "dev/pts") {
			t.Fatalf("planned devpts at %q, want %q", dev.PtsDir, path.Join(root, "dev/pts"))
		}
		o := ExecPTYOrigin(ContainerPlan{Name: "app", Root: root, DevPtsDir: dev.PtsDir})
		if got := path.Join(o.Root, o.Ptmx); got != path.Join(dev.PtsDir, "ptmx") {
			t.Errorf("exec opens %q but the plan mounts the instance at %q", got, dev.PtsDir)
		}
		if len(dev.Links) != 1 || dev.Links[0].LinkTo != "pts/ptmx" {
			t.Errorf("links = %+v, want /dev/ptmx -> pts/ptmx", dev.Links)
		}
	})
}

// TestPumpResizeAppliesEverySizeInOrder drives the resize consumer with a fake
// source and a fake ioctl. It is the seam's whole point: the real one runs in a
// goroutine inside a linux-only file, and this is where its ordering, its
// termination and its error posture are actually checked.
func TestPumpResizeAppliesEverySizeInOrder(t *testing.T) {
	t.Parallel()

	t.Run("every delivered size is applied, in order", func(t *testing.T) {
		in := []WinSize{{Rows: 24, Cols: 80}, {Rows: 50, Cols: 200}, {Rows: 1, Cols: 1}}
		var got []WinSize
		err := PumpResize(sizes(in), func(sz WinSize) error {
			got = append(got, sz)
			return nil
		})
		if err != nil {
			t.Fatalf("PumpResize: %v", err)
		}
		if len(got) != len(in) {
			t.Fatalf("applied %d sizes, want %d", len(got), len(in))
		}
		for i := range in {
			if got[i] != in[i] {
				t.Errorf("size %d = %+v, want %+v (a reordered resize leaves the terminal at the wrong size)", i, got[i], in[i])
			}
		}
	})

	t.Run("the pump ends when the source ends, and not before", func(t *testing.T) {
		calls := 0
		if err := PumpResize(sizes(nil), func(WinSize) error { calls++; return nil }); err != nil {
			t.Fatalf("PumpResize: %v", err)
		}
		if calls != 0 {
			t.Errorf("%d ioctls for an empty stream", calls)
		}
	})

	t.Run("a failing ioctl ends the pump rather than spinning on a dead terminal", func(t *testing.T) {
		want := errors.New("bad file descriptor")
		calls := 0
		err := PumpResize(sizes([]WinSize{{Rows: 1, Cols: 1}, {Rows: 2, Cols: 2}}), func(WinSize) error {
			calls++
			return want
		})
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
		if calls != 1 {
			t.Errorf("%d ioctls after the first failure, want 1", calls)
		}
	})
}

// TestTTYReaderTreatsEIOAsEndOfStream pins the rule without which every
// successful tty exec would report a read failure.
func TestTTYReaderTreatsEIOAsEndOfStream(t *testing.T) {
	t.Parallel()

	t.Run("EIO becomes EOF and keeps the bytes read with it", func(t *testing.T) {
		r := TTYReader(&scriptReader{steps: []step{
			{data: "hello", err: nil},
			{data: "bye", err: &pathErr{err: syscall.EIO}},
		}})
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v (EIO must read as a clean end of stream)", err)
		}
		if string(out) != "hellobye" {
			t.Errorf("read %q, want %q: the last bytes arrived with the EIO and must not be dropped", out, "hellobye")
		}
	})

	t.Run("a real error is still an error", func(t *testing.T) {
		want := syscall.EPERM
		r := TTYReader(&scriptReader{steps: []step{{err: want}}})
		if _, err := io.ReadAll(r); !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
	})

	t.Run("IsTTYEOF sees through the wrapping os.File applies", func(t *testing.T) {
		if !IsTTYEOF(&pathErr{err: syscall.EIO}) {
			t.Error("a *fs.PathError wrapping EIO is not recognised; os.File returns exactly that shape")
		}
		if IsTTYEOF(io.EOF) || IsTTYEOF(syscall.EPERM) {
			t.Error("IsTTYEOF matched something that is not EIO")
		}
	})
}

// sizes returns a PumpResize source that yields in, then reports the end.
func sizes(in []WinSize) func() (WinSize, bool) {
	i := 0
	return func() (WinSize, bool) {
		if i >= len(in) {
			return WinSize{}, false
		}
		sz := in[i]
		i++
		return sz, true
	}
}

// step is one scripted read.
type step struct {
	data string
	err  error
}

// scriptReader replays a fixed sequence of reads, which is how a pty master's
// final "some bytes AND an EIO" call is reproduced without a pty.
type scriptReader struct {
	steps []step
	i     int
}

func (s *scriptReader) Read(p []byte) (int, error) {
	if s.i >= len(s.steps) {
		return 0, io.EOF
	}
	st := s.steps[s.i]
	s.i++
	n := copy(p, st.data)
	return n, st.err
}

// pathErr mimics the *fs.PathError os.File wraps a raw errno in.
type pathErr struct{ err error }

func (e *pathErr) Error() string { return "read /dev/pts/0: " + e.err.Error() }
func (e *pathErr) Unwrap() error { return e.err }

// execFDStrings renders a descriptor list for a comparison message.
func execFDStrings(fds []ExecFD) []string {
	out := make([]string, 0, len(fds))
	for _, fd := range fds {
		out = append(out, string(fd))
	}
	return out
}

// containsFD reports whether fds contains want.
func containsFD(fds []ExecFD, want ExecFD) bool {
	for _, fd := range fds {
		if fd == want {
			return true
		}
	}
	return false
}
