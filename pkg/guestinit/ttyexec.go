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
	"io"
	"path"
	"syscall"
)

// The guest's own pty devices, from the devtmpfs and devpts the boot mounts
// (PseudoMounts). They are the FALLBACK origin for an exec's pty — see
// ExecPTYOrigin for why a container's own instance is preferred.
const (
	// GuestPtmxPath is the guest-root pty multiplexer.
	GuestPtmxPath = "/dev/ptmx"

	// GuestPtsDir is the guest-root devpts instance the slaves appear in.
	GuestPtsDir = "/dev/pts"
)

// ContainerPtmxPath and ContainerPtsDir are the CONTAINER-ABSOLUTE paths of a
// container's private devpts instance — what the container itself sees after the
// chroot, and what ContainerDevMounts mounts.
const (
	ContainerPtmxPath = "/dev/pts/ptmx"
	ContainerPtsDir   = "/dev/pts"
)

// WinSize is a terminal window size in character cells.
//
// It mirrors struct winsize's two meaningful fields without importing the
// linux-only unix package, so the resize plumbing below is ordinary Go that a
// darwin `go test -race` reaches. SetWinsize performs the one ioctl this
// translates to.
type WinSize struct {
	Rows, Cols uint16
}

// DefaultWinSize is the size a freshly allocated pty is given before the child
// is forked.
//
// A pty comes up 0x0, and `kubectl exec -it` delivers the client's real size as
// a resize FRAME that races the child's first instruction. A shell that ran
// `stty size` — or any curses program that sized itself — before that frame
// arrived saw "0 0" and laid itself out for a terminal with no cells. 24x80 is
// the historical default every terminal-aware program is already written
// against, and the client's first resize supersedes it microseconds later.
var DefaultWinSize = WinSize{Rows: 24, Cols: 80}

// PTYOrigin names where an exec's pty pair is allocated from.
//
// # The invariant
//
// A pty slave's PATH must be valid INSIDE the chroot the exec'd process runs in.
// The kernel gives the slave an index N within the devpts INSTANCE its ptmx
// belongs to, and every consumer that turns a tty fd back into a name —
// ttyname(3), `tty(1)`, ps's TTY column, a shell's job control — resolves that N
// against whatever /dev/pts the process can see.
//
// Since each container gets its OWN devpts instance (ContainerDevMounts), a pty
// allocated from the GUEST's /dev/ptmx has an index that means nothing in the
// container's instance: /dev/pts/N is either absent there, or — worse — present
// and belonging to a DIFFERENT pty that some other process in the same container
// allocated. The first makes `tty` report no terminal; the second makes a write
// to the reported path land on someone else's terminal.
//
// So an exec allocates from the container's own ptmx whenever the container has
// a private instance, and the guest's only when it does not (a pod that mounted
// something of its own over /dev or /dev/pts — see ContainerDevMounts). The
// choice is DATA on the plan rather than a probe at exec time, so it is pinned
// by a unit test rather than discovered in a lab.
type PTYOrigin struct {
	// Root is the container root Ptmx and Pts must be resolved inside, with
	// chroot semantics (ResolveTarget). It is empty for the guest origin, whose
	// paths are already guest paths.
	Root string

	// Ptmx is the multiplexer to open, and Pts the directory the slave appears
	// in. Both are container-absolute when Root is set.
	Ptmx string
	Pts  string

	// Container reports whether this is the container's own instance. A false
	// here is the degraded case described above and is worth a log line.
	Container bool
}

// ExecPTYOrigin returns where an exec into cp must allocate its pty. See
// PTYOrigin for the invariant it encodes.
func ExecPTYOrigin(cp ContainerPlan) PTYOrigin {
	if cp.DevPtsDir == "" {
		return PTYOrigin{Ptmx: GuestPtmxPath, Pts: GuestPtsDir}
	}
	return PTYOrigin{
		Root:      cp.Root,
		Ptmx:      path.Join(ContainerPtsDir, "ptmx"),
		Pts:       ContainerPtsDir,
		Container: true,
	}
}

// ExecFD names one descriptor in an exec's stdio wiring. The plan is expressed
// in names rather than in *os.File values so the whole shape is comparable in a
// table test on a platform that has neither a devpts nor a fork/exec of a
// chrooted child.
type ExecFD string

// The descriptors an exec can carry.
const (
	// FDNone is the absence of a descriptor.
	FDNone ExecFD = ""

	// FDStdinRead and FDStdinWrite are the non-tty stdin pipe's two ends.
	FDStdinRead  ExecFD = "stdin-r"
	FDStdinWrite ExecFD = "stdin-w"

	// FDStdoutRead and FDStdoutWrite are the non-tty stdout pipe's two ends.
	FDStdoutRead  ExecFD = "stdout-r"
	FDStdoutWrite ExecFD = "stdout-w"

	// FDStderrRead and FDStderrWrite are the non-tty stderr pipe's two ends.
	FDStderrRead  ExecFD = "stderr-r"
	FDStderrWrite ExecFD = "stderr-w"

	// FDPTYMaster and FDPTYSlave are the pty pair's two ends.
	FDPTYMaster ExecFD = "pty-master"
	FDPTYSlave  ExecFD = "pty-slave"
)

// ExecStream names which of the client's two output streams a pump feeds.
type ExecStream string

// The client-visible output streams.
const (
	StreamStdout ExecStream = "stdout"
	StreamStderr ExecStream = "stderr"
)

// OutputPump is one parent-side reader draining a descriptor into a client
// stream.
type OutputPump struct {
	// Source is the descriptor to read.
	Source ExecFD

	// Stream is the client stream the bytes are framed as.
	Stream ExecStream

	// TTYEOF is set when the source is a pty master, whose end of stream
	// arrives as EIO rather than as a zero-length read. See TTYReader.
	TTYEOF bool
}

// ExecWiring is the whole plan for one exec's stdio: what to open, what the
// child's three descriptors are, the process attributes the terminal requires,
// which pumps to run, and — the half that is easiest to get wrong — the order in
// which each end is closed.
type ExecWiring struct {
	// TTY reports whether this exec runs on a pseudo-terminal.
	TTY bool

	// Open are the descriptors the caller creates, in order. For a tty that is
	// the pty pair; otherwise the three pipes.
	Open []ExecFD

	// ChildFiles are the child's descriptors 0, 1 and 2.
	ChildFiles [3]ExecFD

	// Setsid, Setctty and Ctty are the SysProcAttr shape.
	//
	// Ctty indexes ChildFiles — Linux performs the TIOCSCTTY ioctl AFTER the
	// fork's descriptor dance, so it names the CHILD's fd number and not the
	// parent's. The slave is ChildFiles[0], hence 0. A stale value here does not
	// fail loudly: the child simply never acquires a controlling terminal, and
	// the first thing to notice is that ^C does nothing.
	Setsid  bool
	Setctty bool
	Ctty    int

	// InitialSize is applied to the pty before the fork. Zero for a non-tty.
	InitialSize WinSize

	// Outputs are the pumps to run. A tty has exactly ONE: stdout and stderr are
	// merged by the line discipline before either reaches the master, so there
	// is no second stream to read and nothing to demultiplex. That mirrors the
	// darwin host path, which likewise frames a tty exec's output as Stdout
	// only — the two ends must agree or a tty exec's stderr would arrive on a
	// different stream depending on the pod's backend.
	Outputs []OutputPump

	// StdinSink is where client stdin bytes are written, or FDNone when stdin is
	// not wired.
	StdinSink ExecFD

	// CloseStdinSinkOnEOF closes StdinSink when the client half-closes, which is
	// how the child's stdin reaches EOF.
	//
	// It is FALSE for a tty. The sink there is the pty MASTER, and closing it
	// does not deliver EOF — it destroys the terminal, hanging up the child's
	// session with SIGHUP. A tty client signals end of input with ^D, which the
	// line discipline turns into the zero-length read the child is waiting for.
	CloseStdinSinkOnEOF bool

	// Resize reports whether a resize consumer must run for this exec.
	Resize bool

	// CloseAfterFork are the descriptors the PARENT closes immediately after the
	// fork: the child's own ends. Holding the write end of a pipe open here
	// means the reader never sees EOF and the exec appears to hang after the
	// command has exited; holding the pty slave open means the same for the
	// master's EIO.
	CloseAfterFork []ExecFD

	// CloseAfterWait are the descriptors closed only after the child has been
	// reaped AND every pump has drained. Closing a pump's source earlier races
	// the pump for the last bytes the command wrote.
	CloseAfterWait []ExecFD
}

// PlanExecIO returns the wiring for one exec.
//
// tty and stdin are the two bits `kubectl exec` carries, and every difference
// between the four combinations is decided here rather than at four call sites
// in a linux-only file no test can reach.
func PlanExecIO(tty, stdin bool) ExecWiring {
	if tty {
		w := ExecWiring{
			TTY:        true,
			Open:       []ExecFD{FDPTYMaster, FDPTYSlave},
			ChildFiles: [3]ExecFD{FDPTYSlave, FDPTYSlave, FDPTYSlave},
			// Setsid detaches the child from PID 1's session so it can acquire
			// one of its own; Setctty then makes the slave that session's
			// controlling terminal, which is what job control, ^C and SIGWINCH
			// all require. A tty without a controlling terminal is a pipe that
			// happens to echo.
			Setsid:         true,
			Setctty:        true,
			Ctty:           0,
			InitialSize:    DefaultWinSize,
			Outputs:        []OutputPump{{Source: FDPTYMaster, Stream: StreamStdout, TTYEOF: true}},
			Resize:         true,
			CloseAfterFork: []ExecFD{FDPTYSlave},
			CloseAfterWait: []ExecFD{FDPTYMaster},
		}
		if stdin {
			w.StdinSink = FDPTYMaster
		}
		return w
	}

	w := ExecWiring{
		Open: []ExecFD{
			FDStdinRead, FDStdinWrite,
			FDStdoutRead, FDStdoutWrite,
			FDStderrRead, FDStderrWrite,
		},
		ChildFiles: [3]ExecFD{FDStdinRead, FDStdoutWrite, FDStderrWrite},
		Setsid:     true,
		Outputs: []OutputPump{
			{Source: FDStdoutRead, Stream: StreamStdout},
			{Source: FDStderrRead, Stream: StreamStderr},
		},
		CloseAfterFork: []ExecFD{FDStdinRead, FDStdoutWrite, FDStderrWrite},
		CloseAfterWait: []ExecFD{FDStdoutRead, FDStderrRead},
	}
	if stdin {
		w.StdinSink = FDStdinWrite
		w.CloseStdinSinkOnEOF = true
		return w
	}
	// Nothing will ever write to the stdin pipe, so its write end goes with the
	// child's ends: a command that reads stdin must get EOF rather than block
	// forever on a pipe whose only writer is a caller that is not going to write.
	w.CloseAfterFork = append(w.CloseAfterFork, FDStdinWrite)
	return w
}

// PumpResize applies every terminal size next yields to set, in order, until
// next reports the stream has ended.
//
// next is a closure rather than a channel so the caller can adapt whatever type
// its transport delivers without an extra goroutine standing between the client
// and the ioctl — and so a table test can drive the pump with a slice.
//
// A set failure ENDS the pump and is returned. The only ioctl failure a live pty
// produces is EBADF after the master has been closed, which happens on exactly
// one path — teardown — so continuing would spin on a dead descriptor for as
// long as the client keeps resizing its window. A resize that is dropped because
// the terminal is already gone has nothing to be applied to.
func PumpResize(next func() (WinSize, bool), set func(WinSize) error) error {
	for {
		sz, ok := next()
		if !ok {
			return nil
		}
		if err := set(sz); err != nil {
			return err
		}
	}
}

// TTYReader adapts a pty master so its end of stream reads as io.EOF.
//
// A master does not report EOF. Once the last descriptor on the slave side is
// closed — which happens when the exec'd process exits — every read returns
// EIO, and a pump that treated it as a read error would report a failure on
// every single successful tty exec. This is the same rule the darwin host path
// applies to its own master; the two must agree, because the client cannot tell
// which backend answered.
//
// Bytes read alongside the error are preserved: a kernel is entitled to return
// the last of the terminal's output and the EIO in one call.
func TTYReader(r io.Reader) io.Reader { return ttyReader{r: r} }

// ttyReader is TTYReader's implementation.
type ttyReader struct{ r io.Reader }

func (t ttyReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && IsTTYEOF(err) {
		return n, io.EOF
	}
	return n, err
}

// IsTTYEOF reports whether err is a pty master's end of stream.
//
// syscall.EIO is used rather than the linux-only unix.EIO so this predicate is
// reachable from a darwin test; errno 5 is EIO on both, and on every other Unix.
func IsTTYEOF(err error) bool {
	return errors.Is(err, syscall.EIO)
}
