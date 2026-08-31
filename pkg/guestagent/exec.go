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

package guestagent

import (
	"errors"
	"fmt"
	"io"
)

// maxExecArgv and maxExecArgBytes bound one exec's command.
//
// The command arrives from the host, which got it from an authenticated
// `kubectl exec` — so this is not a trust boundary. It is a bound on what PID 1 of
// a small guest will try to allocate before execve(2) refuses it anyway: E2BIG
// from the kernel is a worse diagnostic than a named refusal, and building the
// argv first means having already allocated it.
const (
	maxExecArgv      = 1024
	maxExecArgBytes  = 1 << 20
	execCopyChunkMax = 32 << 10
)

// ErrExecInvalid reports an exec request the agent will not run.
var ErrExecInvalid = errors.New("guestagent: invalid exec request")

// ExecSpec is one `kubectl exec` as the guest runs it.
type ExecSpec struct {
	// Container is the container name within the pod, ALREADY RESOLVED HOST-SIDE
	// against what the pod declared. The agent still checks it against its own
	// container set — the host's resolution and the guest's reality are two
	// different facts, and a container that has exited is knowable only here.
	Container string
	// Argv is the command and its arguments.
	Argv []string
	// TTY requests a pseudo-terminal.
	TTY bool
	// Stdin keeps standard input open.
	Stdin bool
}

// ExecIO is the exec's stream plumbing. Stdout and Stderr stay SEPARATE even under
// TTY: merging is the host's presentation choice, and a split that was collapsed
// here could not be recovered there.
type ExecIO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Resize delivers terminal size changes for a TTY exec; nil for a non-TTY.
	Resize <-chan TerminalSize
}

// TerminalSize is a tty window size, mirroring runtime/v1's TerminalSize without
// importing it — this file stays proto-free so the exec plumbing is testable as
// plain Go.
type TerminalSize struct {
	Width, Height uint32
}

// ExecResult is an exec's terminal outcome.
type ExecResult struct {
	// ExitCode is the process's exit status. See ExitCodeForSignal for the
	// signal case.
	ExitCode int32
}

// ValidateExec rejects an exec the guest will not attempt.
//
// An EMPTY ARGV is the one that matters. execve(2) with no program is not a
// no-op — depending on how the argv is assembled it is either an error the caller
// sees late or, worse, a spawn of something unintended — and upstream's own rule
// is that `kubectl exec` requires a command. Rejecting it here means the failure
// names itself.
func ValidateExec(spec ExecSpec) error {
	if spec.Container == "" {
		return fmt.Errorf("%w: no container selected", ErrExecInvalid)
	}
	if len(spec.Argv) == 0 {
		return fmt.Errorf("%w: command is required", ErrExecInvalid)
	}
	if len(spec.Argv) > maxExecArgv {
		return fmt.Errorf("%w: argv has %d entries, over the %d bound", ErrExecInvalid, len(spec.Argv), maxExecArgv)
	}
	total := 0
	for _, a := range spec.Argv {
		total += len(a) + 1
	}
	if total > maxExecArgBytes {
		return fmt.Errorf("%w: argv is %d bytes, over the %d bound (execve would report E2BIG)", ErrExecInvalid, total, maxExecArgBytes)
	}
	if spec.Argv[0] == "" {
		return fmt.Errorf("%w: argv[0] is empty", ErrExecInvalid)
	}
	return nil
}

// ExitCodeForSignal maps a signal-terminated process to the 128+n exit code every
// shell and every Kubernetes consumer expects.
//
// It is the SAME convention runtime/v1's host path uses, and it has to be: a
// `kubectl exec … ; echo $?` must not report a different number depending on
// whether the pod happened to be a host process or a guest. 137 for SIGKILL and
// 143 for SIGTERM are the two an operator reads by sight.
func ExitCodeForSignal(sig int) int32 {
	if sig <= 0 {
		return 0
	}
	return int32(128 + sig)
}

// CopyChunked pumps src into dst in bounded chunks, returning the first error.
//
// The chunk bound is what keeps one exec's output from becoming one enormous gRPC
// frame: the host applies a receive bound (pkg/runtime's maxGuestFrameBytes) and
// an over-bound frame ends the stream with ResourceExhausted, so an agent that
// wrote a whole buffer at once would turn a large single write by the workload
// into a failed exec.
func CopyChunked(dst io.Writer, src io.Reader) error {
	buf := make([]byte, execCopyChunkMax)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
