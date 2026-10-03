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

package execsession

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// chunkSize is the read buffer for streaming a session's output. Output is
// streamed as raw byte chunks (not lines) so interactive and binary output
// passes through unmangled.
const chunkSize = 32 * 1024

// Stream is an exec stream as a server sees it: runtimev1.Runtime_ExecServer and
// shimv1.ContainerShim_ExecServer both satisfy it.
type Stream interface {
	Context() context.Context
	Send(*runtimev1.ExecResponse) error
	Recv() (*runtimev1.ExecRequest, error)
}

// Run wires cmd's stdio to stream, runs it to completion, and delivers the exit
// code. stdout/stderr stream back to the client; client stdin frames and tty
// resizes stream to the command. The goroutines have bounded lifetimes: the
// output pumps end when the command's output closes (process exit), and the
// stdin pump ends when the client half-closes the stream (io.EOF) or the
// stream's context is cancelled (handler return). stream.Send is serialized (it
// is not safe to call concurrently from the stdout and stderr pumps).
//
// With tty the command gets a fresh pty and its own session with the pty as
// controlling terminal (Setsid+Setctty); without, its own process group
// (Setpgid), so a client ^C never reaches the server.
func Run(stream Stream, cmd *exec.Cmd, tty, wantStdin bool) error {
	send := serializedSend(stream)

	var (
		wg          sync.WaitGroup
		stdinW      io.Writer // where client stdin bytes are written (pipe or pty master)
		stdinCloser io.Closer // closed on client EOF to signal command stdin EOF (non-tty only)
		ttyMaster   *os.File  // pty master for resize + the closer below (tty only)
	)

	if tty {
		master, slave, err := OpenPTY()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: allocate tty: %v", err)
		}
		ttyMaster = master
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
		if err := cmd.Start(); err != nil {
			_ = slave.Close()
			_ = master.Close()
			return status.Errorf(codes.Internal, "exec: start: %v", err)
		}
		_ = slave.Close() // the child holds its dup; the parent keeps only the master
		if wantStdin {
			stdinW = master
		}
		// On a tty stdout and stderr are merged onto the line discipline; the master
		// read ends with EIO once the child exits and the kernel closes the slave.
		wg.Add(1)
		go func() {
			defer wg.Done()
			PumpReader(master, func(b []byte) error { return send(&runtimev1.ExecResponse{Stdout: b}) })
		}()
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own pgrp; a client ^C never reaches the server
		if wantStdin {
			w, err := cmd.StdinPipe()
			if err != nil {
				return status.Errorf(codes.Internal, "exec: stdin pipe: %v", err)
			}
			stdinW, stdinCloser = w, w
		}
		stdoutR, err := cmd.StdoutPipe()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: stdout pipe: %v", err)
		}
		stderrR, err := cmd.StderrPipe()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: stderr pipe: %v", err)
		}
		if err := cmd.Start(); err != nil {
			return status.Errorf(codes.Internal, "exec: start: %v", err)
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			PumpReader(stdoutR, func(b []byte) error { return send(&runtimev1.ExecResponse{Stdout: b}) })
		}()
		go func() {
			defer wg.Done()
			PumpReader(stderrR, func(b []byte) error { return send(&runtimev1.ExecResponse{Stderr: b}) })
		}()
	}

	// Stdin + resize pump (bounded: ends on the client half-close or stream
	// cancellation). Detached — never waited on before returning, since a client
	// that keeps stdin open would otherwise block teardown; gRPC cancels the
	// stream on handler return, which unblocks the Recv and ends this goroutine.
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if stdinCloser != nil {
					_ = stdinCloser.Close() // EOF to the command's stdin
				}
				return
			}
			if d := req.GetStdinData(); len(d) > 0 && stdinW != nil {
				if _, werr := stdinW.Write(d); werr != nil {
					return
				}
			}
			if rs := req.GetResize(); rs != nil && ttyMaster != nil {
				_ = SetWinsize(ttyMaster, uint16(rs.GetWidth()), uint16(rs.GetHeight()))
			}
		}
	}()

	// Drain all output before reaping (os/exec requires pipe reads to complete
	// before Wait; the tty master pump ends on the child's exit), then reap.
	wg.Wait()
	waitErr := cmd.Wait()
	if ttyMaster != nil {
		_ = ttyMaster.Close()
	}
	return sendExit(send, waitErr)
}

// RunOnSlave runs cmd on a terminal whose MASTER is held by someone else: slave
// becomes the command's stdin, stdout, stderr and controlling terminal
// (Setsid+Setctty), and only the exit travels on stream — the session's bytes
// and resizes move through the master. Client frames that still arrive are
// drained and ignored. It is a resident shim's tty session: the daemon
// allocated the pty (a confined shim cannot) and handed the slave over. Run
// closes slave once the command holds it.
func RunOnSlave(stream Stream, cmd *exec.Cmd, slave *os.File) error {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	err := cmd.Start()
	_ = slave.Close()
	if err != nil {
		return status.Errorf(codes.Internal, "exec: start: %v", err)
	}
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}()
	return sendExit(serializedSend(stream), cmd.Wait())
}

// serializedSend wraps stream.Send in a mutex.
func serializedSend(stream Stream) func(*runtimev1.ExecResponse) error {
	var mu sync.Mutex
	return func(resp *runtimev1.ExecResponse) error {
		mu.Lock()
		defer mu.Unlock()
		return stream.Send(resp)
	}
}

// sendExit delivers the command's exit as the terminal ExecResult. A
// signal-killed command maps to 128+signo, the supervisor's reaper convention.
func sendExit(send func(*runtimev1.ExecResponse) error, waitErr error) error {
	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) {
			return status.Errorf(codes.Internal, "exec: %v", waitErr)
		}
		exitCode = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			exitCode = 128 + int(ws.Signal())
		}
	}
	return send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: int32(exitCode)}})
}

// PumpReader copies r in chunks to emit until r returns EOF or an error, or emit
// fails (a dead stream). It is the streaming primitive for session output.
func PumpReader(r io.Reader, emit func([]byte) error) {
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if e := emit(append([]byte(nil), buf[:n]...)); e != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
