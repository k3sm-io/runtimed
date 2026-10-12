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

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	shimv1 "k3sm.io/apis/shim/v1"
)

// The launch payload: how a launch-mode exec-shim receives the pod's
// environment without ever holding it in its own environ.
//
// The shim is ad-hoc signed without the hardened runtime, and in launch mode it
// starts unconfined, at the daemon's uid, before the credential drop and
// sandbox_apply. dyld honours DYLD_INSERT_LIBRARIES from a process's own
// environ at load, before main, so a pod-chosen library named there would run
// inside the shim with neither confinement in place. Every launch-mode shim is
// therefore spawned with an EMPTY environment, and the pod's
// environment, with the daemon's two hand-offs as typed fields, crosses on a
// dedicated inherited descriptor (LaunchSpecChildFD), read once at the top of
// the shim's main. The shim builds the pod's envp from it only at the exec
// call, after the drop and the sandbox, and never calls setenv.
//
// The descriptor is never fd 0: in launch mode fd 0 is the container's stdin.
// The serve-mode shim keeps receiving its ShimSpec on fd 0, as before: it has
// no stdin of its own to give the container. The exec mode a resident shim
// forks for an exec session keeps its environ: it starts after the shim's own
// drop and sandbox_apply, so there is no unconfined window to protect.
const (
	// LaunchSpecChildFD is the descriptor the LaunchPayload occupies in a
	// launch-mode shim: after the exec-sync pipe (ExecSyncChildFD).
	LaunchSpecChildFD = 4
	// LaunchSpecToken is the argv token, directly after the launch mode token,
	// that tells the shim its payload is on LaunchSpecChildFD. Only this exact
	// value is honoured, and it is required.
	//
	// Its position makes binary skew fail closed in both directions: an older
	// shim reads it where it expects the uid and refuses to parse it, and a
	// newer shim handed an older argv finds the uid where the spec token must
	// be and refuses the argv. Neither pairing execs a pod.
	LaunchSpecToken = "spec=4"
)

// ErrLaunchEnviron reports a launch-spec spawn that also carries an environ:
// the payload is the only way the pod's environment may reach the shim.
var ErrLaunchEnviron = errors.New("supervisor: a launch-spec spawn must have an empty environment")

// LaunchPayload is what a launch-mode shim reads from
// LaunchSpecChildFD. It shares the ShimSpec wire format: one JSON document read
// to EOF under the same size bound, refused unless APIVersion is the shim's own
// contract version.
type LaunchPayload struct {
	// APIVersion is the writer's shimv1.APIVersion; EncodeLaunchPayload fills
	// it in and the shim refuses another.
	APIVersion string `json:"apiVersion"`
	// Env is the pod process's environment, exactly as its binary receives it.
	Env []string `json:"env"`
	// Argv0 replaces argv[0] for the pod binary when it differs from the path
	// exec'd (a re-signed shell copy run as "sh"); empty means none.
	Argv0 string `json:"argv0,omitempty"`
	// ExecSync is true when the exec-sync pipe is on ExecSyncChildFD: the shim
	// marks it close-on-exec so the daemon's read end sees EOF exactly at the
	// pod binary's exec.
	ExecSync bool `json:"execSync,omitempty"`
}

// EncodeLaunchPayload renders p for LaunchSpecChildFD, stamping the contract
// version.
func EncodeLaunchPayload(p LaunchPayload) ([]byte, error) {
	p.APIVersion = shimv1.APIVersion
	return encodeBounded("launch payload", p)
}

// DecodeLaunchPayload reads one payload from r to EOF, bounded, and refuses a
// truncated, malformed or oversized one, one of another contract version, and
// an environment entry that is not NAME=value.
func DecodeLaunchPayload(r io.Reader) (LaunchPayload, error) {
	var p LaunchPayload
	if err := decodeBounded("launch payload", r, &p); err != nil {
		return LaunchPayload{}, err
	}
	if err := checkShimAPIVersion(p.APIVersion); err != nil {
		return LaunchPayload{}, err
	}
	for _, e := range p.Env {
		if name, _, ok := strings.Cut(e, "="); !ok || name == "" {
			return LaunchPayload{}, fmt.Errorf("launch payload env entry %q is not NAME=value", e)
		}
	}
	return p, nil
}

// ReadLaunchPayload is the shim side: it marks fd close-on-exec, requires it to
// be a pipe, reads and decodes the payload, and closes fd whatever the outcome.
// A missing descriptor, a non-pipe, or a bad payload is an error the shim must
// treat as fatal.
func ReadLaunchPayload(fd int) (LaunchPayload, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return LaunchPayload{}, fmt.Errorf("launch payload descriptor %d: %w", fd, err)
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "launch-payload")
	defer func() { _ = f.Close() }()
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFIFO {
		return LaunchPayload{}, fmt.Errorf("launch payload descriptor %d is not a pipe", fd)
	}
	return DecodeLaunchPayload(f)
}

// PodExec returns what the shim execs for argv: the file (always argv[0], as
// the daemon resolved it), the argv the pod sees (with Argv0 substituted), and
// the pod's envp, a fresh copy of Env.
func (p LaunchPayload) PodExec(argv []string) (path string, execArgv, envp []string) {
	if len(argv) == 0 {
		return "", nil, append([]string{}, p.Env...)
	}
	execArgv = argv
	if p.Argv0 != "" {
		execArgv = append([]string{p.Argv0}, argv[1:]...)
	}
	return argv[0], execArgv, append([]string{}, p.Env...)
}

// Getenv returns the value of name in the payload's environment, or "" when
// it is unset (the last entry wins, as getenv does on a duplicate).
func (p LaunchPayload) Getenv(name string) string {
	v := ""
	for _, e := range p.Env {
		if k, val, ok := strings.Cut(e, "="); ok && k == name {
			v = val
		}
	}
	return v
}

// launchPipe is a payload pipe the parent writes after the spawn.
type launchPipe struct {
	r, w    *os.File
	payload []byte
}

// openLaunchPipe encodes p and makes the pipe its bytes cross. The read end is
// moved above LaunchSpecChildFD, so a child-side dup2 onto LaunchSpecChildFD
// never lands on, or is clobbered by, the stream or exec-sync descriptors.
func openLaunchPipe(p LaunchPayload) (*launchPipe, error) {
	payload, err := EncodeLaunchPayload(p)
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("launch payload pipe: %w", err)
	}
	if r.Fd() <= LaunchSpecChildFD {
		nfd, err := unix.FcntlInt(r.Fd(), unix.F_DUPFD_CLOEXEC, LaunchSpecChildFD+1)
		_ = r.Close()
		if err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("launch payload pipe: move the read end: %w", err)
		}
		r = os.NewFile(uintptr(nfd), "launch-payload")
	}
	return &launchPipe{r: r, w: w, payload: payload}, nil
}

// start writes the payload in the background and then closes the write end,
// so the spawn never waits on the pipe buffer. A child that dies before
// reading ends the write with EPIPE once the parent's read end is closed too.
func (l *launchPipe) start() {
	go func() {
		_, _ = l.w.Write(l.payload)
		_ = l.w.Close()
	}()
}

// abandon closes both ends of a pipe whose spawn failed.
func (l *launchPipe) abandon() { _, _ = l.r.Close(), l.w.Close() }

// AttachLaunchPayload prepares cmd, an exec.Cmd of a launch-mode shim whose
// argv already carries LaunchSpecToken, to start with an EMPTY
// environment and p on LaunchSpecChildFD. The payload is written in the
// background. release closes the parent's copy of the read end; call it once
// cmd has started (or failed to), and it is safe to call more than once. cmd
// must not carry ExtraFiles of its own.
func AttachLaunchPayload(cmd *exec.Cmd, p LaunchPayload) (release func(), err error) {
	if len(cmd.ExtraFiles) != 0 {
		return nil, errors.New("supervisor: the launch payload owns the command's extra descriptors")
	}
	lp, err := openLaunchPipe(p)
	if err != nil {
		return nil, err
	}
	// ExtraFiles[i] becomes fd 3+i; a nil entry is closed in the child, so
	// nothing but the payload sits between the stderr and payload descriptors.
	extra := make([]*os.File, LaunchSpecChildFD-2)
	extra[LaunchSpecChildFD-3] = lp.r
	cmd.ExtraFiles = extra
	cmd.Env = []string{}
	lp.start()
	var once sync.Once
	return func() { once.Do(func() { _ = lp.r.Close() }) }, nil
}
