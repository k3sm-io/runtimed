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

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/pathsafe"
	"k3sm.io/runtimed/pkg/supervisor"
)

// Adoption of a running vm host helper after a daemon restart.
//
// A k3sm-vmhost helper is spawned POSIX_SPAWN_SETSID and writes its output to a
// file in its own run dir, so a daemon exit takes nothing from it: the helper,
// its machine and its guest keep running, reparented to launchd. That is the
// kubelet's contract for containers (a kubelet restart stops none), and it is
// the one native pods already have (pkg/runtime podreap.go, attach.go). The
// next daemon either ADOPTS the helper — the node asks for it through the
// runtime's AttachPod, before the startup sweep — or the sweep KILLS it exactly
// as it always did. There is no third outcome.
//
// FAIL CLOSED. A helper is adopted only when every one of these holds
// (vmAdoptDecision, table-tested on each refusal):
//
//   - the record is this schema (vmRecordSchema): a record an earlier binary
//     wrote carries no version and is killed;
//   - the record was written by this very daemon build (its code-directory
//     hash, the podreap fingerprint), so an upgrade recreates vm pods once and
//     a daemon never drives a helper another build spawned;
//   - the record is from this boot session (kern.bootsessionuuid): nothing is
//     adopted across a reboot, whatever a recycled pgid and start time say;
//   - the group's leader is the recorded instance — groupIsRecordedVMInstance,
//     the very predicate the sweep's kill re-probes with, never a second one;
//   - the run dir is inside this node's run tree, reached through no symlink,
//     and carries the owner marker naming the pod;
//   - the running leader's code-directory hash equals the one recorded at spawn;
//   - the helper answers a version call on its control socket within
//     vmAdoptProbeTimeout with the recorded protocol version, served by the
//     recorded pid (the kernel's LOCAL_PEERPID, not only the helper's say-so).
//
// Then an exclusive flock on the record is taken, so two runtimes can never
// both adopt one helper, and the helper's exit is followed by a kqueue
// EVFILT_PROC/NOTE_EXIT registration checked against the recorded identity
// after it is armed (watchAdoptedHelperExit). Any refusal leaves the record to the
// sweep, which kills the group exactly as before and says why.

// vmRecordSchema is the version of the vmProcRecord shape this build writes and
// the only one it adopts. Bump it on any change a reader must not misread; a
// record of another schema is never adopted (it is still killed by the sweep,
// which reads only the identity fields every schema carries).
const vmRecordSchema = 1

// VMHostProtocolVersion is the helper control protocol this build's daemon and
// k3sm-vmhost speak: the answer the helper gives on its control socket, and the
// value the daemon records at spawn and requires at adoption. Bump it on any
// change to what the daemon asks of a running helper (the control socket, the
// agent proxy, the stop sequence), so a helper that predates the change is
// killed and recreated rather than driven by a daemon that assumes it.
const VMHostProtocolVersion = 1

// VMHostControlSocketName is the basename of the helper's control socket, in
// its run dir beside the agent socket. It answers one JSON line
// (VMHostVersion) per connection and nothing else; the agent socket stays a
// byte relay that never speaks for the helper.
const VMHostControlSocketName = "vmhost.ctl"

// VMHostLogName is the basename of the helper's own output file in its run
// dir: the daemon opens it O_WRONLY|O_APPEND|O_CREAT 0600 and hands it to the
// helper as fd 1 and fd 2. A file, not a pipe, so a daemon exit can never
// SIGPIPE or EIO the helper; the daemon reads its tail for a boot failure and
// for a helper that died after readiness, including one it adopted.
const VMHostLogName = "vmhost.log"

// VMHostLogMaxBytes caps the helper's output file. The helper itself rotates
// it (to VMHostLogName + ".1", replacing the previous rotation) when a write
// would take it past the cap, so no reader ever truncates it and a pod costs at
// most twice the cap on disk.
//
// 1 MiB, from what the helper writes: a handful of lifecycle lines per boot and
// stop (a few hundred bytes each) and one error line at most. A megabyte holds
// thousands of those, so the cap only engages for a helper that is looping on a
// fault, and the tail the daemon reads (vmHelperLogTailLines) is always in the
// current file or its one rotation.
const VMHostLogMaxBytes = 1 << 20

// vmAdoptProbeTimeout bounds the version call on a helper's control socket.
// The helper answers from its accept loop without touching the guest, so a
// healthy one answers in well under a millisecond; the bound exists for one
// that is wedged, and it is short because the node attaches its pods before it
// registers, one after another.
const vmAdoptProbeTimeout = 2 * time.Second

// vmHostLogTailBytes bounds how much of the helper's output file one tail read
// takes: comfortably more than vmHelperLogTailLines of the helper's lines.
const vmHostLogTailBytes = 64 << 10

// ErrVMNotAdopted reports that AdoptVM found no helper it may adopt for a pod.
// Every refusal wraps it; the reason follows in the message.
var ErrVMNotAdopted = errors.New("sandbox: the vm host helper was not adopted")

// VMHostVersion is a helper's answer on its control socket.
type VMHostVersion struct {
	// Protocol is the helper's VMHostProtocolVersion.
	Protocol int `json:"protocol"`
	// Pid is the helper's own pid.
	Pid int `json:"pid"`
}

// vmHostAnswer is a version answer as the daemon received it: what the helper
// said, and the kernel's word on which process said it.
type vmHostAnswer struct {
	VMHostVersion
	// PeerPid is the socket peer's pid (LOCAL_PEERPID).
	PeerPid int
}

// ServeVMHostControl answers every connection accepted on lis with v as one
// JSON line, then closes the connection. It returns nil once lis is closed.
//
// It is exported for k3sm-vmhost, which serves it for its whole life, and for
// the tests that stand a real process in for a helper.
func ServeVMHostControl(lis net.Listener, v VMHostVersion) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal the vm host version: %w", err)
	}
	line = append(line, '\n')
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept on the vm host control socket: %w", err)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(vmAdoptProbeTimeout))
		_, _ = conn.Write(line)
		_ = conn.Close()
	}
}

// decodeVMHostVersion reads one bounded JSON line from r, refusing unknown
// fields.
func decodeVMHostVersion(r io.Reader) (VMHostVersion, error) {
	var v VMHostVersion
	dec := json.NewDecoder(io.LimitReader(r, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return VMHostVersion{}, fmt.Errorf("decode the vm host version: %w", err)
	}
	return v, nil
}

// vmAdoptSeams are the impure probes adoption reads. Each has a production
// default (defaultVMAdoptSeams); WithVMAdoptionProbes replaces them in tests.
type vmAdoptSeams struct {
	// selfVersion names this daemon's build ("cdhash:<hex>"), read once.
	selfVersion func() (string, error)
	// bootSession names the running boot (kern.bootsessionuuid).
	bootSession func() (string, error)
	// cdHash reads a running process's code-directory hash.
	cdHash func(pid int) (string, error)
	// version asks the helper behind a control socket for its version.
	version func(ctx context.Context, socket string) (vmHostAnswer, error)
	// watchExit follows a helper this daemon did not spawn (watchAdoptedHelperExit).
	watchExit func(ctx context.Context, pid int, verify func() bool) (<-chan struct{}, error)
}

func defaultVMAdoptSeams() vmAdoptSeams {
	return vmAdoptSeams{
		selfVersion: func() (string, error) {
			h, err := supervisor.CodeDirectoryHash(os.Getpid())
			if err != nil || h == "" {
				return "", fmt.Errorf("read this daemon's code-directory hash: %w", err)
			}
			return "cdhash:" + h, nil
		},
		bootSession: bootSessionID,
		cdHash:      supervisor.CodeDirectoryHash,
		version:     dialVMHostVersion,
		watchExit:   watchAdoptedHelperExit,
	}
}

// WithVMAdoptionProbes replaces adoption's impure probes. Test-only; a nil
// argument keeps the production probe.
func WithVMAdoptionProbes(
	selfVersion func() (string, error),
	bootSession func() (string, error),
	cdHash func(pid int) (string, error),
	version func(ctx context.Context, socket string) (VMHostVersion, int, error),
) VMBackendOption {
	return func(b *VMBackend) {
		if selfVersion != nil {
			b.adopt.selfVersion = selfVersion
		}
		if bootSession != nil {
			b.adopt.bootSession = bootSession
		}
		if cdHash != nil {
			b.adopt.cdHash = cdHash
		}
		if version != nil {
			b.adopt.version = func(ctx context.Context, socket string) (vmHostAnswer, error) {
				v, peer, err := version(ctx, socket)
				return vmHostAnswer{VMHostVersion: v, PeerPid: peer}, err
			}
		}
	}
}

// runtimeVersion returns this daemon's build fingerprint, or "" when it cannot
// be read — in which case nothing is ever adopted (vmAdoptDecision) and the
// first miss is logged once.
func (b *VMBackend) runtimeVersion() string {
	b.selfVersionOnce.Do(func() {
		if b.adopt.selfVersion == nil {
			return
		}
		v, err := b.adopt.selfVersion()
		if err != nil {
			b.logger().Warn("cannot name this daemon's build; vm pods will not be re-attached across a daemon restart", "err", err)
			return
		}
		b.selfVersion = v
	})
	return b.selfVersion
}

// currentBootSession returns the running boot's id, or "" when it cannot be read.
func (b *VMBackend) currentBootSession() string {
	if b.adopt.bootSession == nil {
		return ""
	}
	s, err := b.adopt.bootSession()
	if err != nil {
		return ""
	}
	return s
}

// helperCDHash returns pid's code-directory hash, or "" when it cannot be read.
// An empty hash in a record makes that helper unadoptable, never unbootable.
func (b *VMBackend) helperCDHash(pid int) string {
	if b.adopt.cdHash == nil {
		return ""
	}
	h, err := b.adopt.cdHash(pid)
	if err != nil {
		return ""
	}
	return h
}

// vmAdoptExpect is what this daemon requires of a record: its own build and
// the running boot.
type vmAdoptExpect struct {
	runtimeVersion string
	bootSession    string
}

// vmAdoptProbes are the per-record probes vmAdoptDecision runs, in order.
type vmAdoptProbes struct {
	// identity is groupIsRecordedVMInstance: the leader is the recorded instance.
	identity func(rec vmProcRecord) bool
	// owned proves the run dir is this node's and stamped for the pod.
	owned func(rec vmProcRecord) bool
	// cdHash reads the running leader's code-directory hash.
	cdHash func(pid int) (string, error)
	// version asks the helper behind its control socket.
	version func(ctx context.Context, socket string) (vmHostAnswer, error)
}

// vmAdoptDecision decides whether rec's helper may be adopted, returning "" to
// adopt and the reason otherwise. It is pure over its probes, which run only
// once every cheaper check has passed, in the order listed in the file header;
// the first failing check names the refusal.
func vmAdoptDecision(ctx context.Context, rec vmProcRecord, want vmAdoptExpect, p vmAdoptProbes) string {
	if rec.Schema != vmRecordSchema {
		return fmt.Sprintf("the record has schema %d and this daemon adopts only schema %d (an earlier build wrote it)", rec.Schema, vmRecordSchema)
	}
	if want.runtimeVersion == "" {
		return "this daemon cannot name its own build"
	}
	if rec.RuntimeVersion != want.runtimeVersion {
		return "another daemon build spawned the helper"
	}
	if want.bootSession == "" {
		return "the boot session cannot be read"
	}
	if rec.BootSession != want.bootSession {
		return "the helper was recorded in another boot session"
	}
	if rec.Pgid <= 1 || rec.StartUnixNano == 0 || !p.identity(rec) {
		return "the process group's leader is not the recorded instance"
	}
	if rec.AgentSocket == "" || rec.RunDir == "" || filepath.Dir(rec.AgentSocket) != filepath.Clean(rec.RunDir) {
		return "the record names an inconsistent run dir"
	}
	if !p.owned(rec) {
		return "the run dir is not proven to be this pod's"
	}
	if rec.HelperCDHash == "" {
		return "no helper code-directory hash was recorded"
	}
	h, err := p.cdHash(rec.Pgid)
	if err != nil {
		return fmt.Sprintf("the running helper's code-directory hash cannot be read: %v", err)
	}
	if h != rec.HelperCDHash {
		return "the running helper's code-directory hash differs from the recorded one"
	}
	if rec.HelperProtocol != VMHostProtocolVersion {
		return fmt.Sprintf("the helper was recorded speaking protocol %d and this daemon speaks %d", rec.HelperProtocol, VMHostProtocolVersion)
	}
	vctx, cancel := context.WithTimeout(ctx, vmAdoptProbeTimeout)
	defer cancel()
	ans, err := p.version(vctx, filepath.Join(rec.RunDir, VMHostControlSocketName))
	if err != nil {
		return fmt.Sprintf("the helper did not answer its version call: %v", err)
	}
	if ans.Protocol != rec.HelperProtocol {
		return fmt.Sprintf("the helper answers protocol %d, the record says %d", ans.Protocol, rec.HelperProtocol)
	}
	if ans.Pid != rec.Pgid || ans.PeerPid != rec.Pgid {
		return fmt.Sprintf("the control socket is served by pid %d (says %d), not the recorded helper %d", ans.PeerPid, ans.Pid, rec.Pgid)
	}
	return ""
}

// AdoptVM takes ownership of the pod's helper a previous daemon run left
// running, if vmAdoptDecision admits it, and registers it exactly as a booted
// one: VMDone, VMHelperOutput, StopVM and StopAllVMs then treat it as they
// treat a helper this daemon spawned. It returns nil also when the pod already
// has a live helper here.
//
// Every refusal wraps ErrVMNotAdopted, leaves the record in place and notes the
// reason, and ReapOrphanVMs then kills the helper exactly as before, naming it.
// Of several records for the pod the newest instance is the candidate; the
// others are the sweep's.
//
// ORDERING: AdoptVM refuses once ReapOrphanVMs has begun, and the sweep skips
// every helper adopted before it began, so a helper is either adopted or swept,
// never both.
func (b *VMBackend) AdoptVM(ctx context.Context, podID string) error {
	b.mu.Lock()
	started := b.sweepStarted
	_, live := b.live[podID]
	b.mu.Unlock()
	if live {
		return nil
	}
	if started {
		return fmt.Errorf("%w: pod %s: the startup sweep has begun", ErrVMNotAdopted, podID)
	}
	records, _, err := b.listVMProcRecords()
	if err != nil {
		return fmt.Errorf("%w: pod %s: %w", ErrVMNotAdopted, podID, err)
	}
	var rec vmProcRecord
	found := false
	for _, r := range records {
		if r.PodID == podID && (!found || r.StartUnixNano > rec.StartUnixNano) {
			rec, found = r, true
		}
	}
	if !found {
		return fmt.Errorf("%w: pod %s: no helper is recorded for it", ErrVMNotAdopted, podID)
	}
	refuse := func(reason string) error {
		b.mu.Lock()
		if b.refusals == nil {
			b.refusals = map[int]string{}
		}
		b.refusals[rec.Pgid] = reason
		b.mu.Unlock()
		return fmt.Errorf("%w: pod %s helper pid %d: %s", ErrVMNotAdopted, podID, rec.Pgid, reason)
	}

	want := vmAdoptExpect{runtimeVersion: b.runtimeVersion(), bootSession: b.currentBootSession()}
	probes := vmAdoptProbes{
		identity: b.groupIsRecordedVMInstance,
		owned:    b.vmRunDirProven,
		cdHash:   b.adopt.cdHash,
		version:  b.adopt.version,
	}
	if reason := vmAdoptDecision(ctx, rec, want, probes); reason != "" {
		return refuse(reason)
	}

	lock, err := lockVMRecord(rec.path)
	if err != nil {
		return refuse(fmt.Sprintf("the record cannot be locked (another runtime holds it): %v", err))
	}
	watchCtx, stopWatch := context.WithCancel(context.Background())
	done, err := b.adopt.watchExit(watchCtx, rec.Pgid, func() bool { return b.groupIsRecordedVMInstance(rec) })
	if err != nil {
		stopWatch()
		_ = lock.Close()
		return refuse(fmt.Sprintf("the helper's exit cannot be watched: %v", err))
	}
	select {
	case <-done:
		stopWatch()
		_ = lock.Close()
		return refuse("the helper exited during adoption")
	default:
	}
	vp := &vmProc{
		podID:         podID,
		exit:          adoptedExit{done: done},
		pgid:          rec.Pgid,
		startUnixNano: rec.StartUnixNano,
		helperGrace:   clampStopGrace(time.Duration(rec.StopGraceNanos)),
		agentSocket:   rec.AgentSocket,
		runDir:        rec.RunDir,
		consolePath:   rec.ConsolePath,
		logPath:       filepath.Join(rec.RunDir, VMHostLogName),
		lock:          lock,
		stopWatch:     stopWatch,
	}
	b.mu.Lock()
	if b.sweepStarted {
		b.mu.Unlock()
		vp.release()
		return refuse("the startup sweep began during the adoption")
	}
	if b.live == nil {
		b.live = make(map[string]*vmProc)
	}
	b.live[podID] = vp
	b.mu.Unlock()
	b.logger().Info("adopted a running vm host helper left by a previous daemon run",
		"pod", podID, "pid", rec.Pgid, "start_unix_nano", rec.StartUnixNano)
	return nil
}

// DetachVMs lets go of every live helper without signalling any: the record
// locks are released, adopted exit watches stop, and the handle map is emptied.
// The helpers keep running for the next daemon to adopt or sweep. It is what a
// daemon exit does with its vm pods.
func (b *VMBackend) DetachVMs() {
	b.mu.Lock()
	procs := b.live
	b.live = make(map[string]*vmProc)
	b.mu.Unlock()
	for _, vp := range procs {
		vp.release()
	}
}

// vmRunDirProven reports whether rec's run dir is inside this node's run tree,
// reached through no symlinked or non-directory component, and stamped with the
// owner marker naming rec's pod: clearOrphanRunDir's three gates, as a verdict.
func (b *VMBackend) vmRunDirProven(rec vmProcRecord) bool {
	if b.stateRoot == "" || rec.RunDir == "" {
		return false
	}
	runRoot := filepath.Join(b.stateRoot, "run")
	clean := filepath.Clean(rec.RunDir)
	if !isAtOrUnderDir(clean, runRoot) || clean == runRoot {
		return false
	}
	if pathsafe.RefuseSymlinkedPath(runRoot, clean) != nil {
		return false
	}
	return vmRunDirIsOwnedBy(clean, rec.PodID)
}

// runDirInUse reports whether a live helper owns dir.
func (b *VMBackend) runDirInUse(dir string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, vp := range b.live {
		if vp.runDir != "" && filepath.Clean(vp.runDir) == dir {
			return true
		}
	}
	return false
}

// lockVMRecord opens a record file without following a symlink and takes an
// exclusive, non-blocking flock on it, held until the returned file is closed.
// flock binds the open file description, so a second runtime — in another
// process or this one — that tries the same lock fails with EWOULDBLOCK.
func lockVMRecord(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("the record has no path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// helperExit is the exit edge of a live helper, whoever spawned it: the
// supervisor's Process for a helper this daemon spawned (its sole kqueue
// reaper closes it), adoptedExit for one it adopted.
type helperExit interface {
	Done() <-chan struct{}
}

// adoptedExit is the exit edge of an adopted helper, closed by its kqueue
// watch (watchAdoptedHelperExit). The exit STATUS is not known — the helper is not
// this daemon's child — and nothing here pretends otherwise: the daemon only
// ever needed the edge.
type adoptedExit struct {
	done <-chan struct{}
}

func (a adoptedExit) Done() <-chan struct{} { return a.done }

// openVMHostLog opens the helper's output file for the spawn: append-only,
// created owner-only, never through a symlink.
func openVMHostLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the vm host helper's output file %s: %w", path, err)
	}
	return f, nil
}

// readVMHostLogTail renders the last maxLines lines of the helper's output
// file (and of its one rotation, when the current file holds fewer), joined
// with " | ", or a stated absence.
func readVMHostLogTail(path string, maxLines int) string {
	cur, err := tailLines(path, maxLines)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("(the helper's output file could not be read: %v)", err)
	}
	if len(cur) < maxLines {
		if prev, perr := tailLines(path+".1", maxLines-len(cur)); perr == nil {
			cur = append(prev, cur...)
		}
	}
	if len(cur) == 0 {
		return "(the helper produced no output)"
	}
	return strings.Join(cur, " | ")
}

// tailLines returns up to n of the last non-empty lines of path, reading at
// most vmHostLogTailBytes from its end.
func tailLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := fi.Size() - vmHostLogTailBytes
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	lines := strings.Split(string(buf), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // the first line was cut by the read window
	}
	var out []string
	for _, l := range lines {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}
