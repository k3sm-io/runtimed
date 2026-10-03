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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	shimv1 "k3sm.io/apis/shim/v1"
)

// The resident shim: one k3sm-execshim process per container that stays alive
// as the container's parent (the containerd-shim shape). It is the leader of the
// pod's process group, holds the container's stdout/stderr pipes, writes the
// CRI log itself, reaps the container for its real wait status, persists that
// status, and serves shimv1.ContainerShim on a unix socket in its shim dir. A
// daemon that restarts reconnects to the socket (ConnectShim), so output, the
// exit code and exec all survive the daemon.
//
// Everything both ends must agree on is defined once, here: the file names in
// the shim dir, the exit record and its tmp+rename write, the launch spec that
// crosses the shim's stdin, and the pty hand-off.

const (
	// ShimSockName is the gRPC socket in a container's shim dir.
	ShimSockName = "shim.sock"
	// ShimPtySockName is the descriptor hand-off socket in a container's shim
	// dir: pty slaves and rotated log files (see SendHandoff).
	ShimPtySockName = "pty.sock"
	// ShimExitFile is the persisted exit record in a container's shim dir. It is
	// the AUTHORITY for the container's exit status on every path: the shim
	// writes it (in place, through a descriptor it opened before confinement;
	// see OpenExitRecord) after it reaped the container and before it exits,
	// and the daemon reads it when it observes the shim's exit.
	ShimExitFile = "exit.json"

	// ShimModeServe, ShimModeLaunch and ShimModeExec are the exec-shim's first
	// argument. serve is the resident shim; launch is the container's own
	// launch sequence (the shim spawns it); exec is an exec session the shim
	// spawns inside its own, already applied, confinement.
	ShimModeServe  = "serve"
	ShimModeLaunch = "launch"
	ShimModeExec   = "exec"

	// ShimPtyTokenKey is the gRPC metadata key an Exec stream names its handed-off
	// pty slave by (SendHandoff). Present only on a tty session.
	ShimPtyTokenKey = "k3sm-pty-token"
	// ShimLogTokenKey is the gRPC metadata key a ReopenLog call names its
	// handed-off log descriptor by (SendHandoff).
	ShimLogTokenKey = "k3sm-log-token"
	// ShimSessionPidKey and ShimSessionStartKey are the response-header keys an
	// Exec stream reports its session's pid and start time under, once the
	// session has started (see EndExecSession).
	ShimSessionPidKey   = "k3sm-session-pid"
	ShimSessionStartKey = "k3sm-session-start"

	// maxSunPath is the longest unix socket path bind(2) accepts on darwin:
	// sockaddr_un.sun_path is 104 bytes including the terminating NUL.
	maxSunPath = 103

	// maxShimSpecBytes bounds the launch spec the shim reads from its stdin.
	maxShimSpecBytes = 4 << 20
)

// Exit codes the serve-mode shim uses for a failure before it serves, so the
// daemon can name the cause from the wait status alone.
const (
	// ShimExitSpec is a launch spec that could not be read or decoded.
	ShimExitSpec = 7
	// ShimExitSunPath is a socket path longer than sun_path (ErrSunPathTooLong).
	ShimExitSunPath = 8
	// ShimExitSetup is any other failure before the shim serves (bind, log,
	// spawn of the container, confinement).
	ShimExitSetup = 9
)

// RPC deadlines on the daemon-to-shim calls. Every call carries one: a shim that
// stops answering must not wedge the daemon goroutine that asked.
const (
	ShimStatusTimeout = 2 * time.Second
	ShimSignalTimeout = 5 * time.Second
	ShimReopenTimeout = 5 * time.Second
)

var (
	// ErrSunPathTooLong reports a shim socket path that does not fit sun_path.
	ErrSunPathTooLong = errors.New("supervisor: shim socket path exceeds sun_path")
	// ErrShimVersion reports a shim speaking another shimv1 contract version.
	// The contract is lockstep with the daemon build; there is no negotiation.
	ErrShimVersion = errors.New("supervisor: shim contract version differs from this daemon's")
	// ErrShimIdentity reports a shim whose identity (pid, start time, or the
	// peer pid of its socket) is not the recorded one.
	ErrShimIdentity = errors.New("supervisor: shim is not the recorded instance")
	// ErrShimUnresponsive reports a live shim that failed two Status calls.
	ErrShimUnresponsive = errors.New("supervisor: shim is not answering")
	// ErrShimCrashed reports a shim that exited without persisting the
	// container's exit record and without a kill this daemon asked for: the
	// container's status is lost with it, and the container may still run.
	ErrShimCrashed = errors.New("supervisor: the container's shim exited without recording an exit status")
)

// ShimSockPath is the gRPC socket in shim dir dir.
func ShimSockPath(dir string) string { return filepath.Join(dir, ShimSockName) }

// ShimPtySockPath is the descriptor hand-off socket in shim dir dir.
func ShimPtySockPath(dir string) string { return filepath.Join(dir, ShimPtySockName) }

// CheckSunPath returns ErrSunPathTooLong when path cannot be bound as a unix
// socket. The shim checks before it binds and fails the container start with
// ShimExitSunPath, rather than letting bind(2) truncate or refuse it.
func CheckSunPath(path string) error {
	if len(path) > maxSunPath {
		return fmt.Errorf("%w: %d bytes > %d: %s", ErrSunPathTooLong, len(path), maxSunPath, path)
	}
	return nil
}

// ExitRecord is the persisted exit status of a shim's container. ExitCode and
// Signal follow the reaper convention (KqueueReaper.WaitExit): a signal death
// reports Signal and ExitCode 128+Signal.
type ExitRecord struct {
	ExitCode           int   `json:"exitCode"`
	Signal             int   `json:"signal"`
	FinishedAtUnixNano int64 `json:"finishedAtUnixNano"`
}

// OpenExitRecord opens (creating) dir's exit record for the shim to write at
// exit. The shim opens it BEFORE it confines itself and keeps the descriptor
// (close-on-exec), so its profile grants no write on any path in its dir: an
// exec session, which inherits that profile, can neither forge the record nor
// replace it.
//
// The plan wrote the record through a tmp file and a rename. That needs a
// create-and-rename grant on two paths in the shim dir, which every exec
// session would inherit; writing in place through the held descriptor needs
// none. The cost is atomicity: a reader can see an empty or torn file, and
// ReadExitRecord reads either as "no record yet" (with the shim alive its
// Status answers; with it dead, the daemon's recorded kill intent or an
// unknown status stands, as for a missing record).
func OpenExitRecord(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, ShimExitFile), os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open exit record: %w", err)
	}
	return f, nil
}

// WriteExitRecordTo writes rec into f in place: pwrite at offset 0, truncate to
// the record's length, fsync.
func WriteExitRecordTo(f *os.File, rec ExitRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal exit record: %w", err)
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write exit record: %w", err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("truncate exit record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync exit record: %w", err)
	}
	return nil
}

// WriteExitRecord persists rec in dir (OpenExitRecord + WriteExitRecordTo).
func WriteExitRecord(dir string, rec ExitRecord) error {
	f, err := OpenExitRecord(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return WriteExitRecordTo(f, rec)
}

// ReadExitRecord reads dir's exit record. ok is false, with a nil error, when
// there is none yet — including an empty or unparseable file, which is what a
// record mid-write (or never written) looks like (see OpenExitRecord).
func ReadExitRecord(dir string) (rec ExitRecord, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, ShimExitFile))
	if errors.Is(err, os.ErrNotExist) {
		return ExitRecord{}, false, nil
	}
	if err != nil {
		return ExitRecord{}, false, fmt.Errorf("read exit record: %w", err)
	}
	if len(data) == 0 || json.Unmarshal(data, &rec) != nil {
		return ExitRecord{}, false, nil
	}
	return rec, true, nil
}

// RemoveExitRecord drops a previous instance's exit record from dir before a new
// shim starts there, so the new instance can never be read as the old one's exit.
func RemoveExitRecord(dir string) error {
	err := os.Remove(filepath.Join(dir, ShimExitFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove exit record: %w", err)
	}
	return nil
}

// ShimSpec is the launch spec the daemon hands the serve-mode shim over its
// stdin (SpawnSpec.StdinFD). It carries the pod environment — Secret-derived
// variables and the DYLD interposes included — which is why it travels over an
// inherited descriptor, read once before the shim confines itself, and never
// through the shim's own environ or a file.
type ShimSpec struct {
	// APIVersion is the daemon's shimv1.APIVersion; the shim refuses another.
	APIVersion string `json:"apiVersion"`
	// Container is the container's name, asserted by every RPC.
	Container string `json:"container"`
	// Dir is the shim dir: its sockets and the exit record live here.
	Dir string `json:"dir"`
	// LogPath is the container's CRI log file. The daemon creates it; the shim
	// opens it for append.
	LogPath string `json:"logPath"`
	// ShimProfile is the path of the shim's own Seatbelt profile (the pod
	// profile plus the shim grant), applied after the container is spawned.
	ShimProfile string `json:"shimProfile"`
	// Launch is the launch-mode argv after the mode token: <uid> <gid>
	// <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary> [args...].
	Launch []string `json:"launch"`
	// Env is the container's spawn environment (exec hand-offs included).
	Env []string `json:"env"`
	// ExecEnv and ExecDir are what an exec session runs with: the container's
	// resolved environment (no daemon-to-shim hand-off variables) and working
	// directory.
	ExecEnv []string `json:"execEnv"`
	ExecDir string   `json:"execDir"`
	// ExecSync is true when the shim inherited the exec-sync pipe on fd 3; the
	// shim relays it to the container as fd 3 and closes its own copy.
	ExecSync bool `json:"execSync,omitempty"`
}

// EncodeShimSpec renders s for the shim's stdin.
func EncodeShimSpec(s ShimSpec) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode shim spec: %w", err)
	}
	if len(b) > maxShimSpecBytes {
		return nil, fmt.Errorf("encode shim spec: %d bytes exceeds %d", len(b), maxShimSpecBytes)
	}
	return b, nil
}

// DecodeShimSpec reads one spec from r to EOF, bounded, and checks it is
// complete enough to launch from.
func DecodeShimSpec(r io.Reader) (ShimSpec, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxShimSpecBytes+1))
	if err != nil {
		return ShimSpec{}, fmt.Errorf("read shim spec: %w", err)
	}
	if len(b) > maxShimSpecBytes {
		return ShimSpec{}, fmt.Errorf("shim spec exceeds %d bytes", maxShimSpecBytes)
	}
	var s ShimSpec
	if err := json.Unmarshal(b, &s); err != nil {
		return ShimSpec{}, fmt.Errorf("decode shim spec: %w", err)
	}
	switch {
	case s.APIVersion != shimv1.APIVersion:
		return ShimSpec{}, fmt.Errorf("%w: spec %q, shim %q", ErrShimVersion, s.APIVersion, shimv1.APIVersion)
	case s.Container == "" || s.Dir == "" || s.LogPath == "" || s.ShimProfile == "":
		return ShimSpec{}, errors.New("shim spec is missing the container, dir, log path or shim profile")
	case len(s.Launch) < 7:
		return ShimSpec{}, fmt.Errorf("shim spec launch argv has %d tokens, want at least 7", len(s.Launch))
	}
	return s, nil
}

// ShimIdentity is the recorded identity of a resident shim: the pid and kernel
// start time of the pod group's leader, the container it hosts, and its dir.
type ShimIdentity struct {
	Container     string
	Dir           string
	Pid           int
	StartUnixNano int64
}

// ShimDialer dials a shim's unix socket and reports the peer pid the kernel
// attributes the connection to (getsockopt LOCAL_PEERPID on darwin). It is the
// seam a unit test fakes; UnixShimDialer is the production one.
type ShimDialer interface {
	DialShim(ctx context.Context, path string) (conn net.Conn, peerPID int, err error)
}

// ShimConn is a verified connection to one resident shim. Every call carries a
// deadline (ShimStatusTimeout, ShimSignalTimeout, ShimReopenTimeout), and the
// two streams run with gRPC keepalive so a dead peer ends them.
type ShimConn struct {
	id     ShimIdentity
	dialer ShimDialer
	cc     *grpc.ClientConn
	client shimv1.ContainerShimClient
}

// shimKeepalive bounds how long a stream outlives a peer that stopped
// answering. The shim's server enforcement admits it (ShimKeepaliveEnforcement).
var shimKeepalive = keepalive.ClientParameters{Time: 15 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}

// ShimKeepaliveEnforcement is the server-side policy that admits the daemon's
// keepalive pings; the shim serves with it.
var ShimKeepaliveEnforcement = keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}

// ConnectShim dials the shim id names and proves it is that shim before any of
// its answers is trusted:
//
//   - when procStart is non-nil, the live process at id.Pid must report exactly
//     id.StartUnixNano (the groupIsRecordedInstance shape, re-checked here so
//     the identity the EVFILT_PROC exit watch is armed on is the recorded one);
//   - the socket's peer pid (LOCAL_PEERPID) must be id.Pid, on this dial and on
//     every redial gRPC makes later;
//   - Status must answer, within ShimStatusTimeout, at the second attempt at
//     the latest (ErrShimUnresponsive otherwise), with api_version equal to
//     shimv1.APIVersion (ErrShimVersion otherwise, a stated refusal), and with
//     its own shim pid and, when recorded, start time equal to id's.
//
// It returns the connection and the first Status answer.
func ConnectShim(ctx context.Context, dialer ShimDialer, id ShimIdentity, procStart func(pid int) (int64, bool)) (*ShimConn, *shimv1.StatusResponse, error) {
	if id.Pid <= 1 {
		return nil, nil, fmt.Errorf("%w: pid %d", ErrShimIdentity, id.Pid)
	}
	if procStart != nil {
		if start, ok := procStart(id.Pid); !ok || start != id.StartUnixNano {
			return nil, nil, fmt.Errorf("%w: pid %d start %d, recorded %d", ErrShimIdentity, id.Pid, start, id.StartUnixNano)
		}
	}
	sock := ShimSockPath(id.Dir)
	// The first dial is made here, not lazily by gRPC, so a wrong peer is a
	// returned error rather than a connection gRPC keeps retrying.
	first, err := dialVerified(ctx, dialer, sock, id.Pid)
	if err != nil {
		return nil, nil, err
	}
	handed := make(chan net.Conn, 1)
	handed <- first
	cc, err := grpc.NewClient("passthrough:///"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(shimKeepalive),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			select {
			case c := <-handed:
				return c, nil
			default:
			}
			return dialVerified(ctx, dialer, sock, id.Pid)
		}))
	if err != nil {
		_ = first.Close()
		return nil, nil, fmt.Errorf("shim client %s: %w", sock, err)
	}
	c := &ShimConn{id: id, dialer: dialer, cc: cc, client: shimv1.NewContainerShimClient(cc)}
	st, err := c.Status(ctx)
	if err != nil {
		// One retry: a single lost answer is not an unresponsive shim.
		if st, err = c.Status(ctx); err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("%w: %s: %w", ErrShimUnresponsive, sock, err)
		}
	}
	switch {
	case st.GetApiVersion() != shimv1.APIVersion:
		_ = c.Close()
		return nil, nil, fmt.Errorf("%w: shim %q, daemon %q", ErrShimVersion, st.GetApiVersion(), shimv1.APIVersion)
	case int(st.GetShimPid()) != id.Pid:
		_ = c.Close()
		return nil, nil, fmt.Errorf("%w: shim reports pid %d, recorded %d", ErrShimIdentity, st.GetShimPid(), id.Pid)
	case id.StartUnixNano != 0 && st.GetShimStartUnixNano() != id.StartUnixNano:
		_ = c.Close()
		return nil, nil, fmt.Errorf("%w: shim reports start %d, recorded %d", ErrShimIdentity, st.GetShimStartUnixNano(), id.StartUnixNano)
	}
	return c, st, nil
}

// dialVerified dials path and refuses a connection whose peer is not wantPid.
func dialVerified(ctx context.Context, dialer ShimDialer, path string, wantPid int) (net.Conn, error) {
	conn, peer, err := dialer.DialShim(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("dial shim %s: %w", path, err)
	}
	if peer != wantPid {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socket %s peer pid %d, recorded %d", ErrShimIdentity, path, peer, wantPid)
	}
	return conn, nil
}

// Identity returns the identity the connection was verified against.
func (c *ShimConn) Identity() ShimIdentity { return c.id }

// Status asks the shim for its status, bounded by ShimStatusTimeout.
func (c *ShimConn) Status(ctx context.Context) (*shimv1.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, ShimStatusTimeout)
	defer cancel()
	return c.client.Status(ctx, &shimv1.StatusRequest{Container: c.id.Container})
}

// Signal delivers sig to the container's child alone, or to its whole group,
// bounded by ShimSignalTimeout.
func (c *ShimConn) Signal(ctx context.Context, sig int, group bool) error {
	ctx, cancel := context.WithTimeout(ctx, ShimSignalTimeout)
	defer cancel()
	_, err := c.client.Signal(ctx, &shimv1.SignalRequest{Container: c.id.Container, Signal: int32(sig), Group: group})
	return err
}

// ReopenLog hands the shim f, the container's new log file the daemon created
// and opened, and asks it to write there from now on, bounded by
// ShimReopenTimeout. The shim never opens a log path after it confined itself,
// so no path grant lets an exec session reach the log.
func (c *ShimConn) ReopenLog(ctx context.Context, f *os.File) error {
	ctx, cancel := context.WithTimeout(ctx, ShimReopenTimeout)
	defer cancel()
	token, err := c.handoff(ctx, HandoffLog, f)
	if err != nil {
		return err
	}
	_, err = c.client.ReopenLog(metadata.AppendToOutgoingContext(ctx, ShimLogTokenKey, token), &shimv1.ReopenLogRequest{Container: c.id.Container})
	return err
}

// handoff passes f to the shim over its hand-off socket and returns the token.
func (c *ShimConn) handoff(ctx context.Context, kind byte, f *os.File) (string, error) {
	conn, err := dialVerified(ctx, c.dialer, ShimPtySockPath(c.id.Dir), c.id.Pid)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	return SendHandoff(conn, kind, f)
}

// Exec opens an exec stream; the caller sends the first ExecRequest.
func (c *ShimConn) Exec(ctx context.Context) (shimv1.ContainerShim_ExecClient, error) {
	return c.client.Exec(ctx)
}

// ExecTTY hands slave to the shim over its pty socket and opens an exec stream
// naming it. The caller keeps the master: a tty session's bytes move between
// the caller and the master directly, and the shim stream carries only the
// session's exit.
func (c *ShimConn) ExecTTY(ctx context.Context, slave *os.File) (shimv1.ContainerShim_ExecClient, error) {
	token, err := c.handoff(ctx, HandoffPty, slave)
	if err != nil {
		return nil, err
	}
	return c.client.Exec(metadata.AppendToOutgoingContext(ctx, ShimPtyTokenKey, token))
}

// Follow subscribes to the container's live output.
func (c *ShimConn) Follow(ctx context.Context) (shimv1.ContainerShim_FollowClient, error) {
	return c.client.Follow(ctx, &shimv1.FollowRequest{Container: c.id.Container})
}

// Close closes the connection. The shim keeps running.
func (c *ShimConn) Close() error { return c.cc.Close() }

// handoffTokenBytes is the hand-off token's length.
const handoffTokenBytes = 16

// The hand-off kinds: the first byte of a hand-off message names what the
// descriptor is for, so a pty slave can never be claimed as a log or the reverse.
const (
	HandoffPty byte = 'p'
	HandoffLog byte = 'l'
)

// SendHandoff passes f to the shim over conn (SCM_RIGHTS) with its kind and a
// fresh random token, waits for the shim's one-byte acknowledgement, and returns
// the token hex-encoded for the RPC that claims it (ShimPtyTokenKey on an Exec,
// ShimLogTokenKey on a ReopenLog).
//
// Why descriptors cross a socket at all: the shim is confined, and its profile
// grants no open of a terminal and no write on any path. The daemon opens the
// pty (keeping the master) or the rotated log, unconfined, and hands over only
// the descriptor, so the shim — and every exec session inheriting its profile —
// reaches nothing by path.
func SendHandoff(conn net.Conn, kind byte, f *os.File) (string, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "", errors.New("descriptor hand-off needs a unix socket")
	}
	msg := make([]byte, 1+handoffTokenBytes)
	msg[0] = kind
	if _, err := rand.Read(msg[1:]); err != nil {
		return "", fmt.Errorf("hand-off token: %w", err)
	}
	if _, _, err := uc.WriteMsgUnix(msg, unix.UnixRights(int(f.Fd())), nil); err != nil {
		return "", fmt.Errorf("send descriptor: %w", err)
	}
	var ack [1]byte
	_ = uc.SetReadDeadline(time.Now().Add(ShimSignalTimeout))
	if _, err := io.ReadFull(uc, ack[:]); err != nil {
		return "", fmt.Errorf("descriptor hand-off acknowledgement: %w", err)
	}
	if ack[0] != 1 {
		return "", errors.New("the shim refused the descriptor")
	}
	return fmt.Sprintf("%x", msg[1:]), nil
}

// RecvHandoff is the shim's half of SendHandoff: it reads the kind, token and
// descriptor from conn. accept decides whether the shim keeps it (a full store
// refuses); the answer is sent back as the acknowledgement, and a refused
// descriptor is closed here.
func RecvHandoff(conn *net.UnixConn, accept func(kind byte, token string, f *os.File) bool) error {
	buf := make([]byte, 1+handoffTokenBytes)
	oob := make([]byte, unix.CmsgSpace(4))
	_ = conn.SetReadDeadline(time.Now().Add(ShimSignalTimeout))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return fmt.Errorf("receive descriptor: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return fmt.Errorf("receive descriptor: none attached (%v)", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return fmt.Errorf("receive descriptor: want one (%v)", err)
	}
	f := os.NewFile(uintptr(fds[0]), "handoff")
	kept := n == len(buf) && (buf[0] == HandoffPty || buf[0] == HandoffLog) &&
		accept(buf[0], fmt.Sprintf("%x", buf[1:]), f)
	ack := byte(0)
	if kept {
		ack = 1
	} else {
		_ = f.Close()
	}
	if _, err := conn.Write([]byte{ack}); err != nil {
		return fmt.Errorf("acknowledge descriptor: %w", err)
	}
	return nil
}

// SessionIdentity reads an exec session's (pid, start time) from its stream's
// response header, which the shim sends once the session has started; it
// blocks until then. ok is false when the header carries none (the session
// never started).
func SessionIdentity(sc shimv1.ContainerShim_ExecClient) (pid int, start int64, ok bool) {
	md, err := sc.Header()
	if err != nil {
		return 0, 0, false
	}
	pids, starts := md.Get(ShimSessionPidKey), md.Get(ShimSessionStartKey)
	if len(pids) != 1 || len(starts) != 1 {
		return 0, 0, false
	}
	p, perr := strconv.Atoi(pids[0])
	st, serr := strconv.ParseInt(starts[0], 10, 64)
	if perr != nil || serr != nil || p <= 1 || st == 0 {
		return 0, 0, false
	}
	return p, st, true
}

// EndExecSession enforces the exec-session invariant from the daemon's side: a
// session ends with its stream. Exec sessions lead their own session or group,
// outside the pod group, so a group kill that takes the shim down (a delete, an
// OOM kill, a grace expiry) leaves them running with nobody to stop them. When a
// proxied stream ends for any reason the daemon calls this: while pid is still
// EXACTLY the reported instance (procStart equals start; a recycled pid is never
// signalled), its group gets SIGTERM, then SIGKILL once grace has passed.
func EndExecSession(pid int, start int64, procStart func(int) (int64, bool), signal func(pgid int, sig os.Signal) error, grace time.Duration) {
	same := func() bool {
		got, ok := procStart(pid)
		return ok && got == start
	}
	if pid <= 1 || !same() {
		return
	}
	_ = signal(pid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !same() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if same() {
		_ = signal(pid, syscall.SIGKILL)
	}
}
