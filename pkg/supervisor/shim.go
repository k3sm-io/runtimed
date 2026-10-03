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
	// ShimPtySockName is the pty hand-off socket in a container's shim dir (see
	// SendPtyHandoff).
	ShimPtySockName = "pty.sock"
	// ShimExitFile is the persisted exit record in a container's shim dir. It is
	// the AUTHORITY for the container's exit status on every path: the shim
	// writes it (tmp + rename) after it reaped the container and before it
	// exits, and the daemon reads it when it observes the shim's exit.
	ShimExitFile = "exit.json"

	// ShimModeServe, ShimModeLaunch and ShimModeExec are the exec-shim's first
	// argument. serve is the resident shim; launch is the container's own
	// launch sequence (the shim spawns it); exec is an exec session the shim
	// spawns inside its own, already applied, confinement.
	ShimModeServe  = "serve"
	ShimModeLaunch = "launch"
	ShimModeExec   = "exec"

	// ShimPtyTokenKey is the gRPC metadata key an Exec stream names its handed-off
	// pty slave by (SendPtyHandoff). Present only on a tty session.
	ShimPtyTokenKey = "k3sm-pty-token"

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

// ShimPtySockPath is the pty hand-off socket in shim dir dir.
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

// WriteExitRecord persists rec in dir as ShimExitFile, through a tmp file and a
// rename (the podreap record idiom), so a reader sees the whole record or none.
func WriteExitRecord(dir string, rec ExitRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal exit record: %w", err)
	}
	final := filepath.Join(dir, ShimExitFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write exit record: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit exit record: %w", err)
	}
	return nil
}

// ReadExitRecord reads dir's exit record. ok is false, with a nil error, when
// there is none yet.
func ReadExitRecord(dir string) (rec ExitRecord, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, ShimExitFile))
	if errors.Is(err, os.ErrNotExist) {
		return ExitRecord{}, false, nil
	}
	if err != nil {
		return ExitRecord{}, false, fmt.Errorf("read exit record: %w", err)
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return ExitRecord{}, false, fmt.Errorf("decode exit record: %w", err)
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

// ReopenLog asks the shim to reopen the container's log at its path, bounded by
// ShimReopenTimeout. The daemon has already created the new, empty file there:
// the shim only opens it.
func (c *ShimConn) ReopenLog(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ShimReopenTimeout)
	defer cancel()
	_, err := c.client.ReopenLog(ctx, &shimv1.ReopenLogRequest{Container: c.id.Container})
	return err
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
	conn, err := dialVerified(ctx, c.dialer, ShimPtySockPath(c.id.Dir), c.id.Pid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	token, err := SendPtyHandoff(conn, slave)
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

// ptyTokenBytes is the hand-off token's length.
const ptyTokenBytes = 16

// SendPtyHandoff passes slave to the shim over conn (SCM_RIGHTS) with a fresh
// random token, waits for the shim's one-byte acknowledgement, and returns the
// token hex-encoded for the Exec stream's ShimPtyTokenKey metadata.
//
// Why the slave crosses a socket at all: the shim is confined by the pod's
// profile plus its grant, and a confined process cannot open /dev/ptmx or a
// tty node. The daemon allocates the pty unconfined, keeps the master, and
// hands only the slave over, so a confined exec session gets a terminal without
// the shim ever holding a grant that would reach another session's tty.
func SendPtyHandoff(conn net.Conn, slave *os.File) (string, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "", errors.New("pty hand-off needs a unix socket")
	}
	token := make([]byte, ptyTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("pty hand-off token: %w", err)
	}
	if _, _, err := uc.WriteMsgUnix(token, unix.UnixRights(int(slave.Fd())), nil); err != nil {
		return "", fmt.Errorf("send pty slave: %w", err)
	}
	var ack [1]byte
	_ = uc.SetReadDeadline(time.Now().Add(ShimSignalTimeout))
	if _, err := io.ReadFull(uc, ack[:]); err != nil {
		return "", fmt.Errorf("pty hand-off acknowledgement: %w", err)
	}
	return fmt.Sprintf("%x", token), nil
}

// RecvPtyHandoff is the shim's half of SendPtyHandoff: it reads the token and the
// descriptor from conn, acknowledges, and returns them.
func RecvPtyHandoff(conn *net.UnixConn) (string, *os.File, error) {
	buf := make([]byte, ptyTokenBytes)
	oob := make([]byte, unix.CmsgSpace(4))
	_ = conn.SetReadDeadline(time.Now().Add(ShimSignalTimeout))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return "", nil, fmt.Errorf("receive pty slave: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return "", nil, fmt.Errorf("receive pty slave: no descriptor (%v)", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return "", nil, fmt.Errorf("receive pty slave: want one descriptor (%v)", err)
	}
	f := os.NewFile(uintptr(fds[0]), "pty-slave")
	if n != ptyTokenBytes {
		_ = f.Close()
		return "", nil, fmt.Errorf("receive pty slave: token of %d bytes", n)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		_ = f.Close()
		return "", nil, fmt.Errorf("acknowledge pty slave: %w", err)
	}
	return fmt.Sprintf("%x", buf), f, nil
}
