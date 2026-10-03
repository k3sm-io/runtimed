//go:build darwin

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
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// solLocal is SOL_LOCAL, the darwin socket level of the LOCAL_PEER* options
// (<sys/un.h>; golang.org/x/sys/unix exports the option, not the level).
const solLocal = 0

// UnixShimDialer is the production ShimDialer: a unix-socket dial plus the peer
// pid the kernel attributes the connection to (getsockopt LOCAL_PEERPID). The
// zero value is usable.
type UnixShimDialer struct{}

// DialShim dials path and reads the connection's peer pid.
func (UnixShimDialer) DialShim(ctx context.Context, path string) (net.Conn, int, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, 0, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, 0, fmt.Errorf("dial %s: not a unix socket", path)
	}
	pid, err := PeerPID(uc)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	return conn, pid, nil
}

// PeerPID returns the pid of the process on the other end of conn
// (getsockopt LOCAL_PEERPID).
func PeerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peer pid: %w", err)
	}
	var pid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		pid, serr = unix.GetsockoptInt(int(fd), solLocal, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, fmt.Errorf("peer pid: %w", err)
	}
	if serr != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERPID: %w", serr)
	}
	return pid, nil
}
