//go:build !darwin

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
	"net"
)

// UnixShimDialer off darwin is a stub: the peer-pid check (LOCAL_PEERPID) the
// shim's identity rests on exists only on darwin, so it refuses every dial.
type UnixShimDialer struct{}

// DialShim is unsupported off darwin.
func (UnixShimDialer) DialShim(context.Context, string) (net.Conn, int, error) {
	return nil, 0, errUnsupported
}

// PeerPID is unsupported off darwin.
func PeerPID(*net.UnixConn) (int, error) { return 0, errUnsupported }
