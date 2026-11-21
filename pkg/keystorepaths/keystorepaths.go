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

package keystorepaths

import "path/filepath"

// DataRootPrefix is the name prefix of every keystore entry directly under the
// data root: its files (the floor and delivery records, the logs and their
// archives, the maintenance marker, staging files), RunDir and SockDir. Every
// pod profile denies every data-root name that begins with it, so a keystore
// file a later change adds is denied without a runtime change.
const DataRootPrefix = "keystore-"

// RunDir is the keystore's data-root run directory.
const RunDir = DataRootPrefix + "run"

// SockDir is the root-owned data-root directory that holds the keystore's
// socket (SocketPath).
const SockDir = DataRootPrefix + "sock"

// SocketName is the keystore socket's name inside SockDir.
const SocketName = "keys.sock"

// SocketPath returns the keystore socket path under dataRoot:
// <dataRoot>/keystore-sock/keys.sock.
func SocketPath(dataRoot string) string {
	return filepath.Join(dataRoot, SockDir, SocketName)
}
