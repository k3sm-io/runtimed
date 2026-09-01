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

package vmhost

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

	guestv1 "k3sm.io/apis/guest/v1"
)

// maxSpecBytes bounds the vmhost.spec.json this helper will read. The file is
// written by the daemon into the pod dir, so this is a corruption/runaway guard
// rather than a trust boundary — but an unbounded ReadFile on a path another
// process owns is how a helper turns a disk-filling bug into an OOM.
const maxSpecBytes = 4 << 20

// ReadSpec reads and decodes the host-written VMHostSpec at path.
//
// unknown FIELDS are rejected (DiscardUnknown: false), mirroring
// cmd/k3sm-guest-init's readSpec exactly. The file is the proto-JSON encoding of
// VMHostSpec and nothing else, so a key this binary does not know means the daemon
// and this helper were built from different contracts. That skew must fail AT BOOT
// with a legible reason: the alternative is a helper that silently drops the field
// — a share the daemon meant to attach, a port it meant to use — and then a guest
// that fails much later for a reason nothing connects back to the skew.
//
// The two ends really can differ: guest/v1 is a versioned wire contract precisely
// because the guest half ships in an independently-released initramfs, and the
// dev-lab --guest-artifacts-dir override makes an unsupported pairing reachable.
// Legible-and-refused is the posture for all of it.
func ReadSpec(path string) (*guestv1.VMHostSpec, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read vmhost spec: %w", err)
	}
	if fi.Size() > maxSpecBytes {
		return nil, fmt.Errorf("read vmhost spec %s: %d bytes exceeds the %d-byte bound", path, fi.Size(), maxSpecBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vmhost spec: %w", err)
	}
	spec := &guestv1.VMHostSpec{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, spec); err != nil {
		return nil, fmt.Errorf("decode vmhost spec %s (a key this helper does not know means the daemon and this helper disagree about guest/v1): %w", path, err)
	}
	return spec, nil
}
