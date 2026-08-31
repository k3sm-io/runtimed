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
	"crypto/sha256"
	"net"
)

// DeriveMAC returns the guest NIC's hardware address for podID: the first six
// bytes of sha256(podID), with the first byte forced UNICAST and LOCALLY
// ADMINISTERED (clear bit 0, set bit 1).
//
// DETERMINISM IS THE FEATURE. macOS's NAT attachment leases the guest's address
// over DHCP keyed on the MAC, so a MAC derived fresh per boot would give the same
// pod a different address every time it restarted — and the pod's status IP, its
// endpoint, and any in-flight connection would move with it. Deriving from the pod
// id makes the lease stable across a VM restart of the SAME pod and different
// between pods, without the helper holding any state at all.
//
// The two bit edits are not cosmetic. Bit 0 set marks a MULTICAST address, which
// is not a legal source address for a NIC; bit 1 clear claims a globally-unique
// address under some vendor's OUI, and k3sm owns none — a guest carrying one can
// collide with real hardware on the operator's LAN. Forcing them makes every
// derived address legal by construction rather than by luck of the hash.
//
// sha256 is used as a fixed, well-specified spreading function, not as a security
// primitive: nothing here is secret, and a pod id is not attacker-chosen in a way
// that a MAC collision would help. A collision would cost two guests on one node a
// confused DHCP lease, which is why 48 bits is enough.
func DeriveMAC(podID string) string {
	sum := sha256.Sum256([]byte(podID))
	hw := net.HardwareAddr(sum[:6])
	hw[0] = hw[0]&^0x01 | 0x02
	return hw.String()
}
