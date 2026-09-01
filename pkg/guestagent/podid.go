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

package guestagent

import (
	"errors"
	"fmt"
	"strings"
)

// PodIDCmdlineKey is the kernel command-line key carrying the pod id the guest
// booted for: `k3sm.pod_id=<kube Pod UID>`.
//
// # Why the command line, and not the boot spec
//
// guest.proto requires this agent to "reject a pod_id that is not the pod it
// booted" — but guest/v1's GuestSpec carries no pod_id field, so as the contract
// stands the guest is asked to assert an identity it is never told. Only
// VMHostSpec has pod_id, and that message is read by the HOST-side VM helper, not
// by anything inside the guest.
//
// Rather than edit the shared contract, the id rides the kernel command line,
// which is the same posture guestinit.SpecShareTag already takes: "a host/guest
// convention, not a guest/v1 field". It is a good fit for this particular value —
// it is fixed for the machine's whole life, it is set by the hypervisor before any
// guest code runs, and it is therefore not something a compromised workload can
// rewrite to make its guest answer for a different pod.
//
// The residual is honest: a pod_id field on GuestSpec would be the cleaner home,
// and adding one is an apis change, tracked separately.
//
// # Who writes it
//
// pkg/vmhost's FromSpec appends it from VMHostSpec.pod_id when the daemon's
// cmdline does not already carry it, and refuses a cmdline that carries a
// different one — so the value the guest reads is the value the host meant, and a
// disagreement is a loud rejection rather than a guest that quietly answers for
// the wrong pod.
const PodIDCmdlineKey = "k3sm.pod_id"

// ErrPodIDAbsent reports that the kernel command line carried no PodIDCmdlineKey.
//
// It is fatal for the agent, not a degraded mode: an agent that does not know its
// own pod cannot perform the rejection guest.proto requires of it, and one that
// accepted every pod_id would answer Exec, Logs and Stats for a pod it is not.
var ErrPodIDAbsent = errors.New("guestagent: the kernel command line carries no " + PodIDCmdlineKey)

// PodIDFromCmdline extracts the pod id from a /proc/cmdline string.
//
// The kernel command line is whitespace-separated `key=value` tokens. Parsing is
// deliberately strict: the last occurrence wins (matching the kernel's own
// last-wins rule for repeated parameters, so a reader here and the kernel never
// disagree about which value took effect), an empty value is an absence rather
// than an empty id, and nothing is unquoted or unescaped — the value is a kube UID,
// which is hex and dashes.
func PodIDFromCmdline(cmdline string) (string, error) {
	prefix := PodIDCmdlineKey + "="
	found := ""
	for _, tok := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(tok, prefix); ok {
			found = v
		}
	}
	if found == "" {
		return "", ErrPodIDAbsent
	}
	if err := validPodIDToken(found); err != nil {
		return "", err
	}
	return found, nil
}

// validPodIDToken rejects a pod id the agent will not adopt as its identity: one
// carrying anything outside printable ASCII, or longer than a kube UID could be.
// A malformed id here would be compared against every incoming pod_id, so a silent
// acceptance would turn a boot-time typo into a pod that can never be reached.
func validPodIDToken(id string) error {
	if len(id) > 253 {
		return fmt.Errorf("%s is %d bytes, over the 253-byte bound", PodIDCmdlineKey, len(id))
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("%s carries a character outside printable ASCII", PodIDCmdlineKey)
		}
	}
	return nil
}
