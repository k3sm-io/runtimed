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

package runtime

import (
	"context"
	"fmt"
	"log/slog"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The Rosetta capability conditions (B103) — evaluated EAGERLY, EXACTLY ONCE, in
// New, and stored immutably on the Runtime.
//
// Why eager-once and not a sync.Once cache: GetRuntimeInfo is a CONCURRENT gRPC
// handler, so a lazily-populated field is shared mutable state reachable from
// several goroutines — a -race finding waiting to happen, and a lock to review
// forever after. Values computed before the Runtime pointer escapes New are
// race-free by CONSTRUCTION, need no synchronisation, and additionally bound the
// host probe to at most ONE fork per daemon lifetime.
//
// The probes are NOT wired into the image-pull platform policy. See pullPolicy in
// pod.go for why that stays false until the Seatbelt x Rosetta spawn is proven
// (B105).

// Rosetta condition Reason tokens. They are MACHINE tokens: an operator greps them
// and a future k3sm reader may branch on them, so each state gets its own and none
// is reused across a different meaning. The host/guest state tokens come from
// sandbox.HostRosettaState.String() / sandbox.GuestRosettaState.String(); the one
// token owned here is the vm-backend short-circuit, which is a runtime-level
// composition fact the sandbox package cannot know about.
const (
	// reasonRosettaVMBackendUnavailable is the guest condition's Reason when the
	// probe was SHORT-CIRCUITED because the vm backend is unavailable.
	reasonRosettaVMBackendUnavailable = "VMBackendUnavailable"
)

// rosettaCondition is one probe's IMMUTABLE, eagerly-evaluated outcome: the three
// fields GetRuntimeInfo needs to build a RuntimeCondition. Plain data rather than a
// cached *runtimev1.RuntimeCondition on purpose — a proto message is a mutable
// pointer, and handing the same pointer to every concurrent caller invites a
// cross-RPC mutation. Each RPC stamps a fresh message from these values.
type rosettaCondition struct {
	status  runtimev1.ConditionStatus
	reason  string
	message string
}

// condition renders c as an additive RuntimeCondition of the given Type.
func (c rosettaCondition) condition(condType string) *runtimev1.RuntimeCondition {
	return &runtimev1.RuntimeCondition{
		Type:    condType,
		Status:  c.status,
		Reason:  c.reason,
		Message: c.message,
	}
}

// logRosettaProbe emits the ONE construction-time log line for a Rosetta probe,
// carrying the full condition (type/status/reason/message). It logs at Info for BOTH
// outcomes — not Warn-on-absent — because an absent host capability is normal, not a
// fault, and the operator question this answers ("why is my node not labelled for
// Rosetta?") is asked in exactly the unavailable case.
func logRosettaProbe(log *slog.Logger, condType string, c rosettaCondition) {
	log.Info("rosetta capability probe",
		"type", condType,
		"status", c.status.String(),
		"reason", c.reason,
		"message", c.message)
}

// evalHostRosetta turns the host-Rosetta probe's state into the condition data.
// ONLY sandbox.HostRosettaAvailable maps to TRUE; every other state — including one
// out of range — is FALSE with its own Reason, so the condition fails closed.
//
// That available/not decision has exactly ONE home: sandbox.HostRosettaState.Available().
// The switch below therefore chooses only the operator MESSAGE (and names an
// unrecognized state). Re-deriving `state == sandbox.HostRosettaAvailable` here would
// give the fail-closed rule two homes, and the copy pkg/sandbox's tests pin would not
// be the copy that ships — a divergence would leave those tests green while the shipped
// condition mislabels a state.
func evalHostRosetta(ctx context.Context, probe func(context.Context) sandbox.HostRosettaState) rosettaCondition {
	state := probe(ctx)
	c := rosettaCondition{status: runtimev1.ConditionStatus_CONDITION_STATUS_FALSE, reason: state.String()}
	if state.Available() {
		c.status = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
	}
	switch state {
	case sandbox.HostRosettaAvailable:
		c.message = "Rosetta 2 present and a translated exec succeeded; this host can run darwin/amd64 Mach-O payloads"
	case sandbox.HostRosettaTranslationFailed:
		c.message = "the Rosetta 2 runtime is installed but a translated exec did not succeed (non-zero exit, spawn error, or probe timeout); treating darwin/amd64 as unrunnable"
	case sandbox.HostRosettaAbsent:
		c.message = "the Rosetta 2 runtime is not installed on this host; darwin/amd64 Mach-O payloads cannot be translated"
	default:
		// An unrecognized state has no Message of its own: NAME it rather than
		// silently folding it into one of the known Reasons. Its status needs no
		// override here — Available() is false for every state outside the known
		// set, which is where the fail-closed guarantee actually comes from.
		c.reason = "Unknown"
		c.message = fmt.Sprintf("the host-Rosetta probe returned an unrecognized state (%d); failing closed", int(state))
	}
	return c
}

// evalGuestRosetta turns the guest-Rosetta probe's state into the condition data,
// SHORT-CIRCUITING the probe entirely when the vm backend is unavailable.
//
// The short-circuit is not an optimisation of convenience: k3sm composes the node's
// guest-Rosetta capability as VMBackendAvailable AND RosettaGuestAvailable, so with
// the vm backend down the guest result cannot change any label — and skipping it
// keeps a Virtualization.framework call off every unentitled Mac. When
// short-circuited the condition is FALSE naming that cause, never TRUE.
//
// ONLY sandbox.GuestRosettaInstalled maps to TRUE, and — exactly as in
// evalHostRosetta — that decision has ONE home, sandbox.GuestRosettaState.Available();
// the switch chooses only the operator Message.
func evalGuestRosetta(vmBackend VMBackend, probe func() sandbox.GuestRosettaState) rosettaCondition {
	if vmBackend == nil || !vmBackend.Available() {
		return rosettaCondition{
			status:  runtimev1.ConditionStatus_CONDITION_STATUS_FALSE,
			reason:  reasonRosettaVMBackendUnavailable,
			message: "the vm backend is unavailable, so no Linux guest can run here and guest Rosetta was not probed (the node capability is VMBackendAvailable AND RosettaGuestAvailable)",
		}
	}
	state := probe()
	c := rosettaCondition{status: runtimev1.ConditionStatus_CONDITION_STATUS_FALSE, reason: state.String()}
	if state.Available() {
		c.status = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
	}
	switch state {
	case sandbox.GuestRosettaInstalled:
		c.message = "Rosetta for Linux is installed; a Linux guest on this host can run linux/amd64 ELF payloads"
	case sandbox.GuestRosettaNotInstalled:
		c.message = "Rosetta for Linux is supported but not installed; runtimed never installs it (the framework's install entry points prompt the user, which a GUI-less daemon cannot answer)"
	case sandbox.GuestRosettaNotSupported:
		c.message = "this host does not support Rosetta for Linux (Apple-Silicon-only); linux/amd64 ELF payloads cannot be translated in a guest"
	case sandbox.GuestRosettaQueryFailed:
		c.message = "the guest-Rosetta availability query could not answer (no Virtualization.framework in this build lane, or an unexpected framework result); failing closed"
	default:
		// As in evalHostRosetta: name the state; Available() already made it FALSE.
		c.reason = "Unknown"
		c.message = fmt.Sprintf("the guest-Rosetta probe returned an unrecognized state (%d); failing closed", int(state))
	}
	return c
}
