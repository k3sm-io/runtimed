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
	"errors"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// errInconsistentRosettaObservation reports that a concurrent GetRuntimeInfo caller
// saw conditions that disagree with the eagerly-computed, immutable values — the
// symptom a lazily-populated cache would produce.
var errInconsistentRosettaObservation = errors.New("concurrent caller observed inconsistent rosetta conditions")

// findCondition returns the named RuntimeCondition from a GetRuntimeInfo response,
// or nil. Shared with the VMBackendAvailable test so both look conditions up the
// same way.
func findCondition(info *runtimev1.GetRuntimeInfoResponse, condType string) *runtimev1.RuntimeCondition {
	for _, c := range info.GetConditions() {
		if c.GetType() == condType {
			return c
		}
	}
	return nil
}

// countingHostProbe is a Deps.HostRosetta fake that returns a canned state and
// counts its invocations (the eager-exactly-once and never-invoked proofs). The
// mutex is not decoration: the concurrency subtest calls GetRuntimeInfo from 8
// goroutines, and calls() must be readable under -race.
type countingHostProbe struct {
	state sandbox.HostRosettaState

	mu    sync.Mutex
	calls int
}

func (p *countingHostProbe) probe(_ context.Context) sandbox.HostRosettaState {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.state
}

func (p *countingHostProbe) calledTimes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// countingGuestProbe is the Deps.GuestRosetta counterpart.
type countingGuestProbe struct {
	state sandbox.GuestRosettaState

	mu    sync.Mutex
	calls int
}

func (p *countingGuestProbe) probe() sandbox.GuestRosettaState {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.state
}

func (p *countingGuestProbe) calledTimes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// rosettaDeps builds the Deps for a Rosetta-condition case: the two probe fakes
// plus a vm backend whose availability decides whether the guest probe runs at all.
// rosettaShare is set TRUE here because these cases are about the PROBE's states;
// the share term is B229's own gate and is exercised by
// TestGuestRosettaWithheldWithoutVMHostShare.
func rosettaDeps(host *countingHostProbe, guest *countingGuestProbe, vmAvailable bool) Deps {
	return Deps{
		VMBackend:    &fakeVMBackend{available: vmAvailable, rosettaShare: true},
		HostRosetta:  host.probe,
		GuestRosetta: guest.probe,
	}
}

// TestGetRuntimeInfo_RosettaAvailability is B103's gate. It proves GetRuntimeInfo
// advertises the two Rosetta capabilities as ADDITIVE RuntimeConditions driven by
// the injectable Deps.HostRosetta / Deps.GuestRosetta probe seams: independent of
// each other, fail-closed on every non-available state, distinct machine Reasons,
// evaluated eagerly exactly once, and never an RPC error.
//
// EVERY assertion is a t.Run SUBTEST of this ONE function on purpose: the gate runs
// `go test -run '^TestGetRuntimeInfo_RosettaAvailability$'`, so a sibling top-level
// Test* would be silently filtered out and never run.
//
// All subtests are hermetic — no real Rosetta, no real Virtualization.framework, no
// root, no network. Nothing here asserts a REAL probe's value: a dev Mac has Rosetta
// 2 installed and a clean one does not, so such an assertion would flip per host.
func TestGetRuntimeInfo_RosettaAvailability(t *testing.T) {
	const (
		condTrue  = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
		condFalse = runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
	)

	// info builds a Runtime over the injected probes and returns its GetRuntimeInfo
	// response, failing the test if the RPC itself errors.
	info := func(t *testing.T, d Deps) *runtimev1.GetRuntimeInfoResponse {
		t.Helper()
		rt := newTestRuntime(t, d)
		resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
		if err != nil {
			t.Fatalf("GetRuntimeInfo: %v", err)
		}
		return resp
	}

	// check asserts one condition's presence, status, Reason and a non-empty Message.
	check := func(t *testing.T, resp *runtimev1.GetRuntimeInfoResponse, condType string, want runtimev1.ConditionStatus, wantReason string) {
		t.Helper()
		c := findCondition(resp, condType)
		if c == nil {
			t.Fatalf("no %s condition; conditions = %v", condType, resp.GetConditions())
		}
		if c.GetStatus() != want {
			t.Errorf("%s status = %v, want %v (reason %q)", condType, c.GetStatus(), want, c.GetReason())
		}
		if c.GetReason() != wantReason {
			t.Errorf("%s reason = %q, want %q", condType, c.GetReason(), wantReason)
		}
		if c.GetMessage() == "" {
			t.Errorf("%s message is empty; an operator needs it to explain the status", condType)
		}
	}

	// --- the availability matrix: the two capabilities are INDEPENDENT ---------

	t.Run("host_true_guest_true", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAvailable},
			&countingGuestProbe{state: sandbox.GuestRosettaInstalled},
			true))
		check(t, resp, ConditionRosettaHostAvailable, condTrue, "Available")
		check(t, resp, ConditionRosettaGuestAvailable, condTrue, "Available")
	})

	t.Run("host_true_guest_false", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAvailable},
			&countingGuestProbe{state: sandbox.GuestRosettaNotInstalled},
			true))
		check(t, resp, ConditionRosettaHostAvailable, condTrue, "Available")
		check(t, resp, ConditionRosettaGuestAvailable, condFalse, "NotInstalled")
	})

	// The load-bearing one: a host without Rosetta 2 must NOT drag the guest
	// capability down with it. They are different translation engines.
	t.Run("host_false_guest_true", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAbsent},
			&countingGuestProbe{state: sandbox.GuestRosettaInstalled},
			true))
		check(t, resp, ConditionRosettaHostAvailable, condFalse, "NotInstalled")
		check(t, resp, ConditionRosettaGuestAvailable, condTrue, "Available")
	})

	t.Run("host_false_guest_false", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAbsent},
			&countingGuestProbe{state: sandbox.GuestRosettaNotSupported},
			true))
		check(t, resp, ConditionRosettaHostAvailable, condFalse, "NotInstalled")
		check(t, resp, ConditionRosettaGuestAvailable, condFalse, "NotSupported")
	})

	// --- fail-closed states get their own Reasons -----------------------------

	// arch(1) collapses EBADARCH and every other failure into a generic non-zero
	// exit, so "the payload is there but translation did not run" is only
	// distinguishable by the probe's STRUCTURE. That distinction must survive into
	// the Reason, or an operator cannot tell a broken Rosetta from an absent one.
	t.Run("host_translation_failed_is_distinct", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaTranslationFailed},
			&countingGuestProbe{state: sandbox.GuestRosettaInstalled},
			true))
		check(t, resp, ConditionRosettaHostAvailable, condFalse, "TranslationFailed")

		absent := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAbsent},
			&countingGuestProbe{state: sandbox.GuestRosettaInstalled},
			true))
		failed := findCondition(resp, ConditionRosettaHostAvailable)
		missing := findCondition(absent, ConditionRosettaHostAvailable)
		if failed.GetReason() == missing.GetReason() {
			t.Errorf("translation-failed and not-installed share reason %q; they must be distinguishable", failed.GetReason())
		}
		if failed.GetMessage() == missing.GetMessage() {
			t.Error("translation-failed and not-installed share the same Message")
		}
	})

	t.Run("guest_not_supported_vs_not_installed", func(t *testing.T) {
		cases := []struct {
			name       string
			state      sandbox.GuestRosettaState
			wantReason string
		}{
			{"not-supported", sandbox.GuestRosettaNotSupported, "NotSupported"},
			{"not-installed", sandbox.GuestRosettaNotInstalled, "NotInstalled"},
		}
		seen := map[string]string{}
		for _, tc := range cases {
			resp := info(t, rosettaDeps(
				&countingHostProbe{state: sandbox.HostRosettaAvailable},
				&countingGuestProbe{state: tc.state},
				true))
			check(t, resp, ConditionRosettaGuestAvailable, condFalse, tc.wantReason)
			c := findCondition(resp, ConditionRosettaGuestAvailable)
			if prev, dup := seen[c.GetReason()]; dup {
				t.Errorf("%s reuses %s's reason %q", tc.name, prev, c.GetReason())
			}
			seen[c.GetReason()] = tc.name
		}
	})

	// A probe that cannot answer must never be read as "yes".
	t.Run("guest_query_failed_fails_closed", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAvailable},
			&countingGuestProbe{state: sandbox.GuestRosettaQueryFailed},
			true))
		check(t, resp, ConditionRosettaGuestAvailable, condFalse, "QueryFailed")
	})

	// --- the vm-backend short-circuit ----------------------------------------

	// With the vm backend unavailable the guest result cannot change any node label
	// (k3sm composes VMBackendAvailable AND RosettaGuestAvailable), so the probe must
	// not be called at all — that is what keeps a Virtualization.framework call off
	// every unentitled Mac. The condition is still emitted, FALSE, naming the cause.
	t.Run("guest_short_circuited_when_vm_unavailable", func(t *testing.T) {
		guest := &countingGuestProbe{state: sandbox.GuestRosettaInstalled}
		resp := info(t, rosettaDeps(&countingHostProbe{state: sandbox.HostRosettaAvailable}, guest, false))
		check(t, resp, ConditionRosettaGuestAvailable, condFalse, reasonRosettaVMBackendUnavailable)
		if n := guest.calledTimes(); n != 0 {
			t.Errorf("guest probe invoked %d times with the vm backend unavailable; want 0 (short-circuited)", n)
		}
	})

	// --- a capability absence is not a handshake failure ----------------------

	t.Run("probe_failure_is_not_a_handshake_failure", func(t *testing.T) {
		cases := []struct {
			name  string
			host  sandbox.HostRosettaState
			guest sandbox.GuestRosettaState
		}{
			{"host-absent", sandbox.HostRosettaAbsent, sandbox.GuestRosettaInstalled},
			{"host-translation-failed", sandbox.HostRosettaTranslationFailed, sandbox.GuestRosettaInstalled},
			{"guest-query-failed", sandbox.HostRosettaAvailable, sandbox.GuestRosettaQueryFailed},
			{"both-unavailable", sandbox.HostRosettaAbsent, sandbox.GuestRosettaNotSupported},
		}
		for _, tc := range cases {
			rt := newTestRuntime(t, rosettaDeps(
				&countingHostProbe{state: tc.host},
				&countingGuestProbe{state: tc.guest},
				true))
			resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
			if err != nil {
				t.Errorf("%s: GetRuntimeInfo err = %v, want nil (an absent capability is not a handshake failure)", tc.name, err)
			}
			if resp == nil {
				t.Errorf("%s: GetRuntimeInfo returned a nil response", tc.name)
			}
		}
	})

	// --- additive, never replacing -------------------------------------------

	t.Run("existing_conditions_preserved", func(t *testing.T) {
		resp := info(t, rosettaDeps(
			&countingHostProbe{state: sandbox.HostRosettaAvailable},
			&countingGuestProbe{state: sandbox.GuestRosettaInstalled},
			true))
		for _, ct := range []string{ConditionSandboxBackend, ConditionVMBackendAvailable} {
			if findCondition(resp, ct) == nil {
				t.Errorf("pre-existing condition %s went missing; the Rosetta conditions are ADDITIVE", ct)
			}
		}
		if n := len(resp.GetConditions()); n != 4 {
			t.Errorf("condition count = %d, want exactly 4 (2 pre-existing + 2 additive); conditions = %v", n, resp.GetConditions())
		}
	})

	// --- the cross-repo wire contract ----------------------------------------

	// k3sm's provider imports these constants, but what actually travels is the
	// STRING. Pin the literals: a rename here would leave the node label silently,
	// permanently absent rather than failing loudly.
	t.Run("condition_types_are_the_documented_literals", func(t *testing.T) {
		if ConditionRosettaHostAvailable != "RosettaHostAvailable" {
			t.Errorf("ConditionRosettaHostAvailable = %q, want %q (wire contract)", ConditionRosettaHostAvailable, "RosettaHostAvailable")
		}
		if ConditionRosettaGuestAvailable != "RosettaGuestAvailable" {
			t.Errorf("ConditionRosettaGuestAvailable = %q, want %q (wire contract)", ConditionRosettaGuestAvailable, "RosettaGuestAvailable")
		}
		if ConditionSandboxBackend != "SandboxBackend" {
			t.Errorf("ConditionSandboxBackend = %q, want %q (wire contract)", ConditionSandboxBackend, "SandboxBackend")
		}
		if ConditionVMBackendAvailable != "VMBackendAvailable" {
			t.Errorf("ConditionVMBackendAvailable = %q, want %q (wire contract)", ConditionVMBackendAvailable, "VMBackendAvailable")
		}
	})

	// --- eager-exactly-once --------------------------------------------------

	// The probes run in the CONSTRUCTOR, once. Three GetRuntimeInfo calls must not
	// add a single fork or framework call: that is what makes the stored results
	// immutable (hence race-free) and bounds the host probe to one fork per daemon.
	t.Run("probes_evaluated_once", func(t *testing.T) {
		host := &countingHostProbe{state: sandbox.HostRosettaAvailable}
		guest := &countingGuestProbe{state: sandbox.GuestRosettaInstalled}
		rt := newTestRuntime(t, rosettaDeps(host, guest, true))
		for i := 0; i < 3; i++ {
			if _, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{}); err != nil {
				t.Fatalf("GetRuntimeInfo #%d: %v", i, err)
			}
		}
		if n := host.calledTimes(); n != 1 {
			t.Errorf("host probe called %d times, want exactly 1 (eager-once in New)", n)
		}
		if n := guest.calledTimes(); n != 1 {
			t.Errorf("guest probe called %d times, want exactly 1 (eager-once in New)", n)
		}
	})

	// --- concurrency ---------------------------------------------------------

	// GetRuntimeInfo is a concurrent gRPC handler. Eight goroutines hammering it must
	// see identical conditions and add no probe calls — and must be clean under
	// -race, which is the real assertion here (a lazily-populated cache would trip it).
	t.Run("concurrent_getruntimeinfo", func(t *testing.T) {
		host := &countingHostProbe{state: sandbox.HostRosettaAvailable}
		guest := &countingGuestProbe{state: sandbox.GuestRosettaInstalled}
		rt := newTestRuntime(t, rosettaDeps(host, guest, true))

		const goroutines, perGoroutine = 8, 25
		var wg sync.WaitGroup
		errs := make(chan error, goroutines*perGoroutine)
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perGoroutine; i++ {
					resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
					if err != nil {
						errs <- err
						return
					}
					h := findCondition(resp, ConditionRosettaHostAvailable)
					gc := findCondition(resp, ConditionRosettaGuestAvailable)
					if h == nil || gc == nil || h.GetStatus() != condTrue || gc.GetStatus() != condTrue {
						errs <- errInconsistentRosettaObservation
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent GetRuntimeInfo: %v", err)
		}
		if n := host.calledTimes(); n != 1 {
			t.Errorf("host probe called %d times under concurrency, want exactly 1", n)
		}
		if n := guest.calledTimes(); n != 1 {
			t.Errorf("guest probe called %d times under concurrency, want exactly 1", n)
		}
	})

	// --- the real production wiring ------------------------------------------

	// With NIL probe deps, New must fall back to sandbox.ProbeHostRosetta /
	// sandbox.ProbeGuestRosetta and STILL advertise both conditions. It deliberately
	// asserts NO VALUE: this repo's dev Macs have Rosetta 2 installed and a clean
	// machine does not, so any value assertion would flip per host. What it does
	// catch is a builder who forgot to wire the real probes at all — the conditions
	// would then be missing, or would carry no Reason.
	//
	// It constructs through testDeps rather than the info/newTestRuntime helper on
	// purpose — the same split pull_wiring_test.go uses for Puller. newTestRuntimeCfg
	// defaults the two probe seams to fakes, so the ~85 constructions that go through
	// it cost no stat and no fork; testDeps leaves them nil, which is how THIS subtest
	// still reaches the real sandbox.Probe*Rosetta. (A few other constructions fall
	// through to the real probes too — pull_wiring_test.go's two and volume_test.go's
	// hand-rolled Deps literal — but this is the only one that ASSERTS on them.)
	t.Run("default_probe_wiring", func(t *testing.T) {
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
		if err != nil {
			t.Fatalf("GetRuntimeInfo: %v", err)
		}
		for _, ct := range []string{ConditionRosettaHostAvailable, ConditionRosettaGuestAvailable} {
			c := findCondition(resp, ct)
			if c == nil {
				t.Fatalf("no %s condition with the DEFAULT (nil) probe deps; the real probes are not wired in New", ct)
			}
			if c.GetReason() == "" {
				t.Errorf("%s has an empty Reason under the default wiring", ct)
			}
			if c.GetMessage() == "" {
				t.Errorf("%s has an empty Message under the default wiring", ct)
			}
		}
	})
}

// TestGuestRosettaWithheldWithoutVMHostShare is B229's gate: a node must not
// advertise a capability it lacks.
//
// The regression it forecloses is specific and would have arrived silently. The
// moment the vm backend becomes available on an entitled Mac, evalGuestRosetta
// would reach the framework probe; +[VZLinuxRosettaDirectoryShare availability]
// says Installed on any recent Apple-Silicon Mac with the payload present; the
// node would then report RosettaGuestAvailable=TRUE, k3sm would label it
// k3sm.io/rosetta-linux, and pkg/image's PlatformPolicy would add linux/amd64 to
// the pull candidate set for every vm pod — while the k3sm-vmhost helper attaches
// no Rosetta share, so each of those images would be pulled and then fail to
// execute in a guest with no interpreter registered.
//
// So the assertions are: with the share unsupported the condition is FALSE with
// its OWN Reason, the framework probe is never called at all (a capability that
// cannot matter is not queried), and — the term-independence check — the same
// probe state DOES report TRUE once the share term holds, which is what proves the
// FALSE above came from the share gate and not from a probe that had been broken.
func TestGuestRosettaWithheldWithoutVMHostShare(t *testing.T) {
	const condFalse = runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
	const condTrue = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE

	t.Run("share-unsupported-withholds-the-capability", func(t *testing.T) {
		guest := &countingGuestProbe{state: sandbox.GuestRosettaInstalled}
		rt := newTestRuntime(t, Deps{
			// Available, entitled, and the host framework says Rosetta for Linux
			// IS installed — every term except the one that matters.
			VMBackend:    &fakeVMBackend{available: true, rosettaShare: false},
			HostRosetta:  (&countingHostProbe{state: sandbox.HostRosettaAvailable}).probe,
			GuestRosetta: guest.probe,
		})
		resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
		if err != nil {
			t.Fatalf("GetRuntimeInfo: %v", err)
		}
		c := findCondition(resp, ConditionRosettaGuestAvailable)
		if c == nil {
			t.Fatalf("no %s condition; conditions = %v", ConditionRosettaGuestAvailable, resp.GetConditions())
		}
		if c.GetStatus() != condFalse {
			t.Errorf("%s status = %v, want FALSE: the VM host attaches no Rosetta share, so a linux/amd64 ELF cannot run in a guest on this node",
				ConditionRosettaGuestAvailable, c.GetStatus())
		}
		if c.GetReason() != reasonRosettaGuestShareUnsupported {
			t.Errorf("%s reason = %q, want %q — the operator must be able to tell this apart from a node that cannot run guests at all",
				ConditionRosettaGuestAvailable, c.GetReason(), reasonRosettaGuestShareUnsupported)
		}
		if c.GetMessage() == "" {
			t.Errorf("%s message is empty; an operator needs it to explain the status", ConditionRosettaGuestAvailable)
		}
		if n := guest.calledTimes(); n != 0 {
			t.Errorf("guest-Rosetta probe called %d times; want 0 — the framework's answer cannot change a capability the VM host does not build", n)
		}
		// The HOST capability is a different translation engine and must be
		// untouched by the guest-side gate.
		if h := findCondition(resp, ConditionRosettaHostAvailable); h.GetStatus() != condTrue {
			t.Errorf("%s status = %v, want TRUE; the vm-host share gate must not drag the host capability down",
				ConditionRosettaHostAvailable, h.GetStatus())
		}
	})

	t.Run("share-supported-restores-the-capability", func(t *testing.T) {
		guest := &countingGuestProbe{state: sandbox.GuestRosettaInstalled}
		rt := newTestRuntime(t, Deps{
			VMBackend:    &fakeVMBackend{available: true, rosettaShare: true},
			HostRosetta:  (&countingHostProbe{state: sandbox.HostRosettaAbsent}).probe,
			GuestRosetta: guest.probe,
		})
		resp, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
		if err != nil {
			t.Fatalf("GetRuntimeInfo: %v", err)
		}
		if c := findCondition(resp, ConditionRosettaGuestAvailable); c.GetStatus() != condTrue {
			t.Errorf("%s status = %v, want TRUE once the VM host attaches the share; the FALSE above must come from the share gate, not from a broken probe",
				ConditionRosettaGuestAvailable, c.GetStatus())
		}
		if n := guest.calledTimes(); n != 1 {
			t.Errorf("guest-Rosetta probe called %d times; want exactly 1 (eager, once)", n)
		}
	})

	t.Run("the-shipped-backend-withholds-it", func(t *testing.T) {
		// The production wiring, not a fake: whatever the fakes above prove about
		// the composition, the binary that ships must answer false today.
		if sandbox.NewVMBackend().GuestRosettaShareSupported() {
			t.Error("the shipped sandbox.VMBackend reports a guest Rosetta share; k3sm-vmhost attaches none")
		}
	})
}
