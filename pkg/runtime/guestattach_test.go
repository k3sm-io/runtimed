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
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/guestagent"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// drainAttach collects everything already buffered on the fake attach stream.
// It is called after the handler returned, so the buffer is complete and the
// drain is non-blocking — an assertion about what did NOT arrive needs that
// determinism.
func drainAttach(st *fakeAttachStream) (stdout, stderr []byte, exit *runtimev1.ExecResult, frames int) {
	for {
		select {
		case resp := <-st.out:
			frames++
			stdout = append(stdout, resp.GetStdout()...)
			stderr = append(stderr, resp.GetStderr()...)
			if ex := resp.GetExit(); ex != nil {
				exit = ex
			}
		default:
			return stdout, stderr, exit, frames
		}
	}
}

// TestVMPodAttachRoutesToGuestAgent is the vm attach route's gate.
//
// A vm pod's containers are GUEST processes: they have no host containerProc, so
// the host-process attach path cannot answer for one at all, and before this
// route `kubectl attach` on a vm pod died in lookupContainer with "container not
// found" for a container that was demonstrably running. What the route has to
// get right is the same short list Exec's does — resolve the pod BEFORE the
// container lookup, re-stamp the first frame with what this node resolved,
// forward nothing but stdin bytes and resizes afterwards, and rebuild the
// response field by field — plus the one property that is attach's alone:
// tearing the stream down must not touch the workload.
func TestVMPodAttachRoutesToGuestAgent(t *testing.T) {
	t.Run("output-demux-and-exit-code-round-trip", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			for _, resp := range []*runtimev1.AttachResponse{
				{Stdout: []byte("out-a")},
				{Stderr: []byte("err-1")},
				{Stdout: []byte("out-b")},
			} {
				if err := gs.Send(resp); err != nil {
					return err
				}
			}
			return gs.Send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: 42}})
		}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdout: true, Stderr: true})
		st.closeSend()
		if err := rt.Attach(st); err != nil {
			t.Fatalf("Attach: %v", err)
		}

		stdout, stderr, exit, _ := drainAttach(st)
		if got, want := string(stdout), "out-aout-b"; got != want {
			t.Errorf("stdout = %q, want %q (stderr must not leak into it)", got, want)
		}
		if got, want := string(stderr), "err-1"; got != want {
			t.Errorf("stderr = %q, want %q", got, want)
		}
		if exit == nil || exit.GetExitCode() != 42 {
			t.Errorf("exit = %+v, want exit code 42", exit)
		}

		// The route dialed the pod's own runtimed-private agent socket.
		want, err := guestAgentSocket(rt.cfg.Root, "pod-vm")
		if err != nil {
			t.Fatal(err)
		}
		if got := dialed(); len(got) != 1 || got[0] != want {
			t.Errorf("dialed = %v, want exactly [%s]", got, want)
		}

		// The first frame carries the pod id this route resolved and the
		// container it resolved host-side against what the PodBox declared —
		// never whatever the client happened to send.
		frames := agent.attachSeen()
		if len(frames) == 0 {
			t.Fatal("the guest agent received no frame")
		}
		if frames[0].GetPodId() != "pod-vm" {
			t.Errorf("forwarded pod_id = %q, want %q", frames[0].GetPodId(), "pod-vm")
		}
		if frames[0].GetContainer() != "app" {
			t.Errorf("forwarded container = %q, want the pod's sole declared container %q",
				frames[0].GetContainer(), "app")
		}
	})

	t.Run("stdin-and-resize-are-forwarded-and-nothing-else-is", func(t *testing.T) {
		relayed := make(chan *runtimev1.AttachRequest, 8)
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			for {
				req, err := gs.Recv()
				if err != nil {
					close(relayed)
					return nil
				}
				relayed <- req
			}
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app", "sidecar")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Container: "app", Stdin: true, Stdout: true, Tty: true})
		st.feed(&runtimev1.AttachRequest{StdinData: []byte("typed")})
		st.feed(&runtimev1.AttachRequest{Resize: &runtimev1.TerminalSize{Width: 100, Height: 40}})
		// A frame trying to re-aim the stream at the pod's OTHER container, with
		// no payload of its own: it must not reach the guest at all.
		st.feed(&runtimev1.AttachRequest{PodId: "pod-elsewhere", Container: "sidecar"})
		st.closeSend()
		if err := rt.Attach(st); err != nil {
			t.Fatalf("Attach: %v", err)
		}

		var got []*runtimev1.AttachRequest
		deadline := time.After(3 * time.Second)
		for {
			select {
			case req, ok := <-relayed:
				if !ok {
					goto done
				}
				got = append(got, req)
				continue
			case <-deadline:
				t.Fatal("timed out draining the frames the guest received")
			}
		}
	done:
		// got holds the POST-PARAMETER frames only: the fake agent consumes the
		// first one itself, exactly as the shipped agent does. Two is the whole
		// point — the payload-free re-aiming frame is dropped by the host pump
		// and never crosses at all.
		if len(got) != 2 {
			t.Fatalf("the guest received %d post-parameter frames, want 2 (stdin, resize) — got %+v", len(got), got)
		}
		if string(got[0].GetStdinData()) != "typed" {
			t.Errorf("stdin frame = %q, want %q", got[0].GetStdinData(), "typed")
		}
		if got[1].GetResize().GetWidth() != 100 || got[1].GetResize().GetHeight() != 40 {
			t.Errorf("resize frame = %+v, want 100x40", got[1].GetResize())
		}
		for i, req := range got {
			if req.GetPodId() != "" || req.GetContainer() != "" {
				t.Errorf("post-parameter frame %d carried a selector (%q/%q) — a later frame must not be able to re-aim the stream",
					i, req.GetPodId(), req.GetContainer())
			}
		}
		params := agent.attachSeen()
		if len(params) != 1 {
			t.Fatalf("the guest saw %d parameter frames, want exactly 1", len(params))
		}
		if params[0].GetContainer() != "app" || params[0].GetPodId() != "pod-vm" {
			t.Errorf("parameter frame = %q/%q, want pod-vm/app", params[0].GetPodId(), params[0].GetContainer())
		}
		if !params[0].GetTty() || !params[0].GetStdin() || !params[0].GetStdout() {
			t.Errorf("the client's stdin/stdout/tty flags did not cross: %+v", params[0])
		}
	})

	t.Run("the-agents-refusal-reaches-the-client-with-its-own-code", func(t *testing.T) {
		// The shipped agent answers a stdin request against a container with no
		// retained endpoint with FailedPrecondition. That code, and the message
		// naming the fix, is the whole value of the refusal — a route that
		// flattened it to Internal would leave the operator with nothing to act
		// on.
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			return status.Error(codes.FailedPrecondition,
				"attach: container \"app\" retains no stdin endpoint; set stdin: true and recreate the pod")
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdin: true, Stdout: true})
		st.closeSend()

		err := rt.Attach(st)
		if code := status.Code(err); code != codes.FailedPrecondition {
			t.Fatalf("Attach = %v (code %s), want FailedPrecondition", err, code)
		}
		if !strings.Contains(err.Error(), "stdin: true") {
			t.Errorf("the agent's remedy was dropped on the way out: %v", err)
		}
	})

	t.Run("a-host-process-pod-never-takes-this-route", func(t *testing.T) {
		// The native attach path is byte-unchanged and must stay so: the route
		// dispatch keys off the RESOLVED backend, so a Seatbelt-confined pod
		// dials nothing.
		agent := &fakeGuestAgent{bootedPod: "pod-native"}
		dial, dialed := startFakeGuestAgent(t, agent)
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{GuestDialer: dial, Backend: &recordingExecBackend{}, Waiter: w})
		mustCreatePod(t, rt, hostBinBox(rt, "pod-native"))
		defer w.release(1001)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-native", Stdin: true, Stdout: true})
		st.closeSend()

		// The M2 native limitation still applies, and the guest was never dialed.
		if code := status.Code(rt.Attach(st)); code != codes.Unimplemented {
			t.Errorf("native attach with stdin = %s, want Unimplemented (PHASES M2.7)", code)
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("a host-process pod's attach dialed a guest agent: %v", got)
		}
	})

	t.Run("an-undeclared-container-is-refused-host-side", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Container: "ghost", Stdout: true})
		st.closeSend()

		if code := status.Code(rt.Attach(st)); code != codes.NotFound {
			t.Errorf("attach to an undeclared container = %s, want NotFound", code)
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("a selector the pod never declared was carried to the guest: %v", got)
		}
	})

	t.Run("an-oversized-guest-frame-ends-the-stream-and-is-named", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			return gs.Send(&runtimev1.AttachResponse{Stdout: make([]byte, maxGuestFrameBytes+1024)})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdout: true})
		st.closeSend()

		err := rt.Attach(st)
		if code := status.Code(err); code != codes.ResourceExhausted {
			t.Fatalf("Attach over an oversized frame = %v (code %s), want ResourceExhausted", err, code)
		}
		if !strings.Contains(err.Error(), "byte bound") {
			t.Errorf("the refusal does not name the bound it enforced: %v", err)
		}
		if _, _, _, frames := drainAttach(st); frames != 0 {
			t.Errorf("%d frames reached the client from an over-bound guest message, want 0", frames)
		}
	})
}

// TestGuestCapabilityNegotiation is the gate on the legible-skew requirement.
//
// Compat is LOCKSTEP via the in-code initramfs sha256 pin, so the only reachable
// way to pair this daemon with an older guest is the dev-lab
// --guest-artifacts-dir override. guest.proto's answer is that unsupported must
// still be LEGIBLE: without this, such a pairing answers `kubectl attach` with a
// bare "method Attach not implemented" and `kubectl exec -it` with a refusal
// from inside the guest — both true, and neither distinguishable by the
// operator from a bug in this daemon.
//
// The three-state rule is the substance. An agent that ANSWERED and did not
// advertise the token has made a positive statement and is refused; a pod whose
// agent has not been polled yet has made none, and is let through, because
// refusing on the strength of never having asked would fail every verb issued
// before the lease watcher's first poll landed.
func TestGuestCapabilityNegotiation(t *testing.T) {
	t.Run("classify-is-three-valued", func(t *testing.T) {
		full := map[string]struct{}{
			guestagent.CapabilityTTYExec: {},
			guestagent.CapabilityAttach:  {},
		}
		for _, tc := range []struct {
			name     string
			observed bool
			caps     map[string]struct{}
			token    string
			want     guestCapVerdict
		}{
			{"never-polled", false, nil, guestagent.CapabilityAttach, guestCapUnobserved},
			{"never-polled-ignores-a-stale-set", false, full, guestagent.CapabilityAttach, guestCapUnobserved},
			{"advertised", true, full, guestagent.CapabilityAttach, guestCapPresent},
			{"advertised-tty-exec", true, full, guestagent.CapabilityTTYExec, guestCapPresent},
			{"old-guest-advertises-nothing", true, map[string]struct{}{}, guestagent.CapabilityAttach, guestCapAbsent},
			{"partial-guest", true, map[string]struct{}{guestagent.CapabilityTTYExec: {}}, guestagent.CapabilityAttach, guestCapAbsent},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := classifyGuestCapability(tc.observed, tc.caps, tc.token); got != tc.want {
					t.Errorf("classify = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("only-known-tokens-are-retained", func(t *testing.T) {
		// Everything an agent sends is guest-controlled data. The recorded set
		// is filtered to this daemon's own vocabulary, so no guest-chosen string
		// is ever stored on a pod, and a flood of them is bounded.
		rt := newTestRuntime(t, Deps{})
		p := addVMPod(t, rt, "pod-vm", "app")

		advertised := []string{guestagent.CapabilityAttach, "made-up", strings.Repeat("x", 4096)}
		for i := 0; i < 200; i++ {
			advertised = append(advertised, "flood")
		}
		rt.setGuestCapabilities(p, advertised)

		p.mu.Lock()
		caps, observed := p.guestCaps, p.guestCapsObserved
		p.mu.Unlock()
		if !observed {
			t.Fatal("the capability set was not marked observed")
		}
		if len(caps) != 1 {
			t.Fatalf("retained %d tokens, want 1 (only known ones): %v", len(caps), caps)
		}
		if _, ok := caps[guestagent.CapabilityAttach]; !ok {
			t.Errorf("the known token was not retained: %v", caps)
		}
	})

	t.Run("an-old-guest-gets-a-legible-refusal-never-a-crash", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		p := addVMPod(t, rt, "pod-vm", "app")
		// An initramfs that predates both slices advertises nothing at all.
		rt.setGuestCapabilities(p, nil)

		t.Run("attach", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			st := newFakeAttachStream(ctx)
			st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdout: true})
			st.closeSend()

			err := rt.Attach(st)
			if code := status.Code(err); code != codes.FailedPrecondition {
				t.Fatalf("attach against an old guest = %v (code %s), want FailedPrecondition", err, code)
			}
			for _, want := range []string{guestagent.CapabilityAttach, "recreate the pod", "guest-artifacts-dir"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %q: %v", want, err)
				}
			}
		})

		t.Run("tty-exec", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			st := newFakeExecStream(ctx)
			st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/sh"}, Tty: true})
			st.closeSend()

			err := rt.Exec(st)
			if code := status.Code(err); code != codes.FailedPrecondition {
				t.Fatalf("tty exec against an old guest = %v (code %s), want FailedPrecondition", err, code)
			}
			if !strings.Contains(err.Error(), guestagent.CapabilityTTYExec) {
				t.Errorf("the refusal does not name the missing capability: %v", err)
			}
		})

		if got := dialed(); len(got) != 0 {
			t.Errorf("a refused request still dialed the guest: %v", got)
		}
	})

	t.Run("a-plain-exec-is-never-gated", func(t *testing.T) {
		// Only a TTY exec needs negotiating: a plain exec has been served by
		// every initramfs this daemon has ever paired with, and gating it would
		// refuse working pods for nothing.
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		p := addVMPod(t, rt, "pod-vm", "app")
		rt.setGuestCapabilities(p, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/true"}})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("a plain exec against an old guest was refused: %v", err)
		}
	})

	t.Run("a-capable-guest-is-let-through", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			return gs.Send(&runtimev1.AttachResponse{Stdout: []byte("hi")})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		p := addVMPod(t, rt, "pod-vm", "app")
		rt.setGuestCapabilities(p, guestagent.Capabilities())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdout: true})
		st.closeSend()
		if err := rt.Attach(st); err != nil && err != io.EOF {
			t.Fatalf("attach against a capable guest: %v", err)
		}
		stdout, _, _, _ := drainAttach(st)
		if string(stdout) != "hi" {
			t.Errorf("stdout = %q, want %q", stdout, "hi")
		}
	})

	t.Run("an-unpolled-pod-is-let-through", func(t *testing.T) {
		// The bootstrap case: an exec issued before the lease watcher's first
		// poll landed. Refusing here would break every such request.
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.attach = func(gs guestv1.GuestAgent_AttachServer) error {
			return gs.Send(&runtimev1.AttachResponse{Stdout: []byte("hi")})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app") // never polled

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{PodId: "pod-vm", Stdout: true})
		st.closeSend()
		if err := rt.Attach(st); err != nil && err != io.EOF {
			t.Fatalf("attach against an unpolled pod: %v", err)
		}
		stdout, _, _, _ := drainAttach(st)
		if string(stdout) != "hi" {
			t.Errorf("stdout = %q, want %q", stdout, "hi")
		}
	})
}
