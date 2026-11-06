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
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pathErrorSigner fails as the production signer does, with the host path in the
// error, so a message that passes the error on shows the path to the caller.
type pathErrorSigner struct {
	suffix  string
	signErr error
}

func (s pathErrorSigner) Sign(_ context.Context, _, path string) error {
	return fmt.Errorf("copy %s: %w", path, s.signErr)
}

func (s pathErrorSigner) Check(_ context.Context, _ runtimev1.SignaturePolicy, path string) error {
	if strings.HasSuffix(path, s.suffix) {
		return fmt.Errorf("%w: %s is unsigned", image.ErrSignatureRejected, path)
	}
	return nil
}

// TestExecGateRefusalNamesTheContainerPath pins who reads what: the caller of a
// refused exec gets the path it sent, and only the daemon log names the host
// rootfs.
func TestExecGateRefusalNamesTheContainerPath(t *testing.T) {
	tree := map[string]string{"bin/tool": imageScript}
	cases := []struct {
		name   string
		policy runtimev1.SignaturePolicy
	}{
		{name: "a_check_refusal", policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED},
		{name: "a_sign_failure", policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			signer := pathErrorSigner{suffix: "/bin/tool", signErr: errors.New("no space left")}
			p := newExecArgvPodCfg(t, cfg, tree, signer, func(box *runtimev1.PodBox) {
				box.SignaturePolicy = tc.policy
			})

			got, _, err := p.exec(t, "/bin/tool")
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("Exec error = %v, want FailedPrecondition", err)
			}
			if got != "" {
				t.Errorf("a refused exec reached the confinement seam with argv[0] %q", got)
			}
			msg := status.Convert(err).Message()
			if !strings.Contains(msg, `"/bin/tool"`) {
				t.Errorf("message %q does not name the path the caller sent", msg)
			}
			if strings.Contains(msg, p.rt.cfg.Root) {
				t.Errorf("message %q shows the caller a host path under %q", msg, p.rt.cfg.Root)
			}
			if line := logs.String(); !strings.Contains(line, p.rootfs) {
				t.Errorf("daemon log %q does not name the host rootfs %q", line, p.rootfs)
			}
		})
	}
}

// heldSigner blocks every first check of a file under /bin/ until release closes,
// or until the caller's context ends, which reads as a refusal just as a killed
// codesign does (runCodesignVerify). Sign clears a file.
type heldSigner struct {
	mu      sync.Mutex
	release chan struct{}
	entered int
	signed  []string
}

func (s *heldSigner) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.release = make(chan struct{})
}

func (s *heldSigner) open() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.release)
}

func (s *heldSigner) Sign(ctx context.Context, _, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signed = append(s.signed, path)
	return nil
}

func (s *heldSigner) Check(ctx context.Context, _ runtimev1.SignaturePolicy, path string) error {
	if !strings.Contains(path, "/bin/") {
		return nil
	}
	s.mu.Lock()
	s.entered++
	release := s.release
	done := slices.Contains(s.signed, path)
	s.mu.Unlock()
	if done {
		return nil
	}
	select {
	case <-release:
	case <-ctx.Done():
	}
	return fmt.Errorf("%w: %s is unsigned", image.ErrSignatureRejected, path)
}

func (s *heldSigner) counts() (entered, signed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entered, len(s.signed)
}

// heldExec is one exec session running against a heldSigner.
type heldExec struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	exit   *runtimev1.ExecResult
}

// startHeldExec starts one session. Everything it blocks on is made here, inside
// the caller's synctest bubble, so synctest.Wait sees it as durably blocked.
func startHeldExec(p *execArgvPod, cmdv ...string) *heldExec {
	ctx, cancel := context.WithCancel(context.Background())
	e := &heldExec{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(e.done)
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: p.podID, Command: cmdv})
		st.closeSend()
		e.err = p.rt.Exec(st)
		for {
			select {
			case resp := <-st.out:
				if ex := resp.GetExit(); ex != nil {
					e.exit = ex
				}
			default:
				return
			}
		}
	}()
	return e
}

func (e *heldExec) wait(t *testing.T) {
	t.Helper()
	<-e.done
	e.cancel()
}

func (e *heldExec) wantRan(t *testing.T) {
	t.Helper()
	e.wait(t)
	if e.err != nil {
		t.Errorf("Exec: %v", e.err)
	} else if e.exit == nil || e.exit.GetExitCode() != 0 {
		t.Errorf("exit = %v, want 0", e.exit)
	}
}

// TestConcurrentExecsShareOneGate pins that sessions arriving together cost one
// run of the gate: under ADHOC_OK that run copies a pod-written file, signs it and
// flushes it in the daemon. Only sessions that overlap share: a later session gates
// the file again, because the pod can have changed it.
func TestConcurrentExecsShareOneGate(t *testing.T) {
	const sessions = 8
	tree := map[string]string{"bin/tool": imageScript, "bin/other": imageScript}
	require := func(box *runtimev1.PodBox) {
		box.SignaturePolicy = runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED
	}

	t.Run("overlapping_sessions_run_one_gate", func(t *testing.T) {
		signer := &heldSigner{}
		p := newExecArgvPod(t, tree, signer, nil)
		synctest.Test(t, func(t *testing.T) {
			signer.arm()
			var execs []*heldExec
			for range sessions {
				execs = append(execs, startHeldExec(p, "/bin/tool"))
			}
			synctest.Wait()
			if entered, _ := signer.counts(); entered != 1 {
				t.Errorf("%d gates ran for %d overlapping sessions, want 1", entered, sessions)
			}
			signer.open()
			for _, e := range execs {
				e.wantRan(t)
			}
			if _, signed := signer.counts(); signed != 1 {
				t.Errorf("signed %d times, want 1", signed)
			}

			before, _ := signer.counts()
			startHeldExec(p, "/bin/tool").wantRan(t)
			if after, _ := signer.counts(); after != before+1 {
				t.Errorf("a later session ran %d checks, want 1: an old answer must not be reused", after-before)
			}
		})
	})

	t.Run("a_refusal_reaches_every_session_without_the_host_path", func(t *testing.T) {
		signer := &heldSigner{}
		p := newExecArgvPod(t, tree, signer, require)
		synctest.Test(t, func(t *testing.T) {
			signer.arm()
			var execs []*heldExec
			for range sessions {
				execs = append(execs, startHeldExec(p, "/bin/tool"))
			}
			synctest.Wait()
			if entered, _ := signer.counts(); entered != 1 {
				t.Errorf("%d gates ran, want 1", entered)
			}
			signer.open()
			for _, e := range execs {
				e.wait(t)
				if status.Code(e.err) != codes.FailedPrecondition {
					t.Errorf("Exec error = %v, want FailedPrecondition", e.err)
				}
				if msg := status.Convert(e.err).Message(); strings.Contains(msg, p.rt.cfg.Root) {
					t.Errorf("message %q shows a host path", msg)
				}
			}
		})
	})

	t.Run("a_canceled_leader_hands_the_gate_to_a_waiter", func(t *testing.T) {
		signer := &heldSigner{}
		p := newExecArgvPod(t, tree, signer, nil)
		synctest.Test(t, func(t *testing.T) {
			signer.arm()
			leader := startHeldExec(p, "/bin/tool")
			synctest.Wait()
			waiter := startHeldExec(p, "/bin/tool")
			synctest.Wait()
			if entered, _ := signer.counts(); entered != 1 {
				t.Errorf("%d gates ran before the cancel, want 1", entered)
			}

			leader.cancel()
			leader.wait(t)
			if status.Code(leader.err) != codes.Canceled {
				t.Errorf("the canceled session's error = %v, want Canceled", leader.err)
			}
			synctest.Wait()
			if entered, _ := signer.counts(); entered != 2 {
				t.Errorf("%d gates ran after the cancel, want 2: the waiter runs its own", entered)
			}
			signer.open()
			waiter.wantRan(t)
		})
	})

	t.Run("a_canceled_waiter_leaves_the_gate_running", func(t *testing.T) {
		signer := &heldSigner{}
		p := newExecArgvPod(t, tree, signer, nil)
		synctest.Test(t, func(t *testing.T) {
			signer.arm()
			leader := startHeldExec(p, "/bin/tool")
			synctest.Wait()
			waiter := startHeldExec(p, "/bin/tool")
			synctest.Wait()

			waiter.cancel()
			waiter.wait(t)
			if status.Code(waiter.err) != codes.Canceled {
				t.Errorf("the canceled waiter's error = %v, want Canceled", waiter.err)
			}
			signer.open()
			leader.wantRan(t)
			if _, signed := signer.counts(); signed != 1 {
				t.Errorf("signed %d times, want 1", signed)
			}
		})
	})

	t.Run("different_paths_do_not_share", func(t *testing.T) {
		signer := &heldSigner{}
		p := newExecArgvPod(t, tree, signer, nil)
		synctest.Test(t, func(t *testing.T) {
			signer.arm()
			one, other := startHeldExec(p, "/bin/tool"), startHeldExec(p, "/bin/other")
			synctest.Wait()
			if entered, _ := signer.counts(); entered != 2 {
				t.Errorf("%d gates ran for two paths, want 2", entered)
			}
			signer.open()
			one.wantRan(t)
			other.wantRan(t)
		})
	})
}
