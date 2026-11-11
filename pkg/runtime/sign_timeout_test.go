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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// hungSigner stands in for a signer whose tools hang on a dead system policy
// daemon: every call blocks until its context ends and returns that context's
// error. Sign calls are counted so a test can prove none was made.
type hungSigner struct {
	signs  atomic.Int32
	checks atomic.Int32
}

func (s *hungSigner) Sign(ctx context.Context, _, _ string) error {
	s.signs.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func (s *hungSigner) Check(ctx context.Context, _ runtimev1.SignaturePolicy, _ string) error {
	s.checks.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

// hungSignSigner answers Check at once with a plain "unsigned" verdict (an
// error that is neither a timeout nor a cancellation) and hangs in Sign until
// its context ends. Both are counted.
type hungSignSigner struct {
	signs  atomic.Int32
	checks atomic.Int32
}

var errUnsigned = errors.New("code object is not signed at all")

func (s *hungSignSigner) Sign(ctx context.Context, _, _ string) error {
	s.signs.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func (s *hungSignSigner) Check(context.Context, runtimev1.SignaturePolicy, string) error {
	s.checks.Add(1)
	return errUnsigned
}

// shortenSignatureTimeouts sets the gate's deadlines for one test.
func shortenSignatureTimeouts(t *testing.T, check, sign time.Duration) {
	t.Helper()
	oldCheck, oldSign := signatureCheckTimeout, signatureSignTimeout
	signatureCheckTimeout, signatureSignTimeout = check, sign
	t.Cleanup(func() { signatureCheckTimeout, signatureSignTimeout = oldCheck, oldSign })
}

// TestGateSignatureHungSignerFailsClosedWithinTimeout pins the gate's behavior
// when the signature tools hang: the start returns within the check deadline
// with image.ErrSignatureCheckTimeout, reported as the retryable IMAGE_PULL
// rather than SIGNATURE_REJECTED; under ADHOC_OK no Sign is attempted and the
// target is untouched; under both require policies the start fails; and a
// cancelled caller is reported as a cancellation, not as the timeout.
func TestGateSignatureHungSignerFailsClosedWithinTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	// The sign deadline is long, so a check bounded by it fails the elapsed bound.
	const longTimeout = 10 * time.Second
	const slack = 3 * time.Second

	t.Run("adhoc-ok-no-sign-target-unchanged", func(t *testing.T) {
		shortenSignatureTimeouts(t, timeout, longTimeout)
		signer := &hungSigner{}
		rt := newTestRuntime(t, Deps{Signer: signer})
		rootfs := t.TempDir()
		target := filepath.Join(rootfs, "app")
		const content = "unsigned-mach-o-bytes"
		if err := os.WriteFile(target, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err := rt.gateSignature(context.Background(), runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, rootfs, target, false)
		elapsed := time.Since(start)
		if !errors.Is(err, image.ErrSignatureCheckTimeout) {
			t.Fatalf("gateSignature err = %v, want ErrSignatureCheckTimeout", err)
		}
		if elapsed > timeout+slack {
			t.Errorf("gate returned after %s, want within %s", elapsed, timeout+slack)
		}
		if got := signatureFailureReason(err); got != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
			t.Errorf("failure reason = %v, want IMAGE_PULL (retryable), never SIGNATURE_REJECTED", got)
		}
		if n := signer.signs.Load(); n != 0 {
			t.Errorf("Sign called %d times after a check timeout, want 0", n)
		}
		if n := signer.checks.Load(); n != 1 {
			t.Errorf("Check called %d times, want 1 (no re-check after a timeout)", n)
		}
		b, rerr := os.ReadFile(target)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(b) != content {
			t.Errorf("target bytes changed after a check timeout")
		}
	})

	for _, policy := range []runtimev1.SignaturePolicy{
		runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
		runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			shortenSignatureTimeouts(t, timeout, longTimeout)
			podID := "pod-sig-hung"
			signer := &hungSigner{}
			sp := &fakeSpawner{}
			rt := newTestRuntime(t, Deps{Signer: signer, Spawner: sp})
			box := hostBinBox(rt, podID)
			box.SignaturePolicy = policy
			start := time.Now()
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed %v; a gate failure is container-class", resp.GetError())
			}
			if elapsed > timeout+slack {
				t.Errorf("start returned after %s, want within %s", elapsed, timeout+slack)
			}
			w := statusNamed(t, rt, podID, "main").GetState().GetWaiting()
			if w == nil {
				t.Fatalf("container is not Waiting; a hung check must fail the start")
			}
			if got := w.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
				t.Errorf("waiting failure_reason = %v, want IMAGE_PULL (retryable), never SIGNATURE_REJECTED", got)
			}
			sp.mu.Lock()
			spawned := len(sp.specs)
			sp.mu.Unlock()
			if spawned != 0 {
				t.Errorf("spawned %d processes past a hung check", spawned)
			}
			if n := signer.signs.Load(); n != 0 {
				t.Errorf("Sign called %d times under %v", n, policy)
			}
			// The gate itself returns an error, never nil, under this policy.
			if gerr := rt.gateSignature(context.Background(), policy, "/fake", "/fake/bin", false); !errors.Is(gerr, image.ErrSignatureCheckTimeout) {
				t.Errorf("gateSignature under %v = %v, want ErrSignatureCheckTimeout", policy, gerr)
			}
		})
	}

	t.Run("parent-cancel-is-not-the-sentinel", func(t *testing.T) {
		shortenSignatureTimeouts(t, 10*time.Second, 10*time.Second)
		signer := &hungSigner{}
		rt := newTestRuntime(t, Deps{Signer: signer})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		err := rt.gateSignature(ctx, runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, "/fake", "/fake/bin", false)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("gateSignature err = %v, want context.Canceled", err)
		}
		if errors.Is(err, image.ErrSignatureCheckTimeout) {
			t.Errorf("a parent cancel read as the timeout sentinel: %v", err)
		}
		if time.Since(start) > slack {
			t.Errorf("cancel took %s to stop the gate", time.Since(start))
		}
		if n := signer.signs.Load(); n != 0 {
			t.Errorf("Sign called %d times after a cancel, want 0", n)
		}
	})
}

// TestGateSignatureSignTimeout pins the ADHOC_OK sign path when the signer
// hangs: an "unsigned" check leads to one Sign, which is bounded by the sign
// deadline (not the much longer check deadline) and reported as the
// image.ErrSignatureCheckTimeout sentinel with the retryable IMAGE_PULL reason;
// the timed-out sign is not followed by a re-check.
func TestGateSignatureSignTimeout(t *testing.T) {
	const checkTimeout = 10 * time.Second
	const signTimeout = 400 * time.Millisecond
	const slack = 3 * time.Second
	shortenSignatureTimeouts(t, checkTimeout, signTimeout)
	signer := &hungSignSigner{}
	rt := newTestRuntime(t, Deps{Signer: signer})
	start := time.Now()
	err := rt.gateSignature(context.Background(), runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, "/fake", "/fake/bin", false)
	elapsed := time.Since(start)
	if !errors.Is(err, image.ErrSignatureCheckTimeout) {
		t.Fatalf("gateSignature err = %v, want ErrSignatureCheckTimeout", err)
	}
	if elapsed > signTimeout+slack || elapsed >= checkTimeout {
		t.Errorf("gate returned after %s, want within %s (the sign deadline, not the %s check deadline)",
			elapsed, signTimeout+slack, checkTimeout)
	}
	if got := signatureFailureReason(err); got != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
		t.Errorf("failure reason = %v, want IMAGE_PULL (retryable), never SIGNATURE_REJECTED", got)
	}
	if n := signer.signs.Load(); n != 1 {
		t.Errorf("Sign called %d times, want exactly 1", n)
	}
	if n := signer.checks.Load(); n != 1 {
		t.Errorf("Check called %d times, want 1 (no re-check after a timed-out sign)", n)
	}
}
