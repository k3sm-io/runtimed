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

package image

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// testToolTimeout is the shortened check and sign deadline these tests run
// under; slack is how far past it a call may return and still count as bounded.
const (
	testToolTimeout = 200 * time.Millisecond
	slack           = 3 * time.Second
)

// toolStub replaces the command seam for one test. Every invocation is recorded
// by tool name and turned into the command stub returns, so no test here ever
// runs the real codesign or spctl.
type toolStub struct {
	mu    sync.Mutex
	calls []string
}

func (s *toolStub) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// stubTools points commandContext at stub and shortens the deadlines, restoring
// all of it when the test ends.
func stubTools(t *testing.T, stub func(ctx context.Context) *exec.Cmd) *toolStub {
	t.Helper()
	rec := &toolStub{}
	oldCmd, oldCheck, oldSign, oldWait := commandContext, checkTimeout, signTimeout, toolWaitDelay
	commandContext = func(ctx context.Context, name string, _ ...string) *exec.Cmd {
		rec.mu.Lock()
		rec.calls = append(rec.calls, name)
		rec.mu.Unlock()
		return stub(ctx)
	}
	checkTimeout, signTimeout, toolWaitDelay = testToolTimeout, testToolTimeout, 200*time.Millisecond
	t.Cleanup(func() {
		commandContext, checkTimeout, signTimeout, toolWaitDelay = oldCmd, oldCheck, oldSign, oldWait
	})
	return rec
}

// sleeper is a stub tool that never answers within the test deadline.
func sleeper(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sleep", "30")
}

// pipeHolder is a stub whose own child outlives it holding the output pipe: the
// shell forks sleep (the trailing ":" stops it exec'ing sleep in place), so
// killing the shell leaves the pipe open and only WaitDelay ends the Wait.
func pipeHolder(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", "-c", "/bin/sleep 10; :")
}

// assertTimeout fails unless err is the timeout sentinel and the call returned
// within the deadline plus slack.
func assertTimeout(t *testing.T, err error, elapsed time.Duration) {
	t.Helper()
	if !errors.Is(err, ErrSignatureCheckTimeout) {
		t.Fatalf("err = %v, want ErrSignatureCheckTimeout", err)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		t.Errorf("timeout error exposes an *exec.ExitError (%v); a killed tool must not read as an exit verdict", ee)
	}
	if elapsed > testToolTimeout+slack {
		t.Errorf("returned after %s, want within %s", elapsed, testToolTimeout+slack)
	}
}

// TestSignatureToolTimeoutEveryMapper drives each verdict mapper through the
// real wrapper with a tool that sleeps past its deadline: every one returns the
// timeout sentinel, never a false verdict with a nil error.
func TestSignatureToolTimeoutEveryMapper(t *testing.T) {
	mappers := []struct {
		name string
		run  func(ctx context.Context) (bool, error)
	}{
		{"signed", func(ctx context.Context) (bool, error) { return CodesignTool{}.Signed(ctx, "/x") }},
		{"adhoc", func(ctx context.Context) (bool, error) { return CodesignTool{}.AdHoc(ctx, "/x") }},
		{"notarized", func(ctx context.Context) (bool, error) { return CodesignTool{}.Notarized(ctx, "/x") }},
		{"verify-arch", func(ctx context.Context) (bool, error) {
			return CodesignTreeSigner{}.VerifyArch(ctx, "/x", "arm64")
		}},
	}
	for _, m := range mappers {
		t.Run(m.name, func(t *testing.T) {
			stubTools(t, sleeper)
			start := time.Now()
			ok, err := m.run(context.Background())
			assertTimeout(t, err, time.Since(start))
			if ok {
				t.Errorf("verdict = true on a timeout")
			}
		})
	}
}

// TestSignatureToolTimeoutSign covers both signing entry points: each runs under
// the per-file sign deadline and reports the sentinel.
func TestSignatureToolTimeoutSign(t *testing.T) {
	signers := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"adhoc-sign", func(ctx context.Context) error { return AdHocSign(ctx, "/x") }},
		{"codesign-as", func(ctx context.Context) error { return codesignAs(ctx, "/x", "x") }},
	}
	for _, s := range signers {
		t.Run(s.name, func(t *testing.T) {
			stubTools(t, sleeper)
			start := time.Now()
			err := s.run(context.Background())
			assertTimeout(t, err, time.Since(start))
		})
	}
}

// TestSignatureToolWrapperKillsPipeHolder runs the real wrapper with output
// captured and a stub whose grandchild keeps the pipe: cmd.Cancel kills the
// child and cmd.WaitDelay stops Wait from blocking on the pipe.
func TestSignatureToolWrapperKillsPipeHolder(t *testing.T) {
	stubTools(t, pipeHolder)
	start := time.Now()
	_, err := CodesignTool{}.AdHoc(context.Background(), "/x") // AdHoc captures stderr
	assertTimeout(t, err, time.Since(start))
}

// TestSignatureToolParentCancelIsNotTimeout pins the order of the test: a
// cancelled caller context is reported as that cancellation, not as the
// timeout sentinel, and not as a verdict either.
func TestSignatureToolParentCancelIsNotTimeout(t *testing.T) {
	stubTools(t, sleeper)
	checkTimeout = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	ok, err := CodesignTool{}.Signed(ctx, "/x")
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("Signed = %v, %v; want false, context.Canceled", ok, err)
	}
	if errors.Is(err, ErrSignatureCheckTimeout) {
		t.Errorf("a parent cancel read as the timeout sentinel: %v", err)
	}
	if time.Since(start) > slack {
		t.Errorf("cancel took %s to stop the tool", time.Since(start))
	}
}

// TestSignatureToolExitStillMapsToUnsigned keeps the ordinary mapping: a tool
// that answers with a non-zero exit inside its deadline is "not signed", nil.
func TestSignatureToolExitStillMapsToUnsigned(t *testing.T) {
	stubTools(t, func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, "/usr/bin/false") })
	ok, err := CodesignTool{}.Signed(context.Background(), "/x")
	if ok || err != nil {
		t.Fatalf("Signed = %v, %v; want false, nil", ok, err)
	}
}

// TestAdHocSignTreeCheckTimeoutFailsWithoutSigning runs the tree path with the
// production signer over a one-Mach-O tree and a hung tool: the walk fails with
// the sentinel after ONE verify, and no codesign sign is ever started.
func TestAdHocSignTreeCheckTimeoutFailsWithoutSigning(t *testing.T) {
	rec := stubTools(t, sleeper)
	root := t.TempDir()
	thin := []byte{0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01} // thin 64-bit Mach-O, little-endian
	bin := filepath.Join(root, "bin")
	if err := os.WriteFile(bin, thin, 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	stats, err := AdHocSignTree(context.Background(), CodesignTreeSigner{}, runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, root)
	assertTimeout(t, err, time.Since(start))
	if stats.Signed != 0 {
		t.Errorf("Signed = %d after a check timeout, want 0", stats.Signed)
	}
	if got := rec.names(); len(got) != 1 {
		t.Errorf("tool invocations = %v, want exactly one verify and no sign", got)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(thin) {
		t.Errorf("tree file changed after a check timeout")
	}
}
