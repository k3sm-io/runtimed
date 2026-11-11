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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// scriptedSigner answers Check and Sign with the errors its funcs build from
// the host path it was handed, so a test can plant the host path, a staging
// path and tool output in the gate's error.
type scriptedSigner struct {
	check func(path string) error
	sign  func(path string) error
}

func (s *scriptedSigner) Check(_ context.Context, _ runtimev1.SignaturePolicy, path string) error {
	return s.check(path)
}

func (s *scriptedSigner) Sign(_ context.Context, _, path string) error {
	if s.sign == nil {
		return nil
	}
	return s.sign(path)
}

// TestSignatureFailureMessageHidesHostPaths pins what a pod is told when the
// signature gate fails its container's start: a fixed sentence naming only the
// program as the pod wrote it. The cache root, the sign staging directory and
// the signature tool's output stay in the daemon's Warn line, which carries
// the full error once.
func TestSignatureFailureMessageHidesHostPaths(t *testing.T) {
	const (
		program  = "/bin/app"
		toolOut  = "TOOL-OUTPUT: the codesign_allocate helper tool cannot be found or used"
		podID    = "pod-sig-msg"
		imageRef = "example.test/app:v1"
	)
	staging := filepath.Join(t.TempDir(), ".sign-staging", "app.k3sm-sign-123456")

	cases := []struct {
		name     string
		policy   runtimev1.SignaturePolicy
		signer   *scriptedSigner
		reason   runtimev1.FailureReason
		wantMsg  string
		wantLogs []string // beyond the host path, which every case logs
	}{
		{
			name:   "rejected",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			signer: &scriptedSigner{check: func(path string) error {
				return fmt.Errorf("%w: %s is unsigned (require-signed): %s", image.ErrSignatureRejected, path, toolOut)
			}},
			reason:   runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED,
			wantMsg:  "rejected",
			wantLogs: []string{toolOut},
		},
		{
			name:   "timed-out",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			signer: &scriptedSigner{check: func(path string) error {
				return fmt.Errorf("%w after 30s: codesign -v %s: %s", image.ErrSignatureCheckTimeout, path, toolOut)
			}},
			reason:   runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			wantMsg:  "may be retried",
			wantLogs: []string{toolOut},
		},
		{
			name:   "sign-failed",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			signer: &scriptedSigner{
				check: func(path string) error {
					return fmt.Errorf("%w: %s is unsigned (adhoc-ok requires a signature)", image.ErrSignatureRejected, path)
				},
				sign: func(string) error {
					// runSign's shape: the staged copy, the exit status, the tool's output.
					return fmt.Errorf("ad-hoc sign %s: exit status 1: %s", staging, toolOut)
				},
			},
			reason:   runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED,
			wantMsg:  "ad-hoc sign",
			wantLogs: []string{staging, toolOut},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Signer:  tc.signer,
				Spawner: &fakeSpawner{},
				Puller: &fakePuller{
					manifest:   &runtimev1.ImageManifest{Reference: imageRef, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
					descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
				},
				Unpacker: &treeUnpacker{
					files:  map[string]string{"bin/app": "unsigned-mach-o"},
					runCfg: image.ImageRunConfig{Entrypoint: []string{program}},
				},
			})
			box := hostBinBox(rt, podID)
			box.SignaturePolicy = tc.policy
			box.Containers = []*runtimev1.Container{{Name: "main", Image: imageRef}}
			hostPath := filepath.Join(derivedRootfs(t, rt, podID), "bin", "app")

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed %v; a gate failure is container-class", resp.GetError())
			}
			w := statusNamed(t, rt, podID, "main").GetState().GetWaiting()
			if w == nil {
				t.Fatal("container is not Waiting after a failed signature gate")
			}
			if got := w.GetFailureReason(); got != tc.reason {
				t.Errorf("failure_reason = %v, want %v", got, tc.reason)
			}
			msg := w.GetMessage()
			for _, leak := range []string{rt.cache.Root(), hostPath, filepath.Dir(staging), "TOOL-OUTPUT"} {
				if strings.Contains(msg, leak) {
					t.Errorf("waiting message %q carries %q", msg, leak)
				}
			}
			if !strings.Contains(msg, program) || !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("waiting message %q, want the fixed %q sentence naming %q", msg, tc.wantMsg, program)
			}

			out := logs.String()
			assertGateErrorLoggedOnce(t, out, "level=WARN", append([]string{hostPath}, tc.wantLogs...))

			// StartContainer re-attempts the same gate; its reply must say what
			// the waiting message says, not the error the log line carries.
			sresp, err := rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: podID, Container: "main"})
			if err != nil {
				t.Fatal(err)
			}
			if sresp.GetError() == nil {
				t.Fatal("StartContainer succeeded through a failing signature gate")
			}
			assertNoHostPaths(t, "StartContainer error", sresp.GetError().GetMessage(),
				podID+"/main", program, tc.wantMsg, rt.cache.Root(), hostPath, filepath.Dir(staging))
		})
	}
}

// assertNoHostPaths fails t when msg carries any leak (or the tool output
// sentinel) or lacks any of prefix, program and sentence.
func assertNoHostPaths(t *testing.T, what, msg, prefix, program, sentence string, leaks ...string) {
	t.Helper()
	for _, leak := range append(leaks, "TOOL-OUTPUT") {
		if strings.Contains(msg, leak) {
			t.Errorf("%s %q carries %q", what, msg, leak)
		}
	}
	for _, want := range []string{prefix, program, sentence} {
		if !strings.Contains(msg, want) {
			t.Errorf("%s %q lacks %q", what, msg, want)
		}
	}
}

// assertGateErrorLoggedOnce fails t unless exactly one line of out carries the
// tool output sentinel, at level, holding every one of wants.
func assertGateErrorLoggedOnce(t *testing.T, out, level string, wants []string) {
	t.Helper()
	var warns []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "TOOL-OUTPUT") {
			warns = append(warns, line)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("the full gate error was logged %d times, want once:\n%s", len(warns), out)
	}
	if !strings.Contains(warns[0], level) {
		t.Errorf("gate error logged as %q, want %s", warns[0], level)
	}
	for _, want := range wants {
		if !strings.Contains(warns[0], want) {
			t.Errorf("daemon log line %q lacks %q", warns[0], want)
		}
	}
}

// TestSignatureFailureMessageHidesHostPathsOnRestart pins the same rule on
// RestartContainer: when the replacement instance fails the signature gate, the
// reply carries the gate's fixed sentence, and the full error — host path,
// staging directory, tool output — is logged once, at Error, by the daemon.
func TestSignatureFailureMessageHidesHostPathsOnRestart(t *testing.T) {
	const (
		program  = "/bin/app"
		toolOut  = "TOOL-OUTPUT: the codesign_allocate helper tool cannot be found or used"
		podID    = "pod-sig-restart"
		imageRef = "example.test/app:v1"
	)
	staging := filepath.Join(t.TempDir(), ".sign-staging", "app.k3sm-sign-654321")

	cases := []struct {
		name     string
		policy   runtimev1.SignaturePolicy
		check    func(path string) error
		sign     func(path string) error
		wantMsg  string
		wantLogs []string
	}{
		{
			name:   "rejected",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			check: func(path string) error {
				return fmt.Errorf("%w: %s is unsigned (require-signed): %s", image.ErrSignatureRejected, path, toolOut)
			},
			wantMsg:  "rejected",
			wantLogs: []string{toolOut},
		},
		{
			name:   "sign-failed",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			check: func(path string) error {
				return fmt.Errorf("%w: %s is unsigned (adhoc-ok requires a signature)", image.ErrSignatureRejected, path)
			},
			sign: func(string) error {
				return fmt.Errorf("ad-hoc sign %s: exit status 1: %s", staging, toolOut)
			},
			wantMsg:  "ad-hoc sign",
			wantLogs: []string{staging, toolOut},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The first instance passes the gate; the replacement does not.
			var failing atomic.Bool
			signer := &scriptedSigner{
				check: func(path string) error {
					if !failing.Load() {
						return nil
					}
					return tc.check(path)
				},
				sign: tc.sign,
			}
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			w := newBlockingWaiter()
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Signer:  signer,
				Spawner: &fakeSpawner{},
				Waiter:  w,
				Puller: &fakePuller{
					manifest:   &runtimev1.ImageManifest{Reference: imageRef, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
					descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
				},
				Unpacker: &treeUnpacker{
					files:  map[string]string{"bin/app": "unsigned-mach-o"},
					runCfg: image.ImageRunConfig{Entrypoint: []string{program}},
				},
			})
			box := hostBinBox(rt, podID)
			box.SignaturePolicy = tc.policy
			box.Containers = []*runtimev1.Container{{Name: "main", Image: imageRef}}
			hostPath := filepath.Join(derivedRootfs(t, rt, podID), "bin", "app")

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed: %v", resp.GetError())
			}

			failing.Store(true)
			go w.release(1001) // the old instance exits when RestartContainer stops it
			rresp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
			if err != nil {
				t.Fatal(err)
			}
			if rresp.GetError() == nil {
				t.Fatal("RestartContainer succeeded through a failing signature gate")
			}
			assertNoHostPaths(t, "RestartContainer error", rresp.GetError().GetMessage(),
				podID+"/main", program, tc.wantMsg, rt.cache.Root(), hostPath, filepath.Dir(staging))
			assertGateErrorLoggedOnce(t, logs.String(), "level=ERROR", append([]string{hostPath}, tc.wantLogs...))
		})
	}
}
