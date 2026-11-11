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
			var warns []string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "TOOL-OUTPUT") {
					warns = append(warns, line)
				}
			}
			if len(warns) != 1 {
				t.Fatalf("the full gate error was logged %d times, want once:\n%s", len(warns), out)
			}
			if !strings.Contains(warns[0], "level=WARN") {
				t.Errorf("gate error logged as %q, want level=WARN", warns[0])
			}
			for _, want := range append([]string{hostPath}, tc.wantLogs...) {
				if !strings.Contains(warns[0], want) {
					t.Errorf("daemon log line %q lacks %q", warns[0], want)
				}
			}
		})
	}
}
