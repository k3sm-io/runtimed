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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// orderedSigner records the ORDER of Sign/Check calls so a test can assert the
// policy gate runs in the right sequence relative to the ad-hoc-sign step (M2.6).
type orderedSigner struct {
	mu       sync.Mutex
	calls    []string
	checkErr error
}

func (s *orderedSigner) Sign(context.Context, string) error {
	s.mu.Lock()
	s.calls = append(s.calls, "sign")
	s.mu.Unlock()
	return nil
}

func (s *orderedSigner) Check(_ context.Context, policy runtimev1.SignaturePolicy, _ string) error {
	s.mu.Lock()
	s.calls = append(s.calls, "check")
	s.mu.Unlock()
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		return image.ErrPolicyUnspecified
	}
	return s.checkErr
}

func (s *orderedSigner) seq() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

// TestGateSignatureOrdering is the M2.6-d2 proof on a fake signer: the signature
// policy is enforced BEFORE (and instead of) ad-hoc signing for require-* policies
// (no silent downgrade), while adhoc-ok signs then checks.
func TestGateSignatureOrdering(t *testing.T) {
	cases := []struct {
		name       string
		policy     runtimev1.SignaturePolicy
		hostBinary bool
		checkErr   error
		wantSeq    []string
		wantErr    bool
	}{
		{
			name:    "adhoc-ok-signs-then-checks",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			wantSeq: []string{"sign", "check"},
		},
		{
			// A host binary (native pod / host path) is already signed + read-only:
			// verify only, NEVER ad-hoc re-sign — even under the ADHOC_OK policy.
			// This is the fix for `codesign -s - -f /bin/sh` failing on a SIP binary.
			name:       "adhoc-ok-host-binary-checks-without-signing",
			policy:     runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			hostBinary: true,
			wantSeq:    []string{"check"},
		},
		{
			name:    "require-signed-checks-without-signing",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			wantSeq: []string{"check"},
		},
		{
			name:     "require-notarized-rejects-before-any-sign",
			policy:   runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED,
			checkErr: image.ErrSignatureRejected,
			wantSeq:  []string{"check"},
			wantErr:  true,
		},
		{
			name:    "unspecified-fails-closed-without-signing",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED,
			wantSeq: []string{"check"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := &orderedSigner{checkErr: tc.checkErr}
			rt := newTestRuntime(t, Deps{Signer: signer})
			err := rt.gateSignature(context.Background(), tc.policy, "/fake/bin", tc.hostBinary)
			if (err != nil) != tc.wantErr {
				t.Fatalf("gateSignature err = %v, wantErr = %v", err, tc.wantErr)
			}
			got := signer.seq()
			if strings.Join(got, ",") != strings.Join(tc.wantSeq, ",") {
				t.Errorf("call order = %v, want %v", got, tc.wantSeq)
			}
			// The load-bearing invariant: require-* / unspecified / any host binary
			// never ad-hoc sign (silent downgrade / re-signing a signed host binary).
			if tc.policy != runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK || tc.hostBinary {
				for _, c := range got {
					if c == "sign" {
						t.Errorf("policy %v hostBinary %v must NOT ad-hoc sign", tc.policy, tc.hostBinary)
					}
				}
			}
		})
	}
}

// fakeCredentialResolver returns a fixed credential and records what it was asked
// to resolve (the CredentialResolver seam).
type fakeCredentialResolver struct {
	cred       *image.RegistryCredential
	gotNS      string
	gotSecrets []*runtimev1.LocalObjectReference
}

func (f *fakeCredentialResolver) PullCredential(_ context.Context, ns string, secrets []*runtimev1.LocalObjectReference, _ string) (*image.RegistryCredential, bool, error) {
	f.gotNS = ns
	f.gotSecrets = secrets
	if f.cred == nil {
		return nil, false, nil
	}
	return f.cred, true, nil
}

// TestCreatePodImagePullSecretConfinedToPuller is the M2.6-d1 proof: the
// imagePullSecret credential reaches the pull client and is NEVER written into the
// pod dir / materialized filesystem.
func TestCreatePodImagePullSecretConfinedToPuller(t *testing.T) {
	const secret = "topsecret-REGISTRY-PASSWORD"
	dataVol := t.TempDir()
	w := newBlockingWaiter()
	pull := &fakePuller{}
	resolver := &fakeCredentialResolver{cred: &image.RegistryCredential{Username: "robot", Password: secret}}
	rt := newTestRuntime(t, Deps{Waiter: w, Puller: pull, Credentials: resolver})

	box := &runtimev1.PodBox{
		PodId:           "pod-pull",
		Namespace:       "team-a",
		Name:            "p",
		RootfsPath:      dataVol,
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: dataVol},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		ImagePullSecrets: []*runtimev1.LocalObjectReference{
			{Name: "regcred"},
		},
		Containers: []*runtimev1.Container{{
			Name:    "main",
			Image:   "registry.example.com/private/app:v1",
			Command: []string{"/app/server"}, // command set → the image is pulled
		}},
	}
	mustCreatePod(t, rt, box)

	// (1) the credential reached the pull client.
	got := pull.credential()
	if got == nil || got.Username != "robot" || got.Password != secret {
		t.Fatalf("puller credential = %+v, want robot/<secret>", got)
	}
	// the resolver was asked with the pod's namespace + imagePullSecret refs.
	if resolver.gotNS != "team-a" || len(resolver.gotSecrets) != 1 || resolver.gotSecrets[0].GetName() != "regcred" {
		t.Errorf("resolver got ns=%q secrets=%v", resolver.gotNS, resolver.gotSecrets)
	}
	// (1b) B99: the host-process spine pulls under a NATIVE platform policy, so a
	// multi-platform image resolves to darwin/arm64 and never to
	// go-containerregistry's implicit linux/amd64 default. This runs through the
	// REAL createPod, so it also proves the wiring the unit test cannot: the
	// backend sandbox.SelectBackend resolved is what reached the puller (an
	// unset pod.backend would arrive as UNSPECIFIED, which has no candidates).
	pol := pull.policy()
	if pol.Backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC {
		t.Errorf("pull policy backend = %v, want the resolved SEATBELT_INPROC rung", pol.Backend)
	}
	cands, err := image.Candidates(pol)
	if err != nil {
		t.Fatalf("pull policy has no candidates: %v", err)
	}
	if len(cands) != 1 || cands[0].OS != "darwin" || cands[0].Architecture != "arm64" {
		t.Errorf("pull policy candidates = %v, want [darwin/arm64/v8]", cands)
	}

	// (2) the credential is NOWHERE on disk in the pod dir.
	assertSecretNotOnDisk(t, dataVol, secret)
	assertSecretNotOnDisk(t, dataVol, "robot")

	w.release(1001)
}

// assertSecretNotOnDisk fails if any file under root contains secret.
func assertSecretNotOnDisk(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("credential leaked to disk: %q contains %q", path, secret)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk pod dir: %v", err)
	}
}
