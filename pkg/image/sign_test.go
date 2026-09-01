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
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeInspector is a table-driven SignatureInspector for policy unit tests.
type fakeInspector struct {
	signed, adhoc, notarized bool
	err                      error
}

func (f fakeInspector) Signed(context.Context, string) (bool, error) {
	return f.signed, f.err
}
func (f fakeInspector) AdHoc(context.Context, string) (bool, error) {
	return f.adhoc, f.err
}
func (f fakeInspector) Notarized(context.Context, string) (bool, error) {
	return f.notarized, f.err
}

// TestCheckSignaturePolicy is the decision table for the gate, including the
// fail-closed UNSPECIFIED case (acceptance support for M1.1-a3's reject half and
// the apis fail-closed contract).
func TestCheckSignaturePolicy(t *testing.T) {
	const bin = "/var/lib/k3sm/pods/p/rootfs/app"
	cases := []struct {
		name    string
		policy  runtimev1.SignaturePolicy
		insp    fakeInspector
		wantErr error
	}{
		// fail-closed: unspecified policy always refuses.
		{
			name:    "unspecified-fails-closed",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED,
			insp:    fakeInspector{signed: true, notarized: true},
			wantErr: ErrPolicyUnspecified,
		},
		// ADHOC_OK: any valid signature (incl. ad-hoc) passes.
		{
			name:   "adhoc-ok-adhoc-passes",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			insp:   fakeInspector{signed: true, adhoc: true},
		},
		{
			name:    "adhoc-ok-unsigned-rejected",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			insp:    fakeInspector{signed: false},
			wantErr: ErrSignatureRejected,
		},
		// REQUIRE_SIGNED: needs a real (non-ad-hoc) authority.
		{
			name:   "require-signed-real-passes",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			insp:   fakeInspector{signed: true, adhoc: false},
		},
		{
			name:    "require-signed-adhoc-rejected",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			insp:    fakeInspector{signed: true, adhoc: true},
			wantErr: ErrSignatureRejected,
		},
		{
			name:    "require-signed-unsigned-rejected",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			insp:    fakeInspector{signed: false},
			wantErr: ErrSignatureRejected,
		},
		// REQUIRE_NOTARIZED: needs Gatekeeper assessment.
		{
			name:   "require-notarized-passes",
			policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED,
			insp:   fakeInspector{signed: true, notarized: true},
		},
		{
			name:    "require-notarized-not-notarized-rejected",
			policy:  runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED,
			insp:    fakeInspector{signed: true, notarized: false},
			wantErr: ErrSignatureRejected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSignaturePolicy(context.Background(), tc.insp, tc.policy, bin)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("want nil, got %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestCheckSignaturePolicyInspectError surfaces inspector errors (not silently
// treated as a pass).
func TestCheckSignaturePolicyInspectError(t *testing.T) {
	boom := errors.New("codesign exploded")
	err := CheckSignaturePolicy(context.Background(),
		fakeInspector{err: boom},
		runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, "/x")
	if !errors.Is(err, boom) {
		t.Fatalf("want wrapped inspector error, got %v", err)
	}
}

// TestUnknownPolicyFailsClosed ensures a future/unknown enum value fails closed.
func TestUnknownPolicyFailsClosed(t *testing.T) {
	err := CheckSignaturePolicy(context.Background(),
		fakeInspector{signed: true, notarized: true},
		runtimev1.SignaturePolicy(99), "/x")
	if !errors.Is(err, ErrPolicyUnspecified) {
		t.Fatalf("want fail-closed for unknown policy, got %v", err)
	}
}
