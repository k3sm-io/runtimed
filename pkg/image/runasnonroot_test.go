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
	"errors"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVerifyRunAsNonRootMatchesKubelet pins branch and text parity with the
// kubelet's verifyRunAsNonRoot (pkg/kubelet/kuberuntime/
// security_context_others.go) at the Kubernetes version this tree is pinned
// to. It claims parity at that version only; noticing a later kubelet change
// is the upstream-tracking sweep's job, not this table's.
//
// Each row names the kubelet branch it reproduces. The kubelet's runAsUser
// branch for an EXPLICIT 0 ("container's runAsUser breaks non-root policy") has
// no row: RunSpecRequest.RunAsUID 0 means unset, so that branch is not reachable
// on this wire.
func TestVerifyRunAsNonRootMatchesKubelet(t *testing.T) {
	const pod = `"web-0_default(0b5e3a1c-9f0e-4d1e-8a5b-3c2f7d9e1a44)"`
	base := RunSpecRequest{
		Container:    &runtimev1.Container{Name: "app"},
		PodName:      "web-0",
		PodNamespace: "default",
		PodUID:       "0b5e3a1c-9f0e-4d1e-8a5b-3c2f7d9e1a44",
	}
	cases := []struct {
		name      string
		nonRoot   bool
		runAsUID  int64
		imageUser string
		wantErr   string
	}{
		// effectiveSc.RunAsNonRoot == nil || !*effectiveSc.RunAsNonRoot -> nil
		{name: "runAsNonRoot unset allows even a root image", imageUser: "0"},
		// effectiveSc.RunAsUser != nil && *RunAsUser != 0 -> nil
		{name: "a non-zero runAsUser allows a root image", nonRoot: true, runAsUID: 1000, imageUser: "0"},
		// uid != nil && *uid == 0 -> "image will run as root"
		{name: "USER 0", nonRoot: true, imageUser: "0",
			wantErr: "container has runAsNonRoot and image will run as root (pod: " + pod + ", container: app)"},
		// the uid half of USER is what the image config reports, so 0:0 is uid 0
		{name: "USER 0:0", nonRoot: true, imageUser: "0:0",
			wantErr: "container has runAsNonRoot and image will run as root (pod: " + pod + ", container: app)"},
		// uid == nil && len(username) > 0 -> "image has non-numeric user"
		{name: "USER app", nonRoot: true, imageUser: "app",
			wantErr: "container has runAsNonRoot and image has non-numeric user (app), cannot verify user is non-root (pod: " + pod + ", container: app)"},
		// the username is the user half only, as the CRI reports it
		{name: "USER app:staff", nonRoot: true, imageUser: "app:staff",
			wantErr: "container has runAsNonRoot and image has non-numeric user (app), cannot verify user is non-root (pod: " + pod + ", container: app)"},
		// uid != nil && *uid != 0 -> falls through to the default arm -> nil
		{name: "USER 1000", nonRoot: true, imageUser: "1000"},
		// default arm: no USER at all -> nil (the verified fail-open)
		{name: "no USER allows", nonRoot: true, imageUser: ""},
		// native posture: the spine passes the pod's non-zero service uid as
		// RunAsUID, so the RunAsUser branch returns before USER is read.
		{name: "native: the service uid allows USER root", nonRoot: true, runAsUID: 501, imageUser: "root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.RunAsNonRoot, req.RunAsUID = tc.nonRoot, tc.runAsUID
			err := verifyRunAsNonRoot(tc.imageUser, req)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("allowed; want %q", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("message\n got %q\nwant %q", err.Error(), tc.wantErr)
			}
			if !errors.Is(err, ErrRunAsNonRoot) || !errors.Is(err, ErrRunSpecInvalid) {
				t.Errorf("err %v must match both ErrRunAsNonRoot and ErrRunSpecInvalid", err)
			}
		})
	}

	t.Run("the no-command refusal is not a runAsNonRoot refusal", func(t *testing.T) {
		_, err := MergeRunSpec(ImageRunConfig{}, RunSpecRequest{Container: &runtimev1.Container{Name: "app"}})
		if !errors.Is(err, ErrRunSpecInvalid) || errors.Is(err, ErrRunAsNonRoot) {
			t.Errorf("err = %v; want ErrRunSpecInvalid and not ErrRunAsNonRoot", err)
		}
	})

	t.Run("a hostile image user is bounded and quoted", func(t *testing.T) {
		req := base
		req.RunAsNonRoot = true
		// The user half ends at the first colon, as the CRI reports it.
		err := verifyRunAsNonRoot("evil\n(pod: forged)", req)
		if err == nil {
			t.Fatal("allowed")
		}
		want := `container has runAsNonRoot and image has non-numeric user ("evil\n(pod"), cannot verify user is non-root (pod: ` + pod + ", container: app)"
		if err.Error() != want {
			t.Errorf("message\n got %q\nwant %q", err.Error(), want)
		}
	})
}
