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
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// imageVolumeBox is a native pod mounting one image volume of ref at /models.
func imageVolumeBox(rt *Runtime, podID, ref string, paths ...string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:           podID,
		Namespace:       "default",
		Name:            "llm",
		LogDirectory:    filepath.Join(rt.cfg.PodLogsDir, "default_llm_"+podID),
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: filepath.Join(rt.cfg.Root, "pods", podID, "rootfs")},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Volumes: []*runtimev1.Volume{{
			Name:  "model",
			Image: &runtimev1.ImageVolumeSource{Reference: ref, Paths: paths},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			Image:        "/bin/sleep",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "model", MountPath: "/models"}},
		}},
	}
}

// TestCreatePodMountsImageVolume is the native route end to end below the
// apiserver: CreatePod fetches the artifact through the puller, builds its
// view, links the pod's mount path to it, and compiles a profile that grants
// that view read-only and no-exec.
func TestCreatePodMountsImageVolume(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("the daemon's views clone with APFS clonefile, darwin-only")
	}
	f := modelArtifact(map[string][]byte{"config.json": []byte("{}"), "w.safetensors": []byte("w")}, []string{"config.json", "w.safetensors"})
	_, rt := artifactRPCClient(t, f)
	t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
	box := imageVolumeBox(rt, "pod-model", artifactTestHost+"/models/tiny:v1")
	mustCreatePod(t, rt, box)

	link := filepath.Join(rt.cfg.Root, "pods", "pod-model", "rootfs", "models")
	view, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("the image mount is not a link: %v", err)
	}
	want, err := rt.ArtifactView(context.Background(), sha(f.manifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if view != want {
		t.Errorf("mount links to %s, want the view %s", view, want)
	}
	if b, err := os.ReadFile(filepath.Join(link, "w.safetensors")); err != nil || string(b) != "w" {
		t.Errorf("read through the mount = %q, %v", b, err)
	}
	rt.mu.Lock()
	profile := rt.pods["pod-model"].profile
	rt.mu.Unlock()
	for _, stanza := range []string{"(allow file-read*\n", "(deny process-exec* file-map-executable\n", "(deny file-write*\n"} {
		if !strings.Contains(profile, stanza+"  (subpath \""+view+"\")") {
			t.Errorf("profile lacks %q on the view %s", strings.TrimSpace(stanza), view)
		}
	}
	// The profile the attach path recompiles from the links is the same one.
	again, err := rt.boxProfile(box)
	if err != nil {
		t.Fatalf("boxProfile: %v", err)
	}
	if again != profile {
		t.Error("the attach-time profile differs from the create-time profile")
	}
}

// TestCreatePodRefusesImageVolumePaths pins the fail-closed refusal of
// a subset request: a non-empty paths fails the create with the stable
// ArtifactMountRefused reason, before any host check or fetch.
func TestCreatePodRefusesImageVolumePaths(t *testing.T) {
	ap := &scriptedArtifactPuller{}
	rt := newTestRuntime(t, Deps{ArtifactPuller: ap})
	box := imageVolumeBox(rt, "pod-subset", artifactTestHost+"/models/tiny:v1", "w.safetensors")
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if !strings.HasPrefix(resp.GetError().GetMessage(), "ArtifactMountRefused") {
		t.Errorf("error = %q, want it to begin with ArtifactMountRefused", resp.GetError().GetMessage())
	}
	if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED {
		t.Errorf("reason = %v, want UNSUPPORTED", resp.GetFailureReason())
	}
	if n := ap.hostCheckCalls.Load(); n != 0 {
		t.Errorf("the puller was consulted %d times for a refused subset", n)
	}
}

// TestCreatePodImageVolumePullRefusalReasons pins the typed fetch refusals:
// every one begins with the stable ArtifactPullRefused prefix, and its
// FailureReason tells a credential, a short volume and a foreign registry
// apart from a transient pull failure.
func TestCreatePodImageVolumePullRefusalReasons(t *testing.T) {
	ref := artifactTestHost + "/models/tiny:v1"
	for _, tc := range []struct {
		name    string
		ref     string
		pullErr error
		credErr error
		want    runtimev1.FailureReason
	}{
		{name: "foreign registry", ref: "ghcr.io/evil/model:v1",
			want: runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX},
		{name: "pull credential", ref: ref, credErr: errors.New("secret regcred not found"),
			want: runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL},
		{name: "insufficient space", ref: ref, pullErr: fmt.Errorf("need 40 GB: %w", artifact.ErrInsufficientSpace),
			want: runtimev1.FailureReason_FAILURE_REASON_RESOURCE_EXHAUSTED},
		{name: "foreign registry from the puller", ref: ref, pullErr: fmt.Errorf("redirected: %w", artifact.ErrNotClusterRegistry),
			want: runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX},
		{name: "stalled transfer", ref: ref, pullErr: fmt.Errorf("%w: %w", artifact.ErrBlobTransfer, artifact.ErrBlobStalled),
			want: runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL},
		{name: "cancelled", ref: ref, pullErr: context.Canceled,
			want: runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := &fakeCredentialResolver{err: tc.credErr}
			rt := newTestRuntime(t, Deps{ArtifactPuller: &scriptedArtifactPuller{err: tc.pullErr}, Credentials: creds})
			box := imageVolumeBox(rt, "pod-refused", tc.ref)
			box.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if !strings.HasPrefix(resp.GetError().GetMessage(), "ArtifactPullRefused") {
				t.Errorf("error = %q, want it to begin with ArtifactPullRefused", resp.GetError().GetMessage())
			}
			if resp.GetFailureReason() != tc.want {
				t.Errorf("reason = %v, want %v", resp.GetFailureReason(), tc.want)
			}
		})
	}
}
