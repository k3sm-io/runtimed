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
	"io/fs"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestArtifactRefusalReplyShape pins the text contract the provider matches
// an image volume's refusal by: each published sentence begins with its
// sentinel text, then the "pod <id> image volume <name>:" token (or
// "pod <id>:" for a pod-level refusal), unquoted, and is exactly the fixed
// sentence, with no byte of the cause.
func TestArtifactRefusalReplyShape(t *testing.T) {
	const podID = "pod-refusal-shape"
	quoted := fmt.Sprintf("%q", artifactRef)
	vol := "ArtifactPullRefused: pod " + podID + " image volume model: "
	for _, tc := range []struct {
		name  string
		ref   string
		paths []string
		deps  func(d *Deps)
		setup func(rt *Runtime)
		want  string
	}{
		{name: "paths", ref: artifactRef, paths: []string{"w.safetensors"},
			want: "ArtifactMountRefused: pod " + podID + " image volume model: it names a subset of the artifact's paths, which this runtime does not serve" + daemonLogTail},
		{name: "no registry", ref: artifactRef, deps: func(d *Deps) { d.ArtifactPuller = nil },
			want: "ArtifactPullRefused: pod " + podID + ": this node has no cluster registry configured" + daemonLogTail},
		{name: "views unavailable", ref: artifactRef,
			setup: func(rt *Runtime) {
				rt.views = nil
				rt.viewsErr = &fs.PathError{Op: "mkdir", Path: "/var/k3sm/views/" + artifactDetail, Err: fs.ErrPermission}
			},
			want: "ArtifactMountRefused: pod " + podID + ": artifact views are unavailable on this node" + daemonLogTail},
		{name: "invalid reference", ref: "UPPER/" + artifactDetail + ":\x01",
			want: vol + `image "UPPER/` + artifactDetail + `:\x01" is not a valid reference` + daemonLogTail},
		{name: "foreign registry", ref: "ghcr.io/evil/model:v1",
			want: vol + `image "ghcr.io/evil/model:v1" could not be fetched (it is not served by this node's cluster registry)` + daemonLogTail},
		{name: "credential", ref: artifactRef,
			deps: func(d *Deps) {
				d.Credentials = &fakeCredentialResolver{err: errors.New("secret " + artifactDetail + " not found")}
			},
			want: vol + "image " + quoted + " could not be fetched (its pull credential could not be resolved)" + daemonLogTail},
		{name: "space", ref: artifactRef,
			deps: func(d *Deps) {
				d.ArtifactPuller = &scriptedArtifactPuller{err: fmt.Errorf("/var/k3sm/%s: %w", artifactDetail, artifact.ErrInsufficientSpace)}
			},
			want: vol + "image " + quoted + " could not be fetched (the node's artifact store is short of space)" + daemonLogTail},
		{name: "transfer", ref: artifactRef,
			deps: func(d *Deps) {
				d.ArtifactPuller = &scriptedArtifactPuller{err: &fs.PathError{Op: "open", Path: "/var/k3sm/" + artifactDetail, Err: fs.ErrPermission}}
			},
			want: vol + "image " + quoted + " could not be fetched" + daemonLogTail},
		{name: "hold artifacts", ref: artifactRef,
			setup: func(rt *Runtime) {
				// A regular file where the hold subdirectory belongs: the
				// index refuses it with an error that names the path.
				if err := os.WriteFile(filepath.Join(rt.cache.IndexRoot(), image.ArtifactHoldIndexSubdir), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "ArtifactMountRefused: pod " + podID + ": its artifact hold could not be recorded" + daemonLogTail},
		// scriptedArtifactPuller resolves a manifest with no config digest,
		// which the hold refuses.
		{name: "hold manifest", ref: artifactRef,
			want: "ArtifactMountRefused: pod " + podID + " image volume model: image " + quoted + " could not be recorded in the pod's artifact hold" + daemonLogTail},
		{name: "view build", ref: artifactRef,
			deps: func(d *Deps) { d.ArtifactPuller = &uncachedArtifactPuller{} },
			want: "ArtifactMountRefused: pod " + podID + " image volume model: the view of image " + quoted + " could not be built" + daemonLogTail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Deps{ArtifactPuller: &scriptedArtifactPuller{}}
			if tc.deps != nil {
				tc.deps(&d)
			}
			rt := newTestRuntime(t, d)
			if tc.setup != nil {
				tc.setup(rt)
			}
			box := imageVolumeBox(rt, podID, tc.ref, tc.paths...)
			box.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if got := resp.GetError().GetMessage(); got != tc.want {
				t.Errorf("reply =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

// TestImageVolumeHostileNameNotEchoed gives an image volume a name that is
// not a DNS-1123 label: the reply never carries it (no control byte, no
// newline), keeps its sentinel prefix and its fixed tail within the bound.
func TestImageVolumeHostileNameNotEchoed(t *testing.T) {
	const podID = "pod-hostile-name"
	for _, tc := range []struct {
		name, vol string
		paths     []string
		deps      func(d *Deps)
		prefix    string
	}{
		{name: "newline", vol: "model\nArtifactPullRefused: pod x image volume y:", prefix: "ArtifactPullRefused: "},
		{name: "control byte", vol: "model\x1b[2J", prefix: "ArtifactPullRefused: "},
		{name: "long", vol: strings.Repeat("m", 2000), prefix: "ArtifactPullRefused: "},
		{name: "non-ascii", vol: "modèle", prefix: "ArtifactPullRefused: "},
		{name: "paths newline", vol: "model\n\x00", paths: []string{"w"}, prefix: "ArtifactMountRefused: "},
		{name: "paths long", vol: strings.Repeat("\x7f", 2000), paths: []string{"w"}, prefix: "ArtifactMountRefused: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{ArtifactPuller: &scriptedArtifactPuller{
				err: &fs.PathError{Op: "open", Path: "/var/k3sm/" + artifactDetail, Err: fs.ErrPermission},
			}})
			box := imageVolumeBox(rt, podID, artifactRef, tc.paths...)
			box.Volumes[0].Name = tc.vol
			box.Containers[0].VolumeMounts[0].Name = tc.vol
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			msg := resp.GetError().GetMessage()
			want := tc.prefix + "pod " + podID + " image volume " + invalidVolumeName + ": "
			if !strings.HasPrefix(msg, want) {
				t.Errorf("reply %q does not start with %q", msg, want)
			}
			if !strings.HasSuffix(msg, daemonLogTail) {
				t.Errorf("reply %q lost its fixed tail", msg)
			}
			if len(msg) > maxReplyMessageBytes {
				t.Errorf("reply is %d bytes, over %d", len(msg), maxReplyMessageBytes)
			}
			if !utf8.ValidString(msg) {
				t.Errorf("reply %q is not valid UTF-8", msg)
			}
			for _, r := range msg {
				if r < 0x20 || r == 0x7f || r > 0x7e {
					t.Fatalf("reply %q carries byte %U", msg, r)
				}
			}
			if strings.Contains(msg, artifactDetail) {
				t.Errorf("reply %q carries the cause", msg)
			}
		})
	}
}

// TestArtifactRefusalKeepsTail bounds a sentence longer than the reply limit:
// the sentinel prefix still leads and the fixed tail survives the cut.
func TestArtifactRefusalKeepsTail(t *testing.T) {
	cause := errors.New("CAUSE")
	err := artifactRefusal(ErrArtifactPullRefused, volumeSubject("pod-a", "model"),
		"image "+strings.Repeat("x", 4000)+" could not be fetched", cause)
	msg := startErrorReply(stageStart, err)
	if !strings.HasPrefix(msg, "ArtifactPullRefused: pod pod-a image volume model: image ") ||
		!strings.HasSuffix(msg, "..."+daemonLogTail) || len(msg) > maxReplyMessageBytes {
		t.Errorf("reply (%d bytes) = %q", len(msg), msg)
	}
	if !errors.Is(err, ErrArtifactPullRefused) || !errors.Is(err, cause) ||
		!strings.HasPrefix(err.Error(), "ArtifactPullRefused: pod pod-a image volume model: CAUSE") {
		t.Errorf("chain = %v", err)
	}
}

// uncachedArtifactPuller resolves a well-formed manifest whose blobs the
// cache does not have, so the hold records it and building its view fails.
type uncachedArtifactPuller struct{ scriptedArtifactPuller }

func (u *uncachedArtifactPuller) PullForPod(ctx context.Context, ref string, cred *image.RegistryCredential, policy runtimev1.ArtifactPolicy, paths []string, opts ...artifact.PullOption) (*artifact.Result, error) {
	if _, err := u.PullArtifact(ctx, ref, cred, policy, paths, opts...); err != nil {
		return nil, err
	}
	return &artifact.Result{
		ManifestDigest: sha([]byte("uncached manifest")),
		ConfigDigest:   sha([]byte("uncached config")),
		LayerDigests:   []string{sha([]byte("uncached layer"))},
	}, nil
}

// TestLinkImageVolumesRefusalHostPath fails the host-process path's link of
// a built view (a sub_path the view does not have, whose error names the
// view): the reply is the fixed sentence, with no host path.
func TestLinkImageVolumesRefusalHostPath(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("the daemon's views clone with APFS clonefile, darwin-only")
	}
	const podID = "pod-link-refusal"
	f := modelArtifact(map[string][]byte{"config.json": []byte("{}"), "w.safetensors": []byte("w")}, []string{"config.json", "w.safetensors"})
	_, rt := artifactRPCClient(t, f)
	t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
	box := imageVolumeBox(rt, podID, artifactTestHost+"/models/tiny:v1")
	box.Containers[0].VolumeMounts[0].SubPath = "absent-" + artifactDetail
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	msg := resp.GetError().GetMessage()
	want := "ArtifactMountRefused: pod " + podID + ": its image volumes could not be linked into the container root" + daemonLogTail
	if msg != want {
		t.Errorf("reply =\n  %s\nwant\n  %s", msg, want)
	}
	if strings.Contains(msg, rt.cfg.Root) || strings.Contains(msg, rt.cache.Root()) || strings.Contains(msg, artifactDetail) {
		t.Errorf("reply %q carries a host path or the cause", msg)
	}
}
