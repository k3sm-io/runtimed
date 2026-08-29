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
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestDefaultPullerPlatformWiring exercises the puller runtime.New builds when
// Deps.Puller is absent — the DAEMON'S OWN wiring, image.NewPuller(cache,
// image.RemoteFetch) — against an in-process registry.
//
// Every other pull test in this package injects a fakePuller, so none of them
// can tell the production wiring from a mis-wiring: a fetcher bound to the wrong
// platform policy (or to something that ignores the policy it is passed) would
// leave them all green. This is the one test that fails if that binding is
// wrong, and the positive control is what makes the negative case mean
// "refused because of the platform" rather than "errored for any reason".
func TestDefaultPullerPlatformWiring(t *testing.T) {
	host := testRegistryHost(t)

	cases := []struct {
		name    string
		os      string
		arch    string
		repo    string
		wantErr bool
	}{
		// The host-process spine runs Mach-O: a linux/amd64 image is refused at
		// PULL with a legible error, never pulled and discovered at exec.
		{"foreign_platform_refused", "linux", "amd64", "foreign", true},
		{"native_platform_pulls", "darwin", "arm64", "native", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := pushPlatformImage(t, host, tc.repo, tc.os, tc.arch)
			// testDeps leaves Puller nil (unlike newTestRuntime, which injects
			// the fake), so New builds the daemon's own puller.
			rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{}))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			p := &pod{box: hostBinBox(rt, "pod-wiring"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
			c := &runtimev1.Container{Name: "app", Image: ref, Command: []string{"/app"}}
			rb, rerr := rt.resolveBinary(context.Background(), p, t.TempDir(), c)
			if !tc.wantErr {
				if rerr != nil {
					t.Fatalf("resolveBinary: %v", rerr)
				}
				if rb.path != "/app" {
					t.Errorf("bin = %q, want /app", rb.path)
				}
				return
			}
			if !errors.Is(rerr, image.ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want image.ErrNoPlatformMatch", rerr)
			}
		})
	}
}

// testRegistryHost starts an in-process OCI registry (loopback httptest, no
// external network) and returns its host:port.
func testRegistryHost(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test registry url %q: %v", srv.URL, err)
	}
	return u.Host
}

// pushPlatformImage publishes a single-manifest image whose CONFIG declares the
// given platform — the config is the only platform claim an image's digest
// actually covers, so it is what the fixture must control.
func pushPlatformImage(t *testing.T, host, repo, os, arch string) string {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = os, arch, ""
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatalf("mutate config file: %v", err)
	}
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("write image %s: %v", ref, err)
	}
	return ref.String()
}

// TestPullPolicyForwardedToPuller pins the runtimed half of the M12.1 skew
// contract: the container's STAMPED imagePullPolicy reaches the puller exactly
// as the PodBox carried it, and an unset field arrives as UNSPECIFIED (the
// legacy pull-through) rather than being re-derived from the tag.
//
// Every case uses a `:latest` reference — the tag whose corev1 default is
// Always — so a re-derivation anywhere on this path would show up as a policy
// the PodBox never stamped.
func TestPullPolicyForwardedToPuller(t *testing.T) {
	for _, want := range []runtimev1.ImagePullPolicy{
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED,
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
	} {
		t.Run(want.String(), func(t *testing.T) {
			pull := &fakePuller{}
			rt := newTestRuntime(t, Deps{Puller: pull})
			p := &pod{
				box:     hostBinBox(rt, "pod-pullpolicy"),
				backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
			}
			c := &runtimev1.Container{
				Name:            "app",
				Image:           "example.com/app:latest",
				Command:         []string{"/app"}, // command set → the image is pulled
				ImagePullPolicy: want,
			}
			if _, err := rt.resolveBinary(context.Background(), p, t.TempDir(), c); err != nil {
				t.Fatalf("resolveBinary: %v", err)
			}
			if got := pull.pullPolicy(); got != want {
				t.Errorf("puller received pull policy %v, want %v", got, want)
			}
		})
	}
}
