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

package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/guestartifacts"
)

var _ guestartifacts.ClusterStore = (*GuestStore)(nil)

const mediaTypeOCIEmpty = "application/vnd.oci.empty.v1+json"

var (
	guestKernel    = []byte("guest kernel bytes\n")
	guestInitramfs = []byte("guest initramfs bytes\n")
)

func guestLayers() []layer {
	return []layer{
		{mt: artifactv1.MediaTypeGuestKernel, path: guestartifacts.ImageFileName, data: guestKernel},
		{mt: artifactv1.MediaTypeGuestInitramfs, path: guestartifacts.InitramfsFileName, data: guestInitramfs},
	}
}

func TestPullGuestArtifactIsTheOnlyGuestEntry(t *testing.T) {
	e := newEnv(t)
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty, guestLayers())
	p := e.puller(t)

	if _, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
		t.Fatalf("image-volume pull of a guest artifact: err = %v, want ErrTypeRefused", err)
	}
	if _, err := p.PullForPod(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
		t.Fatalf("pod pull of a guest artifact: err = %v, want ErrTypeRefused", err)
	}
	res, err := p.PullGuestArtifact(context.Background(), testRef, nil)
	if err != nil {
		t.Fatalf("guest pull: %v", err)
	}
	res.Lease.Release()
	if res.ArtifactType != artifactv1.ArtifactTypeGuest || len(res.LayerDigests) != 2 {
		t.Errorf("result = %+v", res)
	}
	raw, ok, err := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeGuest)
	if err != nil || !ok {
		t.Fatalf("guest record: ok=%v err=%v", ok, err)
	}
	if !raw.PodOnly {
		t.Error("the guest record is pinned; it must be PodOnly so its blobs are collectable")
	}

	// The guest entry admits the guest type and its two layer types only.
	e.fetch.publishModel(testRef, modelLayer("a.json", "a"))
	if _, err := p.PullGuestArtifact(context.Background(), testRef, nil); !errors.Is(err, ErrTypeRefused) {
		t.Errorf("guest pull of a model: err = %v, want ErrTypeRefused", err)
	}
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty,
		[]layer{{mt: artifactv1.MediaTypeModelWeight, path: "Image", data: guestKernel}})
	if _, err := p.PullGuestArtifact(context.Background(), testRef, nil); !errors.Is(err, ErrLayerTypeRefused) {
		t.Errorf("guest pull with a model layer: err = %v, want ErrLayerTypeRefused", err)
	}
}

func TestGuestStoreFillsGuestArtifactsCache(t *testing.T) {
	e := newEnv(t)
	sum := func(b []byte) string { return strings.TrimPrefix(digestOfBytes(b), "sha256:") }
	pin := guestartifacts.GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     sum(guestKernel),
		InitramfsSHA256: sum(guestInitramfs),
		ReleaseURL:      "https://example.invalid/guest",
		Cmdline:         "console=hvc0",
	}
	const version = "v6.18.48-0123456789ab"
	art, err := guestartifacts.NewStoreArtifact(version, pin)
	if err != nil {
		t.Fatal(err)
	}
	e.fetch.publish(art.Reference(testHost), art.ArtifactType, mediaTypeOCIEmpty, guestLayers())

	dir := filepath.Join(t.TempDir(), guestartifacts.GuestArtifactsSubdir)
	store := &GuestStore{Puller: e.puller(t), Blobs: e.cache}
	got, err := guestartifacts.EnsureGuestArtifactsFromStore(context.Background(), dir, version, pin, testHost, store)
	if err != nil {
		t.Fatalf("ensure from the store: %v", err)
	}
	for path, want := range map[string][]byte{got.KernelPath: guestKernel, got.InitramfsPath: guestInitramfs} {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s = %q (%v), want %q", path, b, err, want)
		}
	}

	// A store without the pin is a named refusal.
	_, err = guestartifacts.EnsureGuestArtifactsFromStore(context.Background(),
		filepath.Join(t.TempDir(), "g"), "v6.18.49-0123456789ab", pin, testHost, store)
	if !errors.Is(err, guestartifacts.ErrNotInClusterStore) {
		t.Errorf("missing pin: err = %v, want ErrNotInClusterStore", err)
	}
}

// TestPullGuestArtifactCallersAreConfined fails when any non-test Go file in
// this module names PullGuestArtifact outside the guest adapter and the
// guestartifacts package. The guest allow-set is an internal entry point; a
// new caller (an RPC handler, a pod path) would widen who can make the daemon
// fetch a guest artifact, and must be a reviewed change to this list.
func TestPullGuestArtifactCallersAreConfined(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	allowed := func(rel string) bool {
		return rel == filepath.Join("pkg", "artifact", "guest.go") ||
			strings.HasPrefix(rel, filepath.Join("pkg", "guestartifacts")+string(filepath.Separator))
	}
	fset := token.NewFileSet()
	seen := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		seen++
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "PullGuestArtifact" && !allowed(rel) {
				t.Errorf("%s names PullGuestArtifact; only pkg/artifact/guest.go and pkg/guestartifacts may", fset.Position(sel.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 50 {
		t.Fatalf("walked only %d Go files under %s; the guard is not looking at the module", seen, root)
	}
}

// TestNoPolicySelectsGuestAllowSet asserts the guest allow-set is unreachable
// from an ArtifactPolicy: every declared policy, and values past them, either
// fails or yields a set that refuses the guest type.
func TestNoPolicySelectsGuestAllowSet(t *testing.T) {
	var policies []runtimev1.ArtifactPolicy
	for v := range runtimev1.ArtifactPolicy_name {
		policies = append(policies, runtimev1.ArtifactPolicy(v))
	}
	policies = append(policies, -1, 1<<20)
	for v := int32(0); v < 64; v++ {
		policies = append(policies, runtimev1.ArtifactPolicy(v))
	}
	for _, pol := range policies {
		set, err := artifactv1.AllowSetFor(pol)
		if err != nil {
			continue
		}
		if set.AllowsType(artifactv1.ArtifactTypeGuest) || set.Name() == artifactv1.GuestAllowSet().Name() {
			t.Errorf("policy %v (%d) yields the guest allow-set %q", pol, int32(pol), set.Name())
		}
		for _, mt := range []string{artifactv1.MediaTypeGuestKernel, artifactv1.MediaTypeGuestInitramfs} {
			for _, typ := range set.ArtifactTypes() {
				if set.AllowsLayer(typ, mt) {
					t.Errorf("policy %v admits guest layer %s under %s", pol, mt, typ)
				}
			}
		}
	}
}
