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
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodIDValidation pins the pod-id ingress hardening (B114): a pod id is a
// single clean path component, rejected at CreatePod (the narrowest ingress —
// every path consumer inherits it) with INVALID_POD_BOX.
func TestPodIDValidation(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"", false},
		{".", false},
		{"..", false},
		{"a/b", false},
		{`a\b`, false},
		{"../escape", false},
		{"a/../../b", false},
		{"pod\x00nul", false},
		{"good-pod-123", true},
		{"..hidden-but-legal", true},
		{"web-0.web.default", true},
	}
	for _, tc := range cases {
		name := tc.id
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			err := validPodID(tc.id)
			if tc.ok && err != nil {
				t.Errorf("validPodID(%q) = %v, want nil", tc.id, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("validPodID(%q) = nil, want error", tc.id)
			}
		})
	}

	// Ingress pin: a traversal id is refused by CreatePod as INVALID_POD_BOX
	// before any on-disk path is derived.
	rt := newTestRuntime(t, Deps{})
	box := hostBinBox("../escape")
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod accepted a traversal pod id")
	}
	if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
		t.Errorf("reason = %v, want INVALID_POD_BOX", resp.GetFailureReason())
	}
}

// TestRemovePodDirContainment pins the removePodDir separator-aware fix
// (B114): the containment check is mount.IsStrictlyUnder against <Root>/pods,
// not a bare prefix — so a ".."-collapsed path landing in a SIBLING whose name
// shares Root's prefix (/root-evil is NOT under /root) is refused, and the
// sibling survives.
func TestRemovePodDirContainment(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{cfg: Config{Root: root}, cache: cache}

	// The separator-sibling shape: this id collapses to <parent>/root-evil/x —
	// a strings.HasPrefix(dir, root) check would bless it.
	evil := filepath.Join(parent, "root-evil", "x")
	if err := os.MkdirAll(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(evil, "keep.txt")
	if err := os.WriteFile(marker, []byte("must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostileID := "../../root-evil/x"
	if got := r.podDir(hostileID); !strings.HasPrefix(got, root) {
		// Sanity: the collapsed dir escapes root/pods yet shares root's prefix
		// only via the separator-sibling; either way removePodDir must refuse.
		t.Logf("collapsed pod dir: %s", got)
	}
	if err := r.removePodDir(hostileID); err == nil {
		t.Error("removePodDir accepted a traversal pod id")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("sibling dir was damaged: %v", err)
	}

	// Root itself and the pods root are refused (strictly-under, not equality).
	for _, id := range []string{"", ".", ".."} {
		if err := r.removePodDir(id); err == nil {
			t.Errorf("removePodDir(%q) succeeded, want refusal", id)
		}
	}

	// The happy path still removes exactly <Root>/pods/<id>.
	podDir := filepath.Join(root, "pods", "p1")
	if err := os.MkdirAll(filepath.Join(podDir, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.removePodDir("p1"); err != nil {
		t.Fatalf("removePodDir(p1): %v", err)
	}
	if _, err := os.Stat(podDir); !os.IsNotExist(err) {
		t.Errorf("pod dir survived removal: %v", err)
	}
}
