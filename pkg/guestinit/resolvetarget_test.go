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

package guestinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveTarget is the gate on a vm Pod being unable to reach the API server
// as itself. On a plain vm pod the ServiceAccount token was simply absent:
//
//	$ kubectl exec vm-hello -- ls /var/run/secrets/kubernetes.io/serviceaccount/
//	ls: ...: No such file or directory
//
// Everything upstream was correct — the files were rendered on the host, the
// guest spec named the right bind — but the guest prepared the target by
// MkdirAll'ing <containerRoot>/var/run/secrets/... and mounting there. The image
// ships /var/run as an ABSOLUTE symlink to /run, and the kernel resolves that
// against the GUEST's root, not the container's. Both calls SUCCEEDED, against a
// guest path that exists, and the container saw nothing at its mountPath.
//
// The mountPath that worked in the same guest, /shared, is a single top-level
// component and traverses no symlink — which is exactly what localised it.
func TestResolveTarget(t *testing.T) {
	// alpineRoot is a container rootfs shaped like the base images that ship
	// /var/run -> /run: alpine, debian, ubuntu.
	alpineRoot := func(t *testing.T) string {
		t.Helper()
		root := containerRoot(t, "run/", "var/", "etc/")
		if err := os.Symlink("/run", filepath.Join(root, "var", "run")); err != nil {
			t.Fatal(err)
		}
		return root
	}

	cases := []struct {
		name string
		// entries beyond the alpine shape.
		extra []string
		// links are "path->target" symlinks created after entries.
		links   []string
		target  string
		want    string // container-relative expectation
		wantErr bool
	}{
		{
			// THE DEFECT. The SA token's mountPath traverses /var/run.
			name:   "a-credential-mountpath-through-an-absolute-symlink-lands-inside-the-container",
			target: "/var/run/secrets/kubernetes.io/serviceaccount",
			want:   "run/secrets/kubernetes.io/serviceaccount",
		},
		{
			// The regression guard: the emptyDir mountPath that works today.
			name:   "a-plain-top-level-mountpath-is-unchanged",
			target: "/shared",
			want:   "shared",
		},
		{
			// A configMap/secret volume is the same code path — nothing branches
			// on volume kind — so it must resolve identically.
			name:   "a-configmap-mountpath-through-the-same-symlink-resolves-the-same-way",
			target: "/var/run/config/app",
			want:   "run/config/app",
		},
		{
			// A subPath narrows the bind SOURCE, not the target; the target is
			// still the mountPath and is affected exactly as any other is.
			name:   "a-subpath-mountpath-is-resolved-like-any-other-target",
			target: "/var/run/secrets/kubernetes.io/serviceaccount/token",
			want:   "run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			name:   "an-existing-directory-resolves-to-itself",
			target: "/etc",
			want:   "etc",
		},
		{
			name:   "a-relative-symlink-resolves-against-the-links-own-directory",
			extra:  []string{"opt/real/"},
			links:  []string{"opt/link->real"},
			target: "/opt/link/data",
			want:   "opt/real/data",
		},
		{
			name:   "a-chain-of-absolute-symlinks-resolves",
			extra:  []string{"final/"},
			links:  []string{"a->/b", "b->/final"},
			target: "/a/x",
			want:   "final/x",
		},
		{
			// REFUSED, not silently mounted outside the container.
			name:    "a-target-escaping-the-root-via-a-symlink-is-refused",
			links:   []string{"escape->../../../../etc"},
			target:  "/escape/passwd",
			wantErr: true,
		},
		{
			// An ABSOLUTE target's leading ".." is clamped at the root, which is
			// what a real chroot does — there is nothing above / to reach. The
			// security-relevant escape is the SYMLINK one above, and that is
			// refused rather than clamped: stricter than the kernel, deliberately,
			// and consistent with ResolveProgram.
			name:   "an-absolute-targets-leading-dotdot-is-clamped-at-the-root",
			target: "/../../../../etc/passwd",
			want:   "etc/passwd",
		},
		{
			name:    "a-symlink-loop-is-refused",
			links:   []string{"a->/b", "b->/a"},
			target:  "/a/x",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := alpineRoot(t)
			for _, e := range tc.extra {
				p := filepath.Join(root, filepath.FromSlash(e))
				if strings.HasSuffix(e, "/") {
					if err := os.MkdirAll(p, 0o755); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, l := range tc.links {
				link, target, _ := strings.Cut(l, "->")
				p := filepath.Join(root, filepath.FromSlash(link))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			}

			got, err := ResolveTarget(root, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveTarget = %q, want a refusal — a target outside the container root must not be mounted", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveTarget: %v", err)
			}
			want := filepath.Join(root, filepath.FromSlash(tc.want))
			if got != want {
				t.Errorf("ResolveTarget = %q, want %q", got, want)
			}
			// The property that actually matters: whatever it resolved to is
			// INSIDE the container root. A regression that resolved against the
			// guest root would leave this false.
			if !strings.HasPrefix(got, root+string(filepath.Separator)) && got != root {
				t.Errorf("ResolveTarget = %q, which is outside the container root %q", got, root)
			}
		})
	}
}

// TestResolveTargetPlacesTheMountWhereTheContainerLooks is the end-to-end shape
// of the fix, driven the way the guest drives it: resolve, create, and then check
// the path the CHROOTED container would open.
func TestResolveTargetPlacesTheMountWhereTheContainerLooks(t *testing.T) {
	root := containerRoot(t, "run/", "var/")
	if err := os.Symlink("/run", filepath.Join(root, "var", "run")); err != nil {
		t.Fatal(err)
	}
	const mountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

	resolved, err := ResolveTarget(root, mountPath)
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	// What applyMounts does next.
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resolved, "token"), []byte("BOUND-TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The chrooted container opens /var/run/secrets/... — which, inside its own
	// root, traverses its own /var/run -> /run. Resolving the same way is how a
	// test on a host with no chroot asks the container's question.
	viaSymlink, err := ResolveTarget(root, mountPath+"/token")
	if err != nil {
		t.Fatalf("ResolveTarget(token): %v", err)
	}
	got, err := os.ReadFile(viaSymlink)
	if err != nil {
		t.Fatalf("the container cannot read its token at %s: %v", mountPath, err)
	}
	if string(got) != "BOUND-TOKEN" {
		t.Errorf("token = %q, want the rendered one", got)
	}
	// And it is genuinely inside the container, not at the guest's /run.
	if !strings.HasPrefix(viaSymlink, root+string(filepath.Separator)) {
		t.Errorf("the token resolved to %q, outside the container root %q", viaSymlink, root)
	}
}

// TestContainerMountsCarryTheirResolutionRoot pins the wiring: every step whose
// target lies inside a container's composed rootfs must say so, or applyMounts
// will prepare and mount it against the guest's root instead. A step that
// silently loses ResolveRoot reintroduces the whole defect.
func TestContainerMountsCarryTheirResolutionRoot(t *testing.T) {
	root := ContainerRootDir("app")
	pod := []MountStep{
		{Target: "/var/run/secrets/kubernetes.io/serviceaccount", Options: []MountOption{OptionBind}},
		{Target: "/var/run/secrets/kubernetes.io/serviceaccount", Options: []MountOption{OptionBind, OptionRemount, OptionReadOnly}},
		{Target: "/shared", Options: []MountOption{OptionBind}},
	}

	steps := append(containerVisibleMounts("app", pod), EtcBinds("app")...)
	if len(steps) == 0 {
		t.Fatal("no container mounts were produced")
	}
	for i, s := range steps {
		if !strings.HasPrefix(s.Target, root+"/") {
			t.Errorf("step %d targets %s, which is not inside the container rootfs %s", i, s.Target, root)
			continue
		}
		if s.ResolveRoot != root {
			t.Errorf("step %d (%s) carries ResolveRoot %q, want %q — without it the target is resolved against the GUEST root",
				i, s.Target, s.ResolveRoot, root)
		}
		for _, dir := range s.MkdirExtra {
			if !strings.HasPrefix(dir, root+"/") {
				t.Errorf("step %d MkdirExtra %s is outside the container rootfs", i, dir)
			}
		}
	}

	t.Run("a-credential-bind-is-still-read-only-at-the-mountpath", func(t *testing.T) {
		// The direction that must not regress: the token bind is resolved AND
		// read-only. A resolution change that dropped the remount would expose a
		// credential file writable, which mounts.go warns about by name.
		var sawBind, sawReadOnlyRemount bool
		for _, s := range steps {
			if !strings.HasSuffix(s.Target, "/var/run/secrets/kubernetes.io/serviceaccount") {
				continue
			}
			if hasOption(s.Options, OptionRemount) && hasOption(s.Options, OptionReadOnly) {
				sawReadOnlyRemount = true
				if s.ResolveRoot != root {
					t.Error("the read-only remount is not resolved inside the container; it would remount a guest path")
				}
				continue
			}
			sawBind = true
		}
		if !sawBind || !sawReadOnlyRemount {
			t.Errorf("credential mountPath: bind=%v read-only remount=%v, want both", sawBind, sawReadOnlyRemount)
		}
	})
}
