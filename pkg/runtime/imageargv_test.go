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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestPulledImageAbsoluteArgvResolvesInRootfs is B197's gate: argv[0] is
// resolved by the IMAGE-REFERENCE discriminator and never by argv's own shape.
//
// # The counterfactual it pins
//
// The M8 lab run (miko-studio, 2026-08-30) measured both halves of the same
// image: mlx-serve's own ENTRYPOINT /bin/python3.12 failed
// FAILURE_REASON_SIGNATURE_REJECTED with "no such file or directory", while the
// byte-identical imported image invoked with a relative argv[0] ran to
// Succeeded. Only the leading slash differed, so the two arms must be tested
// together — a table over one of them cannot see the discriminator at all.
//
// # Why this is not vacuous
//
// The signer here is not a rubber stamp: statSigner reproduces what codesign
// actually does to a path that is not on disk (ENOENT), so a run that resolves
// /bin/python3.12 to the HOST fails for the lab's own reason rather than for a
// reason the test invented. The unpacker writes a real tree into the pod's
// rootfs, so the resolved path is a file that exists exactly when the
// resolution is right. And every row asserts the SPAWN SEAM — the argv the
// sandbox backend was handed — not just resolveBinary's return, because it is
// the spawn that the lab observed failing.
//
// The two host-binary arms are in the same table for the mutant that matters in
// the other direction: a fix that resolved every argv[0] under the rootfs would
// break the M0 native convention, and those rows go red the moment it does.
func TestPulledImageAbsoluteArgvResolvesInRootfs(t *testing.T) {
	// The image tree every pulled row materializes: a payload at bin/python3.12,
	// which is the file an image-relative resolution finds and a host resolution
	// does not.
	imageTree := map[string]string{
		"bin/python3.12": "#!/bin/sh\nexit 0\n",
		"escape":         "the pod's own copy",
	}

	cases := []struct {
		name string
		// container builds the container spec under test. hostBin is an absolute
		// path to a real file outside any pod rootfs — the host binary the M0
		// conventions name.
		container func(hostBin string) *runtimev1.Container
		// entrypoint is the image config's ENTRYPOINT for the pulled rows (the
		// producer of argv[0] when the pod supplies no command).
		entrypoint []string
		// want is the path the spawn seam must receive as argv[0].
		want func(rootfs, hostBin string) string
		// hostBinary records whether the row is a host-binary route, where the
		// signature gate must check and never ad-hoc sign.
		hostBinary bool
		// wantErrContains, when set, makes the row a refusal: CreatePod must fail
		// with a message containing it and nothing may be spawned.
		wantErrContains string
	}{
		{
			// the BLOCKER. The image's own ENTRYPOINT is absolute, as every
			// python-based image's is; it names a file in the IMAGE.
			name: "pulled_image_absolute_entrypoint",
			container: func(string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: "example.test/mlx-serve:v1"}
			},
			entrypoint: []string{"/bin/python3.12", "-m", "mlx_serve"},
			want:       func(rootfs, _ string) string { return filepath.Join(rootfs, "bin/python3.12") },
		},
		{
			// The same rule for the other producer of argv: a pod-supplied
			// absolute command, which overrides the image's entrypoint.
			name: "pulled_image_absolute_pod_command",
			container: func(string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: "example.test/mlx-serve:v1", Command: []string{"/bin/python3.12"}}
			},
			entrypoint: []string{"/entrypoint-not-used"},
			want:       func(rootfs, _ string) string { return filepath.Join(rootfs, "bin/python3.12") },
		},
		{
			// the COUNTERFACTUAL, pinned unchanged-green: the same image invoked
			// relatively already worked and must keep working byte-for-byte.
			name: "pulled_image_relative_entrypoint",
			container: func(string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: "example.test/mlx-serve:v1"}
			},
			entrypoint: []string{"bin/python3.12", "-m", "mlx_serve"},
			want:       func(rootfs, _ string) string { return filepath.Join(rootfs, "bin/python3.12") },
		},
		{
			// M0 native sentinel: command[0] is a HOST path, taken verbatim.
			name: "native_sentinel_absolute_command",
			container: func(hostBin string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: NativeImage, Command: []string{hostBin}}
			},
			want:       func(_, hostBin string) string { return hostBin },
			hostBinary: true,
		},
		{
			// M0 absolute-host-path convention: the image reference IS the binary.
			name: "host_path_convention_image_is_the_binary",
			container: func(hostBin string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: hostBin}
			},
			want:       func(_, hostBin string) string { return hostBin },
			hostBinary: true,
		},
		{
			// Containment: an image-supplied argv[0] may not name a path above its
			// own root. The tree carries a decoy "escape" inside the rootfs and the
			// harness plants one in the parent dir, so an unguarded join would
			// resolve to a real, signable file — the refusal is the only thing
			// standing between the daemon and spawning it.
			name: "pulled_image_argv_escaping_the_rootfs",
			container: func(string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: "example.test/mlx-serve:v1"}
			},
			entrypoint:      []string{"/../escape"},
			wantErrContains: "escapes the pod rootfs",
		},
		{
			name: "pulled_image_relative_argv_escaping_the_rootfs",
			container: func(string) *runtimev1.Container {
				return &runtimev1.Container{Name: "main", Image: "example.test/mlx-serve:v1"}
			},
			entrypoint:      []string{"../escape"},
			wantErrContains: "escapes the pod rootfs",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostBin := filepath.Join(t.TempDir(), "hostprog")
			if err := os.WriteFile(hostBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatalf("write host binary: %v", err)
			}

			signer := &statSigner{}
			backend := &argvBackend{available: true}
			spawner := &fakeSpawner{}
			waiter := newBlockingWaiter()
			rt := newTestRuntime(t, Deps{
				Signer:   signer,
				Backend:  backend,
				Spawner:  spawner,
				Waiter:   waiter,
				Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.test/mlx-serve:v1", Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}}},
				Unpacker: &treeUnpacker{files: imageTree, runCfg: image.ImageRunConfig{Entrypoint: tc.entrypoint}},
			})

			podID := "pod-argv"
			rootfs := derivedRootfs(t, rt, podID)
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{tc.container(hostBin)}

			// The decoy the containment rows aim at: a file in the rootfs's parent,
			// so "/../escape" would resolve to something that exists and would pass
			// the signature gate if the join were not bounded.
			decoy := filepath.Join(filepath.Dir(rootfs), "escape")
			if err := os.MkdirAll(filepath.Dir(decoy), 0o755); err != nil {
				t.Fatalf("mkdir pod dir: %v", err)
			}
			if err := os.WriteFile(decoy, []byte("host-side decoy"), 0o755); err != nil {
				t.Fatalf("write decoy: %v", err)
			}

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}

			if tc.wantErrContains != "" {
				if resp.GetError() == nil {
					t.Fatalf("CreatePod succeeded; want a refusal mentioning %q (argv[0] resolved to %v)",
						tc.wantErrContains, backend.lastArgv())
				}
				if got := resp.GetError().GetMessage(); !strings.Contains(got, tc.wantErrContains) {
					t.Errorf("refusal = %q, want it to mention %q", got, tc.wantErrContains)
				}
				if n := backend.calls(); n != 0 {
					t.Errorf("the sandbox backend was reached %d times on a refused argv[0]; want 0", n)
				}
				if got := signer.paths(); len(got) != 0 {
					t.Errorf("the signature gate saw %v on a refused argv[0]; want nothing", got)
				}
				return
			}

			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
			}
			defer waiter.release(1001)

			want := tc.want(rootfs, hostBin)

			// (a) The SPAWN SEAM — what the sandbox backend was asked to confine —
			// carries the resolved path. This is the assertion the lab failure is
			// about; resolveBinary's return value alone would not prove the spawn
			// ever saw it.
			argv := backend.lastArgv()
			if len(argv) == 0 || argv[0] != want {
				t.Errorf("spawn argv = %v, want argv[0] = %q", argv, want)
			}
			spawner.mu.Lock()
			spawned := len(spawner.specs)
			spawner.mu.Unlock()
			if spawned != 1 {
				t.Errorf("spawned %d processes, want 1", spawned)
			}

			// (b) The SIGNATURE GATE saw the same path — the step that failed in the
			// lab with ENOENT on the host's /bin/python3.12.
			if got := signer.paths(); len(got) == 0 || got[0] != want {
				t.Errorf("signature gate checked %v, want it to start at %q", got, want)
			}
			// A host binary is checked and never ad-hoc re-signed (gateSignature).
			if tc.hostBinary && len(signer.signedPaths()) != 0 {
				t.Errorf("host binary was ad-hoc signed at %v; a host route must only check", signer.signedPaths())
			}

			// (c) The published image identity still distinguishes the two arms: a
			// host-binary route has no manifest, so image_id stays empty.
			cs := resp.GetStatus().GetContainerStatuses()
			if len(cs) != 1 {
				t.Fatalf("container statuses = %d, want 1", len(cs))
			}
			if tc.hostBinary && cs[0].GetImageId() != "" {
				t.Errorf("host-binary route published image_id %q, want empty", cs[0].GetImageId())
			}
			if !tc.hostBinary && cs[0].GetImageId() == "" {
				t.Errorf("pulled route published no image_id; want the config digest")
			}
		})
	}
}

// TestResolveImageArgv0Containment is the unit-level companion: the containment
// predicate itself, over the shapes a table driven through CreatePod cannot
// reach cheaply (a bare "..", a path that merely shares a prefix with the
// rootfs, the empty program).
func TestResolveImageArgv0Containment(t *testing.T) {
	rootfs := "/var/lib/k3sm/pods/pod-a/rootfs"
	cases := []struct {
		argv0   string
		want    string
		wantErr bool
	}{
		{argv0: "/bin/python3.12", want: rootfs + "/bin/python3.12"},
		{argv0: "bin/python3.12", want: rootfs + "/bin/python3.12"},
		{argv0: "./bin/app", want: rootfs + "/bin/app"},
		{argv0: "/usr/bin/env", want: rootfs + "/usr/bin/env"},
		{argv0: "/bin/../bin/app", want: rootfs + "/bin/app"},
		{argv0: "/../escape", wantErr: true},
		{argv0: "../escape", wantErr: true},
		{argv0: "/../../../../etc/passwd", wantErr: true},
		{argv0: "..", wantErr: true},
		{argv0: "/", wantErr: true}, // resolves to the rootfs itself, not a file in it
		{argv0: ".", wantErr: true}, // ditto
		{argv0: "", wantErr: true},  // an empty program is not a path
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.argv0), func(t *testing.T) {
			got, err := resolveImageArgv0(rootfs, tc.argv0)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveImageArgv0(%q) = %q, want a refusal", tc.argv0, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveImageArgv0(%q): %v", tc.argv0, err)
			}
			if got != tc.want {
				t.Errorf("resolveImageArgv0(%q) = %q, want %q", tc.argv0, got, tc.want)
			}
		})
	}
}

// --- fixtures ------------------------------------------------------------

// statSigner is the Signer that makes the argv gate non-vacuous: it behaves like
// codesign on a path that is not on disk, returning the ENOENT the lab session
// saw, and records every path it was handed.
type statSigner struct {
	mu      sync.Mutex
	checked []string
	signed  []string
}

func (s *statSigner) Sign(_ context.Context, path string) error {
	s.mu.Lock()
	s.signed = append(s.signed, path)
	s.mu.Unlock()
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("codesign -s - -f %s: %w", path, err)
	}
	return nil
}

func (s *statSigner) Check(_ context.Context, policy runtimev1.SignaturePolicy, path string) error {
	s.mu.Lock()
	s.checked = append(s.checked, path)
	s.mu.Unlock()
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		return image.ErrPolicyUnspecified
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("codesign -v %s: %w", path, err)
	}
	return nil
}

func (s *statSigner) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.checked...)
}

func (s *statSigner) signedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.signed...)
}

// argvBackend records the UNWRAPPED argv handed to the sandbox seam, which is
// the pod's own argv before the exec-shim prefix — the value a spawn assertion
// wants without doing index arithmetic on the shim's argv shape.
type argvBackend struct {
	available bool

	mu    sync.Mutex
	argvs [][]string
}

func (b *argvBackend) Available() bool { return b.available }
func (b *argvBackend) Name() string    { return "argv-recording" }

func (b *argvBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.argvs = append(b.argvs, append([]string{}, argv...))
	b.mu.Unlock()
	return fakeBackend{available: b.available}.WrapCommand(ctx, profile, argv, spec)
}

func (b *argvBackend) lastArgv() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.argvs) == 0 {
		return nil
	}
	return b.argvs[len(b.argvs)-1]
}

func (b *argvBackend) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.argvs)
}

// treeUnpacker is a runtime.Unpacker that WRITES a fixed tree into the pod
// rootfs, so a resolved argv[0] either names a file that exists or does not.
// fakeUnpacker cannot serve this gate: it records the destination without
// populating it, and every path would then be equally absent.
type treeUnpacker struct {
	files  map[string]string
	runCfg image.ImageRunConfig
}

func (u *treeUnpacker) MaterializeTree(_ context.Context, _ *runtimev1.ImageManifest, policy image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	for rel, data := range u.files {
		p := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, []byte(data), 0o755); err != nil {
			return nil, err
		}
	}
	return &image.MaterializeResult{Tree: &image.Tree{Key: "sha256:tree", Rootfs: dst, Policy: policy}}, nil
}

func (u *treeUnpacker) ImageRunConfig(*runtimev1.ImageManifest) (image.ImageRunConfig, error) {
	return u.runCfg, nil
}
