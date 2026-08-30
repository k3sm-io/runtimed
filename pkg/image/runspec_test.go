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
	"os"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/mutate"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// env builds the pod-side env list.
func env(kv ...string) []*runtimev1.EnvVar {
	out := make([]*runtimev1.EnvVar, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, &runtimev1.EnvVar{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

// TestMergeRunSpecFourQuadrants is the M11.2-d1 gate's merge half: Kubernetes'
// command/args table, all four rows, plus the asymmetry that makes row 3 the one
// implementations get wrong — a pod command discards the image's Cmd, because
// that Cmd is arguments to an entrypoint the pod just replaced.
func TestMergeRunSpecFourQuadrants(t *testing.T) {
	cfg := ImageRunConfig{Entrypoint: []string{"/entry", "-e"}, Cmd: []string{"cfg1", "cfg2"}}

	cases := []struct {
		name    string
		command []string
		args    []string
		want    []string
	}{
		{"neither: entrypoint + cmd", nil, nil, []string{"/entry", "-e", "cfg1", "cfg2"}},
		{"args only: entrypoint + args", nil, []string{"a1"}, []string{"/entry", "-e", "a1"}},
		{"command only: command, cmd DISCARDED", []string{"/mine"}, nil, []string{"/mine"}},
		{"both: command + args", []string{"/mine"}, []string{"a1", "a2"}, []string{"/mine", "a1", "a2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MergeRunSpec(cfg, RunSpecRequest{Container: &runtimev1.Container{
				Name: "app", Image: "example.com/app:v1", Command: tc.command, Args: tc.args,
			}})
			if err != nil {
				t.Fatalf("MergeRunSpec: %v", err)
			}
			if !slices.Equal(got.Argv, tc.want) {
				t.Errorf("argv = %v, want %v", got.Argv, tc.want)
			}
		})
	}

	// An image with only a Cmd (no Entrypoint) is runnable — the shape most
	// `FROM scratch`-less base images ship.
	t.Run("cmd_only_image", func(t *testing.T) {
		got, err := MergeRunSpec(ImageRunConfig{Cmd: []string{"/bin/sh"}},
			RunSpecRequest{Container: &runtimev1.Container{Name: "app"}})
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		if !slices.Equal(got.Argv, []string{"/bin/sh"}) {
			t.Errorf("argv = %v, want [/bin/sh]", got.Argv)
		}
	})

	// An image with a Cmd and a pod that supplies ARGS ONLY: the Cmd is
	// discarded because args replace it, and with no Entrypoint the argv is the
	// args alone.
	t.Run("args_replace_cmd", func(t *testing.T) {
		got, err := MergeRunSpec(ImageRunConfig{Cmd: []string{"/bin/sh"}},
			RunSpecRequest{Container: &runtimev1.Container{Name: "app", Args: []string{"/bin/true"}}})
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		if !slices.Equal(got.Argv, []string{"/bin/true"}) {
			t.Errorf("argv = %v, want [/bin/true]", got.Argv)
		}
	})

	// Nothing on either side is a legible REFUSAL, not an empty argv handed to
	// a spawn.
	t.Run("nothing_to_run_is_refused", func(t *testing.T) {
		_, err := MergeRunSpec(ImageRunConfig{}, RunSpecRequest{
			Container: &runtimev1.Container{Name: "app", Image: "example.com/app:v1"},
		})
		if !errors.Is(err, ErrRunSpecInvalid) {
			t.Fatalf("MergeRunSpec error = %v, want ErrRunSpecInvalid", err)
		}
	})
}

// TestMergeRunSpecExpandsVars pins upstream's $(VAR) grammar over the merged
// argv, including the two rules that make it safe to pass a shell snippet as an
// argument: "$$" is a literal "$", and an UNDEFINED reference is left exactly as
// written rather than emptied.
func TestMergeRunSpecExpandsVars(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		lookup map[string]string
		want   string
	}{
		{"defined", "$(HOME)/bin", map[string]string{"HOME": "/root"}, "/root/bin"},
		{"undefined_is_verbatim", "$(NOPE)/bin", nil, "$(NOPE)/bin"},
		{"escaped_dollar", "$$(HOME)", map[string]string{"HOME": "/root"}, "$(HOME)"},
		{"double_escape", "$$$$", nil, "$$"},
		{"bare_dollar", "cost: $5", nil, "cost: $5"},
		{"unterminated", "$(HOME", map[string]string{"HOME": "/root"}, "$(HOME"},
		{"two_refs", "$(A):$(B)", map[string]string{"A": "1", "B": "2"}, "1:2"},
		{"adjacent", "$(A)$(A)", map[string]string{"A": "x"}, "xx"},
		{"empty_value", "[$(A)]", map[string]string{"A": ""}, "[]"},
		{"empty_name", "$()", map[string]string{"": "z"}, "z"},
		{"no_dollar", "plain", nil, "plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandVars(tc.in, tc.lookup); got != tc.want {
				t.Errorf("expandVars(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// Through the merge: the expansion sees the MERGED environment, so an
	// image-supplied variable expands a pod-supplied argument.
	t.Run("through_the_merge", func(t *testing.T) {
		got, err := MergeRunSpec(
			ImageRunConfig{Env: []string{"APPHOME=/opt/app"}},
			RunSpecRequest{Container: &runtimev1.Container{
				Name:    "app",
				Command: []string{"$(APPHOME)/bin/server"},
				Args:    []string{"--data=$(DATA)", "--lit=$$(NOPE)"},
				Env:     env("DATA", "/var/data"),
			}},
		)
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		want := []string{"/opt/app/bin/server", "--data=/var/data", "--lit=$(NOPE)"}
		if !slices.Equal(got.Argv, want) {
			t.Errorf("argv = %v, want %v", got.Argv, want)
		}
	})
}

// TestMergeRunSpecEnvAndWorkingDir pins the other two merged fields: the pod's
// env overrides the image's BY NAME AND IN PLACE (image order is preserved), and
// the pod's workingDir wins over the image's while an unset one falls through.
func TestMergeRunSpecEnvAndWorkingDir(t *testing.T) {
	cfg := ImageRunConfig{
		Env:        []string{"PATH=/usr/bin", "LANG=C", "APP=image"},
		WorkingDir: "/img",
	}

	t.Run("env_override_in_place", func(t *testing.T) {
		got, err := MergeRunSpec(cfg, RunSpecRequest{Container: &runtimev1.Container{
			Name: "app", Command: []string{"/x"},
			Env: env("APP", "pod", "EXTRA", "1"),
		}})
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		want := []string{"PATH=/usr/bin", "LANG=C", "APP=pod", "EXTRA=1"}
		if !slices.Equal(got.Env, want) {
			t.Errorf("env = %v, want %v", got.Env, want)
		}
	})

	t.Run("malformed_image_entries_are_dropped", func(t *testing.T) {
		got, err := MergeRunSpec(ImageRunConfig{Env: []string{"OK=1", "NOEQUALS", "=novalue"}},
			RunSpecRequest{Container: &runtimev1.Container{Name: "app", Command: []string{"/x"}}})
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		if !slices.Equal(got.Env, []string{"OK=1"}) {
			t.Errorf("env = %v, want [OK=1]", got.Env)
		}
	})

	t.Run("duplicate_image_names_collapse", func(t *testing.T) {
		got, err := MergeRunSpec(ImageRunConfig{Env: []string{"A=1", "A=2"}},
			RunSpecRequest{Container: &runtimev1.Container{Name: "app", Command: []string{"/x"}}})
		if err != nil {
			t.Fatalf("MergeRunSpec: %v", err)
		}
		if !slices.Equal(got.Env, []string{"A=2"}) {
			t.Errorf("env = %v, want [A=2] (last image entry wins, in place)", got.Env)
		}
	})

	t.Run("working_dir", func(t *testing.T) {
		for _, tc := range []struct{ pod, want string }{
			{"", "/img"},
			{"/pod", "/pod"},
		} {
			got, err := MergeRunSpec(cfg, RunSpecRequest{Container: &runtimev1.Container{
				Name: "app", Command: []string{"/x"}, WorkingDir: tc.pod,
			}})
			if err != nil {
				t.Fatalf("MergeRunSpec: %v", err)
			}
			if got.WorkingDir != tc.want {
				t.Errorf("workingDir with pod %q = %q, want %q", tc.pod, got.WorkingDir, tc.want)
			}
		}
	})
}

// TestMergeRunSpecRunAsNonRoot pins upstream's verifyRunAsNonRoot branch for
// branch, including the numeric-USER rule (a NAME is never resolved host-side
// out of the image's own /etc/passwd) and the documented fail-OPEN branch for an
// image that declares no USER at all.
func TestMergeRunSpecRunAsNonRoot(t *testing.T) {
	cases := []struct {
		name       string
		imageUser  string
		runAsUID   int64
		nonRoot    bool
		wantErr    bool
		wantUID    int64
		wantHasUID bool
	}{
		{"off: image root is fine and still resolves", "0", 0, false, false, 0, true},
		{"runAsUser wins", "0", 1000, true, false, 1000, true},
		{"image numeric non-root", "1000", 0, true, false, 1000, true},
		{"image numeric with group", "1000:1000", 0, true, false, 1000, true},
		{"image numeric root refused", "0", 0, true, true, 0, false},
		{"image numeric root with group refused", "0:0", 0, true, true, 0, false},
		{"image name refused", "nobody", 0, true, true, 0, false},
		{"image name with group refused", "nobody:nogroup", 0, true, true, 0, false},
		{"image declares no user: upstream admits it", "", 0, true, false, 0, false},
		{"name with runAsNonRoot off is allowed", "nobody", 0, false, false, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MergeRunSpec(
				ImageRunConfig{Cmd: []string{"/app"}, User: tc.imageUser},
				RunSpecRequest{
					Container:    &runtimev1.Container{Name: "app"},
					RunAsUID:     tc.runAsUID,
					RunAsNonRoot: tc.nonRoot,
				})
			if tc.wantErr {
				if !errors.Is(err, ErrRunSpecInvalid) {
					t.Fatalf("MergeRunSpec error = %v, want ErrRunSpecInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("MergeRunSpec: %v", err)
			}
			if got.UID != tc.wantUID || got.HasUID != tc.wantHasUID {
				t.Errorf("uid = %d/%v, want %d/%v", got.UID, got.HasUID, tc.wantUID, tc.wantHasUID)
			}
			if got.User != tc.imageUser {
				t.Errorf("User = %q, want the image directive verbatim %q", got.User, tc.imageUser)
			}
		})
	}
}

// TestIsHostPathReference pins the DISCRIMINATOR: an absolute path is the M0
// host-binary convention and everything else is an OCI reference. The two are
// disjoint by construction, which is what makes the discriminator a property of
// the value rather than a mode a caller sets.
func TestIsHostPathReference(t *testing.T) {
	hostPaths := []string{"/bin/sleep", "/usr/local/bin/app", "/"}
	for _, r := range hostPaths {
		if !IsHostPathReference(r) {
			t.Errorf("IsHostPathReference(%q) = false, want true", r)
		}
	}
	ociRefs := []string{
		"nginx", "nginx:1.27", "library/nginx", "docker.io/library/nginx:1.27",
		"example.com:5000/team/app@sha256:" + hexOf('a'),
		"native", "", "./relative", "../up",
	}
	for _, r := range ociRefs {
		if IsHostPathReference(r) {
			t.Errorf("IsHostPathReference(%q) = true, want false", r)
		}
	}
}

// TestUnpackPolicyFor pins the ONE producer of the layer dialect: it is derived
// from the resolved sandbox backend, and it FAILS CLOSED on the zero value and
// on anything unknown rather than defaulting to the native rules.
func TestUnpackPolicyFor(t *testing.T) {
	cases := []struct {
		backend runtimev1.SandboxBackend
		want    UnpackPolicy
		wantErr bool
	}{
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC, NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL, NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, LinuxUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED, UnpackPolicy{}, true},
		{runtimev1.SandboxBackend(9999), UnpackPolicy{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.backend.String(), func(t *testing.T) {
			got, err := UnpackPolicyFor(tc.backend)
			if tc.wantErr {
				if !errors.Is(err, ErrUnsupportedLayerSemantics) {
					t.Fatalf("UnpackPolicyFor error = %v, want ErrUnsupportedLayerSemantics", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnpackPolicyFor: %v", err)
			}
			if got != tc.want {
				t.Errorf("policy = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestImageRunConfigReadsTheVerifiedConfig proves the run config comes from the
// SAME verified config blob the diffIDs do — an unverified second read would put
// a registry-supplied Entrypoint into argv with no digest behind it.
func TestImageRunConfigReadsTheVerifiedConfig(t *testing.T) {
	c, u := newTestUnpacker(t)
	img := linuxImageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}}))
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.Config.Entrypoint = []string{"/entry"}
	cf.Config.Cmd = []string{"--serve"}
	cf.Config.Env = []string{"PATH=/usr/bin"}
	cf.Config.WorkingDir = "/srv"
	cf.Config.User = "1000:1000"
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	mfst := commitImage(t, c, img)

	got, err := u.ImageRunConfig(mfst)
	if err != nil {
		t.Fatalf("ImageRunConfig: %v", err)
	}
	if !slices.Equal(got.Entrypoint, []string{"/entry"}) || !slices.Equal(got.Cmd, []string{"--serve"}) ||
		!slices.Equal(got.Env, []string{"PATH=/usr/bin"}) || got.WorkingDir != "/srv" || got.User != "1000:1000" {
		t.Errorf("ImageRunConfig = %+v, want the image's own declarations", got)
	}

	// A config blob that no longer hashes to its descriptor is REFUSED, so the
	// run config can never come from unverified bytes.
	t.Run("corrupted_config_is_refused", func(t *testing.T) {
		p, err := c.BlobPath(mfst.GetConfig().GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"config":{"Entrypoint":["/evil"]},"rootfs":{"diff_ids":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := u.ImageRunConfig(mfst); !errors.Is(err, ErrDigestMismatch) {
			t.Errorf("ImageRunConfig error = %v, want ErrDigestMismatch", err)
		}
		// And the same corruption blocks the unpack it feeds.
		if _, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy()); !errors.Is(err, ErrDigestMismatch) {
			t.Errorf("Unpack error = %v, want ErrDigestMismatch", err)
		}
	})
}
