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

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// newTestBackend builds an ExecShimBackend pointing at a fake shim file with an
// injectable OS-version function, bypassing host detection.
func newTestBackend(t *testing.T, osMajor int, osErr error) *ExecShimBackend {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, ExecShimName)
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := NewExecShimBackend(shim, dir)
	if err != nil {
		t.Fatal(err)
	}
	b.osMajorFn = func() (int, error) { return osMajor, osErr }
	return b
}

// TestExecShimAvailable covers the OS-version gate and fail-closed posture: the
// backend is available only on darwin at/above the gated major with the shim
// present; below the gate, with a version error, or with a missing shim it is
// unavailable (so the runtime refuses the pod).
func TestExecShimAvailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Available() requires darwin (GOOS gate)")
	}
	cases := []struct {
		name      string
		osMajor   int
		osErr     error
		removeBin bool
		want      bool
	}{
		{"supported", 26, nil, false, true},
		{"newer", 27, nil, false, true},
		{"too-old", 25, nil, false, false},
		{"version-error", 0, errors.New("sysctl failed"), false, false},
		{"missing-shim", 26, nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newTestBackend(t, tc.osMajor, tc.osErr)
			if tc.removeBin {
				_ = os.Remove(b.shimPath)
			}
			if got := b.Available(); got != tc.want {
				t.Errorf("Available()=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestWrapCommand checks the argv shape, profile staging, fail-closed validation,
// and that an invalid profile is rejected before any spawn.
func TestWrapCommand(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("WrapCommand exercises Available() which requires darwin")
	}
	b := newTestBackend(t, 26, nil)
	good, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid-no-drop", func(t *testing.T) {
		// No securityContext → no-drop credential → sentinel tokens "-1 -1 -";
		// no rlimits/qos → "-" "-" sentinels in the two launch-spec positions.
		path, argv, cleanup, err := b.WrapCommand(context.Background(), good, []string{"/bin/echo", "hi"}, supervisor.LaunchSpec{})
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		defer cleanup()
		if path != b.shimPath {
			t.Errorf("path=%q, want shim %q", path, b.shimPath)
		}
		// argv = [shim, <uid>, <gid>, <groups>, <rlimits>, <qos>, profilePath, /bin/echo, hi]
		if len(argv) != 9 || argv[0] != b.shimPath || argv[7] != "/bin/echo" || argv[8] != "hi" {
			t.Fatalf("unexpected argv: %v", argv)
		}
		if argv[1] != "-1" || argv[2] != "-1" || argv[3] != "-" {
			t.Errorf("no-drop credential tokens = %q, want [-1 -1 -]", argv[1:4])
		}
		if argv[4] != "-" || argv[5] != "-" {
			t.Errorf("empty rlimit/qos tokens = %q, want [- -]", argv[4:6])
		}
		profilePath := argv[6]
		data, rerr := os.ReadFile(profilePath)
		if rerr != nil {
			t.Fatalf("staged profile unreadable: %v", rerr)
		}
		if string(data) != good {
			t.Errorf("staged profile mismatch")
		}
		if err := cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if _, err := os.Stat(profilePath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cleanup did not remove profile %s", profilePath)
		}
	})

	t.Run("carries-drop-credential", func(t *testing.T) {
		spec := supervisor.LaunchSpec{Cred: supervisor.Credential{UID: 501, GID: 20, Groups: []int{20, 999}, Drop: true}}
		_, argv, cleanup, err := b.WrapCommand(context.Background(), good, []string{"/bin/echo"}, spec)
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		defer cleanup()
		if argv[1] != "501" || argv[2] != "20" || argv[3] != "20,999" {
			t.Errorf("drop credential tokens = %q, want [501 20 20,999]", argv[1:4])
		}
	})

	t.Run("carries-rlimits-and-qos-before-profile", func(t *testing.T) {
		plan := []supervisor.PlannedRlimit{
			{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}},
		}
		spec := supervisor.LaunchSpec{Rlimits: plan, BgQoS: true}
		_, argv, cleanup, err := b.WrapCommand(context.Background(), good, []string{"/bin/echo"}, spec)
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		defer cleanup()
		// The tokens sit at the fixed positions before the profile path — an old
		// shim (pre-B7 arity) would read argv[4] as its profile path, fail the
		// ReadFile, and exit 3: fail-closed under daemon/shim binary skew.
		if want := supervisor.EncodeRlimits(plan); argv[4] != want {
			t.Errorf("rlimit token = %q, want %q", argv[4], want)
		}
		if argv[5] != "q=bg" {
			t.Errorf("qos token = %q, want %q", argv[5], "q=bg")
		}
		// Round-trip through the shim-side decoders: the plan survives, non-nil.
		decoded, derr := supervisor.ParseRlimits(argv[4])
		if derr != nil || !reflect.DeepEqual(decoded, plan) {
			t.Errorf("ParseRlimits(%q) = (%+v, %v), want (%+v, nil)", argv[4], decoded, derr, plan)
		}
		if bg, qerr := supervisor.ParseQoS(argv[5]); qerr != nil || !bg {
			t.Errorf("ParseQoS(%q) = (%v, %v), want (true, nil)", argv[5], bg, qerr)
		}
		if _, rerr := os.ReadFile(argv[6]); rerr != nil {
			t.Errorf("profile path shifted off position 6: %v", rerr)
		}
	})

	t.Run("rejects-failopen-profile", func(t *testing.T) {
		_, _, _, err := b.WrapCommand(context.Background(), "(version 1)\n(allow default)\n", []string{"/bin/echo"}, supervisor.LaunchSpec{})
		if !errors.Is(err, ErrMissingDenyDefault) {
			t.Fatalf("want ErrMissingDenyDefault, got %v", err)
		}
	})

	t.Run("rejects-empty-argv", func(t *testing.T) {
		_, _, _, err := b.WrapCommand(context.Background(), good, nil, supervisor.LaunchSpec{})
		if err == nil {
			t.Fatal("want error for empty argv")
		}
	})
}

// TestBackendName documents the backend identity used in diagnostics.
func TestBackendName(t *testing.T) {
	b := newTestBackend(t, 26, nil)
	if b.Name() != "seatbelt-execshim" {
		t.Errorf("Name()=%q", b.Name())
	}
}
