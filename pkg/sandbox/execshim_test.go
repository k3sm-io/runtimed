package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
	good, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		path, argv, cleanup, err := b.WrapCommand(context.Background(), good, []string{"/bin/echo", "hi"})
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		defer cleanup()
		if path != b.shimPath {
			t.Errorf("path=%q, want shim %q", path, b.shimPath)
		}
		// argv = [shim, profilePath, /bin/echo, hi]
		if len(argv) != 4 || argv[0] != b.shimPath || argv[2] != "/bin/echo" || argv[3] != "hi" {
			t.Fatalf("unexpected argv: %v", argv)
		}
		profilePath := argv[1]
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

	t.Run("rejects-failopen-profile", func(t *testing.T) {
		_, _, _, err := b.WrapCommand(context.Background(), "(version 1)\n(allow default)\n", []string{"/bin/echo"})
		if !errors.Is(err, ErrMissingDenyDefault) {
			t.Fatalf("want ErrMissingDenyDefault, got %v", err)
		}
	})

	t.Run("rejects-empty-argv", func(t *testing.T) {
		_, _, _, err := b.WrapCommand(context.Background(), good, nil)
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
