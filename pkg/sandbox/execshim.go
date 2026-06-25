package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ExecShimName is the basename of the ad-hoc-signed helper that applies a pod's
// Seatbelt profile in-process (via libsandbox) and then execs the pod binary,
// preserving the environment. The runtime ships this beside its own binary.
const ExecShimName = "k3sm-execshim"

// ErrShimNotFound reports that the k3sm-execshim helper could not be located.
var ErrShimNotFound = errors.New("sandbox: k3sm-execshim helper not found")

// ExecShimBackend confines pods with a NON-PLATFORM exec-shim: it spawns the
// ad-hoc-signed k3sm-execshim helper, which compiles+applies the per-pod SBPL
// via libsandbox and then execve(pod, argv, envp). Because the shim is an
// ordinary ad-hoc-signed binary (NOT a platform binary) and the supervisor
// passes envp through, DYLD_INSERT_LIBRARIES survives into the pod — the
// cross-repo DNS-shim enabler that /usr/bin/sandbox-exec would break.
//
// The backend is OS-version-gated via Available; the supervisor must refuse to
// start a pod when Available is false (fail closed, never run unconfined).
//
// ExecShimBackend's zero value is not usable; construct it with NewExecShimBackend.
type ExecShimBackend struct {
	// shimPath is the resolved absolute path to the k3sm-execshim helper.
	shimPath string
	// profileDir is where per-pod compiled profiles are written before spawn.
	profileDir string
	// minMajor is the minimum macOS major version the libsandbox SPI is known to
	// support; below it Available returns false.
	minMajor int
	// osMajorFn returns the host macOS major version (injectable for tests).
	osMajorFn func() (int, error)
}

// NewExecShimBackend constructs an ExecShimBackend. shimPath is the path to the
// k3sm-execshim helper (if empty, FindExecShim is used to locate it next to the
// current executable or on PATH). profileDir is where per-pod profiles are
// staged (if empty, os.TempDir is used). It returns an error only if the shim
// cannot be located.
func NewExecShimBackend(shimPath, profileDir string) (*ExecShimBackend, error) {
	if shimPath == "" {
		p, err := FindExecShim()
		if err != nil {
			return nil, err
		}
		shimPath = p
	}
	if profileDir == "" {
		profileDir = os.TempDir()
	}
	return &ExecShimBackend{
		shimPath:   shimPath,
		profileDir: profileDir,
		minMajor:   26, // k3sm targets macOS 26+ (Seatbelt SPI validated there).
		osMajorFn:  darwinMajorVersion,
	}, nil
}

// Name returns the backend identifier.
func (b *ExecShimBackend) Name() string { return "seatbelt-execshim" }

// Available reports whether the exec-shim backend can confine pods: the host
// must be darwin at or above the gated minimum macOS major version and the shim
// helper must exist. A false return means the runtime MUST refuse the pod.
func (b *ExecShimBackend) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if b.shimPath == "" {
		return false
	}
	if _, err := os.Stat(b.shimPath); err != nil {
		return false
	}
	major, err := b.osMajorFn()
	if err != nil {
		return false
	}
	return major >= b.minMajor
}

// WrapCommand validates profile (fail-closed), writes it to a per-pod temp file
// under the backend's profile dir, and returns the shim path plus argv:
//
//	[shimPath, profilePath, pod, args...]
//
// so the spawned shim applies profile to itself and execs pod with args,
// preserving envp. cleanup removes the staged profile file.
func (b *ExecShimBackend) WrapCommand(ctx context.Context, profile string, argv []string) (string, []string, func() error, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, nil, err
	}
	if len(argv) == 0 {
		return "", nil, nil, errors.New("sandbox: empty argv")
	}
	if err := Validate(profile); err != nil {
		return "", nil, nil, err
	}
	if !b.Available() {
		return "", nil, nil, fmt.Errorf("sandbox: %s backend unavailable on this host", b.Name())
	}

	f, err := os.CreateTemp(b.profileDir, "k3sm-sbpl-*.sb")
	if err != nil {
		return "", nil, nil, fmt.Errorf("stage sbpl profile: %w", err)
	}
	profilePath := f.Name()
	cleanup := func() error { return os.Remove(profilePath) }
	if _, err := f.WriteString(profile); err != nil {
		_ = f.Close()
		_ = cleanup()
		return "", nil, nil, fmt.Errorf("write sbpl profile %s: %w", profilePath, err)
	}
	if err := f.Close(); err != nil {
		_ = cleanup()
		return "", nil, nil, fmt.Errorf("close sbpl profile %s: %w", profilePath, err)
	}

	args := make([]string, 0, len(argv)+2)
	args = append(args, b.shimPath, profilePath)
	args = append(args, argv...)
	return b.shimPath, args, cleanup, nil
}

// FindExecShim locates the k3sm-execshim helper: first beside the current
// executable, then on PATH. It returns ErrShimNotFound if neither resolves.
func FindExecShim() (string, error) {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), ExecShimName)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if p, err := exec.LookPath(ExecShimName); err == nil {
		return p, nil
	}
	return "", ErrShimNotFound
}
