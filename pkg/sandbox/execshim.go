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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"k3sm.io/runtimed/pkg/supervisor"
)

// ExecShimName is the basename of the ad-hoc-signed helper that applies a pod's
// Seatbelt profile in-process (via libsandbox) and then execs the pod binary,
// preserving the environment. The runtime ships this beside its own binary.
const ExecShimName = "k3sm-execshim"

// ErrShimNotFound reports that the k3sm-execshim helper could not be located.
var ErrShimNotFound = errors.New("sandbox: k3sm-execshim helper not found")

// ProfileSubdir is the daemon-private per-pod SBPL staging dir name
// (<root>/sbpl), a sibling of PodReapSubdir and VMReapSubdir under the runtime
// work-dir. It is an exported const for the same reason those two are: three
// consumers must name the same directory — WrapCommand stages into it,
// resolvePosture pins it into the protected deny-set (so Generate emits a
// matching (deny ...) and validateExtraPaths refuses a caller-supplied path
// under it), and SweepStaleProfiles empties it at startup. A drifted second
// literal would leave the deny guarding an empty sibling while the real staging
// dir stayed writable.
//
// The staging dir is created 0700 and its files 0600. Those modes are hygiene
// against other local users and daemons on the host — they are NOT a boundary
// between pods: every pod runs as the daemon's uid, so a pod that obtained a
// path grant reaching here could read and rewrite a sibling's profile. The
// boundary is the emitted Seatbelt deny, and it is load-bearing: the shim reads
// the profile BEFORE it applies the sandbox, so a writable staging dir would be
// a sandbox-substitution primitive.
const ProfileSubdir = "sbpl"

// ProfileTempPattern is the os.CreateTemp pattern for a staged per-pod profile.
// It is exported and shared with SweepStaleProfiles for the reason above in the
// small: the sweep deletes exactly the shape WrapCommand creates, so the two
// cannot drift into a staging dir that fills forever. The pattern is also what
// the legacy top-level (pre-ProfileSubdir) files were named, which is why the
// sweep can still find them.
const ProfileTempPattern = "k3sm-sbpl-*.sb"

// ExecShimBackend confines pods with a non-PLATFORM exec-shim: it spawns the
// ad-hoc-signed k3sm-execshim helper, which compiles+applies the per-pod SBPL
// via libsandbox and then execve(pod, argv, envp). Because the shim is an
// ordinary ad-hoc-signed binary (not a platform binary) and the supervisor
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
	// root is the runtime work-dir; per-pod profiles are staged under its
	// ProfileSubdir child (see profileDir).
	root string
	// minMajor is the minimum macOS major version the libsandbox SPI is known to
	// support; below it Available returns false.
	minMajor int
	// osMajorFn returns the host macOS major version (injectable for tests).
	osMajorFn func() (int, error)
}

// NewExecShimBackend constructs an ExecShimBackend. shimPath is the path to the
// k3sm-execshim helper (if empty, FindExecShim is used to locate it next to the
// current executable or on PATH). root is the runtime work-dir, under whose
// ProfileSubdir child per-pod profiles are staged (if empty, os.TempDir is
// used). It returns an error only if the shim cannot be located.
//
// The staging dir is NOT created here: the backend creates it on demand (the
// PodReapSubdir/VMReapSubdir store-root idiom), so a caller that never spawns a
// pod leaves no directory behind and a dir removed under a running daemon is
// re-created at the next spawn rather than failing it.
func NewExecShimBackend(shimPath, root string) (*ExecShimBackend, error) {
	if shimPath == "" {
		p, err := FindExecShim()
		if err != nil {
			return nil, err
		}
		shimPath = p
	}
	if root == "" {
		root = os.TempDir()
	}
	return &ExecShimBackend{
		shimPath:  shimPath,
		root:      root,
		minMajor:  26, // k3sm targets macOS 26+ (Seatbelt SPI validated there).
		osMajorFn: darwinMajorVersion,
	}, nil
}

// profileDir is the per-pod SBPL staging directory, <root>/sbpl. It is derived
// rather than stored so the leaf name has one spelling (ProfileSubdir) shared
// with the SBPL deny-set and the startup sweep.
func (b *ExecShimBackend) profileDir() string {
	return filepath.Join(b.root, ProfileSubdir)
}

// ExecShimBackendName identifies the host-process Seatbelt rung in
// logging/diagnostics. It is an exported const rather than a literal inside Name
// because a capability decision keys on it: SandboxGPUSupported reports
// GPUFacts.sandbox_gpu_supported only for this rung (it is the only backend whose
// generated profile carries the Metal allow-set), and a drifted second spelling
// would silently make that advertisement false on a perfectly capable node.
const ExecShimBackendName = "seatbelt-execshim"

// Name returns the backend identifier.
func (b *ExecShimBackend) Name() string { return ExecShimBackendName }

// Available reports whether the exec-shim backend can confine pods: the host
// must be darwin at or above the gated minimum macOS major version and the shim
// helper must exist. A false return means the runtime must refuse the pod.
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
// under the backend's staging dir (<root>/sbpl, created on demand), and returns
// the shim path plus argv:
//
//	[shimPath, <uid>, <gid>, <groups-csv>, <rlimits>, <qos>, profilePath, pod, args...]
//
// where the three credential tokens (spec.Cred.ShimArgs) tell the shim which
// identity to drop to, and the rlimit + qos tokens (supervisor.EncodeRlimits /
// EncodeQoS, "-" sentinels when empty) carry the resolved numeric setrlimit(2)
// plan and the darwin background-QoS decision. The two launch-spec tokens sit
// before the profile path so binary skew fails closed: an old shim reads the
// rlimit token as its profile path and aborts on the ReadFile. The spawned shim
// applies the limits, drops to the credential, backgrounds itself if requested,
// applies profile to itself, and execs pod with args — in that irreversible
// order — preserving envp. cleanup removes the staged profile file.
func (b *ExecShimBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
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

	dir := b.profileDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, nil, fmt.Errorf("create the sbpl staging dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ProfileTempPattern)
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

	credArgs := spec.Cred.ShimArgs() // [uid, gid, groups]
	args := make([]string, 0, len(argv)+len(credArgs)+4)
	args = append(args, b.shimPath)
	args = append(args, credArgs...)
	args = append(args, supervisor.EncodeRlimits(spec.Rlimits), supervisor.EncodeQoS(spec.BgQoS))
	args = append(args, profilePath)
	args = append(args, argv...)
	return b.shimPath, args, cleanup, nil
}

// SweepStaleProfiles removes every staged profile left behind by a previous
// daemon incarnation and returns how many it removed. It sweeps both
// <root>/sbpl/ and — as a one-time migration for hosts that ran the pre-sbpl
// layout — the legacy top-level <root>/k3sm-sbpl-*.sb files, matching only
// ProfileTempPattern so an unrelated file at either level is never touched. A
// missing staging dir is not an error (nothing has been staged yet). It logs
// nothing: the caller owns the log line, because only the caller knows which
// startup this was.
//
// Why everything present is stale, with no mtime or age heuristic: the decision
// is made by WHERE this is called, not by how old a file looks. The one call
// site is the runtime's exactly-once startup reap, after the pod-process reap
// has run — so every process group a previous daemon spawned has been SIGKILLed
// or (the keep-and-warn ceiling) recorded as leaked. A leaked shim cannot need
// its profile: the shim reads the file exactly once, at the top of its main,
// before it applies the sandbox and execs the pod binary, so any shim still
// alive at this point read its profile long ago. Nothing this daemon staged can
// be in the directory yet, because the reap runs before CreatePod is served.
// An age heuristic would only add a window in which a genuinely stale file is
// kept, and would still be wrong the moment a host clock moved.
func (b *ExecShimBackend) SweepStaleProfiles() (removed int, err error) {
	var errs []error
	for _, dir := range []string{b.profileDir(), b.root} {
		matches, gerr := filepath.Glob(filepath.Join(dir, ProfileTempPattern))
		if gerr != nil {
			// The only Glob error is ErrBadPattern, which a const pattern cannot
			// produce; keep it rather than discard it so a future pattern edit is
			// not silent.
			errs = append(errs, fmt.Errorf("scan staged profiles in %s: %w", dir, gerr))
			continue
		}
		for _, p := range matches {
			if rerr := os.Remove(p); rerr != nil {
				if errors.Is(rerr, os.ErrNotExist) {
					continue
				}
				errs = append(errs, fmt.Errorf("remove stale profile %s: %w", p, rerr))
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(errs...)
}

// FindExecShim locates the k3sm-execshim helper: first beside the current
// executable with symlinks resolved (see executableSibling), then on PATH. It returns ErrShimNotFound if neither resolves.
func FindExecShim() (string, error) {
	if cand, ok := executableSibling(ExecShimName); ok {
		return cand, nil
	}
	if p, err := exec.LookPath(ExecShimName); err == nil {
		return p, nil
	}
	return "", ErrShimNotFound
}
