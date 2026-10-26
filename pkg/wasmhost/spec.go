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

package wasmhost

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"k3sm.io/runtimed/pkg/pathsafe"
)

// SpecVersion is the one LaunchSpec version this package writes and reads. A
// file carrying any other version was written by a daemon built against a
// different contract and is refused.
const SpecVersion = 1

// The bounds a valid spec stays inside. They exist so that a spec's size is
// bounded by construction, which is what lets maxSpecBytes be small (see
// TestMaximalSpecFitsTheReadBound).
const (
	// MaxPreopens bounds the preopen list: the rootfs plus every volume mount
	// of one container.
	MaxPreopens = 64
	// MaxPathBytes bounds every path in the spec. It is darwin's PATH_MAX.
	MaxPathBytes = 1024
	// MaxArgvEntries bounds the number of guest argv entries.
	MaxArgvEntries = 1024
	// MaxArgvBytes bounds the summed length of the guest argv entries.
	MaxArgvBytes = 64 << 10
	// MaxEnvEntries bounds the number of guest environment entries. It leaves
	// room for the service-link variables Kubernetes injects per Service.
	MaxEnvEntries = 4096
	// MaxEnvBytes bounds the summed length of the guest environment entries.
	MaxEnvBytes = 128 << 10
	// MaxMemoryLimitBytes is the largest pod memory limit a spec may carry,
	// 1 TiB: above any Apple Silicon machine's memory, so a larger value is a
	// unit mistake, not a real limit.
	MaxMemoryLimitBytes uint64 = 1 << 40
)

// ErrInvalidSpec is wrapped by every refusal of a launch spec: a shape check,
// an on-disk check, a decode failure, a size bound or a version mismatch.
var ErrInvalidSpec = errors.New("invalid wasm launch spec")

// Bounds are the trusted directories every host path in a spec must sit under.
// They never come from the spec: the daemon fills them from its own state, and
// the wasm host takes both from its daemon-built argv (--pod-dir and the
// optional --volume-root, parsed by ParseArgs). Without
// them a spec could name its own containment root, and containment would be a
// tautology.
type Bounds struct {
	// PodDir is the pod's own state directory. Required.
	PodDir string
	// VolumeRoot is the root persistent-volume data directories are resolved
	// under (the storage class base path). Empty admits no preopen outside
	// PodDir.
	VolumeRoot string
}

func (b Bounds) list() []string {
	if b.VolumeRoot == "" {
		return []string{b.PodDir}
	}
	return []string{b.PodDir, b.VolumeRoot}
}

func (b Bounds) validate() error {
	if err := checkPath(b.PodDir); err != nil {
		return invalid("bounds: pod dir: %v", err)
	}
	if b.PodDir == "/" {
		return invalid("bounds: pod dir is the filesystem root")
	}
	if b.VolumeRoot != "" {
		if err := checkPath(b.VolumeRoot); err != nil {
			return invalid("bounds: volume root: %v", err)
		}
		if b.VolumeRoot == "/" {
			return invalid("bounds: volume root is the filesystem root")
		}
	}
	return nil
}

// boundOf returns the bound p lies at or under, the longest when both match,
// and false when p is under none.
func (b Bounds) boundOf(p string) (string, bool) {
	best := ""
	for _, d := range b.list() {
		if isAtOrUnder(p, d) && len(d) > len(best) {
			best = d
		}
	}
	return best, best != ""
}

// PreopenKind is the closed set of preopen types.
type PreopenKind string

const (
	// PreopenRootfs is the container's root filesystem, preopened at guest
	// path "/". A spec carries exactly one, first.
	PreopenRootfs PreopenKind = "rootfs"
	// PreopenVolume is one declared volume mount of the container.
	PreopenVolume PreopenKind = "volume"
)

// Preopen is one host directory the guest may reach, and the guest path it
// appears at.
type Preopen struct {
	// Kind is PreopenRootfs or PreopenVolume.
	Kind PreopenKind `json:"kind"`
	// GuestPath is the absolute path the directory appears at in the guest.
	GuestPath string `json:"guestPath"`
	// HostPath is the absolute host directory.
	HostPath string `json:"hostPath"`
	// Root is a volume preopen's containment root: the base HostPath was
	// resolved under (for a persistent volume, its claim's directory). It is
	// NOT trusted on its own say-so: Root must itself lie at or under one of
	// the caller's Bounds, and HostPath at or under Root. It is empty for the
	// rootfs preopen.
	Root string `json:"root,omitempty"`
	// ReadOnly makes the directory read-only to the guest.
	ReadOnly bool `json:"readOnly"`
}

// LaunchSpec is the document the daemon writes and the wasm host reads. Build
// one with BuildLaunchSpec; an Engine never sees a LaunchSpec, only a
// Validated.
//
// It has no listener, port or socket field: a wasm guest has no inbound
// networking.
type LaunchSpec struct {
	// Version is SpecVersion.
	Version int `json:"version"`
	// Module is the absolute host path of the .wasm module or component. It
	// lies inside the rootfs preopen's host directory.
	Module string `json:"module"`
	// Preopens is the rootfs preopen first, then the volume preopens.
	Preopens []Preopen `json:"preopens"`
	// Workdir is the guest working directory. It lies inside a preopen's guest
	// path.
	Workdir string `json:"workdir"`
	// MemoryLimitBytes is the pod memory limit. The engine derives its own
	// runaway backstop from it; the pod's footprint sampler stays the
	// authority that reports OOMKilled.
	MemoryLimitBytes uint64 `json:"memoryLimitBytes"`
	// Argv is the guest argv, argv[0] first.
	Argv []string `json:"argv"`
	// Env is the guest environment, each entry NAME=VALUE.
	Env []string `json:"env"`
}

// Validated is a LaunchSpec that passed Validate. Its fields are unexported so
// that no package other than this one can make one without validating; an
// Engine takes a Validated, never a LaunchSpec. The zero value is not valid
// and every Engine must refuse it (check Valid).
type Validated struct {
	spec   LaunchSpec
	bounds Bounds
	valid  bool
}

// Valid reports whether v came from Validate. The zero Validated is not valid.
func (v Validated) Valid() bool { return v.valid }

// Spec returns a deep copy of the validated spec.
func (v Validated) Spec() LaunchSpec { return v.spec.clone() }

// Module returns the module's host path.
func (v Validated) Module() string { return v.spec.Module }

// Preopens returns a copy of the preopen list, the rootfs first.
func (v Validated) Preopens() []Preopen { return append([]Preopen(nil), v.spec.Preopens...) }

// Workdir returns the guest working directory.
func (v Validated) Workdir() string { return v.spec.Workdir }

// MemoryLimitBytes returns the pod memory limit.
func (v Validated) MemoryLimitBytes() uint64 { return v.spec.MemoryLimitBytes }

// Argv returns a copy of the guest argv.
func (v Validated) Argv() []string { return append([]string(nil), v.spec.Argv...) }

// Env returns a copy of the guest environment.
func (v Validated) Env() []string { return append([]string(nil), v.spec.Env...) }

// Bounds returns the bounds the spec was validated against.
func (v Validated) Bounds() Bounds { return v.bounds }

func (s LaunchSpec) clone() LaunchSpec {
	s.Preopens = append([]Preopen(nil), s.Preopens...)
	s.Argv = append([]string(nil), s.Argv...)
	s.Env = append([]string(nil), s.Env...)
	return s
}

// Validate checks s against the caller's trusted bounds and returns it as a
// Validated. BuildLaunchSpec and ReadLaunchSpec both run it; it is the only way
// to make a Validated.
//
// It checks shape (the version; absolute, clean, NUL- and control-free paths
// with no ".." component; unique guest paths; the typed preopen order; the
// argv, env and memory bounds; the workdir inside a preopen), containment (the
// rootfs and every volume Root at or under one of b, never "/"; each volume
// host path at or under its Root), overlap (no writable preopen whose host
// path equals, contains or lies inside another preopen's, so no writable view
// aliases the rootfs or another volume), and then the disk: no component from
// the bound down to any preopen or to the module is a symlink (pkg/pathsafe),
// each preopen is a directory and the module a regular file inside the
// rootfs.
//
// The disk checks prove what the paths resolved to when Validate ran. An engine
// must not reopen them by path afterwards: OpenPreopens re-walks each from its
// bound with O_NOFOLLOW at every component and hands back descriptors.
//
// Every refusal wraps ErrInvalidSpec.
func (s LaunchSpec) Validate(b Bounds) (Validated, error) {
	if err := b.validate(); err != nil {
		return Validated{}, err
	}
	if err := s.validateShape(); err != nil {
		return Validated{}, err
	}
	if err := s.validateContainment(b); err != nil {
		return Validated{}, err
	}
	if err := s.validateDisk(b); err != nil {
		return Validated{}, err
	}
	return Validated{spec: s.clone(), bounds: b, valid: true}, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidSpec}, args...)...)
}

func (s LaunchSpec) validateShape() error {
	if s.Version != SpecVersion {
		return invalid("version %d, want %d", s.Version, SpecVersion)
	}
	if err := checkPath(s.Module); err != nil {
		return invalid("module: %v", err)
	}
	if n := len(s.Preopens); n == 0 || n > MaxPreopens {
		return invalid("%d preopens, want 1..%d", n, MaxPreopens)
	}
	seen := make(map[string]bool, len(s.Preopens))
	for i, p := range s.Preopens {
		if err := checkPreopen(i, p); err != nil {
			return err
		}
		if seen[p.GuestPath] {
			return invalid("preopen %d: guest path %q is not unique", i, p.GuestPath)
		}
		seen[p.GuestPath] = true
	}
	if !isAtOrUnder(s.Module, s.Preopens[0].HostPath) || s.Module == s.Preopens[0].HostPath {
		return invalid("module %q is not inside the rootfs %q", s.Module, s.Preopens[0].HostPath)
	}
	if err := checkPath(s.Workdir); err != nil {
		return invalid("workdir: %v", err)
	}
	inside := false
	for _, p := range s.Preopens {
		if isAtOrUnder(s.Workdir, p.GuestPath) {
			inside = true
			break
		}
	}
	if !inside {
		return invalid("workdir %q is not inside any preopen", s.Workdir)
	}
	if s.MemoryLimitBytes == 0 || s.MemoryLimitBytes > MaxMemoryLimitBytes {
		return invalid("memory limit %d bytes, want 1..%d", s.MemoryLimitBytes, MaxMemoryLimitBytes)
	}
	if n := len(s.Argv); n == 0 || n > MaxArgvEntries {
		return invalid("%d argv entries, want 1..%d", n, MaxArgvEntries)
	}
	total := 0
	for i, a := range s.Argv {
		if strings.IndexByte(a, 0) >= 0 {
			return invalid("argv[%d] contains NUL", i)
		}
		if !utf8.ValidString(a) {
			return invalid("argv[%d] is not valid UTF-8", i)
		}
		total += len(a)
	}
	if total > MaxArgvBytes {
		return invalid("argv is %d bytes, over the %d-byte bound", total, MaxArgvBytes)
	}
	return checkEnv(s.Env)
}

// checkEnv admits NAME=VALUE entries whose NAME is non-empty printable ASCII
// without "=" (the Kubernetes env-name rule) and whose VALUE is valid UTF-8
// with no NUL, inside the count and byte bounds.
func checkEnv(env []string) error {
	if len(env) > MaxEnvEntries {
		return invalid("%d env entries, over the %d bound", len(env), MaxEnvEntries)
	}
	total := 0
	for i, e := range env {
		name, value, ok := strings.Cut(e, "=")
		if !ok {
			return invalid("env[%d] has no \"=\"", i)
		}
		if name == "" {
			return invalid("env[%d] has an empty name", i)
		}
		for j := 0; j < len(name); j++ {
			if c := name[j]; c < 0x20 || c > 0x7e {
				return invalid("env[%d] name %q is not printable ASCII", i, name)
			}
		}
		if strings.IndexByte(value, 0) >= 0 {
			return invalid("env[%d] value contains NUL", i)
		}
		if !utf8.ValidString(value) {
			return invalid("env[%d] value is not valid UTF-8", i)
		}
		total += len(e)
	}
	if total > MaxEnvBytes {
		return invalid("env is %d bytes, over the %d-byte bound", total, MaxEnvBytes)
	}
	return nil
}

func (s LaunchSpec) validateContainment(b Bounds) error {
	rootfs := s.Preopens[0].HostPath
	if rootfs == "/" {
		return invalid("rootfs is the filesystem root")
	}
	if _, ok := b.boundOf(rootfs); !ok {
		return invalid("rootfs %q is not under the bounds %v", rootfs, b.list())
	}
	for i, p := range s.Preopens[1:] {
		if p.Root == "/" {
			return invalid("preopen %d: containment root is the filesystem root", i+1)
		}
		if _, ok := b.boundOf(p.Root); !ok {
			return invalid("preopen %d: containment root %q is not under the bounds %v", i+1, p.Root, b.list())
		}
	}
	for i, p := range s.Preopens {
		if p.ReadOnly {
			continue
		}
		for j, q := range s.Preopens {
			if i == j {
				continue
			}
			if isAtOrUnder(p.HostPath, q.HostPath) || isAtOrUnder(q.HostPath, p.HostPath) {
				return invalid("writable preopen %d (%q) overlaps preopen %d (%q)", i, p.HostPath, j, q.HostPath)
			}
		}
	}
	return nil
}

func checkPreopen(i int, p Preopen) error {
	if err := checkPath(p.GuestPath); err != nil {
		return invalid("preopen %d: guest path: %v", i, err)
	}
	if err := checkPath(p.HostPath); err != nil {
		return invalid("preopen %d: host path: %v", i, err)
	}
	switch {
	case i == 0 && p.Kind != PreopenRootfs:
		return invalid("preopen 0 is %q, want the %q preopen first", p.Kind, PreopenRootfs)
	case i == 0:
		if p.GuestPath != "/" {
			return invalid("rootfs preopen at guest path %q, want \"/\"", p.GuestPath)
		}
		if p.Root != "" {
			return invalid("rootfs preopen carries a containment root %q; its root is its host path", p.Root)
		}
	case p.Kind == PreopenRootfs:
		return invalid("preopen %d is a second rootfs preopen", i)
	case p.Kind != PreopenVolume:
		return invalid("preopen %d has unknown kind %q", i, p.Kind)
	default:
		if p.GuestPath == "/" {
			return invalid("volume preopen %d at guest path \"/\", which is the rootfs", i)
		}
		if err := checkPath(p.Root); err != nil {
			return invalid("preopen %d: containment root: %v", i, err)
		}
		if !isAtOrUnder(p.HostPath, p.Root) {
			return invalid("preopen %d: host path %q is not at or under its root %q", i, p.HostPath, p.Root)
		}
	}
	return nil
}

// checkPath refuses anything but an absolute, clean, bounded path of valid
// UTF-8 with no NUL, no control character and no "." or ".." component.
// Clean-equality alone refuses "//", "/./", a trailing slash and every ".."
// that Clean would fold; the component loop states the ".." rule outright.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty")
	case len(p) > MaxPathBytes:
		return fmt.Errorf("%d bytes, over the %d-byte bound", len(p), MaxPathBytes)
	case !utf8.ValidString(p):
		return errors.New("not valid UTF-8")
	case strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		return fmt.Errorf("%q contains a NUL or control character", p)
	case !filepath.IsAbs(p):
		return fmt.Errorf("%q is not absolute", p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("%q is not clean", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." || c == "." {
			return fmt.Errorf("%q has a %q component", p, c)
		}
	}
	return nil
}

// isAtOrUnder reports whether p is dir or lies beneath it, separator-aware.
func isAtOrUnder(p, dir string) bool {
	if p == dir || dir == "/" {
		return true
	}
	return len(p) > len(dir)+1 && p[:len(dir)] == dir && p[len(dir)] == '/'
}

func (s LaunchSpec) validateDisk(b Bounds) error {
	for i, p := range s.Preopens {
		bound, _ := b.boundOf(p.HostPath) // containment already proved one exists
		if err := pathsafe.RefuseSymlinkedPath(bound, p.HostPath); err != nil {
			return fmt.Errorf("%w: preopen %d: %w", ErrInvalidSpec, i, err)
		}
		// RefuseSymlinkedPath passes a missing component; a preopen must exist.
		if err := requireDir(p.HostPath); err != nil {
			return invalid("preopen %d: %v", i, err)
		}
	}
	rootfs := s.Preopens[0].HostPath
	if err := pathsafe.RefuseSymlinkedPath(rootfs, filepath.Dir(s.Module)); err != nil {
		return fmt.Errorf("%w: module: %w", ErrInvalidSpec, err)
	}
	fi, err := os.Lstat(s.Module)
	if err != nil {
		return fmt.Errorf("%w: module: %w", ErrInvalidSpec, err)
	}
	if !fi.Mode().IsRegular() {
		return invalid("module %q is %s, not a regular file", s.Module, fi.Mode().Type())
	}
	return nil
}

// requireDir refuses a path that is absent, a symlink, or not a directory.
func requireDir(p string) error {
	fi, err := os.Lstat(p)
	switch {
	case err != nil:
		return err
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%q is a symlink", p)
	case !fi.IsDir():
		return fmt.Errorf("%q is not a directory", p)
	}
	return nil
}
