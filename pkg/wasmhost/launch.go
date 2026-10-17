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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxSpecBytes bounds the launch spec ReadLaunchSpec will read and
// WriteLaunchSpec will write. 2 MiB holds the largest spec Validate admits with
// room to spare: every bound in spec.go caps a field, and the worst JSON
// escaping of a maximal spec (64 preopens of three 1 KiB paths, a 64 KiB argv
// and a 128 KiB env of control characters) is about 1.6 MiB
// (TestMaximalSpecFitsTheReadBound). A file over it was not written by this
// package, so reading it into memory buys nothing; the bound turns a runaway or
// planted file into a refusal instead of an allocation the helper's memory
// limit pays for.
const maxSpecBytes = 2 << 20

// The flags the wasm host binary accepts: --spec and --pod-dir are required,
// --volume-root is optional.
const (
	SpecFlag       = "--spec"
	PodDirFlag     = "--pod-dir"
	VolumeRootFlag = "--volume-root"
)

// ErrUsage is wrapped by ParseArgs when the host's argument list is not exactly
// --spec=<path> and --pod-dir=<dir>, optionally with --volume-root=<dir>.
var ErrUsage = errors.New("wasm host usage: --spec=<absolute path> --pod-dir=<absolute dir> [--volume-root=<absolute dir>]")

// VolumeMount is one already-resolved volume mount of the container.
type VolumeMount struct {
	// GuestPath is the mount path inside the container.
	GuestPath string
	// HostPath is the host directory backing the mount.
	HostPath string
	// Root is the containment root HostPath was resolved under; see
	// Preopen.Root.
	Root string
	// ReadOnly makes the mount read-only to the guest.
	ReadOnly bool
}

// BuildInput is what the daemon's start path knows about a wasm container.
type BuildInput struct {
	// Rootfs is the container's materialized root filesystem.
	Rootfs string
	// RootfsReadOnly preopens the rootfs read-only.
	RootfsReadOnly bool
	// Module is the host path of the .wasm file inside Rootfs, already resolved
	// (no symlink left to follow).
	Module string
	// Volumes are the container's volume mounts, in mount order.
	Volumes []VolumeMount
	// MemoryLimitBytes is the pod memory limit.
	MemoryLimitBytes uint64
	// Argv is the guest argv, argv[0] first.
	Argv []string
	// Workdir is the guest working directory; empty means "/".
	Workdir string
	// Env is the guest environment, each entry NAME=VALUE.
	Env []string
}

// BuildLaunchSpec assembles the launch spec for in and validates it against the
// daemon's trusted bounds. The rootfs is the first preopen, at guest path "/",
// and the volumes follow in order.
func BuildLaunchSpec(b Bounds, in BuildInput) (Validated, error) {
	workdir := in.Workdir
	if workdir == "" {
		workdir = "/"
	}
	preopens := make([]Preopen, 0, 1+len(in.Volumes))
	preopens = append(preopens, Preopen{
		Kind:      PreopenRootfs,
		GuestPath: "/",
		HostPath:  in.Rootfs,
		ReadOnly:  in.RootfsReadOnly,
	})
	for _, v := range in.Volumes {
		preopens = append(preopens, Preopen{
			Kind:      PreopenVolume,
			GuestPath: v.GuestPath,
			HostPath:  v.HostPath,
			Root:      v.Root,
			ReadOnly:  v.ReadOnly,
		})
	}
	spec := LaunchSpec{
		Version:          SpecVersion,
		Module:           in.Module,
		Preopens:         preopens,
		Workdir:          workdir,
		MemoryLimitBytes: in.MemoryLimitBytes,
		Argv:             append([]string(nil), in.Argv...),
		Env:              append([]string(nil), in.Env...),
	}
	return spec.Validate(b)
}

// encodeSpec is the one encoder of a launch spec. HTML escaping is off because
// the reader is this package, not a browser, and it would only inflate paths.
func encodeSpec(s LaunchSpec) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteLaunchSpec writes v to path, mode 0600. path is a daemon-owned file the
// caller chooses, in a directory no group or other may write (the same check
// ReadLaunchSpec makes); the write goes to a temporary file in that directory
// and is renamed over path, so the helper never reads a partial spec and an
// existing symlink at path is replaced, not followed.
func WriteLaunchSpec(path string, v Validated) error {
	if !v.Valid() {
		return fmt.Errorf("write wasm launch spec %s: %w: not a validated spec", path, ErrInvalidSpec)
	}
	if err := checkPath(path); err != nil {
		return fmt.Errorf("write wasm launch spec: %w: path: %v", ErrInvalidSpec, err)
	}
	if err := checkSpecDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	if err := refuseSpecInWritablePreopen(path, v); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	raw, err := encodeSpec(v.spec)
	if err != nil {
		return fmt.Errorf("encode wasm launch spec: %w", err)
	}
	if len(raw) > maxSpecBytes {
		return fmt.Errorf("write wasm launch spec %s: %w: %d bytes exceeds the %d-byte bound", path, ErrInvalidSpec, len(raw), maxSpecBytes)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".wasmhost-spec-*")
	if err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()      // best effort on the failure path; the write error is what is returned
			_ = os.Remove(tmp) // likewise: a leftover temp file is harmless and never read
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write wasm launch spec %s: %w", path, err)
	}
	ok = true
	return nil
}

// ReadLaunchSpec reads, strictly decodes and validates the launch spec at path
// against the bounds the host took from its own argv.
//
// The file must be what the daemon wrote: opened with O_NOFOLLOW, a regular
// file owned by the current effective uid with no group or other write bit, in
// a directory no group or other may write. The decode is strict: at most
// maxSpecBytes, no unknown, duplicate or case-variant key (a key this binary
// does not know means the daemon and the helper were built from different
// contracts, and that must fail at start, legibly), nothing after the one JSON
// object, and Version equal to SpecVersion. Then Validate runs.
func ReadLaunchSpec(path string, b Bounds) (Validated, error) {
	if err := checkPath(path); err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec: %w: path: %v", ErrInvalidSpec, err)
	}
	if err := checkSpecDir(filepath.Dir(path)); err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return Validated{}, fmt.Errorf("read wasm launch spec %s: %w: the spec is a symlink", path, ErrInvalidSpec)
		}
		return Validated{}, fmt.Errorf("read wasm launch spec: %w", &fs.PathError{Op: "open", Path: path, Err: err})
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	fi, err := f.Stat()
	if err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	if err := checkSpecFile(fi, os.Geteuid()); err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSpecBytes+1))
	if err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	if len(raw) > maxSpecBytes {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w: larger than the %d-byte bound", path, ErrInvalidSpec, maxSpecBytes)
	}
	spec, err := decodeSpec(raw)
	if err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	v, err := spec.Validate(b)
	if err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	if err := refuseSpecInWritablePreopen(path, v); err != nil {
		return Validated{}, fmt.Errorf("read wasm launch spec %s: %w", path, err)
	}
	return v, nil
}

// refuseSpecInWritablePreopen refuses a spec path at or under the host path of
// any writable preopen of v, the rootfs included: a guest that can write the
// spec could rewrite what the next start of its own helper trusts.
func refuseSpecInWritablePreopen(path string, v Validated) error {
	for i, p := range v.spec.Preopens {
		if !p.ReadOnly && isAtOrUnder(path, p.HostPath) {
			return fmt.Errorf("%w: the spec lies inside writable preopen %d (%s)", ErrInvalidSpec, i, p.HostPath)
		}
	}
	return nil
}

// checkSpecFile admits a regular file owned by euid with no group or other
// write bit.
func checkSpecFile(fi fs.FileInfo, euid int) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: the spec is not a regular file (%v)", ErrInvalidSpec, fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: the spec is group- or other-writable (%v)", ErrInvalidSpec, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: the spec's owner is unknown", ErrInvalidSpec)
	}
	if int(st.Uid) != euid {
		return fmt.Errorf("%w: the spec is owned by uid %d, not %d", ErrInvalidSpec, st.Uid, euid)
	}
	return nil
}

// checkSpecDir refuses a spec directory that is missing, not a directory, or
// group- or other-writable: anyone who can write the directory can replace the
// spec by rename, whatever the file's own mode says.
func checkSpecDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: the spec directory: %v", ErrInvalidSpec, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: the spec directory %s is not a directory", ErrInvalidSpec, dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: the spec directory %s is group- or other-writable (%v)", ErrInvalidSpec, dir, fi.Mode().Perm())
	}
	return nil
}

func decodeSpec(raw []byte) (LaunchSpec, error) {
	if err := checkKeys(raw); err != nil {
		return LaunchSpec{}, fmt.Errorf("%w: %v", ErrInvalidSpec, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var spec LaunchSpec
	if err := dec.Decode(&spec); err != nil {
		return LaunchSpec{}, fmt.Errorf("%w: decode: %v", ErrInvalidSpec, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return LaunchSpec{}, fmt.Errorf("%w: trailing data after the spec object", ErrInvalidSpec)
	}
	if spec.Version != SpecVersion {
		return LaunchSpec{}, fmt.Errorf("%w: version %d, want %d", ErrInvalidSpec, spec.Version, SpecVersion)
	}
	return spec, nil
}

// keySchema is the exact key set of the spec's JSON objects. encoding/json
// matches keys case-insensitively and lets a duplicate key overwrite the first,
// so DisallowUnknownFields alone admits {"module":..,"Module":..}; checkKeys
// walks the raw tokens first and admits only these exact names, once each.
// TestKeySchemaMatchesTheStructTags keeps it in step with the json tags.
type keySchema struct {
	fields map[string]*keySchema // non-nil: an object with exactly these keys
	elem   *keySchema            // non-nil: an array of these
}

var (
	scalarKey  = &keySchema{}
	preopenKey = &keySchema{fields: map[string]*keySchema{
		"kind": scalarKey, "guestPath": scalarKey, "hostPath": scalarKey, "root": scalarKey, "readOnly": scalarKey,
	}}
	specKeys = &keySchema{fields: map[string]*keySchema{
		"version":          scalarKey,
		"module":           scalarKey,
		"preopens":         {elem: preopenKey},
		"workdir":          scalarKey,
		"memoryLimitBytes": scalarKey,
		"argv":             {elem: scalarKey},
		"env":              {elem: scalarKey},
	}}
)

// checkKeys refuses an unknown, duplicate or case-variant key anywhere in raw,
// and an object or array where the schema has none. Value types are left to
// the struct decode that follows.
func checkKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return walkKeys(dec, specKeys, "$")
}

func walkKeys(dec *json.Decoder, s *keySchema, at string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode %s: %v", at, err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar; its type is the struct decode's to check
	}
	switch d {
	case '{':
		if s.fields == nil {
			return fmt.Errorf("decode %s: unexpected object", at)
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("decode %s: %v", at, err)
			}
			k, _ := kt.(string) // object keys are always strings
			if seen[k] {
				return fmt.Errorf("decode %s: duplicate key %q", at, k)
			}
			seen[k] = true
			sub, known := s.fields[k]
			if !known {
				return fmt.Errorf("decode %s: unknown key %q (keys are case-sensitive)", at, k)
			}
			if err := walkKeys(dec, sub, at+"."+k); err != nil {
				return err
			}
		}
	case '[':
		if s.elem == nil {
			return fmt.Errorf("decode %s: unexpected array", at)
		}
		for i := 0; dec.More(); i++ {
			if err := walkKeys(dec, s.elem, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	if err != nil {
		return fmt.Errorf("decode %s: %v", at, err)
	}
	return nil
}

// HostArgs is the wasm host's parsed argument list.
type HostArgs struct {
	// SpecPath is the launch spec's path.
	SpecPath string
	// PodDir is the pod's state directory, the host's Bounds.PodDir.
	PodDir string
	// VolumeRoot is the persistent-volume root, the host's Bounds.VolumeRoot.
	// Empty when the daemon passed none; a spec with a volume outside PodDir
	// is then refused.
	VolumeRoot string
}

// Args returns the argument list (without argv[0]) that ParseArgs parses back
// to a: --spec=<path> --pod-dir=<dir>, then --volume-root=<dir> when set.
func (a HostArgs) Args() []string {
	out := []string{SpecFlag + "=" + a.SpecPath, PodDirFlag + "=" + a.PodDir}
	if a.VolumeRoot != "" {
		out = append(out, VolumeRootFlag+"="+a.VolumeRoot)
	}
	return out
}

// Bounds returns the trusted bounds the host validates its spec against.
func (a HostArgs) Bounds() Bounds {
	return Bounds{PodDir: a.PodDir, VolumeRoot: a.VolumeRoot}
}

// ParseArgs parses the wasm host's argument list (os.Args[1:]). It accepts
// --spec=<absolute path> and --pod-dir=<absolute dir>, both required, and
// --volume-root=<absolute dir>, optional, in any order, each at most once, and
// refuses anything else, so a guest argument can never be read as a host flag:
// guest argv lives only inside the spec. Neither directory may be "/".
func ParseArgs(args []string) (HostArgs, error) {
	if len(args) < 2 || len(args) > 3 {
		return HostArgs{}, fmt.Errorf("%w: got %d arguments", ErrUsage, len(args))
	}
	var a HostArgs
	for _, arg := range args {
		var dst *string
		var v string
		if p, ok := strings.CutPrefix(arg, SpecFlag+"="); ok {
			dst, v = &a.SpecPath, p
		} else if p, ok := strings.CutPrefix(arg, PodDirFlag+"="); ok {
			dst, v = &a.PodDir, p
		} else if p, ok := strings.CutPrefix(arg, VolumeRootFlag+"="); ok {
			dst, v = &a.VolumeRoot, p
		} else {
			return HostArgs{}, fmt.Errorf("%w: got %q", ErrUsage, arg)
		}
		if *dst != "" {
			return HostArgs{}, fmt.Errorf("%w: %q repeats a flag", ErrUsage, arg)
		}
		if err := checkPath(v); err != nil {
			return HostArgs{}, fmt.Errorf("%w: %q: %v", ErrUsage, arg, err)
		}
		*dst = v
	}
	switch {
	case a.SpecPath == "" || a.PodDir == "":
		return HostArgs{}, fmt.Errorf("%w: --spec and --pod-dir are both required", ErrUsage)
	case a.PodDir == "/":
		return HostArgs{}, fmt.Errorf("%w: the pod dir is the filesystem root", ErrUsage)
	case a.VolumeRoot == "/":
		return HostArgs{}, fmt.Errorf("%w: the volume root is the filesystem root", ErrUsage)
	}
	return a, nil
}
