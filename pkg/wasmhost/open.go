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
	"strings"

	"golang.org/x/sys/unix"
)

// OpenedPreopen is a preopen and the directory descriptor OpenPreopens reached
// it through.
type OpenedPreopen struct {
	Preopen
	// Dir is the open directory. The engine hands this descriptor, never
	// Preopen.HostPath, to the guest's filesystem view.
	Dir *os.File
}

// Opened is the descriptors of a validated spec: one directory per preopen,
// in spec order, and the module file.
type Opened struct {
	Preopens []OpenedPreopen
	// Module is the open module file. The engine reads the module from it.
	Module *os.File
}

// Close closes every descriptor. It returns the first error.
func (o *Opened) Close() error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, p := range o.Preopens {
		keep(p.Dir.Close())
	}
	if o.Module != nil {
		keep(o.Module.Close())
	}
	return first
}

// OpenPreopens opens every preopen and the module of v by descriptor. Each walk
// starts at the trusted bound the path was validated under (opened with
// O_NOFOLLOW) and descends one component at a time with openat(O_NOFOLLOW), a
// directory at every step, so a component swapped for a symlink after Validate
// ran fails the open instead of redirecting it. The module is opened the same
// way from the rootfs descriptor and must be a regular file.
//
// Validate proves what the paths were; this is what makes the engine act on
// that and nothing else. An Engine MUST obtain its directories and module
// through OpenPreopens and never reopen a host path by name. The caller owns
// the result and closes it.
func OpenPreopens(v Validated) (*Opened, error) {
	if !v.Valid() {
		return nil, fmt.Errorf("open preopens: %w: not a validated spec", ErrInvalidSpec)
	}
	o := &Opened{}
	ok := false
	defer func() {
		if !ok {
			_ = o.Close() // the failure path; the open error is what is returned
		}
	}()
	for i, p := range v.spec.Preopens {
		bound, found := v.bounds.boundOf(p.HostPath)
		if !found {
			return nil, fmt.Errorf("open preopen %d: %w: %s is under no bound", i, ErrInvalidSpec, p.HostPath)
		}
		d, err := openUnder(bound, p.HostPath)
		if err != nil {
			return nil, fmt.Errorf("open preopen %d: %w", i, err)
		}
		o.Preopens = append(o.Preopens, OpenedPreopen{Preopen: p, Dir: d})
	}
	rootfs := o.Preopens[0]
	m, err := openFileAt(rootfs.Dir, rootfs.HostPath, v.spec.Module)
	if err != nil {
		return nil, fmt.Errorf("open module: %w", err)
	}
	o.Module = m
	ok = true
	return o, nil
}

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

// openUnder opens target, a directory at or under bound, one component at a
// time. The bound itself is opened by name with O_NOFOLLOW on its last
// component: it is trusted configuration, and nothing above it is checked (the
// pkg/pathsafe doctrine).
func openUnder(bound, target string) (*os.File, error) {
	fd, err := unix.Open(bound, dirFlags, 0)
	if err != nil {
		return nil, refusal(bound, err)
	}
	return descend(fd, bound, strings.TrimPrefix(strings.TrimPrefix(target, bound), "/"))
}

// descend walks rel (slash-separated, possibly empty) from the open directory
// fd, which it consumes, and returns the final directory.
func descend(fd int, at, rel string) (*os.File, error) {
	if rel != "" {
		for _, c := range strings.Split(rel, "/") {
			next, err := unix.Openat(fd, c, dirFlags, 0)
			_ = unix.Close(fd) // the parent is done with either way
			at += "/" + c
			if err != nil {
				return nil, refusal(at, err)
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), at), nil
}

// openFileAt opens file, a regular file under dirPath, from dir's descriptor.
func openFileAt(dir *os.File, dirPath, file string) (*os.File, error) {
	rel := strings.TrimPrefix(file, dirPath+"/")
	parentRel, name := "", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		parentRel, name = rel[:i], rel[i+1:]
	}
	dfd, err := unix.Dup(int(dir.Fd()))
	if err != nil {
		return nil, fmt.Errorf("dup %s: %w", dirPath, err)
	}
	parent, err := descend(dfd, dirPath, parentRel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }() // only the leaf descriptor is kept
	fd, err := unix.Openat(int(parent.Fd()), name, fileFlags, 0)
	if err != nil {
		return nil, refusal(file, err)
	}
	f := os.NewFile(uintptr(fd), file)
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // refusing; the stat error is what is returned
		return nil, fmt.Errorf("stat %s: %w", file, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close() // refusing
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidSpec, file)
	}
	return f, nil
}

// refusal maps a symlink or non-directory met mid-walk to ErrInvalidSpec, and
// passes any other error through as a path error.
func refusal(at string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%w: %s is a symlink or not a directory", ErrInvalidSpec, at)
	}
	return &fs.PathError{Op: "open", Path: at, Err: err}
}
