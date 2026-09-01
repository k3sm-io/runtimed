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

package guestagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The cgroup2 interface files this package reads or writes, named once.
//
// SampleFiles are exactly the three the Sampler needs, and they are listed here
// rather than restated in a test: a leaf that does not carry all three produces
// no sample at all (a partially-read sample is not a sample — see
// ContainerSample), so "which files must exist" is a property of the leaf, not of
// the reader.
const (
	// ControllersFile lists the controllers a cgroup's parent made available.
	ControllersFile = "cgroup.controllers"
	// SubtreeControlFile enables controllers for a cgroup's CHILDREN. A leaf's
	// memory.* files exist only because its PARENT enabled memory here.
	SubtreeControlFile = "cgroup.subtree_control"
	// ProcsFile is the membership file: writing a pid moves that whole thread
	// group into the cgroup.
	ProcsFile = "cgroup.procs"
)

// SampleFiles are the interface files cgroupSampler reads from a leaf.
var SampleFiles = []string{"cpu.stat", "memory.current", "memory.stat"}

// StatsControllers are the cgroup2 controllers whose presence in a parent's
// subtree_control is what creates SampleFiles in its children. cpu.stat exists in
// every v2 cgroup, but memory.current and memory.stat do not: they appear only
// when the memory controller is delegated downward.
var StatsControllers = []string{"cpu", "memory"}

// ErrInvalidCgroupName reports a container name that cannot be a cgroup leaf
// directory component.
var ErrInvalidCgroupName = errors.New("guestagent: invalid cgroup leaf name")

// LeafPath returns the cgroup2 leaf directory for a container under root.
//
// The container name becomes a single path COMPONENT, so it is validated where it
// turns into one: a name containing a separator, or "." / "..", would address a
// sibling or an ancestor of the hierarchy root — and the leaf is a directory this
// guest creates and writes pids into. The name reaching here came from the pod
// spec by way of the host, and Kubernetes' own DNS-1123 rule already makes it a
// single component; this is the fail-closed check that does not depend on that
// staying true.
func LeafPath(root, container string) (string, error) {
	if container == "" {
		return "", fmt.Errorf("%w: empty name", ErrInvalidCgroupName)
	}
	if container == "." || container == ".." || strings.ContainsAny(container, `/\`) {
		return "", fmt.Errorf("%w: %q must be a single path component", ErrInvalidCgroupName, container)
	}
	if filepath.Clean(container) != container {
		return "", fmt.Errorf("%w: %q is not a clean path component", ErrInvalidCgroupName, container)
	}
	return filepath.Join(root, container), nil
}

// AvailableControllers returns the controllers root's own cgroup.controllers
// lists, which is the set root may delegate to its children.
func AvailableControllers(root string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, ControllersFile))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Join(root, ControllersFile), err)
	}
	return strings.Fields(string(raw)), nil
}

// EnableSubtreeControllers delegates each of want that root actually has to
// root's children, and returns the ones enabled.
//
// ONE WRITE PER CONTROLLER, deliberately. The kernel rejects a whole
// subtree_control write if any token in it is unacceptable, so "+cpu +memory" in
// one write on a kernel built without CONFIG_CGROUP_SCHED loses the memory
// controller too — and memory is the one that carries the OOM truth. Writing them
// separately degrades one controller at a time.
//
// A controller root does not list is skipped rather than attempted: it cannot be
// delegated, and asking produces an error that says less than the skip does.
// Requesting a controller ALREADY enabled is not an error — the write is
// idempotent — so this is safe to call once per boot without checking first.
func EnableSubtreeControllers(root string, want []string) ([]string, error) {
	have, err := AvailableControllers(root)
	if err != nil {
		return nil, err
	}
	available := make(map[string]bool, len(have))
	for _, c := range have {
		available[c] = true
	}
	path := filepath.Join(root, SubtreeControlFile)
	var enabled []string
	var errs []error
	for _, c := range want {
		if !available[c] {
			errs = append(errs, fmt.Errorf("controller %q is not available at %s", c, root))
			continue
		}
		if err := appendLine(path, "+"+c); err != nil {
			errs = append(errs, fmt.Errorf("enable controller %q: %w", c, err))
			continue
		}
		enabled = append(enabled, c)
	}
	return enabled, errors.Join(errs...)
}

// CreateLeaf creates (or reuses) the cgroup2 leaf for a container and returns its
// path. Creating a cgroup2 directory is what makes the kernel populate its
// interface files, so there is nothing else to write.
func CreateLeaf(root, container string) (string, error) {
	leaf, err := LeafPath(root, container)
	if err != nil {
		return "", err
	}
	// 0755 is what the kernel gives a cgroup dir anyway; cgroupfs ignores the
	// mode on the directory it synthesizes, and MkdirAll makes the call
	// idempotent for a leaf a previous boot step already created.
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return "", fmt.Errorf("create cgroup leaf %s: %w", leaf, err)
	}
	return leaf, nil
}

// JoinLeaf moves pid's thread group into the leaf by writing it to cgroup.procs.
//
// It is a RECONCILE, not the primary mechanism: the container is placed into its
// leaf by the kernel at fork time (CLONE_INTO_CGROUP, via
// syscall.SysProcAttr.UseCgroupFD in the guest's spawn), which is atomic and
// cannot race the child's first instruction. This exists for the case where that
// path did not apply — an older kernel without clone3 — and for that case only.
// Writing a pid already in the cgroup succeeds and changes nothing, so calling it
// unconditionally is safe.
func JoinLeaf(leaf string, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("%w: pid %d", ErrInvalidCgroupName, pid)
	}
	if err := appendLine(filepath.Join(leaf, ProcsFile), strconv.Itoa(pid)); err != nil {
		return fmt.Errorf("join cgroup %s: %w", leaf, err)
	}
	return nil
}

// appendLine writes one line to a cgroup2 interface file.
//
// ONE write(2), and no O_APPEND / no trailing newline batching: the kernel parses
// a cgroup2 interface write per call, so a split write is two malformed commands
// rather than one good one — the same rule registerBinfmt states for
// binfmt_misc. O_WRONLY without O_CREATE|O_TRUNC because the file always exists
// and is not a regular file to be truncated.
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("write %q to %s: %w", line, path, err)
	}
	return nil
}
