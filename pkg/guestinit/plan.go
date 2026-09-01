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

package guestinit

import (
	"fmt"
	"path"
	"strings"

	guestv1 "k3sm.io/apis/guest/v1"
)

// Phase is when in the boot a container starts.
type Phase string

// The two start phases. guest/v1 expresses exactly this distinction and no
// other (see the package doc's sidecar ceiling).
const (
	// PhaseInit is an init container: it runs to completion, in list order,
	// before any main container starts.
	PhaseInit Phase = "init"

	// PhaseMain is a main container: it starts after every init container has
	// exited 0, and it is not waited for.
	PhaseMain Phase = "main"
)

// ContainerPlan is everything needed to start one container: the mounts that
// compose its rootfs and its view of the pod, the identity it runs as, and the
// process to exec.
type ContainerPlan struct {
	// Name is the container name, unique within the pod.
	Name string

	// Phase and WaitForExit are the ordering contract: an init container is
	// waited for, a main container is not.
	Phase       Phase
	WaitForExit bool

	// Mounts compose this container's rootfs, in application order: the
	// rootfs overlay, the pod mounts re-exposed inside it, then the /etc bind
	// set. The /etc binds come last so nothing can be stacked over them.
	Mounts []MountStep

	// Root is the composed rootfs the process is chrooted into.
	Root string

	// Argv is the process argv, already merged host-side against the image
	// config; Argv[0] is the program.
	Argv []string

	// Env are fully resolved KEY=value entries.
	Env []string

	// WorkingDir is the working directory inside Root; empty means "/".
	WorkingDir string

	// Ident is the identity the process runs as.
	Ident Ident

	// TTY and Stdin mirror the pod spec's terminal requests.
	TTY   bool
	Stdin bool
}

// BootPlan is the whole boot, as data. The executor walks it top to bottom and
// makes no decisions of its own.
type BootPlan struct {
	// Pseudo are the kernel filesystems, mounted first.
	Pseudo []MountStep

	// Hostname is the guest hostname.
	Hostname string

	// Etc is the pod-level /etc content written under EtcDir and bound into
	// every container.
	Etc EtcFiles

	// PodMounts are the pod-level mounts, applied once before any container.
	PodMounts []MountStep

	// Binfmt is the Rosetta registration, or nil when the pod was booted
	// without the Rosetta share.
	Binfmt *BinfmtRegistration

	// Containers are the containers in START order: every init container
	// first, then the mains.
	Containers []ContainerPlan

	// Warnings are non-fatal observations for the boot log (a truncated search
	// list, a dropped nameserver).
	Warnings []string
}

// Options are the guest facts the spec does not carry.
type Options struct {
	// MemTotalBytes is the guest's total RAM, used to bound each container's
	// overlay upper. Zero means unknown, which takes the default bound rather
	// than an unbounded upper (see UpperSizeBytes).
	MemTotalBytes int64
}

// Plan turns a GuestSpec into the boot plan. It is pure: it touches no
// filesystem and starts nothing.
//
// Every rejection is fail-closed. The executor is PID 1 of a VM that exists to
// run exactly this pod, so a spec it cannot realize has no degraded mode worth
// having: refusing with a legible reason produces a pod failure event, whereas
// booting a partial pod produces a workload that is subtly wrong.
func Plan(spec *guestv1.GuestSpec, opts Options) (*BootPlan, error) {
	if spec == nil {
		return nil, fmt.Errorf("%w: nil spec", ErrInvalidSpec)
	}
	if spec.GetAgentPort() == 0 || spec.GetAgentPort() > 65535 {
		return nil, fmt.Errorf("%w: agent_port %d is not a usable vsock port",
			ErrInvalidSpec, spec.GetAgentPort())
	}
	if err := checkID("fsGroup", spec.GetFsGroup()); err != nil {
		return nil, err
	}

	plan := &BootPlan{Pseudo: PseudoMounts(), Hostname: spec.GetHostname()}

	resolv, warnings := RenderResolvConf(spec.GetResolvConf())
	plan.Warnings = append(plan.Warnings, warnings...)
	plan.Etc = EtcFiles{
		ResolvConf: resolv,
		Hosts:      RenderHosts(spec.GetHostname(), ""),
		Hostname:   RenderHostname(spec.GetHostname()),
	}
	if spec.GetHostname() == "" {
		plan.Warnings = append(plan.Warnings, "spec carries no hostname; the guest keeps the kernel default")
	}

	podMounts, err := PodMounts(spec.GetMounts(), spec.GetFsGroup())
	if err != nil {
		return nil, err
	}
	plan.PodMounts = podMounts

	if spec.GetRosetta() {
		reg := RosettaBinfmt()
		plan.Binfmt = &reg
	}

	ordered, err := StartOrder(spec.GetContainers())
	if err != nil {
		return nil, err
	}
	upperSize := UpperSizeBytes(opts.MemTotalBytes, len(ordered))
	for _, step := range ordered {
		cp, err := containerPlan(step, spec.GetFsGroup(), podMounts, upperSize)
		if err != nil {
			return nil, err
		}
		plan.Containers = append(plan.Containers, cp)
	}
	return plan, nil
}

// StartStep is one container paired with the phase the ordering put it in.
type StartStep struct {
	Container *guestv1.GuestContainer
	Phase     Phase

	// WaitForExit is true for an init container: the next container does not
	// start until this one has exited 0.
	//
	// It is derived from GuestContainer.init and nothing else, because that is
	// the only ordering bit guest/v1 carries. A native sidecar — an init
	// container with restartPolicy: Always, which by definition never exits —
	// cannot be told apart here and would hang the boot; the package doc
	// records that ceiling and this field is the one place it is decided.
	WaitForExit bool
}

// StartOrder applies the pod's start ordering: every init container, in list
// order, then every main container, in list order.
//
// The spec documents its containers as already being in start order, but the
// ordering is APPLIED here rather than assumed. A producer bug that emitted a
// main container ahead of an init container would otherwise start the workload
// before its initialization ran — a data-corrupting ordering failure that no
// later check catches — and the fix costs a stable partition.
func StartOrder(containers []*guestv1.GuestContainer) ([]StartStep, error) {
	if len(containers) == 0 {
		return nil, fmt.Errorf("%w: the pod has no containers", ErrInvalidSpec)
	}
	seen := map[string]bool{}
	var inits, mains []StartStep
	for i, c := range containers {
		if c == nil {
			return nil, fmt.Errorf("%w: containers[%d] is nil", ErrInvalidSpec, i)
		}
		if err := validContainerName(c.GetName()); err != nil {
			return nil, fmt.Errorf("containers[%d]: %w", i, err)
		}
		if seen[c.GetName()] {
			return nil, fmt.Errorf("%w: duplicate container name %q", ErrInvalidSpec, c.GetName())
		}
		seen[c.GetName()] = true
		if c.GetInit() {
			inits = append(inits, StartStep{Container: c, Phase: PhaseInit, WaitForExit: true})
			continue
		}
		mains = append(mains, StartStep{Container: c, Phase: PhaseMain})
	}
	if len(mains) == 0 {
		return nil, fmt.Errorf("%w: the pod has only init containers", ErrInvalidSpec)
	}
	return append(inits, mains...), nil
}

// validContainerName rejects a name that cannot be used as a path element.
//
// The name is a component of every per-container path this package composes
// (ContainerRootDir and friends), so a name containing a separator or a dot
// segment would place a container's rootfs somewhere the plan did not intend —
// including over another container's.
func validContainerName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty container name", ErrInvalidSpec)
	case strings.ContainsAny(name, "/\x00"):
		return fmt.Errorf("%w: container name %q contains a path separator", ErrInvalidSpec, name)
	case name == "." || name == "..":
		return fmt.Errorf("%w: container name %q is a path dot segment", ErrInvalidSpec, name)
	case path.Clean(name) != name:
		return fmt.Errorf("%w: container name %q is not a clean path element", ErrInvalidSpec, name)
	}
	return nil
}

// containerPlan builds one container's plan.
func containerPlan(step StartStep, fsGroup int64, podMounts []MountStep, upperSize int64) (ContainerPlan, error) {
	c := step.Container
	argv := append(append([]string{}, c.GetCommand()...), c.GetArgs()...)
	if len(argv) == 0 {
		return ContainerPlan{}, fmt.Errorf("%w: container %q has an empty argv", ErrInvalidSpec, c.GetName())
	}
	for _, e := range c.GetEnv() {
		if !strings.Contains(e, "=") {
			return ContainerPlan{}, fmt.Errorf("%w: container %q env entry %q is not KEY=VALUE",
				ErrInvalidSpec, c.GetName(), e)
		}
	}
	if wd := c.GetWorkingDir(); wd != "" {
		if err := validTarget(wd); err != nil {
			return ContainerPlan{}, fmt.Errorf("container %q working_dir: %w", c.GetName(), err)
		}
	}
	ident, err := ContainerIdent(c, fsGroup)
	if err != nil {
		return ContainerPlan{}, err
	}
	rootfs, err := RootfsMounts(c.GetName(), c.GetRootfsTag(), upperSize)
	if err != nil {
		return ContainerPlan{}, err
	}
	mounts := rootfs
	mounts = append(mounts, containerVisibleMounts(c.GetName(), podMounts)...)
	mounts = append(mounts, EtcBinds(c.GetName())...)
	return ContainerPlan{
		Name:        c.GetName(),
		Phase:       step.Phase,
		WaitForExit: step.WaitForExit,
		Mounts:      mounts,
		Root:        ContainerRootDir(c.GetName()),
		Argv:        argv,
		Env:         append([]string{}, c.GetEnv()...),
		WorkingDir:  c.GetWorkingDir(),
		Ident:       ident,
		TTY:         c.GetTty(),
		Stdin:       c.GetStdin(),
	}, nil
}
