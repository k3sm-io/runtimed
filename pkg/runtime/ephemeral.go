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

package runtime

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Ephemeral (debug) containers: PodBox.ephemeral_containers.
//
// They arrive only by UpdatePod appending to the list, and each one is started
// once, exactly like any other container of the pod and under nothing the
// caller can widen:
//
//   - the image goes through the same resolve path as every container
//     (startContainer → resolveBinary): the pull under the pod's platform
//     policy, materialization into the pod's own rootfs, ad-hoc signing, and the
//     signature gate under the pod's CREATE-TIME signature policy;
//   - the process is confined by the pod's compiled profile (p.profile), which
//     an append never recompiles or widens; an image that needs paths outside it
//     fails at its first access, closed;
//   - its process group is recorded in the reap ledger like any container's, so
//     a daemon crash leaves it for the startup reap, not orphaned, and DeletePod
//     stops it with the mains.
//
// They are never restarted, never decide the pod's phase, and report under
// ephemeral_container_statuses. A vm pod cannot start one: guest/v1 has no
// verb to start a container in a booted guest.

// errEphemeralOnVM is the vm backend's answer to an ephemeral append.
var errEphemeralOnVM = errors.New("ephemeral containers are not supported on the vm RuntimeClass")

// ephemeralNotStartedReason is the terminated reason of an ephemeral container
// a re-created pod lists: it is not started, because ephemeral containers are
// never restarted. It is the kubelet's reason for a container whose state could
// not be recovered.
const ephemeralNotStartedReason = "ContainerStatusUnknown"

// ephemeralNotStartedExitCode is the exit code the kubelet reports with
// ContainerStatusUnknown.
const ephemeralNotStartedExitCode = 137

// maxContainerNameLen is a DNS-1123 label's limit, which is what a Kubernetes
// container name is.
const maxContainerNameLen = 63

// validContainerLabel reports whether name is a DNS-1123 label. The name
// becomes a directory under the pod's log tree and a key in the reap ledger, so
// anything with a separator or a dot segment is refused before it reaches
// either.
func validContainerLabel(name string) error {
	if name == "" || len(name) > maxContainerNameLen {
		return fmt.Errorf("container name %q must be 1 to %d characters", name, maxContainerNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && (c != '-' || i == 0 || i == len(name)-1) {
			return fmt.Errorf("container name %q is not a DNS-1123 label", name)
		}
	}
	return nil
}

// checkEphemeralNamesLocked refuses an append whose names are not labels, or
// collide with any init, regular or ephemeral container of the pod or with each
// other. Caller holds p.mu.
func checkEphemeralNamesLocked(p *pod, appends []*runtimev1.Container) error {
	taken := map[string]bool{}
	for _, list := range [][]*runtimev1.Container{
		p.box.GetInitContainers(), p.box.GetContainers(), p.box.GetEphemeralContainers(),
	} {
		for _, c := range list {
			taken[c.GetName()] = true
		}
	}
	for _, cp := range p.containers {
		taken[cp.name] = true
	}
	for _, c := range appends {
		if err := validContainerLabel(c.GetName()); err != nil {
			return err
		}
		if taken[c.GetName()] {
			return fmt.Errorf("container name %q is already used in pod %s", c.GetName(), p.box.GetPodId())
		}
		taken[c.GetName()] = true
	}
	return nil
}

// ephemeralRefusal is an UpdatePod answer for an append that cannot proceed.
type ephemeralRefusal struct {
	code   codes.Code
	reason runtimev1.FailureReason
	err    error
}

// reserveEphemeralLocked decides an append and, when it may proceed, reserves
// it: each new container gets a Waiting placeholder in p.containers holding
// the single-flight start claim, and its spec is appended to the STORED box.
// It returns the placeholders to start, in order. Caller holds p.mu, and the
// append compare has already run under the same hold.
//
// Reserving under the lock is what makes two concurrent appends of one name
// spawn once: the second request's compare then sees the name already in the
// stored list and has nothing to append (or is a mutation, if its spec
// differs).
func reserveEphemeralLocked(p *pod, appends []*runtimev1.Container) ([]*containerProc, *ephemeralRefusal) {
	switch {
	case p.isVM():
		return nil, &ephemeralRefusal{codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED, errEphemeralOnVM}
	case p.stopping:
		return nil, &ephemeralRefusal{codes.FailedPrecondition, installFailureReason(errPodStopping), errPodStopping}
	case p.phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED || p.phase == runtimev1.PodPhase_POD_PHASE_FAILED:
		return nil, &ephemeralRefusal{codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			fmt.Errorf("pod %s has terminated; an ephemeral container cannot be added", p.box.GetPodId())}
	}
	if err := checkEphemeralNamesLocked(p, appends); err != nil {
		return nil, &ephemeralRefusal{codes.InvalidArgument, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX, err}
	}
	stored := append([]*runtimev1.Container{}, p.box.GetEphemeralContainers()...)
	placeholders := make([]*containerProc, 0, len(appends))
	for _, c := range appends {
		// A copy: the stored box must not alias the caller's request message.
		spec, _ := proto.Clone(c).(*runtimev1.Container)
		stored = append(stored, spec)
		cp := &containerProc{
			name:      spec.GetName(),
			spec:      spec,
			ephemeral: true,
			starting:  true,
			state: &runtimev1.ContainerStatus{
				Name:  spec.GetName(),
				Image: spec.GetImage(),
				State: &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
			},
		}
		p.containers = append(p.containers, cp)
		placeholders = append(placeholders, cp)
	}
	p.box.EphemeralContainers = stored
	return placeholders, nil
}

// startEphemeral starts one reserved ephemeral container through the shared
// container path and installs it over its placeholder. It is called with no
// lock held: the image step can take seconds. A failure leaves the placeholder
// Waiting with the typed reason; a spawn that cannot be installed (the pod
// began deleting meanwhile) is SIGKILLed, never left untracked.
func (r *Runtime) startEphemeral(p *pod, placeholder *containerProc) {
	fail := func(reason runtimev1.FailureReason, err error) {
		r.log.Warn("ephemeral container could not be started",
			"pod", p.box.GetPodId(), "container", placeholder.name, "reason", reason.String(), "err", err)
		p.mu.Lock()
		placeholder.state.State = &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{
			Message: boundedFailureMessage(err), FailureReason: reason,
		}}
		releaseStartClaimLocked(placeholder)
		p.mu.Unlock()
	}
	rootfs, err := r.rootfsPath(p.box)
	if err != nil {
		fail(runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX, err)
		return
	}
	// Under the pod-lifetime context, as every spawn is: the process and its
	// supervision outlive this RPC.
	cp, reason, err := r.startContainer(p.supCtx, p, rootfs, placeholder.spec, false, 0)
	if err != nil {
		fail(reason, err)
		return
	}
	p.mu.Lock()
	cp.ephemeral = true
	// The SECOND stopping check, the one with no pull between it and the
	// install (installContainerLocked): a DeletePod that began during the image
	// step has already snapshotted what it will signal.
	ierr := installContainerLocked(p, cp, nil)
	releaseStartClaimLocked(placeholder)
	p.mu.Unlock()
	if ierr != nil {
		r.killUntrackedSpawn(p.supCtx, p, cp, ierr.Error())
	}
}

// recordEphemeralNotStartedLocked records every ephemeral container the box
// lists as terminated and not started. It runs when a pod is (re-)created or
// re-attached after a daemon restart: an ephemeral container is never
// restarted, and the one that ran before is not this daemon's to resume (the
// startup reap collects its process group). Caller holds p.mu, or owns p
// exclusively.
func recordEphemeralNotStartedLocked(p *pod) {
	for _, c := range p.box.GetEphemeralContainers() {
		p.containers = append(p.containers, &containerProc{
			name:      c.GetName(),
			spec:      c,
			ephemeral: true,
			state: &runtimev1.ContainerStatus{
				Name:  c.GetName(),
				Image: c.GetImage(),
				State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
					ExitCode:   ephemeralNotStartedExitCode,
					Reason:     ephemeralNotStartedReason,
					Message:    "ephemeral containers are never restarted; this one was not running when the runtime re-created the pod",
					FinishedAt: nowProto(),
				}},
			},
		})
	}
}
