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
	"errors"
	"fmt"
)

// StartEffects is the executor's side of RunStart: the three things only the
// linux executor can do. It is defined here, at its consumer, so the ORDER in
// which they happen is decided by code a darwin test can run.
type StartEffects interface {
	// Compose builds one container's root: its mounts (with the ownership step
	// at its split point), its links, and its identity (ResolvePlanIdent). It
	// receives a pointer into the plan so a resolved identity lands on the
	// element every later step reads, not on a copy.
	Compose(cp *ContainerPlan) error

	// Detach applies one BootPlan.Detach step.
	Detach(step MountStep) error

	// Start spawns one container and, when cp.WaitForExit is set, waits for it
	// to exit 0. A non-zero exit of a waited container is an error.
	Start(cp ContainerPlan) error
}

// ErrIdentityPending reports a container that reached the start pass with its
// image_user still unresolved. It is a guard, not a path: Compose resolves the
// identity, and a Compose that forgot to would otherwise start the container
// with the provisional Ident, whose zero uid is root.
var ErrIdentityPending = errors.New("container identity is still pending")

// RunStart realizes the plan's containers in three passes, in this order:
//
//  1. compose every container's root, in start order;
//  2. apply BootPlan.Detach;
//  3. start every container, in start order, honouring WaitForExit.
//
// # Why three passes and not one per container
//
// A guest-private mount must be gone before any container process exists,
// and every container's root is composed out of the pod mounts, the private
// ones included (a staged share is what the per-volume binds are made from).
// Interleaving compose and start, as one loop would, leaves the private mount
// in the guest's table while init containers run; composing everything first
// is what lets the detach land after the last bind and before the first spawn.
//
// # Fail closed
//
// Any compose error, any detach error, and any container whose identity is
// still pending stops the boot before ANYTHING is started. A detach that
// failed is not logged and skipped: the mount it left in place is exactly the
// exposure the detach exists to remove.
//
// Recorded consequence: every root is composed before the first init container
// runs, so a mount an init container makes inside a shared volume does not
// reach a later container's recursive bind of that volume, and an init
// container that can chroot can reach a later container's composed root (one
// pod is one tenant; see the package doc's ceilings).
func RunStart(plan *BootPlan, fx StartEffects) error {
	for i := range plan.Containers {
		cp := &plan.Containers[i]
		if err := fx.Compose(cp); err != nil {
			return fmt.Errorf("compose container %s: %w", cp.Name, err)
		}
		if cp.PendingImageUser != "" {
			return fmt.Errorf("container %s: %w after its root was composed", cp.Name, ErrIdentityPending)
		}
	}
	for _, step := range plan.Detach {
		if err := fx.Detach(step); err != nil {
			return fmt.Errorf("detach guest-private mount %s: %w", step.Target, err)
		}
	}
	for i := range plan.Containers {
		cp := plan.Containers[i]
		if cp.PendingImageUser != "" {
			return fmt.Errorf("container %s: %w", cp.Name, ErrIdentityPending)
		}
		if err := fx.Start(cp); err != nil {
			return err
		}
	}
	return nil
}

// ShutdownPlan is the order a guest stops its containers in.
type ShutdownPlan struct {
	// Mains are stopped first, together.
	Mains []string
	// Sidecars are stopped after every main has stopped, one at a time, in
	// REVERSE start order: the sidecar started last was started to serve the
	// containers after it, and stops first.
	Sidecars []string
}

// ShutdownOrder derives the stop order from the plan's containers (which are
// in start order). A plain init container is listed with the mains: by the
// time a shutdown can happen it has normally exited, and if it has not, there
// is no later container that depends on it outliving the rest.
func ShutdownOrder(containers []ContainerPlan) ShutdownPlan {
	var out ShutdownPlan
	for _, cp := range containers {
		if cp.Sidecar {
			out.Sidecars = append(out.Sidecars, cp.Name)
			continue
		}
		out.Mains = append(out.Mains, cp.Name)
	}
	for i, j := 0, len(out.Sidecars)-1; i < j; i, j = i+1, j-1 {
		out.Sidecars[i], out.Sidecars[j] = out.Sidecars[j], out.Sidecars[i]
	}
	return out
}
