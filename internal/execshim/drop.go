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

package execshim

import (
	"fmt"

	"k3sm.io/runtimed/pkg/supervisor"
)

// dropSeam is the identity-change subset of supervisor.LaunchSeam.
type dropSeam interface {
	Setgid(gid int) error
	Initgroups(groups []int) error
	Setuid(uid int) error
}

// dropShim moves a resident shim to the pod's credential after it spawned the
// container and before it confines itself: chown of paths (its shim dir and the
// container's log, so the descriptors it already holds for them stay usable as
// the pod user), then setgid → initgroups → setuid. A credential without a drop
// — every pod of the shipped unprivileged daemon — changes nothing; a drop is
// refused unless euid is 0 (supervisor.Credential.Validate), exactly as the
// launch sequence refuses it.
func dropShim(seam dropSeam, chown func(path string, uid, gid int) error, cred supervisor.Credential, euid int, paths ...string) error {
	if err := cred.Validate(euid); err != nil {
		return err
	}
	if !cred.Drop {
		return nil
	}
	for _, p := range paths {
		if err := chown(p, cred.UID, cred.GID); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	if err := seam.Setgid(cred.GID); err != nil {
		return fmt.Errorf("setgid(%d): %w", cred.GID, err)
	}
	if err := seam.Initgroups(cred.Groups); err != nil {
		return fmt.Errorf("initgroups %v: %w", cred.Groups, err)
	}
	if err := seam.Setuid(cred.UID); err != nil {
		return fmt.Errorf("setuid(%d): %w", cred.UID, err)
	}
	return nil
}
