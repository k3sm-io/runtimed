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

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// ErrGuestArtifactsNotSettable reports that this Runtime's vm backend cannot
// take a guest-artifact locator after construction (an injected VMBackend that
// is not a *sandbox.VMBackend). Compare with errors.Is.
var ErrGuestArtifactsNotSettable = errors.New("runtime: the vm backend does not accept guest artifacts after construction")

// guestArtifactSetter is the slice of the vm backend RefreshGuestArtifacts
// needs; *sandbox.VMBackend satisfies it.
type guestArtifactSetter interface {
	SetGuestArtifacts(locator sandbox.GuestArtifactLocator)
}

var _ guestArtifactSetter = (*sandbox.VMBackend)(nil)

// GuestClusterStore returns the cluster store a worker fills its guest-artifact
// cache from (guestartifacts.EnsureGuestArtifactsFromStore). It pulls through
// this Runtime's own artifact puller and reads its own blob cache, so the pull
// shares the node's one image index, its store lock and its index observer.
// cred authenticates to the cluster registry; nil pulls anonymously.
//
// With no cluster registry configured (or an injected ArtifactPuller that is
// not an *artifact.Puller) the store has no puller, and PullGuest fails closed.
func (r *Runtime) GuestClusterStore(cred *image.RegistryCredential) *artifact.GuestStore {
	return &artifact.GuestStore{Puller: r.guestPuller, Blobs: r.cache, Cred: cred}
}

// RefreshGuestArtifacts wires a guest-artifact set ensured after New into the
// vm backend, so vm pods stop failing closed with
// sandbox.ErrGuestArtifactsUnavailable. The set is verified against pin first
// and the call changes nothing if it does not verify; once installed it is
// re-verified on every boot (guestartifacts.Locator). Safe for concurrent use.
func (r *Runtime) RefreshGuestArtifacts(pin guestartifacts.GuestKernelPin, art sandbox.GuestArtifacts) error {
	setter, ok := r.vmBackend.(guestArtifactSetter)
	if !ok {
		return ErrGuestArtifactsNotSettable
	}
	locator := guestartifacts.Locator(pin, art)
	if _, err := locator(); err != nil {
		return fmt.Errorf("refresh the guest artifacts: %w", err)
	}
	setter.SetGuestArtifacts(locator)
	return nil
}
