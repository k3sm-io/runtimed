//go:build !(darwin && cgo)

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
	"errors"

	"k3sm.io/runtimed/pkg/supervisor"
)

// ErrUnsupported reports that the libsandbox exec-shim is only available on
// darwin with cgo enabled.
var ErrUnsupported = errors.New("execshim: libsandbox confinement requires darwin+cgo")

// RunPodLaunch is unsupported off darwin/cgo; it returns ErrUnsupported so the
// helper fails closed rather than execing a pod unconfined.
func RunPodLaunch(profile string, argv []string, cred supervisor.Credential) error {
	return ErrUnsupported
}
