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

package guestartifacts

import (
	"reflect"
	"strings"
	"testing"
)

// pinPlaceholder is the literal a re-pin carries between the source change and
// the release it names: the host-side producers that need the new initramfs
// land first, and the two values that can only be read off published assets
// are filled after publication.
const pinPlaceholder = "TODO-PUBLISH"

// TestGuestArtifactPinsAreFilled keeps an unfilled re-pin from merging.
//
// The digests of a pinned set are re-derived by downloading the published
// assets, never from local build output, so they cannot exist before the
// release does — and the source change that needs the release has to be
// reviewed before it. That change therefore carries a placeholder, and this
// test is red for exactly as long as it does.
//
// It also refuses the one wrong value a hurried fill would most likely paste:
// the previous release, whose initramfs predates the guest-side handling the
// host now relies on (guest-private mounts, native sidecars, a named image
// user). A host that emits those fields against that initramfs fails every vm
// pod that uses them at boot.
func TestGuestArtifactPinsAreFilled(t *testing.T) {
	t.Parallel()
	const releasePrefix = "https://github.com/k3sm-io/linux-guest/releases/download/v"
	const previousRelease = "v6.18.53-k3sm.1"
	if len(guestKernelPins) == 0 {
		t.Fatal("no shipped guest artifact pin; the check would be vacuous")
	}
	for key, pin := range guestKernelPins {
		v := reflect.ValueOf(pin)
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Kind() == reflect.String && strings.Contains(f.String(), pinPlaceholder) {
				t.Errorf("pin %s: %s = %q: the guest artifact pin is unfilled: publish the release, "+
					"then fill InitramfsSHA256/ReleaseURL from the downloaded assets",
					key, v.Type().Field(i).Name, f.String())
			}
		}
		if !strings.HasPrefix(pin.ReleaseURL, releasePrefix) {
			t.Errorf("pin %s: ReleaseURL %q is not a linux-guest release download (want the %q prefix)",
				key, pin.ReleaseURL, releasePrefix)
		}
		if strings.HasSuffix(pin.ReleaseURL, previousRelease) {
			t.Errorf("pin %s: ReleaseURL %q still names %s, whose initramfs predates the guest fields this host emits",
				key, pin.ReleaseURL, previousRelease)
		}
	}
}
