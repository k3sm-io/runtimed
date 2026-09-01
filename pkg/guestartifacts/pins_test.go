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
	"errors"
	"strings"
	"testing"
)

const (
	testImageDigest     = "1111111111111111111111111111111111111111111111111111111111111111"
	testInitramfsDigest = "abababababababababababababababababababababababababababababababab"
)

// completePin is a well-formed pin fixture: the shape the shipped table takes
// once the guest build has minted it.
func completePin() GuestKernelPin {
	return GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     testImageDigest,
		InitramfsSHA256: testInitramfsDigest,
		ReleaseURL:      "https://example.invalid/guest/v6.18.48-abc",
		Cmdline:         "console=hvc0 reboot=k panic=1",
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"64 lowercase hex", testImageDigest, true},
		{"64 hex spanning the whole alphabet", strings.Repeat("0123456789abcdef", 4), true},
		{"empty", "", false},
		{"63 characters", strings.Repeat("a", 63), false},
		{"65 characters", strings.Repeat("a", 65), false},
		{"uppercase hex", strings.Repeat("A", 64), false},
		{"non-hex letter", strings.Repeat("a", 63) + "g", false},
		{"sha256-prefixed", "sha256:" + testImageDigest, false},
		{"trailing newline", testImageDigest + "\n", false},
		{"leading space", " " + testImageDigest[1:], false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidDigest(tc.in); got != tc.want {
				t.Fatalf("IsValidDigest(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestGuestKernelPinComplete(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*GuestKernelPin)
		want bool
	}{
		{"both digests present", func(*GuestKernelPin) {}, true},
		{"image digest empty", func(p *GuestKernelPin) { p.ImageSHA256 = "" }, false},
		{"initramfs digest empty", func(p *GuestKernelPin) { p.InitramfsSHA256 = "" }, false},
		{"both digests empty", func(p *GuestKernelPin) { p.ImageSHA256, p.InitramfsSHA256 = "", "" }, false},
		// Complete answers "has the build minted this?", not "is it usable?" —
		// a malformed digest is present, so Complete is true and Lookup is what
		// rejects it. Pinning that split here keeps the two questions separable.
		{"malformed digest is still complete", func(p *GuestKernelPin) { p.ImageSHA256 = "nope" }, true},
		{"missing release url is still complete", func(p *GuestKernelPin) { p.ReleaseURL = "" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := completePin()
			tc.mut(&p)
			if got := p.Complete(); got != tc.want {
				t.Fatalf("Complete() = %v, want %v (pin %+v)", got, tc.want, p)
			}
		})
	}
}

func TestSetDigest(t *testing.T) {
	base := completePin()
	got := base.SetDigest()
	if !IsValidDigest(got) {
		t.Fatalf("SetDigest() = %q, want 64 lowercase hex characters", got)
	}
	if again := completePin().SetDigest(); again != got {
		t.Fatalf("SetDigest() is not deterministic: %q then %q", got, again)
	}

	// The set identity must move when EITHER artifact moves; a key derived from
	// the kernel alone would let a new initramfs land in an old set's directory.
	kernelMoved := base
	kernelMoved.ImageSHA256 = testInitramfsDigest
	if kernelMoved.SetDigest() == got {
		t.Fatal("SetDigest() did not change when the kernel digest changed")
	}
	initramfsMoved := base
	initramfsMoved.InitramfsSHA256 = testImageDigest
	if initramfsMoved.SetDigest() == got {
		t.Fatal("SetDigest() did not change when the initramfs digest changed")
	}
	// Swapping the two digests must not collide with the original: the hashed
	// input is field-labelled precisely so the pair is ordered.
	swapped := base
	swapped.ImageSHA256, swapped.InitramfsSHA256 = base.InitramfsSHA256, base.ImageSHA256
	if swapped.SetDigest() == got {
		t.Fatal("SetDigest() collides when the two digests are swapped")
	}
	// Fields that do not describe the BYTES must not move the key, or a release
	// re-host would orphan a perfectly good cache.
	rehosted := base
	rehosted.ReleaseURL = "https://elsewhere.invalid/guest"
	rehosted.Cmdline = "console=hvc0"
	rehosted.KernelVersion = "v6.18.49"
	if rehosted.SetDigest() != got {
		t.Fatal("SetDigest() changed for a pin whose artifact digests are identical")
	}
}

func TestLookup(t *testing.T) {
	malformed := completePin()
	malformed.ImageSHA256 = "abc"
	upper := completePin()
	upper.InitramfsSHA256 = strings.ToUpper(testInitramfsDigest)
	unminted := completePin()
	unminted.ImageSHA256, unminted.InitramfsSHA256 = "", ""
	noRelease := completePin()
	noRelease.ReleaseURL = ""

	table := map[string]GuestKernelPin{
		"v6.18.48-good":      completePin(),
		"v6.18.48-malformed": malformed,
		"v6.18.48-upper":     upper,
		"v6.18.48-unminted":  unminted,
		"v6.18.48-norelease": noRelease,
	}

	tests := []struct {
		name    string
		version string
		wantErr error
		// wantMsg is a substring the error message must carry, so two cases
		// that share a sentinel are still told apart by what an operator reads.
		wantMsg string
	}{
		{name: "a complete pin resolves", version: "v6.18.48-good"},
		{name: "unknown version", version: "v6.18.48-nope", wantErr: ErrUnknownVersion, wantMsg: "v6.18.48-nope"},
		{name: "empty version", version: "", wantErr: ErrUnknownVersion, wantMsg: "the version is empty"},
		{name: "entry incomplete", version: "v6.18.48-unminted", wantErr: ErrPinIncomplete, wantMsg: "has not been minted"},
		{name: "malformed hex digest", version: "v6.18.48-malformed", wantErr: ErrPinIncomplete, wantMsg: "malformed ImageSHA256"},
		{name: "uppercase hex digest", version: "v6.18.48-upper", wantErr: ErrPinIncomplete, wantMsg: "malformed InitramfsSHA256"},
		{name: "no release url", version: "v6.18.48-norelease", wantErr: ErrPinIncomplete, wantMsg: "names no release url"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := lookupIn(table, tc.version)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("lookupIn(%q) = %v, want no error", tc.version, err)
				}
				if got != completePin() {
					t.Fatalf("lookupIn(%q) = %+v, want %+v", tc.version, got, completePin())
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("lookupIn(%q) error = %v, want errors.Is %v", tc.version, err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("lookupIn(%q) error = %q, want it to mention %q", tc.version, err, tc.wantMsg)
			}
			if got != (GuestKernelPin{}) {
				t.Fatalf("lookupIn(%q) returned a pin alongside an error: %+v", tc.version, got)
			}
		})
	}

	// The SHIPPED table, through the exported entry point. The assertion is
	// deliberately two-sided so it stays true across the commit that mints the
	// digests: before, the pin is refused with ErrPinIncomplete; after, it
	// resolves and every field is usable. What it forbids is the state in
	// between — a pin that resolves while carrying something unfetchable.
	t.Run("the shipped active pin either resolves or fails closed", func(t *testing.T) {
		p, err := Lookup(ActiveGuestKernel)
		switch {
		case err == nil:
			if !IsValidDigest(p.ImageSHA256) || !IsValidDigest(p.InitramfsSHA256) {
				t.Fatalf("Lookup(%q) resolved with digests that are not 64 lowercase hex: %+v", ActiveGuestKernel, p)
			}
			if p.ReleaseURL == "" || p.Cmdline == "" || p.KernelVersion == "" {
				t.Fatalf("Lookup(%q) resolved with an unusable pin: %+v", ActiveGuestKernel, p)
			}
		case errors.Is(err, ErrPinIncomplete):
			// The shipped state while the guest build has not run.
		default:
			t.Fatalf("Lookup(%q) = %v, want nil or ErrPinIncomplete", ActiveGuestKernel, err)
		}
	})

	t.Run("every declared pin is reachable by its own key", func(t *testing.T) {
		if len(guestKernelPins) == 0 {
			t.Fatal("the shipped pin table is empty — no guest kernel can ever be resolved")
		}
		for version, p := range guestKernelPins {
			if version == "" {
				t.Error("the shipped pin table carries an empty version key")
			}
			if p.KernelVersion == "" {
				t.Errorf("the pin keyed %q declares no KernelVersion", version)
			}
			if p.Cmdline == "" {
				t.Errorf("the pin keyed %q declares no Cmdline", version)
			}
		}
		if _, ok := guestKernelPins[ActiveGuestKernel]; !ok {
			t.Fatalf("ActiveGuestKernel is %q but the pin table declares no such entry", ActiveGuestKernel)
		}
	})
}
