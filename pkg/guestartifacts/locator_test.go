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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
)

// stageLocator writes a verified set into a fresh cache and returns the pin and
// the artifacts a locator is built over — the exact pair EnsureGuestArtifacts
// hands the daemon.
func stageLocator(t *testing.T) (GuestKernelPin, sandbox.GuestArtifacts) {
	t.Helper()
	dir := t.TempDir()
	pin := testPin()
	setDir := stageSet(t, dir, pin, testKernelBytes, testInitramfsBytes)
	return pin, sandbox.GuestArtifacts{
		KernelPath:    filepath.Join(setDir, ImageFileName),
		InitramfsPath: filepath.Join(setDir, InitramfsFileName),
		Cmdline:       pin.Cmdline,
	}
}

func TestLocator(t *testing.T) {
	t.Run("verified artifacts are returned unchanged", func(t *testing.T) {
		pin, art := stageLocator(t)
		got, err := Locator(pin, art)()
		if err != nil {
			t.Fatalf("Locator: %v", err)
		}
		if got != art {
			t.Fatalf("Locator returned %+v, want %+v", got, art)
		}
	})

	t.Run("every call re-hashes rather than caching the first verdict", func(t *testing.T) {
		pin, art := stageLocator(t)
		locate := Locator(pin, art)
		for i := 0; i < 3; i++ {
			if _, err := locate(); err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		}
		// The witness that the hash is recomputed and not remembered: the file
		// is removed AFTER three good calls, and the fourth must notice.
		if err := os.Remove(art.KernelPath); err != nil {
			t.Fatalf("remove the kernel: %v", err)
		}
		if _, err := locate(); err == nil {
			t.Fatal("the locator succeeded after its kernel was deleted, so it is not re-reading")
		}
	})

	t.Run("a missing kernel is reported by path", func(t *testing.T) {
		pin, art := stageLocator(t)
		if err := os.Remove(art.KernelPath); err != nil {
			t.Fatalf("remove the kernel: %v", err)
		}
		_, err := Locator(pin, art)()
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("error = %v, want errors.Is os.ErrNotExist", err)
		}
		assertNames(t, err, art.KernelPath)
	})

	t.Run("a missing initramfs is reported by path", func(t *testing.T) {
		pin, art := stageLocator(t)
		if err := os.Remove(art.InitramfsPath); err != nil {
			t.Fatalf("remove the initramfs: %v", err)
		}
		_, err := Locator(pin, art)()
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("error = %v, want errors.Is os.ErrNotExist", err)
		}
		assertNames(t, err, art.InitramfsPath)
	})

	t.Run("a pin the artifacts never matched is refused on the first call", func(t *testing.T) {
		_, art := stageLocator(t)
		other := pinFor([]byte("some other kernel"), []byte("some other initramfs"))
		_, err := Locator(other, art)()
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("error = %v, want errors.Is ErrDigestMismatch", err)
		}
	})
}

// assertNames fails unless err's message carries want — the operator-facing half
// of the contract: "which artifact moved", not "the vm capability is off".
func assertNames(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one naming %s", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not name the offending file %s", err, want)
	}
}

// ============================================================================
// Mutation legs for the locator. Each one is a state a VERIFY-ONCE locator — the
// constant closure this API replaced — would happily boot: the artifacts passed
// verification at daemon start and changed afterwards. They are named Mutation*
// so hack/acceptance/B108.sh can assert each RAN, on the same discipline as the
// ensure ladder.
// ============================================================================

func TestLocatorMutations(t *testing.T) {
	t.Run("MutationKernelFlippedAfterAVerifiedCall", func(t *testing.T) {
		pin, art := stageLocator(t)
		locate := Locator(pin, art)
		if _, err := locate(); err != nil {
			t.Fatalf("the first call must verify: %v", err)
		}
		mutated := append([]byte(nil), testKernelBytes...)
		mutated[len(mutated)/2] ^= 0x01
		if err := os.WriteFile(art.KernelPath, mutated, 0o644); err != nil {
			t.Fatalf("mutate the verified kernel: %v", err)
		}
		_, err := locate()
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("error = %v, want errors.Is ErrDigestMismatch", err)
		}
		assertNames(t, err, art.KernelPath)
	})

	t.Run("MutationInitramfsFlippedAfterAVerifiedCall", func(t *testing.T) {
		pin, art := stageLocator(t)
		locate := Locator(pin, art)
		if _, err := locate(); err != nil {
			t.Fatalf("the first call must verify: %v", err)
		}
		mutated := append([]byte(nil), testInitramfsBytes...)
		mutated[0] ^= 0x80
		if err := os.WriteFile(art.InitramfsPath, mutated, 0o644); err != nil {
			t.Fatalf("mutate the verified initramfs: %v", err)
		}
		_, err := locate()
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("error = %v, want errors.Is ErrDigestMismatch", err)
		}
		assertNames(t, err, art.InitramfsPath)
	})

	t.Run("MutationArtifactsSwappedAfterAVerifiedCall", func(t *testing.T) {
		// Both files still exist, both still hash to a digest the pin names —
		// just not to the one at their own path. A per-file existence check, or
		// a set-level hash over the pair, accepts this; a per-path comparison
		// does not, and booting an initramfs as a kernel is not a boot.
		pin, art := stageLocator(t)
		locate := Locator(pin, art)
		if _, err := locate(); err != nil {
			t.Fatalf("the first call must verify: %v", err)
		}
		if err := os.WriteFile(art.KernelPath, testInitramfsBytes, 0o644); err != nil {
			t.Fatalf("swap the kernel: %v", err)
		}
		if err := os.WriteFile(art.InitramfsPath, testKernelBytes, 0o644); err != nil {
			t.Fatalf("swap the initramfs: %v", err)
		}
		_, err := locate()
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("error = %v, want errors.Is ErrDigestMismatch", err)
		}
	})
}
