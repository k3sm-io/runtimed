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

package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// opDigest is a syntactically valid blob digest for name. It names no real blob:
// these tests are about the RECORD, and the digests only have to survive the
// store's closed algorithm allowlist.
func opDigest(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// darwinPlatform and linuxPlatform are the two keys these tests file roots
// under. They are complete, because an incomplete platform is refused at write.
var (
	darwinPlatform = Platform{OS: "darwin", Architecture: "arm64"}
	linuxPlatform  = Platform{OS: "linux", Architecture: "arm64"}
)

// TestOperatorImageRootsAreKeyedByThePair pins the record's write semantics: a
// root is owned by a (reference x platform) pair, re-recording the pair replaces
// it, and removing one pair leaves the other alone.
//
// The pair keying is the whole reason this record exists separately from the
// per-pod ones. Untagging linux/arm64 of a multi-platform reference must unpin
// only the linux blobs; a reference-keyed record would unpin both, which is a
// silent over-collection of content the operator still names.
func TestOperatorImageRootsAreKeyedByThePair(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	const ref = "example.com/app:v1"

	if err := cache.RecordOperatorImage(ref, darwinPlatform, ImageRoot{
		Reference: ref, Config: opDigest("darwin-config"), Layers: []string{opDigest("darwin-layer")},
	}); err != nil {
		t.Fatalf("RecordOperatorImage(darwin): %v", err)
	}
	if err := cache.RecordOperatorImage(ref, linuxPlatform, ImageRoot{
		Reference: ref, Config: opDigest("linux-config"), Layers: []string{opDigest("linux-layer")},
	}); err != nil {
		t.Fatalf("RecordOperatorImage(linux): %v", err)
	}
	roots, err := cache.OperatorImageRoots()
	if err != nil {
		t.Fatalf("OperatorImageRoots: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("OperatorImageRoots = %v, want one entry per platform", roots)
	}

	t.Run("re-recording a pair replaces it", func(t *testing.T) {
		if err := cache.RecordOperatorImage(ref, darwinPlatform, ImageRoot{
			Reference: ref, Config: opDigest("darwin-config-2"),
		}); err != nil {
			t.Fatalf("RecordOperatorImage: %v", err)
		}
		roots, err := cache.OperatorImageRoots()
		if err != nil {
			t.Fatalf("OperatorImageRoots: %v", err)
		}
		if len(roots) != 2 {
			t.Fatalf("OperatorImageRoots = %v, want 2 (a re-record replaces, it does not accumulate)", roots)
		}
		for _, r := range roots {
			if r.Platform == darwinPlatform.Normalize() && r.Root.Config != opDigest("darwin-config-2") {
				t.Errorf("darwin root config = %s, want the re-recorded digest", r.Root.Config)
			}
		}
	})

	t.Run("removing one pair leaves the sibling platform pinned", func(t *testing.T) {
		removed, err := cache.RemoveOperatorImage(ref, linuxPlatform)
		if err != nil || !removed {
			t.Fatalf("RemoveOperatorImage = (%v, %v), want (true, nil)", removed, err)
		}
		roots, err := cache.OperatorImageRoots()
		if err != nil {
			t.Fatalf("OperatorImageRoots: %v", err)
		}
		if len(roots) != 1 || roots[0].Platform != darwinPlatform.Normalize() {
			t.Fatalf("OperatorImageRoots = %v, want only the darwin entry", roots)
		}
	})

	t.Run("removing an absent pair is false, not an error", func(t *testing.T) {
		removed, err := cache.RemoveOperatorImage(ref, linuxPlatform)
		if err != nil || removed {
			t.Fatalf("RemoveOperatorImage of an absent pair = (%v, %v), want (false, nil)", removed, err)
		}
	})

	t.Run("an incomplete platform is refused at write", func(t *testing.T) {
		if err := cache.RecordOperatorImage(ref, Platform{OS: "darwin"}, ImageRoot{Reference: ref}); err == nil {
			t.Error("RecordOperatorImage accepted a platform with no architecture; the key would be unmatchable")
		}
	})
}

// TestOperatorRootsJoinTheReachabilitySet is the claim the whole operator-root
// mechanism exists to make: what an operator named is REACHABLE, so a pull that
// no pod uses survives a prune, and an untag makes it collectable again.
//
// It asserts through Cache.Roots — the GC's own enumerator — rather than through
// the operator record, because the record being correct and the GC consulting it
// are different facts and only the second one protects anything.
func TestOperatorRootsJoinTheReachabilitySet(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	const ref = "example.com/warm:v1"
	cfg, layer := opDigest("warm-config"), opDigest("warm-layer")

	// Before: a node with no pods and no operator roots has an empty set.
	roots, err := cache.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("Roots = %v on an empty store, want none", roots)
	}

	if err := cache.RecordOperatorImage(ref, darwinPlatform, ImageRoot{
		Reference: ref, Config: cfg, Layers: []string{layer},
	}); err != nil {
		t.Fatalf("RecordOperatorImage: %v", err)
	}
	roots, err = cache.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("Roots = %v, want the operator root", roots)
	}
	got := map[string]bool{}
	for _, d := range roots[0].Digests() {
		got[d] = true
	}
	if !got[cfg] || !got[layer] {
		t.Errorf("Roots digests = %v, want both %s and %s", roots[0].Digests(), cfg, layer)
	}

	// After the untag the content is unrooted again — which is what makes an
	// operator's pin releasable at all.
	if _, err := cache.RemoveOperatorImage(ref, darwinPlatform); err != nil {
		t.Fatalf("RemoveOperatorImage: %v", err)
	}
	roots, err = cache.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("Roots = %v after the untag, want none", roots)
	}
}

// TestOperatorRootsFailClosed pins the fail-closed reads. An unreadable operator
// record must abort the whole prune, exactly as an unreadable pod record does:
// a root set that is silently short does not degrade a prune's answer, it
// inverts it — every blob the missing roots named looks unreferenced.
func TestOperatorRootsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"undecodable", "{not json"},
		{"unknown_schema", `{"schema":99,"images":[]}`},
		{"unusable_digest", `{"schema":1,"images":[{"reference":"a:b","platform":{"os":"darwin","architecture":"arm64"},"config":"md5:zz"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatalf("NewCache: %v", err)
			}
			dir := cache.OperatorRootDir()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, OperatorReferencesName), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := cache.OperatorImageRoots(); !errors.Is(err, ErrRootsIncomplete) {
				t.Errorf("OperatorImageRoots = %v, want ErrRootsIncomplete", err)
			}
			// And the GC's own enumerator inherits the refusal.
			if _, err := cache.Roots(); !errors.Is(err, ErrRootsIncomplete) {
				t.Errorf("Roots = %v, want ErrRootsIncomplete", err)
			}
		})
	}
}

// TestOperatorRootsSerializeConcurrentWrites pins the lost-update guard. The
// record is ONE file rewritten whole, so two concurrent tag/untag/pull calls
// racing read-modify-write would drop a root — and a dropped root, unlike a
// dropped edge, makes live content collectable.
func TestOperatorRootsSerializeConcurrentWrites(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref := "example.com/app:v" + string(rune('a'+i))
			errs[i] = cache.RecordOperatorImage(ref, darwinPlatform, ImageRoot{
				Reference: ref, Config: opDigest(ref),
			})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent RecordOperatorImage %d: %v", i, err)
		}
	}
	roots, err := cache.OperatorImageRoots()
	if err != nil {
		t.Fatalf("OperatorImageRoots: %v", err)
	}
	if len(roots) != n {
		t.Errorf("OperatorImageRoots recorded %d of %d concurrent roots; the read-modify-write must be serialized",
			len(roots), n)
	}
}
