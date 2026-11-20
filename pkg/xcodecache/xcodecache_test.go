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

package xcodecache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestValidKey(t *testing.T) {
	for _, k := range []string{"yureisha", "app-1", "a", "x.y_z-0", strings.Repeat("a", 63)} {
		if err := ValidKey(k); err != nil {
			t.Errorf("ValidKey(%q) = %v, want nil", k, err)
		}
	}
	for _, k := range []string{"", "-a", ".a", "_a", "A", "a/b", "../x", "a..b", "a b", strings.Repeat("a", 64), "ä"} {
		if err := ValidKey(k); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidKey(%q) = %v, want ErrInvalid", k, err)
		}
	}
}

func TestEntryValidateRefusesPathEscapes(t *testing.T) {
	good := Entry{Namespace: "yurei-yureisha", Key: "app", Build: "17E5159k"}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate(%+v) = %v", good, err)
	}
	for _, e := range []Entry{
		{Namespace: "..", Key: "app", Build: "1"},
		{Namespace: "a/b", Key: "app", Build: "1"},
		{Namespace: "ns", Key: "app", Build: "../1"},
		{Namespace: "ns", Key: "app", Build: ""},
		{Namespace: "ns", Key: "..", Build: "1"},
	} {
		if err := e.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalid", e, err)
		}
	}
}

const versionPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BuildAliasOf</key>
	<string>IDEFrameworks</string>
	<key>BuildVersion</key>
	<string>6</string>
	<key>CFBundleShortVersionString</key>
	<string>27.1</string>
	<key>ProductBuildVersion</key>
	<string>17E5159k</string>
	<key>ProjectName</key>
	<string>IDEApplication</string>
</dict>
</plist>
`

func fakeXcode(t *testing.T, plist string) string {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "Xcode.app")
	dev := filepath.Join(bundle, "Contents", "Developer")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	if plist != "" {
		if err := os.WriteFile(filepath.Join(bundle, "Contents", "version.plist"), []byte(plist), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dev
}

func TestReadBuildVersion(t *testing.T) {
	got, err := ReadBuildVersion(fakeXcode(t, versionPlist))
	if err != nil || got != "17E5159k" {
		t.Fatalf("ReadBuildVersion = %q, %v; want 17E5159k", got, err)
	}
}

func TestReadBuildVersionRefuses(t *testing.T) {
	cases := map[string]string{
		"missing file":  "",
		"no key":        strings.Replace(versionPlist, "ProductBuildVersion", "Other", 1),
		"path in value": strings.Replace(versionPlist, "17E5159k", "../../x", 1),
		"not xml":       "garbage <<",
	}
	for name, plist := range cases {
		if v, err := ReadBuildVersion(fakeXcode(t, plist)); err == nil {
			t.Errorf("%s: ReadBuildVersion = %q, nil; want an error", name, v)
		}
	}
	// Command Line Tools: no bundle, no version.
	if _, err := ReadBuildVersion("/Library/Developer/CommandLineTools"); !errors.Is(err, ErrInvalid) {
		t.Errorf("CLT dir: err = %v, want ErrInvalid", err)
	}
}

// writeHome lays out a home with both parts, each holding one file whose
// content is tag.
func writeHome(t *testing.T, home, tag string) {
	t.Helper()
	for _, part := range Parts {
		d := filepath.Join(home, part, "nested")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte(tag), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readPart(t *testing.T, home, part string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, part, "nested", "f"))
	if err != nil {
		t.Fatalf("read %s: %v", part, err)
	}
	return string(b)
}

var entry = Entry{Namespace: "ns", Key: "app", Build: "17E5159k"}

func TestCheckoutWithoutSnapshotIsCold(t *testing.T) {
	s := Store{Root: t.TempDir()}
	home := t.TempDir()
	got, err := s.Checkout(entry, home)
	if err != nil || len(got) != 0 {
		t.Fatalf("Checkout = %v, %v; want nothing, nil", got, err)
	}
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Fatalf("cold checkout wrote %d entries into home", len(ents))
	}
}

func TestPublishThenCheckout(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "build-1")
	parts, err := s.Publish(entry, src, "pod-a")
	if err != nil || len(parts) != len(Parts) {
		t.Fatalf("Publish = %v, %v", parts, err)
	}
	home := t.TempDir()
	got, err := s.Checkout(entry, home)
	if err != nil || len(got) != len(Parts) {
		t.Fatalf("Checkout = %v, %v", got, err)
	}
	for _, p := range Parts {
		if v := readPart(t, home, p); v != "build-1" {
			t.Errorf("%s = %q, want build-1", p, v)
		}
	}
	// The clone is private: writing it leaves the snapshot alone.
	if err := os.WriteFile(filepath.Join(home, Parts[0], "nested", "f"), []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := readPart(t, filepath.Join(s.Dir(entry), SnapshotName), Parts[0]); v != "build-1" {
		t.Errorf("snapshot changed through a checkout: %q", v)
	}
	// No staging dir is left behind.
	ents, _ := os.ReadDir(s.Dir(entry))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), incomingPrefix) {
			t.Errorf("staging dir left behind: %s", e.Name())
		}
	}
}

func TestCheckoutKeepsAnExistingPart(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "snapshot")
	if _, err := s.Publish(entry, src, "p"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	writeHome(t, home, "own")
	got, err := s.Checkout(entry, home)
	if err != nil || len(got) != 0 {
		t.Fatalf("Checkout = %v, %v; want nothing cloned", got, err)
	}
	if v := readPart(t, home, Parts[0]); v != "own" {
		t.Errorf("checkout overwrote the pod's own tree: %q", v)
	}
}

func TestPublishEmptyHomeKeepsSnapshot(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "keep")
	if _, err := s.Publish(entry, src, "p1"); err != nil {
		t.Fatal(err)
	}
	parts, err := s.Publish(entry, t.TempDir(), "p2")
	if err != nil || len(parts) != 0 {
		t.Fatalf("Publish(empty) = %v, %v", parts, err)
	}
	if v := readPart(t, filepath.Join(s.Dir(entry), SnapshotName), Parts[1]); v != "keep" {
		t.Errorf("snapshot = %q, want keep", v)
	}
}

func TestEntriesAreIsolated(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "ns-a")
	if _, err := s.Publish(Entry{Namespace: "a", Key: "app", Build: "1"}, src, "p"); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Entry{{Namespace: "b", Key: "app", Build: "1"}, {Namespace: "a", Key: "other", Build: "1"}, {Namespace: "a", Key: "app", Build: "2"}} {
		got, err := s.Checkout(e, t.TempDir())
		if err != nil || len(got) != 0 {
			t.Errorf("Checkout(%+v) = %v, %v; want cold", e, got, err)
		}
	}
}

// failFS fails the clone of the second part.
type failFS struct {
	apfsFS
	n int
}

func (f *failFS) CloneAt(sfd int, src string, dfd int, dst string) error {
	f.n++
	if f.n == 2 {
		return errors.New("injected")
	}
	return f.apfsFS.CloneAt(sfd, src, dfd, dst)
}

func TestFailedStageLeavesSnapshotAndNoStage(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "good")
	if _, err := s.Publish(entry, src, "p1"); err != nil {
		t.Fatal(err)
	}
	bad := t.TempDir()
	writeHome(t, bad, "half")
	s.FS = &failFS{}
	if _, err := s.Publish(entry, bad, "p2"); err == nil {
		t.Fatal("Publish with a failing clone succeeded")
	}
	s.FS = nil
	for _, p := range Parts {
		if v := readPart(t, filepath.Join(s.Dir(entry), SnapshotName), p); v != "good" {
			t.Errorf("%s = %q after a failed publish, want good", p, v)
		}
	}
	if _, err := os.Lstat(filepath.Join(s.Dir(entry), incomingPrefix+"p2")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed stage left its dir: %v", err)
	}
}

// redirectFS fails the first clone after leaving a partial tree at its
// destination and swapping home/Library for a link to another tree, as a
// process left over from an earlier instance of the pod could while the daemon
// checks out. The cleanup that follows runs as root in production.
type redirectFS struct {
	apfsFS
	home, elsewhere string
}

func (f *redirectFS) CloneAt(sfd int, src string, dfd int, dst string) error {
	if err := unix.Mkdirat(dfd, dst, 0o700); err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, filepath.Join(dst, "partial"), unix.O_WRONLY|unix.O_CREAT, 0o600)
	if err != nil {
		return err
	}
	unix.Close(fd)
	lib := filepath.Join(f.home, "Library")
	if err := os.Rename(lib, lib+".moved"); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join(f.elsewhere, "Library"), lib); err != nil {
		return err
	}
	return errors.New("injected")
}

// The cleanup after a failed checkout removes what the daemon made, relative
// to the directory it pinned. It must not remove the tree that the part's PATH
// names by then: here that path leads through a link into another pod's home.
func TestFailedCheckoutCleanupDoesNotFollowASwappedPath(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "x")
	if _, err := s.Publish(entry, src, "p"); err != nil {
		t.Fatal(err)
	}
	victim := t.TempDir()
	writeHome(t, victim, "victim")
	home := t.TempDir()
	s.FS = &redirectFS{home: home, elsewhere: victim}
	if _, err := s.Checkout(entry, home); err == nil {
		t.Fatal("Checkout with a failing clone succeeded")
	}
	for _, p := range Parts {
		if v := readPart(t, victim, p); v != "victim" {
			t.Errorf("the other tree's %s = %q after the cleanup, want it untouched", p, v)
		}
	}
	moved := filepath.Join(home, "Library.moved", strings.TrimPrefix(Parts[0], "Library/"))
	if _, err := os.Lstat(moved); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the daemon's own partial clone was left behind at %s: %v", moved, err)
	}
}

// removeTreeAt unlinks a link as a link and never descends through one.
func TestRemoveTreeAtDoesNotFollowLinks(t *testing.T) {
	keep := t.TempDir()
	if err := os.WriteFile(filepath.Join(keep, "f"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tree", "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tree", "a", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keep, filepath.Join(dir, "tree", "a", "b", "link")); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := removeTreeAt(int(d.Fd()), "tree"); err != nil {
		t.Fatalf("removeTreeAt: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tree survived: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(keep, "f")); err != nil || string(b) != "keep" {
		t.Errorf("the link's target was touched: %q, %v", b, err)
	}
	if err := removeTreeAt(int(d.Fd()), "tree"); err != nil {
		t.Errorf("removing a name that is gone: %v", err)
	}
}

func TestFailedCheckoutLeavesNoPartialPart(t *testing.T) {
	s := Store{Root: t.TempDir()}
	src := t.TempDir()
	writeHome(t, src, "x")
	if _, err := s.Publish(entry, src, "p"); err != nil {
		t.Fatal(err)
	}
	s.FS = &failFS{}
	home := t.TempDir()
	got, err := s.Checkout(entry, home)
	if err == nil {
		t.Fatal("Checkout with a failing clone succeeded")
	}
	if len(got) != 1 {
		t.Fatalf("cloned = %v, want the first part only", got)
	}
	if _, err := os.Lstat(filepath.Join(home, Parts[1])); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("partial second part left in home: %v", err)
	}
}

func TestStageRefusesBadNames(t *testing.T) {
	s := Store{Root: t.TempDir()}
	home := t.TempDir()
	writeHome(t, home, "x")
	for _, st := range []string{"", "a/b", "..", "x..y"} {
		if _, _, err := s.Stage(entry, home, st); !errors.Is(err, ErrInvalid) {
			t.Errorf("Stage(%q) = %v, want ErrInvalid", st, err)
		}
	}
	if err := s.Commit(entry, filepath.Join(t.TempDir(), incomingPrefix+"x")); !errors.Is(err, ErrInvalid) {
		t.Errorf("Commit outside the entry dir = %v, want ErrInvalid", err)
	}
}

// Concurrent publishers and readers: every publish succeeds, the snapshot
// ends as exactly one publisher's tree, and every reader sees one whole tree
// (both parts from the same publisher), never a mix or a partial one.
func TestConcurrentPublishAndCheckout(t *testing.T) {
	s := Store{Root: t.TempDir()}
	seed := t.TempDir()
	writeHome(t, seed, "seed")
	if _, err := s.Publish(entry, seed, "seed"); err != nil {
		t.Fatal(err)
	}
	const writers, readers = 6, 12
	var wg sync.WaitGroup
	errs := make(chan error, writers+readers)
	for i := 0; i < writers; i++ {
		home := t.TempDir()
		writeHome(t, home, fmt.Sprintf("w%d", i))
		wg.Add(1)
		go func(i int, home string) {
			defer wg.Done()
			if _, err := s.Publish(entry, home, fmt.Sprintf("pod-%d", i)); err != nil {
				errs <- fmt.Errorf("publisher %d: %w", i, err)
			}
		}(i, home)
	}
	for i := 0; i < readers; i++ {
		home := t.TempDir()
		wg.Add(1)
		go func(home string) {
			defer wg.Done()
			got, err := s.Checkout(entry, home)
			if err != nil {
				errs <- fmt.Errorf("reader: %w", err)
				return
			}
			if len(got) != len(Parts) {
				errs <- fmt.Errorf("reader cloned %v, want every part", got)
				return
			}
			a, b := readPart(t, home, Parts[0]), readPart(t, home, Parts[1])
			if a != b {
				errs <- fmt.Errorf("reader saw a mixed snapshot: %q and %q", a, b)
			}
		}(home)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	snap := filepath.Join(s.Dir(entry), SnapshotName)
	a, b := readPart(t, snap, Parts[0]), readPart(t, snap, Parts[1])
	if a != b || !strings.HasPrefix(a, "w") {
		t.Errorf("final snapshot = %q / %q, want one publisher's tree", a, b)
	}
	ents, _ := os.ReadDir(s.Dir(entry))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), incomingPrefix) {
			t.Errorf("staging dir left behind: %s", e.Name())
		}
	}
}

func TestLockWaitIsBounded(t *testing.T) {
	s := Store{Root: t.TempDir(), LockWait: 100 * time.Millisecond}
	seed := t.TempDir()
	writeHome(t, seed, "x")
	if _, err := s.Publish(entry, seed, "seed"); err != nil {
		t.Fatal(err)
	}
	unlock, err := lock(filepath.Join(s.Dir(entry), lockName), unix.LOCK_EX, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	start := time.Now()
	if _, err := s.Checkout(entry, t.TempDir()); err == nil {
		t.Fatal("Checkout under a held exclusive lock succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Checkout waited %v, want about 100ms", d)
	}
}

// A pod that plants a symlink in its home (home/Library pointing elsewhere)
// must not get the daemon to clone what it points at into the cache.
func TestStageRefusesSymlinkedComponents(t *testing.T) {
	secret := t.TempDir()
	if err := os.MkdirAll(filepath.Join(secret, "Developer", "Xcode", "DerivedData"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "Developer", "Xcode", "DerivedData", "key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(home, "Library")); err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	if _, err := s.Publish(entry, home, "p"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Publish through a symlinked Library = %v, want ErrInvalid", err)
	}
	if _, err := os.Lstat(filepath.Join(s.Dir(entry), SnapshotName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a snapshot was published through the link: %v", err)
	}
	// A symlinked last component is refused the same way.
	home2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home2, "Library", "Developer", "Xcode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "Developer", "Xcode", "DerivedData"), filepath.Join(home2, Parts[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(entry, home2, "p2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Publish of a symlinked part = %v, want ErrInvalid", err)
	}
}

// A pod can replace a directory ABOVE its home (its rootfs) with a link to
// another pod's. StageAt and CheckoutAt walk from a base the pod cannot
// replace and refuse the link; Stage and Checkout on the same path, which
// resolve it, are the contrast that shows what the anchor is for.
func TestAnchoredWalkRefusesALinkAboveHome(t *testing.T) {
	victim := t.TempDir()
	if err := os.MkdirAll(filepath.Join(victim, "home", Parts[0]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "home", Parts[0], "key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	podDir := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(podDir, "rootfs")); err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	homeRel := filepath.Join("rootfs", "home")
	if incoming, parts, err := s.StageAt(entry, podDir, homeRel, "p"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("StageAt through a linked rootfs = (%q, %v, %v), want ErrInvalid", incoming, parts, err)
	}
	if ents, _ := os.ReadDir(s.Dir(entry)); len(ents) != 0 {
		t.Fatalf("StageAt left %d entries in the store", len(ents))
	}
	if _, err := s.CheckoutAt(entry, podDir, homeRel); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CheckoutAt through a linked rootfs = %v, want ErrInvalid", err)
	}
	// The contrast: the unanchored call resolves the link and stages the
	// other tree. This is what the runtime must never do with a pod's path.
	incoming, parts, err := s.Stage(entry, filepath.Join(podDir, homeRel), "q")
	if err != nil || len(parts) != 1 {
		t.Fatalf("Stage by path = (%q, %v, %v), want the one part staged", incoming, parts, err)
	}
	if b, err := os.ReadFile(filepath.Join(incoming, Parts[0], "key")); err != nil || string(b) != "secret" {
		t.Fatalf("the contrast did not read the linked tree: %q, %v", b, err)
	}
}

// swapFS swaps home/Library for a link to another tree just before the first
// clone, as a process that survived the pod's stop could.
type swapFS struct {
	apfsFS
	home, elsewhere string
	done            bool
}

func (f *swapFS) CloneAt(sfd int, src string, dfd int, dst string) error {
	if !f.done {
		f.done = true
		lib := filepath.Join(f.home, "Library")
		if err := os.Rename(lib, lib+".moved"); err != nil {
			return err
		}
		if err := os.Symlink(filepath.Join(f.elsewhere, "Library"), lib); err != nil {
			return err
		}
	}
	return f.apfsFS.CloneAt(sfd, src, dfd, dst)
}

// The stage clones the directories it checked, not whatever their paths name
// by the time the clone runs: a swap after the check publishes the pod's own
// tree, never the link's target.
func TestStageClonesThePinnedTreeNotASwappedPath(t *testing.T) {
	victim := t.TempDir()
	writeHome(t, victim, "stolen")
	home := t.TempDir()
	writeHome(t, home, "mine")
	s := Store{Root: t.TempDir(), FS: &swapFS{home: home, elsewhere: victim}}
	if _, err := s.Publish(entry, home, "p"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, p := range Parts {
		if v := readPart(t, filepath.Join(s.Dir(entry), SnapshotName), p); v != "mine" {
			t.Errorf("%s = %q, want the pod's own tree (mine)", p, v)
		}
	}
}

func TestCommitSweepsOrphanedStages(t *testing.T) {
	s := Store{Root: t.TempDir()}
	orphan := filepath.Join(s.Dir(entry), incomingPrefix+"dead")
	fresh := filepath.Join(s.Dir(entry), incomingPrefix+"live")
	for _, d := range []string{orphan, fresh} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleStage)
	if err := os.Chtimes(orphan, old, old); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	writeHome(t, home, "x")
	if _, err := s.Publish(entry, home, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("orphaned stage survived a commit: %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Errorf("a fresh stage was swept: %v", err)
	}
}
