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

package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// byPathFSGroupWalk is the walk ChownForFSGroup made before it was pinned to
// descriptors, kept here as the reference: the ordinary-tree test compares
// results with it, and the swap tests run it as the contrast that shows what a
// walk by path does when an entry is swapped under it. hook is called where
// fsGroupBeforeApply is: after the walk read what the entry is, before it
// changes it.
func byPathFSGroupWalk(root string, gid int, hook func(path string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if hook != nil {
			hook(path)
		}
		if err := os.Lchown(path, -1, gid); err != nil {
			return fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		mode |= (mode & 0o700) >> 3
		newMode := info.Mode()&^fs.FileMode(0o777) | mode
		if d.IsDir() {
			newMode |= os.ModeSetgid
		}
		if err := os.Chmod(path, newMode); err != nil {
			return fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return nil
	})
}

// fsGroupTestGid returns a gid the test process may chown to, and skips when
// there is none above 0. It prefers a supplementary group that differs from
// the group new files get in dir, so that a chown is visible as well as a
// chmod; when the process has only one group the mode assertions still hold.
func fsGroupTestGid(t *testing.T, dir string) int {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g > 0 && g != int(st.Gid) {
			return g
		}
	}
	if g := os.Getgid(); g > 0 {
		return g
	}
	t.Skip("the test process has no gid above 0 to chown to")
	return 0
}

// entryState is what the walk can change about one entry.
type entryState struct {
	Mode uint32 // type and permission bits, as lstat reports them
	Gid  uint32
}

// treeState maps each path below root (root itself is ".") to its state,
// without following links.
func treeState(t *testing.T, root string) map[string]entryState {
	t.Helper()
	out := map[string]entryState{}
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[rel] = entryState{Mode: uint32(st.Mode), Gid: st.Gid}
		return nil
	})
	if err != nil {
		t.Fatalf("read tree %s: %v", root, err)
	}
	return out
}

func describeState(m map[string]entryState) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-28s mode %07o gid %d\n", k, m[k].Mode, m[k].Gid)
	}
	return b.String()
}

func mustEqualState(t *testing.T, what string, got, want map[string]entryState) {
	t.Helper()
	if describeState(got) != describeState(want) {
		t.Errorf("%s differs.\n--- got ---\n%s--- want ---\n%s", what, describeState(got), describeState(want))
	}
}

// buildOrdinaryTree makes, under a new pod dir, a rootfs holding every kind of
// entry a pod can leave there, and returns the pod dir and the rootfs.
func buildOrdinaryTree(t *testing.T) (podDir, root string) {
	t.Helper()
	podDir = t.TempDir()
	root = filepath.Join(podDir, "rootfs")
	mk := func(rel string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	file := func(rel string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk(".", 0o700)
	mk("home", 0o700)
	mk("home/Library/Developer", 0o755)
	mk("tmp", 0o700|os.ModeSticky)
	mk("vol/a/b/c/d", 0o750)
	mk("vol/readonly", 0o500)
	file("home/.gitconfig", 0o600)
	file("home/Library/tool", 0o755)
	file("vol/a/data", 0o644)
	file("vol/a/b/secret", 0o400)
	file("vol/a/b/setuid", 0o755|os.ModeSetuid)
	file("vol/a/b/setgid", 0o750|os.ModeSetgid)
	if err := os.Symlink("data", filepath.Join(root, "vol/a/link-to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(root, "vol/a/link-to-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/target", filepath.Join(root, "vol/dangling")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "vol/fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	return podDir, root
}

// TestFSGroupWalkMatchesTheByPathWalk: on a tree nobody is rearranging, the
// descriptor-pinned walk leaves every entry exactly as the by-path walk it
// replaced did: the same group, the same mode bits, on directories, files with
// and without special bits, symlinks, a dangling link and a FIFO.
func TestFSGroupWalkMatchesTheByPathWalk(t *testing.T) {
	podA, rootA := buildOrdinaryTree(t)
	_, rootB := buildOrdinaryTree(t)
	gid := fsGroupTestGid(t, rootA)
	mustEqualState(t, "the two trees before either walk", treeState(t, rootA), treeState(t, rootB))

	if err := ChownForFSGroup(podA, rootA, gid); err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if err := byPathFSGroupWalk(rootB, gid, nil); err != nil {
		t.Fatalf("the by-path reference walk: %v", err)
	}
	got, want := treeState(t, rootA), treeState(t, rootB)
	mustEqualState(t, "the tree after the pinned walk, against the by-path walk", got, want)

	// The comparison would also pass if neither walk did anything: pin a few
	// outcomes outright. (The setuid and setgid files are left to the
	// comparison: whether a chown clears those bits depends on who runs it.)
	for rel, wantMode := range map[string]uint32{
		".":                 unix.S_IFDIR | unix.S_ISGID | 0o770,
		"tmp":               unix.S_IFDIR | unix.S_ISGID | unix.S_ISVTX | 0o770,
		"vol/readonly":      unix.S_IFDIR | unix.S_ISGID | 0o550,
		"vol/a/data":        unix.S_IFREG | 0o664,
		"vol/a/b/secret":    unix.S_IFREG | 0o440,
		"vol/fifo":          unix.S_IFIFO | 0o660,
		"vol/a/b/c/d":       unix.S_IFDIR | unix.S_ISGID | 0o770,
		"home/Library/tool": unix.S_IFREG | 0o775,
	} {
		if got[rel].Mode != wantMode {
			t.Errorf("%s mode = %07o, want %07o", rel, got[rel].Mode, wantMode)
		}
		if int(got[rel].Gid) != gid {
			t.Errorf("%s gid = %d, want %d", rel, got[rel].Gid, gid)
		}
	}
	if int(got["vol/a/link-to-file"].Gid) != gid {
		t.Errorf("a symlink's own gid = %d, want %d (lchown)", got["vol/a/link-to-file"].Gid, gid)
	}
}

// victimTree is another pod's tree: a directory and a file the walk must never
// reach. It returns the tree's root.
func victimTree(t *testing.T) string {
	t.Helper()
	victim := t.TempDir()
	if err := os.MkdirAll(filepath.Join(victim, "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"f", "b/f"} {
		if err := os.WriteFile(filepath.Join(victim, f), []byte("theirs"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	return victim
}

// swapCase builds a pod tree and a hook that, the first time the walk is about
// to change the entry at trigger, swaps part of the tree for a link into the
// victim tree, as a process of the pod could at that moment.
type swapCase struct {
	name string
	// build makes the tree under root and returns the path the hook waits for
	// and the swap it then makes.
	build func(t *testing.T, root, victim string) (trigger string, swap func() error)
	// wantErr says whether the pinned walk must fail (it meets a link where it
	// listed a directory) or may finish (it changed a link as a link).
	wantErr bool
}

func swapCases() []swapCase {
	return []swapCase{
		{
			name: "a directory above the entry becomes a link",
			build: func(t *testing.T, root, victim string) (string, func() error) {
				if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "a", "b", "f"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				a := filepath.Join(root, "a")
				return filepath.Join(a, "b"), func() error {
					if err := os.Rename(a, a+".moved"); err != nil {
						return err
					}
					return os.Symlink(victim, a)
				}
			},
			wantErr: true,
		},
		{
			name: "the file itself becomes a link",
			build: func(t *testing.T, root, victim string) (string, func() error) {
				if err := os.MkdirAll(filepath.Join(root, "a"), 0o700); err != nil {
					t.Fatal(err)
				}
				f := filepath.Join(root, "a", "f")
				if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return f, func() error {
					if err := os.Remove(f); err != nil {
						return err
					}
					return os.Symlink(filepath.Join(victim, "f"), f)
				}
			},
			wantErr: true,
		},
		{
			name: "the rootfs becomes a link once the walk is inside it",
			build: func(t *testing.T, root, victim string) (string, func() error) {
				if err := os.MkdirAll(filepath.Join(root, "b"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "b", "f"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(root, "b"), func() error {
					if err := os.Rename(root, root+".moved"); err != nil {
						return err
					}
					return os.Symlink(victim, root)
				}
			},
		},
	}
}

// oneShot returns a hook that runs swap the first time it sees trigger, and
// reports whether it ran.
func oneShot(t *testing.T, trigger string, swap func() error) (hook func(string), ran *bool) {
	t.Helper()
	ran = new(bool)
	return func(path string) {
		if *ran || path != trigger {
			return
		}
		*ran = true
		if err := swap(); err != nil {
			t.Errorf("the swap at %s failed: %v", trigger, err)
		}
	}, ran
}

// TestFSGroupWalkDoesNotFollowASwappedPath is B1870's gate. A pod process
// swaps a directory, a file, or the rootfs itself for a symlink into another
// pod's tree in the window between the walk reading an entry and changing it.
// The pinned walk leaves the other tree's owner and mode untouched. The
// contrast subtests run the by-path walk it replaced through the same swap and
// require that it DOES change the other tree, so the swap is known to land in
// the window and the test cannot pass by never racing.
func TestFSGroupWalkDoesNotFollowASwappedPath(t *testing.T) {
	for _, tc := range swapCases() {
		t.Run(tc.name, func(t *testing.T) {
			victim := victimTree(t)
			podDir := t.TempDir()
			root := filepath.Join(podDir, "rootfs")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			gid := fsGroupTestGid(t, victim)
			trigger, swap := tc.build(t, root, victim)
			before := treeState(t, victim)

			hook, ran := oneShot(t, trigger, swap)
			fsGroupBeforeApply = hook
			t.Cleanup(func() { fsGroupBeforeApply = nil })
			err := ChownForFSGroup(podDir, root, gid)
			fsGroupBeforeApply = nil

			if !*ran {
				t.Fatalf("the walk never reached %s, so nothing was swapped", trigger)
			}
			if tc.wantErr && err == nil {
				t.Error("the walk finished although a directory it listed had become a link")
			}
			mustEqualState(t, "the other pod's tree after the pinned walk", treeState(t, victim), before)
		})
		t.Run("contrast, by path: "+tc.name, func(t *testing.T) {
			victim := victimTree(t)
			root := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			gid := fsGroupTestGid(t, victim)
			trigger, swap := tc.build(t, root, victim)
			before := treeState(t, victim)
			hook, ran := oneShot(t, trigger, swap)
			_ = byPathFSGroupWalk(root, gid, hook)
			if !*ran {
				t.Fatalf("the by-path walk never reached %s", trigger)
			}
			if describeState(treeState(t, victim)) == describeState(before) {
				t.Error("the by-path walk left the other tree untouched: the swap does not exercise the window, so the test above proves nothing")
			}
		})
	}
}

// TestFSGroupWalkLeavesLinkTargetsAlone: links that are simply there (no race)
// are chowned as links and never followed, whether they name a directory or a
// file outside the tree.
func TestFSGroupWalkLeavesLinkTargetsAlone(t *testing.T) {
	victim := victimTree(t)
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, victim)
	for link, target := range map[string]string{
		"to-dir":    victim,
		"d/to-file": filepath.Join(victim, "f"),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	before := treeState(t, victim)
	if err := ChownForFSGroup(podDir, root, gid); err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	mustEqualState(t, "the links' targets", treeState(t, victim), before)
	got := treeState(t, root)
	for _, link := range []string{"to-dir", "d/to-file"} {
		if int(got[link].Gid) != gid {
			t.Errorf("link %s gid = %d, want %d", link, got[link].Gid, gid)
		}
	}
	if _, descended := got["to-dir/b"]; descended {
		t.Error("the walk listed entries through a link")
	}
}

// TestFSGroupWalkRootIsALink: a rootfs that is itself a symlink when the walk
// starts (a pod can replace its own rootfs with one) is chowned as a link and
// nothing below its target is touched.
func TestFSGroupWalkRootIsALink(t *testing.T) {
	victim := victimTree(t)
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	if err := os.Symlink(victim, root); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, victim)
	before := treeState(t, victim)
	if err := ChownForFSGroup(podDir, root, gid); err != nil {
		t.Fatalf("ChownForFSGroup on a linked rootfs: %v", err)
	}
	mustEqualState(t, "the linked rootfs's target", treeState(t, victim), before)
}

// TestFSGroupWalkRefusesALinkedComponentAboveRoot: a directory between bound
// and root that is a link is refused, not followed.
func TestFSGroupWalkRefusesALinkedComponentAboveRoot(t *testing.T) {
	victim := victimTree(t)
	bound := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(bound, "pod-a")); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, victim)
	before := treeState(t, victim)
	if err := ChownForFSGroup(bound, filepath.Join(bound, "pod-a", "b"), gid); err == nil {
		t.Error("the walk went through a linked directory above its root")
	}
	mustEqualState(t, "the link's target", treeState(t, victim), before)
}

// TestFchmodatNoFollowLeavesTheTarget measures the system call the walk rests
// on for non-directories: fchmodat with AT_SYMLINK_NOFOLLOW on a name that is
// a symlink must not change the link's target. Systems differ on what it does
// instead (change the link's own mode, or refuse); either is safe, and the
// test records which this one does.
func TestFchmodatNoFollowLeavesTheTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	err = unix.Fchmodat(int(d.Fd()), "link", 0o777, unix.AT_SYMLINK_NOFOLLOW)
	t.Logf("fchmodat(link, 0777, AT_SYMLINK_NOFOLLOW) = %v", err)
	if got := modeOf(t, target).Perm(); got != 0o600 {
		t.Fatalf("the link's target mode = %o, want 0600: fchmodat followed the link", got)
	}
	if err == nil {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(dir, "link"), &st); err != nil {
			t.Fatal(err)
		}
		t.Logf("the link's own mode is now %o", st.Mode&0o7777)
	}
}

// openDescriptors counts this process's open file descriptors.
func openDescriptors(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("cannot list /dev/fd: %v", err)
	}
	return len(ents)
}

// TestFSGroupWalkHoldsAFixedNumberOfDescriptors: the walk does not keep one
// descriptor open per directory level. The tree is pod-authored, and a walk
// that did would let a deep chain of directories exhaust the daemon's
// descriptors. Measured at the deepest entry of a 120-level tree.
func TestFSGroupWalkHoldsAFixedNumberOfDescriptors(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	const depth = 120
	deep := root
	for i := 0; i < depth; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(deep, "leaf")
	if err := os.WriteFile(leaf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	base := openDescriptors(t)
	held := -1
	fsGroupBeforeApply = func(path string) {
		if path == leaf {
			held = openDescriptors(t) - base
		}
	}
	t.Cleanup(func() { fsGroupBeforeApply = nil })
	if err := ChownForFSGroup(podDir, root, gid); err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	fsGroupBeforeApply = nil
	if held < 0 {
		t.Fatal("the walk never reached the leaf")
	}
	// The pod dir, the root, the directory being listed, and the one that
	// listing /dev/fd itself opens: far below one per level.
	if held > 8 {
		t.Errorf("the walk held %d descriptors at depth %d, want a fixed handful", held, depth)
	}
	if got := modeOf(t, leaf).Perm(); got != 0o660 {
		t.Errorf("the leaf mode = %o, want 0660 (the walk must reach the bottom)", got)
	}
	if after := openDescriptors(t); after != base {
		t.Errorf("descriptors after the walk = %d, before = %d: the walk leaked", after, base)
	}
}

// TestFSGroupWalkDepthBound: a tree nested deeper than the bound is refused
// with ErrFSGroupTreeTooDeep, and one exactly at the bound is walked.
func TestFSGroupWalkDepthBound(t *testing.T) {
	old := maxFSGroupDepth
	maxFSGroupDepth = 3
	t.Cleanup(func() { maxFSGroupDepth = old })

	build := func(levels int) (podDir, root string) {
		podDir = t.TempDir()
		root = filepath.Join(podDir, "rootfs")
		p := root
		for i := 0; i < levels; i++ {
			p = filepath.Join(p, "d")
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return podDir, root
	}
	podDir, root := build(3)
	gid := fsGroupTestGid(t, root)
	if err := ChownForFSGroup(podDir, root, gid); err != nil {
		t.Errorf("a tree 3 directories deep with the bound at 3: %v", err)
	}
	podDir, root = build(4)
	if err := ChownForFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooDeep) {
		t.Errorf("a tree 4 directories deep with the bound at 3 = %v, want ErrFSGroupTreeTooDeep", err)
	}
}

// TestFSGroupWalkReportsErrors: a root that is not there, and a directory the
// walk cannot open, are reported, not skipped.
func TestFSGroupWalkReportsErrors(t *testing.T) {
	podDir := t.TempDir()
	gid := fsGroupTestGid(t, podDir)
	if err := ChownForFSGroup(podDir, filepath.Join(podDir, "absent"), gid); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("a missing root = %v, want ENOENT", err)
	}
	if os.Geteuid() == 0 {
		return // root opens a directory whatever its mode
	}
	root := filepath.Join(podDir, "rootfs")
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if err := ChownForFSGroup(podDir, root, gid); err == nil {
		t.Error("the walk skipped a directory it could not open")
	}
}
