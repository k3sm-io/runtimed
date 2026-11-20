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
	"context"
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
// changes it; beforeChmod is called where fsGroupBeforeChmod is: after the
// group is set, before the mode is.
func byPathFSGroupWalk(root string, gid int, hook, beforeChmod func(path string)) error {
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
		if beforeChmod != nil {
			beforeChmod(path)
		}
		if err := os.Chmod(path, newMode); err != nil {
			return fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return nil
	})
}

// walkFSGroup runs the walk under test with a background context and returns
// its report and error.
func walkFSGroup(bound, root string, gid int) (FSGroupReport, error) {
	return ChownForFSGroup(context.Background(), bound, root, gid)
}

// setFSGroupHooks installs the walk's seams for one test.
func setFSGroupHooks(t *testing.T, beforeApply, beforeChmod func(string)) {
	t.Helper()
	fsGroupBeforeApply, fsGroupBeforeChmod = beforeApply, beforeChmod
	t.Cleanup(func() { fsGroupBeforeApply, fsGroupBeforeChmod = nil, nil })
}

// lowerFSGroupBound sets one of the walk's bounds for one test.
func lowerFSGroupBound(t *testing.T, bound *int, v int) {
	t.Helper()
	old := *bound
	*bound = v
	t.Cleanup(func() { *bound = old })
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

	rep, err := walkFSGroup(podA, rootA, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.Skipped() != 0 {
		t.Errorf("the walk skipped entries of an ordinary tree: %+v", rep)
	}
	if err := byPathFSGroupWalk(rootB, gid, nil, nil); err != nil {
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
	// listed something else) or may finish (it never looks the swapped name
	// up again).
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
			// The walk holds the directory it was listing open, so it goes
			// on inside the real one under its new name and never looks the
			// swapped name up again.
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
			setFSGroupHooks(t, hook, nil)
			_, err := walkFSGroup(podDir, root, gid)

			if !*ran {
				t.Fatalf("the walk never reached %s, so nothing was swapped", trigger)
			}
			if tc.wantErr && err == nil {
				t.Error("the walk finished although an entry it listed had become a link")
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
			_ = byPathFSGroupWalk(root, gid, hook, nil)
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
	if _, err := walkFSGroup(podDir, root, gid); err != nil {
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
	if _, err := walkFSGroup(podDir, root, gid); err != nil {
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
	if _, err := walkFSGroup(bound, filepath.Join(bound, "pod-a", "b"), gid); err == nil {
		t.Error("the walk went through a linked directory above its root")
	}
	mustEqualState(t, "the link's target", treeState(t, victim), before)
}

// TestFSGroupWalkOpensWhatItChanges measures the open(2) behaviour the walk
// rests on, on this system: a symlink opened as itself gives a descriptor on
// the link, through which a chown changes the link and not its target; and a
// FIFO with no writer opens at once when the open is non-blocking.
func TestFSGroupWalkOpensWhatItChanges(t *testing.T) {
	if !fsGroupCanOpenLinks {
		t.Skip("this system cannot open a symlink as itself; the walk leaves links alone here")
	}
	dir := t.TempDir()
	gid := fsGroupTestGid(t, dir)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, dir)["target"]
	fd, err := unix.Open(filepath.Join(dir, "link"), fsGroupLinkFlags, 0)
	if err != nil {
		t.Fatalf("open the link as itself: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Fatalf("the descriptor is on a %o, want the symlink itself", st.Mode&unix.S_IFMT)
	}
	if err := unix.Fchown(fd, -1, gid); err != nil {
		t.Fatalf("fchown through the link's descriptor: %v", err)
	}
	unix.Close(fd)
	after := treeState(t, dir)
	if after["target"] != before {
		t.Errorf("the link's target changed: %+v -> %+v", before, after["target"])
	}
	if int(after["link"].Gid) != gid {
		t.Errorf("the link's own gid = %d, want %d", after["link"].Gid, gid)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Were this open to block, the test would hang until the test binary's
	// own timeout, whose stack dump names this line: the watchdog is go
	// test's, not a wall-clock wait here.
	ffd, err := unix.Open(fifo, fsGroupFileFlags, 0)
	if err != nil {
		t.Fatalf("non-blocking open of a FIFO with no writer: %v", err)
	}
	unix.Close(ffd)
}

// outsideFile makes a file that is not in any pod's tree, as the operator's
// own file would be, and returns its path.
func outsideFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "theirs")
	if err := os.WriteFile(f, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func entryOf(t *testing.T, path string) entryState {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return entryState{Mode: uint32(st.Mode), Gid: st.Gid}
}

// TestFSGroupWalkSkipsAHardLinkedFile: a file in the tree that has another
// hard link, which may lie outside the tree where the file is somebody else's,
// is left exactly as it was and reported. The contrast is the by-path walk,
// which changes the outside file's group and mode through the link.
func TestFSGroupWalkSkipsAHardLinkedFile(t *testing.T) {
	build := func(t *testing.T) (podDir, root, outside string) {
		outside = outsideFile(t)
		podDir = t.TempDir()
		root = filepath.Join(podDir, "rootfs")
		if err := os.MkdirAll(filepath.Join(root, "d"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(root, "d", "linked-in")); err != nil {
			t.Skipf("cannot hard-link across these temp dirs: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "d", "own"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return podDir, root, outside
	}
	t.Run("the pinned walk", func(t *testing.T) {
		podDir, root, outside := build(t)
		gid := fsGroupTestGid(t, outside)
		before := entryOf(t, outside)
		rep, err := walkFSGroup(podDir, root, gid)
		if err != nil {
			t.Fatalf("ChownForFSGroup: %v", err)
		}
		if got := entryOf(t, outside); got != before {
			t.Errorf("the outside file changed through its hard link: %+v -> %+v", before, got)
		}
		if rep.MultiLink != 1 || len(rep.Examples) != 1 || !strings.Contains(rep.Examples[0], "linked-in") {
			t.Errorf("report = %+v, want the one hard-linked file named", rep)
		}
		// The control: the walk did run, on the file with one link beside it.
		if got := modeOf(t, filepath.Join(root, "d", "own")).Perm(); got != 0o660 {
			t.Errorf("the singly-linked file beside it has mode %o, want 0660", got)
		}
	})
	t.Run("contrast, by path", func(t *testing.T) {
		_, root, outside := build(t)
		gid := fsGroupTestGid(t, outside)
		before := entryOf(t, outside)
		if err := byPathFSGroupWalk(root, gid, nil, nil); err != nil {
			t.Fatal(err)
		}
		if got := entryOf(t, outside); got == before {
			t.Error("the by-path walk left the outside file untouched: the case does not show the problem")
		}
	})
}

// TestFSGroupWalkChangesTheFileItOpened: the walk sets the group and then the
// mode on one descriptor. A pod process that replaces the name with a hard
// link to an outside file after the group was set and before the mode is, the
// narrowest window there is, gets nothing: the mode goes to the file that was
// opened. The contrast is the by-path walk, whose chmod goes to whatever the
// name means by then.
func TestFSGroupWalkChangesTheFileItOpened(t *testing.T) {
	build := func(t *testing.T) (podDir, root, f, outside string, swap func() error) {
		outside = outsideFile(t)
		podDir = t.TempDir()
		root = filepath.Join(podDir, "rootfs")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		f = filepath.Join(root, "f")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return podDir, root, f, outside, func() error {
			if err := os.Remove(f); err != nil {
				return err
			}
			return os.Link(outside, f)
		}
	}
	t.Run("the pinned walk", func(t *testing.T) {
		podDir, root, f, outside, swap := build(t)
		gid := fsGroupTestGid(t, outside)
		before := entryOf(t, outside)
		hook, ran := oneShot(t, f, swap)
		setFSGroupHooks(t, nil, hook)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Fatalf("ChownForFSGroup: %v", err)
		}
		if !*ran {
			t.Fatal("the walk never reached the window")
		}
		if got := entryOf(t, outside); got != before {
			t.Errorf("the outside file changed: %+v -> %+v", before, got)
		}
	})
	t.Run("contrast, by path", func(t *testing.T) {
		_, root, f, outside, swap := build(t)
		gid := fsGroupTestGid(t, outside)
		before := entryOf(t, outside)
		hook, ran := oneShot(t, f, swap)
		_ = byPathFSGroupWalk(root, gid, nil, hook)
		if !*ran {
			t.Fatal("the by-path walk never reached the window")
		}
		if got := entryOf(t, outside); got == before {
			t.Error("the by-path walk left the outside file untouched: the swap does not land in the window")
		}
	})
}

// TestFSGroupWalkDoesNotBlockOnAFIFO: a directory that a pod process replaces
// with a FIFO between the listing and the open neither blocks the walk (a
// blocking open of a FIFO waits for a writer, for as long as the pod likes)
// nor is treated as a directory: the walk stops with ErrFSGroupEntryChanged.
// A FIFO that is simply there is changed like a file, also without blocking.
func TestFSGroupWalkDoesNotBlockOnAFIFO(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	d := filepath.Join(root, "d")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "plain-fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	hook, ran := oneShot(t, d, func() error {
		if err := os.Remove(d); err != nil {
			return err
		}
		return unix.Mkfifo(d, 0o600)
	})
	setFSGroupHooks(t, hook, nil)
	// A walk that blocked here would hang until the test binary's own
	// timeout, whose stack dump names the open: that is the watchdog.
	_, err := walkFSGroup(podDir, root, gid)
	if !*ran {
		t.Fatal("the walk never reached the directory")
	}
	if !errors.Is(err, ErrFSGroupEntryChanged) {
		t.Errorf("the walk over a directory that became a FIFO = %v, want ErrFSGroupEntryChanged", err)
	}
	if got := modeOf(t, d).Perm(); got != 0o600 {
		t.Errorf("the FIFO that replaced the directory has mode %o, want it untouched (0600)", got)
	}

	// The same tree with nothing swapped: the plain FIFO is opened (with no
	// writer), changed, and the walk returns.
	setFSGroupHooks(t, nil, nil)
	if _, err := walkFSGroup(podDir, root, gid); err != nil {
		t.Fatalf("the walk over a tree holding FIFOs: %v", err)
	}
	if got := modeOf(t, filepath.Join(root, "plain-fifo")).Perm(); got != 0o660 {
		t.Errorf("the plain FIFO has mode %o, want 0660", got)
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

// TestFSGroupWalkCostIsBounded: on a tree that is both deep and wide, the walk
// keeps no more directories open than maxFSGroupHeldDirs (plus the few it
// needs to work), still reaches the deepest entry and comes back to a shallow
// branch whose directory it had closed, and leaks nothing. The tree is
// pod-authored, so the descriptors are what a pod can make the daemon spend;
// its memory is bounded by the budgets TestFSGroupWalkBoundsFailClosed pins.
func TestFSGroupWalkCostIsBounded(t *testing.T) {
	lowerFSGroupBound(t, &maxFSGroupHeldDirs, 8)
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	const depth, width = 60, 40
	deep := root
	for i := 0; i < depth; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	// A wide directory at the bottom, and a second branch near the top that
	// the walk comes back to after the deep one.
	for i := 0; i < width; i++ {
		if err := os.Mkdir(filepath.Join(deep, fmt.Sprintf("w%02d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "d", "second", "branch"), 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(deep, "w39", "leaf")
	if err := os.WriteFile(leaf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	base := openDescriptors(t)
	most := 0
	setFSGroupHooks(t, func(string) {
		if n := openDescriptors(t) - base; n > most {
			most = n
		}
	}, nil)
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	const dirs = 1 + depth + width + 2
	if rep.Changed != dirs+1 {
		t.Errorf("changed %d entries, want %d directories and one file", rep.Changed, dirs)
	}
	// Held directories, the pod dir, the listing's own descriptor, and the
	// one listing /dev/fd opens.
	if limit := maxFSGroupHeldDirs + 6; most > limit {
		t.Errorf("the walk had %d descriptors open at its most, want at most %d for a tree %d deep", most, limit, depth)
	}
	if got := modeOf(t, leaf).Perm(); got != 0o660 {
		t.Errorf("the deepest file has mode %o, want 0660 (the walk must reach it)", got)
	}
	if got := modeOf(t, filepath.Join(root, "d", "second", "branch")); got.Perm() != 0o770 || got&os.ModeSetgid == 0 {
		t.Errorf("the second branch has mode %v, want group rwx and setgid (the walk must come back to it)", got)
	}
	if after := openDescriptors(t); after != base {
		t.Errorf("descriptors after the walk = %d, before = %d: the walk leaked", after, base)
	}
}

// changedCount counts the entries under root whose group is gid.
func changedCount(t *testing.T, root string, gid int) int {
	t.Helper()
	n := 0
	for _, st := range treeState(t, root) {
		if int(st.Gid) == gid {
			n++
		}
	}
	return n
}

// TestFSGroupWalkBoundsFailClosed: a tree past the depth bound, the entry
// budget or the pending-directory budget stops the walk with its own error,
// and nothing past the bound is changed. A tree exactly at each bound is
// walked.
func TestFSGroupWalkBoundsFailClosed(t *testing.T) {
	chain := func(t *testing.T, levels int) (podDir, root string) {
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
	wide := func(t *testing.T, dirs, files int) (podDir, root string) {
		podDir = t.TempDir()
		root = filepath.Join(podDir, "rootfs")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < dirs; i++ {
			if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("d%03d", i)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < files; i++ {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%03d", i)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return podDir, root
	}

	t.Run("depth", func(t *testing.T) {
		lowerFSGroupBound(t, &maxFSGroupDepth, 3)
		podDir, root := chain(t, 3)
		gid := fsGroupTestGid(t, root)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Errorf("a tree 3 directories deep with the bound at 3: %v", err)
		}
		podDir, root = chain(t, 5)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooDeep) {
			t.Errorf("a tree 5 directories deep with the bound at 3 = %v, want ErrFSGroupTreeTooDeep", err)
		}
		past := filepath.Join(root, "d", "d", "d", "d")
		if got := modeOf(t, past); got.Perm() != 0o700 || got&os.ModeSetgid != 0 {
			t.Errorf("the directory past the depth bound has mode %v, want it untouched", got)
		}
	})
	t.Run("entries", func(t *testing.T) {
		lowerFSGroupBound(t, &maxFSGroupEntries, 20)
		// The root is one entry: 19 more reach the budget exactly.
		podDir, root := wide(t, 4, 15)
		gid := fsGroupTestGid(t, root)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Errorf("a tree of 20 entries with the budget at 20: %v", err)
		}
		podDir, root = wide(t, 4, 40)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooLarge) {
			t.Errorf("a tree of 45 entries with the budget at 20 = %v, want ErrFSGroupTreeTooLarge", err)
		}
		if n := changedCount(t, root, gid); n > 20 {
			t.Errorf("%d entries were changed with the budget at 20", n)
		}
	})
	t.Run("pending directories", func(t *testing.T) {
		lowerFSGroupBound(t, &maxFSGroupPendingDirs, 10)
		podDir, root := wide(t, 10, 0)
		gid := fsGroupTestGid(t, root)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Errorf("10 directories side by side with the budget at 10: %v", err)
		}
		podDir, root = wide(t, 30, 0)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooLarge) {
			t.Errorf("30 directories side by side with the budget at 10 = %v, want ErrFSGroupTreeTooLarge", err)
		}
	})
}

// TestFSGroupWalkStopsWhenItsContextEnds: the walk checks its context as it
// goes; cancelling it stops the walk with the context's error and leaves the
// directories it had not reached untouched.
func TestFSGroupWalkStopsWhenItsContextEnds(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	deep := filepath.Join(root, "a", "b", "c", "d")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setFSGroupHooks(t, func(path string) {
		if path == filepath.Join(root, "a") {
			cancel()
		}
	}, nil)
	_, err := ChownForFSGroup(ctx, podDir, root, gid)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the walk under a cancelled context = %v, want context.Canceled", err)
	}
	if got := modeOf(t, deep); got.Perm() != 0o700 || got&os.ModeSetgid != 0 {
		t.Errorf("a directory the walk had not reached has mode %v, want it untouched", got)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := ChownForFSGroup(ctx2, podDir, root, gid); !errors.Is(err, context.Canceled) {
		t.Errorf("the walk started under a cancelled context = %v, want context.Canceled", err)
	}
}

// TestFSGroupWalkPassesOverWhatIsGone: an entry a pod process deletes after
// the walk listed it, a file or a whole directory still waiting to be listed,
// is passed over, and the walk finishes the rest. Not changing what is gone
// changes nothing.
func TestFSGroupWalkPassesOverWhatIsGone(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	for _, d := range []string{"a/gone-dir/x", "z/kept"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	goneFile := filepath.Join(root, "a", "gone-file")
	if err := os.WriteFile(goneFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	removed := 0
	setFSGroupHooks(t, func(path string) {
		switch path {
		case goneFile:
			// Gone between the listing and the open.
			if err := os.Remove(goneFile); err == nil {
				removed++
			}
		case filepath.Join(root, "z"):
			// A directory already changed and waiting to be listed goes away.
			if err := os.RemoveAll(filepath.Join(root, "a", "gone-dir")); err == nil {
				removed++
			}
		}
	}, nil)
	if _, err := walkFSGroup(podDir, root, gid); err != nil {
		t.Fatalf("the walk over a tree losing entries: %v", err)
	}
	if removed != 2 {
		t.Fatalf("%d of the 2 removals ran; the test did not exercise the case", removed)
	}
	if got := modeOf(t, filepath.Join(root, "z", "kept")); got.Perm() != 0o770 || got&os.ModeSetgid == 0 {
		t.Errorf("a directory after the removed ones has mode %v, want group rwx and setgid", got)
	}
}

// TestFSGroupWalkReportsWhatItSkips: a socket is skipped and reported, and a
// root that is not there, or a directory the walk cannot open, is an error.
func TestFSGroupWalkReportsWhatItSkips(t *testing.T) {
	podDir, err := os.MkdirTemp("/tmp", "fsg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(podDir) })
	gid := fsGroupTestGid(t, podDir)
	if _, err := walkFSGroup(podDir, filepath.Join(podDir, "absent"), gid); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("a missing root = %v, want ENOENT", err)
	}
	root := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(root, "s")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatalf("bind %s: %v", sock, err)
	}
	before := entryOf(t, sock)
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.Special != 1 || rep.Skipped() != 1 {
		t.Errorf("report = %+v, want the socket skipped", rep)
	}
	if got := entryOf(t, sock); got != before {
		t.Errorf("the socket changed: %+v -> %+v", before, got)
	}
	if os.Geteuid() == 0 {
		return // root opens a file or a directory whatever its mode
	}
	// A file the caller cannot read cannot be opened, so it cannot be changed
	// through a descriptor: it is skipped and reported, never changed by name.
	writeOnly := filepath.Join(root, "write-only")
	if err := os.WriteFile(writeOnly, []byte("x"), 0o200); err != nil {
		t.Fatal(err)
	}
	wasWriteOnly := entryOf(t, writeOnly)
	rep, err = walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.Unopenable != 1 {
		t.Errorf("report = %+v, want the unreadable file skipped", rep)
	}
	if got := entryOf(t, writeOnly); got != wasWriteOnly {
		t.Errorf("the unreadable file changed: %+v -> %+v", wasWriteOnly, got)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := walkFSGroup(podDir, root, gid); err == nil {
		t.Error("the walk skipped a directory it could not open")
	}
}
