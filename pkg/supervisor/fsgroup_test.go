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
	"math"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// byPathFSGroupWalk is the walk ChownForFSGroup made before it was pinned to
// descriptors, kept here as the reference: the ordinary-tree test compares
// results with it, and the swap tests run it as the contrast that shows what a
// walk by path does when an entry is swapped under it. hook is called where
// fsGroupTuning.beforeApply is: after the walk read what the entry is, before it
// changes it; beforeChmod is called where fsGroupTuning.beforeChmod is: after the
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
// testOwners names the test process as the only owner whose entries the walk
// may change: everything a test makes is the test process's.
var testOwners = FSGroupOwners{UIDs: []int{os.Geteuid()}}

// testTune is the tuning the tests' walks run under: fsGroupDefaults, with a
// test's bounds and seams set for that test by the helpers below. The test
// process's groups are all assigned groups, which the gid allow-list refuses,
// so the tests walk with chownForFSGroup, past the policy; the policy has
// tests of its own.
var testTune = fsGroupDefaults()

func walkFSGroup(bound, root string, gid int) (FSGroupReport, error) {
	return chownForFSGroup(context.Background(), bound, root, gid, testOwners, testTune)
}

// setFSGroupHooks installs the walk's seams for one test.
func setFSGroupHooks(t *testing.T, beforeApply, beforeChmod func(string)) {
	t.Helper()
	testTune.beforeApply, testTune.beforeChmod = beforeApply, beforeChmod
	t.Cleanup(func() { testTune.beforeApply, testTune.beforeChmod = nil, nil })
}

// lowerFSGroupBound sets one of the walk's bounds for one test.
func lowerFSGroupBound(t *testing.T, bound *int, v int) {
	t.Helper()
	old := *bound
	*bound = v
	t.Cleanup(func() { *bound = old })
}

// fsGroupTestGid returns a gid the test process may chown to, outside
// fsGroupNeverGids, and fails the test when there is none. It prefers a supplementary group that differs from
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
		if _, never := fsGroupNeverGids[g]; g > 0 && !never && g != int(st.Gid) {
			return g
		}
	}
	if _, never := fsGroupNeverGids[os.Getgid()]; os.Getgid() > 0 && !never {
		return os.Getgid()
	}
	t.Fatal("the test process has no gid above 0 to chown to (running as root?): the fsGroup tests run unprivileged by design, and a skipped walk test would report green")
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
	lowerFSGroupBound(t, &testTune.heldDirs, 8)
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
	if limit := testTune.heldDirs + 6; most > limit {
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

// changedCount counts the entries under root the walk has changed. The trees
// it is used on are made with owner-only modes, so a changed entry is one with
// a group permission bit; the group itself would not tell, when the process
// has only one group to chown to.
func changedCount(t *testing.T, root string) int {
	t.Helper()
	n := 0
	for _, st := range treeState(t, root) {
		if st.Mode&0o070 != 0 {
			n++
		}
	}
	return n
}

// TestFSGroupWalkBoundsFailClosed: a tree past the depth bound, the entry
// budget or the pending-directory budget stops the walk with its own error.
// The entries before the bound stay changed (a partial state the failed create
// discards) and nothing at or past it is changed. A tree exactly at each bound
// is walked.
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
		lowerFSGroupBound(t, &testTune.depth, 3)
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
		lowerFSGroupBound(t, &testTune.entries, 20)
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
		if n := changedCount(t, root); n == 0 || n > 20 {
			t.Errorf("%d entries were changed with the budget at 20, want some and at most 20", n)
		}
	})
	t.Run("waiting directories", func(t *testing.T) {
		// Each waiting directory named dNNN is charged fsGroupNodeCost + 4
		// bytes, so this budget pays for exactly ten of them.
		lowerFSGroupBound(t, &testTune.pendingBytes, 10*(fsGroupNodeCost+4))
		podDir, root := wide(t, 10, 0)
		gid := fsGroupTestGid(t, root)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Errorf("10 directories side by side with a budget for 10: %v", err)
		}
		podDir, root = wide(t, 30, 0)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooLarge) {
			t.Errorf("30 directories side by side with a budget for 10 = %v, want ErrFSGroupTreeTooLarge", err)
		}
		// The root and the ten the budget paid for, and not the eleventh: the
		// bound is checked before a directory is changed.
		if n := changedCount(t, root); n != 11 {
			t.Errorf("%d directories were changed with a budget for 10 waiting, want the root and 10", n)
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
	_, err := chownForFSGroup(ctx, podDir, root, gid, testOwners, testTune)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the walk under a cancelled context = %v, want context.Canceled", err)
	}
	if got := modeOf(t, deep); got.Perm() != 0o700 || got&os.ModeSetgid != 0 {
		t.Errorf("a directory the walk had not reached has mode %v, want it untouched", got)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := chownForFSGroup(ctx2, podDir, root, gid, testOwners, testTune); !errors.Is(err, context.Canceled) {
		t.Errorf("the walk started under a cancelled context = %v, want context.Canceled", err)
	}
}

// TestFSGroupWalkPassesOverWhatIsGone: an entry a pod process deletes after
// the walk listed it, a file or a whole directory still waiting to be listed,
// is passed over and counted, and the walk finishes the rest. Not changing
// what is gone changes nothing.
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
	goneDir := filepath.Join(root, "a", "gone-dir")
	removed := 0
	setFSGroupHooks(t, func(path string) {
		// Gone between the listing and the open.
		if path == goneFile {
			if err := os.Remove(goneFile); err == nil {
				removed++
			}
		}
	}, func(path string) {
		// A directory goes away once the walk has changed it and is keeping
		// it to list later.
		if path == goneDir {
			if err := os.RemoveAll(goneDir); err == nil {
				removed++
			}
		}
	})
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("the walk over a tree losing entries: %v", err)
	}
	if removed != 2 {
		t.Fatalf("%d of the 2 removals ran; the test did not exercise the case", removed)
	}
	// Passed over, and said so: a create must not succeed with a subtree left
	// unchanged and nothing to show for it.
	if rep.Vanished != 2 || rep.Skipped() != 2 {
		t.Errorf("report = %+v, want the file and the directory counted as vanished", rep)
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

// TestFSGroupMode pins the mode rule, including the part an unprivileged test
// run cannot reach through the walk: a chown by root keeps setuid and setgid,
// so the mode the walk sets must clear them on anything but a directory.
func TestFSGroupMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    uint32
		isDir bool
		want  uint32
	}{
		{"a private file", 0o600, false, 0o660},
		{"an executable", 0o755, false, 0o775},
		{"a read-only file", 0o400, false, 0o440},
		{"a directory gets setgid", 0o700, true, 0o2770},
		{"a sticky directory keeps the bit", 0o1700, true, 0o3770},
		{"a setuid file loses setuid", 0o4755, false, 0o0775},
		{"a setgid file loses setgid", 0o2755, false, 0o0775},
		{"a file with both loses both", 0o6700, false, 0o0770},
		{"a sticky file keeps the bit", 0o1600, false, 0o1660},
		{"the file type bits are not part of the mode", unix.S_IFREG | 0o600, false, 0o660},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fsGroupMode(tc.in, tc.isDir); got != tc.want {
				t.Errorf("fsGroupMode(%o, %v) = %o, want %o", tc.in, tc.isDir, got, tc.want)
			}
		})
	}
}

// TestFSGroupWalkRechecksWhatItOpened: a name that is swapped, after the walk
// read what it was, for a different kind of file that the same open still
// opens, is caught by examining the descriptor, and nothing is changed. A
// regular file replaced by a directory opens read-only; a symlink replaced by
// a regular file opens under O_SYMLINK. Without the re-check the walk would
// treat the one as a file and chown the other as a link.
func TestFSGroupWalkRechecksWhatItOpened(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, p string) // what the walk lists
		swap func(p string) error         // what it then finds
	}{
		{
			name: "a regular file replaced by a directory",
			make: func(t *testing.T, p string) {
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			swap: func(p string) error {
				if err := os.Remove(p); err != nil {
					return err
				}
				return os.Mkdir(p, 0o700)
			},
		},
		{
			name: "a symlink replaced by a regular file",
			make: func(t *testing.T, p string) {
				if err := os.Symlink("nowhere", p); err != nil {
					t.Fatal(err)
				}
			},
			swap: func(p string) error {
				if err := os.Remove(p); err != nil {
					return err
				}
				return os.WriteFile(p, []byte("x"), 0o600)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !fsGroupCanOpenLinks {
				t.Skip("links are not opened on this system")
			}
			podDir := t.TempDir()
			root := filepath.Join(podDir, "rootfs")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(root, "entry")
			tc.make(t, p)
			gid := fsGroupTestGid(t, root)
			hook, ran := oneShot(t, p, func() error { return tc.swap(p) })
			setFSGroupHooks(t, hook, nil)
			base := openDescriptors(t)
			_, err := walkFSGroup(podDir, root, gid)
			if !*ran {
				t.Fatal("the walk never reached the entry")
			}
			if !errors.Is(err, ErrFSGroupEntryChanged) {
				t.Errorf("the walk = %v, want ErrFSGroupEntryChanged", err)
			}
			if got := modeOf(t, p).Perm(); got&0o070 != 0 {
				t.Errorf("what replaced the entry has mode %o, want it untouched", got)
			}
			if after := openDescriptors(t); after != base {
				t.Errorf("descriptors after the refused walk = %d, before = %d: the error path leaked", after, base)
			}
		})
	}
}

// TestFSGroupWalkListsTheDirectoryItChanged: a directory that is replaced,
// after the walk changed it and before its turn to be listed, by a different
// directory of the same name is not listed: the walk recorded which directory
// it changed (device and inode) and stops when the name leads elsewhere.
func TestFSGroupWalkListsTheDirectoryItChanged(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	a := filepath.Join(root, "a")
	if err := os.MkdirAll(a, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	planted := filepath.Join(a, "planted")
	hook, ran := oneShot(t, a, func() error {
		if err := os.Rename(a, a+".moved"); err != nil {
			return err
		}
		if err := os.Mkdir(a, 0o700); err != nil {
			return err
		}
		return os.WriteFile(planted, []byte("x"), 0o600)
	})
	// In the window after the directory was changed: the node the walk keeps
	// for it names the original.
	setFSGroupHooks(t, nil, hook)
	base := openDescriptors(t)
	_, err := walkFSGroup(podDir, root, gid)
	if !*ran {
		t.Fatal("the walk never reached the directory")
	}
	if !errors.Is(err, ErrFSGroupEntryChanged) {
		t.Errorf("the walk = %v, want ErrFSGroupEntryChanged", err)
	}
	if got := modeOf(t, planted).Perm(); got != 0o600 {
		t.Errorf("a file in the directory that took the name has mode %o, want it untouched", got)
	}
	if after := openDescriptors(t); after != base {
		t.Errorf("descriptors after the refused walk = %d, before = %d: the error path leaked", after, base)
	}
}

// TestFSGroupWalkErrorPathsLeakNothing: a walk stopped by a budget or by its
// context closes every descriptor it had open, as one stopped by a changed
// entry does (the tests above).
func TestFSGroupWalkErrorPathsLeakNothing(t *testing.T) {
	build := func(t *testing.T) (podDir, root string) {
		podDir = t.TempDir()
		root = filepath.Join(podDir, "rootfs")
		for _, d := range []string{"a/b/c/d/e", "f/g/h", "i"} {
			if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return podDir, root
	}
	t.Run("the entry budget", func(t *testing.T) {
		lowerFSGroupBound(t, &testTune.entries, 5)
		podDir, root := build(t)
		gid := fsGroupTestGid(t, root)
		base := openDescriptors(t)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooLarge) {
			t.Fatalf("the walk = %v, want ErrFSGroupTreeTooLarge", err)
		}
		if after := openDescriptors(t); after != base {
			t.Errorf("descriptors after = %d, before = %d", after, base)
		}
	})
	t.Run("the depth bound", func(t *testing.T) {
		lowerFSGroupBound(t, &testTune.depth, 2)
		podDir, root := build(t)
		gid := fsGroupTestGid(t, root)
		base := openDescriptors(t)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooDeep) {
			t.Fatalf("the walk = %v, want ErrFSGroupTreeTooDeep", err)
		}
		if after := openDescriptors(t); after != base {
			t.Errorf("descriptors after = %d, before = %d", after, base)
		}
	})
	t.Run("a cancelled context", func(t *testing.T) {
		podDir, root := build(t)
		gid := fsGroupTestGid(t, root)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		seen := 0
		setFSGroupHooks(t, func(string) {
			if seen++; seen == 4 {
				cancel()
			}
		}, nil)
		base := openDescriptors(t)
		if _, err := chownForFSGroup(ctx, podDir, root, gid, testOwners, testTune); !errors.Is(err, context.Canceled) {
			t.Fatalf("the walk = %v, want context.Canceled", err)
		}
		if after := openDescriptors(t); after != base {
			t.Errorf("descriptors after = %d, before = %d", after, base)
		}
	})
}

// TestFSGroupWalkSkipsHardLinksInsideTheTree: hard links between two names in
// the tree, as an image layer's extraction leaves them, are skipped and
// reported like any other multiply-linked file. The walk cannot tell them from
// a link that leads outside, and says what it left alone.
func TestFSGroupWalkSkipsHardLinksInsideTheTree(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	bin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"tool", "plain"} {
		if err := os.WriteFile(filepath.Join(bin, f), []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// One program under three names, the way a layer ships a multi-call tool.
	for _, alias := range []string{"alias-a", "alias-b"} {
		if err := os.Link(filepath.Join(bin, "tool"), filepath.Join(bin, alias)); err != nil {
			t.Fatal(err)
		}
	}
	gid := fsGroupTestGid(t, root)
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.MultiLink != 3 || rep.Skipped() != 3 || len(rep.Examples) != 3 {
		t.Errorf("report = %+v, want the three names of the linked file skipped and named", rep)
	}
	if got := modeOf(t, filepath.Join(bin, "tool")).Perm(); got != 0o700 {
		t.Errorf("the hard-linked file has mode %o, want it untouched (0700)", got)
	}
	if got := modeOf(t, filepath.Join(bin, "plain")).Perm(); got != 0o770 {
		t.Errorf("the file with one link has mode %o, want 0770", got)
	}
}

// TestFSGroupWalkSkipCostIsBounded: skipping an entry costs no path. A pod
// that puts many entries the walk skips at the bottom of a deep tree would
// otherwise make the daemon build a path, in time proportional to the depth,
// for each one. The walk builds a path only for the examples it keeps, and a
// directory's path once per listing: for 400 skipped entries 150 levels down,
// at most one build for the directory and none per entry beyond the kept
// examples. Counted through the walk's seam, not timed.
func TestFSGroupWalkSkipCostIsBounded(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	const depth, skipped = 150, 400
	deep := root
	for i := 0; i < depth; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(deep, "f000")
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < skipped; i++ {
		if err := os.Link(first, filepath.Join(deep, fmt.Sprintf("f%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	gid := fsGroupTestGid(t, root)
	builds := 0
	testTune.onPathBuild = func() { builds++ }
	t.Cleanup(func() { testTune.onPathBuild = nil })
	rep, err := walkFSGroup(podDir, root, gid)
	testTune.onPathBuild = nil
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.MultiLink != skipped {
		t.Fatalf("skipped %d entries, want %d", rep.MultiLink, skipped)
	}
	if len(rep.Examples) != fsGroupReportExamples {
		t.Errorf("the report names %d entries, want %d", len(rep.Examples), fsGroupReportExamples)
	}
	if builds > 1 {
		t.Errorf("the walk built %d paths for %d skipped entries in one directory, want at most 1", builds, skipped)
	}
	for _, ex := range rep.Examples {
		if len(ex) > fsGroupExampleMax {
			t.Errorf("an example is %d bytes, want at most %d", len(ex), fsGroupExampleMax)
		}
	}
}

// reopenTree builds a spine of spine directories below root and, at each
// level of it, a side branch side directories deep. With
// maxFSGroupHeldDirs lowered below side, whichever of a level's two children
// the walk lists first, it closes ancestors of the other on the way down and
// has to re-open them to come back: re-opens happen whatever order the
// directory is read in. It returns the number of entries in the tree.
func reopenTree(t *testing.T, root string, spine, side int) int {
	t.Helper()
	p := root
	for i := 0; i < spine; i++ {
		p = filepath.Join(p, "s")
		q := filepath.Join(p, "b")
		for j := 1; j < side; j++ {
			q = filepath.Join(q, "b")
		}
		if err := os.MkdirAll(q, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return 1 + spine + spine*side
}

// TestFSGroupWalkReopenCostIsCharged: getting back to a directory whose
// ancestors the walk closed costs one open per level it re-opens, and each of
// those is charged to the same budget as the entries. Counted through the
// walk's seam on a deep spine with side branches: the walk finishes with the
// budget at exactly entries + re-opens, and stops with ErrFSGroupTreeTooLarge
// one below it.
func TestFSGroupWalkReopenCostIsCharged(t *testing.T) {
	lowerFSGroupBound(t, &testTune.heldDirs, 4)
	const spine, side = 30, 6
	reopens := 0
	testTune.onReopen = func() { reopens++ }
	t.Cleanup(func() { testTune.onReopen = nil })

	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	entries := reopenTree(t, root, spine, side)
	gid := fsGroupTestGid(t, root)
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	if rep.Changed != entries {
		t.Fatalf("changed %d entries, want %d", rep.Changed, entries)
	}
	if reopens == 0 {
		t.Fatal("the walk re-opened nothing; the tree does not exercise the case")
	}
	// Each listed directory re-opens at most the levels between root and
	// it, and the walk charges all of them: the walk costs at most
	// maxFSGroupEntries opens of either kind.
	if most := spine * (spine + side) * 2; reopens > most {
		t.Errorf("the walk re-opened %d levels, want at most %d", reopens, most)
	}
	t.Logf("%d entries, %d re-opened levels", entries, reopens)
	budget := entries + reopens

	t.Run("at the budget", func(t *testing.T) {
		lowerFSGroupBound(t, &testTune.entries, budget)
		podDir := t.TempDir()
		root := filepath.Join(podDir, "rootfs")
		reopenTree(t, root, spine, side)
		if _, err := walkFSGroup(podDir, root, gid); err != nil {
			t.Errorf("the walk with the budget at entries + re-opens (%d): %v", budget, err)
		}
	})
	t.Run("one below it", func(t *testing.T) {
		lowerFSGroupBound(t, &testTune.entries, budget-1)
		podDir := t.TempDir()
		root := filepath.Join(podDir, "rootfs")
		reopenTree(t, root, spine, side)
		base := openDescriptors(t)
		if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupTreeTooLarge) {
			t.Errorf("the walk with the budget one below entries + re-opens = %v, want ErrFSGroupTreeTooLarge", err)
		}
		if after := openDescriptors(t); after != base {
			t.Errorf("descriptors after = %d, before = %d", after, base)
		}
	})
	t.Run("a context ended during re-opens", func(t *testing.T) {
		podDir := t.TempDir()
		root := filepath.Join(podDir, "rootfs")
		reopenTree(t, root, spine, side)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		testTune.onReopen = cancel
		if _, err := chownForFSGroup(ctx, podDir, root, gid, testOwners, testTune); !errors.Is(err, context.Canceled) {
			t.Errorf("the walk cancelled at its first re-open = %v, want context.Canceled", err)
		}
	})
}

// TestFSGroupWalkRootGoneIsAnError: root removed after the walk changed it and
// before it was listed is an error, not a count: the create must not go on
// with nothing below root changed.
func TestFSGroupWalkRootGoneIsAnError(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	removed := false
	setFSGroupHooks(t, nil, func(path string) {
		if path == root && !removed {
			removed = os.RemoveAll(root) == nil
		}
	})
	_, err := walkFSGroup(podDir, root, gid)
	if !removed {
		t.Fatal("the removal did not run; the test did not exercise the case")
	}
	if !errors.Is(err, ErrFSGroupEntryChanged) {
		t.Errorf("the walk over a root removed before it was listed = %v, want ErrFSGroupEntryChanged", err)
	}
}

// TestFSGroupWalkClipsErrorPaths: the path in an error is cut the way an
// example is: the pod chooses it, and it is logged.
func TestFSGroupWalkClipsErrorPaths(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	long := strings.Repeat("n", 200)
	deep := filepath.Join(root, long, long, long)
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, root)
	lowerFSGroupBound(t, &testTune.depth, 2)
	_, err := walkFSGroup(podDir, root, gid)
	if !errors.Is(err, ErrFSGroupTreeTooDeep) {
		t.Fatalf("the walk = %v, want ErrFSGroupTreeTooDeep", err)
	}
	// The message holds the clipped path, the clipped root and its own words.
	if most := 2*fsGroupExampleMax + 100; len(err.Error()) > most {
		t.Errorf("the error is %d bytes, want at most %d: %.80q...", len(err.Error()), most, err.Error())
	}
	if strings.Contains(err.Error(), deep) {
		t.Error("the error carries the whole path")
	}
}

// TestFSGroupWalkLeavesForeignOwnersAlone: an entry owned by a uid outside the
// owners the caller names (another tenant's file or directory renamed in from
// a writable share keeps its one link and its owner) is left unchanged and
// counted, and a directory so owned is not entered. A root so owned is an
// error. An unprivileged test cannot make a file another uid owns, so the
// owner the walk reads is replaced through the walk's seam for the named
// paths; everything else about each entry is real.
func TestFSGroupWalkLeavesForeignOwnersAlone(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	for _, d := range []string{"own/sub", "theirs/inner"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"own/mine":         "x",
		"their-file":       "x",
		"theirs/inner/doc": "x",
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(root, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gid := fsGroupTestGid(t, root)
	const other = 4242
	foreign := map[string]bool{
		filepath.Join(root, "their-file"): true,
		filepath.Join(root, "theirs"):     true,
	}
	testTune.ownerOf = func(path string, uid uint32) uint32 {
		if foreign[path] {
			return other
		}
		return uid
	}
	t.Cleanup(func() { testTune.ownerOf = nil })
	before := treeState(t, root)
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	after := treeState(t, root)
	for _, rel := range []string{"their-file", "theirs", "theirs/inner", "theirs/inner/doc"} {
		if after[rel] != before[rel] {
			t.Errorf("%s changed: mode %07o gid %d -> mode %07o gid %d; another uid's entry, or one below it, must be left alone",
				rel, before[rel].Mode, before[rel].Gid, after[rel].Mode, after[rel].Gid)
		}
	}
	if got := modeOf(t, filepath.Join(root, "own", "mine")).Perm(); got != 0o660 {
		t.Errorf("the pod's own file has mode %o, want 0660", got)
	}
	if rep.ForeignOwner != 2 || rep.Skipped() != 2 {
		t.Errorf("report = %+v, want the foreign file and directory counted", rep)
	}

	// A root another uid owns is not the pod's tree at all.
	foreign[root] = true
	if _, err := walkFSGroup(podDir, root, gid); !errors.Is(err, ErrFSGroupForeignOwner) {
		t.Errorf("a root another uid owns = %v, want ErrFSGroupForeignOwner", err)
	}
}

// TestFSGroupWalkClearsSetID: a file with setuid or setgid has the bits
// cleared before its group is set, as a chown on Linux does, so a file the pod
// wrote never comes out setgid to the fsGroup; directories keep (and get)
// setgid. The test runs unprivileged, where the chown would clear the bits on
// its own, so the clear is seen through the report and through the order: the
// bits are already gone when the group is set.
func TestFSGroupWalkClearsSetID(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"suid": 0o755 | os.ModeSetuid,
		"sgid": 0o755 | os.ModeSetgid,
	} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if got := modeOf(t, p); got&(os.ModeSetuid|os.ModeSetgid) == 0 {
			t.Fatalf("%s has mode %v; the test could not set the bit", name, got)
		}
	}
	gid := fsGroupTestGid(t, root)
	atChown := map[string]os.FileMode{}
	setFSGroupHooks(t, nil, func(path string) {
		atChown[filepath.Base(path)] = modeOf(t, path)
	})
	rep, err := walkFSGroup(podDir, root, gid)
	if err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}
	for _, name := range []string{"suid", "sgid"} {
		if m := atChown[name]; m&(os.ModeSetuid|os.ModeSetgid) != 0 {
			t.Errorf("%s still had mode %v once its group was set", name, m)
		}
		got := modeOf(t, filepath.Join(root, name))
		if got&(os.ModeSetuid|os.ModeSetgid) != 0 || got.Perm() != 0o775 {
			t.Errorf("%s has mode %v, want 0775 with no setuid or setgid", name, got)
		}
	}
	if rep.SetID != 2 {
		t.Errorf("report = %+v, want both files counted as cleared", rep)
	}
	if got := modeOf(t, root); got&os.ModeSetgid == 0 {
		t.Errorf("the root directory has mode %v, want setgid", got)
	}
}

// unassignedGid is a gid at or above fsGroupMinGid that names no group on
// this host.
func unassignedGid(t *testing.T) int {
	t.Helper()
	for gid := 4242; gid < 4342; gid++ {
		if _, err := user.LookupGroupId(strconv.Itoa(gid)); err != nil {
			var unknown user.UnknownGroupIdError
			if errors.As(err, &unknown) {
				return gid
			}
		}
	}
	t.Fatal("every gid from 4242 to 4341 names a group on this host")
	return 0
}

// TestFSGroupGidAllowList: the gids a pod may be given are an allow-list. By
// default that is an unassigned gid from fsGroupMinGid to MaxInt32; every
// macOS group below that is refused, the ones a deny-list missed among them,
// and so is 250, the one fsGroup the k3sm admission policy admits today (the
// _k3sm uid, which on macOS is also the gid of _analyticsusers). A node may
// admit gids of its own, except fsGroupNeverGids. A refused gid changes
// nothing.
func TestFSGroupGidAllowList(t *testing.T) {
	free := unassignedGid(t)
	refused := []int{0, -1, math.MaxInt32 + 1, math.MaxUint32,
		1, 2, 3, 4, 5, 8, 9, 12, 20, 29, 61, 80, 98, 204, 250, 395, 396, 397, 398, 399, 400, 701, 999}
	for _, gid := range refused {
		if err := FSGroupGidAllowed(gid, nil); !errors.Is(err, ErrFSGroupGidRefused) {
			t.Errorf("gid %d = %v, want ErrFSGroupGidRefused", gid, err)
		}
	}
	for _, gid := range []int{free, fsGroupMinGid} {
		if _, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			continue // assigned on this host: the refusal below covers it
		}
		if err := FSGroupGidAllowed(gid, nil); err != nil {
			t.Errorf("unassigned gid %d = %v, want allowed", gid, err)
		}
	}
	for gid := fsGroupMinGid; gid < fsGroupMinGid+2000; gid++ {
		if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			if err := FSGroupGidAllowed(gid, nil); !errors.Is(err, ErrFSGroupGidRefused) {
				t.Errorf("gid %d, the group %q here, = %v, want refused", gid, g.Name, err)
			}
			break
		}
	}
	if err := FSGroupGidAllowed(12, []int{12}); err != nil {
		t.Errorf("an admitted gid = %v, want allowed", err)
	}
	for _, gid := range []int{0, 20, 80, math.MaxInt32 + 1} {
		if err := FSGroupGidAllowed(gid, []int{gid}); !errors.Is(err, ErrFSGroupGidRefused) {
			t.Errorf("admitted gid %d = %v, want refused all the same", gid, err)
		}
	}

	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, root)
	for _, gid := range refused {
		if _, err := ChownForFSGroup(context.Background(), podDir, root, gid, testOwners, nil); !errors.Is(err, ErrFSGroupGidRefused) {
			t.Errorf("ChownForFSGroup gid %d = %v, want ErrFSGroupGidRefused", gid, err)
		}
		if err := PrepareFSGroupRoot(podDir, root, gid, os.Geteuid(), nil); !errors.Is(err, ErrFSGroupGidRefused) {
			t.Errorf("PrepareFSGroupRoot gid %d = %v, want ErrFSGroupGidRefused", gid, err)
		}
	}
	if !reflect.DeepEqual(treeState(t, root), before) {
		t.Error("a refused gid changed the tree")
	}
	if _, err := ChownForFSGroup(context.Background(), podDir, root, free, FSGroupOwners{}, nil); err == nil || errors.Is(err, ErrFSGroupGidRefused) {
		t.Errorf("an empty owner set = %v, want refused as such", err)
	}
	for _, o := range []FSGroupOwners{{UIDs: []int{-1}}, {UIDs: []int{math.MaxInt32 + 1}}, {UIDs: []int{0}, InGroup: []int{math.MaxInt32 + 1}}} {
		if _, err := chownForFSGroup(context.Background(), podDir, root, fsGroupTestGid(t, root), o, testTune); err == nil {
			t.Errorf("owners %+v were accepted", o)
		}
	}
	if _, err := chownForFSGroup(context.Background(), podDir, root, math.MaxInt32+1, testOwners, testTune); err == nil {
		t.Error("a gid above MaxInt32 was accepted past the policy")
	}
}

// TestFSGroupGidLookupAsksDirectoryServices: a group that lives only in the
// system's directory services, not in /etc/group, is found by the lookup the
// allow-list makes, so such a group is not taken for an unassigned gid.
func TestFSGroupGidLookupAsksDirectoryServices(t *testing.T) {
	etc, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if strings.Contains(string(etc), ":"+strconv.Itoa(g)+":") {
			continue
		}
		grp, err := user.LookupGroupId(strconv.Itoa(g))
		if err != nil {
			t.Fatalf("gid %d, a group of this process missing from /etc/group, was not found: %v", g, err)
		}
		t.Logf("gid %d (%s) is in directory services only, and the lookup finds it", g, grp.Name)
		return
	}
	t.Log("every group of this process is in /etc/group; nothing to measure here")
}

// TestFSGroupLeavesRootOwnedEntriesRenamedIn: a daemon running as root whose
// pod drops to another uid names root only in owners.InGroup. A file and a
// directory root owns, renamed into the tree from a writable share, keep
// their group and mode (the pod would otherwise have the walk give its group
// a root-owned file, then rename it back out); what the daemon put in the
// pod's root, which carries the gid already because the root was given it
// first (PrepareFSGroupRoot), still gets the group's mode. The owner seam
// stands in for root's ownership, which an unprivileged test cannot make.
func TestFSGroupLeavesRootOwnedEntriesRenamedIn(t *testing.T) {
	podDir := t.TempDir()
	root := filepath.Join(podDir, "rootfs")
	share := t.TempDir()
	for _, d := range []string{root, filepath.Join(share, "rootdir", "inner")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gid := fsGroupTestGid(t, root)
	if err := PrepareFSGroupRoot(podDir, root, gid, os.Geteuid(), []int{gid}); err != nil {
		t.Fatalf("PrepareFSGroupRoot: %v", err)
	}
	// What the daemon makes after the root has the group: it takes the group.
	if err := os.MkdirAll(filepath.Join(root, "daemon-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "daemon-dir", "secret"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	// What a pod process renames in from a share: it keeps its group.
	if err := os.WriteFile(filepath.Join(share, "rootfile"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"rootfile", "rootdir"} {
		if err := os.Rename(filepath.Join(share, n), filepath.Join(root, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "pods-own"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	const podUID = 4243
	rootOwned := map[string]bool{
		filepath.Clean(root):                        true,
		filepath.Join(root, "daemon-dir"):           true,
		filepath.Join(root, "daemon-dir", "secret"): true,
		filepath.Join(root, "rootfile"):             true,
		filepath.Join(root, "rootdir"):              true,
		filepath.Join(root, "rootdir", "inner"):     true,
	}
	testTune.ownerOf = func(path string, uid uint32) uint32 {
		if rootOwned[path] {
			return 0
		}
		return podUID
	}
	t.Cleanup(func() { testTune.ownerOf = nil })
	before := treeState(t, root)
	rep, err := chownForFSGroup(context.Background(), podDir, root, gid,
		FSGroupOwners{UIDs: []int{podUID}, InGroup: []int{0}}, testTune)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	after := treeState(t, root)
	for _, rel := range []string{"rootfile", "rootdir", "rootdir/inner"} {
		if after[rel] != before[rel] {
			t.Errorf("%s, root's and renamed in, changed: mode %07o gid %d -> mode %07o gid %d",
				rel, before[rel].Mode, before[rel].Gid, after[rel].Mode, after[rel].Gid)
		}
	}
	for rel, perm := range map[string]os.FileMode{"daemon-dir": 0o775, "daemon-dir/secret": 0o660, "pods-own": 0o660, ".": 0o775} {
		if after[rel].Gid != uint32(gid) || os.FileMode(after[rel].Mode).Perm() != perm {
			t.Errorf("%s: mode %o gid %d, want mode %o gid %d", rel, os.FileMode(after[rel].Mode).Perm(), after[rel].Gid, perm, gid)
		}
	}
	if rep.ForeignOwner != 2 {
		t.Errorf("report = %+v, want the renamed-in file and directory counted as foreign", rep)
	}
}

// TestFSGroupClipKeepsUTF8: a path cut for a message is cut at the start of a
// rune, so the message stays valid UTF-8.
func TestFSGroupClipKeepsUTF8(t *testing.T) {
	for pad := 0; pad < 4; pad++ {
		s := strings.Repeat("a", pad) + strings.Repeat("é€😀", 40)
		got := fsGroupClip(s)
		if len(got) > fsGroupExampleMax {
			t.Errorf("pad %d: %d bytes, want at most %d", pad, len(got), fsGroupExampleMax)
		}
		if !utf8.ValidString(got) {
			t.Errorf("pad %d: the clipped path is not valid UTF-8: %q", pad, got)
		}
	}
}
