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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The mounts the directory/metadata gate rebases. Both are chosen so a rebase
// that does not happen can never mutate the host:
//
//   - dirMetaMount sits directly under "/", on the sealed read-only system
//     volume, so the host path cannot exist and cannot be created.
//   - dirMetaDeepMount is a depth-2 mount whose ancestor (/usr) EXISTS on the
//     host, which is what `mkdir -p <mount>/x/y` needs: mkdir(1) walks the
//     components from "/", and an ancestor above a mount prefix is a host path
//     (the documented ceiling in the shim header). /usr is on the sealed system
//     volume too, so /usr/k3sm-b425-mnt cannot be created either. A fictitious
//     ancestor ("/k3sm-b425/mnt") would make the walk fail at "/k3sm-b425" by
//     design, which is the ceiling, not this item.
const (
	dirMetaMount     = "/k3sm-b425-mnt"
	dirMetaDeepMount = "/usr/k3sm-b425-mnt"
	// dirMetaEscapeName is what "<mount>/../" names: the host path
	// "/k3sm-b425-escape" (sealed volume, cannot exist), which a wrong
	// rebase would instead resolve to "<rootfs>/k3sm-b425-escape".
	dirMetaEscapeName = "k3sm-b425-escape"
)

// dirMetaHelperSrc is a C caller for the raw entry points no shadow utility
// reaches on its own (the *at forms, fopen/freopen, opendir). One op per run;
// every path argument is passed straight to the libc call.
const dirMetaHelperSrc = `#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static int fail(const char *op) { fprintf(stderr, "%s: %s\n", op, strerror(errno)); return 1; }

int main(int argc, char **argv) {
	if (argc < 3) { fprintf(stderr, "usage\n"); return 2; }
	const char *op = argv[1], *a = argv[2], *b = argc > 3 ? argv[3] : NULL;
	if (!strcmp(op, "mkdir")) return mkdir(a, 0755) ? fail(op) : 0;
	if (!strcmp(op, "mkdirat")) return mkdirat(AT_FDCWD, a, 0755) ? fail(op) : 0;
	if (!strcmp(op, "rmdir")) return rmdir(a) ? fail(op) : 0;
	if (!strcmp(op, "unlink")) return unlink(a) ? fail(op) : 0;
	if (!strcmp(op, "unlinkat")) return unlinkat(AT_FDCWD, a, 0) ? fail(op) : 0;
	if (!strcmp(op, "unlinkat-dir")) return unlinkat(AT_FDCWD, a, AT_REMOVEDIR) ? fail(op) : 0;
	if (!strcmp(op, "rename")) return rename(a, b) ? fail(op) : 0;
	if (!strcmp(op, "chmod")) return chmod(a, 0600) ? fail(op) : 0;
	if (!strcmp(op, "fchmodat")) return fchmodat(AT_FDCWD, a, 0600, 0) ? fail(op) : 0;
	if (!strcmp(op, "linkat")) return linkat(AT_FDCWD, a, AT_FDCWD, b, 0) ? fail(op) : 0;
	if (!strcmp(op, "symlink")) return symlink(a, b) ? fail(op) : 0;
	if (!strcmp(op, "symlinkat")) return symlinkat(a, AT_FDCWD, b) ? fail(op) : 0;
	if (!strcmp(op, "readlink")) {
		char buf[1024];
		ssize_t n = readlink(a, buf, sizeof(buf));
		if (n < 0) return fail(op);
		fwrite(buf, 1, (size_t)n, stdout);
		return 0;
	}
	if (!strcmp(op, "utimensat")) {
		struct timespec ts[2] = {{1000000000, 0}, {1000000000, 0}};
		return utimensat(AT_FDCWD, a, ts, 0) ? fail(op) : 0;
	}
	if (!strcmp(op, "clonefileat")) return clonefileat(AT_FDCWD, a, AT_FDCWD, b, 0) ? fail(op) : 0;
	if (!strcmp(op, "fopen-w")) {
		FILE *f = fopen(a, "w");
		if (f == NULL) return fail(op);
		fputs("via-fopen\n", f);
		return fclose(f) ? fail(op) : 0;
	}
	if (!strcmp(op, "fopen-r")) {
		FILE *f = fopen(a, "r");
		if (f == NULL) return fail(op);
		char buf[256];
		size_t n = fread(buf, 1, sizeof(buf), f);
		fwrite(buf, 1, n, stdout);
		return fclose(f) ? fail(op) : 0;
	}
	if (!strcmp(op, "freopen")) {
		if (freopen(a, "w", stdout) == NULL) return fail(op);
		fputs("via-freopen\n", stdout);
		return fflush(stdout) ? fail(op) : 0;
	}
	if (!strcmp(op, "opendir")) {
		DIR *d = opendir(a);
		if (d == NULL) return fail(op);
		struct dirent *e;
		while ((e = readdir(d)) != NULL) printf("%s\n", e->d_name);
		return closedir(d) ? fail(op) : 0;
	}
	fprintf(stderr, "unknown op %s\n", op);
	return 2;
}
`

// buildDirMetaHelper compiles dirMetaHelperSrc for the host arch. clang's
// linker signs it ad hoc, and it is not a platform binary, so dyld honours
// DYLD_INSERT_LIBRARIES in it.
func buildDirMetaHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "helper.c")
	if err := os.WriteFile(src, []byte(dirMetaHelperSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "dirmeta-helper")
	if out, err := exec.Command("clang", "-Wall", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build the C helper: %v\n%s", err, out)
	}
	return bin
}

// dirMetaRow is one interposed call (or one utility whose imports reach it).
type dirMetaRow struct {
	name string
	// tool is a cloned utility name, or "" for the C helper.
	tool string
	// args are passed after the tool (or are the helper's op and paths).
	args []string
	// setup prepares the rootfs (the materialized mount copies).
	setup func(t *testing.T, rootfs string)
	// check returns nil iff the call's effect landed under rootfs. out is the
	// child's stdout+stderr, used only by the read-only rows (opendir,
	// readlink, fopen-r), whose effect IS what they return.
	check func(rootfs, out string) error
	// ceilingErr marks a documented ceiling of the shim (see its header): the
	// row pins that the call still FAILS with the shim with exactly this
	// host-path error in its output, without touching the host, so a change
	// that closes the ceiling turns it red and must flip it, and an unrelated
	// failure cannot satisfy the pin.
	ceilingErr string
	// refused marks a row whose call must FAIL with the shim (check then
	// reads the error the child printed).
	refused bool
	// boundary marks a row asserting a path is NOT rebased: there is no
	// no-shim contrast, because the shim must behave as if absent.
	boundary bool
	// needsClone marks a row that needs clonefile(2) on the test temp dir.
	needsClone bool
}

// TestShadowCopiesRebaseDirectoryAndMetadataCalls is the B425 gate: the path
// shim rebases the directory and metadata family (mkdir, rmdir, unlink, rename,
// chmod, link, symlink, readlink, utimensat, clonefileat, their *at forms, and
// fopen/freopen) for a mounted absolute path, the way it already rebases open.
//
// Each row runs a re-signed clone of the real utility (cp -c + ad-hoc sign,
// the shadow-set recipe, so dyld keeps DYLD_INSERT_LIBRARIES) or the C helper,
// with the BUILT shim inserted and a mount configured, and asserts:
//
//   - the effect landed under <rootfs><mount>/..., read from the filesystem;
//   - the host mount path was not created;
//   - the same run WITHOUT the shim does not produce the effect (the row is
//     not vacuous: the mount is not a host path the call could reach anyway).
//
// A last subtest pins that the interposers are a no-op when the shim is
// loaded but not configured.
func TestShadowCopiesRebaseDirectoryAndMetadataCalls(t *testing.T) {
	requireSealedMountParents(t)
	shim := buildPathShim(t)
	helper := buildDirMetaHelper(t)
	canClone := tempDirClones(t)
	bin := t.TempDir()
	tools := map[string]string{
		"mkdir": "/bin/mkdir", "rmdir": "/bin/rmdir", "rm": "/bin/rm", "mv": "/bin/mv",
		"ln": "/bin/ln", "readlink": "/usr/bin/readlink", "chmod": "/bin/chmod",
		"touch": "/usr/bin/touch", "cp": "/bin/cp", "ls": "/bin/ls", "awk": "/usr/bin/awk",
	}
	for name, src := range tools {
		cloneSigned(t, src, filepath.Join(bin, name))
	}

	const M = dirMetaMount
	file := func(rel, body string) func(*testing.T, string) {
		return func(t *testing.T, rootfs string) {
			t.Helper()
			writeUnder(t, rootfs, rel, body)
		}
	}
	isDir := func(rel string) func(string, string) error {
		return func(rootfs, _ string) error {
			fi, err := os.Stat(filepath.Join(rootfs, rel))
			if err != nil {
				return err
			}
			if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", rel)
			}
			return nil
		}
	}
	gone := func(rel string) func(string, string) error {
		return func(rootfs, _ string) error {
			if _, err := os.Lstat(filepath.Join(rootfs, rel)); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s still present (err=%v)", rel, err)
			}
			return nil
		}
	}
	hasBody := func(rel, body string) func(string, string) error {
		return func(rootfs, _ string) error {
			b, err := os.ReadFile(filepath.Join(rootfs, rel))
			if err != nil {
				return err
			}
			if string(b) != body {
				return fmt.Errorf("%s = %q, want %q", rel, b, body)
			}
			return nil
		}
	}
	modeIs := func(rel string, want fs.FileMode) func(string, string) error {
		return func(rootfs, _ string) error {
			fi, err := os.Stat(filepath.Join(rootfs, rel))
			if err != nil {
				return err
			}
			if fi.Mode().Perm() != want {
				return fmt.Errorf("%s mode %v, want %v", rel, fi.Mode().Perm(), want)
			}
			return nil
		}
	}
	sameFile := func(a, b string) func(string, string) error {
		return func(rootfs, _ string) error {
			fa, err := os.Stat(filepath.Join(rootfs, a))
			if err != nil {
				return err
			}
			fb, err := os.Stat(filepath.Join(rootfs, b))
			if err != nil {
				return err
			}
			if !os.SameFile(fa, fb) {
				return fmt.Errorf("%s and %s are not one inode", a, b)
			}
			return nil
		}
	}
	// linkTo checks the stored symlink bytes: the TARGET is content and must be
	// the caller's string verbatim, never rebased.
	linkTo := func(rel, target string) func(string, string) error {
		return func(rootfs, _ string) error {
			got, err := os.Readlink(filepath.Join(rootfs, rel))
			if err != nil {
				return err
			}
			if got != target {
				return fmt.Errorf("%s -> %q, want %q (the target must be stored verbatim)", rel, got, target)
			}
			return nil
		}
	}
	outIs := func(want string) func(string, string) error {
		return func(_, out string) error {
			if strings.TrimSpace(out) != want {
				return fmt.Errorf("output %q, want %q", out, want)
			}
			return nil
		}
	}
	outHas := func(want string) func(string, string) error {
		return func(_, out string) error {
			if !strings.Contains(out, want) {
				return fmt.Errorf("output %q lacks %q", out, want)
			}
			return nil
		}
	}
	mtimeIs := func(rel string, want time.Time, tol time.Duration) func(string, string) error {
		return func(rootfs, _ string) error {
			fi, err := os.Stat(filepath.Join(rootfs, rel))
			if err != nil {
				return err
			}
			if d := fi.ModTime().Sub(want); d > tol || d < -tol {
				return fmt.Errorf("%s mtime %v, want %v", rel, fi.ModTime(), want)
			}
			return nil
		}
	}
	both2 := func(a, b func(*testing.T, string)) func(*testing.T, string) {
		return func(t *testing.T, rootfs string) {
			t.Helper()
			a(t, rootfs)
			b(t, rootfs)
		}
	}
	both := func(a, b func(string, string) error) func(string, string) error {
		return func(rootfs, out string) error {
			if err := a(rootfs, out); err != nil {
				return err
			}
			return b(rootfs, out)
		}
	}
	stale := func(rel string) func(*testing.T, string) {
		return func(t *testing.T, rootfs string) {
			t.Helper()
			writeUnder(t, rootfs, rel, "x")
			old := time.Unix(1000000000, 0)
			if err := os.Chtimes(filepath.Join(rootfs, rel), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := func(rel string) func(*testing.T, string) {
		return func(t *testing.T, rootfs string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Join(rootfs, rel), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	symlinkAt := func(rel, target string) func(*testing.T, string) {
		return func(t *testing.T, rootfs string) {
			t.Helper()
			dir(filepath.Dir(rel))(t, rootfs)
			if err := os.Symlink(target, filepath.Join(rootfs, rel)); err != nil {
				t.Fatal(err)
			}
		}
	}
	rows := []dirMetaRow{
		// Shadow utilities: each row's tool imports the call named in the shim.
		{name: "mkdir", tool: "mkdir", args: []string{M + "/d"}, setup: dir(M), check: isDir(M + "/d")},
		{name: "mkdir -p depth-2 mount", tool: "mkdir", args: []string{"-p", dirMetaDeepMount + "/x/y"}, setup: dir(dirMetaDeepMount), check: isDir(dirMetaDeepMount + "/x/y")},
		{name: "rmdir", tool: "rmdir", args: []string{M + "/d"}, setup: dir(M + "/d"), check: gone(M + "/d")},
		{name: "touch utimensat", tool: "touch", args: []string{M + "/f"}, setup: stale(M + "/f"), check: mtimeIs(M+"/f", time.Now(), time.Hour)},
		{name: "mv", tool: "mv", args: []string{M + "/a", M + "/b"}, setup: file(M+"/a", "moved"), check: both(gone(M+"/a"), hasBody(M+"/b", "moved"))},
		{name: "ln linkat", tool: "ln", args: []string{M + "/a", M + "/h"}, setup: file(M+"/a", "hard"), check: sameFile(M+"/a", M+"/h")},
		{name: "ln -s symlink", tool: "ln", args: []string{"-s", M + "/a", M + "/s"}, setup: dir(M), check: linkTo(M+"/s", M+"/a")},
		{name: "readlink", tool: "readlink", args: []string{M + "/s"}, setup: symlinkAt(M+"/s", M+"/a"), check: outIs(M + "/a")},
		{name: "chmod fchmodat", tool: "chmod", args: []string{"600", M + "/f"}, setup: file(M+"/f", "x"), check: modeIs(M+"/f", 0o600)},
		{name: "rm", tool: "rm", args: []string{M + "/f"}, setup: file(M+"/f", "x"), check: gone(M + "/f")},
		// rm -r and ls walk a directory with fts(3), whose directory opens are
		// libc-internal open$NOCANCEL calls no interposer here sees.
		{name: "ceiling rm -r (fts)", tool: "rm", args: []string{"-r", M + "/t"}, setup: file(M+"/t/u/f", "x"), check: gone(M + "/t"), ceilingErr: "rm: " + M + "/t: No such file or directory"},
		{name: "ceiling ls of a mounted directory (fts)", tool: "ls", args: []string{M}, setup: file(M+"/listed", "x"), check: outHas("listed"), ceilingErr: "ls: " + M + ": No such file or directory"},
		{name: "cp", tool: "cp", args: []string{M + "/a", M + "/c"}, setup: file(M+"/a", "copied"), check: hasBody(M+"/c", "copied")},
		{name: "cp -c clonefileat", tool: "cp", args: []string{"-c", M + "/a", M + "/c"}, setup: file(M+"/a", "cloned"), check: hasBody(M+"/c", "cloned"), needsClone: true},
		{name: "awk fopen", tool: "awk", args: []string{"{print}", M + "/f"}, setup: file(M+"/f", "via-awk\n"), check: outIs("via-awk")},

		// The raw entry points, through the C helper.
		{name: "helper mkdir", args: []string{"mkdir", M + "/d"}, setup: dir(M), check: isDir(M + "/d")},
		{name: "helper mkdirat", args: []string{"mkdirat", M + "/d"}, setup: dir(M), check: isDir(M + "/d")},
		{name: "helper rmdir", args: []string{"rmdir", M + "/d"}, setup: dir(M + "/d"), check: gone(M + "/d")},
		{name: "helper unlink", args: []string{"unlink", M + "/f"}, setup: file(M+"/f", "x"), check: gone(M + "/f")},
		{name: "helper unlinkat", args: []string{"unlinkat", M + "/f"}, setup: file(M+"/f", "x"), check: gone(M + "/f")},
		{name: "helper unlinkat AT_REMOVEDIR", args: []string{"unlinkat-dir", M + "/d"}, setup: dir(M + "/d"), check: gone(M + "/d")},
		{name: "helper rename", args: []string{"rename", M + "/a", M + "/b"}, setup: file(M+"/a", "renamed"), check: both(gone(M+"/a"), hasBody(M+"/b", "renamed"))},
		{name: "helper chmod", args: []string{"chmod", M + "/f"}, setup: file(M+"/f", "x"), check: modeIs(M+"/f", 0o600)},
		{name: "helper fchmodat", args: []string{"fchmodat", M + "/f"}, setup: file(M+"/f", "x"), check: modeIs(M+"/f", 0o600)},
		{name: "helper linkat", args: []string{"linkat", M + "/a", M + "/h"}, setup: file(M+"/a", "x"), check: sameFile(M+"/a", M+"/h")},
		{name: "helper symlink", args: []string{"symlink", M + "/a", M + "/s"}, setup: dir(M), check: linkTo(M+"/s", M+"/a")},
		{name: "helper symlinkat", args: []string{"symlinkat", M + "/a", M + "/s"}, setup: dir(M), check: linkTo(M+"/s", M+"/a")},
		{name: "helper readlink", args: []string{"readlink", M + "/s"}, setup: symlinkAt(M+"/s", "relative/target"), check: outIs("relative/target")},
		{name: "helper utimensat", args: []string{"utimensat", M + "/f"}, setup: file(M+"/f", "x"), check: mtimeIs(M+"/f", time.Unix(1000000000, 0), time.Second)},
		{name: "helper clonefileat", args: []string{"clonefileat", M + "/a", M + "/c"}, setup: file(M+"/a", "cloned"), check: hasBody(M+"/c", "cloned"), needsClone: true},
		{name: "helper fopen write", args: []string{"fopen-w", M + "/w"}, setup: dir(M), check: hasBody(M+"/w", "via-fopen\n")},
		{name: "helper fopen read", args: []string{"fopen-r", M + "/f"}, setup: file(M+"/f", "fopen-read"), check: outIs("fopen-read")},
		{name: "helper freopen", args: []string{"freopen", M + "/w"}, setup: dir(M), check: hasBody(M+"/w", "via-freopen\n")},
		// A mounted path too long to rebase is refused by every mutating call,
		// never handed to the host twin (the refusal precedes the syscall, so
		// the clonefileat row needs no APFS).
		{name: "helper rename overflow is ENAMETOOLONG", args: []string{"rename", M + "/a", M + "/" + longRel()}, setup: file(M+"/a", "x"), refused: true, check: both(outHas("File name too long"), hasBody(M+"/a", "x"))},
		{name: "helper linkat overflow is ENAMETOOLONG", args: []string{"linkat", M + "/a", M + "/" + longRel()}, setup: file(M+"/a", "x"), refused: true, check: both(outHas("File name too long"), hasBody(M+"/a", "x"))},
		{name: "helper clonefileat overflow is ENAMETOOLONG", args: []string{"clonefileat", M + "/a", M + "/" + longRel()}, setup: file(M+"/a", "x"), refused: true, check: both(outHas("File name too long"), hasBody(M+"/a", "x"))},
		{name: "helper unlink overflow is ENAMETOOLONG", args: []string{"unlink", M + "/" + longRel()}, setup: dir(M), refused: true, check: outHas("File name too long")},
		// Boundaries: a path that climbs out of the mount with ".." and a
		// sibling prefix are host paths, never rebased. Each setup plants the
		// file a wrong rebase WOULD reach, and the check proves it survived.
		{name: "boundary dotdot out of the mount is not rebased", args: []string{"unlink", M + "/../" + dirMetaEscapeName}, setup: both2(dir(M), file("/"+dirMetaEscapeName, "keep")), boundary: true, refused: true, check: both(outHas("No such file or directory"), hasBody("/"+dirMetaEscapeName, "keep"))},
		{name: "boundary sibling prefix is not rebased", args: []string{"mkdir", M + "2/x"}, setup: dir(M + "2"), boundary: true, refused: true, check: both(outHas("No such file or directory"), gone(M+"2/x"))},
		{name: "helper opendir", args: []string{"opendir", M}, setup: file(M+"/listed", "x"), check: outHas("listed")},
	}
	run := func(t *testing.T, row dirMetaRow, withShim bool) (rootfs, out string, err error) {
		t.Helper()
		rootfs = t.TempDir()
		if row.setup != nil {
			row.setup(t, rootfs)
		}
		path, argv := helper, append([]string{"dirmeta-helper"}, row.args...)
		if row.tool != "" {
			path, argv = filepath.Join(bin, row.tool), append([]string{row.tool}, row.args...)
		}
		cmd := &exec.Cmd{Path: path, Args: argv, Dir: rootfs}
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			pathShimRootfsEnv + "=" + rootfs,
			pathShimMountsEnv + "=" + dirMetaMount + ":" + dirMetaDeepMount,
		}
		if withShim {
			cmd.Env = append(cmd.Env, dyldInsertEnv+"="+shim)
		}
		b, err := cmd.CombinedOutput()
		return rootfs, string(b), err
	}
	hostUntouched := func(t *testing.T) {
		t.Helper()
		for _, p := range []string{dirMetaMount, dirMetaDeepMount, dirMetaMount + "2", "/" + dirMetaEscapeName} {
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("host path %s exists (err=%v): a call reached the host instead of the rootfs", p, err)
			}
		}
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.needsClone && !canClone {
				t.Skip("SKIP: the test temp dir does not support clonefile (needs APFS)")
			}
			rootfs, out, err := run(t, row, true)
			if row.ceilingErr != "" {
				if err == nil || row.check(rootfs, out) == nil {
					t.Errorf("documented ceiling now passes with the shim: flip this row to a regular one and drop the ceiling from the shim header\n%s", out)
				}
				if !strings.Contains(out, row.ceilingErr) {
					t.Errorf("ceiling row failed for another reason: want %q in the output\n%s", row.ceilingErr, out)
				}
				hostUntouched(t)
				return
			}
			if (err != nil) != row.refused {
				t.Errorf("with the shim: err=%v, want failure=%v\n%s", err, row.refused, out)
			}
			if cerr := row.check(rootfs, out); cerr != nil {
				t.Errorf("with the shim the effect did not land under the rootfs: %v\n%s", cerr, out)
			}
			hostUntouched(t)
			if row.boundary {
				return
			}

			rootfs, out, _ = run(t, row, false)
			if row.check(rootfs, out) == nil {
				t.Errorf("contrast: without the shim the effect landed anyway, the row proves nothing:\n%s", out)
			}
			hostUntouched(t)
		})
	}

	// Loaded but not configured, every interposer passes the caller's path
	// through: the ops act on a real (test-owned) directory, exactly as if the
	// shim were absent, even though that directory is named as a mount.
	t.Run("disabled shim passes paths through", func(t *testing.T) {
		host := t.TempDir()
		writeUnder(t, host, "a", "x")
		for _, env := range [][]string{
			{pathShimMountsEnv + "=" + host},                                 // no rootfs
			{pathShimRootfsEnv + "=" + t.TempDir(), pathShimMountsEnv + "="}, // no mounts
		} {
			ops := [][]string{
				{"mkdir", host + "/d"}, {"mkdirat", host + "/d2"}, {"rmdir", host + "/d2"},
				{"symlink", host + "/a", host + "/s"}, {"symlinkat", host + "/a", host + "/s2"},
				{"linkat", host + "/a", host + "/h"}, {"rename", host + "/h", host + "/h2"},
				{"chmod", host + "/a"}, {"fchmodat", host + "/a"}, {"utimensat", host + "/a"},
				{"fopen-w", host + "/w"},
				{"unlink", host + "/s"}, {"unlinkat", host + "/s2"}, {"unlinkat-dir", host + "/d"},
			}
			if canClone {
				ops = append(ops, []string{"clonefileat", host + "/a", host + "/c"})
			}
			for _, op := range ops {
				cmd := exec.Command(helper, op...)
				cmd.Env = append([]string{"PATH=/usr/bin:/bin", dyldInsertEnv + "=" + shim}, env...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v with env %v: %v\n%s", op, env, err, out)
				}
			}
			for rel, check := range map[string]func(string, string) error{
				"h2": sameFile("a", "h2"),
				"w":  hasBody("w", "via-fopen\n"),
				"a":  both(modeIs("a", 0o600), mtimeIs("a", time.Unix(1000000000, 0), time.Second)),
				"s":  gone("s"),
				"d":  gone("d"),
			} {
				if err := check(host, ""); err != nil {
					t.Errorf("disabled shim, env %v, %s: %v", env, rel, err)
				}
			}
			if canClone {
				if err := hasBody("c", "x")(host, ""); err != nil {
					t.Errorf("disabled shim, env %v, c: %v", env, err)
				}
			}
			for _, rel := range []string{"h2", "c", "w"} {
				_ = os.Remove(filepath.Join(host, rel))
			}
			if err := os.Chmod(filepath.Join(host, "a"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// requireSealedMountParents refuses to run, BEFORE any child call, when a
// failed rebase could write the host. Both fictitious mounts sit on the
// sealed read-only system volume (/ and /usr), where mkdir is EROFS for every
// user, root included; a non-root caller is also stopped by the root-owned
// 0755 parents. Only root on an unsealed (writable) volume could create
// /k3sm-b425-mnt or /usr/k3sm-b425-mnt, so that combination fails here,
// loudly, instead of running the no-shim contrasts.
func requireSealedMountParents(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	for _, parent := range []string{filepath.Dir(dirMetaMount), filepath.Dir(dirMetaDeepMount)} {
		var st unix.Statfs_t
		if err := unix.Statfs(parent, &st); err != nil {
			t.Fatalf("statfs %s: %v", parent, err)
		}
		if st.Flags&unix.MNT_RDONLY == 0 {
			t.Fatalf("running as root and %s is writable (no sealed system volume): a failed rebase would write the host, refusing to run", parent)
		}
	}
}

// tempDirClones probes whether clonefile(2) works within a test temp dir
// (APFS); the clone rows skip, never fail, where it does not.
func tempDirClones(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return unix.Clonefileat(unix.AT_FDCWD, src, unix.AT_FDCWD, filepath.Join(dir, "dst"), 0) == nil
}

// longRel is a relative path short enough for the kernel (under PATH_MAX)
// but too long to sit under any test rootfs prefix.
func longRel() string {
	seg := strings.Repeat("n", 200)
	return strings.Join([]string{seg, seg, seg, seg, seg[:150]}, "/")
}

// writeUnder writes body to rootfs/rel, creating the parents.
func writeUnder(t *testing.T, rootfs, rel, body string) {
	t.Helper()
	p := filepath.Join(rootfs, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
