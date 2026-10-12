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
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// signReplaceRig is a root (the pod rootfs) and a staging dir side by side under
// one temp dir, so they share a volume as they do under the daemon's Root.
type signReplaceRig struct {
	root, staging, bin string
}

func newSignReplaceRig(t *testing.T) signReplaceRig {
	t.Helper()
	base := t.TempDir()
	r := signReplaceRig{
		root:    filepath.Join(base, "rootfs"),
		staging: filepath.Join(base, "ingest", "sign"),
	}
	if err := os.MkdirAll(filepath.Join(r.root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.bin = filepath.Join(r.root, "bin", "app")
	if err := os.WriteFile(r.bin, []byte("orig"), 0o755); err != nil {
		t.Fatal(err)
	}
	return r
}

// appendSign is a signFunc that writes a marker into the temp, recording the path.
func appendSign(got *[]string) signFunc {
	return func(_ context.Context, path, _ string) error {
		*got = append(*got, path)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		if _, err := f.WriteString("+signed"); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
}

func readString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSignByReplaceNeverFollowsASymlinkSwappedInAfterResolution pins the TOCTOU
// defence. Pods can write their rootfs, so between resolving argv[0] and opening
// it a pod can swap the file, or its directory, for a symlink to a file outside
// the rootfs. The open is relative to a directory handle opened through os.Root,
// with O_NOFOLLOW, so neither swap is followed: the call fails, the outside file
// is untouched, and nothing is signed.
func TestSignByReplaceNeverFollowsASymlinkSwappedInAfterResolution(t *testing.T) {
	cases := []struct {
		name string
		swap func(t *testing.T, r signReplaceRig, outsideDir string)
	}{
		{
			name: "final-component",
			swap: func(t *testing.T, r signReplaceRig, outsideDir string) {
				if err := os.Remove(r.bin); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outsideDir, "app"), r.bin); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "parent-directory",
			swap: func(t *testing.T, r signReplaceRig, outsideDir string) {
				dir := filepath.Dir(r.bin)
				if err := os.Rename(dir, dir+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideDir, dir); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSignReplaceRig(t)
			outsideDir := t.TempDir()
			outside := filepath.Join(outsideDir, "app")
			if err := os.WriteFile(outside, []byte("host"), 0o755); err != nil {
				t.Fatal(err)
			}
			var signed []string
			err := signByReplace(context.Background(), r.staging, r.root, r.bin, appendSign(&signed),
				func(string) { tc.swap(t, r, outsideDir) })
			if !errors.Is(err, ErrSignTarget) {
				t.Fatalf("err = %v, want ErrSignTarget", err)
			}
			if len(signed) != 0 {
				t.Errorf("signed %q after a swap", signed)
			}
			if got := readString(t, outside); got != "host" {
				t.Errorf("file outside the root = %q, want it untouched", got)
			}
		})
	}
}

// TestSignStagingIsPrivate pins that the staging dir, where the copy is signed by
// name, is a 0700 directory owned by the daemon's uid (root, when run as root),
// and that a staging dir anyone else could write is refused before any copy.
func TestSignStagingIsPrivate(t *testing.T) {
	t.Run("created-0700-and-owned-by-the-daemon", func(t *testing.T) {
		r := newSignReplaceRig(t)
		var signed []string
		if err := signByReplace(context.Background(), r.staging, r.root, r.bin, appendSign(&signed), nil); err != nil {
			t.Fatalf("signByReplace: %v", err)
		}
		fi, err := os.Lstat(r.staging)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("staging mode = %v, want a 0700 directory", fi.Mode())
		}
		uid := int(fi.Sys().(*syscall.Stat_t).Uid)
		if uid != os.Geteuid() {
			t.Errorf("staging owner uid = %d, want the daemon's %d", uid, os.Geteuid())
		}
		if os.Geteuid() != 0 {
			t.Log("not root: the root-owned assertion is skipped")
		} else if uid != 0 {
			t.Errorf("running as root, staging owner uid = %d, want 0", uid)
		}
		if len(signed) != 1 || filepath.Dir(signed[0]) != r.staging {
			t.Errorf("signed %q, want one temp in %s", signed, r.staging)
		}
		if got := readString(t, r.bin); got != "orig+signed" {
			t.Errorf("binary = %q, want the signed copy", got)
		}
	})

	t.Run("a-group-or-world-accessible-staging-dir-is-refused", func(t *testing.T) {
		r := newSignReplaceRig(t)
		if err := os.MkdirAll(r.staging, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(r.staging, 0o777); err != nil {
			t.Fatal(err)
		}
		var signed []string
		err := signByReplace(context.Background(), r.staging, r.root, r.bin, appendSign(&signed), nil)
		if !errors.Is(err, ErrSignStaging) {
			t.Fatalf("err = %v, want ErrSignStaging", err)
		}
		if len(signed) != 0 || readString(t, r.bin) != "orig" {
			t.Errorf("signed %q through a shared staging dir", signed)
		}
	})

	t.Run("a-symlinked-staging-dir-is-refused", func(t *testing.T) {
		r := newSignReplaceRig(t)
		elsewhere := t.TempDir()
		if err := os.MkdirAll(filepath.Dir(r.staging), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, r.staging); err != nil {
			t.Fatal(err)
		}
		var signed []string
		err := signByReplace(context.Background(), r.staging, r.root, r.bin, appendSign(&signed), nil)
		if !errors.Is(err, ErrSignStaging) {
			t.Fatalf("err = %v, want ErrSignStaging", err)
		}
		if len(signed) != 0 {
			t.Errorf("signed %q through a symlinked staging dir", signed)
		}
	})
}

// TestSignByReplaceFailureLeavesPathAlone pins the error contract: a failed sign,
// or a target outside the root, leaves the original untouched and no temp file
// behind in either directory.
func TestSignByReplaceFailureLeavesPathAlone(t *testing.T) {
	errSign := errors.New("sign failed")
	t.Run("sign-error-removes-temp", func(t *testing.T) {
		r := newSignReplaceRig(t)
		err := signByReplace(context.Background(), r.staging, r.root, r.bin,
			func(context.Context, string, string) error { return errSign }, nil)
		if !errors.Is(err, errSign) {
			t.Fatalf("err = %v, want %v", err, errSign)
		}
		if got := readString(t, r.bin); got != "orig" {
			t.Errorf("binary = %q, want the original", got)
		}
		for _, dir := range []string{r.staging, filepath.Dir(r.bin)} {
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.Name() != "app" {
					t.Errorf("%s holds %q after a failed sign", dir, e.Name())
				}
			}
		}
	})
	t.Run("target-outside-the-root-is-refused", func(t *testing.T) {
		r := newSignReplaceRig(t)
		outside := filepath.Join(t.TempDir(), "app")
		if err := os.WriteFile(outside, []byte("host"), 0o755); err != nil {
			t.Fatal(err)
		}
		var signed []string
		err := signByReplace(context.Background(), r.staging, r.root, outside, appendSign(&signed), nil)
		if !errors.Is(err, ErrSignTarget) {
			t.Fatalf("err = %v, want ErrSignTarget", err)
		}
		if len(signed) != 0 || readString(t, outside) != "host" {
			t.Errorf("signed a file outside the root: %q", signed)
		}
	})
}

// TestSweepSignStaging pins that the startup sweep removes only this package's
// temps and treats a missing staging dir as empty.
func TestSweepSignStaging(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sign")
	if n, err := SweepSignStaging(dir); n != 0 || err != nil {
		t.Fatalf("missing dir: removed %d, err %v; want 0, nil", n, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{signTempPrefix + "a", signTempPrefix + "b", "other"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	n, err := SweepSignStaging(dir)
	if n != 2 || err != nil {
		t.Fatalf("removed %d, err %v; want 2, nil", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other")); err != nil {
		t.Errorf("sweep removed a file it does not own: %v", err)
	}
}
