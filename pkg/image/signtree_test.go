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
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeTreeSigner records every verify/sign call and answers verification from a
// per-path table, so a test can build a tree of ordinary files and still exercise
// the exact decision a real codesign would drive.
type fakeTreeSigner struct {
	// valid maps a file's base name to the verdict VerifyArch returns for it.
	// Absent means "not validly signed".
	valid map[string]bool
	// verifyErr, when set for a base name, makes VerifyArch fail for it.
	verifyErr map[string]error
	// signErr, when set for a base name, makes Sign fail for it.
	signErr map[string]error

	verified []verifyCall
	signed   []string
}

type verifyCall struct {
	base string
	arch string
}

func (f *fakeTreeSigner) VerifyArch(_ context.Context, path, arch string) (bool, error) {
	base := filepath.Base(path)
	f.verified = append(f.verified, verifyCall{base: base, arch: arch})
	if err := f.verifyErr[base]; err != nil {
		return false, err
	}
	return f.valid[base], nil
}

func (f *fakeTreeSigner) Sign(_ context.Context, path string) error {
	base := filepath.Base(path)
	f.signed = append(f.signed, base)
	return f.signErr[base]
}

// signedNames returns the sorted base names Sign was called on.
func (f *fakeTreeSigner) signedNames() []string {
	out := append([]string(nil), f.signed...)
	sort.Strings(out)
	return out
}

// thinMachO writes a minimal thin arm64 Mach-O header (enough for the magic-based
// classifier — the walk never parses load commands).
func thinMachO(t *testing.T, path string) {
	t.Helper()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:4], machoMagic64)
	writeFile(t, path, buf)
}

// fatMachO writes a universal header naming the given (cputype, cpusubtype) pairs.
func fatMachO(t *testing.T, path string, arches [][2]uint32) {
	t.Helper()
	buf := make([]byte, 8+len(arches)*20)
	binary.BigEndian.PutUint32(buf[0:4], machoFatMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(arches)))
	for i, a := range arches {
		off := 8 + i*20
		binary.BigEndian.PutUint32(buf[off:off+4], a[0])
		binary.BigEndian.PutUint32(buf[off+4:off+8], a[1])
	}
	writeFile(t, path, buf)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestAdHocSignTree is acceptance M8.2-a2: the tree walk's decisions, proven over a
// fake signer with no codesign, no Mach-O toolchain, and no privilege.
func TestAdHocSignTree(t *testing.T) {
	const adhoc = runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK

	t.Run("signs only the invalid Mach-Os", func(t *testing.T) {
		root := t.TempDir()
		thinMachO(t, filepath.Join(root, "bin", "unsigned.dylib"))
		thinMachO(t, filepath.Join(root, "bin", "alreadysigned.dylib"))
		writeFile(t, filepath.Join(root, "share", "readme.txt"), []byte("not a mach-o at all\n"))
		writeFile(t, filepath.Join(root, "share", "tiny"), []byte("ab"))

		signer := &fakeTreeSigner{valid: map[string]bool{"alreadysigned.dylib": true}}
		stats, err := AdHocSignTree(context.Background(), signer, adhoc, root)
		if err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		if got, want := signer.signedNames(), []string{"unsigned.dylib"}; len(got) != 1 || got[0] != want[0] {
			t.Fatalf("signed = %v, want %v", got, want)
		}
		if stats.MachO != 2 || stats.Valid != 1 || stats.Signed != 1 {
			t.Fatalf("stats = %+v, want MachO=2 Valid=1 Signed=1", stats)
		}
		if stats.Files != 4 {
			t.Fatalf("Files = %d, want 4 (every entry walked)", stats.Files)
		}
	})

	// The clonefile invariant, stated as a test: a tree that arrives fully signed —
	// the ordinary case, since the arm64 linker signs what it emits — is not written
	// to at all, so its clones stay CoW.
	t.Run("an already-signed tree is never written", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"a.so", "b.dylib", "c"} {
			thinMachO(t, filepath.Join(root, name))
		}
		signer := &fakeTreeSigner{valid: map[string]bool{"a.so": true, "b.dylib": true, "c": true}}
		stats, err := AdHocSignTree(context.Background(), signer, adhoc, root)
		if err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		if len(signer.signed) != 0 {
			t.Fatalf("re-signed an already-valid tree: %v", signer.signed)
		}
		if stats.Valid != 3 || stats.Signed != 0 {
			t.Fatalf("stats = %+v, want Valid=3 Signed=0", stats)
		}
	})

	// The universal-binary case that motivates per-arch verification: verifying the
	// whole file reports "not signed at all" when a foreign slice is unsigned, which
	// would re-sign — and de-CoW — a file whose executing slice is fine.
	t.Run("universal binaries are verified per-arch", func(t *testing.T) {
		root := t.TempDir()
		fat := filepath.Join(root, "_message.abi3.so")
		fatMachO(t, fat, [][2]uint32{{0x01000007, 3}, {0x0100000C, 0}}) // x86_64 + arm64
		thinMachO(t, filepath.Join(root, "thin.dylib"))

		signer := &fakeTreeSigner{valid: map[string]bool{"_message.abi3.so": true, "thin.dylib": true}}
		if _, err := AdHocSignTree(context.Background(), signer, adhoc, root); err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		wantArch := pickVerifyArch([]string{"x86_64", "arm64"}, runtime.GOARCH)
		for _, call := range signer.verified {
			switch call.base {
			case "_message.abi3.so":
				if call.arch != wantArch {
					t.Fatalf("universal binary verified with arch %q, want %q", call.arch, wantArch)
				}
			case "thin.dylib":
				if call.arch != "" {
					t.Fatalf("thin binary verified with arch %q, want the whole file", call.arch)
				}
			}
		}
		if len(signer.signed) != 0 {
			t.Fatalf("a per-arch-valid universal binary was re-signed: %v", signer.signed)
		}
	})

	// Containment: a symlink is neither followed nor signed, however it is named —
	// a malicious image must not be able to steer the daemon's codesign at a host
	// file, and a "libfoo.dylib" pointing at /bin/ls is exactly that attempt.
	t.Run("symlinks are refused, not followed", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "hostbin")
		thinMachO(t, outside)
		inside := filepath.Join(root, "real.dylib")
		thinMachO(t, inside)
		if err := os.Symlink(outside, filepath.Join(root, "escape.dylib")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(inside, filepath.Join(root, "inner.dylib")); err != nil {
			t.Fatal(err)
		}
		// A symlinked DIRECTORY must not be descended either.
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "escapedir")); err != nil {
			t.Fatal(err)
		}

		signer := &fakeTreeSigner{}
		stats, err := AdHocSignTree(context.Background(), signer, adhoc, root)
		if err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		for _, base := range signer.signed {
			if base != "real.dylib" {
				t.Fatalf("signed through a symlink: %q", base)
			}
		}
		for _, call := range signer.verified {
			if call.base != "real.dylib" {
				t.Fatalf("verified through a symlink: %q", call.base)
			}
		}
		if stats.SkippedLinks != 3 {
			t.Fatalf("SkippedLinks = %d, want 3 (two symlinked files and one symlinked dir)", stats.SkippedLinks)
		}
		if stats.Signed != 1 {
			t.Fatalf("Signed = %d, want 1 (the real file only)", stats.Signed)
		}
	})

	// Containment: signing rewrites the inode, so a multi-link file would mutate
	// every other name for it — including a name outside the tree.
	t.Run("hardlinked files are refused", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "hostbin")
		thinMachO(t, target)
		if err := os.Link(target, filepath.Join(root, "aliased.dylib")); err != nil {
			t.Skipf("hard links unsupported here: %v", err)
		}
		thinMachO(t, filepath.Join(root, "plain.dylib"))

		signer := &fakeTreeSigner{}
		stats, err := AdHocSignTree(context.Background(), signer, adhoc, root)
		if err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		if got := signer.signedNames(); len(got) != 1 || got[0] != "plain.dylib" {
			t.Fatalf("signed = %v, want only plain.dylib", got)
		}
		if stats.SkippedLinks != 1 {
			t.Fatalf("SkippedLinks = %d, want 1", stats.SkippedLinks)
		}
	})

	// Policy gating: ad-hoc signing is structurally unreachable under the policies
	// whose whole purpose is a real authority, and under the fail-closed zero value.
	t.Run("policy gating", func(t *testing.T) {
		root := t.TempDir()
		thinMachO(t, filepath.Join(root, "bin.dylib"))
		for _, policy := range []runtimev1.SignaturePolicy{
			runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED,
			runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED,
			runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED,
		} {
			t.Run(policy.String(), func(t *testing.T) {
				signer := &fakeTreeSigner{}
				_, err := AdHocSignTree(context.Background(), signer, policy, root)
				if !errors.Is(err, ErrTreeSignPolicy) {
					t.Fatalf("err = %v, want ErrTreeSignPolicy", err)
				}
				if len(signer.verified) != 0 || len(signer.signed) != 0 {
					t.Fatal("the tree was touched under a policy that forbids ad-hoc signing")
				}
			})
		}
	})

	t.Run("root must be a real directory", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "afile")
		writeFile(t, file, []byte("x"))
		link := filepath.Join(dir, "alink")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{file, link, filepath.Join(dir, "absent"), "relative/path"} {
			if _, err := AdHocSignTree(context.Background(), &fakeTreeSigner{}, adhoc, root); !errors.Is(err, ErrTreeSignRoot) {
				t.Fatalf("AdHocSignTree(%q) err = %v, want ErrTreeSignRoot", root, err)
			}
		}
	})

	// Errors fail the whole call: a half-signed tree runs pods that fail at exec for
	// reasons that no longer point at the cause.
	t.Run("a signer error fails the call", func(t *testing.T) {
		root := t.TempDir()
		thinMachO(t, filepath.Join(root, "bad.dylib"))
		boom := errors.New("codesign exploded")

		signer := &fakeTreeSigner{signErr: map[string]error{"bad.dylib": boom}}
		if _, err := AdHocSignTree(context.Background(), signer, adhoc, root); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the signer error", err)
		}
		vsigner := &fakeTreeSigner{verifyErr: map[string]error{"bad.dylib": boom}}
		if _, err := AdHocSignTree(context.Background(), vsigner, adhoc, root); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the verify error", err)
		}
	})
}

// TestMachoSlices pins the magic-based classifier, including the collision it must
// not fall for: a Java .class file opens with the same 0xCAFEBABE magic as a fat
// Mach-O, and handing one to codesign would be a write driven by a misread format.
func TestMachoSlices(t *testing.T) {
	dir := t.TempDir()

	javaClass := make([]byte, 32)
	binary.BigEndian.PutUint32(javaClass[0:4], machoFatMagic)
	binary.BigEndian.PutUint16(javaClass[4:6], 0)  // minor version
	binary.BigEndian.PutUint16(javaClass[6:8], 65) // major version (Java 21)
	writeFile(t, filepath.Join(dir, "Main.class"), javaClass)

	// A fat header whose arch count is plausible but whose CPU type is not known.
	unknownCPU := make([]byte, 8+20)
	binary.BigEndian.PutUint32(unknownCPU[0:4], machoFatMagic)
	binary.BigEndian.PutUint32(unknownCPU[4:8], 1)
	binary.BigEndian.PutUint32(unknownCPU[8:12], 0xDEADBEEF)
	writeFile(t, filepath.Join(dir, "weird.bin"), unknownCPU)

	thinMachO(t, filepath.Join(dir, "thin"))
	fatMachO(t, filepath.Join(dir, "universal"), [][2]uint32{{0x01000007, 3}, {0x0100000C, 2}})
	writeFile(t, filepath.Join(dir, "text"), []byte("#!/bin/sh\necho hi\n"))
	writeFile(t, filepath.Join(dir, "short"), []byte("ab"))

	cases := []struct {
		name    string
		isMachO bool
		arches  []string
	}{
		{"Main.class", false, nil},
		{"weird.bin", false, nil},
		{"thin", true, nil},
		{"universal", true, []string{"x86_64", "arm64e"}},
		{"text", false, nil},
		{"short", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arches, isMachO, err := machoSlices(filepath.Join(dir, tc.name))
			if err != nil {
				t.Fatalf("machoSlices: %v", err)
			}
			if isMachO != tc.isMachO {
				t.Fatalf("isMachO = %v, want %v", isMachO, tc.isMachO)
			}
			if len(arches) != len(tc.arches) {
				t.Fatalf("arches = %v, want %v", arches, tc.arches)
			}
			for i := range arches {
				if arches[i] != tc.arches[i] {
					t.Fatalf("arches = %v, want %v", arches, tc.arches)
				}
			}
		})
	}
}

// TestPickVerifyArch pins the slice-selection rule, including the case codesign
// itself punishes: naming an arch the file does not contain errors out instead of
// reporting "unsigned", so the choice must come from the file's own slice list.
func TestPickVerifyArch(t *testing.T) {
	cases := []struct {
		name   string
		arches []string
		goarch string
		want   string
	}{
		{"thin binary verifies whole", nil, "arm64", ""},
		{"native arm64 preferred", []string{"x86_64", "arm64"}, "arm64", "arm64"},
		{"arm64e preferred over arm64", []string{"arm64", "arm64e"}, "arm64", "arm64e"},
		{"amd64 daemon prefers x86_64", []string{"x86_64", "arm64"}, "amd64", "x86_64"},
		{"arm64-only file under an amd64 daemon", []string{"arm64"}, "amd64", "arm64"},
		{"x86_64-only file under an arm64 daemon", []string{"x86_64"}, "arm64", "x86_64"},
		{"no preferred slice falls back to the first", []string{"i386", "arm"}, "arm64", "i386"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickVerifyArch(tc.arches, tc.goarch); got != tc.want {
				t.Fatalf("pickVerifyArch(%v, %q) = %q, want %q", tc.arches, tc.goarch, got, tc.want)
			}
		})
	}
}
