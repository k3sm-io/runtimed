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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// signedMarker is what the fake codesign appends to the file it signs, and what
// markerSigner.Check reads as "validly signed".
const signedMarker = "+FAKE-ADHOC-SIGNATURE"

// markerSigner is the production signer (defaultSigner: its Sign is the real
// codesign entry point) with only Check faked, so the test exercises the real
// signing code against a fake `codesign` first on PATH and never needs codesign
// or a real Mach-O to decide validity.
type markerSigner struct{ defaultSigner }

func (markerSigner) Check(_ context.Context, policy runtimev1.SignaturePolicy, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(signedMarker)) {
		return fmt.Errorf("%w: %s unsigned (fake)", image.ErrSignatureRejected, path)
	}
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK {
		return nil
	}
	return fmt.Errorf("%w: %s is ad-hoc (fake)", image.ErrSignatureRejected, path)
}

// installFakeCodesign puts a `codesign` first on PATH that appends one line per
// call (its argv) to the returned log and appends signedMarker to its last
// argument IN PLACE: a real `codesign -f` on a file rewrites that file, which is
// exactly the write a live mapping must never see.
func installFakeCodesign(t *testing.T) (logPath string) {
	t.Helper()
	bin := t.TempDir()
	logPath = filepath.Join(t.TempDir(), "codesign.log")
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
for last in "$@"; do :; done
printf '%%s' %q >> "$last"
`, logPath, signedMarker)
	if err := os.WriteFile(filepath.Join(bin, "codesign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func codesignCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// signRig is a runtime whose signer is the production one (fake codesign, fake
// Check) and a pod rootfs inside that runtime's own Root, so the staging dir and
// the rootfs share a volume exactly as they do on a node.
type signRig struct {
	rt      *Runtime
	rootfs  string
	logPath string
}

func newSignRig(t *testing.T) signRig {
	t.Helper()
	logPath := installFakeCodesign(t)
	rt := newTestRuntime(t, Deps{})
	rt.signer = markerSigner{defaultSigner{staging: rt.cache.SignStagingDir()}}
	rootfs := derivedRootfs(t, rt, "pod-sign")
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return signRig{rt: rt, rootfs: rootfs, logPath: logPath}
}

func (s signRig) write(t *testing.T, rel, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(s.rootfs, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s signRig) link(t *testing.T, target, rel string) string {
	t.Helper()
	p := filepath.Join(s.rootfs, rel)
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s signRig) gate(t *testing.T, policy runtimev1.SignaturePolicy, path string) error {
	t.Helper()
	return s.rt.gateSignature(context.Background(), policy, s.rootfs, path, false)
}

const unsigned = "unsigned-mach-o-bytes"

var adhocOK = runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK

// TestGateSignatureNeverRewritesALiveInode pins that ad-hoc signing a pod binary
// never writes the inode a running process may have mapped. Re-signing a Mach-O
// in place leaves the kernel's old signature binding on the vnode, and every new
// process mapping it is killed (Code Signature Invalid). So the gate signs a copy
// in a private staging dir, under the final name's identifier, and renames it
// over the path: the old inode, and any open fd on it, keep the old bytes.
func TestGateSignatureNeverRewritesALiveInode(t *testing.T) {
	t.Run("unsigned-is-signed-onto-a-new-inode", func(t *testing.T) {
		s := newSignRig(t)
		bin := s.write(t, "usr/bin/server", unsigned, 0o750)
		before := inodeOf(t, bin)
		live, err := os.Open(bin) // a running process's mapping, as an fd
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()

		if err := s.gate(t, adhocOK, bin); err != nil {
			t.Fatalf("gateSignature: %v", err)
		}

		if after := inodeOf(t, bin); after == before {
			t.Errorf("signed in place: inode %d unchanged", before)
		}
		var buf bytes.Buffer
		if _, err := live.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := buf.ReadFrom(live); err != nil {
			t.Fatal(err)
		}
		if buf.String() != unsigned {
			t.Errorf("open fd on the old file reads %q, want the old bytes %q", buf.String(), unsigned)
		}
		if got := mustRead(t, bin); got != unsigned+signedMarker {
			t.Errorf("path content = %q, want the signed copy", got)
		}
		fi, err := os.Stat(bin)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Errorf("mode = %v, want 0750 preserved", fi.Mode().Perm())
		}

		calls := codesignCalls(t, s.logPath)
		if len(calls) != 1 {
			t.Fatalf("codesign calls = %q, want exactly one", calls)
		}
		args := strings.Fields(calls[0])
		target := args[len(args)-1]
		if strings.HasPrefix(target, s.rootfs) {
			t.Errorf("codesign signed %q inside the pod rootfs, want a temp in the staging dir", target)
		}
		if filepath.Dir(target) != s.rt.cache.SignStagingDir() {
			t.Errorf("codesign signed %q, want a temp in %s", target, s.rt.cache.SignStagingDir())
		}
		if !strings.Contains(calls[0], "-i server ") {
			t.Errorf("codesign argv %q lacks -i server (the identifier must be the final base name)", calls[0])
		}
		for _, dir := range []string{filepath.Dir(bin), s.rt.cache.SignStagingDir()} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != "server" {
					t.Errorf("%s holds %q after signing (temp left behind?)", dir, e.Name())
				}
			}
		}
	})

	t.Run("already-valid-is-untouched", func(t *testing.T) {
		s := newSignRig(t)
		bin := s.write(t, "usr/bin/server", unsigned+signedMarker, 0o755)
		before := inodeOf(t, bin)
		if err := s.gate(t, adhocOK, bin); err != nil {
			t.Fatalf("gateSignature: %v", err)
		}
		if after := inodeOf(t, bin); after != before {
			t.Errorf("valid binary replaced: inode %d -> %d", before, after)
		}
		if calls := codesignCalls(t, s.logPath); len(calls) != 0 {
			t.Errorf("codesign called on a valid binary: %q", calls)
		}
	})

	t.Run("require-signed-is-never-signed", func(t *testing.T) {
		s := newSignRig(t)
		bin := s.write(t, "usr/bin/server", unsigned, 0o755)
		before := inodeOf(t, bin)
		if err := s.gate(t, runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED, bin); err == nil {
			t.Fatal("require-signed accepted an unsigned binary")
		}
		if after := inodeOf(t, bin); after != before {
			t.Errorf("require-signed binary replaced: inode %d -> %d", before, after)
		}
		if calls := codesignCalls(t, s.logPath); len(calls) != 0 {
			t.Errorf("codesign called under require-signed: %q", calls)
		}
	})
}

// TestGateSignatureSignsTheSymlinkTargetInsideTheRootfs pins that a symlinked
// argv[0] (an image's /bin/sh, python3 -> python3.12) is resolved INSIDE the pod
// rootfs, with chroot semantics, and the file at the end of the chain is signed
// onto a new inode while the links themselves are left as links. A chain that
// leaves the rootfs is refused and nothing is signed.
//
// The post-sign Check still reads the path the pod will exec, by name, because
// that is the file the kernel will run. A native pod is not chrooted, so for a
// chain through a rootfs-ABSOLUTE link that name resolves against the HOST root,
// at Check and at exec alike. Checking the in-rootfs target instead would
// approve one file and exec another, so those cases sign the target and then
// fail the Check (the host has no /opt/k3smtest), and that is asserted here.
func TestGateSignatureSignsTheSymlinkTargetInsideTheRootfs(t *testing.T) {
	cases := []struct {
		name  string
		links [][2]string // {target, rel}, created in order
		entry string      // the argv[0] the gate is given
		// hostResolved: the entry's chain crosses a rootfs-absolute link, so the
		// kernel (and the by-name Check) resolve it against the host root.
		hostResolved bool
	}{
		{name: "relative", links: [][2]string{{"app-1.2", "opt/k3smtest/app"}}, entry: "opt/k3smtest/app"},
		{
			name:         "rootfs-absolute",
			links:        [][2]string{{"/opt/k3smtest/app-1.2", "opt/k3smtest/app"}},
			entry:        "opt/k3smtest/app",
			hostResolved: true,
		},
		{
			name: "relative-chain",
			links: [][2]string{
				{"app-1.2", "opt/k3smtest/app"},
				{"app", "opt/k3smtest/app-current"},
				{"opt/k3smtest/app-current", "run"},
			},
			entry: "run",
		},
		{
			name: "chain-through-an-absolute-link",
			links: [][2]string{
				{"app-1.2", "opt/k3smtest/app"},
				{"/opt/k3smtest/app", "opt/k3smtest/app-current"},
				{"opt/k3smtest/app-current", "run"},
			},
			entry:        "run",
			hostResolved: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSignRig(t)
			real := s.write(t, "opt/k3smtest/app-1.2", unsigned, 0o755)
			before := inodeOf(t, real)
			var linkInodes []uint64
			var links []string
			for _, l := range tc.links {
				p := s.link(t, l[0], l[1])
				links = append(links, p)
				linkInodes = append(linkInodes, inodeOf(t, p))
			}

			err := s.gate(t, adhocOK, filepath.Join(s.rootfs, tc.entry))
			switch {
			case errors.Is(err, image.ErrSignTarget):
				t.Fatalf("gateSignature refused an in-rootfs link: %v", err)
			case tc.hostResolved && err == nil:
				t.Fatal("gateSignature passed a chain the kernel resolves on the host; the by-name Check must fail it")
			case !tc.hostResolved && err != nil:
				t.Fatalf("gateSignature: %v", err)
			}
			if after := inodeOf(t, real); after == before {
				t.Errorf("target signed in place: inode %d unchanged", before)
			}
			if got := mustRead(t, real); got != unsigned+signedMarker {
				t.Errorf("target content = %q, want the signed copy", got)
			}
			for i, p := range links {
				fi, err := os.Lstat(p)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode()&os.ModeSymlink == 0 || inodeOf(t, p) != linkInodes[i] {
					t.Errorf("link %s was replaced; want it left as the same symlink", p)
				}
			}
			calls := codesignCalls(t, s.logPath)
			if len(calls) != 1 || !strings.Contains(calls[0], "-i app-1.2 ") {
				t.Errorf("codesign calls = %q, want one, with -i app-1.2", calls)
			}
		})
	}

	t.Run("escaping-link-is-refused", func(t *testing.T) {
		s := newSignRig(t)
		outside := filepath.Join(t.TempDir(), "host-binary")
		if err := os.WriteFile(outside, []byte(unsigned), 0o755); err != nil {
			t.Fatal(err)
		}
		before := inodeOf(t, outside)
		rel, err := filepath.Rel(filepath.Join(s.rootfs, "usr", "bin"), outside)
		if err != nil {
			t.Fatal(err)
		}
		bin := s.link(t, rel, "usr/bin/escape") // ../../../…/host-binary

		err = s.gate(t, adhocOK, bin)
		if !errors.Is(err, image.ErrSignTarget) {
			t.Fatalf("gateSignature err = %v, want ErrSignTarget", err)
		}
		if got := mustRead(t, outside); got != unsigned || inodeOf(t, outside) != before {
			t.Errorf("the file outside the rootfs was touched: %q", got)
		}
		if calls := codesignCalls(t, s.logPath); len(calls) != 0 {
			t.Errorf("codesign called for an escaping link: %q", calls)
		}
	})
}

// TestGateSignatureDetachesAHardLinkedBinary pins that a hard-linked argv[0]
// (Nlink > 1) is detached by the rename, never mutated through its other name:
// the other name keeps the old inode and the old bytes.
func TestGateSignatureDetachesAHardLinkedBinary(t *testing.T) {
	s := newSignRig(t)
	bin := s.write(t, "usr/bin/server", unsigned, 0o755)
	other := filepath.Join(s.rootfs, "usr", "bin", "server-alias")
	if err := os.Link(bin, other); err != nil {
		t.Fatal(err)
	}
	before := inodeOf(t, bin)

	if err := s.gate(t, adhocOK, bin); err != nil {
		t.Fatalf("gateSignature: %v", err)
	}
	if inodeOf(t, bin) == before {
		t.Errorf("hard-linked binary signed in place")
	}
	if inodeOf(t, other) != before || mustRead(t, other) != unsigned {
		t.Errorf("other hard link was mutated: %q", mustRead(t, other))
	}
	if got := mustRead(t, bin); got != unsigned+signedMarker {
		t.Errorf("path content = %q, want the signed copy", got)
	}
}

// TestStartupSweepRemovesStaleSignedCopies pins the startup sweep: a signed
// copy a crashed daemon left in the staging dir is removed, and nothing else.
func TestStartupSweepRemovesStaleSignedCopies(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	staging := rt.cache.SignStagingDir()
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(staging, ".sign-123")
	keep := filepath.Join(staging, "not-ours")
	for _, p := range []string{orphan, keep} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rt.sweepStaleSignStaging()
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("orphaned signed copy survived the sweep: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("sweep removed a file it does not own: %v", err)
	}
}
