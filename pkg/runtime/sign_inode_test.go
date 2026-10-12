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
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestGateSignatureNeverRewritesALiveInode pins that ad-hoc signing a pod binary
// never writes the inode a running process may have mapped. Re-signing a Mach-O
// in place leaves the kernel's old signature binding on the vnode, and every new
// process mapping it is killed (Code Signature Invalid). So the gate signs a copy
// in the same directory, under the final name's identifier, and renames it over
// the path: the old inode, and any open fd on it, keep the old bytes.
func TestGateSignatureNeverRewritesALiveInode(t *testing.T) {
	const unsigned = "unsigned-mach-o-bytes"
	adhoc := runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK

	t.Run("unsigned-is-signed-onto-a-new-inode", func(t *testing.T) {
		logPath := installFakeCodesign(t)
		rt := newTestRuntime(t, Deps{Signer: markerSigner{}})
		dir := t.TempDir()
		bin := filepath.Join(dir, "server")
		if err := os.WriteFile(bin, []byte(unsigned), 0o750); err != nil {
			t.Fatal(err)
		}
		before := inodeOf(t, bin)
		live, err := os.Open(bin) // a running process's mapping, as an fd
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()

		if err := rt.gateSignature(context.Background(), adhoc, bin, false); err != nil {
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
		got, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != unsigned+signedMarker {
			t.Errorf("path content = %q, want the signed copy", got)
		}
		fi, err := os.Stat(bin)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Errorf("mode = %v, want 0750 preserved", fi.Mode().Perm())
		}

		calls := codesignCalls(t, logPath)
		if len(calls) != 1 {
			t.Fatalf("codesign calls = %q, want exactly one", calls)
		}
		args := strings.Fields(calls[0])
		target := args[len(args)-1]
		if target == bin || filepath.Dir(target) != dir {
			t.Errorf("codesign signed %q, want a temp path in %s other than the final path", target, dir)
		}
		if !strings.Contains(calls[0], "-i server ") {
			t.Errorf("codesign argv %q lacks -i server (the identifier must be the final base name)", calls[0])
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("dir holds %d entries, want only the binary (temp left behind?)", len(entries))
		}
	})

	t.Run("already-valid-is-untouched", func(t *testing.T) {
		logPath := installFakeCodesign(t)
		rt := newTestRuntime(t, Deps{Signer: markerSigner{}})
		bin := filepath.Join(t.TempDir(), "server")
		if err := os.WriteFile(bin, []byte(unsigned+signedMarker), 0o755); err != nil {
			t.Fatal(err)
		}
		before := inodeOf(t, bin)
		if err := rt.gateSignature(context.Background(), adhoc, bin, false); err != nil {
			t.Fatalf("gateSignature: %v", err)
		}
		if after := inodeOf(t, bin); after != before {
			t.Errorf("valid binary replaced: inode %d -> %d", before, after)
		}
		if calls := codesignCalls(t, logPath); len(calls) != 0 {
			t.Errorf("codesign called on a valid binary: %q", calls)
		}
	})

	t.Run("require-signed-is-never-signed", func(t *testing.T) {
		logPath := installFakeCodesign(t)
		rt := newTestRuntime(t, Deps{Signer: markerSigner{}})
		bin := filepath.Join(t.TempDir(), "server")
		if err := os.WriteFile(bin, []byte(unsigned), 0o755); err != nil {
			t.Fatal(err)
		}
		before := inodeOf(t, bin)
		err := rt.gateSignature(context.Background(), runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED, bin, false)
		if err == nil {
			t.Fatal("require-signed accepted an unsigned binary")
		}
		if after := inodeOf(t, bin); after != before {
			t.Errorf("require-signed binary replaced: inode %d -> %d", before, after)
		}
		if calls := codesignCalls(t, logPath); len(calls) != 0 {
			t.Errorf("codesign called under require-signed: %q", calls)
		}
	})
}
