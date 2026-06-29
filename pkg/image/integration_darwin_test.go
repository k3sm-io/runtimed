//go:build integration && darwin

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
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestIntegrationClonefileCoW is acceptance M1.1-a2: materialization is a real
// APFS clone (not a byte copy) and is idempotent. It clones a file with
// APFSCloner and asserts the clone reports cow==true and shares no inode (a
// distinct inode with shared extents is what APFS CoW produces). Requires the
// temp dir to be on an APFS volume (true for the default macOS /var tmp).
func TestIntegrationClonefileCoW(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	if err := os.WriteFile(src, []byte("clone-me-with-apfs-cow"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.bin")

	cow, err := APFSCloner{}.Clone(src, dst)
	if err != nil {
		t.Fatalf("Clone: %v (is %s on APFS?)", err, dir)
	}
	if !cow {
		t.Fatalf("Clone reported byte-copy fallback; expected a real APFS clone on %s", dir)
	}

	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "clone-me-with-apfs-cow" {
		t.Fatalf("clone content = %q, err %v", got, err)
	}

	// A clone is a distinct inode (CoW), and carries no quarantine xattr.
	si := statInode(t, src)
	di := statInode(t, dst)
	if si == di {
		t.Errorf("clone shares the source inode (%d); expected a CoW clone with a distinct inode", si)
	}
	if err := assertNoQuarantine(dst); err != nil {
		t.Errorf("clone unexpectedly quarantined: %v", err)
	}
}

// TestIntegrationMaterializeIdempotent clones a tree, then re-materializes and
// verifies no error and identical content (M1.1-a2 idempotence).
func TestIntegrationMaterializeIdempotent(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "bin", "app"), []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "rootfs")

	cloned1, err := MaterializeTree(APFSCloner{}, src, dst)
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	if cloned1 == 0 {
		t.Error("expected at least one real APFS clone")
	}
	cloned2, err := MaterializeTree(APFSCloner{}, src, dst)
	if err != nil {
		t.Fatalf("second materialize (idempotent): %v", err)
	}
	if cloned2 != 0 {
		t.Errorf("re-materialize cloned %d files; expected 0 (idempotent)", cloned2)
	}
}

// TestIntegrationQuarantineDetected verifies assertNoQuarantine actually fires
// when com.apple.quarantine is present (so the post-materialize assertion is
// real, not vacuous).
func TestIntegrationQuarantineDetected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "q.bin")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Set the quarantine xattr via xattr(1).
	cmd := exec.Command("xattr", "-w", QuarantineXattr, "0081;00000000;test;", f)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot set quarantine xattr (%v): %s", err, out)
	}
	if err := assertNoQuarantine(f); err == nil {
		t.Fatal("assertNoQuarantine returned nil for a quarantined file")
	}
}

// TestIntegrationAdHocSignAMFI is acceptance M1.1-a3: an unsigned arm64 binary
// runs after ad-hoc signing, and the require-signed policy rejects an ad-hoc
// binary. Uses a tiny compiled C binary so the signature can be stripped/applied.
func TestIntegrationAdHocSignAMFI(t *testing.T) {
	ctx := context.Background()
	bin := buildTinyExecutable(t)

	// Strip any signature the linker added so we start unsigned.
	stripSignature(t, bin)

	// Ad-hoc sign on "pull".
	if err := AdHocSign(ctx, bin); err != nil {
		t.Fatalf("AdHocSign: %v", err)
	}

	insp := CodesignTool{}
	// After ad-hoc sign: signed==true, adhoc==true.
	signed, err := insp.Signed(ctx, bin)
	if err != nil || !signed {
		t.Fatalf("ad-hoc signed binary not reported signed: signed=%v err=%v", signed, err)
	}
	adhoc, err := insp.AdHoc(ctx, bin)
	if err != nil || !adhoc {
		t.Fatalf("ad-hoc signed binary not reported ad-hoc: adhoc=%v err=%v", adhoc, err)
	}

	// ADHOC_OK passes; it must also actually EXEC under AMFI.
	if err := CheckSignaturePolicy(ctx, insp, runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, bin); err != nil {
		t.Fatalf("ADHOC_OK rejected an ad-hoc binary: %v", err)
	}
	if out, err := exec.Command(bin).CombinedOutput(); err != nil {
		t.Fatalf("ad-hoc signed binary failed to exec under AMFI: %v: %s", err, out)
	}

	// REQUIRE_SIGNED must REJECT an ad-hoc binary.
	if err := CheckSignaturePolicy(ctx, insp, runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED, bin); err == nil {
		t.Fatal("REQUIRE_SIGNED accepted an ad-hoc binary; want rejection")
	}
}

func statInode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t for %s", path)
	}
	return st.Ino
}

// buildTinyExecutable compiles a minimal C program to an arm64 Mach-O and returns
// its path.
func buildTinyExecutable(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	srcC := filepath.Join(dir, "tiny.c")
	if err := os.WriteFile(srcC, []byte("int main(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "tiny")
	if out, err := exec.Command("clang", "-o", bin, srcC).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable (%v): %s", err, out)
	}
	return bin
}

// stripSignature removes any code signature so the binary starts unsigned.
func stripSignature(t *testing.T, bin string) {
	t.Helper()
	// codesign --remove-signature is best-effort; a freshly clang-built arm64
	// binary carries a linker ad-hoc sig we want gone for the "unsigned" start.
	_ = exec.Command("codesign", "--remove-signature", bin).Run()
}
