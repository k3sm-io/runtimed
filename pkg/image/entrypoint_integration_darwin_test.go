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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestSignTargetResolvesInImageSymlinkEntrypoint is the gate for an in-image
// entrypoint. For every shape the native unpacker admits, it runs the daemon's
// ADHOC_OK sequence on a real unsigned Mach-O with the real codesign: sign by
// replace at the name the image uses, check the policy at that same name, then
// exec it, and the regular file the name reaches is the one signed. A relative
// in-root link and a /bin/sh the image carries already worked; what failed was
// the message. A FROM scratch image whose ENTRYPOINT is /bin/sh failed as "sign
// target is not a regular file inside its root ... does not resolve", which
// reads as a containment problem; it now carries ErrEntrypointNotInImage and
// says the image does not carry it. A chain that leaves the root is still
// refused, and not as "not in the image".
func TestSignTargetResolvesInImageSymlinkEntrypoint(t *testing.T) {
	ctx := context.Background()
	src := buildTinyExecutable(t)
	stripSignature(t, src)
	macho, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	insp := CodesignTool{}
	for _, s := range entrypointShapes() {
		t.Run(s.name, func(t *testing.T) {
			root := newEntrypointRoot(t, s, macho)
			// The sign staging dir must share the rootfs volume, as the
			// daemon's ingest dir does.
			staging := filepath.Join(filepath.Dir(root), "ingest", "sign")
			bin := filepath.Join(root, filepath.FromSlash(s.argv0))
			err := AdHocSignByReplace(ctx, staging, root, bin)
			if s.wantErr != nil {
				if !errors.Is(err, s.wantErr) {
					t.Fatalf("AdHocSignByReplace(%s) = %v; want %v", s.argv0, err, s.wantErr)
				}
				if s.wantErr == ErrEntrypointNotInImage && !strings.Contains(err.Error(), "names nothing the image carries") {
					t.Errorf("message does not say the image lacks it: %v", err)
				}
				if s.wantErr == ErrSignTarget && errors.Is(err, ErrEntrypointNotInImage) {
					t.Errorf("an escaping chain is reported as not in the image: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AdHocSignByReplace(%s): %v", s.argv0, err)
			}
			if err := CheckSignaturePolicy(ctx, insp, runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, bin); err != nil {
				t.Fatalf("ADHOC_OK check at %s after signing: %v", bin, err)
			}
			if out, err := exec.Command(bin).CombinedOutput(); err != nil {
				t.Fatalf("exec %s: %v: %s", bin, err, out)
			}
			real := filepath.Join(root, filepath.FromSlash(s.want))
			if fi, err := os.Lstat(real); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("%s is not the regular in-image file: %v", real, err)
			}
			if ok, err := insp.Signed(ctx, real); err != nil || !ok {
				t.Fatalf("in-image file %s not signed: %v, %v", real, ok, err)
			}
		})
	}
}
