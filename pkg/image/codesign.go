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
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// CodesignTool is the production SignatureInspector. It shells out to the macOS
// codesign and spctl tools to read a Mach-O's signature facts. It is darwin-only
// in practice (the tools exist only there); off darwin its methods will error,
// which the fail-closed policy gate surfaces.
//
// The zero value is usable.
type CodesignTool struct{}

// Signed reports whether path has any valid code signature (ad-hoc included):
// `codesign --verify` exits 0.
func (CodesignTool) Signed(ctx context.Context, path string) (bool, error) {
	err := exec.CommandContext(ctx, "codesign", "--verify", "--strict", path).Run()
	if err == nil {
		return true, nil
	}
	if exitErr := (&exec.ExitError{}); asExit(err, exitErr) {
		// Non-zero exit means not validly signed; not a tool failure.
		return false, nil
	}
	return false, err
}

// AdHoc reports whether path's signature is ad-hoc. `codesign -dv` prints
// "Signature=adhoc" (and the CodeDirectory flags include adhoc) for ad-hoc
// signatures. codesign writes the detail to stderr.
func (CodesignTool) AdHoc(ctx context.Context, path string) (bool, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "codesign", "-dv", path)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if exitErr := (&exec.ExitError{}); asExit(err, exitErr) {
			// Unsigned binaries make -dv exit non-zero; they are not ad-hoc.
			return false, nil
		}
		return false, err
	}
	out := stderr.String()
	return strings.Contains(out, "Signature=adhoc") || strings.Contains(out, "flags=0x2(adhoc)") || strings.Contains(out, "adhoc"), nil
}

// Notarized reports whether path passes Gatekeeper notarization assessment:
// `spctl --assess --type execute` exits 0.
func (CodesignTool) Notarized(ctx context.Context, path string) (bool, error) {
	err := exec.CommandContext(ctx, "spctl", "--assess", "--type", "execute", path).Run()
	if err == nil {
		return true, nil
	}
	if exitErr := (&exec.ExitError{}); asExit(err, exitErr) {
		return false, nil
	}
	return false, err
}

// asExit reports whether err is an *exec.ExitError, copying it into dst.
func asExit(err error, dst *exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*dst = *ee
		return true
	}
	return false
}
