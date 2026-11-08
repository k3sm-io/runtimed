//go:build darwin

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

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// pcCaseSensitive is _PC_CASE_SENSITIVE from the macOS SDK's <sys/unistd.h>:
// pathconf answers 1 on a case-sensitive volume and 0 on a case-insensitive
// one. golang.org/x/sys/unix does not export it.
const pcCaseSensitive = 11

// TestStateDirEnforcedAcrossCaseAndNormalization proves the state-dir deny is not
// a byte match the filesystem can step around. The default macOS volume is
// case-insensitive and normalization-insensitive APFS, so <data>/CPÉ and the NFD
// spelling of <data>/cpé open the same directory as the NFC <data>/cpé the
// posture names, and each such spelling must be denied in both firmlink
// spellings.
//
// The volume is asked rather than guessed. pathconf(_PC_CASE_SENSITIVE) says
// whether a case variant must resolve, so a variant that disagrees with it fails
// the test, and on a case-sensitive volume the case rows skip: there a variant
// is another directory and nothing to deny. No interface reports normalization
// sensitivity, so the NFD rows expect resolution only on case-insensitive APFS,
// the default volume, and fail if it does not resolve there; elsewhere they skip
// with that reason.
func TestStateDirEnforcedAcrossCaseAndNormalization(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	const leaf = "cpé" // NFC: c, p, U+00E9
	tr := newStateDirTree(t, "/var/tmp", false, leaf)
	sensitive, err := unix.Pathconf(tr.data, pcCaseSensitive)
	if err != nil {
		t.Fatalf("pathconf(%s, _PC_CASE_SENSITIVE): %v", tr.data, err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(tr.data, &fs); err != nil {
		t.Fatalf("statfs(%s): %v", tr.data, err)
	}
	fsType := unix.ByteSliceToString(fs.Fstypename[:])
	caseInsensitive := sensitive == 0
	defaultAPFS := caseInsensitive && fsType == "apfs"

	rootOnly := Posture{WorkDir: tr.pods, DataRoot: tr.data}
	withState := Posture{WorkDir: tr.pods, DataRoot: tr.data, StateDir: tr.stateDir}
	tr.requireStateDirControls(t, withState)
	want, err := os.Stat(tr.secret)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		variant string
		// resolves is whether this volume must open the variant as the state dir;
		// why is the skip reason when it need not.
		resolves bool
		why      string
	}{
		"upper case":     {"CPÉ", caseInsensitive, "the volume is case-sensitive"},         // C, P, U+00C9
		"mixed case":     {"Cpé", caseInsensitive, "the volume is case-sensitive"},         // C, p, U+00E9
		"NFD":            {"cpé", defaultAPFS, "the volume is not case-insensitive APFS"}, // c, p, e, U+0301
		"upper-case NFD": {"CPÉ", defaultAPFS, "the volume is not case-insensitive APFS"},
	} {
		t.Run(name, func(t *testing.T) {
			secret := filepath.Join(tr.data, tc.variant, "server-ca.key")
			got, statErr := os.Stat(secret)
			same := statErr == nil && os.SameFile(want, got)
			switch {
			case !tc.resolves && !same:
				t.Skipf("%s (%s, pathconf case-sensitive %d), so %q is another directory and nothing to deny", tc.why, fsType, sensitive, tc.variant)
			case !tc.resolves:
				t.Fatalf("%q opened the state dir although %s (%s, pathconf %d): the volume probe is wrong", tc.variant, tc.why, fsType, sensitive)
			case !same:
				t.Fatalf("%q does not open the state dir on %s with pathconf case-sensitive %d (stat: %v), which this volume should", tc.variant, fsType, sensitive, statErr)
			}
			// The control: the variant reaches the secret with DataRoot alone, so
			// the refusal below is the state-dir deny and not a missing file.
			if out, prof, err := tr.run(t, rootOnly, stateDirReadScript, secret); err != nil || string(out) != "private-key" {
				t.Fatalf("with DataRoot alone %s was not readable, so this case proves nothing: %v\n%s\n--- profile ---\n%s", secret, err, out, prof)
			}
			for _, target := range []string{secret, otherFirmlinkSpelling(secret)} {
				out, prof, err := tr.run(t, withState, stateDirReadScript, target)
				requireSandboxDenied(t, "read of "+target, out, err, prof)
				out, prof, err = tr.run(t, withState, stateDirWriteScript, target)
				requireSandboxDenied(t, "write to "+target, out, err, prof)
			}
		})
	}
	if got, err := os.ReadFile(tr.secret); err != nil || string(got) != stateDirSecret {
		t.Errorf("secret after the attempts = %q, %v; want %q", got, err, stateDirSecret)
	}
}
