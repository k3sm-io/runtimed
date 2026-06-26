package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestGenerateGolden pins the full rendered profile against the golden file:
// acceptance M1.2-a2 (always (import "system.sb")) and the M2.2 rule ordering
// (protected denies after the allows, narrow re-allows last). Run with -update to
// regenerate the golden.
func TestGenerateGolden(t *testing.T) {
	sp := &runtimev1.SandboxProfile{
		DataVolumePath: "/var/lib/k3sm/pods/pod-abc123/rootfs",
		AllowNetwork:   true,
	}
	got, err := Generate(sp, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	goldenPath := filepath.Join("testdata", "pod.golden.sb")
	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("generated SBPL differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestGenerateDenySet asserts the full deny-set: the profile is default-deny,
// imports system.sb, denies /Users, /private/var/db (with the dyld-only read
// exception), the shared pods root, and the dyld cryptex (write), then re-allows
// the pod's own data volume. This is the security contract of M1.2-a1 + M2.2.
func TestGenerateDenySet(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowNetwork: true}
	out, err := Generate(sp, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	mustContain := []struct {
		name, frag string
	}{
		{"deny-default", "(deny default)"},
		{"import-system", `(import "system.sb")`},
		{"deny-users", "(deny file-read* file-write*\n  (subpath \"/Users\"))"},
		{"deny-var-db", "(deny file-read* file-write*\n  (subpath \"/private/var/db\"))"},
		{"deny-pods-root", "(deny file-read* file-write*\n  (subpath \"/var/lib/k3sm/pods\"))"},
		{"deny-cryptex-write", "(deny file-write*\n  (subpath \"/System/Volumes/Preboot/Cryptexes\")"},
		{"dyld-read-exception", "(subpath \"/private/var/db/dyld\")"},
		{"datavol-reallow", "(allow file-read* file-write*\n  (subpath \"" + dataVol + "\"))"},
		{"read-system", "(subpath \"/System\")"},
		{"net-dns-vip", `(remote ip "10.96.0.10:53")`},
		{"mach-dns", `(global-name "com.apple.mDNSResponder")`},
	}
	for _, tc := range mustContain {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(out, tc.frag) {
				t.Errorf("profile missing %s:\n%q\nfull profile:\n%s", tc.name, tc.frag, out)
			}
		})
	}

	// /Users must never appear in an allow, and the var-db store must never be
	// granted write.
	mustNotContain := []struct{ name, frag string }{
		{"no-users-allow", "(allow file-read* file-write*\n  (subpath \"/Users\""},
		{"no-write-var-db", "(allow file-write*\n  (subpath \"/private/var/db\")"},
	}
	for _, tc := range mustNotContain {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(out, tc.frag) {
				t.Errorf("profile unexpectedly contains %s: %q", tc.name, tc.frag)
			}
		})
	}
}

// TestGenerateProtectedDeniesAfterExtraAllows is acceptance M2.2-a2 (ordering
// half): SBPL is last-match-wins, so the protected denies MUST be emitted AFTER
// any extra-path allow (a hostPath-style extra path cannot override them), and
// the pod's own data-volume re-allow MUST come after the pods-root deny (so the
// pod keeps its own dir).
func TestGenerateProtectedDeniesAfterExtraAllows(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		ExtraReadPaths: []string{"/opt/data"},
	}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	iExtra := strings.Index(out, `(subpath "/opt/data")`)
	iDenyUsers := strings.Index(out, `(subpath "/Users")`)
	iDenyPods := strings.Index(out, `(subpath "/var/lib/k3sm/pods")`)
	iDataReallow := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\"))")
	for name, i := range map[string]int{"extra": iExtra, "deny-users": iDenyUsers, "deny-pods": iDenyPods, "datavol-reallow": iDataReallow} {
		if i < 0 {
			t.Fatalf("fragment %q not found in profile:\n%s", name, out)
		}
	}
	if iExtra >= iDenyUsers || iExtra >= iDenyPods {
		t.Errorf("extra-path allow (%d) must precede the protected denies (users=%d pods=%d) so the denies win", iExtra, iDenyUsers, iDenyPods)
	}
	if iDenyPods >= iDataReallow {
		t.Errorf("pods-root deny (%d) must precede the pod's own data-volume re-allow (%d) so the pod keeps its dir", iDenyPods, iDataReallow)
	}
}

// TestGenerateRejectsProtectedExtraPath is acceptance M2.2-a2 (rejection half): a
// caller-supplied extra path at/under the protected deny-set is rejected with
// ErrProtectedPath, so a hostPath can never widen the allow-list into /Users, the
// secrets store, a sibling pod's dir, or the dyld cryptex.
func TestGenerateRejectsProtectedExtraPath(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	cases := []struct {
		name string
		sp   *runtimev1.SandboxProfile
		opts GenerateOptions
	}{
		{"users", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{"/Users/alice/.ssh"}}, GenerateOptions{}},
		{"sibling-pod", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraWritePaths: []string{"/var/lib/k3sm/pods/other/rootfs"}}, GenerateOptions{}},
		{"var-db", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{"/private/var/db/secret"}}, GenerateOptions{}},
		{"cryptex", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{"/System/Volumes/Preboot/Cryptexes/OS"}}, GenerateOptions{}},
		{"whole-fs", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{"/"}}, GenerateOptions{}},
		{"relative", &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraWritePaths: []string{"opt/rel"}}, GenerateOptions{}},
		{"cred-under-users", &runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{ReadOnlyPaths: []string{"/Users/alice/token"}}},
		{"pv-write-under-users", &runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{WritePaths: []string{"/Users/bob/data"}}},
		{"pv-read-under-var-db", &runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{ReadPaths: []string{"/private/var/db/x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(tc.sp, tc.opts); !errors.Is(err, ErrProtectedPath) {
				t.Fatalf("want ErrProtectedPath, got %v", err)
			}
		})
	}
}

// TestGenerateSecretReadOnlySubScope is acceptance M2.2-a3 (SBPL half): a
// credential mount (secret / SA-token) gets file-read* AND an explicit
// file-write* deny, emitted LAST so the write-deny wins even though the secret
// lives inside the writable data volume — a pod can read but not overwrite its
// credentials.
func TestGenerateSecretReadOnlySubScope(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	secret := dataVol + "/volumes/git-ssh-key"
	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		ReadOnlyPaths: []string{secret},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.Contains(out, "(allow file-read*\n  (subpath \""+secret+"\")") {
		t.Errorf("secret missing file-read* sub-scope:\n%s", out)
	}
	iDataWrite := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\"))")
	iCredDeny := strings.Index(out, "(deny file-write*\n  (subpath \""+secret+"\")")
	if iDataWrite < 0 || iCredDeny < 0 {
		t.Fatalf("missing data-vol write re-allow (%d) or credential write-deny (%d):\n%s", iDataWrite, iCredDeny, out)
	}
	if iCredDeny <= iDataWrite {
		t.Errorf("credential write-deny (%d) must come AFTER the data-volume write re-allow (%d) to win (last-match-wins)", iCredDeny, iDataWrite)
	}
}

// TestPVCInSBPLWriteScope is acceptance runtimed:M3.1-a1 (SBPL half): a read-write
// persistent-volume mount root (opts.WritePaths) — which lives OUTSIDE the pod data
// volume on the APFS storage root — gets BOTH a file-write* and a file-read* allow,
// a read-only PV root (opts.ReadPaths) gets read but NOT write, and the protected
// denies (e.g. /Users) still win regardless.
func TestPVCInSBPLWriteScope(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	const pvWrite = "/var/lib/k3sm/storage/prod/pgdata"

	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		WritePaths: []string{pvWrite},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The PV root is granted file-write* (the write block carries the subpath).
	wantWriteBlock := "(allow file-write*\n  (subpath \"" + pvWrite + "\")\n  (literal \"/dev/null\"))"
	if !strings.Contains(out, wantWriteBlock) {
		t.Errorf("PV mount root missing file-write* allow:\n%s", out)
	}
	// A read-write PV must be readable too (it joins the read allow).
	if !strings.Contains(out, "(subpath \""+pvWrite+"\")\n  (literal \"/dev/null\") (literal \"/dev/zero\")") {
		t.Errorf("PV mount root missing file-read* allow:\n%s", out)
	}
	// The protected denies still win: /Users is denied AFTER the allows.
	if !strings.Contains(out, "(deny file-read* file-write*\n  (subpath \"/Users\"))") {
		t.Errorf("protected /Users deny missing — PV write-scope must not weaken it:\n%s", out)
	}

	// A READ-ONLY PV root gets a read allow but NO write allow (default-deny then
	// blocks writes): the write block stays the bare /dev/null default.
	const pvRO = "/var/lib/k3sm/storage/prod/config"
	ro, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		ReadPaths: []string{pvRO},
	})
	if err != nil {
		t.Fatalf("Generate (read-only): %v", err)
	}
	if !strings.Contains(ro, "(subpath \""+pvRO+"\")") {
		t.Errorf("read-only PV root missing file-read* allow:\n%s", ro)
	}
	if !strings.Contains(ro, "(allow file-write*\n  (literal \"/dev/null\"))") {
		t.Errorf("read-only PV root must NOT get a file-write* allow:\n%s", ro)
	}
}

// TestGenerateNetworkGating checks that without AllowNetwork the profile emits no
// network-outbound allow (default-deny egress).
func TestGenerateNetworkGating(t *testing.T) {
	cases := []struct {
		name        string
		allow       bool
		wantOutFrag string
		wantPresent bool
	}{
		{"network-denied", false, "(allow network-outbound", false},
		{"network-allowed", true, "(allow network-outbound", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath: "/var/lib/k3sm/pods/p/rootfs",
				AllowNetwork:   tc.allow,
			}, GenerateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Contains(out, tc.wantOutFrag)
			if got != tc.wantPresent {
				t.Errorf("network-outbound present=%v, want %v", got, tc.wantPresent)
			}
		})
	}
}

// TestGenerateExtraPaths confirms allowed extra read/write paths (outside the
// protected deny-set) are merged, cleaned, and deterministically ordered.
func TestGenerateExtraPaths(t *testing.T) {
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:  "/var/lib/k3sm/pods/p/rootfs",
		ExtraReadPaths:  []string{"/opt/data", "/opt/data"}, // dup collapses
		ExtraWritePaths: []string{"/var/scratch"},
	}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `(subpath "/opt/data")`) {
		t.Errorf("missing extra read path /opt/data:\n%s", out)
	}
	if strings.Count(out, `(subpath "/opt/data")`) != 1 {
		t.Errorf("extra read path /opt/data not deduped:\n%s", out)
	}
	if !strings.Contains(out, `(subpath "/var/scratch")`) {
		t.Errorf("missing extra write path /var/scratch:\n%s", out)
	}
}

// TestGenerateInvalid checks rejection of profiles with no writable data volume.
func TestGenerateInvalid(t *testing.T) {
	cases := []struct {
		name string
		sp   *runtimev1.SandboxProfile
	}{
		{"nil", nil},
		{"empty-datavol", &runtimev1.SandboxProfile{}},
		{"root-datavol", &runtimev1.SandboxProfile{DataVolumePath: "/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(tc.sp, GenerateOptions{}); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

// TestValidate covers the fail-closed gate: a profile MUST have (deny default)
// and (import "system.sb"); the generator's output passes, a hand-rolled profile
// lacking either is rejected (acceptance M1.2-a2).
func TestValidate(t *testing.T) {
	good, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		profile string
		wantErr error
	}{
		{"generated-ok", good, nil},
		{"missing-deny-default", "(version 1)\n(import \"system.sb\")\n(allow default)\n", ErrMissingDenyDefault},
		{"missing-system-import", "(version 1)\n(deny default)\n(allow process-exec*)\n", ErrMissingSystemImport},
		{"deny-default-only-in-comment", ";; (deny default)\n(import \"system.sb\")\n", ErrMissingDenyDefault},
		{"empty", "", ErrMissingDenyDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.profile)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}
