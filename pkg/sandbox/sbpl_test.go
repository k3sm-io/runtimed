package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestGenerateGolden pins the full rendered profile against the golden file:
// acceptance M1.2-a2 (always (import "system.sb")) and the tightened deny-set.
// Run with -update to regenerate the golden.
func TestGenerateGolden(t *testing.T) {
	sp := &runtimev1.SandboxProfile{
		DataVolumePath: "/var/lib/k3sm/pods/pod-abc123/rootfs",
		AllowNetwork:   true,
	}
	got, err := Generate(sp)
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

// TestGenerateDenySet asserts the full deny-set (NOT just /Users): the profile is
// default-deny, imports system.sb, denies /private/var/db (with the dyld-only
// read exception), denies the shared pods root, and scopes file-write* to the pod
// data volume. This is the security contract of M1.2-a1's static half.
func TestGenerateDenySet(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowNetwork: true}
	out, err := Generate(sp)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	mustContain := []struct {
		name, frag string
	}{
		{"deny-default", "(deny default)"},
		{"import-system", `(import "system.sb")`},
		{"deny-var-db", "(deny file-read* file-write*\n  (subpath \"/private/var/db\"))"},
		{"dyld-read-exception", "(subpath \"/private/var/db/dyld\")"},
		{"deny-pods-root", "(deny file-read* file-write*\n  (subpath \"/var/lib/k3sm/pods\"))"},
		{"write-scoped-datavol", "(allow file-write*\n  (subpath \"" + dataVol + "\")"},
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

	// The pod must NOT be granted blanket write outside its data volume, and the
	// home dir must never be granted.
	mustNotContain := []struct{ name, frag string }{
		{"no-users-allow", `(allow file-read* file-write*\n  (subpath "/Users"`},
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
			})
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

// TestGenerateExtraPaths confirms extra read/write paths are merged, cleaned, and
// deterministically ordered.
func TestGenerateExtraPaths(t *testing.T) {
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:  "/var/lib/k3sm/pods/p/rootfs",
		ExtraReadPaths:  []string{"/opt/data", "/opt/data"}, // dup collapses
		ExtraWritePaths: []string{"/var/scratch"},
	})
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
			if _, err := Generate(tc.sp); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

// TestValidate covers the fail-closed gate: a profile MUST have (deny default)
// and (import "system.sb"); the generator's output passes, a hand-rolled profile
// lacking either is rejected (acceptance M1.2-a2).
func TestValidate(t *testing.T) {
	good, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"})
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
