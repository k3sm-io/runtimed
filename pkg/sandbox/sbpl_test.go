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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
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
		{"deny-pods-root", "(deny file-read* file-write*\n  (subpath \"/var/lib/k3sm/pods\")"},
		{"deny-pods-root-firmlink", "(subpath \"/private/var/lib/k3sm/pods\")"},
		{"deny-cryptex-write", "(deny file-write*\n  (subpath \"/System/Volumes/Preboot/Cryptexes\")"},
		{"dyld-read-exception", "(subpath \"/private/var/db/dyld\")"},
		{"datavol-reallow", "(allow file-read* file-write*\n  (subpath \"" + dataVol + "\")"},
		{"datavol-reallow-firmlink", "(subpath \"/private" + dataVol + "\")"},
		{"read-system", "(subpath \"/System\")"},
		{"net-outbound-unfiltered", "(allow network-outbound)"},
		{"net-bind-unfiltered", "(allow network-bind)"},
		{"mach-dns", `(global-name "com.apple.mDNSResponder")`},
	}
	for _, tc := range mustContain {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(out, tc.frag) {
				t.Errorf("profile missing %s:\n%q\nfull profile:\n%s", tc.name, tc.frag, out)
			}
		})
	}

	// /Users must never appear in an allow, the var-db store must never be
	// granted write, and no per-IP network filter may ever be emitted (it does
	// not compile on macOS 26 — the M10.1 P0).
	mustNotContain := []struct{ name, frag string }{
		{"no-users-allow", "(allow file-read* file-write*\n  (subpath \"/Users\""},
		{"no-write-var-db", "(allow file-write*\n  (subpath \"/private/var/db\")"},
		{"no-remote-ip-filter", "(remote ip"},
		{"no-local-ip-filter", "(local ip"},
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
	iDataReallow := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\")")
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

// TestProtectedPathRefusalNamesPodRootRemedy is B179: a protected-path refusal
// must name its remedy, not just its cause. It goes through Generate (never
// validateExtraPaths directly) with the SAME trigger as the
// "pv-write-under-users" case above — a WritePaths entry under /Users — so this
// assertion and that table can never diverge on what actually rejects. The
// error must still satisfy errors.Is(err, ErrProtectedPath) AND its text must
// name --pod-root (the k3sm server flag that relocates the runtimed on-disk
// root off the protected prefix) — not --work-dir, which does not.
func TestProtectedPathRefusalNamesPodRootRemedy(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol}
	opts := GenerateOptions{WritePaths: []string{"/Users/bob/data"}}

	_, err := Generate(sp, opts)
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("want ErrProtectedPath, got %v", err)
	}
	if !strings.Contains(err.Error(), "--pod-root") {
		t.Fatalf("error %q must name the --pod-root remedy", err.Error())
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
	iDataWrite := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\")")
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

	// The PV root (under the /var firmlink) is granted file-write* in BOTH the raw
	// and /private-resolved form (the write block carries both subpaths).
	wantWriteBlock := "(allow file-write*\n  (subpath \"" + pvWrite + "\")\n  (subpath \"/private" + pvWrite + "\")\n  (literal \"/dev/null\"))"
	if !strings.Contains(out, wantWriteBlock) {
		t.Errorf("PV mount root missing file-write* allow (both firmlink forms):\n%s", out)
	}
	// A read-write PV must be readable too (it joins the read allow, both forms).
	if !strings.Contains(out, "(subpath \""+pvWrite+"\")\n  (subpath \"/private"+pvWrite+"\")\n  (literal \"/dev/null\") (literal \"/dev/zero\")") {
		t.Errorf("PV mount root missing file-read* allow (both firmlink forms):\n%s", out)
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

// TestGeneratePodReapStoreDenied is the podreap trust-boundary contract: the
// daemon-private startup-reap store (<WorkDir>/podreap) MUST be read+write denied
// so a confined pod can never forge a reap record (which drives a root-privileged
// kill(-pgid) at a group of its choosing). The load-bearing case is an ANCESTOR
// extra_write_path: even when a caller grants write to the whole work-dir, the
// emitted podreap deny — placed AFTER the allows (last-match-wins) — must still
// re-deny the store. A validate-set entry alone would not close this; the emitted
// deny is the barrier.
func TestGeneratePodReapStoreDenied(t *testing.T) {
	const workDir = "/var/lib/k3sm"
	const dataVol = workDir + "/pods/p1/rootfs"
	const podReapRoot = workDir + "/" + PodReapSubdir

	// Grant write to the work-dir ITSELF — an ancestor of the reap store. This
	// passes validateExtraPaths (an ancestor is not "under" a protected prefix),
	// so it emits an (allow file-write* (subpath "/var/lib/k3sm")) with no
	// implicit protection of the podreap child.
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:  dataVol,
		ExtraWritePaths: []string{workDir},
	}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The ancestor allow is present (proving this is the dangerous shape, not a
	// validation rejection).
	ancestorAllow := "(allow file-write*\n  (subpath \"" + workDir + "\")"
	iAllow := strings.Index(out, ancestorAllow)
	if iAllow < 0 {
		t.Fatalf("expected the ancestor work-dir write allow in the profile:\n%s", out)
	}

	// The podreap store is denied in BOTH firmlink forms.
	for _, frag := range []string{
		"(subpath \"" + podReapRoot + "\")",
		"(subpath \"/private" + podReapRoot + "\")",
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("podreap store not denied (missing %q):\n%s", frag, out)
		}
	}

	// And the deny is emitted AFTER the ancestor allow so last-match-wins keeps
	// the store denied despite the ancestor write grant.
	iDeny := strings.Index(out, "(deny file-read* file-write*\n  (subpath \""+workDir+"/pods\")")
	if iDeny < 0 {
		t.Fatalf("work-dir protected deny stanza missing:\n%s", out)
	}
	if iDeny <= iAllow {
		t.Errorf("podreap deny (%d) must come AFTER the ancestor work-dir allow (%d) to win (last-match-wins)", iDeny, iAllow)
	}

	// The store dir name is single-sourced: pkg/runtime references this const.
	if PodReapSubdir != "podreap" {
		t.Errorf("PodReapSubdir = %q, want \"podreap\" (single-sourced with pkg/runtime)", PodReapSubdir)
	}
}

// TestWorkDirDenyRootsCoverControlPlaneTrees is the control-plane-tree contract:
// the work-dir siblings that hold the cluster CA keys + kine datastore
// (<WorkDir>/server), the node-agent state (<WorkDir>/agent), the daemon control
// sockets + wireguard mesh private key (<WorkDir>/run) and the content-addressed
// blob store (<WorkDir>/blobs) MUST be BOTH rejected as caller-supplied paths and
// EMITTED as denies after the allows — a validate-set entry alone would not
// survive an ancestor grant, and an emitted deny placed before the allows would
// be worthless (SBPL is last-match-wins).
//
// The work-dir is a t.TempDir(), so a hard-coded /var/lib/k3sm literal cannot
// pass, and the positive control keeps the table honest: a legitimate PV path
// under <WorkDir>/storage must still be granted.
func TestWorkDirDenyRootsCoverControlPlaneTrees(t *testing.T) {
	workDir := t.TempDir()
	dataVol := filepath.Join(workDir, "pods", "p1", "rootfs")
	posture := Posture{WorkDir: workDir}
	subdirs := []string{ServerSubdir, AgentSubdir, RunSubdir, BlobsSubdir}

	// (0) The mesh private key's ABSOLUTE home is denied even though this posture's
	// work-dir is elsewhere. Everything else in the deny-set moves with the
	// work-dir; the key does not, because the installer writes it at a fixed path.
	// Without this the unprivileged home-rooted posture would guard an empty
	// sibling while the key stayed grantable — and note workDir here is a TempDir,
	// so a hard-coded /var/lib/k3sm elsewhere could not make this pass.
	t.Run("the absolute mesh-key dir is denied under a non-default work-dir", func(t *testing.T) {
		absRun := DefaultWorkDir + "/" + RunSubdir
		_, _, protected, err := resolvePosture(posture)
		if err != nil {
			t.Fatalf("resolvePosture: %v", err)
		}
		if err := validateExtraPaths(dataVol, protected, []string{absRun}); !errors.Is(err, ErrProtectedPath) {
			t.Errorf("validateExtraPaths(%q) = %v, want ErrProtectedPath", absRun, err)
		}
		out, gerr := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{Posture: posture})
		if gerr != nil {
			t.Fatalf("Generate: %v", gerr)
		}
		if !strings.Contains(out, `(subpath "`+absRun+`")`) {
			t.Errorf("rendered profile does not deny the absolute mesh-key dir %q", absRun)
		}
	})

	// (1) Rejection: a caller-supplied path AT or UNDER one of the trees is
	// refused outright, whichever path group it arrives in.
	t.Run("rejected as a caller-supplied path", func(t *testing.T) {
		for _, sub := range subdirs {
			root := filepath.Join(workDir, sub)
			for _, p := range []string{root, filepath.Join(root, "child")} {
				for name, opts := range map[string]GenerateOptions{
					"write-path": {Posture: posture, WritePaths: []string{p}},
					"read-path":  {Posture: posture, ReadPaths: []string{p}},
					"credential": {Posture: posture, ReadOnlyPaths: []string{p}},
				} {
					t.Run(sub+"/"+name+"/"+filepath.Base(p), func(t *testing.T) {
						sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol}
						if _, err := Generate(sp, opts); !errors.Is(err, ErrProtectedPath) {
							t.Fatalf("Generate with %s %q: err = %v, want ErrProtectedPath", name, p, err)
						}
					})
				}
			}
			// The same verdict at the validation seam Generate calls, so a future
			// refactor that stops routing through it still fails here.
			_, _, protected, err := resolvePosture(posture)
			if err != nil {
				t.Fatalf("resolvePosture: %v", err)
			}
			if err := validateExtraPaths(dataVol, protected, []string{root}); !errors.Is(err, ErrProtectedPath) {
				t.Fatalf("validateExtraPaths(%q) = %v, want ErrProtectedPath", root, err)
			}
		}
	})

	// (2) Emission + ordering: grant write to the work-dir ITSELF (an ancestor,
	// which validateExtraPaths permits) and require every tree to be re-denied
	// AFTER that allow, by byte index.
	t.Run("emitted deny follows the ancestor allow", func(t *testing.T) {
		out, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:  dataVol,
			ExtraWritePaths: []string{workDir},
		}, GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		iAllow := strings.Index(out, "(allow file-write*\n  (subpath \""+workDir+"\")")
		if iAllow < 0 {
			t.Fatalf("expected the ancestor work-dir write allow in the profile:\n%s", out)
		}
		for _, sub := range subdirs {
			root := filepath.Join(workDir, sub)
			iDeny := strings.Index(out, "(deny file-read* file-write*\n")
			if iDeny < 0 {
				t.Fatalf("protected deny stanza missing:\n%s", out)
			}
			iRoot := strings.Index(out, "(subpath \""+root+"\")")
			if iRoot < 0 {
				t.Fatalf("%s tree %q is not denied:\n%s", sub, root, out)
			}
			if iRoot <= iAllow {
				t.Errorf("%s deny (%d) must come AFTER the ancestor work-dir allow (%d) to win (last-match-wins)", sub, iRoot, iAllow)
			}
			// Both firmlink forms, since a deny written only against the
			// firmlink spelling fails OPEN.
			for _, form := range firmlinkForms(root) {
				if !strings.Contains(out, "(subpath \""+form+"\")") {
					t.Errorf("%s tree missing deny form %q:\n%s", sub, form, out)
				}
			}
		}
	})

	// (3) POSITIVE CONTROL: a legitimate PV mount root under <WorkDir>/storage is
	// still granted and is not covered by any denied root. Without this the table
	// cannot tell "control-plane trees protected" from "all PV volumes broken".
	t.Run("legitimate pv path still granted", func(t *testing.T) {
		pv := filepath.Join(workDir, "storage", "prod", "pgdata")
		out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
			Posture:    posture,
			WritePaths: []string{pv},
		})
		if err != nil {
			t.Fatalf("Generate with a PV write path: %v", err)
		}
		if !strings.Contains(out, "(allow file-write*\n  (subpath \""+pv+"\")") {
			t.Fatalf("PV mount root %q lost its file-write* allow:\n%s", pv, out)
		}
		_, denyRoots, _, err := resolvePosture(posture)
		if err != nil {
			t.Fatalf("resolvePosture: %v", err)
		}
		for _, root := range denyRoots {
			if isUnder(pv, root) {
				t.Fatalf("PV path %q is under denied root %q — the deny-set would clobber every PVC", pv, root)
			}
		}
	})

	// (4) The blobs leaf name is single-sourced in spirit with pkg/image, which
	// derives the same dir from its own literal: if the two drift, this deny
	// guards an empty sibling while the real store stays writable.
	t.Run("blobs leaf agrees with the image store layout", func(t *testing.T) {
		root := t.TempDir()
		c, err := image.NewCache(root)
		if err != nil {
			t.Fatalf("NewCache: %v", err)
		}
		blob, err := c.BlobPath("sha256:" + strings.Repeat("a", 64))
		if err != nil {
			t.Fatalf("BlobPath: %v", err)
		}
		if want := filepath.Join(root, BlobsSubdir); !isUnder(blob, want) {
			t.Errorf("image blob %q is not under %q — BlobsSubdir has drifted from pkg/image", blob, want)
		}
	})
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

// TestGenerateDeniedUnixSockets is deliverable #1 (the AF_UNIX barrier): for each
// SandboxProfile.denied_unix_socket_paths the generator emits an explicit
// (deny network-outbound (remote unix-socket (literal …))) on top of the
// default-deny. Because pods share the runtime client's uid (no per-pod uid
// isolation), this Seatbelt deny is the ONLY barrier keeping a pod off the
// privileged k3sm-netd helper socket, so it must hold whether or not the pod is
// granted network egress — and, when egress is allowed, come AFTER the outbound
// allow (last-match-wins).
func TestGenerateDeniedUnixSockets(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	// Two paths, supplied out of order, to also prove dedupe/sort determinism.
	sockets := []string{"/var/run/k3sm/other.sock", "/var/run/k3sm/netd.sock"}
	for _, allowNet := range []bool{false, true} {
		name := "network-denied"
		if allowNet {
			name = "network-allowed"
		}
		t.Run(name, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:        dataVol,
				AllowNetwork:          allowNet,
				DeniedUnixSocketPaths: sockets,
			}, GenerateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range sockets {
				frag := `(remote unix-socket (literal "` + s + `"))`
				if !strings.Contains(out, frag) {
					t.Errorf("missing AF_UNIX deny for %q:\n%s", s, out)
				}
			}
			// The path is denied (under a (deny network-outbound …) block), never
			// allowed. netd.sock sorts before other.sock, so it heads the block.
			if !strings.Contains(out, "(deny network-outbound\n  (remote unix-socket (literal \"/var/run/k3sm/netd.sock\"))") {
				t.Errorf("AF_UNIX path must lead a (deny network-outbound …) block:\n%s", out)
			}
			if strings.Contains(out, "(allow network-outbound\n  (remote unix-socket") {
				t.Errorf("AF_UNIX socket must never be ALLOWed:\n%s", out)
			}
			if allowNet {
				iAllow := strings.Index(out, "(allow network-outbound")
				iDeny := strings.Index(out, "(deny network-outbound")
				if iAllow < 0 || iDeny < 0 || iDeny <= iAllow {
					t.Errorf("AF_UNIX deny (%d) must come AFTER the network-outbound allow (%d) to win", iDeny, iAllow)
				}
			}
		})
	}

	// No configured sockets => no unix-socket rule at all.
	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "unix-socket") {
		t.Errorf("no denied sockets configured, but profile emits a unix-socket rule:\n%s", out)
	}
}

// TestGeneratePostureWorkDir is deliverable #2 (posture-aware SBPL): a $HOME-style
// work-dir pins the pods-root UNDER it and the protected denies track it (no
// hardcoded /var/lib), while the fixed /Users deny survives and the pod's own
// data-volume re-allow still wins (emitted after the denies). A work-dir that
// escapes the configured home, or is otherwise malformed, is rejected.
func TestGeneratePostureWorkDir(t *testing.T) {
	const home = "/Users/_k3sm"
	const workDir = home + "/Library/k3sm"
	const podsRoot = workDir + "/pods"
	const dataVol = podsRoot + "/pod-abc/rootfs"

	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture: Posture{WorkDir: workDir, Home: home},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The pods-root deny tracks the work-dir (NOT the legacy /var/lib/k3sm/pods).
	if !strings.Contains(out, "(deny file-read* file-write*\n  (subpath \""+podsRoot+"\")") {
		t.Errorf("pods-root deny does not track the work-dir (%q):\n%s", podsRoot, out)
	}
	if strings.Contains(out, "/var/lib/k3sm/pods") {
		t.Errorf("profile still references the legacy /var/lib/k3sm/pods despite a configured work-dir:\n%s", out)
	}
	// The fixed /Users protected deny survives (the daemon home is under /Users,
	// but only THIS pod's data volume is re-allowed; siblings/other homes stay
	// denied).
	if !strings.Contains(out, "(deny file-read* file-write*\n  (subpath \"/Users\"))") {
		t.Errorf("fixed /Users deny missing under a $HOME-style work-dir:\n%s", out)
	}
	// The pod's own data volume is re-allowed AFTER the pods-root deny (last-match-wins).
	iDeny := strings.Index(out, "(subpath \""+podsRoot+"\")")
	iReallow := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\")")
	if iDeny < 0 || iReallow < 0 {
		t.Fatalf("pods-root deny (%d) or data-vol re-allow (%d) missing:\n%s", iDeny, iReallow, out)
	}
	if iDeny >= iReallow {
		t.Errorf("pods-root deny (%d) must precede the data-vol re-allow (%d)", iDeny, iReallow)
	}

	// Rejections: an escaping work-dir and malformed work-dirs fail closed.
	reject := []struct {
		name    string
		posture Posture
		wantErr error
	}{
		{"escapes-home", Posture{WorkDir: "/Users/dev/k3sm", Home: home}, ErrWorkDirEscapesHome},
		{"relative", Posture{WorkDir: "relative/k3sm"}, ErrInvalidWorkDir},
		{"filesystem-root", Posture{WorkDir: "/"}, ErrInvalidWorkDir},
		{"unclean", Posture{WorkDir: "/var/lib//k3sm"}, ErrInvalidWorkDir},
		{"dotdot", Posture{WorkDir: "/Users/_k3sm/../miko", Home: home}, ErrInvalidWorkDir},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{Posture: tc.posture}); !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestGenerateNetworkBindUnfiltered is the M10.1 P0 contract: an allow_network
// pod gets an UNFILTERED (allow network-bind) — never the pre-M10.1 (local ip
// "<PodIP>:*") scoping, which the macOS 26 Seatbelt grammar rejects at
// sandbox_apply ("host must be * or localhost in network address"), making
// every networked pod fail to spawn. A known PodIP must NOT change the rendered
// profile (it is plumbing-only), and without allow_network no bind is granted.
func TestGenerateNetworkBindUnfiltered(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	const podIP = "10.1.2.3"
	cases := []struct {
		name     string
		allowNet bool
		podIP    string
		wantBind bool
	}{
		{"net-with-ip", true, podIP, true},
		{"net-without-ip", true, "", true},
		{"ip-without-net", false, podIP, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath: dataVol,
				AllowNetwork:   tc.allowNet,
			}, GenerateOptions{PodIP: tc.podIP})
			if err != nil {
				t.Fatal(err)
			}
			gotBind := strings.Contains(out, "(allow network-bind)")
			if gotBind != tc.wantBind {
				t.Fatalf("unfiltered network-bind present=%v, want %v:\n%s", gotBind, tc.wantBind, out)
			}
			// The uncompilable per-IP filter must never come back, and the pod IP
			// must never leak into the profile at all.
			if strings.Contains(out, "(local ip") {
				t.Errorf("profile emits a (local ip …) filter — does not compile on macOS 26:\n%s", out)
			}
			if tc.podIP != "" && strings.Contains(out, tc.podIP) {
				t.Errorf("PodIP is plumbing-only and must not render into the SBPL:\n%s", out)
			}
		})
	}

	// PodIP must not perturb the rendered profile byte-for-byte (plumbing-only).
	withIP, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowNetwork: true}, GenerateOptions{PodIP: podIP})
	if err != nil {
		t.Fatal(err)
	}
	withoutIP, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowNetwork: true}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if withIP != withoutIP {
		t.Errorf("PodIP changed the rendered profile; it must be plumbing-only.\n--- with ---\n%s\n--- without ---\n%s", withIP, withoutIP)
	}
}

// TestGenerateVIPsDoNotRenderSBPL is the M10.1 P0 contract for the node VIPs:
// Posture.ResolverVIP and Posture.APIServerVIP are plumbing-only — they render
// NO (remote ip …) filter, because per-IP network filters do not compile on
// macOS 26 (the pre-M10.1 VIP-scoped egress failed sandbox_apply and no
// networked pod could spawn). A networked pod instead gets the unfiltered
// (allow network-outbound), and the AF_UNIX helper-socket deny stays intact and
// AFTER it (last-match-wins keeps the socket denied).
func TestGenerateVIPsDoNotRenderSBPL(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	const apiVIP = "10.43.0.1"
	const resolverVIP = "10.43.0.10"
	const netdSock = "/var/run/k3sm/netd.sock"

	cases := []struct {
		name     string
		posture  Posture
		allowNet bool
	}{
		{"vips-set-with-network", Posture{ResolverVIP: resolverVIP, APIServerVIP: apiVIP}, true},
		{"vips-unset-with-network", Posture{}, true},
		{"vips-set-without-network", Posture{ResolverVIP: resolverVIP, APIServerVIP: apiVIP}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:        dataVol,
				AllowNetwork:          tc.allowNet,
				DeniedUnixSocketPaths: []string{netdSock},
			}, GenerateOptions{Posture: tc.posture})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			// NO per-IP filter, ever — it does not compile on macOS 26. The VIPs
			// must not leak into the profile in any form.
			if strings.Contains(out, "(remote ip") || strings.Contains(out, "(local ip") {
				t.Errorf("profile emits a per-IP network filter — does not compile on macOS 26:\n%s", out)
			}
			for _, vip := range []string{apiVIP, resolverVIP, DefaultResolverVIP} {
				if strings.Contains(out, vip) {
					t.Errorf("VIP %s is plumbing-only and must not render into the SBPL:\n%s", vip, out)
				}
			}

			// A networked pod gets the unfiltered allows; a non-networked pod none.
			gotOut := strings.Contains(out, "(allow network-outbound)")
			if gotOut != tc.allowNet {
				t.Errorf("unfiltered network-outbound present=%v, want %v:\n%s", gotOut, tc.allowNet, out)
			}

			// The AF_UNIX helper-socket deny is intact and never turned into an allow.
			if !strings.Contains(out, `(remote unix-socket (literal "`+netdSock+`"))`) {
				t.Errorf("AF_UNIX helper-socket deny missing:\n%s", out)
			}
			if strings.Contains(out, "(allow network-outbound\n  (remote unix-socket") {
				t.Errorf("AF_UNIX socket must never be ALLOWed:\n%s", out)
			}

			// For a networked pod the unfiltered allow must precede the AF_UNIX deny
			// so last-match-wins keeps the helper socket denied.
			if tc.allowNet {
				iAllow := strings.Index(out, "(allow network-outbound)")
				iDeny := strings.Index(out, "(deny network-outbound")
				if iAllow < 0 || iDeny < 0 || iDeny <= iAllow {
					t.Errorf("network allow (%d) must come BEFORE the AF_UNIX deny (%d) to stay denied:\n%s", iAllow, iDeny, out)
				}
			}
		})
	}
}

// TestFirmlinkForms proves a firmlinked socket path also gets its /private-resolved
// form — without it the socket deny fails open, since libsandbox matches a connect()
// target against the symlink-resolved path (verified against macOS 26 libsandbox).
func TestFirmlinkForms(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/var/lib/k3sm/run/netd.sock", []string{"/var/lib/k3sm/run/netd.sock", "/private/var/lib/k3sm/run/netd.sock"}},
		{"/tmp/x.sock", []string{"/tmp/x.sock", "/private/tmp/x.sock"}},
		{"/etc/y.sock", []string{"/etc/y.sock", "/private/etc/y.sock"}},
		{"/var", []string{"/var", "/private/var"}},
		{"/var/lib/../lib/x.sock", []string{"/var/lib/x.sock", "/private/var/lib/x.sock"}}, // cleaned first
		{"/private/var/lib/x.sock", []string{"/private/var/lib/x.sock"}},                   // already resolved
		{"/Users/a/x.sock", []string{"/Users/a/x.sock"}},                                   // not a firmlink
		{"/variant/x.sock", []string{"/variant/x.sock"}},                                   // /var-prefixed but not under /var/
	}
	for _, tc := range cases {
		if got := firmlinkForms(tc.in); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("firmlinkForms(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
