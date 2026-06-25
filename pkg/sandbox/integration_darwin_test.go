//go:build integration && darwin

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// buildExecShim builds and ad-hoc signs the k3sm-execshim helper into a temp dir
// and returns its path. The ad-hoc signature is plain (flags=0x2): hardened
// runtime and library validation are NOT applied, so a DYLD insert can load.
func buildExecShim(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, ExecShimName)
	cmd := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build k3sm-execshim: %v\n%s", err, out)
	}
	// Ad-hoc sign, stripping hardened-runtime/library-validation (no -o options).
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("codesign shim: %v\n%s", err, out)
	}
	return shim
}

// genProfileAllowing renders a generated profile whose data volume is dataVol and
// that additionally reads the extra paths (so test binaries under /private/tmp
// can be exec'd and read).
func genProfile(t *testing.T, dataVol string, extraRead ...string) string {
	t.Helper()
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		ExtraReadPaths: extraRead,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// runUnderShim runs argv via the exec-shim with profile, returning combined
// output and the exit error. env is the child environment.
func runUnderShim(t *testing.T, shim, profile string, env []string, argv ...string) (string, error) {
	t.Helper()
	pf := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(pf, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	full := append([]string{pf}, argv...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shim, full...)
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// TestIntegrationConfinement is acceptance M1.2-a1 (live half): a process spawned
// under a generated profile reads /System but is DENIED /Users.
func TestIntegrationConfinement(t *testing.T) {
	shim := buildExecShim(t)
	dataVol := t.TempDir()
	profile := genProfile(t, dataVol, "/private/tmp", "/private/var/folders")

	t.Run("reads-System", func(t *testing.T) {
		out, err := runUnderShim(t, shim, profile, os.Environ(),
			"/bin/ls", "/System/Library/CoreServices")
		if err != nil {
			t.Fatalf("ls /System denied unexpectedly: %v\n%s", err, out)
		}
	})

	t.Run("denied-Users", func(t *testing.T) {
		out, err := runUnderShim(t, shim, profile, os.Environ(), "/bin/ls", "/Users")
		if err == nil {
			t.Fatalf("ls /Users succeeded under confinement; want denial.\n%s", out)
		}
		if !strings.Contains(out, "Operation not permitted") {
			t.Errorf("expected 'Operation not permitted', got:\n%s", out)
		}
	})

	t.Run("foundation-binary-runs", func(t *testing.T) {
		// plutil is Foundation-linked; it must launch (dyld init succeeds despite
		// the /private/var/db tightening).
		out, err := runUnderShim(t, shim, profile, os.Environ(),
			"/usr/bin/plutil", "-p", "/System/Library/CoreServices/SystemVersion.plist")
		if err != nil {
			t.Fatalf("Foundation binary failed under tightened profile: %v\n%s", err, out)
		}
		if !strings.Contains(out, "ProductVersion") {
			t.Errorf("plutil output unexpected:\n%s", out)
		}
	})
}

// TestIntegrationDYLDPreserved is the KEY cross-repo enabler: a process spawned
// by the exec-shim still sees DYLD_INSERT_LIBRARIES in its environment. This is
// what unblocks darwin-net's DNS shim and what /usr/bin/sandbox-exec would break.
func TestIntegrationDYLDPreserved(t *testing.T) {
	shim := buildExecShim(t)
	work := t.TempDir()

	// A dylib whose constructor announces it ran (proves DYLD actually inserted).
	dylib := filepath.Join(work, "libmarker.dylib")
	dySrc := filepath.Join(work, "marker.c")
	if err := os.WriteFile(dySrc, []byte(
		"#include <stdio.h>\n__attribute__((constructor)) static void init(void){fprintf(stderr,\"MARKER-CONSTRUCTOR-RAN\\n\");}\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-dynamiclib", "-o", dylib, dySrc).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable to build dylib (%v): %s", err, out)
	}

	// A pod binary that prints whether it sees DYLD_INSERT_LIBRARIES in its env.
	pod := filepath.Join(work, "podbin")
	podSrc := filepath.Join(work, "pod.c")
	if err := os.WriteFile(podSrc, []byte(
		"#include <stdio.h>\n#include <stdlib.h>\nint main(void){const char*v=getenv(\"DYLD_INSERT_LIBRARIES\");printf(\"POD-SEES-DYLD=%s\\n\",v?v:\"(unset)\");return 0;}\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-o", pod, podSrc).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable to build pod (%v): %s", err, out)
	}
	// Ad-hoc sign the pod (plain adhoc; hardened runtime would strip DYLD insert).
	if out, err := exec.Command("codesign", "-s", "-", "-f", pod).CombinedOutput(); err != nil {
		t.Fatalf("codesign pod: %v\n%s", err, out)
	}

	profile := genProfile(t, work, "/private/tmp", "/private/var/folders", work)
	env := append(os.Environ(), "DYLD_INSERT_LIBRARIES="+dylib)

	out, err := runUnderShim(t, shim, profile, env, pod)
	if err != nil {
		t.Fatalf("pod under shim failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "POD-SEES-DYLD="+dylib) {
		t.Fatalf("DYLD_INSERT_LIBRARIES NOT preserved through the exec-shim.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "MARKER-CONSTRUCTOR-RAN") {
		t.Errorf("DYLD insert dylib constructor did not run under the shim.\noutput:\n%s", out)
	}
}
