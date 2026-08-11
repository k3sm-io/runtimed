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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestGeneratedProfileAppliesOnDarwin feeds a realistic M2 profile to the SAME
// libsandbox the runtime uses (/usr/bin/sandbox-exec), so an invalid SBPL construct
// (the `path-equal` class of bug that broke every M2 pod) fails here, not on the
// live gate. It skips where sandbox-exec is absent (non-darwin CI).
func TestGeneratedProfileAppliesOnDarwin(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	sp := &runtimev1.SandboxProfile{
		DataVolumePath:        "/var/lib/k3sm/pods/pod-check/rootfs",
		AllowNetwork:          true,
		DeniedUnixSocketPaths: []string{"/var/lib/k3sm/run/netd.sock"},
		ExtraReadPaths:        []string{"/private/tmp/k3sm-conformance-bin"},
	}
	prof, err := Generate(sp, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	f := filepath.Join(t.TempDir(), "m2.sb")
	if err := os.WriteFile(f, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", f, "/usr/bin/true").CombinedOutput(); err != nil {
		t.Fatalf("sandbox-exec rejected the generated profile: %v\n--- output ---\n%s\n--- profile ---\n%s", err, out, prof)
	}
}

// TestGeneratedProfileAllowsRebasedFileRead is the file-read counterpart to the
// socket guard: it proves a pod CAN read a file under its own data volume via the
// path a macOS firmlink resolves to (/var,/tmp,/etc → /private/…). Before the
// firmlink fix the profile allowed only the raw /var form, so libsandbox (which
// matches the RESOLVED path) denied the rebased read with EPERM — every volume
// mount criterion failed. The work-dir is under /tmp so the test needs no root.
//
// The data volume is sited at <WorkDir>/pods/<id>/rootfs — the production layout
// — because Generate now bounds it there (ErrDataVolumeUnbounded). Keeping this
// test on an arbitrary /tmp dir would mean loosening the bound; this test and the
// integration one are the ONLY two that exercise real libsandbox, so re-siting
// them is strictly cheaper than letting them rot.
func TestGeneratedProfileAllowsRebasedFileRead(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/tmp", "k3sm-fr-"+strconv.Itoa(os.Getpid()))
	dataVol := filepath.Join(base, "pods", "pod-fr", "rootfs")
	// runtimed writes the materialized volume at dataVol; the OS lands it under the
	// /private-resolved path, which is what libsandbox matches.
	realDir := "/private" + filepath.Join(dataVol, "etc", "nats")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll("/private" + base)
	if err := os.WriteFile(filepath.Join(realDir, "nats.conf"), []byte("port: 4222\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture: Posture{WorkDir: base},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "fr.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pod's rebased path is the RAW /tmp firmlink alias; test -r does the
	// access(R_OK) the sandbox gates. exit 0 = the read is allowed.
	target := filepath.Join(dataVol, "etc", "nats", "nats.conf")
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/test", "-r", target).CombinedOutput(); err != nil {
		t.Fatalf("rebased read of %s was DENIED under the generated profile (firmlink allow missing): %v\n%s\n--- profile ---\n%s", target, err, out, prof)
	}
}

// TestSocketDenyBlocksFirmlinkConnect is the fail-open regression guard: it proves
// the generated deny actually BLOCKS a connect() to a socket reached through a
// macOS firmlink (/tmp → /private/tmp), the exact case a raw-path literal misses.
// A same-uid pod can only be kept off the privileged netd socket by this deny, so a
// silent fail-open is a real escape — this asserts the /private-resolved form bites.
func TestSocketDenyBlocksFirmlinkConnect(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available for the connecter")
	}

	// A listening socket at a /tmp (firmlink) alias: the "pod" connects via /tmp/…,
	// but libsandbox matches the resolved /private/tmp/… path.
	alias := filepath.Join("/tmp", "k3sm-denytest-"+strconv.Itoa(os.Getpid())+".sock")
	_ = os.Remove(alias)
	ln, err := net.Listen("unix", alias)
	if err != nil {
		t.Fatalf("listen %s: %v", alias, err)
	}
	defer ln.Close()
	defer os.Remove(alias)
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Minimal profile: allow everything EXCEPT the denied socket (its firmlinkForms),
	// isolating the socket-deny from the full profile's other constraints.
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n(deny network-outbound\n")
	for _, form := range firmlinkForms(alias) {
		b.WriteString(fmt.Sprintf("  (remote unix-socket (literal %q))\n", form))
	}
	b.WriteString("  )\n")
	prof := filepath.Join(t.TempDir(), "deny.sb")
	if err := os.WriteFile(prof, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	const connecter = `import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1]); print("CONNECTED"); sys.exit(0)
except PermissionError: print("DENIED"); sys.exit(3)
except Exception as e: print("ERR:%s"%e); sys.exit(4)
`
	out, err := exec.Command("/usr/bin/sandbox-exec", "-f", prof, py, "-c", connecter, alias).CombinedOutput()
	if err == nil {
		t.Fatalf("connect via the /tmp firmlink alias was NOT denied (FAIL-OPEN):\n%s\n--- profile ---\n%s", out, b.String())
	}
	if !strings.Contains(string(out), "DENIED") {
		t.Fatalf("expected the sandboxed connect to be DENIED, got: %s", out)
	}
}
