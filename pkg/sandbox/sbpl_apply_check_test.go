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

// TestGeneratedProfileAppliesOnDarwin feeds a realistic M2 profile to the same
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
		// The loopback port denies ride the same compile check, and they need it
		// for the same reason: a (remote ip …) form libsandbox will not accept
		// makes every NETWORKED pod on the node fail at sandbox_apply, one pod at
		// a time, with nothing pointing at the profile. Two ports so the repeated
		// emission is covered, not just the single-line case.
		DeniedLocalPorts: []uint32{10257, 12379},
		ExtraReadPaths:   []string{"/private/tmp/k3sm-conformance-bin"},
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
// socket guard: it proves a pod can read a file under its own data volume via the
// path a macOS firmlink resolves to (/var,/tmp,/etc → /private/…). Before the
// firmlink fix the profile allowed only the raw /var form, so libsandbox (which
// matches the RESOLVED path) denied the rebased read with EPERM — every volume
// mount criterion failed. The work-dir is under /tmp so the test needs no root.
//
// The data volume is sited at <WorkDir>/pods/<id>/rootfs — the production layout
// — because Generate now bounds it there (ErrDataVolumeUnbounded). Keeping this
// test on an arbitrary /tmp dir would mean loosening the bound; this test and the
// integration one are the only two that exercise real libsandbox, so re-siting
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

// TestLocalPortDenyBlocksLoopbackConnect is the AF_INET counterpart of
// TestSocketDenyBlocksFirmlinkConnect, and it carries the whole evidential weight
// of denied_local_ports: it proves through real libsandbox that the emitted
// (deny network-outbound (remote ip "localhost:<port>")) BITES — a dial to the
// denied port is refused while the pod's network grant otherwise stands.
//
// Both halves matter and neither alone is enough. A denied port that connects is
// a fail-open: the caller was told a local listener is unreachable from a
// same-uid pod and it is not. A second, undenied port that ALSO fails would mean
// the profile broke networking for everything, which would "pass" a one-sided
// test while making every networked pod useless — so the same profile, in the
// same run, must refuse portA and allow portB.
//
// The profile is the real generated one, not a minimal hand-written stand-in:
// what has to hold is that the deny survives its position after the network
// stanza in the artifact pods actually run under (SBPL is last-match-wins).
func TestLocalPortDenyBlocksLoopbackConnect(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available for the connecter")
	}

	// The connecter distinguishes the three outcomes that matter. A timeout is
	// NOT a denial — it is the answer of a host that never replied — so it gets
	// its own exit code and fails the test rather than reading as success.
	const connecter = `import socket,sys
host=sys.argv[1]; port=int(sys.argv[2])
fam=socket.AF_INET6 if ":" in host else socket.AF_INET
s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(5)
try:
    s.connect((host,port)); print("CONNECTED"); sys.exit(0)
except PermissionError: print("DENIED:EPERM"); sys.exit(3)
except ConnectionRefusedError: print("DENIED:ECONNREFUSED"); sys.exit(3)
except socket.timeout: print("TIMEOUT"); sys.exit(5)
except Exception as e: print("ERR:%r"%(e,)); sys.exit(4)
`

	// listenPair returns two live listeners on host and their ports; the caller
	// closes them. Ephemeral ports (":0") keep the test from colliding with
	// anything on the developer's machine and keep every port here a datum.
	listenPair := func(t *testing.T, network, host string) (int, int, func()) {
		t.Helper()
		var lns []net.Listener
		var ports []int
		for i := 0; i < 2; i++ {
			ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
			if err != nil {
				for _, l := range lns {
					_ = l.Close()
				}
				t.Skipf("cannot listen on %s %s: %v", network, host, err)
			}
			lns = append(lns, ln)
			_, p, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				t.Fatalf("SplitHostPort(%s): %v", ln.Addr(), err)
			}
			n, err := strconv.Atoi(p)
			if err != nil {
				t.Fatalf("port %q: %v", p, err)
			}
			ports = append(ports, n)
			go func(l net.Listener) {
				for {
					c, e := l.Accept()
					if e != nil {
						return
					}
					_ = c.Close()
				}
			}(ln)
		}
		return ports[0], ports[1], func() {
			for _, l := range lns {
				_ = l.Close()
			}
		}
	}

	run := func(t *testing.T, network, host string) {
		t.Helper()
		portA, portB, closeAll := listenPair(t, network, host)
		defer closeAll()

		prof, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:   "/var/lib/k3sm/pods/pod-portdeny/rootfs",
			AllowNetwork:     true,
			DeniedLocalPorts: []uint32{uint32(portA)},
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		want := fmt.Sprintf("(deny network-outbound (remote ip \"localhost:%d\"))", portA)
		if !strings.Contains(prof, want) {
			t.Fatalf("generated profile does not carry %s:\n%s", want, prof)
		}
		sb := filepath.Join(t.TempDir(), "portdeny.sb")
		if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
			t.Fatal(err)
		}
		dial := func(port int) (string, error) {
			out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, py, "-c", connecter, host, strconv.Itoa(port)).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		}

		// The denied port: must be refused, and refused by the SANDBOX. A
		// TIMEOUT or a python-level ERR would mean the test proved nothing about
		// the deny, so only an explicit DENIED verdict counts.
		outA, errA := dial(portA)
		if errA == nil {
			t.Fatalf("connect to the DENIED port %d succeeded (FAIL-OPEN): %s\n--- profile ---\n%s", portA, outA, prof)
		}
		if !strings.HasPrefix(outA, "DENIED:") {
			t.Fatalf("connect to the denied port %d failed, but not as a sandbox denial: %q (%v)", portA, outA, errA)
		}

		// The undenied port, under the SAME profile: must still connect, or the
		// deny is not port-precise and the network grant has been broken.
		outB, errB := dial(portB)
		if errB != nil || outB != "CONNECTED" {
			t.Fatalf("connect to the UNDENIED port %d did not succeed: %q (%v)\n--- profile ---\n%s", portB, outB, errB, prof)
		}
		t.Logf("%s: port %d %s, port %d %s", host, portA, outA, portB, outB)
	}

	t.Run("ipv4", func(t *testing.T) { run(t, "tcp4", "127.0.0.1") })
	// IPv6 loopback is not guaranteed to be configured; listenPair skips if it
	// cannot listen. `localhost` in an SBPL filter is a host-family-blind name, so
	// this asserts the same deny covers the v6 loopback where one exists.
	t.Run("ipv6", func(t *testing.T) { run(t, "tcp6", "::1") })
}
