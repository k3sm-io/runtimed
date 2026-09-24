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

package sandbox

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// buildExecShim builds and ad-hoc signs the k3sm-execshim helper for the ambient
// toolchain's architecture. Callers that care which architecture the confiner is
// use buildExecShimForGOARCH.
func buildExecShim(t *testing.T) string {
	t.Helper()
	return buildExecShimForGOARCH(t, "")
}

// buildExecShimForGOARCH builds and ad-hoc signs the k3sm-execshim helper into a
// temp dir and returns its path. The ad-hoc signature is plain (flags=0x2):
// hardened runtime and library validation are not applied, so a DYLD insert can
// load.
//
// goarch pins GOARCH for the build; empty means "whatever the toolchain defaults
// to". Pinning matters wherever a test's meaning depends on the confiner's
// architecture, because the toolchain's own arch is not necessarily the host's.
func buildExecShimForGOARCH(t *testing.T, goarch string) string {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, ExecShimName)
	cmd := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if goarch != "" {
		cmd.Env = append(cmd.Env, "GOARCH="+goarch)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build k3sm-execshim (GOARCH=%q): %v\n%s", goarch, err, out)
	}
	// Ad-hoc sign, stripping hardened-runtime/library-validation (no -o options).
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("codesign shim: %v\n%s", err, out)
	}
	return shim
}

// podVolume returns a node posture rooted at a fresh t.TempDir() work-dir plus
// the pod data volume derived under it (<WorkDir>/pods/<podID>/rootfs), created
// on disk so a test can build its helper binaries inside it.
//
// Every live-libsandbox test here goes through it because Generate bounds the
// data volume to the posture's pods root (ErrDataVolumeUnbounded); a bare
// t.TempDir() data volume is exactly the unbounded shape the bound refuses. It
// also makes these tests render the production path layout instead of an
// arbitrary one.
func podVolume(t *testing.T, podID string) (Posture, string) {
	t.Helper()
	workDir := t.TempDir()
	dataVol := filepath.Join(workDir, "pods", podID, "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	return Posture{WorkDir: workDir}, dataVol
}

// genProfile renders a generated profile whose data volume is dataVol under
// posture, and that additionally reads the extra paths (so test binaries under
// /private/tmp can be exec'd and read).
func genProfile(t *testing.T, posture Posture, dataVol string, extraRead ...string) string {
	t.Helper()
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		ExtraReadPaths: extraRead,
	}, GenerateOptions{Posture: posture})
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
	// Shim contract: <uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary>...
	// "-1 -1 -" requests no privilege drop (run as the test/daemon identity); the
	// two launch-spec tokens are the empty sentinels supervisor.EncodeRlimits(nil)
	// and EncodeQoS(false) both emit — no setrlimit plan, no background QoS. They
	// sit before the profile path so binary skew fails closed (execshim.go).
	full := append([]string{"-1", "-1", "-", "-", "-", pf}, argv...)
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
// under a generated profile reads /System but is denied /Users.
func TestIntegrationConfinement(t *testing.T) {
	shim := buildExecShim(t)
	posture, dataVol := podVolume(t, "pod-confine")
	profile := genProfile(t, posture, dataVol, "/private/tmp", "/private/var/folders")

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

// TestIntegrationNetworkStanzaCompiles is the M10.1 P0 regression gate: a
// profile generated with the full production networked-pod shape —
// AllowNetwork=true, a PodIP, and both node VIPs set — must actually COMPILE
// and APPLY through the real exec-shim/libsandbox path. On macOS 26 Seatbelt
// network filters accept only localhost/* hosts, so the pre-M10.1 IP-scoped
// stanza ((remote ip "<VIP>:53"), (local ip "<PodIP>:*")) failed sandbox_apply
// ("host must be * or localhost in network address") and every networked pod
// died at spawn. This test goes red if such a filter ever returns. User-space
// only: ad-hoc sign, no root.
func TestIntegrationNetworkStanzaCompiles(t *testing.T) {
	shim := buildExecShim(t)
	posture, work := podVolume(t, "pod-net")
	posture.ResolverVIP, posture.APIServerVIP = "10.43.0.10", "10.43.0.1"

	profile, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: work,
		AllowNetwork:   true,
		ExtraReadPaths: []string{"/private/tmp", "/private/var/folders"},
	}, GenerateOptions{
		Posture: posture,
		PodIP:   "10.64.0.7",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("profile-compiles-and-applies", func(t *testing.T) {
		out, err := runUnderShim(t, shim, profile, os.Environ(), "/usr/bin/true")
		if err != nil {
			t.Fatalf("networked-pod profile failed to compile/apply at sandbox_apply: %v\n%s", err, out)
		}
	})

	t.Run("bind-and-listen-succeeds", func(t *testing.T) {
		// A tiny server helper that binds and listen()s proves both (allow
		// network-bind) grants bind() and (allow network-inbound) grants listen().
		// The listen() leg is load-bearing: a bare network-bind passes bind() but a
		// TCP server's listen() is gated by the separate network-inbound operation, so
		// without it every server pod (a Service target, a readiness/liveness HTTP
		// server) fails listen() with EPERM (the M10.1 regression this test now guards).
		bin := filepath.Join(work, "bindbin")
		src := filepath.Join(work, "bind.c")
		if err := os.WriteFile(src, []byte(
			"#include <stdio.h>\n#include <string.h>\n#include <arpa/inet.h>\n#include <sys/socket.h>\n#include <unistd.h>\n"+
				"int main(void){int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0){perror(\"socket\");return 1;}\n"+
				"struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;a.sin_port=0;a.sin_addr.s_addr=inet_addr(\"127.0.0.1\");\n"+
				"if(bind(fd,(struct sockaddr*)&a,sizeof a)!=0){perror(\"bind\");return 1;}\n"+
				"if(listen(fd,1)!=0){perror(\"listen\");return 1;}\n"+
				"printf(\"LISTEN-OK\\n\");close(fd);return 0;}\n"),
			0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("clang", "-o", bin, src).CombinedOutput(); err != nil {
			t.Skipf("clang unavailable to build bind helper (%v): %s", err, out)
		}
		if out, err := exec.Command("codesign", "-s", "-", "-f", bin).CombinedOutput(); err != nil {
			t.Fatalf("codesign bind helper: %v\n%s", err, out)
		}
		out, err := runUnderShim(t, shim, profile, os.Environ(), bin)
		if err != nil {
			t.Fatalf("bind+listen(127.0.0.1) failed under the networked-pod profile (network-inbound missing?): %v\n%s", err, out)
		}
		if !strings.Contains(out, "LISTEN-OK") {
			t.Fatalf("server helper did not report listen success:\n%s", out)
		}
	})
}

// TestIntegrationDYLDPreserved is the KEY cross-repo enabler: a process spawned
// by the exec-shim still sees DYLD_INSERT_LIBRARIES in its environment. This is
// what unblocks darwin-net's DNS shim and what /usr/bin/sandbox-exec would break.
func TestIntegrationDYLDPreserved(t *testing.T) {
	shim := buildExecShim(t)
	posture, work := podVolume(t, "pod-dyld")

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

	profile := genProfile(t, posture, work, "/private/tmp", "/private/var/folders", work)
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

// firstLANIPv4 returns the first non-loopback IPv4 address on an up interface, or
// "" when the host has none (an unplugged, wifi-off Mac is a legitimate state, not
// a failure). Point-to-point and link-local addresses are skipped: a utun tunnel
// or a 169.254 self-assigned address is not the LAN address the claim is about.
func firstLANIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			t.Logf("LAN address: %s on %s", ip, ifi.Name)
			return ip.String()
		}
	}
	return ""
}

// TestLocalPortDenyBlocksLANConnect discharges the reach half of the
// denied_local_ports claim. network.go and sbpl.go both state that because macOS
// Seatbelt admits only `localhost` or `*` as a filter host, a
// (deny network-outbound (remote ip "localhost:<port>")) denies that port on EVERY
// address the host owns — loopback, the lo0-aliased pod addresses, and the LAN
// address alike. Until this test the claim was proven only at 127.0.0.1 and ::1
// (TestLocalPortDenyBlocksLoopbackConnect), and "localhost matches the LAN
// address" is the surprising half: it is what makes the deny a real same-host
// defence rather than a loopback-only one, and it is also what makes it overreach
// (a Service that reused the port number is unreachable from a confined pod too).
// A comment asserting a Seatbelt matching rule that nothing exercises is a comment
// that can quietly become false under an OS update.
//
// It lives behind the integration tag, the package's convention for tests that
// depend on real OS surface, because it dials a real address on the real network
// and its outcome can be decided by host state no unit test should be subject to —
// an interface that went down, or the macOS application firewall. Those states are
// SKIPS with a named cause, never passes: a test that "passes" because nothing
// answered would be asserting the claim from silence. The only failure is the one
// that matters — a CONNECT to the denied port, which would mean the claim is false
// and both comments must be corrected rather than the code.
func TestLocalPortDenyBlocksLANConnect(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	bin := buildTCPConnecter(t)
	host := firstLANIPv4(t)
	if host == "" {
		t.Skip("no non-loopback IPv4 interface address on this host")
	}

	portA, portB, closeAll := listenTCPPair(t, "tcp4", host)
	defer closeAll()
	sb, prof := portDenyProfile(t, portA, filepath.Dir(bin))

	// The denied port at the LAN address. EPERM is the claim holding: the filter
	// named `localhost` and the sandbox applied it to an address that is not
	// loopback at all.
	outA, errA := dialUnderProfile(t, sb, bin, host, portA)
	switch {
	case outA == "CONNECTED":
		t.Fatalf("the localhost port deny did NOT reach the LAN address %s:%d — "+
			"the deny is loopback-only and the reach claim in network.go/sbpl.go is FALSE "+
			"(correct the comments, not this test)\n--- profile ---\n%s", host, portA, prof)
	case outA == "TIMEOUT":
		t.Skipf("dial to %s:%d timed out rather than being answered — inconclusive; "+
			"the macOS application firewall blocking inbound connections to the test "+
			"process is the usual cause", host, portA)
	case strings.HasPrefix(outA, "DENIED:EPERM"):
		// The verdict this test exists to record.
	default:
		t.Fatalf("dial to the denied LAN port %s:%d gave no usable verdict: %q (%v)\n--- profile ---\n%s",
			host, portA, outA, errA, prof)
	}

	// A second, UNDENIED port on the same LAN address, under the same profile:
	// without this, a profile that simply broke all outbound would "prove" the
	// claim.
	outB, errB := dialUnderProfile(t, sb, bin, host, portB)
	switch {
	case outB == "CONNECTED":
	case outB == "TIMEOUT":
		t.Skipf("the control dial to the undenied port %s:%d timed out — inconclusive "+
			"(application firewall?); the deny verdict above is unusable without it", host, portB)
	default:
		t.Fatalf("the UNDENIED port %s:%d did not connect: %q (%v) — the profile broke "+
			"outbound networking wholesale, so the deny verdict proves nothing\n--- profile ---\n%s",
			host, portB, outB, errB, prof)
	}
	t.Logf("LAN %s: denied port %d %s, undenied port %d %s", host, portA, outA, portB, outB)
}
