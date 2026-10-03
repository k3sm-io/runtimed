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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// unixConnecterGo dials a unix socket and prints a verdict, the AF_UNIX twin of
// tcpConnecterGo (built for the same reason: a compiled binary in a directory the
// profile reads, never a host interpreter the profile may not).
const unixConnecterGo = `package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	c, err := net.Dial("unix", os.Args[1])
	if err == nil {
		c.Close()
		fmt.Println("CONNECTED")
		os.Exit(0)
	}
	if errors.Is(err, syscall.EPERM) {
		fmt.Println("DENIED:EPERM")
		os.Exit(3)
	}
	fmt.Printf("ERR:%v\n", err)
	os.Exit(4)
}
`

// listenUnix serves path (accept-and-close) until the test ends.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

// TestShimSocketDenyBlocksPodConnect is the resident-shim socket deny's gate,
// the TestLocalPortDenyBlocksLANConnect shape over AF_UNIX: under the REAL
// generated profile of a networked pod, a connect(2) to its own container's
// shim socket and to a sibling pod's are both refused with EPERM, while a
// socket outside the shim root still connects under the same profile (without
// that control, a profile that broke unix connect wholesale would pass).
func TestShimSocketDenyBlocksPodConnect(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt is darwin-only")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the connecter")
	}
	binDir := t.TempDir()
	src := filepath.Join(binDir, "main.go")
	if err := os.WriteFile(src, []byte(unixConnecterGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "connecter")
	build := exec.Command(goTool, "build", "-o", bin, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build connecter: %v\n%s", err, out)
	}

	// A short work dir under /tmp (a firmlink, so the /private form is
	// exercised) keeps every socket path inside sun_path.
	workDir, err := os.MkdirTemp("/tmp", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	own := filepath.Join(ShimRoot(workDir), "0a1b2c3d", "shim.sock")
	sibling := filepath.Join(ShimRoot(workDir), "4e5f6a7b", "shim.sock")
	control := filepath.Join(workDir, "control.sock")
	for _, p := range []string{own, sibling, control} {
		listenUnix(t, p)
	}

	prof, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs"),
		AllowNetwork:   true,
		ExtraReadPaths: []string{binDir},
	}, GenerateOptions{Posture: Posture{WorkDir: workDir}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "pod.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	dial := func(path string) string {
		out, _ := exec.Command("/usr/bin/sandbox-exec", "-f", sb, bin, path).CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	for name, path := range map[string]string{"its own shim": own, "a sibling pod's shim": sibling} {
		if got := dial(path); got != "DENIED:EPERM" {
			t.Fatalf("a confined networked pod connecting to %s (%s): %q, want DENIED:EPERM\n--- profile ---\n%s", name, path, got, prof)
		}
	}
	if got := dial(control); got != "CONNECTED" {
		t.Fatalf("the control socket outside the shim root: %q, want CONNECTED — the profile broke unix connect wholesale, so the deny verdict proves nothing\n--- profile ---\n%s", got, prof)
	}
}

// grantRules returns the allow/deny rules of the text appended to a pod profile,
// as "<rule head> <filter>" lines, sorted.
func grantRules(t *testing.T, suffix string) []string {
	t.Helper()
	var out []string
	head := ""
	for _, line := range strings.Split(suffix, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, ";;") || line == ")":
		case strings.HasPrefix(line, "(allow ") || strings.HasPrefix(line, "(deny "):
			if i := strings.Index(line, " ("); i > 0 && strings.HasSuffix(line, "))") {
				out = append(out, line[1:i]+" "+strings.TrimSuffix(line[i+1:], ")"))
				head = ""
				continue
			}
			head = strings.TrimPrefix(line, "(")
		default:
			out = append(out, head+" "+line)
		}
	}
	sort.Strings(out)
	return out
}

// TestShimProfileIsThePodProfilePlusTheGrant pins the shim profile's shape: the
// pod profile unchanged, plus a write set of EXACTLY the exit record's two
// literals and the log literal (both firmlink forms), and no network rule.
func TestShimProfileIsThePodProfilePlusTheGrant(t *testing.T) {
	pod, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p1/rootfs", AllowNetwork: true}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := "/var/lib/k3sm/run/shim/0a1b2c3d"
	log := "/var/log/pods/ns_p1_uid/c/0.log"
	shim, err := ShimProfile(pod, ShimGrant{Dir: dir, LogPath: log})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(shim, pod) {
		t.Fatal("the shim profile does not start with the pod profile unchanged")
	}
	var writes, network []string
	for _, r := range grantRules(t, strings.TrimPrefix(shim, pod)) {
		switch {
		case strings.Contains(r, "file-write"):
			writes = append(writes, r)
		case strings.Contains(r, "network"):
			network = append(network, r)
		}
	}
	want := []string{
		`allow file-write* (literal "/private/var/lib/k3sm/run/shim/0a1b2c3d/exit.json")`,
		`allow file-write* (literal "/private/var/lib/k3sm/run/shim/0a1b2c3d/exit.json.tmp")`,
		`allow file-write* (literal "/var/lib/k3sm/run/shim/0a1b2c3d/exit.json")`,
		`allow file-write* (literal "/var/lib/k3sm/run/shim/0a1b2c3d/exit.json.tmp")`,
		`allow file-write-data (literal "/private/var/log/pods/ns_p1_uid/c/0.log")`,
		`allow file-write-data (literal "/var/log/pods/ns_p1_uid/c/0.log")`,
	}
	if strings.Join(writes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the grant's write set:\n%s\nwant exactly:\n%s", strings.Join(writes, "\n"), strings.Join(want, "\n"))
	}
	if len(network) != 0 {
		t.Fatalf("the grant carries network rules: %v", network)
	}
	if err := Validate(shim); err != nil {
		t.Fatalf("the shim profile is not fail-closed: %v", err)
	}
	for _, bad := range []ShimGrant{{Dir: "rel", LogPath: log}, {Dir: dir, LogPath: ""}, {Dir: dir + "/../x", LogPath: log}} {
		if _, err := ShimProfile(pod, bad); err == nil {
			t.Errorf("ShimProfile accepted %+v", bad)
		}
	}
	if _, err := ShimProfile("(version 1)\n(allow default)\n", ShimGrant{Dir: dir, LogPath: log}); err == nil {
		t.Error("ShimProfile extended a fail-open profile")
	}
}

// TestShimSubdirIsInsideTheDeniedRunTree pins why ShimSubdir needs no deny of its
// own in DaemonTreeSubdirs: the run tree's protected file deny already covers it.
func TestShimSubdirIsInsideTheDeniedRunTree(t *testing.T) {
	for _, wd := range []string{"", "/Users/_k3sm/k3sm"} {
		_, roots, _, err := resolvePosture(Posture{WorkDir: wd})
		if err != nil {
			t.Fatal(err)
		}
		shimRoot := ShimRoot(wd)
		covered := false
		for _, r := range roots {
			if strictlyUnder(shimRoot, r) && filepath.Base(r) == RunSubdir {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("work dir %q: shim root %s is not strictly under a denied run tree %v", wd, shimRoot, roots)
		}
	}
}
