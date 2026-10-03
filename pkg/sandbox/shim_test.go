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

	"k3sm.io/runtimed/pkg/execsession"
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
// pod profile unchanged, plus a grant that writes NOTHING (the shim profile's
// write set is exactly the pod profile's) and carries no network rule.
func TestShimProfileIsThePodProfilePlusTheGrant(t *testing.T) {
	pod, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p1/rootfs", AllowNetwork: true}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := "/var/lib/k3sm/run/shim/0a1b2c3d"
	shim, err := ShimProfile(pod, ShimGrant{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(shim, pod) {
		t.Fatal("the shim profile does not start with the pod profile unchanged")
	}
	got := grantRules(t, strings.TrimPrefix(shim, pod))
	want := []string{
		`allow file-ioctl (regex #"^/dev/ttys[0-9]+$")`,
		`allow file-read* (subpath "/private/var/lib/k3sm/run/shim/0a1b2c3d")`,
		`allow file-read* (subpath "/var/lib/k3sm/run/shim/0a1b2c3d")`,
		`allow signal (target children)`,
		`allow signal (target pgrp)`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the grant:\n%s\nwant exactly:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err := Validate(shim); err != nil {
		t.Fatalf("the shim profile is not fail-closed: %v", err)
	}
	for _, bad := range []ShimGrant{{Dir: "rel"}, {Dir: ""}, {Dir: dir + "/../x"}} {
		if _, err := ShimProfile(pod, bad); err == nil {
			t.Errorf("ShimProfile accepted %+v", bad)
		}
	}
	if _, err := ShimProfile("(version 1)\n(allow default)\n", ShimGrant{Dir: dir}); err == nil {
		t.Error("ShimProfile extended a fail-open profile")
	}
}

// reachProbeGo tries one operation on a path and prints a verdict.
const reachProbeGo = `package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	op, path := os.Args[1], os.Args[2]
	var err error
	switch op {
	case "openw":
		var f *os.File
		if f, err = os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
	case "openr":
		var f *os.File
		if f, err = os.Open(path); err == nil {
			f.Close()
		}
	case "openrw":
		var f *os.File
		if f, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0); err == nil {
			f.Close()
		}
	case "connect":
		var c net.Conn
		if c, err = net.Dial("unix", path); err == nil {
			c.Close()
		}
	case "unlink":
		err = os.Remove(path)
	}
	switch {
	case err == nil:
		fmt.Println("OK")
	case errors.Is(err, syscall.EPERM):
		fmt.Println("DENIED:EPERM")
	default:
		fmt.Printf("ERR:%v\n", err)
	}
}
`

// TestShimProfileReach is the exec-session-reach regression: a process under the
// shim profile — what every exec session runs under — cannot open the exit
// record or the CRI log for writing, cannot connect to or unlink either shim
// socket, and cannot open a terminal node it did not inherit, so the tty ioctl
// grant adds no reach. The read of the exit record succeeding is the control:
// the probe runs, and the grant it does carry is live.
func TestShimProfileReach(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt is darwin-only")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the probe")
	}
	binDir := t.TempDir()
	src := filepath.Join(binDir, "main.go")
	if err := os.WriteFile(src, []byte(reachProbeGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "probe")
	build := exec.Command(goTool, "build", "-o", bin, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}

	workDir, err := os.MkdirTemp("/tmp", "sr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	dir := filepath.Join(ShimRoot(workDir), "0a1b2c3d")
	sock, ptySock := filepath.Join(dir, "shim.sock"), filepath.Join(dir, "pty.sock")
	listenUnix(t, sock)
	listenUnix(t, ptySock)
	exitRec := filepath.Join(dir, "exit.json")
	logDir := filepath.Join(workDir, "logs")
	logPath := filepath.Join(logDir, "ns_p_uid", "c", "0.log")
	for _, f := range []string{exitRec, logPath} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A terminal node that exists and that the probe did not inherit.
	master, slave, err := execsession.OpenPTY()
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	pod, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs"),
		AllowNetwork:   true,
		ExtraReadPaths: []string{binDir},
	}, GenerateOptions{Posture: Posture{WorkDir: workDir, PodLogsDir: logDir}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	shim, err := ShimProfile(pod, ShimGrant{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	sb := filepath.Join(t.TempDir(), "shim.sb")
	if err := os.WriteFile(sb, []byte(shim), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(op, path string) string {
		out, _ := exec.Command("/usr/bin/sandbox-exec", "-f", sb, bin, op, path).CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	if got := run("openr", exitRec); got != "OK" {
		t.Fatalf("control: reading the exit record under the shim profile = %q, want OK\n--- profile ---\n%s", got, shim)
	}
	for _, c := range []struct{ op, path, what string }{
		{"openw", exitRec, "write the exit record"},
		{"openw", logPath, "write the CRI log"},
		{"connect", sock, "connect to shim.sock"},
		{"connect", ptySock, "connect to pty.sock"},
		{"unlink", sock, "unlink shim.sock"},
		{"unlink", ptySock, "unlink pty.sock"},
		{"openrw", slave.Name(), "open a terminal node it did not inherit"},
	} {
		if got := run(c.op, c.path); got != "DENIED:EPERM" {
			t.Errorf("a process under the shim profile could %s (%s): %q, want DENIED:EPERM", c.what, c.path, got)
		}
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
