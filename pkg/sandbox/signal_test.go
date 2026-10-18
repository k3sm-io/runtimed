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
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// signalHelperGo is the pod helper TestNativeProfileAllowsSignalsWithinPod runs.
// It confines ITSELF with sandbox_apply (the private libsandbox SPI the exec
// shim uses), so the profile is applied in a child of the test and never by a
// nested sandbox-exec. Modes:
//
//	idle <profile>        confine, print READY, sleep (pod B)
//	sleep                 sleep (a child, inheriting the confinement)
//	setsid-sleep          setsid(2), print READY, sleep (leaves the group)
//	setpgid-sleep         setpgid(0, 0), print READY, sleep (leaves the group)
//	orphaner <self>       start a sleeping child in its group, print its pid,
//	                      exit (the child is orphaned to launchd, still in
//	                      the group)
//	spawner <self>        start a pgrp grandchild and a setsid'd grandchild,
//	                      print "<g1> <g2>", sleep
//	pod <profile> <b> <h> confine, start a child, a spawner, two children
//	                      that leave the group and an orphan, print PIDS,
//	                      then one "<case> <verdict>" line per kill(2)
const signalHelperGo = `package main

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>
extern void *sandbox_compile_string(const char *data, void *params, char **error);
extern int sandbox_apply(void *profile);
static int k3sm_apply(const char *p) {
	char *err = NULL;
	void *h = sandbox_compile_string(p, NULL, &err);
	if (h == NULL) return 1;
	return sandbox_apply(h) == 0 ? 0 : 2;
}
*/
import "C"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func confine(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("FATAL read", err)
		os.Exit(2)
	}
	p := C.CString(string(b))
	defer C.free(unsafe.Pointer(p))
	if rc := C.k3sm_apply(p); rc != 0 {
		fmt.Println("FATAL apply", int(rc))
		os.Exit(2)
	}
}

func verdict(err error) string {
	switch {
	case err == nil:
		return "OK"
	case errors.Is(err, syscall.EPERM):
		return "EPERM"
	default:
		return "ERR:" + err.Error()
	}
}

func start(args ...string) (*exec.Cmd, *bufio.Reader) {
	c := exec.Command(args[0], args[1:]...)
	out, err := c.StdoutPipe()
	if err != nil {
		fmt.Println("FATAL pipe", err)
		os.Exit(2)
	}
	if err := c.Start(); err != nil {
		fmt.Println("FATAL start", err)
		os.Exit(2)
	}
	return c, bufio.NewReader(out)
}

func line(r *bufio.Reader) string {
	s, err := r.ReadString('\n')
	if err != nil {
		fmt.Println("FATAL readline", err)
		os.Exit(2)
	}
	return strings.TrimSpace(s)
}

func main() {
	switch os.Args[1] {
	case "idle":
		confine(os.Args[2])
		fmt.Println("READY")
	case "sleep":
	case "setsid-sleep":
		if _, err := syscall.Setsid(); err != nil {
			fmt.Println("FATAL setsid", err)
			os.Exit(2)
		}
		fmt.Println("READY")
	case "setpgid-sleep":
		if err := syscall.Setpgid(0, 0); err != nil {
			fmt.Println("FATAL setpgid", err)
			os.Exit(2)
		}
		fmt.Println("READY")
	case "orphaner":
		g, _ := start(os.Args[2], "sleep")
		fmt.Println(g.Process.Pid)
		os.Exit(0)
	case "spawner":
		g1, _ := start(os.Args[2], "sleep")
		g2, r := start(os.Args[2], "setsid-sleep")
		if s := line(r); s != "READY" {
			fmt.Println("FATAL", s)
			os.Exit(2)
		}
		fmt.Println(g1.Process.Pid, g2.Process.Pid)
	case "pod":
		confine(os.Args[2])
		b, _ := strconv.Atoi(os.Args[3])
		h, _ := strconv.Atoi(os.Args[4])
		child, _ := start(os.Args[0], "sleep")
		sp, r := start(os.Args[0], "spawner", os.Args[0])
		f := strings.Fields(line(r))
		if len(f) != 2 {
			fmt.Println("FATAL spawner", f)
			os.Exit(2)
		}
		g1, _ := strconv.Atoi(f[0])
		g2, _ := strconv.Atoi(f[1])
		sid, rs := start(os.Args[0], "setsid-sleep")
		if s := line(rs); s != "READY" {
			fmt.Println("FATAL", s)
			os.Exit(2)
		}
		pgid, rp := start(os.Args[0], "setpgid-sleep")
		if s := line(rp); s != "READY" {
			fmt.Println("FATAL", s)
			os.Exit(2)
		}
		// The orphaner has exited and been reaped once Wait returns, so its
		// child has been reparented to launchd and is no longer a descendant
		// of this process; it is still in this process's group.
		orph, ro := start(os.Args[0], "orphaner", os.Args[0])
		orphan, err := strconv.Atoi(line(ro))
		if err != nil {
			fmt.Println("FATAL orphaner", err)
			os.Exit(2)
		}
		_ = orph.Wait()
		fmt.Println("PIDS", child.Process.Pid, sp.Process.Pid, g1, g2, sid.Process.Pid, pgid.Process.Pid, orphan)
		fmt.Println("setsid-child-term", verdict(syscall.Kill(sid.Process.Pid, syscall.SIGTERM)))
		fmt.Println("setpgid-child-term", verdict(syscall.Kill(pgid.Process.Pid, syscall.SIGTERM)))
		fmt.Println("orphan-in-group-term", verdict(syscall.Kill(orphan, syscall.SIGTERM)))
		fmt.Println("setsid-grandchild-term", verdict(syscall.Kill(g2, syscall.SIGTERM)))
		fmt.Println("pgrp-grandchild-term", verdict(syscall.Kill(g1, syscall.SIGTERM)))
		fmt.Println("own-child-term", verdict(syscall.Kill(child.Process.Pid, syscall.SIGTERM)))
		fmt.Println("other-pod-zero", verdict(syscall.Kill(b, 0)))
		fmt.Println("other-pod-term", verdict(syscall.Kill(b, syscall.SIGTERM)))
		fmt.Println("host-zero", verdict(syscall.Kill(h, 0)))
		fmt.Println("DONE")
		os.Exit(0)
	}
	time.Sleep(time.Hour)
}
`

// TestNativeProfileAllowsSignalsWithinPod pins the native pod profile's signal
// scope by effect. Two pods, A and B, run the same generated profile, each a
// session leader (SETSID, as the supervisor spawns a pod) that confined itself.
// In A, SIGTERM is delivered to: its own child; a grandchild still in its
// process group; a direct child that left the group with setsid(2) or
// setpgid(2) ((target children) still matches); and an orphan reparented to
// launchd that stayed in the group ((target pgrp) still matches). A grandchild
// that called setsid(2) is out of reach (the documented ceiling), and B's helper
// and an unconfined host process under the same uid cannot be signalled, not
// even with signal 0.
func TestNativeProfileAllowsSignalsWithinPod(t *testing.T) {
	workDir, err := os.MkdirTemp("/tmp", "sg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	binDir := filepath.Join(workDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prof, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs"),
		ExtraReadPaths: []string{binDir},
	}, GenerateOptions{Posture: Posture{WorkDir: workDir}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Validate(prof); err != nil {
		t.Fatalf("the profile is not fail-closed: %v", err)
	}
	for _, l := range strings.Split(prof, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, ";;") || !strings.Contains(l, "signal") {
			continue
		}
		if l != "(allow signal (target children))" && l != "(allow signal (target pgrp))" {
			t.Errorf("signal rule %q: only (target children) and (target pgrp) are allowed", l)
		}
	}
	for _, want := range []string{"(allow signal (target children))", "(allow signal (target pgrp))"} {
		if !containsDirective(prof, want) {
			t.Errorf("the profile lacks %s", want)
		}
	}

	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt is darwin-only")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the helper")
	}
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(src, []byte(signalHelperGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "sighelper")
	build := exec.Command(goTool, "build", "-o", bin, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	sb := filepath.Join(workDir, "pod.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}

	// Every process this test starts or learns of is SIGKILLed at the end, and
	// only then are the direct children reaped (a Wait before the kill would
	// block on a helper that sleeps).
	var cleanup []int
	var started []*exec.Cmd
	t.Cleanup(func() {
		for _, pid := range cleanup {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		for _, c := range started {
			_ = c.Wait()
		}
	})
	startSetsid := func(args ...string) (*exec.Cmd, *bufio.Reader) {
		t.Helper()
		c := exec.Command(args[0], args[1:]...)
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		c.Stderr = os.Stderr
		out, err := c.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cleanup = append(cleanup, c.Process.Pid)
		started = append(started, c)
		return c, bufio.NewReader(out)
	}
	readLine := func(r *bufio.Reader) string {
		t.Helper()
		type res struct {
			s   string
			err error
		}
		ch := make(chan res, 1)
		go func() { s, err := r.ReadString('\n'); ch <- res{strings.TrimSpace(s), err} }()
		select {
		case got := <-ch:
			if got.err != nil {
				t.Fatalf("helper output ended: %v (last %q)", got.err, got.s)
			}
			return got.s
		case <-time.After(30 * time.Second):
			t.Fatal("helper did not answer in 30 s")
		}
		return ""
	}

	host := exec.Command("/bin/sleep", "60")
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	cleanup = append(cleanup, host.Process.Pid)
	started = append(started, host)

	podB, rb := startSetsid(bin, "idle", sb)
	if got := readLine(rb); got != "READY" {
		t.Fatalf("pod B: %q, want READY", got)
	}
	_, ra := startSetsid(bin, "pod", sb, strconv.Itoa(podB.Process.Pid), strconv.Itoa(host.Process.Pid))
	pids := strings.Fields(readLine(ra))
	if len(pids) != 8 || pids[0] != "PIDS" {
		t.Fatalf("pod A: %q, want PIDS <child> <spawner> <g1> <g2> <setsid child> <setpgid child> <orphan>", strings.Join(pids, " "))
	}
	for _, p := range pids[1:] {
		pid, err := strconv.Atoi(p)
		if err != nil {
			t.Fatal(err)
		}
		cleanup = append(cleanup, pid)
	}
	got := map[string]string{}
	for {
		l := readLine(ra)
		if l == "DONE" {
			break
		}
		f := strings.Fields(l)
		if len(f) != 2 {
			t.Fatalf("pod A: %q", l)
		}
		got[f[0]] = f[1]
	}
	for _, c := range []struct{ name, want, what string }{
		{"own-child-term", "OK", "SIGTERM to its own child"},
		{"pgrp-grandchild-term", "OK", "SIGTERM to a grandchild still in its process group"},
		{"setsid-child-term", "OK", "SIGTERM to its own direct child that called setsid (children still matches)"},
		{"setpgid-child-term", "OK", "SIGTERM to its own direct child that called setpgid (children still matches)"},
		{"orphan-in-group-term", "OK", "SIGTERM to an orphan reparented to launchd that is still in its group (pgrp still matches)"},
		{"setsid-grandchild-term", "EPERM", "SIGTERM to its own grandchild that left the group with setsid (the ceiling)"},
		{"other-pod-term", "EPERM", "SIGTERM to another pod's helper"},
		{"other-pod-zero", "EPERM", "signal 0 to another pod's helper"},
		{"host-zero", "EPERM", "signal 0 to an unconfined host process under the same uid"},
	} {
		if got[c.name] != c.want {
			t.Errorf("pod A, %s: %q, want %s", c.what, got[c.name], c.want)
		}
	}
	if t.Failed() {
		t.Logf("--- profile ---\n%s", prof)
	}
}
