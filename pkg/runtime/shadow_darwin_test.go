//go:build darwin

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

package runtime

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"
)

// shellRun is what one TestShadowShellIsNotRestricted child reported.
type shellRun struct {
	flags uint32
	out   string
}

// runHeldShell starts path with argv and env, reads the child's csflags while
// it is blocked on stdin (os/exec returns from Start only after the exec
// succeeded, so the flags are the shell's own), then releases it and collects
// its output.
func runHeldShell(t *testing.T, path string, argv, env []string) shellRun {
	t.Helper()
	cmd := &exec.Cmd{Path: path, Args: argv, Env: env}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}
	flags, cerr := supervisor.CodeSignStatus(cmd.Process.Pid)
	_, _ = io.WriteString(stdin, "go\n")
	_ = stdin.Close()
	werr := cmd.Wait()
	if cerr != nil {
		t.Fatalf("csops on %s (pid %d): %v", path, cmd.Process.Pid, cerr)
	}
	if werr != nil {
		t.Fatalf("%s exited: %v\n%s", path, werr, out.String())
	}
	return shellRun{flags: flags, out: out.String()}
}

// cloneSigned clones src into dir/name (APFS clone) and ad-hoc signs it with
// image.AdHocSign, exactly as the installer makes the shadow set.
func cloneSigned(t *testing.T, src, dst string) {
	t.Helper()
	if out, err := exec.Command("cp", "-c", src, dst).CombinedOutput(); err != nil {
		t.Skipf("SKIP: cannot clone %s (needs APFS): %v\n%s", src, err, out)
	}
	if err := image.AdHocSign(context.Background(), dst); err != nil {
		t.Fatalf("ad-hoc sign %s: %v", dst, err)
	}
}

// installedShadowDir is where the node installer puts the shadow set. Tests
// that need a copy the interposer will TRUST (root-owned, not group/other
// writable) use it when it is present and skip otherwise: a unit test cannot
// create root-owned files.
const installedShadowDir = "/Library/k3sm/shadow"

// requireTrustedShadowSet skips unless the installed shadow set passes the
// same check the interposer applies.
func requireTrustedShadowSet(t *testing.T) {
	t.Helper()
	for _, n := range []string{"bash", "env"} {
		if err := verifyShadow(installedShadowDir, filepath.Join(installedShadowDir, n), lstatShadow); err != nil {
			t.Skipf("SKIP: no trusted installed shadow set (run sudo k3sm install): %v", err)
		}
	}
}

// TestShadowShellIsNotRestricted is the B243 gate for the re-signed shell
// copies. It clones /bin/bash and /usr/bin/env the way the installer does
// (cp -c + image.AdHocSign), runs the pod shape "sh -c '...'" through
// shadowRewrite with the built path shim inserted, and asserts:
//
//   - the shell's own csflags carry neither CS_PLATFORM_BINARY nor
//     CS_RESTRICT, so dyld keeps DYLD_INSERT_LIBRARIES in it;
//   - it runs as sh (bash in POSIX mode);
//   - the environment its child prints still carries DYLD_INSERT_LIBRARIES
//     (the shell execs the env copy: bash passed the variable on).
//
// Two interposer properties are pinned live beside it: a set the interposer
// does not trust (this test's own, user-owned) is NOT redirected to, so the
// shell's "exec /usr/bin/env" reaches the platform env and loses the
// variable; and, where the installed set is present and trusted, the same
// exec IS redirected and keeps it. The contrast runs the command through the
// real /bin/sh: restricted flags, and the variable gone.
func TestShadowShellIsNotRestricted(t *testing.T) {
	// csops on this very process cannot fail on a darwin+cgo build; an error
	// here is the non-cgo stub, where there is nothing to measure.
	if _, err := supervisor.CodeSignStatus(os.Getpid()); err != nil {
		t.Skipf("SKIP: csops is unavailable in this build: %v", err)
	}
	shim := buildPathShim(t)
	dir := t.TempDir()
	cloneSigned(t, "/bin/bash", filepath.Join(dir, "bash"))
	cloneSigned(t, "/usr/bin/env", filepath.Join(dir, "env"))
	env := []string{
		"PATH=/usr/bin:/bin",
		dyldInsertEnv + "=" + shim,
		shadowDirEnv + "=" + dir,
	}
	const posix = "read _; case \":$SHELLOPTS:\" in *:posix:*) echo SHELL=POSIX;; esac; "
	shell := func(t *testing.T, sdir, execTail string) (shadowExec, shellRun, []string) {
		argv := []string{"/bin/sh", "-c", posix + execTail}
		sx, ok := shadowRewrite("/bin/sh", argv, execRewrite{dir: sdir, readHead: readShebangHead})
		if !ok || sx.path != filepath.Join(sdir, "bash") {
			t.Fatalf("shadowRewrite(/bin/sh) = %+v, %v; want the bash copy", sx, ok)
		}
		e := append([]string{}, env...)
		e[2] = shadowDirEnv + "=" + sdir
		return sx, runHeldShell(t, sx.path, sx.argv, e), argv
	}

	_, shadow, argv := shell(t, dir, "exec "+filepath.Join(dir, "env"))
	if bits := restrictedFlags(shadow.flags); bits != "" {
		t.Errorf("the re-signed shell is restricted (%s, csflags %#x): dyld will scrub DYLD_*", bits, shadow.flags)
	}
	if !strings.Contains(shadow.out, "SHELL=POSIX") {
		t.Errorf("the copy did not run as sh (POSIX mode); output:\n%s", shadow.out)
	}
	if !strings.Contains(shadow.out, dyldInsertEnv+"="+shim) {
		t.Errorf("the child's environment lost %s through the shadow shell; output:\n%s", dyldInsertEnv, shadow.out)
	}

	t.Run("an untrusted set is not redirected to", func(t *testing.T) {
		_, run, _ := shell(t, dir, "exec /usr/bin/env")
		if strings.Contains(run.out, dyldInsertEnv+"=") {
			t.Errorf("the interposer redirected /usr/bin/env into a user-owned set; output:\n%s", run.out)
		}
	})

	t.Run("a trusted set is redirected to", func(t *testing.T) {
		requireTrustedShadowSet(t)
		_, run, _ := shell(t, installedShadowDir, "exec /usr/bin/env")
		if !strings.Contains(run.out, dyldInsertEnv+"="+shim) {
			t.Errorf("exec /usr/bin/env through the trusted set lost %s; output:\n%s", dyldInsertEnv, run.out)
		}
	})

	host := runHeldShell(t, "/bin/sh", argv, env)
	if restrictedFlags(host.flags) == "" {
		t.Errorf("contrast: the host /bin/sh reports csflags %#x, neither platform nor restrict; the premise of the rewrite no longer holds", host.flags)
	}
	if strings.Contains(host.out, dyldInsertEnv+"=") {
		t.Errorf("contrast: the host /bin/sh kept %s; the scrub this works around is gone:\n%s", dyldInsertEnv, host.out)
	}
}

// TestGoCallerExecIsInterposed proves a Go-built caller's execve (Go reaches
// libSystem through its own trampolines, not a C call site) is interposed like
// a C caller's: that is how the exec-shim and every Go workload in a pod reach
// the rewrite. A helper built at test time execs, with the built shim in
// DYLD_INSERT_LIBRARIES:
//
//   - a path under a mount prefix, which exists only as its materialized copy
//     under the rootfs: it runs, so the target was rebased inside Go's execve
//     (and, as the contrast, fails without the shim);
//   - where a trusted installed shadow set exists, /bin/sh -c 'exec
//     /usr/bin/env', which must keep DYLD_INSERT_LIBRARIES.
func TestGoCallerExecIsInterposed(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("SKIP: no go toolchain on PATH to build the caller: %v", err)
	}
	shim := buildPathShim(t)
	src := t.TempDir()
	files := map[string]string{
		"go.mod":  "module execcaller\n\ngo 1.26\n",
		"main.go": "package main\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nfunc main() {\n\terr := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())\n\tos.Stderr.WriteString(\"exec: \" + err.Error() + \"\\n\")\n\tos.Exit(127)\n}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	caller := filepath.Join(t.TempDir(), "execcaller")
	build := exec.Command("go", "build", "-o", caller, ".")
	build.Dir = src
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the Go caller: %v\n%s", err, out)
	}

	t.Run("mounted target is rebased", func(t *testing.T) {
		const mount = "/k3sm-b243-test-mount"
		rootfs := t.TempDir()
		tool := filepath.Join(rootfs, mount, "tool.sh")
		if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tool, []byte("#!/bin/sh\necho REBASED\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		run := func(withShim bool) (string, error) {
			cmd := exec.Command(caller, mount+"/tool.sh")
			cmd.Env = []string{"PATH=/usr/bin:/bin", pathShimRootfsEnv + "=" + rootfs, pathShimMountsEnv + "=" + mount}
			if withShim {
				cmd.Env = append(cmd.Env, dyldInsertEnv+"="+shim)
			}
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		if out, err := run(true); err != nil || !strings.Contains(out, "REBASED") {
			t.Errorf("Go execve of a mounted path was not rebased by the interposer: %v\n%s", err, out)
		}
		if out, err := run(false); err == nil {
			t.Errorf("contrast: without the shim the mounted path ran anyway (the test proves nothing):\n%s", out)
		}
	})

	t.Run("sh -c exec env keeps DYLD through a trusted set", func(t *testing.T) {
		requireTrustedShadowSet(t)
		cmd := exec.Command(caller, "/bin/sh", "-c", "exec /usr/bin/env")
		cmd.Env = []string{"PATH=/usr/bin:/bin", dyldInsertEnv + "=" + shim, shadowDirEnv + "=" + installedShadowDir}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Go caller: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), dyldInsertEnv+"="+shim) {
			t.Errorf("%s did not survive a Go caller's /bin/sh -c 'exec /usr/bin/env':\n%s", dyldInsertEnv, out)
		}
	})
}
