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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func TestGenerateHostSharesRefusesUnsafePaths(t *testing.T) {
	t.Parallel()
	const work = "/var/lib/k3sm"
	dataVol := work + "/pods/p1/rootfs"
	for _, sh := range []HostShare{
		{Path: "/"},
		{Path: "relative"},
		{Path: "/Users"},
		{Path: "/Users/dev"},
		{Path: "/var/lib/k3sm"},
		{Path: "/private/var/lib/k3sm/server"},
		{Path: "/var/lib"},
		{Path: "/private/var/db/secrets"},
		{Path: dataVol},
		{Path: work + "/pods/p2/rootfs"},
		{Path: "/var/log/pods"},
		{Path: "/Users/dev/Code/a\"b"},
		{Path: "/users/dev"},
		{Path: "/USERS/dev/library/Preferences"},
		{Path: "/Users/dev/.ssh"},
		{Path: "/users/dev/Code/.git"},
		{Path: "/System/Volumes/Data/Users/dev/Code/app"},
		{Path: "/VAR/lib/k3sm"},
		{Path: "/Users/dev/Code/caf\u00e9"},
		{Path: "/Users/dev/Code/sock", Socket: true, ReadOnly: true},
	} {
		_, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
			Posture:    Posture{WorkDir: work},
			HostShares: []HostShare{sh},
		})
		if !errors.Is(err, ErrInvalidHostShare) {
			t.Errorf("Generate(share %+v) = %v, want ErrInvalidHostShare", sh, err)
		}
	}
}

func TestGenerateHostSharesRenderAfterTheUsersDeny(t *testing.T) {
	t.Parallel()
	const work = "/var/lib/k3sm"
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: work + "/pods/p1/rootfs"}, GenerateOptions{
		Posture: Posture{WorkDir: work},
		HostShares: []HostShare{
			{Path: "/Users/dev/Code/app"},
			{Path: "/Users/dev/Code/app.lanes"},
			{Path: "/Volumes/data", ReadOnly: true},
			{Path: "/Users/dev/Code/app/run/q.sock", Socket: true},
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	usersDeny := strings.Index(prof, "(subpath \"/Users\"))")
	rw := strings.Index(prof, "(subpath \"/Users/dev/Code/app\")")
	if usersDeny < 0 || rw < 0 || rw < usersDeny {
		t.Fatalf("the read-write share must render after the /Users deny (deny at %d, share at %d):\n%s", usersDeny, rw, prof)
	}
	for _, want := range []string{
		"(subpath \"/Users/dev/Code/app.lanes\")",
		"(deny file-write*\n  (subpath \"/Volumes/data\")",
		"(remote unix-socket (literal \"/Users/dev/Code/app/run/q.sock\"))",
		"(literal \"/Users/dev\")",
		"(literal \"/Users/dev/Code\")",
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile lacks %q", want)
		}
	}
	// The home and /Users get metadata only, never a subtree grant.
	if strings.Contains(prof, "(subpath \"/Users/dev\")") {
		t.Error("profile grants the whole home")
	}
	if err := Validate(prof); err != nil {
		t.Errorf("Validate: %v", err)
	}
	// No shares: no stanza, so every existing profile is unchanged.
	plain, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: work + "/pods/p1/rootfs"}, GenerateOptions{Posture: Posture{WorkDir: work}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "host shares") {
		t.Error("a profile with no shares carries the host share stanza")
	}
}

// TestHostShareUnderSandboxExec runs real processes under the generated
// profile. A read-write share outside the protected trees can be written and
// a read-only one only read; a sibling directory stays denied; a socket share
// can be connected to and its neighbour cannot. When the test's working
// directory is under /Users (a checkout in a home), the same is shown for a
// share there, which is the case the stanza exists for: the /Users deny holds
// everywhere except the shared directory.
func TestHostShareUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/private/tmp", "k3sm-hs-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	rwDir := filepath.Join(base, "rw")
	roDir := filepath.Join(base, "ro")
	other := filepath.Join(base, "other")
	for _, d := range []string{dataVol, rwDir, roDir, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(roDir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(base, "q.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	otherSock := filepath.Join(base, "other.sock")
	ln2, err := net.Listen("unix", otherSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	shares := []HostShare{{Path: rwDir}, {Path: roDir, ReadOnly: true}, {Path: sockPath, Socket: true}}
	var usersShare, usersSibling string
	if wd, err := os.Getwd(); err == nil {
		if rwd, err := filepath.EvalSymlinks(wd); err == nil && strings.HasPrefix(rwd, "/Users/") && len(strings.Split(rwd, "/")) > 3 {
			d, err := os.MkdirTemp(rwd, "hostshare-test-")
			if err == nil {
				t.Cleanup(func() { _ = os.RemoveAll(d) })
				usersShare = filepath.Join(d, "share")
				usersSibling = filepath.Join(d, "sibling")
				_ = os.MkdirAll(usersShare, 0o755)
				_ = os.MkdirAll(usersSibling, 0o755)
				_ = os.WriteFile(filepath.Join(usersSibling, "f"), []byte("x"), 0o644)
				shares = append(shares, HostShare{Path: usersShare})
			}
		}
	}

	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:    Posture{WorkDir: work},
		HostShares: shares,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "hs.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, argv...)...).Run()
	}
	if err := run("/usr/bin/touch", filepath.Join(rwDir, "new")); err != nil {
		t.Errorf("create in the read-write share was denied: %v", err)
	}
	if err := run("/bin/mkdir", "-p", filepath.Join(rwDir, "a", "b")); err != nil {
		t.Errorf("mkdir -p in the read-write share was denied: %v", err)
	}
	if err := run("/bin/cat", filepath.Join(roDir, "f")); err != nil {
		t.Errorf("read in the read-only share was denied: %v", err)
	}
	if err := run("/usr/bin/touch", filepath.Join(roDir, "new")); err == nil {
		t.Error("create in the read-only share was allowed")
	}
	if err := run("/bin/cat", filepath.Join(other, "f")); err == nil {
		t.Error("read of an unshared sibling directory was allowed")
	}
	nc := func(p string) error {
		// nc's -z does not apply to -U; a plain connect with stdin at
		// /dev/null (exec's default) exits 0 once the peer closes.
		return run("/usr/bin/nc", "-U", p)
	}
	if err := nc(sockPath); err != nil {
		t.Errorf("connect to the shared socket was denied: %v", err)
	}
	if err := nc(otherSock); err == nil {
		t.Error("connect to an unshared socket was allowed")
	}
	if usersShare == "" {
		t.Log("working directory is not under a home; the /Users leg did not run")
		return
	}
	if err := run("/usr/bin/touch", filepath.Join(usersShare, "new")); err != nil {
		t.Errorf("create in a share under /Users was denied: %v", err)
	}
	if err := run("/bin/ls", usersShare); err != nil {
		t.Errorf("listing a share under /Users was denied: %v", err)
	}
	if err := run("/bin/cat", filepath.Join(usersSibling, "f")); err == nil {
		t.Error("read of an unshared directory under /Users was allowed")
	}
	if err := run("/bin/ls", filepath.Dir(usersShare)); err == nil {
		t.Error("listing the share's parent under /Users was allowed")
	}
}
