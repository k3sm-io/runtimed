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

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestNativeProfileAllowsOwnPosixSemaphores applies the generated profiles of
// two pods, A and B, to child helper processes (sandbox_init inside the child,
// never a nested sandbox-exec) and measures what each may do with POSIX named
// semaphores:
//
//   - A creates, posts, waits on and unlinks a semaphore under its own prefix;
//   - A cannot open or unlink a semaphore B created under B's prefix (EPERM);
//   - A's unprefixed "/mp-..." is EPERM without the path-rebase shim, and with
//     the shim it is created under A's prefix (an unconfined unlink of the
//     prefixed name finds it);
//   - with the shim, a name spelled with B's prefix still lands under A's, so
//     B's semaphore is untouched;
//   - both profiles still begin with (deny default) and import system.sb.
//
// Red before the grant existed: A's own create was EPERM like every other name.
func TestNativeProfileAllowsOwnPosixSemaphores(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("SKIP: clang not on PATH, the semaphore helper cannot be built: %v", err)
	}
	if !posixSemGrammarAccepted() {
		t.Fatal("this host's libsandbox does not compile the semaphore stanza; Generate would emit no grant")
	}
	helper := filepath.Join(t.TempDir(), "semhelper")
	if out, err := exec.Command(clang, "-o", helper, filepath.Join("testdata", "semhelper.c")).CombinedOutput(); err != nil {
		t.Fatalf("build semhelper: %v\n%s", err, out)
	}
	shim := buildSemTestShim(t)

	uidA, uidB := randomPodUID(t), randomPodUID(t)
	profA, prefixA := semPodProfile(t, uidA)
	profB, prefixB := semPodProfile(t, uidB)
	for name, prof := range map[string]string{"A": profA, "B": profB} {
		if err := Validate(prof); err != nil {
			t.Fatalf("pod %s profile: %v", name, err)
		}
		if first := firstDirectives(prof, 3); first != "(version 1)|(deny default)|(import \"system.sb\")" {
			t.Fatalf("pod %s profile does not start with (deny default) + system.sb: %s", name, first)
		}
	}
	tag := randomHex(t, 3)
	shimEnv := []string{"DYLD_INSERT_LIBRARIES=" + shim, "K3SM_SEM_PREFIX=" + prefixA}

	run := func(profile string, env []string, op, name string) string {
		t.Helper()
		pf := "-"
		if profile != "" {
			pf = filepath.Join(t.TempDir(), "profile.sb")
			if err := os.WriteFile(pf, []byte(profile), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(helper, pf, op, name)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("semhelper %s %s: %v\n%s", op, name, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	const ok, eperm = "ok", "err 1"
	expect := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %q, want %q", what, got, want)
		}
	}

	expect("A create/post/wait/close/unlink under its own prefix", run(profA, nil, "cycle", prefixA+"own"+tag), ok)

	bName := prefixB + "b" + tag
	expect("B creates under its own prefix", run(profB, nil, "create", bName), ok)
	t.Cleanup(func() { run("", nil, "unlink", bName) })
	expect("A opens B's semaphore", run(profA, nil, "open", bName), eperm)
	expect("A unlinks B's semaphore", run(profA, nil, "unlink", bName), eperm)

	mp := "/mp-" + tag
	expect("A creates unprefixed "+mp+" without the shim", run(profA, nil, "create", mp), eperm)
	expect("A creates unprefixed "+mp+" with the shim", run(profA, shimEnv, "create", mp), ok)
	expect("the shim's "+mp+" landed under A's prefix", run("", nil, "unlink", prefixA+"mp-"+tag), ok)

	// A name too long for the prefix is hashed after the same leading '/' the
	// short path drops, so the slash and slash-less spellings meet.
	long := "a-semaphore-name-longer-than-fifteen-" + tag
	expect("A, with the shim, creates long /"+long, run(profA, shimEnv, "create", "/"+long), ok)
	expect("A, with the shim, opens long "+long+" without the slash", run(profA, shimEnv, "open", long), ok)
	expect("A, with the shim, unlinks long "+long+" without the slash", run(profA, shimEnv, "unlink", long), ok)

	// The shim moves the name under A's prefix, where nothing exists: ENOENT.
	expect("A, with the shim, opens a name spelled with B's prefix", run(profA, shimEnv, "open", bName), "err 2")
	expect("B's semaphore is still there", run("", nil, "open", bName), ok)
}

// semPodProfile generates the profile of the pod with uid under a fresh
// work-dir and returns it with the pod's semaphore prefix.
func semPodProfile(t *testing.T, uid string) (string, string) {
	t.Helper()
	workDir := t.TempDir()
	dataVol := filepath.Join(workDir, "pods", uid, "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol},
		GenerateOptions{Posture: Posture{WorkDir: workDir, PodLogsDir: "/var/log/pods"}, PodUID: uid})
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := PosixSemPrefix(uid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, fmt.Sprintf("(allow ipc-posix-sem (ipc-posix-name-prefix %q))", prefix)) {
		t.Fatalf("profile for pod %s carries no semaphore grant for %s:\n%s", uid, prefix, prof)
	}
	return prof, prefix
}

// buildSemTestShim builds the path-rebase shim with hack/build-pathshim.sh.
func buildSemTestShim(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-pathshim.sh"), outDir)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-pathshim.sh: %v\n%s", err, out)
	}
	return filepath.Join(outDir, "libk3sm_pathrebase_shim.dylib")
}

// firstDirectives joins the first n non-comment lines of profile with "|".
func firstDirectives(profile string, n int) string {
	var out []string
	for _, l := range strings.Split(profile, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, ";") {
			continue
		}
		if out = append(out, l); len(out) == n {
			break
		}
	}
	return strings.Join(out, "|")
}

// randomPodUID returns a fresh UUID-shaped pod UID, so a rerun never meets a
// semaphore an earlier run left behind.
func randomPodUID(t *testing.T) string {
	t.Helper()
	h := randomHex(t, 16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
