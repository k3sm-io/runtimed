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

package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// cpShadowCopies are the copies this gate needs, named literally (not read
// from the shadow list) so the file compiles against a tree without the list
// and fails there on behaviour: tar for the kubectl cp round trip, cat to read
// the file back, awk and sed run once each, bash and env as the installed set
// carries them.
var cpShadowCopies = []struct{ name, src string }{
	{"bash", "/bin/bash"},
	{"env", "/usr/bin/env"},
	{"tar", "/usr/bin/bsdtar"},
	{"cat", "/bin/cat"},
	{"awk", "/usr/bin/awk"},
	{"sed", "/usr/bin/sed"},
}

// cpShadowDir returns a shadow directory the interposer and the runtime will
// TRUST (root-owned, no group/other write, a directory and regular files).
// As root it builds one under root exactly as the installer does (cp -c, then
// image.AdHocSign, mode 0755). Otherwise it uses the installed set only when
// that holds a trusted tar and cat, and skips with the reason when it does
// not: a test never calls sudo, and a user cannot make root-owned files.
func cpShadowDir(t *testing.T, root string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		for _, n := range []string{"tar", "cat"} {
			if err := verifyShadow(installedShadowDir, filepath.Join(installedShadowDir, n), lstatShadow); err != nil {
				t.Skipf("SKIP: not root, and the installed shadow set has no trusted %s (run the test as root, or reinstall the node): %v", n, err)
			}
		}
		return installedShadowDir
	}
	dir := filepath.Join(root, "shadow")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // the umask must not decide it
		t.Fatal(err)
	}
	for _, c := range cpShadowCopies {
		dst := filepath.Join(dir, c.name)
		if out, err := exec.Command("cp", "-c", c.src, dst).CombinedOutput(); err != nil {
			t.Fatalf("clone %s: %v\n%s", c.src, err, out)
		}
		if err := image.AdHocSign(context.Background(), dst); err != nil {
			t.Fatalf("ad-hoc sign %s: %v", dst, err)
		}
		if err := os.Chmod(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := verifyShadow(dir, dst, lstatShadow); err != nil {
			t.Fatalf("the built copy is not trusted: %v", err)
		}
	}
	return dir
}

// tarOf returns a tar stream holding one regular file.
func tarOf(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestKubectlCpReachesARebasedPath is the gate for kubectl cp into a mounted
// path on a native pod. kubectl cp runs `tar xmf - -C <dir>` (and `tar cf -
// -C <dir> <file>` the other way) through Exec. /usr/bin/tar is a platform
// binary, so without a re-signed copy dyld drops the path-rebase shim and
// <dir> resolves to the HOST path; and bsdtar's -C is a chdir(2), so the copy
// alone is not enough unless chdir is rebased too.
//
// A native pod (main /bin/sleep) mounts a volume at an absolute path; the
// path shim is built from this tree and the pod gets a trusted shadow set.
// Through the production Exec path (the resident shim's confined session),
// with stdin:
//
//   - `tar xmf - -C <mount>` fed a tar holding hello.txt exits 0, and the
//     file lands at <rootfs><mount>/hello.txt on the host side;
//   - `cat <mount>/hello.txt` returns the bytes;
//   - `tar cf - -C <mount> hello.txt` exits 0 with a tar holding the file;
//   - awk and sed each run as their copies, under the profile, on the
//     mounted file (and awk keeps DYLD_INSERT_LIBRARIES);
//   - a `-C` that climbs out of the data volume with ".." is refused by the
//     pod profile (non-zero, nothing written): the shim only rebases, the
//     profile is the boundary.
func TestKubectlCpReachesARebasedPath(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, the path shim cannot be built: %v", err)
	}
	root := shortRoot(t)
	if err := os.Chmod(root, 0o755); err != nil { // traversable to the pod's uid
		t.Fatal(err)
	}
	shadowDir := cpShadowDir(t, root)

	shim := filepath.Join(root, sandbox.ExecShimName)
	build := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shim: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("sign shim: %v\n%s", err, out)
	}
	backend, err := sandbox.NewExecShimBackend(shim, root)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.Available() {
		t.Skip("exec-shim backend unavailable on this host")
	}

	built := buildPathShim(t)
	pathShim := filepath.Join(root, filepath.Base(built))
	if out, err := exec.Command("cp", built, pathShim).CombinedOutput(); err != nil {
		t.Fatalf("copy the path shim: %v\n%s", err, out)
	}
	if err := image.AdHocSign(context.Background(), pathShim); err != nil {
		t.Fatalf("ad-hoc sign the path shim: %v", err)
	}

	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{
		Root:           root,
		RuntimeVersion: "test",
		PodLogsDir:     filepath.Join(root, "podlogs"),
		PathShimPath:   pathShim,
		ShadowBinDir:   shadowDir,
	}, Deps{
		Cache:   cache,
		Backend: backend,
		Spawner: supervisor.PosixSpawner{},
		Waiter:  supervisor.KqueueReaper{},
		Network: supervisor.NodeNetwork{IP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	const podID = "pod-kubectlcp"
	const mount = "/k3sm-kubectl-cp/data"
	rootfs := derivedRootfs(t, rt, podID)
	box := &runtimev1.PodBox{
		PodId:        podID,
		Namespace:    "default",
		Name:         "kubectlcp",
		LogDirectory: testPodLogDir(rt, podID),
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: rootfs,
			ExtraReadPaths: []string{"/private/tmp", "/private/var/folders", root},
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{{
			Name:         "main",
			Image:        NativeImage,
			Command:      []string{"/bin/sleep", "60"},
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "data", MountPath: mount}},
		}},
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	defer func() {
		_, _ = rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID})
	}()
	waitRunning(t, rt, podID)

	// The volume's materialized directory (the node renders it before start;
	// here the test does).
	volDir := filepath.Join(rootfs, mount)
	if err := os.MkdirAll(volDir, 0o755); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, stdin []byte, cmdv ...string) (stdout []byte, stderr string, code int32) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: podID, Command: cmdv, Stdin: stdin != nil, Stdout: true, Stderr: true})
		if len(stdin) > 0 {
			st.feed(&runtimev1.ExecRequest{StdinData: stdin})
		}
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec(%v): %v", cmdv, err)
		}
		var out, errb []byte
		for {
			select {
			case r := <-st.out:
				out = append(out, r.GetStdout()...)
				errb = append(errb, r.GetStderr()...)
				if r.GetExit() != nil {
					return out, string(errb), r.GetExit().GetExitCode()
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("Exec(%v): timed out collecting output", cmdv)
			}
		}
	}

	body := []byte("hello from kubectl cp\n")
	t.Run("tar-x-into-the-mount", func(t *testing.T) {
		_, errOut, code := run(t, tarOf(t, "hello.txt", body), "tar", "xmf", "-", "-C", mount)
		if code != 0 {
			t.Fatalf("tar xmf - -C %s exit = %d, want 0 (stderr %q)", mount, code, errOut)
		}
		got, err := os.ReadFile(filepath.Join(volDir, "hello.txt"))
		if err != nil {
			t.Fatalf("the extracted file is not at <rootfs>%s/hello.txt: %v", mount, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("<rootfs>%s/hello.txt = %q, want %q", mount, got, body)
		}
	})

	t.Run("cat-reads-it-back", func(t *testing.T) {
		out, errOut, code := run(t, nil, "cat", mount+"/hello.txt")
		if code != 0 || !bytes.Equal(out, body) {
			t.Fatalf("cat %s/hello.txt = %q exit %d, want %q exit 0 (stderr %q)", mount, out, code, body, errOut)
		}
	})

	t.Run("tar-c-out-of-the-mount", func(t *testing.T) {
		out, errOut, code := run(t, nil, "tar", "cf", "-", "-C", mount, "hello.txt")
		if code != 0 {
			t.Fatalf("tar cf - -C %s hello.txt exit = %d, want 0 (stderr %q)", mount, code, errOut)
		}
		tr := tar.NewReader(bytes.NewReader(out))
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("stdout is not a tar stream: %v (%d bytes, stderr %q)", err, len(out), errOut)
		}
		got, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name != "hello.txt" || !bytes.Equal(got, body) {
			t.Fatalf("archive holds %q = %q, want hello.txt = %q", hdr.Name, got, body)
		}
		if _, err := tr.Next(); !errors.Is(err, io.EOF) {
			t.Errorf("archive holds more than hello.txt: %v", err)
		}
	})

	// awk and sed copies are arm64e ad-hoc non-platform binaries like the
	// shells: run each once under the real profile, through the pod's own
	// shell, on the mounted file. The file reaches them on stdin (the shell's
	// redirect is an open(2), rebased): their own file-operand read goes
	// through fopen(3), which the path shim does not interpose, so that form
	// would test the shim's coverage, not the copies. That the copy, not the
	// platform binary, ran is proven by the shim's restricted-child report
	// staying silent about it, and for awk by DYLD_INSERT_LIBRARIES surviving
	// into its environment (dyld scrubs it from a platform binary).
	reportName, err := supervisor.ChildReportName("main")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(rootfs, reportName)
	readReport := func(t *testing.T) []string {
		t.Helper()
		b, err := os.ReadFile(reportPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return strings.Split(string(b), "\n")
	}
	// Control: the report is live in these sessions, so its silence below
	// means something. /usr/bin/true is restricted and on no list; /bin/ls
	// is on the list, but this shadow set has no ls copy, so it really runs
	// unshimmed and must be reported like any other platform binary.
	t.Run("report-names-an-unshadowed-binary", func(t *testing.T) {
		const prog = "/usr/bin/true; /bin/ls / >/dev/null"
		if _, errOut, code := run(t, nil, "sh", "-c", prog); code != 0 {
			t.Fatalf("sh -c %q exit = %d (stderr %q)", prog, code, errOut)
		}
		got := readReport(t)
		for _, want := range []string{"/usr/bin/true", "/bin/ls"} {
			if want == "/bin/ls" && verifyShadow(shadowDir, filepath.Join(shadowDir, "ls"), lstatShadow) == nil {
				continue // an installed set may carry ls; then it is covered
			}
			if !slices.Contains(got, want) {
				t.Errorf("the restricted-child report does not name %s: %q", want, got)
			}
		}
	})
	for _, c := range []struct {
		name string
		prog string
		want string
	}{
		{"awk", "awk '{ print toupper($0) }' < " + mount + "/hello.txt", strings.ToUpper(string(body))},
		{"sed", "sed s/kubectl/k3sm/ < " + mount + "/hello.txt", strings.Replace(string(body), "kubectl", "k3sm", 1)},
	} {
		t.Run(c.name+"-reads-the-mount", func(t *testing.T) {
			if err := verifyShadow(shadowDir, filepath.Join(shadowDir, c.name), lstatShadow); err != nil {
				t.Skipf("SKIP: the shadow set has no trusted %s copy: %v", c.name, err)
			}
			out, errOut, code := run(t, nil, "sh", "-c", c.prog)
			if code != 0 || string(out) != c.want {
				t.Fatalf("sh -c %q = %q exit %d, want %q exit 0 (stderr %q)", c.prog, out, code, c.want, errOut)
			}
			report := readReport(t)
			for _, unshimmed := range []string{"/usr/bin/" + c.name, "/bin/sh"} {
				if slices.Contains(report, unshimmed) {
					t.Errorf("the shim reported %s as run unshimmed: the copy was not used (report %q)", unshimmed, report)
				}
			}
		})
	}
	t.Run("awk-copy-keeps-the-shim", func(t *testing.T) {
		if err := verifyShadow(shadowDir, filepath.Join(shadowDir, "awk"), lstatShadow); err != nil {
			t.Skipf("SKIP: the shadow set has no trusted awk copy: %v", err)
		}
		out, errOut, code := run(t, nil, "awk", `BEGIN { print ENVIRON["DYLD_INSERT_LIBRARIES"] }`)
		if code != 0 || !strings.Contains(string(out), pathShim) {
			t.Fatalf("awk saw DYLD_INSERT_LIBRARIES = %q (exit %d, stderr %q), want it to carry %s", out, code, errOut, pathShim)
		}
	})

	t.Run("dotdot-out-of-the-data-volume-is-refused", func(t *testing.T) {
		outside := filepath.Join(root, "outside")
		if err := os.Mkdir(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		from, err := filepath.EvalSymlinks(volDir)
		if err != nil {
			t.Fatal(err)
		}
		to, err := filepath.EvalSymlinks(outside)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(from, to)
		if err != nil || !strings.HasPrefix(rel, "..") {
			t.Fatalf("no .. path from %s to %s: %q %v", from, to, rel, err)
		}
		escape := mount + "/" + rel
		_, errOut, code := run(t, tarOf(t, "escaped.txt", body), "tar", "xmf", "-", "-C", escape)
		if code == 0 {
			t.Errorf("tar xmf - -C %s exit = 0, want the profile to refuse the write (stderr %q)", escape, errOut)
		}
		// The chdir itself must have succeeded (the outside directory is
		// readable): the refusal is the profile's write deny (EPERM), not a
		// path the shim failed to reach.
		if !strings.Contains(errOut, "Operation not permitted") {
			t.Errorf("tar failed for another reason than the profile's write deny: stderr %q", errOut)
		}
		if _, err := os.Lstat(filepath.Join(outside, "escaped.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a file was written outside the data volume (%v); stderr %q", err, errOut)
		}
		t.Logf("refused: exit %d, stderr %q", code, errOut)
	})
}
