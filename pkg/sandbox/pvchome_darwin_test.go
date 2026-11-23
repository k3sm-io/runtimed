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
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// homeLinkRule is the profile line that answers a shimless /home lookup.
const homeLinkRule = "(allow file-read-metadata (literal \"/home\"))\n"

// pvcHomeFixture is one pod with a read-write PVC mounted at /home/agent the
// way pkg/volume links it (a symlink in the data volume, target spelled in the
// /tmp firmlink form), plus another pod's PVC and rootfs as negatives.
type pvcHomeFixture struct {
	work, dataVol, pvc, otherPVC, otherPod, link, profile, sb string
}

func newPVCHomeFixture(t *testing.T) pvcHomeFixture {
	t.Helper()
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-pvch-"+strconv.Itoa(os.Getpid())+"-"+strings.ReplaceAll(t.Name(), "/", "_"))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	f := pvcHomeFixture{work: filepath.Join(base, "work")}
	f.dataVol = filepath.Join(f.work, "pods", "p1", "rootfs")
	f.otherPod = filepath.Join(f.work, "pods", "p2", "rootfs")
	f.pvc = filepath.Join(f.work, "storage", "ns", "pvc-a")
	f.otherPVC = filepath.Join(f.work, "storage", "ns", "pvc-b")
	for _, d := range []string{f.dataVol, f.otherPod, f.pvc, f.otherPVC} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(f.dataVol, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.link = filepath.Join(f.dataVol, "home", "agent")
	if err := os.Symlink(strings.TrimPrefix(f.pvc, "/private"), f.link); err != nil {
		t.Fatal(err)
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: f.dataVol}, GenerateOptions{
		Posture:    Posture{WorkDir: f.work},
		WritePaths: []string{f.pvc},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	f.profile = prof
	f.sb = filepath.Join(base, "p.sb")
	if err := os.WriteFile(f.sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// statUnder runs /usr/bin/stat on p under the profile file sb and returns
// "ok", "ENOENT", "EPERM", or the raw output.
func statUnder(t *testing.T, sb, p string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/usr/bin/stat", p).CombinedOutput()
	switch s := string(out); {
	case err == nil:
		return "ok"
	case strings.Contains(s, "No such file or directory"):
		return "ENOENT"
	case strings.Contains(s, "Operation not permitted"):
		return "EPERM"
	default:
		return strings.TrimSpace(s)
	}
}

// hostHomeAgentAbsent skips when the host's /home/agent resolves to something
// (an auto_home user named agent), which would void the ENOENT measurement.
func hostHomeAgentAbsent(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/home/agent"); !errors.Is(err, fs.ErrNotExist) {
		t.Skipf("the host's /home/agent is not absent (%v); the measurement needs it absent", err)
	}
}

// TestPVCMissingChildIsENOENT pins what a pod's lookup of a missing child of
// its own home PVC answers, in every spelling a pod process produces. A
// shimless binary (git, xcrun: platform or library-validated, so dyld never
// loads the path-rebase shim) asks for HOME=/home/agent on the host, where
// /home is a symlink Seatbelt checks as its own node. Without the /home link
// rule that was EPERM, which git treats as fatal; with it, ENOENT. Measured on
// macOS 27 before the rule: every PVC spelling below already answered ENOENT,
// and only the host /home forms answered EPERM.
func TestPVCMissingChildIsENOENT(t *testing.T) {
	hostHomeAgentAbsent(t)
	f := newPVCHomeFixture(t)
	if n := strings.Count(f.profile, homeLinkRule); n != 1 {
		t.Fatalf("profile carries the /home link rule %d times, want 1", n)
	}
	if strings.Contains(f.profile, `(subpath "/home")`) || strings.Contains(f.profile, `(subpath "/System/Volumes/Data/home")`) {
		t.Fatal("profile grants a /home subtree; only the link node may be named")
	}
	tmpForm := strings.TrimPrefix(f.pvc, "/private")
	for _, tc := range []struct{ name, path, want string }{
		{"host /home, missing leaf (shimless HOME)", "/home/agent/.gitconfig", "ENOENT"},
		{"host /home, missing nested leaf", "/home/agent/.config/git/config", "ENOENT"},
		{"rootfs link, existing child", f.link + "/f", "ok"},
		{"rootfs link, missing child", f.link + "/.gitconfig", "ENOENT"},
		{"PVC /private form, existing child", f.pvc + "/f", "ok"},
		{"PVC /private form, missing child", f.pvc + "/.gitconfig", "ENOENT"},
		{"PVC /tmp form, existing child", tmpForm + "/f", "ok"},
		{"PVC /tmp form, missing child", tmpForm + "/.config/git/config", "ENOENT"},
		{"data volume, missing child", f.dataVol + "/missing", "ENOENT"},
		// Negatives: the cross-pod boundary is unchanged.
		{"another pod's PVC, existing child", f.otherPVC + "/f", "EPERM"},
		{"another pod's rootfs, existing child", f.otherPod + "/f", "EPERM"},
		{"another pod's rootfs dir", f.otherPod, "EPERM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := statUnder(t, f.sb, tc.path); got != tc.want {
				t.Errorf("stat %s under the profile = %s, want %s", tc.path, got, tc.want)
			}
		})
	}
	// The storage root and the pods root stay unlistable.
	for _, d := range []string{filepath.Join(f.work, "storage"), filepath.Join(f.work, "pods")} {
		if err := exec.Command("/usr/bin/sandbox-exec", "-f", f.sb, "/bin/ls", d).Run(); err == nil {
			t.Errorf("ls %s under the profile succeeded; it must stay denied", d)
		}
	}
}

// TestHomeLinkRuleAddsNothingUnderTheTarget runs the same probes under the
// profile with and without the /home link rule and requires identical answers
// for every path under /System/Volumes/Data/home: the rule names the link
// node only, so what lies under its target is reached exactly as before.
func TestHomeLinkRuleAddsNothingUnderTheTarget(t *testing.T) {
	f := newPVCHomeFixture(t)
	without := filepath.Join(filepath.Dir(f.sb), "without.sb")
	if err := os.WriteFile(without, []byte(strings.Replace(f.profile, homeLinkRule, "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(sb string, args ...string) string {
		out, err := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, args...)...).CombinedOutput()
		return strconv.FormatBool(err == nil) + ":" + string(out)
	}
	for _, args := range [][]string{
		{"/bin/ls", "/System/Volumes/Data/home"},
		{"/usr/bin/stat", "/System/Volumes/Data/home"},
		{"/usr/bin/stat", "/System/Volumes/Data/home/agent"},
		{"/usr/bin/stat", "/System/Volumes/Data/home/agent/.gitconfig"},
	} {
		if a, b := run(f.sb, args...), run(without, args...); a != b {
			t.Errorf("%v differs with the /home link rule:\nwith:    %s\nwithout: %s", args, a, b)
		}
	}
}

// TestShimlessGitAndXcrunUnderProfile runs the platform git and xcrun under
// the profile, the binaries that never load the path-rebase shim. git with
// HOME at the pod's mount path (the host /home lookup) and with HOME at the
// rootfs link must not fail on EPERM; a missing global config is fine. xcrun
// with xcrun_db in the pod's user temp dir (what the runtime injects) must
// print no cache warning.
func TestShimlessGitAndXcrunUnderProfile(t *testing.T) {
	const devDir = "/Library/Developer/CommandLineTools"
	if _, err := os.Stat(devDir + "/usr/bin/git"); err != nil {
		t.Skipf("no Command Line Tools git at %s: %v", devDir, err)
	}
	hostHomeAgentAbsent(t)
	f := newPVCHomeFixture(t)
	tmp := filepath.Join(f.dataVol, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(env []string, args ...string) (string, error) {
		cmd := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", f.sb}, args...)...)
		cmd.Dir = f.dataVol
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "DEVELOPER_DIR=" + devDir, "TMPDIR=" + tmp}, env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// /usr/bin/git is xcrun's trampoline, so it needs xcrun_db as well.
	xcrunDB := "xcrun_db=" + filepath.Join(tmp, "xcrun_db")
	for _, tc := range []struct{ name, home string }{{"host /home", "/home/agent"}, {"rootfs link", f.link}} {
		home := tc.home
		t.Run("git config --list, HOME at the "+tc.name, func(t *testing.T) {
			out, err := run([]string{"HOME=" + home, xcrunDB}, "/usr/bin/git", "config", "--list")
			if err != nil || strings.Contains(out, "Operation not permitted") {
				t.Errorf("git config --list with HOME=%s: err=%v out=%s", home, err, out)
			}
		})
	}
	t.Run("xcrun --find clang", func(t *testing.T) {
		out, err := run([]string{"HOME=" + f.link, xcrunDB}, "/usr/bin/xcrun", "--find", "clang")
		if err != nil || strings.Contains(out, "cache file") || strings.Contains(out, "warning") {
			t.Errorf("xcrun --find clang: err=%v out=%s", err, out)
		}
	})
}

// TestHomeLinkRuleKeepsTheDigestStable pins that the /home link rule is a
// constant: the same inputs render byte-identical profiles, so a pod's
// profile compiled at create and again at re-attach has one digest.
func TestHomeLinkRuleKeepsTheDigestStable(t *testing.T) {
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p1/rootfs"}
	opts := GenerateOptions{WritePaths: []string{"/var/lib/k3sm/storage/ns/pvc-a"}}
	a, err := Generate(sp, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(sp, opts)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("two renders of the same inputs differ")
	}
	if strings.Count(a, homeLinkRule) != 1 {
		t.Fatalf("profile carries the /home link rule %d times, want 1", strings.Count(a, homeLinkRule))
	}
}
