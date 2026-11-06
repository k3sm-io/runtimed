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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Two manifests and their whole-artifact views, under the default work dir.
var (
	viewManifestA = strings.Repeat("a", 64)
	viewManifestB = strings.Repeat("b", 64)
	viewKey       = strings.Repeat("c", 64)
)

func viewPath(workDir, manifest string) string {
	return filepath.Join(workDir, ArtifactViewsSubdir, manifest, viewKey)
}

// viewProfile renders the canonical pod profile with one artifact view (model
// A's) granted.
func viewProfile(t *testing.T) string {
	t.Helper()
	got, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: "/var/lib/k3sm/pods/pod-view123/rootfs",
	}, GenerateOptions{ArtifactViewPaths: []string{viewPath(DefaultWorkDir, viewManifestA)}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return got
}

// TestArtifactViewGolden pins the whole profile of a pod with one image volume
// byte for byte, so an added rule is as red as a changed one. Run with -update
// to regenerate.
func TestArtifactViewGolden(t *testing.T) {
	got := viewProfile(t)
	goldenPath := filepath.Join("testdata", "pod-artifact-view.golden.sb")
	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("generated artifact-view SBPL differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// ruleIndex returns the index of the first line that is exactly rule and whose
// subpath lines (up to the closing paren) include sub, or -1.
func ruleIndex(lines []string, rule, sub string) int {
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != rule {
			continue
		}
		for j := i + 1; j < len(lines) && strings.HasPrefix(lines[j], "  "); j++ {
			if strings.TrimSpace(lines[j]) == `(subpath "`+sub+`")` {
				return i
			}
		}
	}
	return -1
}

// TestArtifactViewReadOnlyNoExec pins the view stanza: the read grant names
// this view only and follows the deny on the views root (last match wins), the
// exec and executable-map deny covers it, the write deny on it is the last rule
// of the profile, and the views root and the blob cache stay denied.
func TestArtifactViewReadOnlyNoExec(t *testing.T) {
	prof := viewProfile(t)
	lines := strings.Split(prof, "\n")
	view := viewPath(DefaultWorkDir, viewManifestA)
	root := filepath.Join(DefaultWorkDir, ArtifactViewsSubdir)
	blobs := filepath.Join(DefaultWorkDir, BlobsSubdir)

	rootDeny := ruleIndex(lines, "(deny file-read* file-write*", root)
	if rootDeny < 0 {
		t.Fatalf("no read+write deny on the views root %s", root)
	}
	if ruleIndex(lines, "(deny file-read* file-write*", blobs) != rootDeny {
		t.Errorf("the blob cache %s is not in the work-dir deny", blobs)
	}
	for _, form := range []string{view, "/private" + view} {
		read := ruleIndex(lines, "(allow file-read*", form)
		if read < 0 || read < rootDeny {
			t.Errorf("read grant on %s at %d, want one after the views-root deny at %d", form, read, rootDeny)
		}
		noexec := ruleIndex(lines, "(deny process-exec* file-map-executable", form)
		if noexec < read {
			t.Errorf("exec/map-executable deny on %s at %d, want one after the read grant at %d", form, noexec, read)
		}
		write := ruleIndex(lines, "(deny file-write*", form)
		if write < noexec {
			t.Errorf("write deny on %s at %d, want one after the exec deny at %d", form, write, noexec)
		}
	}
	// The write deny is the profile's last rule.
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "(") {
			last = i
		}
	}
	if last != ruleIndex(lines, "(deny file-write*", view) {
		t.Errorf("the last rule is %q, want the write deny on the view", lines[last])
	}
	// Nothing grants the views root or the blob cache as a subtree.
	for _, p := range []string{root, "/private" + root, blobs, "/private" + blobs} {
		if ruleIndex(lines, "(allow file-read*", p) >= 0 || ruleIndex(lines, "(allow file-read* file-write*", p) >= 0 {
			t.Errorf("a subtree allow names %s", p)
		}
	}
}

// TestArtifactViewGrantDoesNotReachOtherView is the negative: a pod granted
// model A's view gets no rule that names model B's manifest, and no allow whose
// subpath contains model B's view in either firmlink form.
func TestArtifactViewGrantDoesNotReachOtherView(t *testing.T) {
	prof := viewProfile(t)
	other := viewPath(DefaultWorkDir, viewManifestB)
	if strings.Contains(prof, viewManifestB) {
		t.Fatalf("the profile names model B's manifest %s", viewManifestB)
	}
	inAllow := false
	for _, l := range strings.Split(prof, "\n") {
		switch {
		case strings.HasPrefix(l, "(allow"):
			inAllow = true
		case strings.HasPrefix(l, "("):
			inAllow = false
		}
		if !inAllow {
			continue
		}
		t1 := strings.TrimSpace(l)
		if !strings.HasPrefix(t1, `(subpath "`) {
			continue
		}
		p := strings.TrimSuffix(strings.TrimPrefix(t1, `(subpath "`), `")`)
		if isUnder(other, p) || isUnder("/private"+other, p) {
			t.Errorf("allow subpath %s reaches model B's view %s", p, other)
		}
	}
}

// TestArtifactViewPathsAreValidated refuses anything that is not exactly one
// view directory under <WorkDir>/artifacts.
func TestArtifactViewPathsAreValidated(t *testing.T) {
	root := filepath.Join(DefaultWorkDir, ArtifactViewsSubdir)
	for name, p := range map[string]string{
		"the views root":     root,
		"a manifest dir":     filepath.Join(root, viewManifestA),
		"a file in a view":   filepath.Join(viewPath(DefaultWorkDir, viewManifestA), "w"),
		"a staging dir":      filepath.Join(root, viewManifestA, ".stage-1"),
		"the blob cache":     filepath.Join(DefaultWorkDir, BlobsSubdir, viewManifestA, viewKey),
		"an unclean path":    root + "/" + viewManifestA + "/../" + viewManifestB + "/" + viewKey,
		"a relative path":    "artifacts/" + viewManifestA + "/" + viewKey,
		"another work dir":   viewPath("/opt/k3sm", viewManifestA),
		"an uppercase key":   filepath.Join(root, viewManifestA, strings.ToUpper(viewKey)),
		"a data-volume path": "/var/lib/k3sm/pods/pod-view123/rootfs/m",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/pod-view123/rootfs"},
				GenerateOptions{ArtifactViewPaths: []string{p}})
			if !errors.Is(err, ErrInvalidArtifactView) {
				t.Fatalf("Generate(%s) = %v, want ErrInvalidArtifactView", p, err)
			}
		})
	}
}

// TestArtifactViewUnderSandboxExec runs real processes under the generated
// profile (sandbox-exec, the libsandbox the runtime uses): a file in the
// granted view reads, and cannot be written or executed; a file in another
// view and a cache blob cannot be read. It needs no root: it proves what the
// profile denies, and the 0755/0644 fixtures keep DAC out of the way.
func TestArtifactViewUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/tmp", "k3sm-av-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll("/private" + base) })
	dataVol := filepath.Join(base, "pods", "pod-av", "rootfs")
	viewA, viewB := viewPath(base, viewManifestA), viewPath(base, viewManifestB)
	blobDir := filepath.Join(base, BlobsSubdir, "sha256")
	for _, d := range []string{dataVol, viewA, viewB, blobDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, mode os.FileMode, data string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(viewA, "weights"), 0o644, "model A\n")
	write(filepath.Join(viewB, "weights"), 0o644, "model B\n")
	write(filepath.Join(blobDir, "blob"), 0o644, "blob\n")
	script := filepath.Join(viewA, "run.sh")
	write(script, 0o755, "#!/bin/sh\nexit 0\n")
	// A link in the pod's volume, as LinkImageVolumes leaves it.
	link := filepath.Join(dataVol, "model")
	if err := os.Symlink(viewA, link); err != nil {
		t.Fatal(err)
	}

	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:           Posture{WorkDir: base},
		ArtifactViewPaths: []string{viewA},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "av.sb")
	write(sb, 0o644, prof)
	run := func(argv ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, argv...)...).Run()
	}

	if err := run("/bin/cat", filepath.Join(link, "weights")); err != nil {
		t.Errorf("read of the granted view through the pod link was denied: %v", err)
	}
	if err := run("/bin/cat", filepath.Join(viewA, "weights")); err != nil {
		t.Errorf("read of the granted view was denied: %v", err)
	}
	if err := run("/usr/bin/touch", filepath.Join(viewA, "weights")); err == nil {
		t.Errorf("write to the granted view was allowed")
	}
	if err := run("/usr/bin/touch", filepath.Join(viewA, "new")); err == nil {
		t.Errorf("create in the granted view was allowed")
	}
	if err := run(script); err == nil {
		t.Errorf("exec of a file in the granted view was allowed")
	}
	if err := run("/bin/cat", filepath.Join(viewB, "weights")); err == nil {
		t.Errorf("read of model B's view was allowed to a pod granted model A")
	}
	if err := run("/bin/cat", filepath.Join(blobDir, "blob")); err == nil {
		t.Errorf("read of a cache blob was allowed")
	}
}
