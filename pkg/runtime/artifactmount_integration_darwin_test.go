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
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/apis/k3smtest"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"
)

// artifactHelperEnv marks a re-exec of this test binary as the probe process
// TestArtifactMountUnderSandbox runs under the pod profile.
const artifactHelperEnv = "K3SM_ARTIFACT_MOUNT_HELPER"

// nobodyUID is the unprivileged uid the probe runs as: a pod's uid, never root.
const nobodyUID = 4294967294

// TestArtifactMountHelperProcess is the probe: it performs one operation on one
// path and exits 0 on success, 1 on failure. It does nothing in a normal run.
func TestArtifactMountHelperProcess(t *testing.T) {
	if os.Getenv(artifactHelperEnv) == "" {
		t.Skip("probe process only")
	}
	op, path := os.Getenv(artifactHelperEnv+"_OP"), os.Getenv(artifactHelperEnv+"_PATH")
	var err error
	switch op {
	case "read":
		_, err = os.ReadFile(path)
	case "write":
		var f *os.File
		if f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err == nil {
			_ = f.Close()
		}
	case "exec":
		err = exec.Command(path).Run()
	case "mmap-read", "mmap-exec":
		err = mapFile(path, op == "mmap-exec")
	case "link-alias":
		err = linkAlias(path, os.Getenv(artifactHelperEnv+"_ALIAS"))
	case "fchmod":
		var f *os.File
		if f, err = os.Open(path); err == nil {
			err = f.Chmod(0o644)
			_ = f.Close()
		}
	default:
		t.Fatalf("unknown op %q", op)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// linkAlias hard-links path to alias, makes the alias writable and appends to
// it: what a pod that owns a view file's inode would do to change the bytes
// every other pod mounting that view reads.
func linkAlias(path, alias string) error {
	if err := os.Link(path, alias); err != nil {
		return err
	}
	if err := os.Chmod(alias, 0o644); err != nil {
		return err
	}
	f, err := os.OpenFile(alias, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("tampered"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// mapFile maps path PROT_READ MAP_PRIVATE, plus PROT_EXEC when exec is set.
func mapFile(path string, execMap bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	prot := unix.PROT_READ
	if execMap {
		prot |= unix.PROT_EXEC
	}
	b, err := unix.Mmap(int(f.Fd()), 0, int(fi.Size()), prot, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	return unix.Munmap(b)
}

// TestArtifactMountUnderSandbox fetches a model artifact through the runtime's
// puller, builds its view, links it into a pod with mount.LinkImageVolumes and
// compiles the pod's profile. A real process, sandboxed with that profile
// (sandbox-exec, the libsandbox the runtime applies) and running as an
// unprivileged uid, reads a view file and maps it PROT_READ MAP_PRIVATE; it
// fails to write it, to exec it, to map it executable, and to read a cache
// blob. The write, exec and blob read first succeed as the same uid without
// the profile, so each denial is the profile's and not file permissions'.
func TestArtifactMountUnderSandbox(t *testing.T) {
	k3smtest.SkipUnless(t, k3smtest.Root)
	f := modelArtifact(map[string][]byte{"w.safetensors": []byte("weights"), "run.sh": []byte("#!/bin/sh\nexit 0\n")}, []string{"run.sh", "w.safetensors"})
	_, rt := artifactRPCClient(t, f)
	t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
	ctx := context.Background()
	box := imageVolumeBox(rt, "pod-av", artifactTestHost+"/models/tiny:v1")
	views, _, err := rt.imageVolumeViews(ctx, box)
	if err != nil {
		t.Fatalf("imageVolumeViews: %v", err)
	}
	view := views.ByVolume["model"]
	rootfs := filepath.Join(rt.cfg.Root, "pods", "pod-av", "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	grants, err := mount.LinkImageVolumes(box, rootfs, views)
	if err != nil {
		t.Fatalf("LinkImageVolumes: %v", err)
	}
	profile, err := rt.compileProfile(box, rootfs, "", nil, nil, nil, grants)
	if err != nil {
		t.Fatalf("compileProfile: %v", err)
	}

	// Fixtures that take file permissions out of every refused operation: the
	// tree is traversable, the view's script is 0755, its weights 0666, and a
	// cache blob 0644.
	for d := rt.cfg.Root; d != "/" && d != "."; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && fi.Mode().Perm()&0o001 == 0 {
			if err := os.Chmod(d, fi.Mode().Perm()|0o011); err != nil {
				t.Fatalf("make %s traversable: %v", d, err)
			}
		}
	}
	chmod := func(p string, m os.FileMode) {
		t.Helper()
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	chmod(filepath.Join(view, "run.sh"), 0o755)
	chmod(filepath.Join(view, "w.safetensors"), 0o666)
	blob, err := rt.cache.BlobPath(sha([]byte("weights")))
	if err != nil {
		t.Fatal(err)
	}
	for d := filepath.Dir(blob); isUnderDir(d, rt.cfg.Root); d = filepath.Dir(d) {
		chmod(d, 0o755)
	}
	chmod(blob, 0o644)

	helper := filepath.Join(rootfs, "probe")
	copyExecutable(t, os.Args[0], helper)
	sb := filepath.Join(rt.cfg.Root, "pod-av.sb")
	if err := os.WriteFile(sb, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(sandboxed bool, op, path string) bool {
		t.Helper()
		argv := []string{helper, "-test.run=^TestArtifactMountHelperProcess$"}
		if sandboxed {
			argv = append([]string{"/usr/bin/sandbox-exec", "-f", sb}, argv...)
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{artifactHelperEnv + "=1", artifactHelperEnv + "_OP=" + op, artifactHelperEnv + "_PATH=" + path}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobodyUID, Gid: nobodyUID}}
		return cmd.Run() == nil
	}

	weights := filepath.Join(rootfs, "models", "w.safetensors")
	for _, op := range []string{"read", "mmap-read"} {
		if !run(true, op, weights) {
			t.Errorf("%s of a view file was refused under the profile", op)
		}
	}
	for _, c := range []struct{ op, path string }{
		{"write", weights},
		{"exec", filepath.Join(rootfs, "models", "run.sh")},
		{"read", blob},
	} {
		if !run(false, c.op, c.path) {
			t.Errorf("control: %s of %s fails without the profile, so its denial would prove nothing", c.op, c.path)
			continue
		}
		if run(true, c.op, c.path) {
			t.Errorf("%s of %s succeeded under the profile", c.op, c.path)
		}
	}
	// An executable mapping of a view file must fail under the profile. Its
	// control is reported, not required: on this macOS 26 arm64 host the
	// unprivileged PROT_EXEC mapping already fails without any profile, so
	// there the file-map-executable deny is not separately observable.
	if run(true, "mmap-exec", weights) {
		t.Errorf("mmap-exec of %s succeeded under the profile", weights)
	}
	if !run(false, "mmap-exec", weights) {
		t.Logf("stated negative: mmap PROT_EXEC of %s fails without the profile too (the kernel refuses it first), so the profile's file-map-executable deny is unobservable on this host", weights)
	}
	if strings.Contains(profile, "(allow file-read*\n  (subpath \""+filepath.Join(rt.cache.Root(), sandbox.BlobsSubdir)) {
		t.Errorf("the profile grants the blob cache")
	}
}

// isUnderDir reports whether p is strictly inside dir.
func isUnderDir(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..")
}

// copyExecutable copies src to dst, mode 0755.
func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestArtifactViewHardLinkAlias probes the shared-inode alias: a pod hard-links
// a 0444 view file into its writable data volume, chmods the alias and writes
// through it. Every pod mounting that view reads the same inode, so a write
// that lands changes another pod's model.
//
// It runs in both postures. In the root posture the view file is the daemon's
// (root's) and the pod runs as another uid. In the user posture the daemon and
// the pod are one uid, so the pod owns the inode and file permissions alone
// would let the chmod through; the probe chowns the view file to the pod's uid
// to stand for that. Each posture runs the operation without the profile as a
// control and states its outcome, then requires that under the profile it
// fails and the view's bytes are unchanged. A read-only descriptor's fchmod is
// probed the same way.
func TestArtifactViewHardLinkAlias(t *testing.T) {
	k3smtest.SkipUnless(t, k3smtest.Root)
	for _, posture := range []string{"root", "user"} {
		t.Run(posture, func(t *testing.T) {
			f := modelArtifact(map[string][]byte{"w.safetensors": []byte("weights")}, []string{"w.safetensors"})
			_, rt := artifactRPCClient(t, f)
			t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
			ctx := context.Background()
			box := imageVolumeBox(rt, "pod-ln", artifactTestHost+"/models/tiny:v1")
			views, _, err := rt.imageVolumeViews(ctx, box)
			if err != nil {
				t.Fatalf("imageVolumeViews: %v", err)
			}
			view := views.ByVolume["model"]
			rootfs := filepath.Join(rt.cfg.Root, "pods", "pod-ln", "rootfs")
			if err := os.MkdirAll(rootfs, 0o755); err != nil {
				t.Fatal(err)
			}
			grants, err := mount.LinkImageVolumes(box, rootfs, views)
			if err != nil {
				t.Fatalf("LinkImageVolumes: %v", err)
			}
			profile, err := rt.compileProfile(box, rootfs, "", nil, nil, nil, grants)
			if err != nil {
				t.Fatalf("compileProfile: %v", err)
			}
			for d := rt.cfg.Root; d != "/" && d != "."; d = filepath.Dir(d) {
				if fi, err := os.Stat(d); err == nil && fi.Mode().Perm()&0o001 == 0 {
					if err := os.Chmod(d, fi.Mode().Perm()|0o011); err != nil {
						t.Fatalf("make %s traversable: %v", d, err)
					}
				}
			}
			// The data volume is the pod's own, writable by its uid.
			if err := os.Chown(rootfs, nobodyUID, nobodyUID); err != nil {
				t.Fatal(err)
			}
			viewFile := filepath.Join(view, "w.safetensors")
			if posture == "user" {
				if err := os.Chown(viewFile, nobodyUID, nobodyUID); err != nil {
					t.Fatal(err)
				}
			}
			helper := filepath.Join(rootfs, "probe")
			copyExecutable(t, os.Args[0], helper)
			sb := filepath.Join(rt.cfg.Root, "pod-ln.sb")
			if err := os.WriteFile(sb, []byte(profile), 0o644); err != nil {
				t.Fatal(err)
			}
			reset := func() {
				t.Helper()
				for _, a := range []string{"alias", "alias-ctl"} {
					_ = os.Remove(filepath.Join(rootfs, a))
				}
				if err := os.Chmod(viewFile, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(viewFile, []byte("weights"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(viewFile, 0o444); err != nil {
					t.Fatal(err)
				}
			}
			run := func(sandboxed bool, op, path, alias string) bool {
				t.Helper()
				argv := []string{helper, "-test.run=^TestArtifactMountHelperProcess$"}
				if sandboxed {
					argv = append([]string{"/usr/bin/sandbox-exec", "-f", sb}, argv...)
				}
				cmd := exec.Command(argv[0], argv[1:]...)
				cmd.Env = []string{artifactHelperEnv + "=1", artifactHelperEnv + "_OP=" + op,
					artifactHelperEnv + "_PATH=" + path, artifactHelperEnv + "_ALIAS=" + alias}
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobodyUID, Gid: nobodyUID}}
				return cmd.Run() == nil
			}
			intact := func() bool {
				t.Helper()
				b, err := os.ReadFile(viewFile)
				if err != nil {
					t.Fatal(err)
				}
				fi, err := os.Stat(viewFile)
				if err != nil {
					t.Fatal(err)
				}
				return string(b) == "weights" && fi.Mode().Perm() == 0o444
			}
			// Through the pod's mount path, as the pod sees the file.
			mounted := filepath.Join(rootfs, "models", "w.safetensors")

			reset()
			ctl := run(false, "link-alias", mounted, filepath.Join(rootfs, "alias-ctl"))
			t.Logf("posture %s: link, chmod and write through an alias WITHOUT the profile: succeeded=%v, view intact=%v", posture, ctl, intact())
			reset()
			if run(true, "link-alias", mounted, filepath.Join(rootfs, "alias")) {
				t.Errorf("posture %s: link, chmod and write through an alias succeeded under the profile", posture)
			}
			if !intact() {
				t.Errorf("posture %s: the shared view file changed under the profile", posture)
			}
			// The refused link is the load-bearing step: an alias in the data
			// volume is a path the profile lets the pod chmod and write, so in the
			// user posture only the link's refusal (the view's file-write* deny
			// covers link(2) of a file under it) keeps the inode shared-read-only.
			if _, err := os.Lstat(filepath.Join(rootfs, "alias")); err == nil {
				t.Errorf("posture %s: a hard link to a view file was made in the data volume under the profile", posture)
			}

			reset()
			ctl = run(false, "fchmod", mounted, "")
			t.Logf("posture %s: fchmod of a read-only descriptor WITHOUT the profile: succeeded=%v", posture, ctl)
			reset()
			if run(true, "fchmod", mounted, "") {
				t.Errorf("posture %s: fchmod of a read-only descriptor succeeded under the profile", posture)
			}
			if !intact() {
				t.Errorf("posture %s: the shared view file's mode changed under the profile", posture)
			}
		})
	}
}
