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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	execArgvImage = "example.test/app:v1"
	// imageScript prints a marker no host file prints, so a passing case proves
	// which copy ran rather than only which path was named.
	imageScript = "#!/bin/sh\necho from-image\n"
)

// execArgvPod is one pod the exec argv tests run against.
type execArgvPod struct {
	rt     *Runtime
	be     *recordingExecBackend
	rootfs string
	podID  string
}

// newExecArgvPod creates a running pod whose image materializes tree into the
// pod rootfs. The backend passes argv through unwrapped, so an exec really runs
// the file it names, and spawns no shim.
func newExecArgvPod(t *testing.T, tree map[string]string, signer Signer, edit func(*runtimev1.PodBox)) *execArgvPod {
	t.Helper()
	return newExecArgvPodCfg(t, Config{}, tree, signer, edit)
}

// newExecArgvPodCfg is newExecArgvPod with a caller-supplied Config.
func newExecArgvPodCfg(t *testing.T, cfg Config, tree map[string]string, signer Signer, edit func(*runtimev1.PodBox)) *execArgvPod {
	t.Helper()
	files := map[string]string{"app-main": imageScript}
	for k, v := range tree {
		files[k] = v
	}
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	t.Cleanup(func() { w.release(1001) })
	rt := newTestRuntimeCfg(t, cfg, Deps{
		Backend: be,
		Waiter:  w,
		Signer:  signer,
		Puller: &fakePuller{
			manifest:   &runtimev1.ImageManifest{Reference: execArgvImage, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
			descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
		},
		Unpacker: &treeUnpacker{files: files, runCfg: image.ImageRunConfig{Entrypoint: []string{"/app-main"}}},
	})
	const podID = "pod-exec-argv"
	box := hostBinBox(rt, podID)
	box.Containers = []*runtimev1.Container{{Name: "main", Image: execArgvImage}}
	if edit != nil {
		edit(box)
	}
	mustCreatePod(t, rt, box)
	return &execArgvPod{rt: rt, be: be, rootfs: derivedRootfs(t, rt, podID), podID: podID}
}

// exec runs one session and returns the wrapped argv[0], the session's stdout,
// and the RPC's error. wrapped is "" when the request never reached the
// confinement seam.
func (p *execArgvPod) exec(t *testing.T, cmdv ...string) (wrapped, stdout string, err error) {
	t.Helper()
	before := p.wrapCalls()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := newFakeExecStream(ctx)
	st.feed(&runtimev1.ExecRequest{PodId: p.podID, Command: cmdv})
	st.closeSend()
	err = p.rt.Exec(st)
	if p.wrapCalls() > before {
		wrapped = p.be.lastArgv()[0]
	}
	if err != nil {
		return wrapped, "", err
	}
	out, code := st.collect(t)
	if code != 0 {
		t.Errorf("exec %v exit = %d, want 0 (stdout %q)", cmdv, code, out)
	}
	return wrapped, string(out), nil
}

func (p *execArgvPod) wrapCalls() int {
	p.be.mu.Lock()
	defer p.be.mu.Unlock()
	return len(p.be.argvs)
}

// TestExecResolvesArgvInTheImageRootfs pins the failure measured on a node: an exec
// of an absolute path on a pulled-image pod names a file in the image, as the
// container's own argv[0] does, and failed with "execve /bin/python3.12: no such
// file" while the file sat in the pod rootfs.
//
// The session really runs here, so every row that runs proves which copy ran by
// its output, not only by the path handed to the seam. /bin/echo is the host file
// the host rows reach: the image's copy prints from-image, the host's prints hi.
func TestExecResolvesArgvInTheImageRootfs(t *testing.T) {
	const hostEcho = "/bin/echo"
	inRootfs := func(rel string) func(string) string {
		return func(rootfs string) string { return filepath.Join(rootfs, rel) }
	}
	asNamed := func(name string) func(string) string {
		return func(string) string { return name }
	}
	cases := []struct {
		name    string
		tree    map[string]string
		links   map[string]string // rootfs-relative name -> symlink target
		cmd     string
		want    func(rootfs string) string
		wantOut string
	}{
		{
			name:    "only_in_the_image",
			tree:    map[string]string{"bin/python3.12": imageScript},
			cmd:     "/bin/python3.12",
			want:    inRootfs("bin/python3.12"),
			wantOut: "from-image",
		},
		{
			name:    "only_on_the_host_keeps_the_host_copy",
			tree:    map[string]string{"bin/python3.12": imageScript},
			cmd:     hostEcho,
			want:    asNamed(hostEcho),
			wantOut: "hi",
		},
		{
			name:    "in_both_runs_the_image_copy",
			tree:    map[string]string{"bin/echo": imageScript},
			cmd:     hostEcho,
			want:    inRootfs("bin/echo"),
			wantOut: "from-image",
		},
		{
			// A relative link keeps its own name: a multi-call binary and a
			// venv's interpreter both read argv[0], and start hands them this.
			name:    "relative_symlink_in_the_image_keeps_its_name",
			tree:    map[string]string{"bin/python3.12": imageScript},
			links:   map[string]string{"bin/python3": "python3.12"},
			cmd:     "/bin/python3",
			want:    inRootfs("bin/python3"),
			wantOut: "from-image",
		},
		{
			// The kernel would follow this link to the host, so the session is
			// handed the file the link means inside the image.
			name:    "root_absolute_symlink_stays_in_the_image",
			tree:    map[string]string{"opt/real": imageScript},
			links:   map[string]string{"bin/tool": "/opt/real"},
			cmd:     "/bin/tool",
			want:    inRootfs("opt/real"),
			wantOut: "from-image",
		},
		{
			name:    "directory_symlink_with_no_such_file_keeps_the_host_copy",
			tree:    map[string]string{"usr/bin/other": imageScript},
			links:   map[string]string{"bin": "usr/bin"},
			cmd:     hostEcho,
			want:    asNamed(hostEcho),
			wantOut: "hi",
		},
		{
			name:    "a_file_where_a_directory_belongs_keeps_the_host_copy",
			tree:    map[string]string{"bin": "not a directory"},
			cmd:     hostEcho,
			want:    asNamed(hostEcho),
			wantOut: "hi",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newExecArgvPod(t, tc.tree, nil, nil)
			plantLinks(t, p.rootfs, tc.links)
			got, out, err := p.exec(t, tc.cmd, "hi")
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if want := tc.want(p.rootfs); got != want {
				t.Errorf("session argv[0] = %q, want %q", got, want)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", out, tc.wantOut)
			}
		})
	}
}

// TestExecRefusesASymlinkLeavingTheRootfs pins the containment. Every row plants a link the kernel would follow out of the pod rootfs
// to a real host file, so a resolver that only joined and stat'd would run it; and
// none falls back to the host, because the image does name something at that path.
func TestExecRefusesASymlinkLeavingTheRootfs(t *testing.T) {
	up := strings.Repeat("../", 32)
	cases := []struct {
		name  string
		links map[string]string
		cmd   string
	}{
		{name: "relative_link_out", links: map[string]string{"bin/out": up + "bin/echo"}, cmd: "/bin/out"},
		{name: "root_absolute_link_to_a_host_file", links: map[string]string{"bin/out": "/bin/echo"}, cmd: "/bin/out"},
		{name: "link_shadowing_a_host_name", links: map[string]string{"bin/echo": "/usr/bin/true"}, cmd: "/bin/echo"},
		{name: "directory_link_out", links: map[string]string{"opt": up + "bin"}, cmd: "/opt/echo"},
		{name: "link_loop", links: map[string]string{"bin/a": "b", "bin/b": "a"}, cmd: "/bin/a"},
		{name: "path_above_the_rootfs", cmd: "/../escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newExecArgvPod(t, map[string]string{"bin/python3.12": imageScript}, nil, nil)
			plantLinks(t, p.rootfs, tc.links)
			got, _, err := p.exec(t, tc.cmd, "hi")
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Exec error = %v, want InvalidArgument", err)
			}
			if !strings.Contains(err.Error(), ErrImageArgvEscapes.Error()) {
				t.Errorf("Exec error = %v, want it to name %q", err, ErrImageArgvEscapes)
			}
			if got != "" {
				t.Errorf("a refused exec reached the confinement seam with argv[0] %q", got)
			}
		})
	}
}

// TestExecLeavesOtherShapesAsSent pins what the resolution must not touch: a
// relative or bare name keeps exec's own meaning (the session's cwd, its PATH),
// and a host-binary container names host paths, whatever its rootfs holds.
func TestExecLeavesOtherShapesAsSent(t *testing.T) {
	tree := map[string]string{"bin/echo": imageScript, "bin/tool": imageScript}

	t.Run("relative_path_runs_from_the_session_cwd", func(t *testing.T) {
		p := newExecArgvPod(t, tree, nil, nil)
		got, out, err := p.exec(t, "bin/tool")
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if got != "bin/tool" || !strings.Contains(out, "from-image") {
			t.Errorf("argv[0] = %q stdout = %q, want bin/tool and from-image", got, out)
		}
	})

	t.Run("bare_name_is_left_for_the_session_PATH", func(t *testing.T) {
		p := newExecArgvPod(t, tree, nil, nil)
		got, _, err := p.exec(t, "echo", "hi")
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if got != "echo" {
			t.Errorf("argv[0] = %q, want echo", got)
		}
	})

	hostRoutes := []struct {
		name string
		c    *runtimev1.Container
	}{
		{"native_sentinel", &runtimev1.Container{Name: "main", Image: NativeImage, Command: []string{"/bin/sleep", "60"}}},
		{"host_path_reference", &runtimev1.Container{Name: "main", Image: "/bin/sleep"}},
	}
	for _, hr := range hostRoutes {
		t.Run("host_process_"+hr.name+"_runs_the_host_copy", func(t *testing.T) {
			signer := &countingSigner{}
			be := &recordingExecBackend{}
			w := newBlockingWaiter()
			t.Cleanup(func() { w.release(1001) })
			rt := newTestRuntime(t, Deps{Backend: be, Waiter: w, Signer: signer})
			const podID = "pod-exec-host"
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{hr.c}
			mustCreatePod(t, rt, box)
			p := &execArgvPod{rt: rt, be: be, rootfs: derivedRootfs(t, rt, podID), podID: podID}
			// The same name in the rootfs must not capture a host-process exec.
			if err := os.MkdirAll(filepath.Join(p.rootfs, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p.rootfs, "bin/echo"), []byte(imageScript), 0o755); err != nil {
				t.Fatal(err)
			}
			checks := signer.checks()
			got, out, err := p.exec(t, "/bin/echo", "hi")
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if got != "/bin/echo" || !strings.Contains(out, "hi") {
				t.Errorf("argv[0] = %q stdout = %q, want /bin/echo and hi", got, out)
			}
			if signer.checks() != checks {
				t.Errorf("a host-process exec went through the signature gate")
			}
		})
	}

	t.Run("a_mounted_path_stays_for_the_session_rebase", func(t *testing.T) {
		signer := &countingSigner{rejectSuffix: "/data/tool"}
		p := newExecArgvPod(t, tree, signer, func(box *runtimev1.PodBox) {
			box.Volumes = []*runtimev1.Volume{mediumVolume("data", "")}
			box.Containers[0].VolumeMounts = []*runtimev1.VolumeMount{{Name: "data", MountPath: "/data"}}
		})
		// A file in the volume, which a rootfs resolution would find and gate.
		tool := filepath.Join(p.rootfs, "data/tool")
		if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tool, []byte(imageScript), 0o755); err != nil {
			t.Fatal(err)
		}
		// There is no interposer in this harness to rebase the name, so the
		// session fails to start; the assertion is that it was asked to run the
		// cleaned name, past no gate, so the daemon and the interposer read one form.
		for _, name := range []string{"/data/tool", "/bin/../data/tool", "/data//tool", "/data/./tool"} {
			got, _, err := p.exec(t, name)
			if code := status.Code(err); code != codes.Internal {
				t.Fatalf("Exec %q error = %v, want the start failure of a name no interposer rebased", name, err)
			}
			if got != "/data/tool" {
				t.Errorf("Exec %q: argv[0] = %q, want /data/tool", name, got)
			}
		}
	})
}

// TestExecOfAnImageFileGetsTheStartGate pins "no more than start grants". The
// file exec reaches in the image passes the gate the container's own argv[0]
// passed, in the same order, so a pod whose policy refuses a binary at start does
// not run it by exec; and a host file keeps exec's present answer, ungated.
func TestExecOfAnImageFileGetsTheStartGate(t *testing.T) {
	tree := map[string]string{"bin/tool": imageScript}
	require := func(box *runtimev1.PodBox) {
		box.SignaturePolicy = runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED
	}

	t.Run("a_policy_refusal_stops_the_session", func(t *testing.T) {
		signer := &countingSigner{rejectSuffix: "/bin/tool"}
		p := newExecArgvPod(t, tree, signer, require)
		got, _, err := p.exec(t, "/bin/tool")
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("Exec error = %v, want FailedPrecondition", err)
		}
		if got != "" {
			t.Errorf("a refused exec reached the confinement seam with argv[0] %q", got)
		}
		if n := len(signer.signedPaths()); n != 0 {
			t.Errorf("REQUIRE_SIGNED ad-hoc signed %d files; it must never sign", n)
		}
	})

	t.Run("adhoc_policy_signs_an_unsigned_image_file_before_the_session", func(t *testing.T) {
		signer := &countingSigner{rejectSuffix: "/bin/tool", signClears: true}
		p := newExecArgvPod(t, tree, signer, nil)
		got, out, err := p.exec(t, "/bin/tool")
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		want := filepath.Join(p.rootfs, "bin/tool")
		if got != want || !strings.Contains(out, "from-image") {
			t.Errorf("argv[0] = %q stdout = %q, want %q and from-image", got, out, want)
		}
		if paths := signer.signedPaths(); len(paths) != 1 || paths[0] != want {
			t.Errorf("signed %v, want exactly [%q]", paths, want)
		}
	})

	t.Run("a_host_file_is_not_gated", func(t *testing.T) {
		signer := &countingSigner{rejectSuffix: "/bin/echo"}
		p := newExecArgvPod(t, tree, signer, require)
		got, out, err := p.exec(t, "/bin/echo", "hi")
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if got != "/bin/echo" || !strings.Contains(out, "hi") {
			t.Errorf("argv[0] = %q stdout = %q, want /bin/echo and hi", got, out)
		}
	})
}

// TestExecViaShimSendsTheResolvedArgv pins the route production takes: a
// shim-backed container's session is forked by its shim, so the resolution has to
// happen before the hand-off or the session still looks on the host. It also covers
// a pod this daemon adopted, whose containers it did not start.
func TestExecViaShimSendsTheResolvedArgv(t *testing.T) {
	const pgid, start, child, cstart = 100, int64(5000), 101, int64(5500)
	shim := &fakeShim{pid: pgid, start: start, child: child, cstart: cstart}
	dir := serveShim(t, shim)
	rt := newTestRuntime(t, Deps{
		ProcGroup: fakeGroups{members: map[int][]supervisor.ProcMember{pgid: {mem(pgid, start), mem(child, cstart)}}}.inspect,
		ProcStartTime: func(pid int) (int64, bool) {
			v, ok := map[int]int64{pgid: start, child: cstart}[pid]
			return v, ok
		},
		AdoptedWaiter: unknownExitWaiter{newBlockingWaiter()},
		ShimDialer:    &claimDialer{pid: pgid},
		SignalGroup:   func(int, os.Signal) error { return nil },
	})
	seedRecord(t, rt, attachableRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start,
		ShimDir: dir, ChildPid: child, ChildStartUnixNano: cstart}))
	box := hostBinBox(rt, "p1")
	box.Containers[0].Image = execArgvImage
	if _, err := rt.AttachPod(context.Background(), box); err != nil {
		t.Fatalf("AttachPod: %v", err)
	}
	t.Cleanup(func() { _, _ = rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "p1"}) })

	rootfs := derivedRootfs(t, rt, "p1")
	bin := filepath.Join(rootfs, "bin/python3.12")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte(imageScript), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := newFakeExecStream(ctx)
	st.feed(&runtimev1.ExecRequest{PodId: "p1", Command: []string{"/bin/python3.12", "-m", "probe"}})
	st.closeSend()
	if err := rt.Exec(st); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	shim.mu.Lock()
	defer shim.mu.Unlock()
	if len(shim.execs) != 1 {
		t.Fatalf("the shim saw %d sessions, want 1", len(shim.execs))
	}
	got := shim.execs[0].GetCommand()
	if len(got) != 3 || got[0] != bin || got[1] != "-m" || got[2] != "probe" {
		t.Errorf("the shim was asked to run %v, want [%s -m probe]", got, bin)
	}
}

// plantLinks creates each symlink under rootfs. The pod can write its own rootfs,
// so this needs no image layer to be a shape the daemon meets.
func plantLinks(t *testing.T, rootfs string, links map[string]string) {
	t.Helper()
	for name, target := range links {
		p := filepath.Join(rootfs, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
}

// countingSigner rejects any path ending in rejectSuffix, until Sign clears it
// when signClears is set, and counts what it was asked.
type countingSigner struct {
	rejectSuffix string
	signClears   bool

	mu      sync.Mutex
	nChecks int
	signed  []string
}

func (s *countingSigner) Sign(_ context.Context, _, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signed = append(s.signed, path)
	return nil
}

func (s *countingSigner) Check(_ context.Context, _ runtimev1.SignaturePolicy, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nChecks++
	if s.rejectSuffix == "" || !strings.HasSuffix(path, s.rejectSuffix) {
		return nil
	}
	if s.signClears && len(s.signed) > 0 {
		return nil
	}
	return errors.New("not signed")
}

func (s *countingSigner) checks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nChecks
}

func (s *countingSigner) signedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.signed...)
}
