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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestExecRewriteFollowsShebangs is the B243 gate for the spawn-time rewrite:
// a host shell, or a script whose shebang names one, runs the node's re-signed
// copy with the argv the kernel would have built; a target (or interpreter)
// under a mount prefix is rebased first, as the interposer rebases it; and
// nothing else changes.
func TestExecRewriteFollowsShebangs(t *testing.T) {
	const dir = "/Library/k3sm/shadow"
	const rootfs = "/var/lib/k3sm/pods/p/rootfs"
	scripts := map[string]string{
		"/opt/app/entry.sh":    "#!/bin/sh\necho hi\n",
		"/opt/app/envbash.sh":  "#!/usr/bin/env bash\necho hi\n",
		"/opt/app/bashflag.sh": "#!/bin/bash   -e -u  \r\necho hi\n",
		"/opt/app/tabbed.sh":   "#! \t/bin/zsh\tlogin\n",
		"/opt/app/python.py":   "#!/usr/bin/python3\nprint(1)\n",
		"/opt/app/unfinished":  "#!/bin/sh",
		"/opt/app/crlf.sh":     "#!/bin/sh\r\necho hi\n",
		// Materialized under the pod rootfs (a volume mounted at /etc/tool).
		rootfs + "/etc/tool/run.sh":  "#!/bin/sh\necho hi\n",
		rootfs + "/etc/tool/py.sh":   "#!/usr/bin/python3\n",
		rootfs + "/etc/tool/self.sh": "#!/etc/tool/interp -x\n",
	}
	readHead := func(path string) ([]byte, error) {
		if s, ok := scripts[path]; ok {
			return []byte(s), nil
		}
		return []byte{0xcf, 0xfa, 0xed, 0xfe}, nil // a Mach-O magic: not a script
	}
	mounted := mountRebaser(rootfs, []string{"/etc/tool/"})

	tests := []struct {
		name     string
		dir      string
		rebase   func(string) string
		path     string
		argv     []string
		wantPath string
		wantArgv []string // nil: untouched
	}{
		{"direct sh keeps an sh argv0 (POSIX mode)", dir, nil, "/bin/sh",
			[]string{"/bin/sh", "-c", "exec app"}, dir + "/bash", []string{"/bin/sh", "-c", "exec app"}},
		{"direct sh under another argv0 is named sh", dir, nil, "/bin/sh",
			[]string{"launcher", "-c", "x"}, dir + "/bash", []string{"sh", "-c", "x"}},
		{"direct bash", dir, nil, "/bin/bash",
			[]string{"/bin/bash", "-lc", "x"}, dir + "/bash", []string{"/bin/bash", "-lc", "x"}},
		{"direct zsh", dir, nil, "/bin/zsh",
			[]string{"/bin/zsh", "-c", "x"}, dir + "/zsh", []string{"/bin/zsh", "-c", "x"}},
		{"direct dash", dir, nil, "/bin/dash",
			[]string{"/bin/dash", "-c", "x"}, dir + "/dash", []string{"/bin/dash", "-c", "x"}},
		{"direct env", dir, nil, "/usr/bin/env",
			[]string{"/usr/bin/env", "FOO=1", "app"}, dir + "/env", []string{"/usr/bin/env", "FOO=1", "app"}},
		{"#!/bin/sh script", dir, nil, "/opt/app/entry.sh",
			[]string{"/opt/app/entry.sh", "a", "b"}, dir + "/bash", []string{"/bin/sh", "/opt/app/entry.sh", "a", "b"}},
		{"#!/usr/bin/env bash script", dir, nil, "/opt/app/envbash.sh",
			[]string{"/opt/app/envbash.sh", "x"}, dir + "/env", []string{"/usr/bin/env", "bash", "/opt/app/envbash.sh", "x"}},
		{"shebang argument is one trimmed argument", dir, nil, "/opt/app/bashflag.sh",
			[]string{"/opt/app/bashflag.sh"}, dir + "/bash", []string{"/bin/bash", "-e -u", "/opt/app/bashflag.sh"}},
		{"tabs separate interpreter and argument", dir, nil, "/opt/app/tabbed.sh",
			[]string{"ignored-argv0"}, dir + "/zsh", []string{"/bin/zsh", "login", "/opt/app/tabbed.sh"}},
		{"CRLF interpreter is not a shell (the kernel would not find it either)", dir, nil, "/opt/app/crlf.sh",
			[]string{"/opt/app/crlf.sh"}, "", nil},
		{"non-shell shebang untouched", dir, nil, "/opt/app/python.py",
			[]string{"/opt/app/python.py"}, "", nil},
		{"incomplete first line untouched", dir, nil, "/opt/app/unfinished",
			[]string{"/opt/app/unfinished"}, "", nil},
		{"non-shell binary untouched", dir, nil, "/usr/bin/python3",
			[]string{"/usr/bin/python3", "-c", "1"}, "", nil},
		{"ShadowBinDir empty: sh untouched", "", nil, "/bin/sh",
			[]string{"/bin/sh", "-c", "x"}, "", nil},
		{"ShadowBinDir empty: script untouched", "", nil, "/opt/app/entry.sh",
			[]string{"/opt/app/entry.sh"}, "", nil},
		{"mounted #!/bin/sh script: rebased, then the shell copy", dir, mounted, "/etc/tool/run.sh",
			[]string{"/etc/tool/run.sh", "a"}, dir + "/bash", []string{"/bin/sh", rootfs + "/etc/tool/run.sh", "a"}},
		{"mounted non-shell script: the rebased target only", dir, mounted, "/etc/tool/py.sh",
			[]string{"/etc/tool/py.sh", "a"}, rootfs + "/etc/tool/py.sh", []string{"/etc/tool/py.sh", "a"}},
		{"mounted binary with the shadow set off: still rebased", "", mounted, "/etc/tool/bin",
			[]string{"/etc/tool/bin"}, rootfs + "/etc/tool/bin", []string{"/etc/tool/bin"}},
		{"interpreter under a mount is rebased too", "", mounted, "/etc/tool/self.sh",
			[]string{"/etc/tool/self.sh", "z"}, rootfs + "/etc/tool/interp", []string{"/etc/tool/interp", "-x", rootfs + "/etc/tool/self.sh", "z"}},
		{"a sibling of the mount prefix is not rebased", "", mounted, "/etc/toolbox/x",
			[]string{"/etc/toolbox/x"}, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := shadowRewrite(tc.path, tc.argv, execRewrite{dir: tc.dir, readHead: readHead, rebase: tc.rebase})
			if tc.wantArgv == nil {
				if ok {
					t.Fatalf("rewrote to %q %q, want untouched", got.path, got.argv)
				}
				return
			}
			if !ok {
				t.Fatalf("untouched, want %q %q", tc.wantPath, tc.wantArgv)
			}
			if got.path != tc.wantPath || !slices.Equal(got.argv, tc.wantArgv) {
				t.Errorf("rewrite = %q %q, want %q %q", got.path, got.argv, tc.wantPath, tc.wantArgv)
			}
		})
	}

	t.Run("an unreadable target is untouched", func(t *testing.T) {
		fail := func(string) ([]byte, error) { return nil, errors.New("EACCES") }
		if got, ok := shadowRewrite("/opt/app/x", []string{"/opt/app/x"}, execRewrite{dir: dir, readHead: fail}); ok {
			t.Errorf("rewrote an unreadable file to %q", got.path)
		}
	})

	t.Run("a refused copy falls through to the host binary", func(t *testing.T) {
		refuse := func(string) bool { return false }
		if got, ok := shadowRewrite("/bin/sh", []string{"/bin/sh"}, execRewrite{dir: dir, readHead: readHead, admit: refuse}); ok {
			t.Errorf("used a refused copy: %q", got.path)
		}
	})
}

// TestShadowCopyTrust pins the ownership check both sides apply before a copy
// is used: root-owned 0755 is admitted; a group-writable file, a non-root
// owner, a symlink and a world-writable directory each fall back to the host
// binary with a warning naming the path and the failed property.
func TestShadowCopyTrust(t *testing.T) {
	const dir, file = "/Library/k3sm/shadow", "/Library/k3sm/shadow/bash"
	ok := map[string]shadowStat{
		dir:  {uid: 0, mode: unix.S_IFDIR | 0o755},
		file: {uid: 0, mode: unix.S_IFREG | 0o755},
	}
	cases := []struct {
		name     string
		override map[string]shadowStat
		wantErr  string // "" admits
	}{
		{"root-owned 0755 substitutes", nil, ""},
		{"group-writable file", map[string]shadowStat{file: {uid: 0, mode: unix.S_IFREG | 0o775}}, file + ": group- or world-writable"},
		{"non-root owner", map[string]shadowStat{file: {uid: 501, mode: unix.S_IFREG | 0o755}}, file + ": owned by uid 501"},
		{"symlink", map[string]shadowStat{file: {uid: 0, mode: unix.S_IFLNK | 0o755}}, file + ": is a symlink"},
		{"world-writable dir", map[string]shadowStat{dir: {uid: 0, mode: unix.S_IFDIR | 0o757}}, dir + ": group- or world-writable"},
		{"dir that is a file", map[string]shadowStat{dir: {uid: 0, mode: unix.S_IFREG | 0o755}}, dir + ": not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lstat := func(p string) (shadowStat, error) {
				if st, found := tc.override[p]; found {
					return st, nil
				}
				return ok[p], nil
			}
			err := verifyShadow(dir, file, lstat)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyShadow = %v, want admitted", err)
				}
			} else if err == nil || !errors.Is(err, errShadowUntrusted) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verifyShadow = %v, want an untrusted error naming %q", err, tc.wantErr)
			}

			// The same verdict at the spawn: substitute, or the host binary + a WARN.
			var logs bytes.Buffer
			sp := &fakeSpawner{}
			rt := newTestRuntimeCfg(t, Config{ShadowBinDir: dir, PathShimPath: testShim}, Deps{Spawner: sp})
			rt.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			rt.shadowLstat = lstat
			mustCreatePod(t, rt, nativeShellBox(rt, "pod-trust"))
			spec := sp.specs[len(sp.specs)-1]
			gotFile := spec.Argv[len(spec.Argv)-3]
			if tc.wantErr == "" {
				if gotFile != file {
					t.Errorf("exec file = %q, want the admitted copy %q", gotFile, file)
				}
				return
			}
			if gotFile != "/bin/sh" {
				t.Errorf("exec file = %q, want the host /bin/sh for an untrusted copy", gotFile)
			}
			if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), tc.wantErr) {
				t.Errorf("no WARN naming %q; log:\n%s", tc.wantErr, logs.String())
			}
		})
	}
}

// rootOwnedLstat is the production lstat with the owner forced to root: unit
// tests cannot create root-owned files, and every other property stays real.
func rootOwnedLstat(p string) (shadowStat, error) {
	st, err := lstatShadow(p)
	st.uid = 0
	return st, err
}

// TestShadowMapMatchesInterposer pins the C interposer's k3sm_shadow_map to
// the Go shadowCopies map by reading the source, so the spawn-time rewrite and
// the in-pod rewrite cannot drift apart.
func TestShadowMapMatchesInterposer(t *testing.T) {
	// go test runs in the package directory: pkg/runtime -> the repo root.
	src, err := os.ReadFile(filepath.Join("..", "..", "shim", "pathrebase_shim.c"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "k3sm_shadow_map[] = {")
	if start < 0 {
		t.Fatal("k3sm_shadow_map not found in shim/pathrebase_shim.c")
	}
	end := strings.Index(body[start:], "};")
	entry := regexp.MustCompile(`\{"([^"]+)", "([^"]+)"\}`)
	got := map[string]string{}
	for _, m := range entry.FindAllStringSubmatch(body[start:start+end], -1) {
		got[m[1]] = m[2]
	}
	if !maps.Equal(got, shadowCopies) {
		t.Errorf("interposer map %v != Go shadowCopies %v", got, shadowCopies)
	}
}

// shadowTestDir makes a fake shadow set (plain files: the spawn is faked).
func shadowTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"bash", "zsh", "dash", "env"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// nativeShellBox is a native-sentinel pod running /bin/sh -c.
func nativeShellBox(rt *Runtime, podID string) *runtimev1.PodBox {
	box := hostBinBox(rt, podID)
	box.Containers[0].Image = NativeImage
	box.Containers[0].Command = []string{"/bin/sh", "-c", "exec app"}
	return box
}

// TestShadowRewriteReachesTheSpawn proves the rewrite is what the exec-shim is
// handed: the copy as the file, the original argv[0] through ExecArgv0Env
// (and only in the spawn env, never in the container's own), and
// K3SM_SHADOW_DIR plus the interposer in the container env.
func TestShadowRewriteReachesTheSpawn(t *testing.T) {
	sp := &fakeSpawner{}
	dir := shadowTestDir(t)
	rt := newTestRuntimeCfg(t, Config{ShadowBinDir: dir, PathShimPath: testShim}, Deps{Spawner: sp})
	rt.shadowLstat = rootOwnedLstat
	mustCreatePod(t, rt, nativeShellBox(rt, "pod-sh"))

	sp.mu.Lock()
	spec := sp.specs[len(sp.specs)-1]
	sp.mu.Unlock()
	if got, want := spec.Argv[len(spec.Argv)-3:], []string{filepath.Join(dir, "bash"), "-c", "exec app"}; !slices.Equal(got, want) {
		t.Errorf("shim exec argv tail = %q, want %q", got, want)
	}
	if got := mustEnvValue(t, spec.Env, supervisor.ExecArgv0Env); got != "/bin/sh" {
		t.Errorf("%s = %q, want /bin/sh", supervisor.ExecArgv0Env, got)
	}
	if got := mustEnvValue(t, spec.Env, shadowDirEnv); got != dir {
		t.Errorf("%s = %q, want %q", shadowDirEnv, got, dir)
	}
	if got := mustEnvValue(t, spec.Env, dyldInsertEnv); got != testShim {
		t.Errorf("%s = %q, want the interposer %q even with no mounts", dyldInsertEnv, got, testShim)
	}
	rt.mu.Lock()
	p := rt.pods["pod-sh"]
	rt.mu.Unlock()
	p.mu.Lock()
	cpEnv := p.containers[0].env
	p.mu.Unlock()
	if _, ok := envValue(cpEnv, supervisor.ExecArgv0Env); ok {
		t.Errorf("the container env (what Exec enters) carries %s", supervisor.ExecArgv0Env)
	}

	t.Run("a missing copy keeps the host binary", func(t *testing.T) {
		sp := &fakeSpawner{}
		rt := newTestRuntimeCfg(t, Config{ShadowBinDir: t.TempDir(), PathShimPath: testShim}, Deps{Spawner: sp})
		rt.shadowLstat = rootOwnedLstat
		mustCreatePod(t, rt, nativeShellBox(rt, "pod-sh2"))
		spec := sp.specs[len(sp.specs)-1]
		if got := spec.Argv[len(spec.Argv)-3]; got != "/bin/sh" {
			t.Errorf("exec file = %q, want the host /bin/sh when the copy is absent", got)
		}
	})

	t.Run("ShadowBinDir empty is today's spawn", func(t *testing.T) {
		sp := &fakeSpawner{}
		rt := newTestRuntimeCfg(t, Config{PathShimPath: testShim}, Deps{Spawner: sp})
		mustCreatePod(t, rt, nativeShellBox(rt, "pod-sh3"))
		spec := sp.specs[len(sp.specs)-1]
		if got := spec.Argv[len(spec.Argv)-3]; got != "/bin/sh" {
			t.Errorf("exec file = %q, want /bin/sh", got)
		}
		for _, k := range []string{supervisor.ExecArgv0Env, shadowDirEnv, dyldInsertEnv} {
			if _, ok := envValue(spec.Env, k); ok {
				t.Errorf("%s set with the feature off", k)
			}
		}
	})
}

// TestShimInactiveConditionFromCodeSignFlags proves the detection's wiring:
// the flags read for the spawned pid after the exec become a
// k3sm.io/shim-inactive condition on the pod status, naming both losses; a
// csops error is reported as an unknown load (as loud as an unloaded one); a
// clean process and a pod with no shim requested produce none.
func TestShimInactiveConditionFromCodeSignFlags(t *testing.T) {
	cases := []struct {
		name       string
		flags      uint32
		err        error
		shim       bool
		want       bool
		wantReason string
		wantText   string
	}{
		{"platform binary", supervisor.CSPlatformBinary, nil, true, true, ShimInactiveReason, "CS_PLATFORM_BINARY"},
		{"restricted", supervisor.CSRestrict, nil, true, true, ShimInactiveReason, "CS_RESTRICT"},
		{"platform binary that is also hardened keeps the restricted reason", 0x26010b01, nil, true, true, ShimInactiveReason, "CS_PLATFORM_BINARY|CS_RESTRICT"},
		{"hardened runtime", supervisor.CSRuntime, nil, true, true, ShimInactiveHardenedReason, "com.apple.security.cs.allow-dyld-environment-variables"},
		{"library validation", supervisor.CSRequireLV, nil, true, true, ShimInactiveLibraryValidationReason, "CS_REQUIRE_LV"},
		{"re-signed copy", 0x22000201, nil, true, false, "", ""},
		{"csops error is an unknown load, reported", 0, errors.New("ESRCH"), true, true, ShimInactiveUnknownReason, "may be unavailable"},
		{"no shim requested: nothing to lose", supervisor.CSPlatformBinary, nil, false, false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var asked []int
			called := make(chan struct{})
			var once sync.Once
			css := func(pid int) (uint32, error) {
				mu.Lock()
				asked = append(asked, pid)
				mu.Unlock()
				once.Do(func() { close(called) })
				return tc.flags, tc.err
			}
			cfg := Config{}
			if tc.shim {
				cfg = Config{ShadowBinDir: shadowTestDir(t), PathShimPath: testShim}
			}
			rt := newTestRuntimeCfg(t, cfg, Deps{Spawner: &fakeSpawner{}, CodeSignStatus: css})
			box := hostBinBox(rt, "pod-cs")
			box.Containers[0].Image = "/usr/bin/python3"
			mustCreatePod(t, rt, box)

			// The observer runs on the reaper goroutine, after Start returned:
			// wait for it to have asked, then give the verdict write a bound.
			if tc.shim {
				select {
				case <-called:
				case <-time.After(5 * time.Second):
					t.Fatal("csops was never asked for the spawned pid")
				}
			}
			var cond *runtimev1.PodCondition
			deadline := time.Now().Add(time.Second)
			for {
				resp, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-cs"})
				if err != nil {
					t.Fatal(err)
				}
				cond = nil
				for _, c := range resp.GetStatus().GetConditions() {
					if c.GetType() == ShimInactiveConditionType {
						cond = c
					}
				}
				if cond != nil || time.Now().After(deadline) || (!tc.want && time.Now().After(deadline.Add(-800*time.Millisecond))) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			mu.Lock()
			defer mu.Unlock()
			if (cond != nil) != tc.want {
				t.Fatalf("condition present = %v, want %v (asked csops for %v)", cond != nil, tc.want, asked)
			}
			if tc.shim && len(asked) != 1 {
				t.Errorf("csops asked %d times, want once for the spawned pid", len(asked))
			}
			if cond == nil {
				return
			}
			if cond.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_TRUE || cond.GetReason() != tc.wantReason {
				t.Errorf("condition = %v/%q, want TRUE/%q", cond.GetStatus(), cond.GetReason(), tc.wantReason)
			}
			for _, part := range []string{"container main", "/usr/bin/python3", "DNS", "bind/connect", "node resolver", tc.wantText} {
				if !strings.Contains(cond.GetMessage(), part) {
					t.Errorf("message %q does not name %q", cond.GetMessage(), part)
				}
			}
		})
	}
}

// TestExecEnvCarriesConfiguredShadowDir pins the invariant that makes the
// unscrubbed K3SM_SHADOW_DIR safe: an Exec session (kubectl exec, an exec
// probe) enters an environment runtimed built from its own stored state and
// Config.ShadowBinDir, never one read back from a pod. The container's spec
// tries to aim the interposer at its own directory; the exec session still
// carries exactly the configured value, once.
func TestExecEnvCarriesConfiguredShadowDir(t *testing.T) {
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	dir := shadowTestDir(t)
	rt := newTestRuntimeCfg(t, Config{ShadowBinDir: dir, PathShimPath: testShim}, Deps{Backend: be, Waiter: w})
	box := hostBinBox(rt, "pod-exec-shadow")
	box.Containers[0].Env = []*runtimev1.EnvVar{{Name: shadowDirEnv, Value: t.TempDir()}}
	mustCreatePod(t, rt, box)
	defer w.release(1001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeExecStream(ctx)
	// /usr/bin/env is a platform binary: dyld ignores the (nonexistent) test
	// shim in DYLD_INSERT_LIBRARIES and it prints the environment it was given.
	st.feed(&runtimev1.ExecRequest{PodId: "pod-exec-shadow", Command: []string{"/usr/bin/env"}})
	st.closeSend()
	if err := rt.Exec(st); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	out, code := st.collect(t)
	if code != 0 {
		t.Fatalf("exec exit = %d; output:\n%s", code, out)
	}
	var got []string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, shadowDirEnv+"="); ok {
			got = append(got, v)
		}
	}
	if !slices.Equal(got, []string{dir}) {
		t.Errorf("exec session %s = %q, want exactly the configured [%q]", shadowDirEnv, got, dir)
	}
}

// gateRecorder is a Signer whose Check records the path it was asked about
// and rejects anything that is not a Mach-O (a script cannot carry a code
// signature, which is what the production codesign check reports for one).
type gateRecorder struct {
	mu    sync.Mutex
	asked []string
}

func (g *gateRecorder) Sign(context.Context, string) error { return nil }

func (g *gateRecorder) Check(_ context.Context, _ runtimev1.SignaturePolicy, path string) error {
	g.mu.Lock()
	g.asked = append(g.asked, path)
	g.mu.Unlock()
	head, err := os.ReadFile(path)
	if err != nil || len(head) < 4 || (!bytes.Equal(head[:4], machoMagic) && !bytes.Equal(head[:4], fatMagic)) {
		return fmt.Errorf("%w: %s is unsigned", image.ErrSignatureRejected, path)
	}
	return nil
}

func (g *gateRecorder) paths() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string{}, g.asked...)
}

// machoMagic is MH_MAGIC_64 as it lies on disk (little-endian); fatMagic is
// FAT_MAGIC (big-endian), the shape of Apple's universal /bin binaries.
var (
	machoMagic = []byte{0xcf, 0xfa, 0xed, 0xfe}
	fatMagic   = []byte{0xca, 0xfe, 0xba, 0xbe}
)

// TestScriptEntrypointIsGatedOnItsInterpreter is the rig finding's gate: a
// native pod whose command is a script used to fail the signature gate with
// "unsigned" (FAILURE_REASON_SIGNATURE_REJECTED, surfaced as an image-pull
// failure) because the gate was asked about the script. A script cannot
// carry a signature; the gate now answers for the interpreter the shebang
// names (a host shell even when its admitted shadow copy is what runs: the
// copy is node infrastructure, gated like a direct /bin/sh pod), or for any
// other interpreter as named. A file with no shebang is gated as itself.
func TestScriptEntrypointIsGatedOnItsInterpreter(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	shScript := write("entry.sh", "#!/bin/sh\necho hi\n", 0o755)
	pyScript := write("entry.py", "#!/usr/bin/python3\nprint(1)\n", 0o755)
	bare := write("bare.sh", "echo no shebang\n", 0o755)
	shadow := t.TempDir()
	for _, n := range []string{"bash", "zsh", "dash", "env"} {
		if err := os.WriteFile(filepath.Join(shadow, n), machoMagic, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name       string
		shadowDir  string
		script     string
		wantGate   string
		wantExec   []string // the exec argv tail handed to the shim
		wantArgv0  string   // ExecArgv0Env, "" = unset
		wantReject bool
	}{
		{"#!/bin/sh with a shadow set: the copy runs, gated on /bin/sh", shadow, shScript,
			"/bin/sh", []string{filepath.Join(shadow, "bash"), shScript, "a"}, "/bin/sh", false},
		{"#!/bin/sh without a shadow set: gated on /bin/sh, exec'd directly", "", shScript,
			"/bin/sh", []string{"/bin/sh", shScript, "a"}, "", false},
		{"#!/usr/bin/python3: gated on python3, the script still exec'd", shadow, pyScript,
			"/usr/bin/python3", []string{pyScript, "a"}, "", false},
		{"no shebang: gated on the file itself, still rejected", shadow, bare,
			bare, nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpawner{}
			gate := &gateRecorder{}
			cfg := Config{ShadowBinDir: tc.shadowDir}
			if tc.shadowDir != "" {
				cfg.PathShimPath = testShim
			}
			rt := newTestRuntimeCfg(t, cfg, Deps{Spawner: sp, Signer: gate})
			rt.shadowLstat = rootOwnedLstat
			box := hostBinBox(rt, "pod-script")
			box.Containers[0].Image = NativeImage
			box.Containers[0].Command = []string{tc.script, "a"}

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if got := gate.paths(); !slices.Contains(got, tc.wantGate) {
				t.Errorf("gate asked about %q, want it to answer for %q", got, tc.wantGate)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
			}
			// A rejected signature is container-class (B119): the container
			// waits with the typed reason, which the node reports as the
			// image failure the rig saw.
			reason := statusNamed(t, rt, "pod-script", "main").GetState().GetWaiting().GetFailureReason()
			if tc.wantReject {
				if reason != runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED {
					t.Errorf("waiting failure_reason = %v, want SIGNATURE_REJECTED for a file with no shebang", reason)
				}
				return
			}
			if reason == runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED {
				t.Fatalf("waiting failure_reason = SIGNATURE_REJECTED: a script naming a readable interpreter is not an image failure")
			}
			if slices.Contains(gate.paths(), tc.script) {
				t.Errorf("the gate was asked about the script %q itself", tc.script)
			}
			if len(sp.specs) == 0 {
				t.Fatal("nothing was spawned")
			}
			spec := sp.specs[len(sp.specs)-1]
			if got := spec.Argv[len(spec.Argv)-len(tc.wantExec):]; !slices.Equal(got, tc.wantExec) {
				t.Errorf("exec argv tail = %q, want %q", got, tc.wantExec)
			}
			got, _ := envValue(spec.Env, supervisor.ExecArgv0Env)
			if got != tc.wantArgv0 {
				t.Errorf("%s = %q, want %q", supervisor.ExecArgv0Env, got, tc.wantArgv0)
			}
		})
	}
}
