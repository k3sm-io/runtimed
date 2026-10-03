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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/internal/testwire"
	"k3sm.io/runtimed/pkg/image"
)

// victimPodID is the pod whose materialized data volume the cross-pod and
// case-alias cases aim at. It is a legal (lowercase) id, and no pod with it is
// ever created, so any change under its directory is an escape.
const victimPodID = "pod-victim"

// retiredFieldWarning is the exact message the runtime logs for a box carrying
// the retired PodBox field 4.
const retiredFieldWarning = "PodBox carries retired field 4; ignored"

// permTree lists every path under root with its type, permission bits, setgid
// bit and owning gid — the shape tree() has, plus exactly the attributes
// ChownForFSGroup mutates. tree() alone cannot see an fsGroup escalation: it
// creates no files, it only re-modes and re-groups the ones already there.
func permTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		gid := -1
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			gid = int(st.Gid)
		}
		out = append(out, rel+"|"+info.Mode().String()+"|gid="+strconv.Itoa(gid))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

// levelCapture is a slog.Handler that keeps every record's level, message and
// attrs (flattened to their string values) under a mutex, so the gate asserts
// on what the runtime logged structurally rather than on a rendering of it.
type levelCapture struct {
	mu      sync.Mutex
	records []leveledRecord
}

type leveledRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

func (c *levelCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *levelCapture) Handle(_ context.Context, r slog.Record) error {
	rec := leveledRecord{level: r.Level, msg: r.Message, attrs: make(map[string]string, r.NumAttrs())}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	c.mu.Lock()
	c.records = append(c.records, rec)
	c.mu.Unlock()
	return nil
}

func (c *levelCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *levelCapture) WithGroup(string) slog.Handler      { return c }

// retiredWarnings returns the retired-field records logged for podID.
func (c *levelCapture) retiredWarnings(podID string) []leveledRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []leveledRecord
	for _, r := range c.records {
		if r.msg == retiredFieldWarning && r.attrs["pod_id"] == podID {
			out = append(out, r)
		}
	}
	return out
}

// assertOneRetiredWarning asserts exactly one Warn record for podID carrying
// value, since the given count of earlier records for the same pod.
func assertOneRetiredWarning(t *testing.T, logs *levelCapture, podID, value string, before int) {
	t.Helper()
	got := logs.retiredWarnings(podID)
	if len(got) != before+1 {
		t.Fatalf("%d retired-field warnings for %s, want %d (one per call)", len(got), podID, before+1)
	}
	w := got[len(got)-1]
	if w.level != slog.LevelWarn {
		t.Errorf("retired-field record level = %v, want WARN", w.level)
	}
	if w.attrs["value"] != value {
		t.Errorf("retired-field record value = %q, want %q", w.attrs["value"], value)
	}
}

// TestCreatePodIgnoresCallerRootfsPath is the gate for retiring the PodBox
// rootfs field (number 4): the daemon derives every pod's rootfs from its id and
// never reads a caller-supplied path. A box that carries field 4 — injected on
// the wire, so the test means "an old producer or a confined pod sent it"
// whether or not the schema still declares the field — is created normally on
// the derived <Root>/pods/<id>/rootfs, leaves every other tree untouched, and
// produces one Warn line naming the pod.
//
// It never skips. A skipped security leg reports green, so a root-run test
// process fails instead of passing vacuously.
//
// The victim-tree assertions are the load-bearing half. A daemon that honored
// the value would run os.MkdirAll, mount.Materialize and
// supervisor.ChownForFSGroup (to this process's own gid, so the effects succeed
// rather than failing with EPERM) against the hostile path, and the before/after
// permTree snapshots of the victim trees would differ.
func TestCreatePodIgnoresCallerRootfsPath(t *testing.T) {
	gid := os.Getgid()
	if gid <= 0 {
		t.Fatal("test process gid <= 0 (running as root?): this gate runs unprivileged by design — the fsGroup sink assertions need a >0 gid the test owns — so run it as a normal user rather than skipping a security leg")
	}

	t.Run("hostile-values-are-ignored", func(t *testing.T) {
		// One shared root for Config.Root and the image cache (the production
		// wiring), nested inside an observable parent so an escape above the
		// root is visible.
		outside := t.TempDir()
		root := filepath.Join(outside, "a", "b", "k3sm")
		cache, err := image.NewCache(root)
		if err != nil {
			t.Fatalf("NewCache: %v", err)
		}
		// Siblings of the pods tree inside the daemon root: the control-plane
		// state dir is the case a bare root-prefix check would admit.
		mustMkdirMode(t, filepath.Join(root, "server", "db"), 0o700)
		mustWrite(t, filepath.Join(root, "server", "k3sm.kubeconfig"), "sentinel")
		// A sibling of the ROOT whose name merely starts with it.
		evil := filepath.Join(outside, "a", "b", "k3sm-evil")
		mustMkdirMode(t, evil, 0o700)

		logs := &levelCapture{}
		rt := newTestRuntimeCfg(t, Config{Root: root, Logger: slog.New(logs)}, testDeps(t, Deps{Cache: cache}))
		podsRoot := cache.PodsRoot()

		// The victim pod's materialized data volume (secrets + projected
		// SA-token live here in production), pre-created at 0o700 so a fsGroup
		// pass would have something observable to widen.
		victimID := mustPodID(t, victimPodID)
		victimRootfs := cache.PodRootfs(victimID)
		mustMkdirMode(t, filepath.Join(victimRootfs, "var", "run", "secrets"), 0o700)
		mustWrite(t, filepath.Join(victimRootfs, "var", "run", "secrets", "token"), "VICTIM-SA-TOKEN")

		// The attacker's own data volume, with a symlink planted inside it
		// pointing at the daemon root. A pod's own rootfs is writable at both
		// the POSIX and the SBPL layer, so planting this link is within a
		// confined pod's reach.
		const symlinkPodID = "pod-symlink"
		symlinkRootfs := cache.PodRootfs(mustPodID(t, symlinkPodID))
		mustMkdirMode(t, symlinkRootfs, 0o700)
		if err := os.Symlink(root, filepath.Join(symlinkRootfs, "link")); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		victims := func() []string {
			var out []string
			for _, v := range []string{filepath.Join(root, "server"), cache.PodDir(victimID), evil} {
				for _, e := range permTree(t, v) {
					out = append(out, v+"/"+e)
				}
			}
			// The symlink's target is the daemon root itself; its own mode and
			// group are part of what a followed chmod would change.
			fi, err := os.Stat(root)
			if err != nil {
				t.Fatalf("stat %s: %v", root, err)
			}
			return append(out, root+"|"+fi.Mode().String()+"|gid="+strconv.Itoa(int(fi.Sys().(*syscall.Stat_t).Gid)))
		}
		before := victims()

		cases := []struct {
			name  string
			podID string
			// field4 is the hostile value carried in field 4.
			field4 string
			// absent, when non-empty, must not exist on disk after the call.
			absent string
		}{{
			name:   "the-runtime-work-root",
			podID:  "pod-esc-root",
			field4: root,
		}, {
			name:   "absolute-escape-outside-the-daemon-root",
			podID:  "pod-esc-abs",
			field4: filepath.Join(evil, "loot"),
			absent: filepath.Join(evil, "loot"),
		}, {
			name:   "inside-the-root-outside-the-pods-tree",
			podID:  "pod-esc-server",
			field4: filepath.Join(root, "server"),
		}, {
			name:   "cross-pod-into-another-pods-rootfs",
			podID:  "pod-esc-cross",
			field4: victimRootfs,
		}, {
			// The default APFS volume is case-insensitive, so this names the
			// victim's directory while spelling a different id.
			name:   "uppercase-id-alias-on-case-insensitive-apfs",
			podID:  "pod-esc-case",
			field4: filepath.Join(podsRoot, strings.ToUpper(victimPodID), "rootfs"),
		}, {
			// Lexically under the pod's own rootfs, but "link" leads to the
			// daemon root.
			name:   "symlink-hop-out-of-the-pods-own-rootfs",
			podID:  symlinkPodID,
			field4: filepath.Join(symlinkRootfs, "link", "server"),
		}, {
			name:   "relative-path",
			podID:  "pod-esc-rel",
			field4: "pods/pod-esc-rel/rootfs",
			absent: filepath.Join(outside, "pods"),
		}, {
			name:   "dot-dot-traversal-uncleaned",
			podID:  "pod-esc-dots",
			field4: podsRoot + "/pod-esc-dots/rootfs/../../../server",
		}, {
			name:   "firmlink-alias-of-the-derived-path",
			podID:  "pod-esc-firmlink",
			field4: "/private" + cache.PodRootfs(mustPodID(t, "pod-esc-firmlink")),
		}}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				box := hostBinBox(rt, tc.podID)
				box.PodSecurityContext = &runtimev1.PodSecurityContext{FsGroup: int64(gid)}
				p := assertCreatesDerivedRootfs(t, rt, logs, box, tc.field4)
				if strings.Contains(p.profile, "(allow file-read* file-write*\n  (subpath \""+tc.field4+"\")") {
					t.Errorf("the pod's SBPL profile re-allows the field-4 value %q", tc.field4)
				}
				if tc.absent != "" {
					if _, err := os.Stat(tc.absent); !os.IsNotExist(err) {
						t.Errorf("%s exists after the create (err=%v); the field-4 value reached MkdirAll", tc.absent, err)
					}
				}
			})
		}

		if got := victims(); !slices.Equal(before, got) {
			t.Errorf("a field-4 value mutated a victim tree\nbefore: %v\ndiff:   %v", before, diffTrees(before, got))
		}
	})

	t.Run("derived-spelling-is-the-same-as-empty", func(t *testing.T) {
		logs := &levelCapture{}
		rt := newTestRuntimeCfg(t, Config{Logger: slog.New(logs)}, Deps{})
		assertCreatesDerivedRootfs(t, rt, logs, hostBinBox(rt, "pod-ok-empty"), "")
		assertCreatesDerivedRootfs(t, rt, logs, hostBinBox(rt, "pod-ok-derived"), derivedRootfs(t, rt, "pod-ok-derived"))
	})

	t.Run("update-differing-only-in-field-4-is-updatable", func(t *testing.T) {
		logs := &levelCapture{}
		rt := newTestRuntimeCfg(t, Config{Logger: slog.New(logs)}, Deps{})
		hostile := rt.cfg.Root

		for _, tc := range []struct {
			name, podID          string
			createdWith, updated string
		}{
			{"added-by-the-update", "pod-upd-add", "", hostile},
			{"dropped-by-the-update", "pod-upd-drop", hostile, ""},
			{"changed-by-the-update", "pod-upd-change", derivedRootfs(t, rt, "pod-upd-change"), hostile},
		} {
			t.Run(tc.name, func(t *testing.T) {
				box := hostBinBox(rt, tc.podID)
				if tc.createdWith != "" {
					box = testwire.WithWireField4(t, box, tc.createdWith)
				}
				mustCreatePod(t, rt, box)

				upd := hostBinBox(rt, tc.podID)
				upd.Labels = map[string]string{"app": "updated"}
				if tc.updated != "" {
					upd = testwire.WithWireField4(t, upd, tc.updated)
				}
				warned := len(logs.retiredWarnings(tc.podID))
				resp, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: upd})
				if err != nil {
					t.Fatalf("UpdatePod transport: %v", err)
				}
				if got := resp.GetFailureReason(); got == runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
					t.Fatalf("UpdatePod = NOT_UPDATABLE (%v); a box differing only in field 4 must update in place", resp.GetError())
				}
				if resp.GetError() != nil {
					t.Fatalf("UpdatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
				}
				if tc.updated != "" {
					assertOneRetiredWarning(t, logs, tc.podID, tc.updated, warned)
				} else if n := len(logs.retiredWarnings(tc.podID)); n != warned {
					t.Errorf("an update without field 4 logged %d retired-field warning(s)", n-warned)
				}
			})
		}
	})

	t.Run("exec-and-restart-use-the-derivation", func(t *testing.T) {
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		logs := &levelCapture{}
		rt := newTestRuntimeCfg(t, Config{Logger: slog.New(logs)}, Deps{Spawner: sp, Waiter: w})
		rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
		rt.signalGroup = rec.signal

		const podID = "pod-off-spine"
		hostile := rt.cfg.Root
		mustCreatePod(t, rt, testwire.WithWireField4(t, hostBinBox(rt, podID), hostile))
		derived := derivedRootfs(t, rt, podID)

		p, ok := rt.lookupPod(podID)
		if !ok {
			t.Fatal("pod not registered after CreatePod")
		}
		if v, ok := retiredRootfsField(p.box); !ok || v != hostile {
			t.Fatalf("stored box field 4 = (%q, %v), want the injected %q (else this row tests nothing)", v, ok, hostile)
		}
		// Exec resolves its rootfs through rootfsPath on the stored box, and
		// its cwd from the container's resolved workingDir, else that rootfs.
		if got, err := rt.rootfsPath(p.box); err != nil || got != derived {
			t.Errorf("rootfsPath(stored box) = (%q, %v), want (%q, nil)", got, err, derived)
		}
		p.mu.Lock()
		execDir := p.containers[0].workingDir
		p.mu.Unlock()
		if execDir != derived {
			t.Errorf("Exec cwd source = %q, want the derived %q", execDir, derived)
		}

		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: podID, Container: "main", Reason: "liveness probe failed",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		sp.mu.Lock()
		specs := slices.Clone(sp.specs)
		sp.mu.Unlock()
		if len(specs) != 2 {
			t.Fatalf("spawns = %d, want 2 (create + restart)", len(specs))
		}
		for i, s := range specs {
			if s.Dir != derived {
				t.Errorf("spawn %d Dir = %q, want the derived %q", i, s.Dir, derived)
			}
		}
	})

	t.Run("vm-share-roots-equal-the-clean-run", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		const podID = "pod-vm-field4"
		cleanRoots := vmShareRoots(mustPlanVM(t, rt, vmb, vmShareBox(podID)))
		if len(cleanRoots) == 0 {
			t.Fatal("clean vm run recorded no shares (vacuous comparison)")
		}
		hostiles := []string{rt.cfg.Root, filepath.Join(rt.cfg.Root, "pods", victimPodID, "rootfs")}
		for i, v := range hostiles {
			if _, _, err := rt.createPod(context.Background(), testwire.WithWireField4(t, vmShareBox(podID), v)); err == nil {
				t.Fatal("vm createPod should surface the lab-gated boot error")
			}
			n, spec := vmb.created()
			if want := 2 + i; n != want {
				t.Fatalf("field 4 = %q: CreateVM called %d times, want %d", v, n, want)
			}
			if got := vmShareRoots(spec); !slices.Equal(got, cleanRoots) {
				t.Errorf("field 4 = %q moved share roots:\n  got:   %v\n  clean: %v", v, got, cleanRoots)
			}
		}
	})

	t.Run("detector", func(t *testing.T) {
		tag4 := func(b []byte, v string) []byte {
			return protowire.AppendString(protowire.AppendTag(b, 4, protowire.BytesType), v)
		}
		withUnknown := func(raw []byte) *runtimev1.PodBox {
			box := &runtimev1.PodBox{PodId: "pod-detect"}
			box.ProtoReflect().SetUnknown(raw)
			return box
		}
		varint4 := protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.VarintType), 7)
		otherField := protowire.AppendVarint(protowire.AppendTag(nil, 9999, protowire.VarintType), 1)
		truncated := protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.BytesType), 100)
		truncated = append(truncated, "abc"...)

		for _, tc := range []struct {
			name   string
			box    *runtimev1.PodBox
			want   string
			wantOK bool
		}{
			{"nil box", nil, "", false},
			{"absent", &runtimev1.PodBox{PodId: "pod-detect"}, "", false},
			{"bytes value on the wire", testwire.WithWireField4(t, &runtimev1.PodBox{PodId: "pod-detect"}, "/x"), "/x", true},
			{"bytes value in the unknown set", withUnknown(tag4(nil, "/u")), "/u", true},
			{"after another unknown field", withUnknown(tag4(otherField, "/after")), "/after", true},
			{"varint-typed tag 4 is not the field", withUnknown(varint4), "", false},
			{"duplicated tag 4: last wins", withUnknown(tag4(tag4(nil, "/first"), "/second")), "/second", true},
			{"duplicated on the wire: last wins", testwire.WithWireField4(t, testwire.WithWireField4(t, &runtimev1.PodBox{}, "/first"), "/second"), "/second", true},
			{"truncated bytes: no value", withUnknown(truncated), "", false},
			{"truncated tail keeps the earlier value", withUnknown(append(tag4(nil, "/good"), truncated...)), "/good", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, ok := retiredRootfsField(tc.box)
				if got != tc.want || ok != tc.wantOK {
					t.Errorf("retiredRootfsField = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
				}
			})
		}

		t.Run("a 10 KiB value is logged truncated to the cap", func(t *testing.T) {
			logs := &levelCapture{}
			rt := newTestRuntimeCfg(t, Config{Logger: slog.New(logs)}, Deps{})
			long := strings.Repeat("a", 10<<10)
			rt.warnRetiredRootfsField(testwire.WithWireField4(t, &runtimev1.PodBox{PodId: "pod-long"}, long))
			assertOneRetiredWarning(t, logs, "pod-long", long[:retiredFieldLogCap]+"…(truncated)", 0)
		})

		// UpdatePod logs before the pod id is validated, so the id is capped too.
		t.Run("a 10 KiB pod id is logged truncated to the cap", func(t *testing.T) {
			logs := &levelCapture{}
			rt := newTestRuntimeCfg(t, Config{Logger: slog.New(logs)}, Deps{})
			longID := strings.Repeat("p", 10<<10)
			rt.warnRetiredRootfsField(testwire.WithWireField4(t, &runtimev1.PodBox{PodId: longID}, "x"))
			assertOneRetiredWarning(t, logs, longID[:retiredFieldLogCap]+"…(truncated)", "x", 0)
		})
	})
}

// assertCreatesDerivedRootfs drives a real CreatePod for box, with field4
// injected on the wire when non-empty, and asserts the pod lives on the derived
// <Root>/pods/<id>/rootfs: the directory exists, rootfsPath on the stored box
// returns it, the main container's working dir (the Exec cwd source) is it, and
// the SBPL profile re-allows it. A non-empty field4 must produce exactly one
// Warn naming the pod and the value; an empty one, none. It returns the pod.
func assertCreatesDerivedRootfs(t *testing.T, rt *Runtime, logs *levelCapture, box *runtimev1.PodBox, field4 string) *pod {
	t.Helper()
	podID := box.GetPodId()
	if field4 != "" {
		box = testwire.WithWireField4(t, box, field4)
	}
	warned := len(logs.retiredWarnings(podID))

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod(field 4 = %q) failed: %v (reason %v); a box carrying field 4 must be created, not refused", field4, resp.GetError(), resp.GetFailureReason())
	}
	want := derivedRootfs(t, rt, podID)
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Fatalf("stat %s = (%v, %v), want the derived pod rootfs to exist", want, fi, err)
	}
	p, ok := rt.lookupPod(podID)
	if !ok {
		t.Fatalf("pod %s not registered after CreatePod", podID)
	}
	if got, err := rt.rootfsPath(p.box); err != nil || got != want {
		t.Errorf("rootfsPath(stored box) = (%q, %v), want (%q, nil)", got, err, want)
	}
	p.mu.Lock()
	cwd := p.containers[0].workingDir
	p.mu.Unlock()
	if cwd != want {
		t.Errorf("container working dir = %q, want the derived %q", cwd, want)
	}
	if !strings.Contains(p.profile, "(allow file-read* file-write*\n  (subpath \""+want+"\")") {
		t.Errorf("the SBPL profile does not re-allow the derived data volume %q", want)
	}
	if field4 != "" {
		assertOneRetiredWarning(t, logs, podID, field4, warned)
	} else if n := len(logs.retiredWarnings(podID)); n != warned {
		t.Errorf("a box without field 4 logged %d retired-field warning(s)", n-warned)
	}
	return p
}

func mustPodID(t *testing.T, s string) image.PodID {
	t.Helper()
	id, err := image.ParsePodID(s)
	if err != nil {
		t.Fatalf("ParsePodID(%q): %v", s, err)
	}
	return id
}

func mustMkdirMode(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, mode); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	// MkdirAll applies umask; force the exact mode so the fsGroup widening is
	// observable (0o700 -> 0o770|setgid).
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
}

// diffTrees returns the entries that differ between two permTree snapshots, so a
// failure names the escape instead of dumping the whole filesystem twice.
func diffTrees(before, after []string) []string {
	var out []string
	for _, a := range after {
		if !slices.Contains(before, a) {
			out = append(out, "+"+a)
		}
	}
	for _, b := range before {
		if !slices.Contains(after, b) {
			out = append(out, "-"+b)
		}
	}
	return out
}
