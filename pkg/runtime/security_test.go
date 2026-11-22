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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestResolveRlimitPlan is the pure daemon-side resolver table: it maps the
// explicit PodBox.rlimits[] to a []supervisor.PlannedRlimit and only those —
// every recognized type resolves to its darwin RLIMIT_* selector, soft/hard are
// carried verbatim, "unlimited" sentinels collapse to RLIM_INFINITY, and an
// unknown type is skipped. The negative case is load-bearing: a pod with a memory
// limit and a cpu quota (Guaranteed QoS) but no explicit rlimits[] yields an empty
// plan — runtimed never synthesizes RLIMIT_AS/DATA/CPU from those bands.
func TestResolveRlimitPlan(t *testing.T) {
	cases := []struct {
		name string
		box  *runtimev1.PodBox
		want []supervisor.PlannedRlimit
	}{
		{
			name: "explicit-nofile-soft-hard-verbatim",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 4096},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}},
			},
		},
		{
			// Every recognized type maps to the correct selector. RLIMIT_CPU is
			// included only because it is explicitly named here (the zero-value trap).
			name: "all-recognized-types-map-correctly",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NPROC", Soft: 64, Hard: 128},
				{Type: "RLIMIT_AS", Soft: 1 << 20, Hard: 1 << 21},
				{Type: "RLIMIT_CORE", Soft: 0, Hard: 0},
				{Type: "RLIMIT_STACK", Soft: 8 << 20, Hard: 16 << 20},
				{Type: "RLIMIT_DATA", Soft: 1, Hard: 2},
				{Type: "RLIMIT_FSIZE", Soft: 3, Hard: 4},
				{Type: "RLIMIT_CPU", Soft: 10, Hard: 20},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NPROC, Lim: unix.Rlimit{Cur: 64, Max: 128}},
				{Resource: unix.RLIMIT_AS, Lim: unix.Rlimit{Cur: 1 << 20, Max: 1 << 21}},
				{Resource: unix.RLIMIT_CORE, Lim: unix.Rlimit{Cur: 0, Max: 0}},
				{Resource: unix.RLIMIT_STACK, Lim: unix.Rlimit{Cur: 8 << 20, Max: 16 << 20}},
				{Resource: unix.RLIMIT_DATA, Lim: unix.Rlimit{Cur: 1, Max: 2}},
				{Resource: unix.RLIMIT_FSIZE, Lim: unix.Rlimit{Cur: 3, Max: 4}},
				{Resource: unix.RLIMIT_CPU, Lim: unix.Rlimit{Cur: 10, Max: 20}},
			},
		},
		{
			name: "unlimited-sentinels-map-to-rlim-infinity",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: ^uint64(0), Hard: uint64(unix.RLIM_INFINITY)},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}},
			},
		},
		{
			// (c) negative: a memory limit + a cpu quota (Guaranteed QoS) but NO
			// explicit rlimits[] yields an empty plan — nothing is synthesized.
			name: "memory-and-cpu-quota-without-explicit-rlimits-is-empty",
			box: &runtimev1.PodBox{
				MemoryLimitBytes: 512 << 20,
				QosClass:         runtimev1.QOSClass_QOS_CLASS_GUARANTEED,
			},
			want: nil,
		},
		{
			// (d) an unknown type is skipped, never applied as the zero-value
			// resource (RLIMIT_CPU on darwin); the recognized sibling still maps.
			name: "unknown-type-skipped-recognized-kept",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_BOGUS", Soft: 1, Hard: 2},
				{Type: "RLIMIT_NOFILE", Soft: 100, Hard: 200},
			}},
			want: []supervisor.PlannedRlimit{
				{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 100, Max: 200}},
			},
		},
		{
			// An unknown type alone yields an empty plan — proof it was skipped, not
			// mapped to resource 0 (RLIMIT_CPU).
			name: "unknown-type-only-is-empty",
			box: &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
				{Type: "NOT_A_RLIMIT", Soft: 1, Hard: 2},
			}},
			want: nil,
		},
		{
			name: "no-rlimits-is-empty",
			box:  &runtimev1.PodBox{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRlimitPlan(tc.box)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resolveRlimitPlan = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestResolveBgQoS pins the QoS mapping decision (apis QOSClass → the
// supervisor-local background flag), made here in the runtime layer so the
// supervisor stays decoupled from apis: BEST_EFFORT and UNSPECIFIED map to the
// darwin background band (PRIO_DARWIN_BG via the launch sequence); GUARANTEED,
// BURSTABLE, and any unknown/future enum value map to NO setpriority call at all
// (downward-only — the default band is the absence of the call, never an
// explicit reset-to-0). The unknown-value case is load-bearing: backgrounding
// must be the explicitly-enumerated branch, so a future additive apis QOSClass
// value is never silently BG-throttled by a stale runtimed.
func TestResolveBgQoS(t *testing.T) {
	cases := []struct {
		name string
		qos  runtimev1.QOSClass
		want bool
	}{
		{"besteffort-backgrounds", runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT, true},
		{"unspecified-backgrounds", runtimev1.QOSClass_QOS_CLASS_UNSPECIFIED, true},
		{"guaranteed-untouched", runtimev1.QOSClass_QOS_CLASS_GUARANTEED, false},
		{"burstable-untouched", runtimev1.QOSClass_QOS_CLASS_BURSTABLE, false},
		{"unknown-future-enum-value-untouched", runtimev1.QOSClass(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveBgQoS(&runtimev1.PodBox{QosClass: tc.qos}); got != tc.want {
				t.Fatalf("resolveBgQoS(%v) = %v, want %v", tc.qos, got, tc.want)
			}
		})
	}
}

// TestResolveRlimitPlan_UnknownTypeWarnsAndSkips proves the comma-ok contract:
// an unrecognized type is skipped with a slog.Warn and is never applied as the
// zero-value resource — which on darwin is RLIMIT_CPU (0x0), a cumulative
// CPU-seconds killer. The empty plan is the proof it did not fall through to 0.
func TestResolveRlimitPlan_UnknownTypeWarnsAndSkips(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	box := &runtimev1.PodBox{Rlimits: []*runtimev1.ResourceLimit{
		{Type: "RLIMIT_BOGUS", Soft: 1, Hard: 2},
	}}
	got := resolveRlimitPlan(box)
	if len(got) != 0 {
		t.Fatalf("unknown rlimit type must be skipped (empty plan), got %+v", got)
	}
	if !strings.Contains(buf.String(), "unknown rlimit type") {
		t.Errorf("expected a warning for the unknown type, slog output = %q", buf.String())
	}
}

// TestPodUIDInLoginRangeRefused pins the second keystore layer: a native pod
// whose drop target is a uid of 501 or above is refused before the command is
// wrapped, whichever field asked for the uid, and so is a drop that
// leaves the process at uid 0 (runAsGroup alone), and so is a drop to the
// service user's uid (testService), or any drop when the service user could not
// be resolved. uids 300 and 500 are the controls. The spawn-time half is
// supervisor.TestRunLaunchSequenceRefusesPodUID. With no drop the inherited euid
// is allowed, root and a rootless server's login uid alike.
func TestPodUIDInLoginRangeRefused(t *testing.T) {
	r := &Runtime{service: testService, lookupGroup: noHostGroups}
	type src struct {
		name string
		box  func(uid int64) (*runtimev1.PodBox, *runtimev1.Container)
	}
	srcs := []src{
		{"container runAsUser", func(uid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{}, &runtimev1.Container{SecurityContext: &runtimev1.SecurityContext{RunAsUser: uid, RunAsGroup: 300}}
		}},
		{"pod runAsUser", func(uid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: uid, RunAsGroup: 300}}, &runtimev1.Container{}
		}},
		{"box uid", func(uid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{Uid: uint32(uid), Gid: 300}, &runtimev1.Container{}
		}},
	}
	for _, s := range srcs {
		for _, uid := range []int64{501, 502, 2147483647} {
			t.Run(s.name+"/refused", func(t *testing.T) {
				box, c := s.box(uid)
				cred := resolveCredential(box, c)
				if err := r.checkPodUID(cred); !errors.Is(err, supervisor.ErrPodUIDRefused) {
					t.Errorf("uid %d: err = %v, want ErrPodUIDRefused", uid, err)
				}
			})
		}
		t.Run(s.name+"/service user refused", func(t *testing.T) {
			box, c := s.box(int64(testService.UID))
			if err := r.checkPodUID(resolveCredential(box, c)); !errors.Is(err, supervisor.ErrPodUIDRefused) {
				t.Errorf("uid %d: err = %v, want ErrPodUIDRefused", testService.UID, err)
			}
		})
		for _, uid := range []int64{300, 500} {
			t.Run(fmt.Sprintf("%s/uid %d allowed", s.name, uid), func(t *testing.T) {
				box, c := s.box(uid)
				if err := r.checkPodUID(resolveCredential(box, c)); err != nil {
					t.Errorf("uid %d: %v", uid, err)
				}
			})
		}
		t.Run(s.name+"/unresolved service user refuses every drop", func(t *testing.T) {
			box, c := s.box(300)
			unknown := &Runtime{lookupGroup: noHostGroups, serviceErr: errors.New("directory services down")}
			if err := unknown.checkPodUID(resolveCredential(box, c)); !errors.Is(err, supervisor.ErrPodUIDRefused) {
				t.Errorf("err = %v, want ErrPodUIDRefused", err)
			}
		})
	}
	for name, box := range map[string]*runtimev1.PodBox{
		"pod runAsGroup only": {PodSecurityContext: &runtimev1.PodSecurityContext{RunAsGroup: 300}},
		"box gid only":        {Gid: 300},
	} {
		t.Run("uid 0 after the drop/"+name, func(t *testing.T) {
			cred := resolveCredential(box, &runtimev1.Container{})
			if !cred.Drop || cred.UID != 0 {
				t.Fatalf("fixture: cred = %+v, want a drop to uid 0", cred)
			}
			if err := r.checkPodUID(cred); !errors.Is(err, supervisor.ErrPodUIDRefused) {
				t.Errorf("err = %v, want ErrPodUIDRefused", err)
			}
		})
	}
	// No drop: the pod inherits the daemon's own uid, root or a rootless
	// developer's login uid, and holds nothing that uid does not already hold.
	// Each euid is the one the dropping process would check against
	// (Credential.Validate), so the case is judged as that daemon would judge
	// it, and a drop to 500, the last uid on the allowed side, runs only under
	// a root daemon.
	noDrop := resolveCredential(&runtimev1.PodBox{}, &runtimev1.Container{})
	if noDrop.Drop {
		t.Fatalf("fixture: cred = %+v, want no drop", noDrop)
	}
	boundary := resolveCredential(&runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 500, RunAsGroup: 300}}, &runtimev1.Container{})
	for _, tc := range []struct {
		euid    int
		cred    supervisor.Credential
		allowed bool
	}{
		{501, noDrop, true},
		{0, noDrop, true},
		{testService.UID, noDrop, true},
		{0, boundary, true},
		{testService.UID, boundary, false},
		{501, boundary, false},
	} {
		t.Run(fmt.Sprintf("euid %d drop %v to uid %d", tc.euid, tc.cred.Drop, tc.cred.UID), func(t *testing.T) {
			err := tc.cred.Validate(tc.euid)
			if err == nil {
				err = r.checkPodUID(tc.cred)
			}
			if tc.allowed && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.allowed && !errors.Is(err, supervisor.ErrDropRequiresRoot) {
				t.Errorf("err = %v, want ErrDropRequiresRoot", err)
			}
		})
	}
}

// TestPodGroupsRefused pins the group half of the pod-only rule before a
// command is wrapped: a drop whose runAsGroup (container or pod), box gid or
// fsGroup is staff, admin, a system group such as operator (5), procmod (9)
// or _developer (204), the service user's primary gid, 501 or above or past
// the gid_t range is refused, read from the int64 field as sent; a pod with
// the other gids up to 500 (300, 400) is allowed when the host assigns them no
// group (the fixtures pin noHostGroups), and refused through the runtime's
// Deps.lookupGroup when it is a host-assigned system group. A pod with no drop
// is not judged on the groups it would have asked for.
func TestPodGroupsRefused(t *testing.T) {
	r := &Runtime{service: testService, lookupGroup: noHostGroups}
	srcs := map[string]func(gid int64) (*runtimev1.PodBox, *runtimev1.Container){
		"container runAsGroup": func(gid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{}, &runtimev1.Container{SecurityContext: &runtimev1.SecurityContext{RunAsUser: 300, RunAsGroup: gid}}
		},
		"pod runAsGroup": func(gid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 300, RunAsGroup: gid}}, &runtimev1.Container{}
		},
		"fsGroup": func(gid int64) (*runtimev1.PodBox, *runtimev1.Container) {
			return &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 300, RunAsGroup: 300, FsGroup: gid}}, &runtimev1.Container{}
		},
	}
	for name, src := range srcs {
		for _, gid := range []int64{5, 9, 20, 80, 204, int64(testService.GID), 501, 999, math.MaxUint32 + 1, 1<<32 + 20} {
			t.Run(fmt.Sprintf("%s %d refused", name, gid), func(t *testing.T) {
				box, c := src(gid)
				if err := r.checkPodUID(resolveCredential(box, c)); !errors.Is(err, supervisor.ErrPodGroupRefused) {
					t.Errorf("err = %v, want ErrPodGroupRefused", err)
				}
			})
		}
		for _, gid := range []int64{300, 400} {
			t.Run(fmt.Sprintf("%s %d allowed", name, gid), func(t *testing.T) {
				box, c := src(gid)
				if err := r.checkPodUID(resolveCredential(box, c)); err != nil {
					t.Errorf("gid %d: %v", gid, err)
				}
			})
		}
	}
	for _, gid := range []uint32{5, 204, 20, 80, 501} {
		t.Run(fmt.Sprintf("box gid %d refused", gid), func(t *testing.T) {
			box := &runtimev1.PodBox{Uid: 300, Gid: gid}
			if err := r.checkPodUID(resolveCredential(box, &runtimev1.Container{})); !errors.Is(err, supervisor.ErrPodGroupRefused) {
				t.Errorf("err = %v, want ErrPodGroupRefused", err)
			}
		})
	}
	t.Run("fsGroup 1000 with a drop allowed under the default allow-list", func(t *testing.T) {
		box := &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 300, RunAsGroup: 300, FsGroup: 1000}}
		if err := r.checkPodUID(resolveCredential(box, &runtimev1.Container{})); err != nil {
			t.Errorf("fsGroup 1000: %v", err)
		}
	})
	t.Run("fsGroup 600 refused unless the node admits it", func(t *testing.T) {
		box := &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 300, RunAsGroup: 300, FsGroup: 600}}
		cred := resolveCredential(box, &runtimev1.Container{})
		if err := r.checkPodUID(cred); !errors.Is(err, supervisor.ErrPodGroupRefused) {
			t.Errorf("not admitted: err = %v, want ErrPodGroupRefused", err)
		}
		admits := &Runtime{service: testService, lookupGroup: noHostGroups, cfg: Config{FSGroupAdmitted: []int{600}}}
		if err := admits.checkPodUID(cred); err != nil {
			t.Errorf("admitted: %v", err)
		}
	})
	// A runAsUser with no group drops to nobody, not to gid 0 (wheel), and is
	// allowed: the pod runs as 300:nobody. The proto cannot tell an explicit
	// runAsGroup 0 from an unset one, so an explicit 0 lands here too; a
	// credential that still carries gid 0 is refused
	// (supervisor.TestRunLaunchSequenceRefusesPodGroups).
	t.Run("runAsUser with no group drops to nobody and is allowed", func(t *testing.T) {
		for name, box := range map[string]*runtimev1.PodBox{
			"pod runAsUser":       {PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 300}},
			"box uid":             {Uid: 300},
			"container runAsUser": {},
		} {
			c := &runtimev1.Container{}
			if name == "container runAsUser" {
				c.SecurityContext = &runtimev1.SecurityContext{RunAsUser: 300}
			}
			cred := resolveCredential(box, c)
			if !cred.Drop || cred.UID != 300 || cred.GID != supervisor.NobodyGID() {
				t.Fatalf("%s: cred = %+v, want a drop to 300:%d", name, cred, supervisor.NobodyGID())
			}
			if err := r.checkPodUID(cred); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("a host-assigned system group refused through Deps.lookupGroup", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{lookupGroup: func(gid int) (string, bool, error) {
			return "com.apple.access_remote_ae", gid == 400, nil
		}})
		for name, src := range srcs {
			box, c := src(400)
			if err := rt.checkPodUID(resolveCredential(box, c)); !errors.Is(err, supervisor.ErrPodGroupRefused) {
				t.Errorf("%s 400: err = %v, want ErrPodGroupRefused", name, err)
			}
			box, c = src(300)
			if err := rt.checkPodUID(resolveCredential(box, c)); err != nil {
				t.Errorf("%s 300, unassigned: %v", name, err)
			}
		}
	})
	t.Run("no drop is not judged", func(t *testing.T) {
		box := &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{FsGroup: 20}}
		cred := resolveCredential(box, &runtimev1.Container{})
		if cred.Drop {
			t.Fatalf("fixture: cred = %+v, want no drop", cred)
		}
		if err := r.checkPodUID(cred); err != nil {
			t.Errorf("no drop: %v", err)
		}
	})
}

// testService is the service user the pod-identity tests pin: uid 250, the
// shipped _k3sm uid, with a primary gid of its own.
var testService = supervisor.ServiceIdentity{UID: 250, GID: 250, Known: true}

// noHostGroups is the group lookup the runtime's pod-identity tests run under:
// the host assigns no gid a group, so a verdict does not hang on the groups of
// the Mac the test runs on (macOS assigns 300 and 400 among others).
func noHostGroups(int) (string, bool, error) { return "", false, nil }

// TestServiceUIDFromInstalledDirs pins the runtime half of the fail-closed
// service uid rule: with the service user lookup answering "not found", the
// owner of the keystore's socket directory under Config.DataRoot, or of
// Config.StateDir, is refused as a drop target, and a uid that owns neither
// is not.
func TestServiceUIDFromInstalledDirs(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(filepath.Dir(root), "node-data")
	stateDir := filepath.Join(filepath.Dir(root), "node-work")
	sockDir := filepath.Join(dataRoot, keystorepaths.SockDir)
	owners := map[string]int{sockDir: 260, stateDir: 270}
	var read []string
	rt := newTestRuntimeCfg(t, Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs"), DataRoot: dataRoot, StateDir: stateDir}, Deps{
		lookupService: func() (supervisor.ServiceIdentity, error) { return supervisor.ServiceIdentity{}, nil },
		installedOwner: func(dir string) (int, bool, error) {
			read = append(read, dir)
			uid, ok := owners[dir]
			return uid, ok, nil
		},
	})
	if want := []string{sockDir, stateDir}; !slices.Equal(read, want) {
		t.Fatalf("owners read = %q, want %q", read, want)
	}
	for _, uid := range []int64{260, 270} {
		box := &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: uid, RunAsGroup: 300}}
		if err := rt.checkPodUID(resolveCredential(box, &runtimev1.Container{})); !errors.Is(err, supervisor.ErrPodUIDRefused) {
			t.Errorf("drop to the installed owner %d: err = %v, want ErrPodUIDRefused", uid, err)
		}
	}
	box := &runtimev1.PodBox{PodSecurityContext: &runtimev1.PodSecurityContext{RunAsUser: 261, RunAsGroup: 300}}
	if err := rt.checkPodUID(resolveCredential(box, &runtimev1.Container{})); err != nil {
		t.Errorf("drop to 261: %v", err)
	}
}
