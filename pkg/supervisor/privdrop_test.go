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

package supervisor

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// recordingSeam is a LaunchSeam fake that records the order of operations and
// performs NO real privilege change — the seam that makes the irreversible
// drop→confine→exec ordering unit-testable without root. failAt (when set)
// injects an error at a chosen step to prove fail-closed behavior.
type recordingSeam struct {
	calls    []LaunchStep
	failAt   LaunchStep
	hasFail  bool
	failErr  error
	gotGid   int
	gotUID   int
	gotGroup []int

	// rlimit recording. Setrlimit calls are tracked separately from calls because
	// RunLaunchSequence collapses a multi-entry plan into a single StepSetrlimit in
	// its returned steps.
	rlimitCalls []setrlimitCall     // every Setrlimit(resource, lim) the seam accepted
	inherited   map[int]unix.Rlimit // what Getrlimit returns per resource (the inherited ceiling)
	epermAbove  map[int]uint64      // Setrlimit returns EPERM when lim.Max exceeds this (a non-root hard-raise denial)

	// qos recording: every Setpriority(which, who, prio) the seam saw (B7).
	prioCalls []setprioCall
}

// setrlimitCall records one Setrlimit(resource, lim) the recording seam accepted.
type setrlimitCall struct {
	resource int
	lim      unix.Rlimit
}

// setprioCall records one Setpriority(which, who, prio) the recording seam saw.
type setprioCall struct {
	which, who, prio int
}

func (s *recordingSeam) step(st LaunchStep) error {
	s.calls = append(s.calls, st)
	if s.hasFail && st == s.failAt {
		return s.failErr
	}
	return nil
}

func (s *recordingSeam) Setgid(gid int) error     { s.gotGid = gid; return s.step(StepSetgid) }
func (s *recordingSeam) Initgroups(g []int) error { s.gotGroup = g; return s.step(StepInitgroups) }
func (s *recordingSeam) Setuid(uid int) error     { s.gotUID = uid; return s.step(StepSetuid) }
func (s *recordingSeam) SandboxApply() error      { return s.step(StepSandboxApply) }
func (s *recordingSeam) Exec() error              { return s.step(StepExec) }

// Setpriority records the qos call (which/who/prio) — no real setpriority(2) runs.
func (s *recordingSeam) Setpriority(which, who, prio int) error {
	s.prioCalls = append(s.prioCalls, setprioCall{which: which, who: who, prio: prio})
	return s.step(StepSetpriority)
}

// Setrlimit records an accepted apply, or returns EPERM (without recording) when
// the request raises the hard limit above epermAbove[resource] — emulating the
// kernel's denial of a non-root hard-limit raise so the clamp branch is exercised
// with no real syscall.
func (s *recordingSeam) Setrlimit(resource int, lim unix.Rlimit) error {
	if ceil, ok := s.epermAbove[resource]; ok && lim.Max > ceil {
		return unix.EPERM
	}
	s.rlimitCalls = append(s.rlimitCalls, setrlimitCall{resource: resource, lim: lim})
	return nil
}

// Getrlimit returns the configured inherited ceiling for resource (the value the
// clamp reduces a denied raise to), defaulting to unlimited when unset.
func (s *recordingSeam) Getrlimit(resource int) (unix.Rlimit, error) {
	if v, ok := s.inherited[resource]; ok {
		return v, nil
	}
	return unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}, nil
}

// TestRunLaunchSequenceOrder is the M2.3-a1 ordering proof: with a securityContext
// drop requested (as root), the exec-shim sequence is EXACTLY
// setgid → initgroups → setuid → sandbox_apply → exec, and without a drop it is
// sandbox_apply → exec — even on a non-root daemon, where NO setuid is attempted
// (the unprivileged _k3sm posture: the pod runs at the daemon's own uid). setgid
// must precede setuid (gid is unchangeable after the uid drop); the whole drop
// must precede sandbox_apply (the sandbox is irreversible and a dropped/sandboxed
// process cannot setuid/chown); sandbox_apply must precede exec (the pod starts
// confined).
func TestRunLaunchSequenceOrder(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		euid int
		want []LaunchStep
	}{
		{
			name: "drop-requested-as-root",
			cred: Credential{UID: 501, GID: 20, Groups: []int{20, 999}, Drop: true},
			euid: 0,
			want: []LaunchStep{StepSetgid, StepInitgroups, StepSetuid, StepSandboxApply, StepExec},
		},
		{
			name: "no-drop-unprivileged-in-seatbelt",
			cred: Credential{Drop: false},
			euid: 501, // non-root daemon: Drop=false must NOT attempt any setuid
			want: []LaunchStep{StepSandboxApply, StepExec},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seam := &recordingSeam{}
			done, err := RunLaunchSequence(seam, LaunchSpec{Cred: tc.cred}, tc.euid)
			if err != nil {
				t.Fatalf("RunLaunchSequence: %v", err)
			}
			if !reflect.DeepEqual(seam.calls, tc.want) {
				t.Fatalf("call order = %v, want %v", seam.calls, tc.want)
			}
			if !reflect.DeepEqual(done, tc.want) {
				t.Errorf("returned steps = %v, want %v", done, tc.want)
			}
			if tc.cred.Drop {
				// The drop must carry the requested identity through to the syscalls.
				if seam.gotGid != tc.cred.GID || seam.gotUID != tc.cred.UID {
					t.Errorf("drop used gid=%d uid=%d, want gid=%d uid=%d", seam.gotGid, seam.gotUID, tc.cred.GID, tc.cred.UID)
				}
				if !reflect.DeepEqual(seam.gotGroup, tc.cred.Groups) {
					t.Errorf("initgroups = %v, want %v", seam.gotGroup, tc.cred.Groups)
				}
				// setgid strictly before setuid.
				if idx(seam.calls, StepSetgid) >= idx(seam.calls, StepSetuid) {
					t.Error("setgid must come before setuid")
				}
				// drop strictly before sandbox_apply.
				if idx(seam.calls, StepSetuid) >= idx(seam.calls, StepSandboxApply) {
					t.Error("the privilege drop must complete before sandbox_apply")
				}
			}
			// sandbox_apply strictly before exec, always.
			if idx(seam.calls, StepSandboxApply) >= idx(seam.calls, StepExec) {
				t.Error("sandbox_apply must come before exec")
			}
		})
	}
}

// TestRunLaunchSequenceFailClosed proves that a failure at any step aborts the
// sequence so the pod is NEVER exec'd with the wrong identity or unconfined: an
// error at setuid skips sandbox_apply + exec; an error at sandbox_apply skips
// exec.
func TestRunLaunchSequenceFailClosed(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name        string
		failAt      LaunchStep
		wantReached []LaunchStep
		wantSkipped []LaunchStep
	}{
		{
			name:        "setuid-fails-skips-sandbox-and-exec",
			failAt:      StepSetuid,
			wantReached: []LaunchStep{StepSetgid, StepInitgroups, StepSetuid},
			wantSkipped: []LaunchStep{StepSandboxApply, StepExec},
		},
		{
			name:        "sandbox-fails-skips-exec",
			failAt:      StepSandboxApply,
			wantReached: []LaunchStep{StepSetgid, StepInitgroups, StepSetuid, StepSandboxApply},
			wantSkipped: []LaunchStep{StepExec},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seam := &recordingSeam{hasFail: true, failAt: tc.failAt, failErr: boom}
			// euid 0 (root): the drop is permitted, so the injected failAt — not
			// the euid guard — is what stops the sequence.
			_, err := RunLaunchSequence(seam, LaunchSpec{Cred: Credential{UID: 501, GID: 20, Groups: []int{20}, Drop: true}}, 0)
			if !errors.Is(err, boom) {
				t.Fatalf("want wrapped boom, got %v", err)
			}
			if !reflect.DeepEqual(seam.calls, tc.wantReached) {
				t.Errorf("reached %v, want %v", seam.calls, tc.wantReached)
			}
			for _, st := range tc.wantSkipped {
				if idx(seam.calls, st) != -1 {
					t.Errorf("%v must NOT run after the failure", st)
				}
			}
		})
	}
}

// TestRunLaunchSequenceRefusesDropAsNonRoot proves the credential posture: a
// drop requested on a non-root daemon (euid != 0) is REFUSED with
// ErrDropRequiresRoot before ANY step runs — no setgid/setuid is attempted, the
// sandbox is not applied, and the pod is not exec'd. This is the unprivileged
// _k3sm posture: pods run at the daemon's own uid (Drop=false), never root, and
// a stray Drop=true fails closed rather than silently mis-running the pod.
func TestRunLaunchSequenceRefusesDropAsNonRoot(t *testing.T) {
	seam := &recordingSeam{}
	done, err := RunLaunchSequence(seam, LaunchSpec{Cred: Credential{UID: 501, GID: 20, Drop: true}}, 501)
	if !errors.Is(err, ErrDropRequiresRoot) {
		t.Fatalf("want ErrDropRequiresRoot, got %v", err)
	}
	if len(done) != 0 || len(seam.calls) != 0 {
		t.Fatalf("no step must run when a non-root drop is refused; done=%v calls=%v", done, seam.calls)
	}
}

// TestRunLaunchSequence_Rlimits proves the rlimit slice of the launch sequence:
// StepSetrlimit is applied BEFORE the privilege drop, each planned unix.Rlimit
// reaches the seam verbatim (including unlimited→RLIM_INFINITY), an empty plan
// adds no step, and a non-root hard-limit RAISE is CLAMPED to the inherited
// ceiling (with a warning) instead of failing the pod. No real syscall runs — the
// recording seam fakes the kernel's EPERM denial and the inherited ceiling.
func TestRunLaunchSequence_Rlimits(t *testing.T) {
	// (a) StepSetrlimit is positioned strictly before StepSetuid, and the single
	// planned limit reaches the seam verbatim.
	t.Run("ordered-before-setuid", func(t *testing.T) {
		seam := &recordingSeam{}
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}}}
		// drop requested as root: the full sequence runs.
		done, err := RunLaunchSequence(seam, LaunchSpec{
			Cred:    Credential{UID: 501, GID: 20, Groups: []int{20}, Drop: true},
			Rlimits: plan,
		}, 0)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		want := []LaunchStep{StepSetrlimit, StepSetgid, StepInitgroups, StepSetuid, StepSandboxApply, StepExec}
		if !reflect.DeepEqual(done, want) {
			t.Fatalf("steps = %v, want %v", done, want)
		}
		if idx(done, StepSetrlimit) >= idx(done, StepSetuid) {
			t.Errorf("StepSetrlimit (%d) must come before StepSetuid (%d)", idx(done, StepSetrlimit), idx(done, StepSetuid))
		}
		if len(seam.rlimitCalls) != 1 ||
			seam.rlimitCalls[0].resource != unix.RLIMIT_NOFILE ||
			seam.rlimitCalls[0].lim != (unix.Rlimit{Cur: 1024, Max: 4096}) {
			t.Errorf("rlimitCalls = %+v, want one NOFILE{1024,4096}", seam.rlimitCalls)
		}
	})

	// (b) multiple entries — including an unlimited one — reach the seam verbatim,
	// and they apply even in the no-drop unprivileged posture (no setuid attempted).
	t.Run("multiple-and-unlimited-reach-seam-verbatim", func(t *testing.T) {
		seam := &recordingSeam{}
		plan := []PlannedRlimit{
			{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 256, Max: 512}},
			{Resource: unix.RLIMIT_AS, Lim: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}},
		}
		done, err := RunLaunchSequence(seam, LaunchSpec{Rlimits: plan}, 501)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		want := []LaunchStep{StepSetrlimit, StepSandboxApply, StepExec}
		if !reflect.DeepEqual(done, want) {
			t.Fatalf("steps = %v, want %v (rlimits apply even without a drop)", done, want)
		}
		wantCalls := []setrlimitCall{
			{resource: unix.RLIMIT_NOFILE, lim: unix.Rlimit{Cur: 256, Max: 512}},
			{resource: unix.RLIMIT_AS, lim: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}},
		}
		if !reflect.DeepEqual(seam.rlimitCalls, wantCalls) {
			t.Errorf("rlimitCalls = %+v, want %+v", seam.rlimitCalls, wantCalls)
		}
	})

	// An empty plan adds no StepSetrlimit and calls the seam zero times.
	t.Run("empty-plan-adds-no-step", func(t *testing.T) {
		seam := &recordingSeam{}
		done, err := RunLaunchSequence(seam, LaunchSpec{}, 501)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if idx(done, StepSetrlimit) != -1 {
			t.Errorf("empty plan must add no StepSetrlimit; done=%v", done)
		}
		if len(seam.rlimitCalls) != 0 {
			t.Errorf("empty plan must call Setrlimit 0 times; got %+v", seam.rlimitCalls)
		}
	})

	// (e) a hard-limit raise above the inherited ceiling is clamped, with a
	// warning — NOT a fatal EPERM. (Since the unconditional security clamp the
	// pre-clamp fires BEFORE the kernel would even see the raise; the seam's
	// EPERM emulation stays as the defense-in-depth backstop.)
	t.Run("nonroot-hard-raise-clamped-not-fatal", func(t *testing.T) {
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(old)

		const inheritedHard = 4096
		seam := &recordingSeam{
			inherited:  map[int]unix.Rlimit{unix.RLIMIT_NOFILE: {Cur: 1024, Max: inheritedHard}},
			epermAbove: map[int]uint64{unix.RLIMIT_NOFILE: inheritedHard}, // a raise above 4096 → EPERM (non-root)
		}
		// Request hard = 1<<20 (a RAISE above the inherited 4096): the unprivileged
		// posture cannot raise it, so it must be clamped to 4096, not fail the pod.
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 8192, Max: 1 << 20}}}
		done, err := RunLaunchSequence(seam, LaunchSpec{Rlimits: plan}, 501)
		if err != nil {
			t.Fatalf("clamp must not be fatal, got err=%v", err)
		}
		if idx(done, StepSetrlimit) == -1 {
			t.Errorf("StepSetrlimit must be recorded after a successful clamp; done=%v", done)
		}
		// Only the CLAMPED Setrlimit is accepted (the first, raising attempt EPERM'd
		// without recording).
		if len(seam.rlimitCalls) != 1 {
			t.Fatalf("want exactly one accepted Setrlimit (the clamped retry), got %+v", seam.rlimitCalls)
		}
		got := seam.rlimitCalls[0].lim
		if got.Max != inheritedHard {
			t.Errorf("clamped hard = %d, want inherited %d", got.Max, inheritedHard)
		}
		if got.Cur > got.Max {
			t.Errorf("clamped soft %d exceeds clamped hard %d", got.Cur, got.Max)
		}
		if !strings.Contains(buf.String(), "clamped to inherited") {
			t.Errorf("expected a clamp warning, slog output = %q", buf.String())
		}
	})

	// (B7 post-critique, security HIGH) the inherited-ceiling clamp is
	// UNCONDITIONAL: even in the ROOT posture — where a euid-0 setrlimit hard
	// raise would SUCCEED (the EPERM clamp never fires for root) — a pod-sourced
	// plan must not raise limits above the daemon's inherited posture, or a pod
	// annotation becomes a node-wide escalation lever (e.g. RLIMIT_NPROC on the
	// shared _k3sm uid). The seam accepts everything (no epermAbove — the root
	// emulation); the clamp alone must cap the request.
	t.Run("root-posture-hard-raise-clamped-to-inherited", func(t *testing.T) {
		seam := &recordingSeam{
			inherited: map[int]unix.Rlimit{unix.RLIMIT_NPROC: {Cur: 512, Max: 1024}},
			// no epermAbove: emulates root, where the kernel would permit the raise.
		}
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NPROC, Lim: unix.Rlimit{Cur: 2048, Max: 4096}}}
		// Root drop posture: euid 0, full sequence.
		if _, err := RunLaunchSequence(seam, LaunchSpec{
			Cred:    Credential{UID: 501, GID: 20, Drop: true},
			Rlimits: plan,
		}, 0); err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if len(seam.rlimitCalls) != 1 {
			t.Fatalf("want exactly one Setrlimit, got %+v", seam.rlimitCalls)
		}
		if got := seam.rlimitCalls[0].lim; got != (unix.Rlimit{Cur: 1024, Max: 1024}) {
			t.Errorf("root-posture raise = %+v, want clamped to inherited hard {Cur:1024 Max:1024}", got)
		}
	})

	// The complement: a plan at-or-below the inherited ceiling passes through
	// verbatim — the clamp only ever TIGHTENS, it never rewrites a valid request.
	t.Run("below-inherited-passes-through-verbatim", func(t *testing.T) {
		seam := &recordingSeam{
			inherited: map[int]unix.Rlimit{unix.RLIMIT_NPROC: {Cur: 512, Max: 1024}},
		}
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NPROC, Lim: unix.Rlimit{Cur: 100, Max: 200}}}
		if _, err := RunLaunchSequence(seam, LaunchSpec{Rlimits: plan}, 501); err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if len(seam.rlimitCalls) != 1 {
			t.Fatalf("want exactly one Setrlimit, got %+v", seam.rlimitCalls)
		}
		if got := seam.rlimitCalls[0].lim; got != (unix.Rlimit{Cur: 100, Max: 200}) {
			t.Errorf("below-inherited plan = %+v, want verbatim {Cur:100 Max:200}", got)
		}
	})

	// (B7) darwin NOFILE taxonomy: an infinite soft NOFILE is clamped DOWN before
	// the syscall (darwin setrlimit(2) returns EINVAL for rlim_cur=RLIM_INFINITY on
	// RLIMIT_NOFILE — the launch would abort), so the seam receives the OPEN_MAX
	// ceiling, never RLIM_INFINITY, in Cur.
	t.Run("nofile-infinite-cur-normalized-before-syscall", func(t *testing.T) {
		seam := &recordingSeam{}
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{
			Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}}}
		if _, err := RunLaunchSequence(seam, LaunchSpec{Rlimits: plan}, 501); err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if len(seam.rlimitCalls) != 1 {
			t.Fatalf("want exactly one Setrlimit, got %+v", seam.rlimitCalls)
		}
		got := seam.rlimitCalls[0].lim
		if got.Cur != 10240 {
			t.Errorf("normalized NOFILE Cur = %d, want the OPEN_MAX ceiling 10240", got.Cur)
		}
		if got.Max != uint64(unix.RLIM_INFINITY) {
			t.Errorf("NOFILE Max = %d, want RLIM_INFINITY carried verbatim", got.Max)
		}
	})

	// (B7) shim NOFILE floor: a too-tight soft NOFILE starves sandbox_compile's
	// profile read and the exec'd image's dyld AFTER confinement, so Cur is raised
	// to the named floor (256) with a warning before the syscall.
	t.Run("nofile-tight-soft-floored-up-with-warning", func(t *testing.T) {
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(old)

		seam := &recordingSeam{}
		plan := []PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 16, Max: 1024}}}
		if _, err := RunLaunchSequence(seam, LaunchSpec{Rlimits: plan}, 501); err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if len(seam.rlimitCalls) != 1 {
			t.Fatalf("want exactly one Setrlimit, got %+v", seam.rlimitCalls)
		}
		if got := seam.rlimitCalls[0].lim; got != (unix.Rlimit{Cur: 256, Max: 1024}) {
			t.Errorf("floored NOFILE = %+v, want {Cur:256 Max:1024}", got)
		}
		if !strings.Contains(buf.String(), "RLIMIT_NOFILE") {
			t.Errorf("expected a NOFILE normalization warning, slog output = %q", buf.String())
		}
	})
}

// TestRunLaunchSequence_QoSPriority is the B7 qos slice: a background (BestEffort
// / unspecified — the mapping from the apis QOSClass enum to the supervisor-local
// BgQoS bool lives daemon-side in runtime.resolveBgQoS) launch performs EXACTLY
// one Setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) call, positioned BEFORE
// StepSandboxApply (a default-deny SBPL may deny setpriority afterward; pre-exec
// means the band is inherited by the exec'd image and all descendants,
// race-free). Guaranteed/Burstable (BgQoS=false) is the ABSENCE of the call —
// downward-only, never an explicit reset-to-0.
func TestRunLaunchSequence_QoSPriority(t *testing.T) {
	t.Run("bg-with-drop-ordered-after-drop-before-sandbox", func(t *testing.T) {
		seam := &recordingSeam{}
		spec := LaunchSpec{
			Cred:    Credential{UID: 501, GID: 20, Groups: []int{20}, Drop: true},
			Rlimits: []PlannedRlimit{{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}}},
			BgQoS:   true,
		}
		done, err := RunLaunchSequence(seam, spec, 0)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		want := []LaunchStep{StepSetrlimit, StepSetgid, StepInitgroups, StepSetuid,
			StepSetpriority, StepSandboxApply, StepExec}
		if !reflect.DeepEqual(done, want) {
			t.Fatalf("steps = %v, want %v", done, want)
		}
		if len(seam.prioCalls) != 1 {
			t.Fatalf("Setpriority calls = %+v, want exactly one", seam.prioCalls)
		}
		if got := seam.prioCalls[0]; got != (setprioCall{which: prioDarwinProcess, who: 0, prio: prioDarwinBG}) {
			t.Errorf("Setpriority = %+v, want {which:PRIO_DARWIN_PROCESS(4) who:0 prio:PRIO_DARWIN_BG(0x1000)}", got)
		}
		// The load-bearing orderings: qos strictly before sandbox_apply, and (as
		// today) rlimits strictly before the drop.
		if idx(done, StepSetpriority) >= idx(done, StepSandboxApply) {
			t.Error("StepSetpriority must come before StepSandboxApply")
		}
		if idx(done, StepSetrlimit) >= idx(done, StepSetgid) {
			t.Error("StepSetrlimit must come before the privilege drop")
		}
	})

	t.Run("bg-no-drop-unprivileged", func(t *testing.T) {
		seam := &recordingSeam{}
		done, err := RunLaunchSequence(seam, LaunchSpec{BgQoS: true}, 501)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		want := []LaunchStep{StepSetpriority, StepSandboxApply, StepExec}
		if !reflect.DeepEqual(done, want) {
			t.Fatalf("steps = %v, want %v", done, want)
		}
		if len(seam.prioCalls) != 1 {
			t.Fatalf("Setpriority calls = %+v, want exactly one", seam.prioCalls)
		}
	})

	// Guaranteed/Burstable: the seam's Setpriority is NEVER called — the darwin
	// default band is the absence of the call, not an explicit reset.
	t.Run("guaranteed-burstable-no-call-at-all", func(t *testing.T) {
		seam := &recordingSeam{}
		done, err := RunLaunchSequence(seam, LaunchSpec{}, 501)
		if err != nil {
			t.Fatalf("RunLaunchSequence: %v", err)
		}
		if len(seam.prioCalls) != 0 {
			t.Fatalf("Setpriority must NEVER be called for BgQoS=false; got %+v", seam.prioCalls)
		}
		if idx(done, StepSetpriority) != -1 {
			t.Errorf("no StepSetpriority must be recorded; done=%v", done)
		}
	})

	// Fail-closed: a failed Setpriority aborts the launch before sandbox_apply /
	// exec, consistent with the sequence's stop-at-first-error contract.
	t.Run("setpriority-failure-fail-closed", func(t *testing.T) {
		boom := errors.New("boom")
		seam := &recordingSeam{hasFail: true, failAt: StepSetpriority, failErr: boom}
		_, err := RunLaunchSequence(seam, LaunchSpec{BgQoS: true}, 501)
		if !errors.Is(err, boom) {
			t.Fatalf("want wrapped boom, got %v", err)
		}
		if idx(seam.calls, StepSandboxApply) != -1 || idx(seam.calls, StepExec) != -1 {
			t.Errorf("sandbox_apply/exec must NOT run after a Setpriority failure; calls=%v", seam.calls)
		}
	})
}

// TestCredentialValidate is the unit table for the euid guard: a drop needs root,
// a non-drop credential is always valid (it keeps the daemon's own uid).
func TestCredentialValidate(t *testing.T) {
	cases := []struct {
		name    string
		cred    Credential
		euid    int
		wantErr bool
	}{
		{"drop-as-root-ok", Credential{UID: 501, GID: 20, Drop: true}, 0, false},
		{"drop-as-nonroot-refused", Credential{UID: 501, GID: 20, Drop: true}, 501, true},
		{"no-drop-as-nonroot-ok", Credential{Drop: false}, 501, false},
		{"no-drop-as-root-ok", Credential{Drop: false}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cred.Validate(tc.euid)
			if tc.wantErr {
				if !errors.Is(err, ErrDropRequiresRoot) {
					t.Fatalf("want ErrDropRequiresRoot, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestCredentialShimRoundTrip covers the exec-shim argv encoding: a Credential
// survives ShimArgs → ParseCredential unchanged (the wire the supervisor uses to
// pass the drop target to the exec-shim process).
func TestCredentialShimRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
	}{
		{"no-drop", Credential{Drop: false}},
		{"drop-with-groups", Credential{UID: 501, GID: 20, Groups: []int{20, 999}, Drop: true}},
		{"drop-no-groups", Credential{UID: 1000, GID: 1000, Drop: true}},
		{"drop-root-gid", Credential{UID: 1000, GID: 0, Groups: []int{0}, Drop: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.cred.ShimArgs()
			if len(args) != 3 {
				t.Fatalf("ShimArgs len = %d, want 3", len(args))
			}
			got, err := ParseCredential(args[0], args[1], args[2])
			if err != nil {
				t.Fatalf("ParseCredential: %v", err)
			}
			if got.Drop != tc.cred.Drop || got.UID != tc.cred.UID || got.GID != tc.cred.GID {
				t.Errorf("round-trip = %+v, want %+v", got, tc.cred)
			}
			if tc.cred.Drop && !reflect.DeepEqual(normGroups(got.Groups), normGroups(tc.cred.Groups)) {
				t.Errorf("round-trip groups = %v, want %v", got.Groups, tc.cred.Groups)
			}
		})
	}
}

// TestParseCredentialErrors rejects malformed shim arguments.
func TestParseCredentialErrors(t *testing.T) {
	cases := [][3]string{
		{"notanint", "20", "-"},
		{"501", "x", "-"},
		{"501", "20", "20,bad"},
	}
	for _, c := range cases {
		if _, err := ParseCredential(c[0], c[1], c[2]); err == nil {
			t.Errorf("ParseCredential(%q,%q,%q) = nil err, want error", c[0], c[1], c[2])
		}
	}
}

// TestChownForFSGroup is the root-free half of M2.3-a2: the writable mount root is
// group-owned by fsGroup and group-accessible, with the setgid bit on dirs. It
// chowns to the test process's own gid (a group it is a member of), so no root is
// needed; the real fsGroup chown under an arbitrary gid is the m2.sh e2e.
func TestChownForFSGroup(t *testing.T) {
	gid := os.Getgid()
	if gid <= 0 {
		t.Skip("test process gid <= 0 (running as root?); fsGroup chown asserts a >0 gid")
	}
	// The walk is bounded by the pods root; root is a pod's data volume strictly
	// inside it, mirroring the daemon's real shape.
	podsRoot := t.TempDir()
	root := filepath.Join(podsRoot, "pod-a", "rootfs")
	sub := filepath.Join(root, "vol")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "data")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ChownForFSGroup(podsRoot, root, gid); err != nil {
		t.Fatalf("ChownForFSGroup: %v", err)
	}

	// Directory: group rwx + setgid.
	di, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o070 != 0o070 {
		t.Errorf("dir perm = %o, want group rwx set", di.Mode().Perm())
	}
	if di.Mode()&os.ModeSetgid == 0 {
		t.Error("dir missing setgid bit (group inheritance)")
	}
	if st, ok := di.Sys().(*syscall.Stat_t); ok && int(st.Gid) != gid {
		t.Errorf("dir gid = %d, want %d", st.Gid, gid)
	}
	// File: group rw (owner had rw → group gets rw); group-owned by gid.
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o060 != 0o060 {
		t.Errorf("file perm = %o, want group rw set", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) != gid {
		t.Errorf("file gid = %d, want %d", st.Gid, gid)
	}
}

// TestChownForFSGroupRejectsRootGid rejects a non-positive fsGroup (0 = wheel is
// never a valid target; negative is a bug).
func TestChownForFSGroupRejectsRootGid(t *testing.T) {
	bound := t.TempDir()
	if err := ChownForFSGroup(bound, filepath.Join(bound, "pod-a", "rootfs"), 0); err == nil {
		t.Error("ChownForFSGroup(_, _, 0) = nil, want error")
	}
}

// TestChownForFSGroupRejectsUnboundedRoot is the B140 sink-side half: the
// recursive group-rwx + setgid grant refuses a root outside the permitted tree
// REGARDLESS of the caller, and refuses it BEFORE touching the filesystem. The
// pre-created victim's mode is asserted unchanged, because an error return alone
// would not distinguish "refused" from "escalated, then failed late".
func TestChownForFSGroupRejectsUnboundedRoot(t *testing.T) {
	gid := os.Getgid()
	if gid <= 0 {
		t.Skip("test process gid <= 0 (running as root?); fsGroup chown asserts a >0 gid")
	}
	outside := t.TempDir()
	bound := filepath.Join(outside, "pods")
	victim := filepath.Join(outside, "server")
	if err := os.MkdirAll(filepath.Join(victim, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A sibling whose name merely starts with the bound — the classic
	// prefix-check bypass.
	sibling := filepath.Join(outside, "podsevil")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bound, "pod-a", "rootfs"), 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		root string
	}{
		{"outside-the-bound", victim},
		{"the-bound-itself", bound},           // equality is refused: never the shared root
		{"sibling-sharing-a-prefix", sibling}, // /x/podsevil is not under /x/pods
		{"parent-of-the-bound", outside},
		{"relative", "pods/pod-a/rootfs"},   // a relative root resolves against cwd
		{"traversal", bound + "/../server"}, // cleaned, this leaves the bound
		{"filesystem-root", string(os.PathSeparator)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := modeOf(t, victim)
			err := ChownForFSGroup(bound, tc.root, gid)
			if !errors.Is(err, ErrFSGroupRootUnbounded) {
				t.Errorf("ChownForFSGroup(%q, %q, %d) = %v, want ErrFSGroupRootUnbounded", bound, tc.root, gid, err)
			}
			if got := modeOf(t, victim); got != before {
				t.Errorf("victim %s mode changed %v -> %v; the refusal must precede any chmod", victim, before, got)
			}
		})
	}

	// POSITIVE CONTROL: a root strictly inside the bound is still walked, so the
	// table above cannot pass by refusing everything.
	pod := filepath.Join(bound, "pod-a", "rootfs")
	if err := ChownForFSGroup(bound, pod, gid); err != nil {
		t.Fatalf("ChownForFSGroup(bound, %q, %d) = %v, want nil", pod, gid, err)
	}
	if got := modeOf(t, pod); got.Perm()&0o070 != 0o070 || got&os.ModeSetgid == 0 {
		t.Errorf("pod rootfs mode = %v, want group rwx + setgid (the walk must be reachable)", got)
	}
}

// TestStrictlyUnder pins the containment predicate the fsGroup bound rests on.
// It is the local twin of mount.IsStrictlyUnder; the two tables must agree.
func TestStrictlyUnder(t *testing.T) {
	cases := []struct {
		path, base string
		want       bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b", "/a/b", false},   // equality is NOT under
		{"/a/bc", "/a/b", false},  // separator-aware: a sibling sharing a prefix
		{"/a", "/a/b", false},     // the parent is not under the child
		{"/a/b/../c", "/a", true}, // cleaned first
		{"/a/b/../../c", "/a", false},
		{"/a", "/", true},
		{"/", "/", false},
		{"a/b", "/a", false}, // relative path
		{"/a/b", "a", false}, // relative base
		{"", "/a", false},
		{"/a/b", "", false},
		{"/a/b/", "/a", true}, // trailing separator is cleaned away
	}
	// The DELIBERATE asymmetry with pkg/mount.IsStrictlyUnder, pinned so the
	// divergence cannot be "reconciled" by loosening this one. mount's variant
	// answers true for both of these (it does not require absolute operands),
	// which is harmless where its inputs are absolute by construction but is a
	// fail-OPEN shape for a bound on a recursive privilege grant: a relative base
	// would resolve against the process working directory.
	stricterThanMount := []struct {
		path, base string
	}{
		{"a/b", "a"},
		{"a/b/c", "a/b"},
	}
	for _, tc := range stricterThanMount {
		if strictlyUnder(tc.path, tc.base) {
			t.Errorf("strictlyUnder(%q, %q) = true; this predicate is deliberately STRICTER than mount.IsStrictlyUnder and must refuse relative operands", tc.path, tc.base)
		}
	}
	for _, tc := range cases {
		t.Run(tc.path+"|"+tc.base, func(t *testing.T) {
			if got := strictlyUnder(tc.path, tc.base); got != tc.want {
				t.Errorf("strictlyUnder(%q, %q) = %v, want %v", tc.path, tc.base, got, tc.want)
			}
		})
	}
}

// modeOf returns p's full FileMode (permissions + setgid), failing the test if
// it cannot be stat'd.
func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Mode()
}

// idx returns the index of step in calls, or -1 if absent.
func idx(calls []LaunchStep, step LaunchStep) int {
	for i, s := range calls {
		if s == step {
			return i
		}
	}
	return -1
}

// normGroups maps a nil slice to empty for comparison stability.
func normGroups(g []int) []int {
	if g == nil {
		return []int{}
	}
	return g
}
