package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
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

// TestRunLaunchSequenceOrder is the M2.3-a1 ordering proof: with a securityContext
// drop requested, the exec-shim sequence is EXACTLY
// setgid → initgroups → setuid → sandbox_apply → exec, and without a drop it is
// sandbox_apply → exec. setgid must precede setuid (gid is unchangeable after the
// uid drop); the whole drop must precede sandbox_apply (the sandbox is
// irreversible and a dropped/sandboxed process cannot setuid/chown); sandbox_apply
// must precede exec (the pod starts confined).
func TestRunLaunchSequenceOrder(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		want []LaunchStep
	}{
		{
			name: "drop-requested",
			cred: Credential{UID: 501, GID: 20, Groups: []int{20, 999}, Drop: true},
			want: []LaunchStep{StepSetgid, StepInitgroups, StepSetuid, StepSandboxApply, StepExec},
		},
		{
			name: "no-drop-root-in-seatbelt",
			cred: Credential{Drop: false},
			want: []LaunchStep{StepSandboxApply, StepExec},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seam := &recordingSeam{}
			done, err := RunLaunchSequence(seam, tc.cred)
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
			_, err := RunLaunchSequence(seam, Credential{UID: 501, GID: 20, Groups: []int{20}, Drop: true})
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
	root := t.TempDir()
	sub := filepath.Join(root, "vol")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "data")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ChownForFSGroup(root, gid); err != nil {
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
	if err := ChownForFSGroup(t.TempDir(), 0); err == nil {
		t.Error("ChownForFSGroup(_, 0) = nil, want error")
	}
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
