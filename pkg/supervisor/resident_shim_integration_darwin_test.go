//go:build integration && darwin && cgo

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

package supervisor_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// residentShim is a real resident shim hosting a ticking /bin/sh under the real
// pod profile, as the daemon would start it.
type residentShim struct {
	dir, logPath string
	proc         *supervisor.Process
	cancel       context.CancelFunc
}

// startResidentShim builds the shim, renders the pod profile and the shim
// profile, and starts a container whose script prints "tick <n>" every 100ms.
func startResidentShim(t *testing.T) residentShim {
	t.Helper()
	shim := buildShim(t)
	profile, dataVol := podProfile(t, "pod-resident")
	// A short dir: the socket path must fit sun_path.
	dir, err := os.MkdirTemp("/tmp", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	logPath := filepath.Join(t.TempDir(), "c", "0.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	podText, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	shimText, err := sandbox.ShimProfile(string(podText), sandbox.ShimGrant{Dir: dir, LogPath: logPath})
	if err != nil {
		t.Fatalf("ShimProfile: %v", err)
	}
	shimProfile := filepath.Join(t.TempDir(), "shim.sb")
	if err := os.WriteFile(shimProfile, []byte(shimText), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=/usr/bin:/bin"}
	script := "i=0; while :; do echo tick $i; i=$((i+1)); /bin/sleep 0.1; done"
	// /bin/bash, not /bin/sh: the sh dispatcher re-execs bash with a plain
	// execve, which clears the pressure-kill mark this test pins.
	launch := []string{"-1", "-1", "-", "-", "-", profile, "/bin/bash", "-c", script}
	ctx, cancel := context.WithCancel(context.Background())
	proc := supervisor.NewShimProcess(supervisor.PosixSpawner{PressureKill: true}, supervisor.KqueueReaper{},
		supervisor.SpawnSpec{Path: shim, Argv: []string{shim, supervisor.ShimModeServe}, Env: []string{}, Dir: dataVol},
		supervisor.ShimLaunch{
			Spec: supervisor.ShimSpec{Container: "c", Dir: dir, LogPath: logPath, ShimProfile: shimProfile,
				Launch: launch, Env: env, ExecEnv: env, ExecDir: dataVol},
			Dialer:    supervisor.UnixShimDialer{},
			ProcStart: supervisor.ProcStartTimeNano,
			Kill:      supervisor.SignalGroup,
		})
	if err := proc.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	pgid := proc.PID()
	t.Cleanup(func() {
		_ = supervisor.SignalGroup(pgid, syscall.SIGKILL)
		cancel()
	})
	return residentShim{dir: dir, logPath: logPath, proc: proc, cancel: cancel}
}

// ticks parses the CRI log: every line must be a full stdout "tick <n>" line, in
// order from 0 with no gap. It returns the count.
func ticks(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), " ", 4)
		if len(fields) != 4 || fields[1] != "stdout" || fields[2] != "F" {
			t.Fatalf("log line %d is not a full stdout line: %q", n, sc.Text())
		}
		if want := fmt.Sprintf("tick %d", n); fields[3] != want {
			t.Fatalf("log line %d = %q, want %q (a gap or a marker)", n, fields[3], want)
		}
		n++
	}
	return n
}

func awaitTicks(t *testing.T, path string, atLeast int) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if n := ticks(t, path); n >= atLeast {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the log never reached %d ticks (has %d)", atLeast, ticks(t, path))
	return 0
}

// execEcho runs /bin/echo through the shim and returns its stdout and exit.
func execEcho(t *testing.T, conn *supervisor.ShimConn) (string, int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := conn.Exec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&runtimev1.ExecRequest{Container: "c", Command: []string{"/bin/echo", "hello"}}); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseSend()
	var out strings.Builder
	for {
		resp, err := st.Recv()
		if err == io.EOF {
			t.Fatal("exec stream ended without an exit")
		}
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		out.Write(resp.GetStdout())
		if e := resp.GetExit(); e != nil {
			return out.String(), e.GetExitCode()
		}
	}
}

// TestResidentShimSurvivesTheDaemon is the resident shim's end-to-end gate: a
// ticking container under the real shim, the daemon-side Process dropped (its
// connection closed, its watch cancelled) and a second ConnectShim; the CRI log
// stays continuous with no marker; an exec through the shim answers; the stats
// sample names the container, not the shim; a TERM through the shim ends the
// container, and the exit the reconnected Process reports is the real one,
// equal to the shim's own Status and to its exit record. It also pins the
// pressure-kill mark on both the shim and the container, and logs the shim's
// footprint for docs/resources.md.
func TestResidentShimSurvivesTheDaemon(t *testing.T) {
	rs := startResidentShim(t)
	shimPid, child := rs.proc.PID(), rs.proc.ChildPID()
	if child == shimPid || child <= 1 {
		t.Fatalf("ChildPID %d must name the container, not the shim %d", child, shimPid)
	}
	awaitComm(t, child, "bash")
	for name, pid := range map[string]int{"shim": shimPid, "container": child} {
		if f := mustFlags(t, pid); !supervisor.PcontrolIsKill(f) {
			t.Fatalf("%s pid %d pbi_flags = 0x%x, want pcontrol-KILL", name, pid, f)
		}
	}
	awaitTicks(t, rs.logPath, 3)

	// The daemon dies: nothing of the first Process is used again.
	_ = rs.proc.Shim().Close()
	rs.cancel()
	before := ticks(t, rs.logPath)

	start, ok := supervisor.ProcStartTimeNano(shimPid)
	if !ok {
		t.Fatal("the shim did not survive its daemon")
	}
	ctx := context.Background()
	conn, st, err := supervisor.ConnectShim(ctx, supervisor.UnixShimDialer{},
		supervisor.ShimIdentity{Container: "c", Dir: rs.dir, Pid: shimPid, StartUnixNano: start}, supervisor.ProcStartTimeNano)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	proc, err := supervisor.AdoptShim(ctx, supervisor.AdoptedExitWaiter{}, conn, st)
	if err != nil {
		t.Fatal(err)
	}
	if int(st.GetChildPid()) != child || !st.GetRunning() {
		t.Fatalf("status after reconnect: child %d running %v, want %d running", st.GetChildPid(), st.GetRunning(), child)
	}
	awaitTicks(t, rs.logPath, before+3)

	if out, code := execEcho(t, conn); code != 0 || strings.TrimSpace(out) != "hello" {
		t.Fatalf("exec /bin/echo through the shim: exit %d output %q", code, out)
	}

	sample, err := supervisor.PhysFootprinter{}.RUsage(proc.ChildPID())
	if err != nil || proc.ChildPID() != child {
		t.Fatalf("stats sample of ChildPID %d (want %d): %v", proc.ChildPID(), child, err)
	}
	if sample.PhysFootprintBytes == 0 {
		t.Fatalf("container sample reported no footprint")
	}
	if fp, err := (supervisor.PhysFootprinter{}).RUsage(shimPid); err == nil {
		t.Logf("resident shim footprint: %.1f MiB phys_footprint (container %.1f MiB)",
			float64(fp.PhysFootprintBytes)/(1<<20), float64(sample.PhysFootprintBytes)/(1<<20))
		if fp.PhysFootprintBytes > shimFootprintCeiling {
			t.Fatalf("shim footprint %d bytes exceeds the documented ceiling %d", fp.PhysFootprintBytes, shimFootprintCeiling)
		}
	}

	// An exec session still open when the container exits holds the shim
	// briefly (its stop grace), so the shim's own Status can be read after the
	// exit and compared with the record.
	holdCtx, release := context.WithCancel(ctx)
	defer release()
	hold, err := conn.Exec(holdCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := hold.Send(&runtimev1.ExecRequest{Container: "c", Command: []string{"/bin/sleep", "30"}}); err != nil {
		t.Fatal(err)
	}

	if err := proc.StopSignal(supervisor.SignalGroup)(shimPid, syscall.SIGTERM); err != nil {
		t.Fatalf("TERM through the shim: %v", err)
	}
	var shimExit *supervisor.ExitRecord
	deadline := time.Now().Add(10 * time.Second)
	for shimExit == nil && time.Now().Before(deadline) {
		if s, err := conn.Status(ctx); err == nil && s.GetExit() != nil {
			shimExit = &supervisor.ExitRecord{ExitCode: int(s.GetExit().GetExitCode()), Signal: int(s.GetExit().GetSignal())}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if shimExit == nil {
		rec, ok, rerr := supervisor.ReadExitRecord(rs.dir)
		_, alive := supervisor.ProcStartTimeNano(child)
		t.Fatalf("the shim never reported the container's exit (record %+v %v %v, child alive %v comm %q)", rec, ok, rerr, alive, comm(child))
	}
	release()
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	code, sig, err := proc.Wait(waitCtx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if sig != int(syscall.SIGTERM) || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("exit = code %d signal %d, want the real SIGTERM death (143, 15)", code, sig)
	}
	if code != shimExit.ExitCode || sig != shimExit.Signal {
		t.Fatalf("Process exit (%d, %d) differs from the shim's Status (%d, %d)", code, sig, shimExit.ExitCode, shimExit.Signal)
	}
	rec, ok, err := supervisor.ReadExitRecord(rs.dir)
	if err != nil || !ok || rec.ExitCode != code || rec.Signal != sig {
		t.Fatalf("exit record %+v ok=%v err=%v, want (%d, %d)", rec, ok, err, code, sig)
	}
	if n := ticks(t, rs.logPath); n <= before {
		t.Fatalf("no output was logged after the reconnect (%d <= %d)", n, before)
	}
	t.Logf("log continuous over %s ticks", strconv.Itoa(ticks(t, rs.logPath)))
}

// shimFootprintCeiling is the resident shim's footprint ceiling documented in
// docs/resources.md.
const shimFootprintCeiling = 32 << 20
