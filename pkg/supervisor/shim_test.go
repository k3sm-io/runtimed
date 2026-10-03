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
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"

	shimv1 "k3sm.io/apis/shim/v1"
)

func TestExitRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := ReadExitRecord(dir); ok || err != nil {
		t.Fatalf("empty dir: ok=%v err=%v, want neither", ok, err)
	}
	want := ExitRecord{ExitCode: 143, Signal: 15, FinishedAtUnixNano: 42}
	if err := WriteExitRecord(dir, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := ReadExitRecord(dir)
	if err != nil || !ok || got != want {
		t.Fatalf("ReadExitRecord = %+v ok=%v err=%v, want %+v", got, ok, err, want)
	}
	if _, err := os.Stat(dir + "/" + ShimExitFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the tmp file survived the rename: %v", err)
	}
	// A record mid-write or never written (the shim opens the file at bring-up)
	// reads as "no record yet", never as an error or a status.
	for _, torn := range []string{"", `{"exitCode":1`} {
		if err := os.WriteFile(dir+"/"+ShimExitFile, []byte(torn), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := ReadExitRecord(dir); ok || err != nil {
			t.Fatalf("record %q: ok=%v err=%v, want no record and no error", torn, ok, err)
		}
	}
	// Rewritten in place over a longer previous content, the record is exact.
	if err := WriteExitRecord(dir, ExitRecord{ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := ReadExitRecord(dir); !ok || got != (ExitRecord{ExitCode: 1}) {
		t.Fatalf("rewritten record = %+v ok=%v", got, ok)
	}
	if err := RemoveExitRecord(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadExitRecord(dir); ok {
		t.Fatal("RemoveExitRecord left the record")
	}
	if err := RemoveExitRecord(dir); err != nil {
		t.Fatalf("removing an absent record must be a no-op: %v", err)
	}
}

func TestDecodeShimSpec(t *testing.T) {
	good := ShimSpec{APIVersion: shimv1.APIVersion, Container: "c", Dir: "/d", LogPath: "/l", ShimProfile: "/p",
		Launch: []string{"-1", "-1", "-", "-", "-", "/prof", "/bin/true"}}
	enc := func(s ShimSpec) *bytes.Reader {
		b, err := EncodeShimSpec(s)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(b)
	}
	if _, err := DecodeShimSpec(enc(good)); err != nil {
		t.Fatalf("good spec: %v", err)
	}
	skew := good
	skew.APIVersion = "k3sm.shim.v0"
	if _, err := DecodeShimSpec(enc(skew)); !errors.Is(err, ErrShimVersion) {
		t.Fatalf("skewed spec: %v, want ErrShimVersion", err)
	}
	short := good
	short.Launch = short.Launch[:6]
	if _, err := DecodeShimSpec(enc(short)); err == nil {
		t.Fatal("a launch argv without the pod binary must be refused")
	}
	if _, err := DecodeShimSpec(strings.NewReader("{")); err == nil {
		t.Fatal("a truncated spec must be refused")
	}
}

func TestCheckSunPath(t *testing.T) {
	if err := CheckSunPath("/" + strings.Repeat("a", maxSunPath-1)); err != nil {
		t.Fatalf("a %d-byte path fits: %v", maxSunPath, err)
	}
	if err := CheckSunPath("/" + strings.Repeat("a", maxSunPath)); !errors.Is(err, ErrSunPathTooLong) {
		t.Fatalf("a %d-byte path: %v, want ErrSunPathTooLong", maxSunPath+1, err)
	}
}

// fakeStatusShim serves Status from a canned answer and counts the calls; fail
// makes it answer with an error.
type fakeStatusShim struct {
	shimv1.UnimplementedContainerShimServer
	resp  *shimv1.StatusResponse
	fail  bool
	calls atomic.Int32
}

func (f *fakeStatusShim) Status(_ context.Context, req *shimv1.StatusRequest) (*shimv1.StatusResponse, error) {
	f.calls.Add(1)
	if f.fail {
		return nil, errors.New("wedged")
	}
	return f.resp, nil
}

// pidDialer dials real unix sockets and claims a fixed peer pid.
type pidDialer struct{ pid int }

func (d pidDialer) DialShim(ctx context.Context, path string) (net.Conn, int, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "unix", path)
	return c, d.pid, err
}

// serveFakeShim serves srv on <short tmp dir>/shim.sock and returns the dir.
func serveFakeShim(t *testing.T, srv shimv1.ContainerShimServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "shimt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", ShimSockPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	shimv1.RegisterContainerShimServer(g, srv)
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	return dir
}

func TestConnectShimVerifiesTheShim(t *testing.T) {
	const pid, start = 4242, int64(777)
	ok := &shimv1.StatusResponse{ApiVersion: shimv1.APIVersion, ShimPid: pid, ShimStartUnixNano: start, ChildPid: 4243, Running: true}
	cases := []struct {
		name      string
		srv       *fakeStatusShim
		dialPid   int
		procStart func(int) (int64, bool)
		want      error
	}{
		{name: "verified", srv: &fakeStatusShim{resp: ok}, dialPid: pid},
		{name: "recorded start drifted", srv: &fakeStatusShim{resp: ok}, dialPid: pid,
			procStart: func(int) (int64, bool) { return start + 1, true }, want: ErrShimIdentity},
		{name: "peer is another process", srv: &fakeStatusShim{resp: ok}, dialPid: pid + 9, want: ErrShimIdentity},
		{name: "other contract version", srv: &fakeStatusShim{resp: &shimv1.StatusResponse{ApiVersion: "k3sm.shim.v0", ShimPid: pid, ShimStartUnixNano: start}},
			dialPid: pid, want: ErrShimVersion},
		{name: "status names another shim", srv: &fakeStatusShim{resp: &shimv1.StatusResponse{ApiVersion: shimv1.APIVersion, ShimPid: pid + 1, ShimStartUnixNano: start}},
			dialPid: pid, want: ErrShimIdentity},
		{name: "two failed status calls", srv: &fakeStatusShim{fail: true}, dialPid: pid, want: ErrShimUnresponsive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := serveFakeShim(t, tc.srv)
			id := ShimIdentity{Container: "c", Dir: dir, Pid: pid, StartUnixNano: start}
			conn, st, err := ConnectShim(context.Background(), pidDialer{pid: tc.dialPid}, id, tc.procStart)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ConnectShim: %v", err)
				}
				defer conn.Close()
				if st.GetChildPid() != 4243 {
					t.Fatalf("child pid %d, want 4243", st.GetChildPid())
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ConnectShim: %v, want %v", err, tc.want)
			}
			if tc.want == ErrShimUnresponsive && tc.srv.calls.Load() != 2 {
				t.Fatalf("Status called %d times, want exactly 2", tc.srv.calls.Load())
			}
		})
	}
}

func TestShimExitPrefersTheRecord(t *testing.T) {
	ctx := context.Background()
	t.Run("record", func(t *testing.T) {
		p := &Process{shimDir: t.TempDir()}
		_ = WriteExitRecord(p.shimDir, ExitRecord{ExitCode: 3})
		p.NoteKill(9)
		if code, sig, err := p.shimExit(ctx, 137, 9, nil); code != 3 || sig != 0 || err != nil {
			t.Fatalf("= %d %d %v, want the record's 3 0 <nil>", code, sig, err)
		}
	})
	t.Run("kill intent", func(t *testing.T) {
		p := &Process{shimDir: t.TempDir()}
		p.NoteKill(9)
		if code, sig, err := p.shimExit(ctx, 0, 0, ErrExitUnknown); code != 137 || sig != 9 || err != nil {
			t.Fatalf("= %d %d %v, want 137 9 <nil>", code, sig, err)
		}
	})
	t.Run("crashed", func(t *testing.T) {
		p := &Process{shimDir: t.TempDir()}
		if _, _, err := p.shimExit(ctx, 139, 11, nil); !errors.Is(err, ErrShimCrashed) {
			t.Fatalf("err = %v, want ErrShimCrashed", err)
		}
	})
}
