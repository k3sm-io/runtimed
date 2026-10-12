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
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	shimv1 "k3sm.io/apis/shim/v1"
)

// TestLaunchSpecTokenNamesTheDescriptor pins the token to the descriptor it
// names, so the two can never drift apart.
func TestLaunchSpecTokenNamesTheDescriptor(t *testing.T) {
	if want := "spec=" + strconv.Itoa(LaunchSpecChildFD); LaunchSpecToken != want {
		t.Errorf("LaunchSpecToken = %q, want %q", LaunchSpecToken, want)
	}
	if LaunchSpecChildFD <= ExecSyncChildFD {
		t.Errorf("LaunchSpecChildFD %d must sit above the exec-sync fd %d", LaunchSpecChildFD, ExecSyncChildFD)
	}
}

func TestLaunchPayloadRoundTrip(t *testing.T) {
	in := LaunchPayload{Env: []string{"PATH=/usr/bin", "DYLD_INSERT_LIBRARIES=/x.dylib", "EMPTY="}, Argv0: "sh", ExecSync: true}
	b, err := EncodeLaunchPayload(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeLaunchPayload(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if out.APIVersion != shimv1.APIVersion || !slices.Equal(out.Env, in.Env) || out.Argv0 != "sh" || !out.ExecSync {
		t.Errorf("round trip = %+v, want %+v stamped with %q", out, in, shimv1.APIVersion)
	}
	path, argv, envp := out.PodExec([]string{"/shadow/bash", "-c", "true"})
	if path != "/shadow/bash" || !slices.Equal(argv, []string{"sh", "-c", "true"}) || !slices.Equal(envp, in.Env) {
		t.Errorf("PodExec = (%q, %q, %q)", path, argv, envp)
	}
	envp[0] = "MUTATED=1"
	if out.Env[0] != "PATH=/usr/bin" {
		t.Error("PodExec handed back the payload's own env slice, not a copy")
	}
	if got := out.Getenv("PATH"); got != "/usr/bin" {
		t.Errorf("Getenv(PATH) = %q", got)
	}
}

// TestDecodeLaunchPayloadFailsClosed covers every malformed input the shim must
// refuse rather than exec from: truncated, empty, oversized, another contract
// version, and an env entry that is not NAME=value.
func TestDecodeLaunchPayloadFailsClosed(t *testing.T) {
	good, err := EncodeLaunchPayload(LaunchPayload{Env: []string{"A=b"}})
	if err != nil {
		t.Fatal(err)
	}
	raw := func(s string) []byte { return []byte(s) }
	cases := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{name: "empty", in: nil},
		{name: "truncated", in: good[:len(good)-3]},
		{name: "not json", in: raw("spec=4")},
		{name: "oversized", in: append(append(raw(`{"apiVersion":"`+shimv1.APIVersion+`","env":["A=`), bytes.Repeat([]byte("x"), maxShimSpecBytes)...), raw(`"]}`)...)},
		{name: "no version", in: raw(`{"env":["A=b"]}`), wantErr: ErrShimVersion},
		{name: "other version", in: raw(`{"apiVersion":"shim.k3sm.io/v0","env":["A=b"]}`), wantErr: ErrShimVersion},
		{name: "entry without =", in: raw(`{"apiVersion":"` + shimv1.APIVersion + `","env":["NOVALUE"]}`)},
		{name: "entry without a name", in: raw(`{"apiVersion":"` + shimv1.APIVersion + `","env":["=x"]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeLaunchPayload(bytes.NewReader(tc.in))
			if err == nil {
				t.Fatal("decoded; want a fail-closed error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestEncodeLaunchPayloadSizeCap refuses to write what the shim would refuse
// to read.
func TestEncodeLaunchPayloadSizeCap(t *testing.T) {
	big := LaunchPayload{Env: []string{"A=" + strings.Repeat("x", maxShimSpecBytes)}}
	if _, err := EncodeLaunchPayload(big); err == nil {
		t.Fatal("an oversized payload encoded")
	}
	if _, err := openLaunchPipe(big); err == nil {
		t.Fatal("an oversized payload got a pipe")
	}
}

// TestReadLaunchPayload covers the shim-side read: a pipe is read to EOF and
// closed; a non-pipe and a closed descriptor are refused.
func TestReadLaunchPayload(t *testing.T) {
	t.Run("pipe", func(t *testing.T) {
		lp, err := openLaunchPipe(LaunchPayload{Env: []string{"A=b"}})
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Dup(int(lp.r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = lp.r.Close()
		lp.start()
		p, err := ReadLaunchPayload(fd)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(p.Env, []string{"A=b"}) {
			t.Errorf("env = %q", p.Env)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Errorf("descriptor %d still open after the read (err %v)", fd, err)
		}
	})
	t.Run("regular file", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "payload")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := EncodeLaunchPayload(LaunchPayload{Env: []string{"A=b"}})
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if _, err := ReadLaunchPayload(fd); err == nil {
			t.Fatal("a regular file was accepted as the launch payload")
		}
	})
	t.Run("closed descriptor", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fd := int(r.Fd())
		_, _ = r.Close(), w.Close()
		if _, err := ReadLaunchPayload(fd); err == nil {
			t.Fatal("a closed descriptor was accepted")
		}
	})
}

// TestLaunchPipeReadEndSitsAboveTheChildDescriptors pins the invariant the
// posix_spawn file actions rely on: the read end is never one of the
// descriptors dup2'd before it (0-3) nor LaunchSpecChildFD itself.
func TestLaunchPipeReadEndSitsAboveTheChildDescriptors(t *testing.T) {
	lp, err := openLaunchPipe(LaunchPayload{})
	if err != nil {
		t.Fatal(err)
	}
	defer lp.abandon()
	if fd := lp.r.Fd(); fd <= LaunchSpecChildFD {
		t.Errorf("read end fd %d, want > %d", fd, LaunchSpecChildFD)
	}
}

// TestChildEnvForALaunchSpawn pins the spawner's environment decision: a
// launch-spec spawn gets an empty (never nil, which means inherit) environ and
// refuses one of its own; any other spawn passes Env through.
func TestChildEnvForALaunchSpawn(t *testing.T) {
	env, err := SpawnSpec{Launch: &LaunchPayload{Env: []string{"A=b"}}}.childEnv()
	if err != nil || env == nil || len(env) != 0 {
		t.Errorf("launch spawn childEnv = (%q, %v), want an empty non-nil environ", env, err)
	}
	if _, err := (SpawnSpec{Env: []string{"A=b"}, Launch: &LaunchPayload{}}).childEnv(); !errors.Is(err, ErrLaunchEnviron) {
		t.Errorf("launch spawn with an environ: err = %v, want ErrLaunchEnviron", err)
	}
	if env, _ := (SpawnSpec{Env: []string{"A=b"}}).childEnv(); !slices.Equal(env, []string{"A=b"}) {
		t.Errorf("plain spawn childEnv = %q", env)
	}
}

// TestOpenExecSyncFlagsAPayloadCopy proves the exec-sync hand-off rides the
// payload, not the environ, and never mutates the caller's payload.
func TestOpenExecSyncFlagsAPayloadCopy(t *testing.T) {
	caller := &LaunchPayload{Env: []string{"A=b"}}
	p := NewProcess(nil, nil, SpawnSpec{Path: "/x", Argv: []string{"/x"}, Env: []string{}, Launch: caller}, nil)
	p.ObserveExec(func(int, bool) {}, 0)
	spec, r, w := p.openExecSync()
	defer func() { _, _ = r.Close(), w.Close() }()
	if spec.Launch == nil || !spec.Launch.ExecSync || spec.ExecSyncFD == 0 {
		t.Errorf("spawn spec = %+v, want the exec-sync fd and the payload flag", spec)
	}
	if len(spec.Env) != 0 {
		t.Errorf("exec-sync added to the environ: %q", spec.Env)
	}
	if caller.ExecSync {
		t.Error("the caller's payload was mutated")
	}
}
