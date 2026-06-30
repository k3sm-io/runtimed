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
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeSpawner records the spec and returns a canned pid/err. If it has a logLine
// and the spec carries a LogFD, it writes the line to that fd so the Process log
// pump can be exercised without a real child.
type fakeSpawner struct {
	pid     int
	err     error
	logLine string

	mu      sync.Mutex
	gotSpec SpawnSpec
}

func (f *fakeSpawner) Spawn(_ context.Context, spec SpawnSpec) (int, error) {
	f.mu.Lock()
	f.gotSpec = spec
	f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	if f.logLine != "" && spec.LogFD != 0 {
		w := os.NewFile(spec.LogFD, "logfd")
		_, _ = w.WriteString(f.logLine + "\n")
		_ = w.Close()
	}
	return f.pid, nil
}

// fakeWaiter returns a canned exit after an optional delay, honoring ctx.
type fakeWaiter struct {
	code  int
	sig   int
	err   error
	delay time.Duration
}

func (f fakeWaiter) WaitExit(ctx context.Context, _ int) (int, int, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		}
	}
	return f.code, f.sig, f.err
}

// TestProcessLifecycle exercises the supervisor's Process state machine with
// fakes: Start → Running → reap → Exited, with the recorded exit status.
func TestProcessLifecycle(t *testing.T) {
	cases := []struct {
		name     string
		waiter   fakeWaiter
		wantCode int
		wantSig  int
	}{
		{"clean-exit", fakeWaiter{code: 0}, 0, 0},
		{"nonzero-exit", fakeWaiter{code: 7}, 7, 0},
		{"killed", fakeWaiter{code: 137, sig: 9}, 137, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpawner{pid: 4242}
			p := NewProcess(sp, tc.waiter, SpawnSpec{Path: "/bin/true", Argv: []string{"/bin/true"}}, nil)

			if p.State() != StateInit {
				t.Fatalf("pre-start state = %v", p.State())
			}
			ctx := context.Background()
			if err := p.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if p.PID() != 4242 {
				t.Errorf("PID = %d", p.PID())
			}
			code, sig, err := p.Wait(ctx)
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if code != tc.wantCode || sig != tc.wantSig {
				t.Errorf("exit (code=%d sig=%d), want (code=%d sig=%d)", code, sig, tc.wantCode, tc.wantSig)
			}
			if p.State() != StateExited {
				t.Errorf("post-wait state = %v", p.State())
			}
		})
	}
}

// TestProcessLogCapture checks the combined-log pump delivers the child's output
// to the sink (via a real pipe wired by the fake spawner).
func TestProcessLogCapture(t *testing.T) {
	sp := &fakeSpawner{pid: 1, logLine: "hello-pod"}

	var mu sync.Mutex
	var got []string
	sink := func(line []byte) {
		mu.Lock()
		got = append(got, string(line))
		mu.Unlock()
	}

	p := NewProcess(sp, fakeWaiter{code: 0, delay: 50 * time.Millisecond},
		SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sink)
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := p.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// Give the pump goroutine a moment to flush after EOF.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "hello-pod" {
		t.Fatalf("captured logs = %v, want [hello-pod]", got)
	}
}

// TestProcessLogsDrained checks the drain edge: with a sink, LogsDrained closes only
// AFTER the pump has flushed every line to the sink (the B11 "logs fully drained"
// guarantee watchContainerExit relies on); with no sink there is no pump, so it is
// closed at Start.
func TestProcessLogsDrained(t *testing.T) {
	t.Run("closes-after-all-lines-flushed", func(t *testing.T) {
		sp := &fakeSpawner{pid: 1, logLine: "final-diagnostic-line"}
		var mu sync.Mutex
		var got []string
		sink := func(line []byte) {
			mu.Lock()
			got = append(got, string(line))
			mu.Unlock()
		}
		p := NewProcess(sp, fakeWaiter{code: 1, delay: 20 * time.Millisecond},
			SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sink)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		select {
		case <-p.LogsDrained():
		case <-time.After(2 * time.Second):
			t.Fatal("LogsDrained did not close")
		}
		// Once drained, every emitted line is already in the sink.
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0] != "final-diagnostic-line" {
			t.Fatalf("after drain, sink = %v, want [final-diagnostic-line]", got)
		}
	})

	t.Run("no-sink-drained-at-start", func(t *testing.T) {
		p := NewProcess(&fakeSpawner{pid: 2}, fakeWaiter{code: 0},
			SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		select {
		case <-p.LogsDrained():
		case <-time.After(time.Second):
			t.Fatal("LogsDrained must be closed for a sink-less process")
		}
	})
}

// TestSpawnFailure surfaces a spawn error and leaves the process unstarted.
func TestSpawnFailure(t *testing.T) {
	boom := errors.New("posix_spawn boom")
	sp := &fakeSpawner{err: boom}
	p := NewProcess(sp, fakeWaiter{}, SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
	if err := p.Start(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("want wrapped spawn error, got %v", err)
	}
	if p.State() != StateInit {
		t.Errorf("state after failed start = %v, want init", p.State())
	}
}

// TestWaitBeforeStart returns ErrNotStarted.
func TestWaitBeforeStart(t *testing.T) {
	p := NewProcess(&fakeSpawner{}, fakeWaiter{}, SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
	if _, _, err := p.Wait(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("want ErrNotStarted, got %v", err)
	}
}

// TestEnvCarriesThrough asserts the spawner receives the env verbatim (the DYLD
// insert pass-through the supervisor guarantees).
func TestEnvCarriesThrough(t *testing.T) {
	sp := &fakeSpawner{pid: 5}
	env := []string{"DYLD_INSERT_LIBRARIES=/opt/k3sm/libdnsshim.dylib", "FOO=bar"}
	p := NewProcess(sp, fakeWaiter{code: 0},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}, Env: env}, nil)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, _ = p.Wait(context.Background())
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.gotSpec.Env) != 2 || sp.gotSpec.Env[0] != env[0] {
		t.Fatalf("spawner env = %v, want %v", sp.gotSpec.Env, env)
	}
}

// TestNodeNetwork covers the M1 single-node PodNetwork.
func TestNodeNetwork(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"default-loopback", "", "127.0.0.1"},
		{"node-ip", "10.0.0.5", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NodeNetwork{IP: tc.ip}.Setup(context.Background(), "pod-1")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Setup() = %q, want %q", got, tc.want)
			}
		})
	}
}
