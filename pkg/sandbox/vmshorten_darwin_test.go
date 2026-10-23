//go:build darwin

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

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeHelperStop is a helper's stop as the control socket drives it: it
// applies the shorten function exactly as the lifecycle does (never extending)
// and records what it was asked, in the shared order log.
type fakeHelperStop struct {
	mu    sync.Mutex
	grace time.Duration
	calls int
	order *orderLog
	// stopping makes it answer as a helper whose stop has already begun.
	stopping bool
}

func (f *fakeHelperStop) ShortenGrace(shorten func(time.Duration) (time.Duration, error)) (time.Duration, time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	from := f.grace
	if f.stopping {
		f.order.add("already-stopping")
		return from, from, true, nil
	}
	next, err := shorten(from)
	if err != nil {
		return from, from, false, err
	}
	if next < f.grace {
		f.grace = next
	}
	f.calls++
	f.order.add("shorten")
	return from, f.grace, false, nil
}

func (f *fakeHelperStop) snapshot() (time.Duration, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grace, f.calls
}

type orderLog struct {
	mu  sync.Mutex
	got []string
}

func (o *orderLog) add(s string) {
	o.mu.Lock()
	o.got = append(o.got, s)
	o.mu.Unlock()
}

func (o *orderLog) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.got...)
}

// controlDir returns a short directory for a control socket (a unix socket
// path is capped near 104 bytes).
func controlDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveHelperControl serves a control socket in dir from this process: the
// shorten-aware one when stop is non-nil, the banner-only one (a helper that
// predates the request) otherwise.
func serveHelperControl(t *testing.T, dir string, stop VMHostStopShortener) {
	t.Helper()
	lis, err := net.Listen("unix", filepath.Join(dir, VMHostControlSocketName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	v := VMHostVersion{Protocol: VMHostProtocolVersion, Pid: os.Getpid()}
	go func() {
		if stop == nil {
			_ = ServeVMHostControl(lis, v)
			return
		}
		_ = ServeVMHostControlStop(lis, VMHostControl{Version: v, Stop: stop, PodID: "p1", Logger: slog.New(slog.DiscardHandler)})
	}()
}

// serveBannerAndClose serves socket as a helper that predates the shorten
// request: each connection gets the banner and is closed at once. The returned
// channel receives once per connection, after its close.
func serveBannerAndClose(t *testing.T, socket string) <-chan struct{} {
	t.Helper()
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	banner, err := json.Marshal(VMHostVersion{Protocol: VMHostProtocolVersion, Pid: os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write(append(banner, '\n'))
			_ = conn.Close()
			closed <- struct{}{}
		}
	}()
	return closed
}

// mustDialUnix connects to socket, closing the connection at cleanup.
func mustDialUnix(t *testing.T, socket string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// stopAllBackend returns a backend holding one live helper for pod p1 with the
// given grace, served (as far as the control socket goes) by this process. Its
// signal seam never signals anything: it records the signal in order and, on
// SIGTERM, makes the helper's exit observable, as a helper that stops would.
func stopAllBackend(t *testing.T, runDir string, grace time.Duration, order *orderLog) (*VMBackend, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	exit := make(chan struct{})
	var once sync.Once
	b := NewVMBackend()
	b.log = slog.New(slog.NewTextHandler(&logs, nil))
	b.signal = func(_ int, sig os.Signal) error {
		order.add("signal:" + sig.String())
		if sig == syscall.SIGTERM {
			once.Do(func() { close(exit) })
		}
		return nil
	}
	b.live = map[string]*vmProc{"p1": {
		podID:       "p1",
		exit:        adoptedExit{done: exit},
		pgid:        os.Getpid(),
		helperGrace: grace,
		runDir:      runDir,
	}}
	return b, &logs
}

// TestStopAllVMsShortensACutGrace pins the daemon half: a stop of
// every guest asks a helper whose grace its bound would cut to start its stop
// with the grace that fits, over the real control socket and before the
// SIGTERM; a helper whose grace fits is not asked; and a helper that predates
// the request (banner only) is stopped with plain SIGTERM, as before.
func TestStopAllVMsShortensACutGrace(t *testing.T) {
	t.Run("a grace above the cut receives the shortened value before SIGTERM", func(t *testing.T) {
		order := &orderLog{}
		dir := controlDir(t)
		helper := &fakeHelperStop{grace: 90 * time.Second, order: order}
		serveHelperControl(t, dir, helper)
		b, logs := stopAllBackend(t, dir, 90*time.Second, order)

		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		got, calls := helper.snapshot()
		cut := VMStopAllBound - VMHelperStopMargin
		if calls != 1 || got > cut || got < cut-2*time.Second {
			t.Errorf("the helper's grace is %s after %d requests, want one request shortening it to just under %s", got, calls, cut)
		}
		if seq := order.snapshot(); len(seq) != 2 || seq[0] != "shorten" || seq[1] != "signal:terminated" {
			t.Errorf("order = %q, want the shorten request before the SIGTERM", seq)
		}
		if !strings.Contains(logs.String(), "its helper started the stop with a grace that fits") {
			t.Errorf("no shortened line logged:\n%s", logs.String())
		}
	})

	t.Run("a grace that fits is not asked", func(t *testing.T) {
		order := &orderLog{}
		dir := controlDir(t)
		helper := &fakeHelperStop{grace: 10 * time.Second, order: order}
		serveHelperControl(t, dir, helper)
		b, _ := stopAllBackend(t, dir, 10*time.Second, order)

		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		if _, calls := helper.snapshot(); calls != 0 {
			t.Errorf("a helper whose grace fits was sent %d shorten requests", calls)
		}
		if seq := order.snapshot(); len(seq) != 1 || seq[0] != "signal:terminated" {
			t.Errorf("order = %q, want SIGTERM alone", seq)
		}
	})

	t.Run("an old helper with a banner only falls back to SIGTERM", func(t *testing.T) {
		order := &orderLog{}
		dir := controlDir(t)
		serveHelperControl(t, dir, nil)
		out, err := ShortenVMHostStop(context.Background(), filepath.Join(dir, VMHostControlSocketName), os.Getpid(), VMStopAllBound)
		if err != nil || out.Result != VMHostShortenUnsupported {
			t.Fatalf("ShortenVMHostStop on a banner-only helper = (%+v, %v), want unsupported", out, err)
		}

		b, logs := stopAllBackend(t, dir, 90*time.Second, order)
		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		if seq := order.snapshot(); len(seq) != 1 || seq[0] != "signal:terminated" {
			t.Errorf("order = %q, want the plain SIGTERM", seq)
		}
		if !strings.Contains(logs.String(), "does not take a shorten request") {
			t.Errorf("the fallback was not logged:\n%s", logs.String())
		}
	})

	t.Run("an old helper gone before its peer is read is unsupported and falls back to SIGTERM", func(t *testing.T) {
		// A helper that predates the request writes its banner and closes at
		// once. The peer-pid read below waits until it has, so the kernel's
		// LOCAL_PEERPID meets a disconnected socket every time (ENOTCONN).
		order := &orderLog{}
		dir := controlDir(t)
		socket := filepath.Join(dir, VMHostControlSocketName)
		closed := serveBannerAndClose(t, socket)
		afterClose := func(conn net.Conn) (int, error) {
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Error("the helper never closed the connection")
			}
			return controlPeerPid(conn)
		}
		if _, err := afterClose(mustDialUnix(t, socket)); !errors.Is(err, syscall.ENOTCONN) {
			t.Fatalf("LOCAL_PEERPID after the helper closed = %v, want ENOTCONN (the case this pins)", err)
		}
		out, err := shortenVMHostStop(context.Background(), socket, os.Getpid(), VMStopAllBound, afterClose)
		if err != nil || out.Result != VMHostShortenUnsupported || out.Reason == "" {
			t.Fatalf("shortenVMHostStop on a helper gone before its peer is read = (%+v, %v), want unsupported with a reason", out, err)
		}

		b, logs := stopAllBackend(t, dir, 90*time.Second, order)
		b.shorten = func(ctx context.Context, socket string, pid int, bound time.Duration) (VMHostShortenOutcome, error) {
			return shortenVMHostStop(ctx, socket, pid, bound, afterClose)
		}
		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		if seq := order.snapshot(); len(seq) != 1 || seq[0] != "signal:terminated" {
			t.Errorf("order = %q, want the plain SIGTERM", seq)
		}
		if !strings.Contains(logs.String(), "does not take a shorten request") || strings.Contains(logs.String(), "the shorten request failed") {
			t.Errorf("the fallback was not logged as an old helper:\n%s", logs.String())
		}
	})

	t.Run("a helper with no control socket falls back to SIGTERM", func(t *testing.T) {
		order := &orderLog{}
		b, _ := stopAllBackend(t, controlDir(t), 90*time.Second, order)
		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		if seq := order.snapshot(); len(seq) != 1 || seq[0] != "signal:terminated" {
			t.Errorf("order = %q, want the plain SIGTERM", seq)
		}
	})

	t.Run("an already-stopping helper with a grace the bound cuts is a warned cut", func(t *testing.T) {
		for _, tc := range []struct {
			grace time.Duration
			level string
		}{
			{90 * time.Second, "level=WARN"},
			{20 * time.Second, "level=INFO"},
		} {
			order := &orderLog{}
			dir := controlDir(t)
			serveHelperControl(t, dir, &fakeHelperStop{grace: tc.grace, order: order, stopping: true})
			// The daemon's record says 90s either way; the helper's answer
			// names the grace its stop actually runs with.
			b, logs := stopAllBackend(t, dir, 90*time.Second, order)
			if err := b.StopAllVMs(context.Background()); err != nil {
				t.Fatalf("StopAllVMs: %v", err)
			}
			line := ""
			for _, l := range strings.Split(logs.String(), "\n") {
				if strings.Contains(l, "already stopping") {
					line = l
				}
			}
			if !strings.Contains(line, tc.level) {
				t.Errorf("helper grace %s: already-stopping line %q, want %s", tc.grace, line, tc.level)
			}
		}
	})

	t.Run("no request sent is logged with its reason, never as a request", func(t *testing.T) {
		order := &orderLog{}
		b, logs := stopAllBackend(t, "", 90*time.Second, order)
		if err := b.StopAllVMs(context.Background()); err != nil {
			t.Fatalf("StopAllVMs: %v", err)
		}
		if !strings.Contains(logs.String(), "no request sent: the helper's run dir is not recorded") {
			t.Errorf("no reason logged:\n%s", logs.String())
		}
		if strings.Contains(logs.String(), "asking its helper") || strings.Contains(logs.String(), "started the stop") {
			t.Errorf("a log line claims a request that was not sent:\n%s", logs.String())
		}
	})

	t.Run("a socket served by another pid is never sent the request", func(t *testing.T) {
		order := &orderLog{}
		dir := controlDir(t)
		helper := &fakeHelperStop{grace: 90 * time.Second, order: order}
		serveHelperControl(t, dir, helper)
		_, err := ShortenVMHostStop(context.Background(), filepath.Join(dir, VMHostControlSocketName), os.Getpid()+1, VMStopAllBound)
		if err == nil || !strings.Contains(err.Error(), "nothing sent") {
			t.Errorf("ShortenVMHostStop to the wrong pid = %v, want a refusal before sending", err)
		}
		if _, calls := helper.snapshot(); calls != 0 {
			t.Errorf("the request reached a process that is not the recorded helper")
		}
	})
}

// TestShortenedStopGrace pins the one formula: max(1 s, min(grace, bound -
// VMHelperStopMargin)), with a bound below the floor refused.
func TestShortenedStopGrace(t *testing.T) {
	for _, tc := range []struct {
		name         string
		grace, bound time.Duration
		want         time.Duration
		refused      bool
	}{
		{"a long grace is cut to the bound less the margin", 90 * time.Second, 45 * time.Second, 37 * time.Second, false},
		{"a grace that fits is kept", 30 * time.Second, 45 * time.Second, 30 * time.Second, false},
		{"the floor bound leaves one second", 90 * time.Second, VMHostMinShortenBound, time.Second, false},
		{"below the floor is refused", 90 * time.Second, VMHostMinShortenBound - time.Nanosecond, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ShortenedStopGrace(tc.grace, tc.bound)
			if (err != nil) != tc.refused || got != tc.want {
				t.Errorf("ShortenedStopGrace(%s, %s) = (%s, %v), want (%s, refused=%v)", tc.grace, tc.bound, got, err, tc.want, tc.refused)
			}
		})
	}
}

// TestVMHostControlRefusesAForeignPeer pins the second layer under the
// owner-only socket: a shorten request from a peer whose uid is neither root
// nor the helper's own still gets the banner, is refused with an error, and
// never reaches the stop; the helper's own uid is accepted.
func TestVMHostControlRefusesAForeignPeer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uid     uint32
		refused bool
	}{
		{"a foreign uid is refused", uint32(os.Geteuid()) + 1000, true},
		{"root is accepted", 0, false},
		{"the helper's own uid is accepted", uint32(os.Geteuid()), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order := &orderLog{}
			helper := &fakeHelperStop{grace: 90 * time.Second, order: order}
			dir := controlDir(t)
			socket := filepath.Join(dir, VMHostControlSocketName)
			lis, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lis.Close() })
			go func() {
				_ = ServeVMHostControlStop(lis, VMHostControl{
					Version: VMHostVersion{Protocol: VMHostProtocolVersion, Pid: os.Getpid()},
					Stop:    helper, PodID: "p1", Logger: slog.New(slog.DiscardHandler),
					peerUID: func(net.Conn) (uint32, error) { return tc.uid, nil },
				})
			}()
			out, err := ShortenVMHostStop(context.Background(), socket, os.Getpid(), VMStopAllBound)
			_, calls := helper.snapshot()
			if tc.refused {
				if err == nil || !strings.Contains(err.Error(), "may not shorten") {
					t.Errorf("ShortenVMHostStop = (%+v, %v), want the foreign peer refused", out, err)
				}
				if calls != 0 {
					t.Errorf("a foreign peer's request reached the stop")
				}
				return
			}
			if err != nil || out.Result != VMHostShortened || calls != 1 {
				t.Errorf("ShortenVMHostStop = (%+v, %v) with %d calls, want shortened once", out, err, calls)
			}
		})
	}
}
