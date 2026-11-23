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
	"log/slog"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// stderrInitSpawner writes payload to the FIRST spawn's stderr (the init
// container) and nothing to any later one.
type stderrInitSpawner struct {
	mu      sync.Mutex
	next    int
	payload string
}

func (s *stderrInitSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if _, err := podEnvSpawn(spec); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	if s.next == 1 {
		if err := writeRawToStreamDup(spec.StderrFD, s.payload); err != nil {
			return 0, err
		}
	}
	return 4000 + s.next, nil
}

// firstExitsWaiter reports code at once for the first pid it is asked about
// (the init container) and blocks every later one until its context ends.
type firstExitsWaiter struct {
	mu    sync.Mutex
	first int
	code  int
}

func (w *firstExitsWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	w.mu.Lock()
	if w.first == 0 {
		w.first = pid
	}
	isFirst := w.first == pid
	w.mu.Unlock()
	if isFirst {
		return w.code, 0, nil
	}
	<-ctx.Done()
	return 0, 0, ctx.Err()
}

// TestFailedInitStderrSurvivesRejectedCreate: an init container that writes
// to stderr and exits non-zero rejects the pod, and the rejection's message
// carries the last of that output, bounded and sanitised, because a rejected
// pod has no log directory left to read it from. A clean init adds no tail.
func TestFailedInitStderrSurvivesRejectedCreate(t *testing.T) {
	const line = "yurei-agentd install-tree: refused io-error: /opt/yurei (No such file or directory)"
	var big strings.Builder
	for i := range 200 {
		big.WriteString("noise line ")
		big.WriteString(strings.Repeat("x", 40))
		big.WriteString(" ")
		big.WriteByte(byte('a' + i%26))
		big.WriteString("\n")
	}
	big.WriteString("final " + line + "\n")

	for _, tc := range []struct {
		name    string
		payload string
		code    int
		// want are substrings the rejection message must carry; deny are
		// substrings it must not.
		want []string
		deny []string
	}{
		{
			name:    "one stderr line",
			payload: line + "\n",
			code:    74,
			want:    []string{"init container install-tools exited 74: ", line},
		},
		{
			name:    "10 KB of output is bounded to the last lines",
			payload: big.String(),
			code:    74,
			want:    []string{"init container install-tools exited 74: ", "final " + line},
			deny:    []string{"noise line " + strings.Repeat("x", 40) + " a\n"},
		},
		{
			name:    "control bytes and invalid UTF-8 are stripped",
			payload: "bad\x1b[31mred\x1b[0m\x00nul\x07bell\xff\xfeend\r\n",
			code:    74,
			want:    []string{"init container install-tools exited 74: ", "bad", "red", "nul", "bell", "end"},
			deny:    []string{"\x1b", "\x00", "\x07", "\xff", "\r"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Spawner: &stderrInitSpawner{payload: tc.payload},
				Waiter:  &firstExitsWaiter{code: tc.code},
			})
			box := hostBinBox(rt, "pod-init-stderr")
			box.InitContainers = []*runtimev1.Container{{Name: "install-tools", Image: "/bin/true"}}

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() == nil {
				t.Fatal("CreatePod succeeded; a failed init container rejects the pod")
			}
			if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_SPAWN {
				t.Errorf("failure_reason = %v, want SPAWN", got)
			}
			msg := resp.GetError().GetMessage()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("rejection %q does not carry %q", msg, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(msg, d) {
					t.Errorf("rejection %q carries %q", msg, d)
				}
			}
			if !utf8.ValidString(msg) {
				t.Errorf("rejection %q is not valid UTF-8", msg)
			}
			prefix := "init container install-tools exited 74: "
			tail := strings.TrimPrefix(msg, prefix)
			if len(tail) > initTailMaxBytes {
				t.Errorf("tail is %d bytes, want at most %d", len(tail), initTailMaxBytes)
			}
			if n := strings.Count(tail, "\n") + 1; n > initTailMaxLines {
				t.Errorf("tail has %d lines, want at most %d", n, initTailMaxLines)
			}
			if c := strings.Count(logs.String(), "init container failed"); c != 1 {
				t.Errorf("logged the tail %d times at Warn, want once:\n%s", c, logs.String())
			}
		})
	}

	t.Run("a clean init adds no tail", func(t *testing.T) {
		logs := &lockedBuffer{}
		cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
		rt := newTestRuntimeCfg(t, cfg, Deps{
			Spawner: &stderrInitSpawner{payload: line + "\n"},
			Waiter:  &firstExitsWaiter{code: 0},
		})
		box := hostBinBox(rt, "pod-init-clean")
		box.InitContainers = []*runtimev1.Container{{Name: "install-tools", Image: "/bin/true"}}
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("CreatePod: %v", resp.GetError())
		}
		if strings.Contains(logs.String(), "init container failed") {
			t.Errorf("a clean init logged a failure tail:\n%s", logs.String())
		}
	})
}
