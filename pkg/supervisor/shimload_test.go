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
	"log/slog"
	"maps"
	"strings"
	"sync"
	"testing"
)

// fakeInspector returns fixed csflags or an error and counts its calls.
type fakeInspector struct {
	flags uint32
	err   error
	calls int
}

func (f *fakeInspector) CodeSignStatus(int) (uint32, error) {
	f.calls++
	return f.flags, f.err
}

// logRecord is one captured slog record: its level and its attrs as strings.
type logRecord struct {
	level slog.Level
	attrs map[string]string
}

// recordingHandler captures every record at every level.
type recordingHandler struct {
	mu      sync.Mutex
	records []logRecord
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, logRecord{level: r.Level, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) snapshot() []logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]logRecord(nil), h.records...)
}

// TestUnloadedShimIsDetectedLoudly proves the shim-load verdicts and their
// loudness: a code-signing hint that the shim cannot load, and every case
// where the load cannot be determined, yield exactly one Warn record naming
// the pod, container, binary and reason; an arrived handshake is the only
// route to "loaded" and silences the hint without consulting it; clean flags
// with no producer wired stay quiet.
func TestUnloadedShimIsDetectedLoudly(t *testing.T) {
	const (
		pod       = "pod-a"
		container = "main"
		binary    = "/opt/app/bin/server"
		pid       = 4242
	)
	cases := []struct {
		name       string
		flags      uint32
		err        error
		observed   bool
		handshake  HandshakeState
		want       ShimVerdict
		wantLevel  slog.Level
		wantCause  string // substring of the cause attr
		wantCalls  int
		wantLoud   bool
		wantReason string
	}{
		{"hardened runtime", CSRuntime | 0x2, nil, true, HandshakeUnsupported,
			ShimUnloaded, slog.LevelWarn, "CS_RUNTIME", 1, true, "unloaded"},
		{"library validation only", CSRequireLV, nil, true, HandshakeUnsupported,
			ShimUnloaded, slog.LevelWarn, "CS_REQUIRE_LV", 1, true, "unloaded"},
		{"forced library validation", CSForcedLV, nil, true, HandshakeUnsupported,
			ShimUnloaded, slog.LevelWarn, "CS_FORCED_LV", 1, true, "unloaded"},
		{"platform binary and restricted", CSPlatformBinary | CSRestrict, nil, true, HandshakeUnsupported,
			ShimUnloaded, slog.LevelWarn, "CS_PLATFORM_BINARY|CS_RESTRICT", 1, true, "unloaded"},
		{"plain binary, handshake pending", 0x22000201, nil, true, HandshakePending,
			ShimUnknown, slog.LevelWarn, "no handshake within the window", 1, true, "unknown"},
		{"plain binary, no producer wired", 0x22000201, nil, true, HandshakeUnsupported,
			ShimUnverified, slog.LevelDebug, "no handshake producer", 1, false, "unverified"},
		{"uninspectable process", 0, errors.New("no such process"), true, HandshakeUnsupported,
			ShimUnknown, slog.LevelWarn, "no such process", 1, true, "unknown"},
		{"exec not observed", CSRuntime, nil, false, HandshakeUnsupported,
			ShimUnknown, slog.LevelWarn, "exec not observed", 0, true, "unknown"},
		{"handshake arrived beats a hardened hint", CSRuntime, nil, true, HandshakeArrived,
			ShimLoaded, slog.LevelDebug, "handshake arrived", 0, false, "loaded"},
		{"handshake arrived beats an inspector error", 0, errors.New("no such process"), true, HandshakeArrived,
			ShimLoaded, slog.LevelDebug, "handshake arrived", 0, false, "loaded"},
		{"handshake arrived beats an unobserved exec", 0, nil, false, HandshakeArrived,
			ShimLoaded, slog.LevelDebug, "handshake arrived", 0, false, "loaded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins := &fakeInspector{flags: tc.flags, err: tc.err}
			h := &recordingHandler{}
			ld := ClassifyShimLoad(ins, pid, tc.observed, tc.handshake)
			ld.Log(slog.New(h), pod, container, binary)

			if ld.Verdict != tc.want {
				t.Errorf("verdict = %v, want %v (cause %q)", ld.Verdict, tc.want, ld.Cause)
			}
			if ld.Loud() != tc.wantLoud {
				t.Errorf("Loud() = %v, want %v", ld.Loud(), tc.wantLoud)
			}
			if ins.calls != tc.wantCalls {
				t.Errorf("inspector called %d times, want %d", ins.calls, tc.wantCalls)
			}
			recs := h.snapshot()
			if len(recs) != 1 {
				t.Fatalf("got %d log records, want exactly 1: %+v", len(recs), recs)
			}
			warns := 0
			for _, r := range recs {
				if r.level >= slog.LevelWarn {
					warns++
				}
			}
			if wantWarns := map[bool]int{true: 1, false: 0}[tc.wantLoud]; warns != wantWarns {
				t.Errorf("got %d Warn+ records, want %d", warns, wantWarns)
			}
			got := recs[0]
			if got.level != tc.wantLevel {
				t.Errorf("record level = %v, want %v", got.level, tc.wantLevel)
			}
			if !strings.Contains(got.attrs["cause"], tc.wantCause) {
				t.Errorf("cause = %q, want it to contain %q", got.attrs["cause"], tc.wantCause)
			}
			wantAttrs := map[string]string{
				"pod":       pod,
				"container": container,
				"binary":    binary,
				"reason":    tc.wantReason,
				"cause":     got.attrs["cause"],
			}
			if !maps.Equal(got.attrs, wantAttrs) {
				t.Errorf("record attrs = %v, want %v", got.attrs, wantAttrs)
			}
		})
	}
}
