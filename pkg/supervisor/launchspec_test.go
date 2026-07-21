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
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRlimitShimArgvRoundTrip is the B7 argv-codec slice: the resolved NUMERIC
// rlimit plan and the qos flag each encode as ONE fixed-position shim argv token
// (inserted BEFORE the profile path), decode back to the identical plan, and any
// malformed/truncated token is a shim-FATAL error (fail-closed under daemon/shim
// binary skew — never skip-with-warning, never exec without the handed limits).
//
// The encode expectations are HAND-WRITTEN GOLDEN LITERALS on purpose (never
// encoder-output-vs-encoder-output): they pin the wire format the shim's decoder
// and the daemon's encoder must both speak across a binary-skew window.
func TestRlimitShimArgvRoundTrip(t *testing.T) {
	t.Run("golden-encode-and-decode-match", func(t *testing.T) {
		cases := []struct {
			name string
			plan []PlannedRlimit
			want string // hand-written golden literal
		}{
			{
				name: "empty-plan-dash-sentinel",
				plan: nil,
				want: "-",
			},
			{
				// 8 is darwin RLIMIT_NOFILE — the codec carries the NUMERIC selector;
				// the RLIMIT_* name table stays daemon-side only.
				name: "single-entry",
				plan: []PlannedRlimit{{Resource: 8, Lim: unix.Rlimit{Cur: 1024, Max: 4096}}},
				want: "r=8:1024:4096",
			},
			{
				name: "multiple-entries-comma-joined",
				plan: []PlannedRlimit{
					{Resource: 8, Lim: unix.Rlimit{Cur: 256, Max: 512}},
					{Resource: 7, Lim: unix.Rlimit{Cur: 100, Max: 200}},
				},
				want: "r=8:256:512,7:100:200",
			},
			{
				// darwin RLIM_INFINITY's magnitude (2^63-1) survives verbatim.
				name: "infinity-magnitude-verbatim",
				plan: []PlannedRlimit{{Resource: 5, Lim: unix.Rlimit{
					Cur: 9223372036854775807, Max: 9223372036854775807}}},
				want: "r=5:9223372036854775807:9223372036854775807",
			},
			{
				name: "zero-values-verbatim",
				plan: []PlannedRlimit{{Resource: 4, Lim: unix.Rlimit{Cur: 0, Max: 0}}},
				want: "r=4:0:0",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := EncodeRlimits(tc.plan)
				if got != tc.want {
					t.Fatalf("EncodeRlimits = %q, want golden %q", got, tc.want)
				}
				decoded, err := ParseRlimits(tc.want)
				if err != nil {
					t.Fatalf("ParseRlimits(%q): %v", tc.want, err)
				}
				if !reflect.DeepEqual(decoded, tc.plan) {
					t.Fatalf("round-trip = %+v, want %+v", decoded, tc.plan)
				}
			})
		}
	})

	t.Run("qos-golden-and-round-trip", func(t *testing.T) {
		if got := EncodeQoS(true); got != "q=bg" {
			t.Errorf("EncodeQoS(true) = %q, want golden %q", got, "q=bg")
		}
		if got := EncodeQoS(false); got != "-" {
			t.Errorf("EncodeQoS(false) = %q, want golden %q", got, "-")
		}
		bg, err := ParseQoS("q=bg")
		if err != nil || !bg {
			t.Errorf("ParseQoS(q=bg) = (%v, %v), want (true, nil)", bg, err)
		}
		bg, err = ParseQoS("-")
		if err != nil || bg {
			t.Errorf("ParseQoS(-) = (%v, %v), want (false, nil)", bg, err)
		}
	})

	t.Run("malformed-rlimit-token-is-fatal", func(t *testing.T) {
		bad := []string{
			"",                      // empty (truncated argv splice)
			"r=",                    // prefix with no payload
			"r=8",                   // missing cur/max
			"r=8:1024",              // missing max (truncated)
			"r=8:1024:4096:9",       // extra field
			"r=8:1024:4096,",        // trailing comma (truncated entry)
			"r=,8:1:2",              // leading empty entry
			"r=:1:2",                // empty resource
			"r=a:1:2",               // non-numeric resource
			"r=8:x:4096",            // non-numeric cur
			"r=8:1024:x",            // non-numeric max
			"r=-1:1:2",              // negative resource selector
			"r=8:-1:2",              // negative cur (rlim_t is unsigned)
			"q=bg",                  // qos token in the rlimit position (skew)
			"/tmp/k3sm-sbpl-x42.sb", // OLD-daemon argv: a profile path where the
			"8:1024:4096",           // new shim expects the rlimit token; and a
			"501",                   // stray positional (arity skew) — all fatal
		}
		for _, tok := range bad {
			if plan, err := ParseRlimits(tok); err == nil {
				t.Errorf("ParseRlimits(%q) = (%+v, nil), want a fatal error", tok, plan)
			}
		}
	})

	t.Run("malformed-qos-token-is-fatal", func(t *testing.T) {
		bad := []string{"", "q=", "q=fg", "bg", "q=bg ", "Q=BG", "r=8:1:2", "/tmp/p.sb"}
		for _, tok := range bad {
			if bg, err := ParseQoS(tok); err == nil {
				t.Errorf("ParseQoS(%q) = (%v, nil), want a fatal error", tok, bg)
			}
		}
	})
}

// TestNormalizeNOFILE is the pure-arithmetic table for the darwin RLIMIT_NOFILE
// taxonomy (B7): darwin setrlimit(2) returns EINVAL — NOT a clamp — for
// rlim_cur=RLIM_INFINITY (or beyond OPEN_MAX) on RLIMIT_NOFILE, so an
// infinite/oversized soft limit is clamped DOWN to min(OPEN_MAX ceiling, hard)
// before the syscall; and a too-tight soft limit is floored UP to minNOFILESoft
// so sandbox_compile's profile read and the exec'd image's dyld (+ the
// DYLD-inserted DNS shim) do not starve for descriptors AFTER confinement.
func TestNormalizeNOFILE(t *testing.T) {
	inf := uint64(unix.RLIM_INFINITY)
	cases := []struct {
		name     string
		in, want unix.Rlimit
	}{
		{
			name: "infinite-cur-clamped-to-open-max",
			in:   unix.Rlimit{Cur: inf, Max: inf},
			want: unix.Rlimit{Cur: 10240, Max: inf},
		},
		{
			name: "infinite-cur-clamped-to-finite-hard-below-open-max",
			in:   unix.Rlimit{Cur: inf, Max: 4096},
			want: unix.Rlimit{Cur: 4096, Max: 4096},
		},
		{
			name: "oversized-cur-clamped-to-hard",
			in:   unix.Rlimit{Cur: 20000, Max: 8192},
			want: unix.Rlimit{Cur: 8192, Max: 8192},
		},
		{
			name: "oversized-cur-clamped-to-open-max-under-infinite-hard",
			in:   unix.Rlimit{Cur: 20000, Max: inf},
			want: unix.Rlimit{Cur: 10240, Max: inf},
		},
		{
			name: "tight-soft-floored-up",
			in:   unix.Rlimit{Cur: 16, Max: 1024},
			want: unix.Rlimit{Cur: 256, Max: 1024},
		},
		{
			name: "tight-soft-and-hard-both-floored",
			in:   unix.Rlimit{Cur: 8, Max: 64},
			want: unix.Rlimit{Cur: 256, Max: 256},
		},
		{
			name: "infinite-cur-tiny-hard-clamps-then-floors",
			in:   unix.Rlimit{Cur: inf, Max: 100},
			want: unix.Rlimit{Cur: 256, Max: 256},
		},
		{
			name: "in-range-untouched",
			in:   unix.Rlimit{Cur: 1024, Max: 4096},
			want: unix.Rlimit{Cur: 1024, Max: 4096},
		},
		{
			name: "floor-boundary-untouched",
			in:   unix.Rlimit{Cur: 256, Max: 256},
			want: unix.Rlimit{Cur: 256, Max: 256},
		},
		{
			name: "open-max-boundary-untouched",
			in:   unix.Rlimit{Cur: 10240, Max: 10240},
			want: unix.Rlimit{Cur: 10240, Max: 10240},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeNOFILE(tc.in); got != tc.want {
				t.Fatalf("normalizeNOFILE(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}
