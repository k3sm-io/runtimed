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

package guestagent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMemoryEvents(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    MemoryEvents
		wantErr error
	}{
		{
			name: "a 6.x kernel file with oom_group_kill",
			in:   "low 1\nhigh 22\nmax 3\noom 4\noom_kill 5\noom_group_kill 1\n",
			want: MemoryEvents{Low: 1, High: 22, Max: 3, OOM: 4, OOMKill: 5},
		},
		{name: "oom_kill absent is unknown, not zero", in: "low 0\nhigh 0\n", wantErr: ErrCgroupFieldAbsent},
		{name: "empty", in: "", wantErr: ErrCgroupFieldAbsent},
		{name: "a malformed counter", in: "oom_kill x\n", wantErr: errAny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMemoryEvents(tc.in)
			switch {
			case tc.wantErr == errAny:
				if err == nil {
					t.Fatal("want an error")
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("ParseMemoryEvents: %v", err)
			case got != tc.want:
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

var errAny = errors.New("any error")

func TestApplyMemoryLimitsRefusesForbiddenPairs(t *testing.T) {
	leaf := t.TempDir()
	for _, f := range []string{MemoryMaxFile, MemoryHighFile, MemoryOOMGroupFile} {
		if err := os.WriteFile(filepath.Join(leaf, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range []MemoryLimits{{Max: -1}, {High: -1}, {Max: 10, High: 11}} {
		if err := ApplyMemoryLimits(leaf, l); !errors.Is(err, ErrInvalidMemoryLimits) {
			t.Errorf("ApplyMemoryLimits(%+v) = %v, want ErrInvalidMemoryLimits", l, err)
		}
	}
	for _, f := range []string{MemoryMaxFile, MemoryHighFile, MemoryOOMGroupFile} {
		if b, _ := os.ReadFile(filepath.Join(leaf, f)); len(b) != 0 {
			t.Errorf("%s written on a refused pair: %q", f, b)
		}
	}
}
