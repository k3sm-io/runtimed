//go:build darwin && cgo

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

package main

import "testing"

func TestParseMode(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		mode string
		ok   bool
	}{
		{name: "launch", argv: []string{"launch", "-1", "-1", "-", "-", "-", "/p.sb", "/bin/true"}, mode: "launch", ok: true},
		{name: "serve", argv: []string{"serve"}, mode: "serve", ok: true},
		{name: "exec", argv: []string{"exec", "-", "-", "/bin/echo"}, mode: "exec", ok: true},
		// The pre-mode shape: a new binary handed it must refuse, never read
		// the uid as a mode or the profile path as a token.
		{name: "old-shape argv fails closed", argv: []string{"-1", "-1", "-", "-", "-", "/p.sb", "/bin/true"}},
		{name: "empty", argv: nil},
		{name: "unknown", argv: []string{"launc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, rest, ok := parseMode(tc.argv)
			if ok != tc.ok || mode != tc.mode {
				t.Fatalf("parseMode(%q) = %q, %v; want %q, %v", tc.argv, mode, ok, tc.mode, tc.ok)
			}
			if ok && len(rest) != len(tc.argv)-1 {
				t.Fatalf("rest = %q", rest)
			}
		})
	}
}
