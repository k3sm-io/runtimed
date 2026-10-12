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

package execshim

import (
	"errors"
	"testing"
)

// TestRequireConfined drives the exec-mode guard through its seam: it passes
// only for a process the check reports sandboxed, and fails closed on an
// unsandboxed report and on a check that errors.
func TestRequireConfined(t *testing.T) {
	checkErr := errors.New("sandbox_check failed")
	cases := []struct {
		name    string
		ok      bool
		err     error
		wantErr error
	}{
		{name: "sandboxed", ok: true},
		{name: "not sandboxed", ok: false, wantErr: errExecUnconfined},
		{name: "check fails", err: checkErr, wantErr: checkErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireConfined(func() (bool, error) { return tc.ok, tc.err })
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("requireConfined = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("requireConfined = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRunExecSessionRefusesAnUnconfinedProcess runs the real check: this test
// process is not sandboxed, so exec mode must refuse before it parses or execs
// anything (a successful exec would replace the test binary).
func TestRunExecSessionRefusesAnUnconfinedProcess(t *testing.T) {
	if ok, err := selfSandboxed(); err != nil || ok {
		t.Fatalf("selfSandboxed() = (%v, %v) in an unconfined test process, want (false, nil)", ok, err)
	}
	if err := RunExecSession("-", "-", []string{"/usr/bin/true"}); !errors.Is(err, errExecUnconfined) {
		t.Fatalf("RunExecSession = %v, want errExecUnconfined", err)
	}
}
