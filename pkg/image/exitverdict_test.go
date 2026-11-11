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

package image

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

// TestExitVerdictAbortBeforeExit pins the order of the two tests in
// exitVerdict: a real non-zero exit is "not validly signed" (false, nil), but
// the same exit error wrapped with an abort cause (a parent cancel, the timeout
// sentinel, a passed deadline) is an error, never the unsigned verdict.
func TestExitVerdictAbortBeforeExit(t *testing.T) {
	err := exec.Command("/usr/bin/false").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("/usr/bin/false returned %v (%T), want an *exec.ExitError", err, err)
	}

	cases := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"plain-exit-is-unsigned", ee, false},
		{"parent-cancel", fmt.Errorf("%w: %w", context.Canceled, ee), true},
		{"check-timeout", fmt.Errorf("%w: %w", ErrSignatureCheckTimeout, ee), true},
		{"deadline-exceeded", fmt.Errorf("%w: %w", context.DeadlineExceeded, ee), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := exitVerdict(c.err)
			if ok {
				t.Fatalf("exitVerdict(%v) = true, want false", c.err)
			}
			if c.wantErr && err == nil {
				t.Fatalf("exitVerdict(%v) = false, nil; an aborted tool must not read as unsigned", c.err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("exitVerdict(%v) = false, %v; want false, nil", c.err, err)
			}
		})
	}
}
