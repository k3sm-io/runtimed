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
	"testing"
	"time"
)

// TestToolAbortedParentDeadline pins the third arm of toolAborted: a parent
// context whose own deadline expires while the tool runs. WithSignatureDeadline
// returns the parent's DeadlineExceeded (not the timeout sentinel, the tool
// deadline is far longer), and that error must read as an abort, never as an
// "unsigned" or passing verdict.
func TestToolAbortedParentDeadline(t *testing.T) {
	stubTools(t, sleeper)

	parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := runTool(parent, 30*time.Second, nil, nil, "stub-tool")
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("call took %s, want it bounded by the parent deadline", elapsed)
	}
	if err == nil {
		t.Fatal("runTool returned nil under an expired parent deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if errors.Is(err, ErrSignatureCheckTimeout) {
		t.Fatalf("err = %v, parent deadline must not read as the tool timeout sentinel", err)
	}
	if !toolAborted(err) {
		t.Fatalf("toolAborted(%v) = false, want true", err)
	}

	ok, verr := exitVerdict(err)
	if ok {
		t.Fatal("exitVerdict read a parent-deadline abort as a pass")
	}
	if verr == nil {
		t.Fatal("exitVerdict returned (false, nil): a parent-deadline abort read as unsigned")
	}
}
