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
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCreatePodRefusedWhileTheSameIdIsTornDown: a CreatePod for an id whose
// teardown is still running is refused with a retryable failure and creates
// nothing — the old teardown still removes that id's pod dir and releases its
// address, both keyed by the id alone. Once the teardown has finished, the
// same CreatePod succeeds.
func TestCreatePodRefusedWhileTheSameIdIsTornDown(t *testing.T) {
	const podID = "pod-recreated"
	rt, pn, first := heldDelete(t, podID)

	dir, err := rt.podDir(podID)
	if err != nil {
		t.Fatalf("podDir: %v", err)
	}
	// The held teardown has not reached its pod dir removal yet. Remove the old
	// dir here so that any dir present after the refused create is one that
	// create made.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove the old pod dir: %v", err)
	}
	setupsBefore := pn.setupCount()

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil {
		t.Fatalf("CreatePod during the teardown: RPC error %v, want a typed refusal", err)
	}
	e := resp.GetError()
	if e == nil || codes.Code(e.GetCode()) != codes.Unavailable {
		t.Fatalf("CreatePod during the teardown = %v, want an Unavailable refusal", resp)
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_ALREADY_EXISTS {
		t.Fatalf("failure reason = %v, want ALREADY_EXISTS", got)
	}
	if !strings.Contains(e.GetMessage(), podID) || strings.Contains(e.GetMessage(), rt.cache.PodsRoot()) {
		t.Fatalf("refusal message %q: want the pod id and no host path", e.GetMessage())
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("pod dir after the refused create: stat err = %v, want not-exist", err)
	}
	if got := pn.setupCount(); got != setupsBefore {
		t.Fatalf("network Setup calls = %d after the refused create, want %d", got, setupsBefore)
	}
	rt.mu.Lock()
	creating := rt.creating[podID]
	_, registered := rt.pods[podID]
	rt.mu.Unlock()
	if creating != 0 || registered {
		t.Fatalf("after the refused create: creating = %d, registered = %v; want 0, false", creating, registered)
	}

	close(pn.gate)
	if f := awaitDelete(t, first, "first"); f.err != nil {
		t.Fatalf("DeletePod: %v", f.err)
	}

	resp, err = rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || (resp.GetError() != nil && resp.GetError().GetCode() != 0) {
		t.Fatalf("CreatePod after the teardown = (%v, %v), want success", resp, err)
	}
	if got := pn.setupCount(); got != setupsBefore+1 {
		t.Fatalf("network Setup calls = %d after the teardown, want %d", got, setupsBefore+1)
	}
}
