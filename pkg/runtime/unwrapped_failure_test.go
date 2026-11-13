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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// unwrappedMarker is a host path an unwrapped error carries in the gates
// below: neither it nor the "/var/" prefix may reach a client.
const unwrappedMarker = "/var/lib/k3sm/MARKER"

// assertFixedSentence fails t unless msg carries sentence and nothing of the
// marker path.
func assertFixedSentence(t *testing.T, what, msg, sentence string) {
	t.Helper()
	if strings.Contains(msg, "MARKER") || strings.Contains(msg, "/var/") {
		t.Errorf("%s %q carries the host path", what, msg)
	}
	if m := absHostPath.FindString(msg); m != "" {
		t.Errorf("%s %q matches the absolute path %q", what, msg, m)
	}
	if !strings.Contains(msg, sentence) {
		t.Errorf("%s %q lacks the fixed sentence %q", what, msg, sentence)
	}
}

// assertLoggedAttrs parses out as slog JSON records and requires exactly one
// whose "err" attribute carries marker; that record must be at level and carry
// every attrs entry as its own structured attribute (not a message substring).
func assertLoggedAttrs(t *testing.T, out, level, marker string, attrs map[string]string) {
	t.Helper()
	var found []map[string]any
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q is not a JSON record: %v", line, err)
		}
		if e, _ := rec["err"].(string); strings.Contains(e, marker) {
			found = append(found, rec)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the cause (%q) was logged %d times, want once:\n%s", marker, len(found), out)
	}
	rec := found[0]
	if got, _ := rec["level"].(string); got != level {
		t.Errorf("level attribute = %q, want %q", got, level)
	}
	if msg, _ := rec["msg"].(string); strings.Contains(msg, marker) {
		t.Errorf("the cause is in the log message %q, want it in the err attribute", msg)
	}
	for k, want := range attrs {
		if got, ok := rec[k].(string); !ok || got != want {
			t.Errorf("log attribute %s = %v, want %q (record %v)", k, rec[k], want, rec)
		}
	}
}

// absHostPath matches any absolute-path-looking run: a slash followed by a
// path element. The fixed sentences carry no slash.
var absHostPath = regexp.MustCompile(`/[A-Za-z0-9._-]+`)

// TestCreateFailureReplyHidesHostPathsByDefault drives an unwrapped create
// error (the network setup's, naming a host path) through CreatePod: the reply
// is the create stage's fixed sentence, and the daemon log has the cause.
func TestCreateFailureReplyHidesHostPathsByDefault(t *testing.T) {
	const podID = "pod-unwrapped-create"
	logs := &lockedBuffer{}
	cfg := Config{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	netw := &recordingNetwork{setupErr: fmt.Errorf("open %s/lo0.lease: %w", unwrappedMarker, errors.New("permission denied"))}
	rt := newTestRuntimeCfg(t, cfg, Deps{Network: netw})

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod succeeded through a failing network setup")
	}
	if got := codes.Code(resp.GetError().GetCode()); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
	assertFixedSentence(t, "CreatePod reply", resp.GetError().GetMessage(), stageCreate.sentence())
	assertLoggedAttrs(t, logs.String(), "ERROR", unwrappedMarker, map[string]string{"pod": podID})
}

// TestUnwrappedStartErrorDoesNotReachTheTenant is the start-path sibling: an
// unwrapped error a start site returns is reported by StartContainer's
// failure path as the start stage's fixed sentence, on the Waiting message and
// in the reply, with the cause once in the daemon log beside the pod and
// container. A tenantText error (an invalid PodBox) keeps its own text.
func TestUnwrappedStartErrorDoesNotReachTheTenant(t *testing.T) {
	const podID = "pod-unwrapped-start"
	logs := &lockedBuffer{}
	cfg := Config{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	rt := newTestRuntimeCfg(t, cfg, Deps{})
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v", resp.GetError())
	}
	rt.mu.Lock()
	p := rt.pods[podID]
	rt.mu.Unlock()
	cp := rt.findContainer(p, "main")
	if cp == nil {
		t.Fatal("pod has no container main")
	}

	cause := fmt.Errorf("prepare %s/rootfs: %w", unwrappedMarker, errors.New("input/output error"))
	sresp := rt.startFailed(p, cp, runtimev1.FailureReason_FAILURE_REASON_SPAWN, cause)
	assertFixedSentence(t, "StartContainer reply", sresp.GetError().GetMessage(), stageStart.sentence())
	if got := codes.Code(sresp.GetError().GetCode()); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
	w := statusNamed(t, rt, podID, "main").GetState().GetWaiting()
	if w == nil {
		t.Fatal("container is not Waiting after a failed start")
	}
	assertFixedSentence(t, "Waiting message", w.GetMessage(), stageStart.sentence())
	assertLoggedAttrs(t, logs.String(), "WARN", unwrappedMarker, map[string]string{"pod": podID, "container": "main"})

	refusal := fmt.Errorf("%w: container main: command is required", errInvalidPodBox)
	sresp = rt.startFailed(p, cp, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX, refusal)
	if got := sresp.GetError().GetMessage(); !strings.Contains(got, refusal.Error()) {
		t.Errorf("StartContainer reply %q lost the PodBox refusal %q", got, refusal.Error())
	}
	if got := codes.Code(sresp.GetError().GetCode()); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
	if got := statusNamed(t, rt, podID, "main").GetState().GetWaiting().GetMessage(); !strings.Contains(got, "command is required") {
		t.Errorf("Waiting message %q lost the PodBox refusal", got)
	}
	if !errors.Is(refusal, errInvalidPodBox) || !errors.Is(fmt.Errorf("x: %w", ErrArtifactMountRefused), ErrArtifactMountRefused) {
		t.Error("a tenantText sentinel no longer matches errors.Is")
	}
}

// TestDataVolumeRefusalNamesNoHostPath drives a CreatePod whose
// data_volume_path is not one the runtime derived: dataVolumePath's error
// names the pod dir and the pod rootfs, which are daemon host paths. The reply
// still matches errInvalidPodBox (InvalidArgument) but carries the fixed
// detail and neither path; the daemon log has both. The compileProfile spine's
// refusal, which a start or attach reports, is held to the same rule on its
// Waiting message and its reply.
func TestDataVolumeRefusalNamesNoHostPath(t *testing.T) {
	const podID = "pod-datavol-refusal"
	logs := &lockedBuffer{}
	cfg := Config{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	rt := newTestRuntimeCfg(t, cfg, Deps{})
	box := hostBinBox(rt, podID)
	box.SandboxProfile.DataVolumePath = "/tmp/elsewhere"
	id, err := image.ParsePodID(podID)
	if err != nil {
		t.Fatal(err)
	}
	podDir, rootfs := rt.cache.PodDir(id), rt.cache.PodRootfs(id)
	noPaths := func(what, msg string) {
		t.Helper()
		if strings.Contains(msg, podDir) || strings.Contains(msg, rootfs) {
			t.Errorf("%s %q names a host path", what, msg)
		}
		if !strings.Contains(msg, dataVolumeRefusalDetail) {
			t.Errorf("%s %q lacks the fixed detail %q", what, msg, dataVolumeRefusalDetail)
		}
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod accepted an underived data volume path")
	}
	if got := codes.Code(resp.GetError().GetCode()); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
		t.Errorf("failure reason = %v, want INVALID_POD_BOX", got)
	}
	noPaths("CreatePod reply", resp.GetError().GetMessage())
	if l := logs.String(); !strings.Contains(l, podDir) || !strings.Contains(l, rootfs) {
		t.Errorf("daemon log lacks the pod dir and rootfs:\n%s", l)
	}

	_, err = rt.compileProfile(box, rootfs, "", nil, nil, nil, nil)
	if !errors.Is(err, errInvalidPodBox) || !errors.Is(err, errUnderivedDataVolume) {
		t.Fatalf("compileProfile err = %v, want errInvalidPodBox and errUnderivedDataVolume", err)
	}
	if failureCode(err) != codes.InvalidArgument {
		t.Errorf("failureCode = %v, want InvalidArgument", failureCode(err))
	}
	noPaths("Waiting message", boundedFailureMessage(stageStart, err))
	noPaths("StartContainer reply", startErrorReply(stageStart, err))
	if !strings.Contains(err.Error(), podDir) {
		t.Errorf("the logged error %q lost the pod dir", err.Error())
	}
}

// TestTenantTextReplyIsBoundedAndQuoted pins that a tenantText error's own
// text reaches a start reply bounded and quoted, as its Waiting message does:
// a 10 KiB refusal with a newline neither outgrows the reply cap nor carries
// a raw newline.
func TestTenantTextReplyIsBoundedAndQuoted(t *testing.T) {
	err := tenantText(errors.New(strings.Repeat("a", 10<<10) + "\nforged line"))
	got := startErrorReply(stageStart, err)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("reply carries a raw newline: %q", got)
	}
	if max := maxReplyMessageBytes + len(`""...`); len(got) > max {
		t.Errorf("reply is %d bytes, want at most %d", len(got), max)
	}
}

// TestMergeRunSpecUnknownErrorIsFixedSentence pins that only the merge's
// tenant-worded refusals publish their text: any other MergeRunSpec error
// renders the create stage's fixed sentence.
func TestMergeRunSpecUnknownErrorIsFixedSentence(t *testing.T) {
	other := mergeRunSpecError(fmt.Errorf("merge %s: %w", unwrappedMarker, errors.New("boom")))
	assertFixedSentence(t, "create reply", startErrorReply(stageCreate, other), stageCreate.sentence())
	assertFixedSentence(t, "Waiting message", boundedFailureMessage(stageCreate, other), stageCreate.sentence())

	refusal := mergeRunSpecError(fmt.Errorf("%w: container main has no command", image.ErrRunSpecInvalid))
	if got := startErrorReply(stageCreate, refusal); !strings.Contains(got, "has no command") {
		t.Errorf("create reply %q lost the merge's refusal", got)
	}
}

// TestUnwrappedErrorShapesCarryNoAbsolutePath holds the fail-closed rule for
// every unwrapped error shape, not only the fixture path: neither renderer, at
// either stage, matches any absolute host path, and both are the stage's fixed
// sentence quoted.
func TestUnwrappedErrorShapesCarryNoAbsolutePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"path in the middle", fmt.Errorf("copy %s/rootfs/bin to /private/tmp/x failed: busy", unwrappedMarker)},
		{"wrapped chain", fmt.Errorf("start: %w", fmt.Errorf("prepare: %w", fmt.Errorf("open %s/a: %w", unwrappedMarker, fs.ErrPermission)))},
		{"os.PathError", &fs.PathError{Op: "open", Path: unwrappedMarker + "/rec", Err: fs.ErrNotExist}},
		{"joined", errors.Join(errors.New("a"), &fs.PathError{Op: "stat", Path: "/etc/k3sm/key", Err: fs.ErrPermission})},
		{"bare path", errors.New("/var/run/k3sm.sock")},
	} {
		for _, stage := range []failureStage{stageCreate, stageStart} {
			want := strconv.Quote(stage.sentence())
			for what, got := range map[string]string{
				"reply":           startErrorReply(stage, tc.err),
				"Waiting message": boundedFailureMessage(stage, tc.err),
			} {
				if m := absHostPath.FindString(got); m != "" {
					t.Errorf("%s/%d %s %q matches absolute path %q", tc.name, stage, what, got, m)
				}
				if got != want {
					t.Errorf("%s/%d %s = %s, want %s", tc.name, stage, what, got, want)
				}
			}
		}
	}
}

// TestTenantTextReplyIsQuotedAndCapped asserts the exact quoted form of a
// tenant-text reply and Waiting message, and the byte cap of each (1024 for
// the reply, maxWaitingMessageBytes for the message) with its "..." tail.
func TestTenantTextReplyIsQuotedAndCapped(t *testing.T) {
	short := "say \"hi\"\nnext \u00e9"
	err := fmt.Errorf("wrapped: %w", tenantText(errors.New(short)))
	wantShort := strconv.QuoteToASCII(err.Error())
	if !strings.HasPrefix(wantShort, `"`) || !strings.Contains(wantShort, `\"hi\"\n`) {
		t.Fatalf("fixture quoted form %s is not what the test means to pin", wantShort)
	}
	if got := startErrorReply(stageStart, err); got != wantShort {
		t.Errorf("reply = %s, want %s", got, wantShort)
	}
	if got := boundedFailureMessage(stageStart, err); got != wantShort {
		t.Errorf("Waiting message = %s, want %s", got, wantShort)
	}

	if maxReplyMessageBytes != 1024 {
		t.Fatalf("maxReplyMessageBytes = %d, the reply cap is 1024", maxReplyMessageBytes)
	}
	long := tenantText(errors.New(strings.Repeat("b", 5000)))
	text := long.Error()
	if got, want := startErrorReply(stageStart, long), strconv.QuoteToASCII(text[:1024])+"..."; got != want {
		t.Errorf("capped reply is %d bytes, want exactly the quoted first 1024 bytes plus ...: %d bytes", len(got), len(want))
	}
	if got, want := boundedFailureMessage(stageStart, long), strconv.QuoteToASCII(text[:maxWaitingMessageBytes])+"..."; got != want {
		t.Errorf("capped Waiting message is %d bytes, want %d", len(got), len(want))
	}
	exact := tenantText(errors.New(strings.Repeat("c", 1024)))
	if got, want := startErrorReply(stageStart, exact), strconv.Quote(exact.Error()); got != want {
		t.Errorf("a reply of exactly 1024 bytes was capped: %d bytes", len(got))
	}
}
