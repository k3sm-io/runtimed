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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// panicInApplyCtx is a context whose Err panics when the layer applier asks it,
// and answers normally everywhere else. The applier checks its context before each
// tar entry, so this raises a panic inside the real apply of a real unpacker, with
// no test seam in the production code.
type panicInApplyCtx struct{ context.Context }

func (c panicInApplyCtx) Err() error {
	if strings.Contains(string(debug.Stack()), "(*LayerApplier).Apply") {
		panic("applier state is gone")
	}
	return c.Context.Err()
}

// TestLayerPanicStackReachesTheNodeLog pins the wiring image's own tests cannot:
// the unpacker New builds logs on Config.Logger, so the stack of a recovered layer
// panic reaches the node log, and the caller sees a malformed layer. An unpacker
// built without the logger would pass every test in pkg/image and log nothing.
func TestLayerPanicStackReachesTheNodeLog(t *testing.T) {
	var buf lockedBuffer
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := tw.WriteHeader(&tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// The Puller is a fake because a pull is not the subject. The Unpacker stays
	// nil, so New builds the daemon's own over the same cache.
	mfst := &runtimev1.ImageManifest{Reference: "example.com/panic:v1"}
	rt, err := New(
		Config{Root: t.TempDir(), Logger: slog.New(slog.NewJSONHandler(&buf, nil))},
		testDeps(t, Deps{Puller: &fakePuller{manifest: mfst}}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := rt.unpacker.(*image.Unpacker); !ok {
		t.Fatalf("New wired unpacker %T, want *image.Unpacker", rt.unpacker)
	}
	commit := func(b []byte) string {
		t.Helper()
		h, _, err := ggcrv1.SHA256(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.cache.CommitBlob(h.String(), int64(len(b)), func(w io.Writer) error {
			_, werr := w.Write(b)
			return werr
		}); err != nil {
			t.Fatal(err)
		}
		return h.String()
	}
	// The layer is an uncompressed tar, so its diffID is its own digest.
	layerDigest := commit(layer.Bytes())
	config := []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers","diff_ids":["` + layerDigest + `"]}}`)
	mfst.Config = &runtimev1.Descriptor{Digest: commit(config), Size: int64(len(config))}
	mfst.Layers = []*runtimev1.Descriptor{{
		Digest:    layerDigest,
		Size:      int64(layer.Len()),
		MediaType: "application/vnd.oci.image.layer.v1.tar",
	}}

	p := &pod{box: hostBinBox(rt, "pod-panic"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	c := &runtimev1.Container{Name: "app", Image: mfst.GetReference(), Command: []string{"bin/app"}}
	ctx := panicInApplyCtx{context.Background()}
	_, err = rt.resolveBinary(ctx, p, derivedRootfs(t, rt, "pod-panic"), c)
	if !errors.Is(err, image.ErrLayerMalformed) {
		t.Fatalf("resolveBinary error = %v, want image.ErrLayerMalformed", err)
	}
	if strings.Contains(err.Error(), ".go:") {
		t.Errorf("the error carries stack content: %s", err)
	}

	var stacks []string
	for line := range strings.Lines(buf.String()) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if stack, ok := rec["stack"].(string); ok {
			stacks = append(stacks, stack)
		}
	}
	if len(stacks) != 1 {
		t.Fatalf("logged %d stacks, want 1: %s", len(stacks), buf.String())
	}
	for _, frame := range []string{"panicInApplyCtx", "(*LayerApplier).Apply", "resolveBinary"} {
		if !strings.Contains(stacks[0], frame) {
			t.Errorf("logged stack does not name %q: %s", frame, stacks[0])
		}
	}
}
