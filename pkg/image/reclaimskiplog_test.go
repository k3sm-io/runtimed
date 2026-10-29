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
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// syncBuffer is a bytes.Buffer safe for a logger written from any goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// take returns what was logged since the last take and resets the buffer.
func (b *syncBuffer) take() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	b.buf.Reset()
	return s
}

// TestRecordlessPodDirLoggedOnce pins that a reclaim pass names a skipped
// record-less pod dir in its warning the first time it skips it, and not on
// every later pass that skips it again. A dir that stops being skipped is
// forgotten, so the memory is bounded by the dirs on disk, and one that
// returns is reported again.
func TestRecordlessPodDirLoggedOnce(t *testing.T) {
	f := newGCFixture(t)
	var logs syncBuffer
	cfg := ReclaimConfig{
		HighFreeBytes: 1 << 40, TargetFreeBytes: 1 << 40, Grace: 0,
		FreeBytes: (&fakeFree{free: []uint64{0}}).sample,
	}
	cfg.Log = slog.New(slog.NewTextHandler(&logs, nil))
	cfg.UntrackedPod = func(PodID) bool { return true }

	recordless := func(id string) {
		t.Helper()
		pid := f.pod(id)
		if err := os.Remove(filepath.Join(f.cache.PodDir(pid), PodReferencesName)); err != nil {
			t.Fatalf("remove record: %v", err)
		}
	}
	pass := func() string {
		t.Helper()
		if _, err := f.cache.ReclaimUnderPressure(context.Background(), cfg); err != nil {
			t.Fatalf("reclaim: %v", err)
		}
		return logs.take()
	}

	recordless("pod-gone-a")
	if out := pass(); !strings.Contains(out, "pod-gone-a") {
		t.Fatalf("first pass did not report the skipped dir:\n%s", out)
	}
	for i := range 3 {
		if out := pass(); strings.Contains(out, "pod-gone-a") {
			t.Fatalf("pass %d reported an already-reported dir again:\n%s", i+2, out)
		}
	}

	recordless("pod-gone-b")
	out := pass()
	if !strings.Contains(out, "pod-gone-b") {
		t.Fatalf("a newly skipped dir was not reported:\n%s", out)
	}
	if strings.Contains(out, "pod-gone-a") {
		t.Fatalf("the new dir's report repeated the old one:\n%s", out)
	}

	pidA, err := ParsePodID("pod-gone-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.cache.PodDir(pidA)); err != nil {
		t.Fatal(err)
	}
	if out := pass(); strings.Contains(out, "pod-gone") {
		t.Fatalf("a pass with no newly skipped dir logged a skip:\n%s", out)
	}
	recordless("pod-gone-a")
	if out := pass(); !strings.Contains(out, "pod-gone-a") {
		t.Fatalf("a dir that came back after it was gone was not reported again:\n%s", out)
	}
}
