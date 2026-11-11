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
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

// evictDerivedRecorder is an EvictDerived hook that records each call and
// whether the target's own blobs were already gone when it ran.
type evictDerivedRecorder struct {
	s         *evictScene
	err       error
	manifests []string
	blobsGone []bool
}

func (r *evictDerivedRecorder) hook(_ context.Context, manifest string) error {
	r.manifests = append(r.manifests, manifest)
	r.blobsGone = append(r.blobsGone, !r.s.f.exists(r.s.cfgA) && !r.s.f.exists(r.s.ownA))
	return r.err
}

func (s *evictScene) evictWith(ctx context.Context, dryRun bool, hook func(context.Context, string) error, log *slog.Logger) (*EvictResult, error) {
	return s.f.cache.Evict(ctx, s.manifestA, []string{s.cfgA, s.ownA, s.shared}, ReclaimConfig{
		DryRun:       dryRun,
		FreeBytes:    func(string) (uint64, error) { return 1, nil },
		EvictDerived: hook,
		Log:          log,
	})
}

// TestEvictDerivedRunsOnceAfterUnlink pins the view hook's position: a real
// eviction calls it exactly once, with the target manifest, after the target's
// blobs are unlinked, and its result is the hookless eviction's.
func TestEvictDerivedRunsOnceAfterUnlink(t *testing.T) {
	t.Parallel()
	s := newEvictScene(t)
	r := &evictDerivedRecorder{s: s}
	got, err := s.evictWith(context.Background(), false, r.hook, nil)
	if err != nil {
		t.Fatalf("Evict: %v", err)
	}
	if want := s.want(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Evict = %+v; want %+v", got, want)
	}
	if !reflect.DeepEqual(r.manifests, []string{s.manifestA}) {
		t.Fatalf("EvictDerived calls = %v; want exactly [%s]", r.manifests, s.manifestA)
	}
	if !r.blobsGone[0] {
		t.Errorf("EvictDerived ran while a target blob was still on disk; it must run after the unlink")
	}
}

// TestEvictDerivedErrorDoesNotFailEviction pins that a hook error is logged
// at Warn and the eviction still returns its result and no error.
func TestEvictDerivedErrorDoesNotFailEviction(t *testing.T) {
	t.Parallel()
	s := newEvictScene(t)
	r := &evictDerivedRecorder{s: s, err: errors.New("view busy")}
	var logs syncBuffer
	got, err := s.evictWith(context.Background(), false, r.hook, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("Evict: %v; a hook error must not fail the eviction", err)
	}
	if want := s.want(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Evict = %+v; want %+v", got, want)
	}
	if len(r.manifests) != 1 {
		t.Fatalf("EvictDerived calls = %v; want one", r.manifests)
	}
	if out := logs.take(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "view busy") {
		t.Errorf("log = %q; want a Warn line carrying the hook error", out)
	}
}

// TestEvictDerivedSkipped pins the cases that never call the hook: a dry run,
// a pass that errors (a pod dir with no record makes the roots unreadable),
// and a cancelled context. A nil hook is a plain eviction.
func TestEvictDerivedSkipped(t *testing.T) {
	t.Parallel()
	t.Run("dry run", func(t *testing.T) {
		t.Parallel()
		s := newEvictScene(t)
		r := &evictDerivedRecorder{s: s}
		if _, err := s.evictWith(context.Background(), true, r.hook, nil); err != nil {
			t.Fatalf("Evict: %v", err)
		}
		if len(r.manifests) != 0 {
			t.Errorf("dry run called EvictDerived %v", r.manifests)
		}
	})
	t.Run("pass error", func(t *testing.T) {
		t.Parallel()
		s := newEvictScene(t)
		pid, err := ParsePodID("pod-unrecorded")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(s.f.cache.PodDir(pid), 0o755); err != nil {
			t.Fatal(err)
		}
		r := &evictDerivedRecorder{s: s}
		if _, err := s.evictWith(context.Background(), false, r.hook, nil); !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("Evict err = %v; want ErrRootsIncomplete", err)
		}
		if len(r.manifests) != 0 {
			t.Errorf("a failed pass called EvictDerived %v", r.manifests)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()
		s := newEvictScene(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := &evictDerivedRecorder{s: s}
		if _, err := s.evictWith(ctx, false, r.hook, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("Evict err = %v; want context.Canceled", err)
		}
		if len(r.manifests) != 0 {
			t.Errorf("a cancelled eviction called EvictDerived %v", r.manifests)
		}
	})
	t.Run("nil hook", func(t *testing.T) {
		t.Parallel()
		s := newEvictScene(t)
		got, err := s.evictWith(context.Background(), false, nil, nil)
		if err != nil {
			t.Fatalf("Evict: %v", err)
		}
		if want := s.want(); !reflect.DeepEqual(got, want) {
			t.Fatalf("Evict = %+v; want %+v", got, want)
		}
	})
}
