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

package artifact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/image"
)

// fakeIdle is a stall timer the test fires by hand.
type fakeIdle struct {
	mu     sync.Mutex
	fire   func()
	armed  time.Duration
	resets int
}

func (f *fakeIdle) Reset(time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets++
	return true
}

func (f *fakeIdle) Stop() bool { return true }

func (f *fakeIdle) after(d time.Duration, fn func()) idleTimer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed, f.fire = d, fn
	return f
}

// stallFetcher serves manifests from the fake and blob bodies from body.
type stallFetcher struct {
	*fakeFetcher
	body func(ctx context.Context, data []byte) io.ReadCloser
}

func (s *stallFetcher) Blob(ctx context.Context, ref string, cred *image.RegistryCredential, digest string, offset int64) (io.ReadCloser, int64, error) {
	s.mu.Lock()
	data := s.blobs[digest][offset:]
	s.mu.Unlock()
	return s.body(ctx, data), offset, nil
}

// silentBody sends nothing: each read waits for its request to be cancelled.
type silentBody struct {
	ctx     context.Context
	reading chan<- struct{}
}

func (b *silentBody) Read([]byte) (int, error) {
	select {
	case b.reading <- struct{}{}:
	default:
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *silentBody) Close() error { return nil }

func stallPuller(t *testing.T, e *env, f Fetcher, idle *fakeIdle) *Puller {
	t.Helper()
	p, err := New(Config{
		RegistryHost: testHost,
		PartialDir:   e.partial,
		StorePath:    e.cache.Root(),
		FreeBytes:    func(string) (uint64, error) { return e.free.Load(), nil },
		FloorBytes:   100,
		afterFunc:    idle.after,
	}, Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: f})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPullArtifactFailsAStalledBlob pins the stall bound: a body that sends
// nothing fails its transfer when the stall timer fires, as a resumable
// transfer failure, and nothing is recorded.
func TestPullArtifactFailsAStalledBlob(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", "weights"))
	reading := make(chan struct{}, 1)
	f := &stallFetcher{fakeFetcher: e.fetch, body: func(ctx context.Context, _ []byte) io.ReadCloser {
		return &silentBody{ctx: ctx, reading: reading}
	}}
	idle := &fakeIdle{}
	p := stallPuller(t, e, f, idle)
	done := make(chan error, 1)
	go func() {
		res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
		if res != nil {
			res.Lease.Release()
		}
		done <- err
	}()
	<-reading
	idle.mu.Lock()
	fire, armed := idle.fire, idle.armed
	idle.mu.Unlock()
	if armed != DefaultStallTimeout {
		t.Errorf("stall timer armed for %v, want the default %v", armed, DefaultStallTimeout)
	}
	fire()
	err := <-done
	if !errors.Is(err, ErrBlobStalled) || !errors.Is(err, ErrBlobTransfer) {
		t.Fatalf("PullArtifact = %v, want a stalled, resumable transfer failure", err)
	}
	if _, ok, _ := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeModel); ok {
		t.Error("a stalled pull recorded the artifact")
	}
}

// TestPullArtifactSlowBlobIsNotCutOff pins that the bound is idle, not total: a
// body that delivers one byte per read re-arms the timer on every byte, so a
// transfer that keeps moving completes however long it takes.
func TestPullArtifactSlowBlobIsNotCutOff(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", "weights"))
	f := &stallFetcher{fakeFetcher: e.fetch, body: func(_ context.Context, data []byte) io.ReadCloser {
		return io.NopCloser(iotest.OneByteReader(bytes.NewReader(data)))
	}}
	idle := &fakeIdle{}
	p := stallPuller(t, e, f, idle)
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	res.Lease.Release()
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if idle.resets < len("weights") {
		t.Errorf("the stall timer was re-armed %d times, want at least one per byte", idle.resets)
	}
}
