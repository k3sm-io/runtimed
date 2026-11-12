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
	"slices"
	"sync"
	"sync/atomic"
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

// stallFetcher serves manifests from the fake, or never when silentManifest
// is set, and blob bodies from body.
type stallFetcher struct {
	*fakeFetcher
	body           func(ctx context.Context, data []byte) io.ReadCloser
	silentManifest chan<- struct{}
}

func (s *stallFetcher) Manifest(ctx context.Context, ref string, cred *image.RegistryCredential) ([]byte, string, error) {
	if s.silentManifest == nil {
		return s.fakeFetcher.Manifest(ctx, ref, cred)
	}
	s.silentManifest <- struct{}{}
	<-ctx.Done()
	return nil, "", ctx.Err()
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

// TestPullArtifactFailsAStalledManifest pins the manifest's bound: a registry
// that never answers the manifest request fails the pull when the stall timer
// fires, as a resumable transfer failure. Without it nothing bounds the wait,
// since the registry transport carries no header timeout.
func TestPullArtifactFailsAStalledManifest(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", "weights"))
	asked := make(chan struct{}, 1)
	f := &stallFetcher{fakeFetcher: e.fetch, silentManifest: asked}
	idle := &fakeIdle{}
	p := stallPuller(t, e, f, idle)
	done := make(chan error, 1)
	go func() {
		_, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
		done <- err
	}()
	<-asked
	idle.mu.Lock()
	fire := idle.fire
	idle.mu.Unlock()
	fire()
	if err := <-done; !errors.Is(err, ErrManifestStalled) || !errors.Is(err, ErrBlobTransfer) {
		t.Fatalf("PullArtifact = %v, want a stalled, resumable manifest fetch", err)
	}
}

// shortLeaser hands out the cache's own leases with a short TTL, so a test
// can outlast one on the real clock: the lease clock is the cache's and
// pkg/artifact has no seam into it.
type shortLeaser struct {
	inner Leaser
	ttl   time.Duration
}

func (l *shortLeaser) AcquireLease(digests []string, _ time.Duration) *image.Lease {
	return l.inner.AcquireLease(digests, l.ttl)
}

// slowBody sends one byte per read, sleeping gap before each.
type slowBody struct {
	r   io.Reader
	gap time.Duration
}

func (b *slowBody) Read(p []byte) (int, error) {
	time.Sleep(b.gap)
	return iotest.OneByteReader(b.r).Read(p)
}

func (b *slowBody) Close() error { return nil }

// TestPullArtifactLeaseOutlivesSlowBlob pins lease renewal by progress: a blob
// whose bytes arrive across several lease TTLs keeps the pull's lease, so
// once the bytes are in and before the record is written, a reclaim pass
// still finds the blobs leased instead of unreferenced.
func TestPullArtifactLeaseOutlivesSlowBlob(t *testing.T) {
	// A 1 s lease with a byte every 100 ms for about 2.5 s: only a pause near
	// a whole second between two bytes could lapse it falsely.
	const ttl = time.Second
	e := newEnv(t)
	weights := "0123456789abcdefghijklmn" // 24 bytes, 100ms apart: ~2.4 s, > 2 TTLs
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", weights))
	f := &stallFetcher{fakeFetcher: e.fetch, body: func(_ context.Context, data []byte) io.ReadCloser {
		return &slowBody{r: bytes.NewReader(data), gap: 100 * time.Millisecond}
	}}
	p := stallPuller(t, e, f, &fakeIdle{})
	p.deps.Leases = &shortLeaser{inner: e.cache, ttl: ttl}
	victim := digestOfBytes([]byte(weights))
	start := time.Now()
	var checked bool
	p.afterPresence = func() {
		if checked {
			return
		}
		checked = true
		if took := time.Since(start); took < 2*ttl {
			t.Errorf("the transfer took %v, want more than two lease TTLs (%v)", took, 2*ttl)
		}
		rep, err := e.cache.ReclaimUnderPressure(context.Background(), image.ReclaimConfig{
			Force: true, DryRun: true, Grace: time.Nanosecond,
			FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
		})
		if err != nil {
			t.Errorf("dry-run reclaim: %v", err)
			return
		}
		if slices.Contains(rep.Removed, victim) {
			t.Errorf("a reclaim pass would take %s: the pull's lease lapsed while its bytes arrived", victim)
		}
		leased := false
		for _, k := range rep.Kept {
			if k.Digest == victim && k.Reason == image.ReasonKeptLeased {
				leased = true
			}
		}
		if !leased {
			t.Errorf("%s is not kept as leased after the transfer; kept: %+v", victim, rep.Kept)
		}
	}
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	res.Lease.Release()
	if !checked {
		t.Fatal("the presence hook never ran")
	}
}

// TestFetchWithoutProgressDoesNotRenew pins the other half: renewal follows
// bytes, not time. A transfer whose body sends nothing until the stall timer
// fires never calls renew.
func TestFetchWithoutProgressDoesNotRenew(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", "weights"))
	reading := make(chan struct{}, 1)
	f := &stallFetcher{fakeFetcher: e.fetch, body: func(ctx context.Context, _ []byte) io.ReadCloser {
		return &silentBody{ctx: ctx, reading: reading}
	}}
	idle := &fakeIdle{}
	p := stallPuller(t, e, f, idle)
	d := digestOfBytes([]byte("weights"))
	var renews atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- p.fetchAll(context.Background(), testRef, nil, []blob{{digest: d, size: int64(len("weights"))}}, nil, func() { renews.Add(1) })
	}()
	<-reading
	idle.mu.Lock()
	fire := idle.fire
	idle.mu.Unlock()
	fire()
	if err := <-done; !errors.Is(err, ErrBlobStalled) {
		t.Fatalf("fetchAll = %v, want a stalled transfer", err)
	}
	if n := renews.Load(); n != 0 {
		t.Errorf("a transfer that moved no byte renewed the lease %d times, want 0", n)
	}
}

// countingBody returns its bytes one per read and counts the non-empty reads
// on a counter shared across transfers.
type countingBody struct {
	r     io.Reader
	reads *atomic.Int32
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := iotest.OneByteReader(b.r).Read(p)
	if n > 0 {
		b.reads.Add(1)
	}
	return n, err
}

func (b *countingBody) Close() error { return nil }

// TestFetchRenewsPerRead pins renewal by progress without a clock: two blobs
// fetched in one fetchAll call, each over several reads, call renew at least
// once per non-empty read; a nil renew is accepted.
func TestFetchRenewsPerRead(t *testing.T) {
	tests := []struct {
		name  string
		renew bool
	}{
		{"counting renew", true},
		{"nil renew", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publishModel(testRef, modelLayer("a.safetensors", "alpha"), modelLayer("b.safetensors", "bravo-two"))
			var reads, renews atomic.Int32
			f := &stallFetcher{fakeFetcher: e.fetch, body: func(_ context.Context, data []byte) io.ReadCloser {
				return &countingBody{r: bytes.NewReader(data), reads: &reads}
			}}
			p := stallPuller(t, e, f, &fakeIdle{})
			missing := []blob{
				{digest: digestOfBytes([]byte("alpha")), size: int64(len("alpha"))},
				{digest: digestOfBytes([]byte("bravo-two")), size: int64(len("bravo-two"))},
			}
			var renew func()
			if tc.renew {
				renew = func() { renews.Add(1) }
			}
			if err := p.fetchAll(context.Background(), testRef, nil, missing, nil, renew); err != nil {
				t.Fatalf("fetchAll: %v", err)
			}
			if r := reads.Load(); r < int32(len("alpha")+len("bravo-two")) {
				t.Fatalf("non-empty reads = %d, want one per byte", r)
			}
			if tc.renew {
				if n, r := renews.Load(), reads.Load(); n < r {
					t.Errorf("renew called %d times over %d non-empty reads, want at least one per read", n, r)
				}
			}
		})
	}
}

// TestRecheckRefetchRenews pins that recheck passes renew through to its
// refetch: a blob absent at recheck is fetched again, and its bytes renew.
func TestRecheckRefetchRenews(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w.safetensors", "weights"))
	var reads, renews atomic.Int32
	f := &stallFetcher{fakeFetcher: e.fetch, body: func(_ context.Context, data []byte) io.ReadCloser {
		return &countingBody{r: bytes.NewReader(data), reads: &reads}
	}}
	p := stallPuller(t, e, f, &fakeIdle{})
	need := []blob{{digest: digestOfBytes([]byte("weights")), size: int64(len("weights"))}}
	var res Result
	if err := p.recheck(context.Background(), testRef, nil, need, &res, func() { renews.Add(1) }); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if !res.Fetched {
		t.Fatal("recheck did not refetch the absent blob")
	}
	if n, r := renews.Load(), reads.Load(); r == 0 || n < r {
		t.Errorf("renew called %d times over %d non-empty reads of the refetch, want at least one per read", n, r)
	}
}
