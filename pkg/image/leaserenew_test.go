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
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/registryfetch"
)

// leaseClock is a hand-driven cache clock that is safe to read from any
// goroutine.
type leaseClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *leaseClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *leaseClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// trickleImage is img with its last layer's body handed out in small reads,
// each preceded by onRead, so a test can move the cache clock and run a
// reclaim pass while that layer is still arriving.
type trickleImage struct {
	ggcrv1.Image
	onRead func() error
}

func (ti trickleImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := ti.Image.Layers()
	if err != nil || len(ls) == 0 {
		return ls, err
	}
	out := slices.Clone(ls)
	out[len(out)-1] = trickleLayer{Layer: ls[len(ls)-1], onRead: ti.onRead}
	return out, nil
}

type trickleLayer struct {
	ggcrv1.Layer
	onRead func() error
}

func (tl trickleLayer) Compressed() (io.ReadCloser, error) {
	rc, err := tl.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	return &trickleBody{rc: rc, onRead: tl.onRead}, nil
}

// trickleBody returns at most 64 bytes per Read, after onRead; an onRead
// error fails that Read with no bytes.
type trickleBody struct {
	rc     io.ReadCloser
	onRead func() error
}

func (b *trickleBody) Read(p []byte) (int, error) {
	if err := b.onRead(); err != nil {
		return 0, err
	}
	if len(p) > 64 {
		p = p[:64]
	}
	return b.rc.Read(p)
}

func (b *trickleBody) Close() error { return b.rc.Close() }

// TestLeaseOutlivesItsTTLWhileThePullRuns is the gate for lease renewal on
// the pull path. A two-layer pull commits its config and first layer, then
// receives its last layer slowly: every read of that body moves the cache
// clock a quarter of DefaultLeaseTTL, and once two TTLs have passed a reclaim
// pass that plans the config and the first layer for deletion runs. Those
// blobs are named by nothing but the pull's lease, so they survive only if the
// arriving bytes kept the lease alive: the pass must keep both as leased and
// the pull must finish with every blob present. Without renewal the lease
// lapses at one TTL and the pass unlinks both.
//
// The failing and cancelled rows pin the other half: renewal is driven by the
// pull's own reads, so a pull that ends stops renewing, and a pull that ends
// in an error leaves no lease in the table. A successful pull hands its lease
// to the caller, and without a Release it lapses one TTL after the last byte.
func TestLeaseOutlivesItsTTLWhileThePullRuns(t *testing.T) {
	step := DefaultLeaseTTL / 4
	boom := errors.New("connection reset")

	tests := []struct {
		name string
		// failAt, when non-zero, is the body read (counted from 1) that fails
		// with failErr instead of delivering bytes.
		failAt  int
		failErr func(cancel context.CancelFunc) error
	}{
		{name: "pull succeeds"},
		{name: "pull fails mid-layer", failAt: 12, failErr: func(context.CancelFunc) error { return boom }},
		{name: "pull is cancelled mid-layer", failAt: 12, failErr: func(cancel context.CancelFunc) error {
			cancel()
			return context.Canceled
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The base is a real instant so the committed blobs' mtimes sit
			// at the start of the fake timeline and the reclaim's grace check
			// (grace 0) is not what keeps or removes them.
			clk := &leaseClock{t: time.Now()}
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cache.now = clk.now

			base, err := random.Image(4096, 2)
			if err != nil {
				t.Fatal(err)
			}
			base = withPlatform(t, base, "darwin", "arm64", "")
			mfst, err := base.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			early := []string{mfst.Config.Digest.String(), mfst.Layers[0].Digest.String()}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := clk.now()
			reads := 0
			var rep *ExecuteReport
			var repErr error
			img := trickleImage{Image: base, onRead: func() error {
				reads++
				if tc.failAt != 0 && reads == tc.failAt {
					return tc.failErr(cancel)
				}
				clk.advance(step)
				if rep == nil && clk.now().Sub(start) >= 2*DefaultLeaseTTL {
					pinned := func() (map[string]PruneReason, error) { return cache.pinnedNow(nil) }
					rep, repErr = cache.executePrune(planOf(early...), 0, clk.now(), nil, pinned)
				}
				return nil
			}}
			p := mustPuller(t, cache, (&fakeFetch{img: img}).fetch)

			res, err := p.Pull(ctx, "example.com/slow:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
			if repErr != nil {
				t.Fatalf("executePrune: %v", repErr)
			}
			if rep == nil {
				t.Fatalf("the reclaim pass never ran: %d body reads moved the clock %v, want at least %v",
					reads, clk.now().Sub(start), 2*DefaultLeaseTTL)
			}
			for _, d := range early {
				if slices.Contains(rep.Removed, d) || !cache.Has(d) {
					t.Errorf("blob %s, held by the running pull's lease, was unlinked by the reclaim pass at %v",
						d, 2*DefaultLeaseTTL)
				} else if got := pinnedReason(rep, d); got != ReasonKeptLeased {
					t.Errorf("blob %s kept for reason %q, want %q", d, got, ReasonKeptLeased)
				}
			}

			if tc.failAt != 0 {
				if err == nil {
					res.Lease.Release()
					t.Fatalf("Pull succeeded, want the body's error")
				}
				if n := leaseCount(cache); n != 0 {
					t.Errorf("lease table holds %d leases after a failed pull, want 0", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pull: %v", err)
			}
			for _, l := range res.Manifest.Layers {
				if !cache.Has(l.Digest) {
					t.Errorf("layer %s missing after the pull", l.Digest)
				}
			}
			// The pull has stopped reading, so nothing renews the lease it
			// handed over: unreleased, it lapses one TTL after its last renewal.
			clk.advance(DefaultLeaseTTL + time.Nanosecond)
			if n := leaseCount(cache); n != 1 {
				t.Fatalf("lease table holds %d leases, want the pull's one", n)
			}
			if cache.leaseHas(early[0]) {
				t.Errorf("the pull's lease is still live one TTL after the pull ended")
			}
			res.Lease.Release()
		})
	}

	// The resumed layer fetch (a puller with a partial store) reads its body
	// through transferBlob, not the whole-layer fill: the config blob it
	// committed first must survive the same reclaim pass.
	t.Run("resumed layer fetch", func(t *testing.T) {
		c := newCutRegistry(t, 4096)
		clk := &leaseClock{t: time.Now()}
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cache.now = clk.now
		start := clk.now()
		var config string
		var rep *ExecuteReport
		var repErr error
		rt := &trickleTransport{rt: http.DefaultTransport, path: "/v2/test/app/blobs/" + c.layer.String(), onRead: func() error {
			clk.advance(step)
			if rep == nil && clk.now().Sub(start) >= 2*DefaultLeaseTTL {
				pinned := func() (map[string]PruneReason, error) { return cache.pinnedNow(nil) }
				rep, repErr = cache.executePrune(planOf(config), 0, clk.now(), nil, pinned)
			}
			return nil
		}}
		p := resumePullerVia(t, cache, &registryfetch.PartialStore{Dir: filepath.Join(t.TempDir(), "partials")}, rt)
		p.fetch = configSpy(p.fetch, &config)

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		defer res.Lease.Release()
		if repErr != nil {
			t.Fatalf("executePrune: %v", repErr)
		}
		if rep == nil {
			t.Fatalf("the reclaim pass never ran: the layer body moved the clock %v, want at least %v",
				clk.now().Sub(start), 2*DefaultLeaseTTL)
		}
		if slices.Contains(rep.Removed, config) || !cache.Has(config) {
			t.Errorf("config %s, held by the running pull's lease, was unlinked by the reclaim pass", config)
		} else if got := pinnedReason(rep, config); got != ReasonKeptLeased {
			t.Errorf("config kept for reason %q, want %q", got, ReasonKeptLeased)
		}
		verifyLayer(t, cache, c)
	})
}

// trickleTransport hands the body of a GET for path out through trickleBody.
type trickleTransport struct {
	rt     http.RoundTripper
	path   string
	onRead func() error
}

func (tt *trickleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := tt.rt.RoundTrip(r)
	if err != nil || r.Method != http.MethodGet || r.URL.Path != tt.path {
		return resp, err
	}
	resp.Body = &trickleBody{rc: resp.Body, onRead: tt.onRead}
	return resp, nil
}

// configSpy wraps fetch so the config digest of the image it returns is
// written to config before the pull reads any blob.
func configSpy(fetch FetchFunc, config *string) FetchFunc {
	return func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
		img, err := fetch(ctx, ref, cred, policy)
		if err != nil {
			return nil, err
		}
		h, err := img.ConfigName()
		if err != nil {
			return nil, err
		}
		*config = h.String()
		return img, nil
	}
}

// leaseCount returns the size of the lease table.
func leaseCount(c *Cache) int {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	return len(c.leases)
}

// TestLeaseRenew pins Renew's rules on the cache clock: renewals every
// quarter TTL hold a lease past three TTLs, it lapses one TTL after the last
// one, a call inside the throttle window does not move the expiry, and a
// lapsed or released lease is never revived. The reader renews on bytes and
// never on a zero-byte read.
func TestLeaseRenew(t *testing.T) {
	const d = "sha256:renew"
	ttl := time.Minute
	quarter := ttl / 4

	t.Run("renewed every quarter TTL is held at three TTLs", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		for f.clock.Before(start.Add(3 * ttl)) {
			f.clock = f.clock.Add(quarter)
			l.Renew()
		}
		if !f.cache.leaseHas(d) {
			t.Fatalf("lease lapsed at three TTLs despite renewals")
		}
		last := f.clock
		f.clock = last.Add(ttl)
		if !f.cache.leaseHas(d) {
			t.Errorf("lease lapsed before one TTL after the last renewal")
		}
		f.clock = last.Add(ttl + time.Nanosecond)
		if f.cache.leaseHas(d) {
			t.Errorf("lease still held past one TTL after the last renewal")
		}
	})

	t.Run("no renewal lapses at TTL", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(ttl + time.Nanosecond)
		if f.cache.leaseHas(d) {
			t.Errorf("unrenewed lease held past its TTL")
		}
	})

	t.Run("renew inside the throttle window does not move expiry", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(quarter - time.Nanosecond)
		l.Renew()
		if got, want := l.expires, start.Add(ttl); !got.Equal(want) {
			t.Errorf("expires after throttled Renew = %v, want %v", got, want)
		}
		f.clock = start.Add(quarter)
		l.Renew()
		if got, want := l.expires, start.Add(quarter+ttl); !got.Equal(want) {
			t.Errorf("expires after Renew past the window = %v, want %v", got, want)
		}
	})

	t.Run("renew after lapse is a no-op", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(ttl + time.Nanosecond)
		l.Renew() // lapsed but not yet swept
		if f.cache.leaseHas(d) {
			t.Errorf("Renew revived a lapsed lease")
		}
		if n := leaseCount(f.cache); n != 0 {
			t.Errorf("lease table has %d entries, want 0", n)
		}
	})

	t.Run("renew after release is a no-op", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		l.Release()
		f.clock = start.Add(quarter)
		l.Renew()
		if f.cache.leaseHas(d) {
			t.Errorf("Renew revived a released lease")
		}
		if n := leaseCount(f.cache); n != 0 {
			t.Errorf("lease table has %d entries, want 0", n)
		}
	})

	t.Run("nil lease", func(t *testing.T) {
		var l *Lease
		l.Renew()
		(&Lease{}).Renew()
		if _, err := l.Reader(strings.NewReader("x")).Read(make([]byte, 1)); err != nil {
			t.Errorf("Read through a nil lease's reader: %v", err)
		}
	})

	t.Run("reader renews on bytes, not on a zero-byte read", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(quarter)
		if n, _ := l.Reader(strings.NewReader("")).Read(make([]byte, 1)); n != 0 {
			t.Fatalf("empty read returned %d bytes", n)
		}
		if got, want := l.expires, start.Add(ttl); !got.Equal(want) {
			t.Errorf("zero-byte read moved expires to %v, want %v", got, want)
		}
		if n, _ := l.Reader(strings.NewReader("abc")).Read(make([]byte, 3)); n != 3 {
			t.Fatalf("read returned %d bytes, want 3", n)
		}
		if got, want := l.expires, start.Add(quarter+ttl); !got.Equal(want) {
			t.Errorf("read of bytes left expires at %v, want %v", got, want)
		}
	})
}

// TestLeaseRenewThrottle pins Renew's fast path: inside the throttle window,
// measured from the last effective renewal, Renew returns before the locked
// path that sweeps expired leases, so an expired OTHER lease is still in the
// table after it; at the window's edge it sweeps and extends.
func TestLeaseRenewThrottle(t *testing.T) {
	ttl := time.Minute
	tests := []struct {
		name string
		// prior, when true, makes one effective renewal at a quarter TTL
		// first, so the window is measured from it rather than from the
		// acquisition.
		prior       bool
		advance     time.Duration // after the acquisition or the prior renewal
		otherInTbl  bool          // the expired other lease is still in the table
		wantExpires time.Duration // from the start
	}{
		{"inside the window", false, ttl/4 - time.Nanosecond, true, ttl},
		{"at the window's edge", false, ttl / 4, false, ttl/4 + ttl},
		{"inside the window after a renewal", true, ttl/4 - time.Nanosecond, true, ttl/4 + ttl},
		{"at the edge after a renewal", true, ttl / 4, false, ttl/2 + ttl},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCFixture(t)
			start := f.clock
			l := f.cache.AcquireLease([]string{"sha256:mine"}, ttl)
			if tc.prior {
				f.clock = start.Add(ttl / 4)
				l.Renew()
			}
			from := f.clock
			// other expires one nanosecond after from.
			f.cache.AcquireLease([]string{"sha256:other"}, time.Nanosecond)
			f.clock = from.Add(tc.advance)
			l.Renew()

			want := 1
			if tc.otherInTbl {
				want = 2
			}
			if got := leaseCount(f.cache); got != want {
				t.Errorf("lease table size = %d, want %d", got, want)
			}
			f.cache.leaseMu.Lock()
			exp := l.expires
			f.cache.leaseMu.Unlock()
			if w := start.Add(tc.wantExpires); !exp.Equal(w) {
				t.Errorf("expires = %v, want %v", exp, w)
			}
		})
	}
}

// TestLeaseRenewConcurrent drives Renew (its fast path and its locked path),
// Release and the cache's lease checks on one cache from several goroutines,
// on a fake clock that a goroutine moves a little past each quarter TTL, so
// many renewals are effective and -race checks the atomic mirror against the
// locked fields.
func TestLeaseRenewConcurrent(t *testing.T) {
	f := newGCFixture(t)
	c := f.cache
	clk := &leaseClock{t: f.clock}
	c.now = clk.now
	const iterations = 2000
	ttl := time.Hour

	var wg sync.WaitGroup
	wg.Go(func() {
		for range iterations {
			clk.advance(ttl/4 + time.Nanosecond)
		}
	})
	for g := range 4 {
		l := c.AcquireLease([]string{"sha256:r"}, ttl)
		short := c.AcquireLease([]string{"sha256:s"}, ttl)
		wg.Go(func() {
			for range iterations {
				l.Renew()
				short.Renew()
			}
			l.Release()
		})
		wg.Go(func() {
			for i := range iterations {
				_ = c.leaseHas("sha256:r")
				if i == iterations/2 && g%2 == 0 {
					short.Release()
				}
			}
		})
		wg.Go(func() {
			for range iterations {
				_ = c.leasedDigests()
				short.Renew()
			}
		})
	}
	wg.Wait()

	if c.leaseHas("sha256:r") {
		t.Errorf("leaseHas after every holder released, want false")
	}
}
