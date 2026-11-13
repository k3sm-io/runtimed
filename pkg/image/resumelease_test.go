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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// leaseClock is a cache clock the test advances; reads and writes may come
// from different goroutines (the stall watchdog), so it is locked.
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
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// tickingBody yields one chunk per Read and advances the clock by step before
// returning it, as a layer body slower than the lease TTL would.
type tickingBody struct {
	chunks [][]byte
	clock  *leaseClock
	step   time.Duration
	// eofStep is added to the clock on the zero-byte EOF read, which renews
	// nothing: time passes after the last arriving bytes and before commit.
	eofStep time.Duration
}

func (b *tickingBody) Read(p []byte) (int, error) {
	if len(b.chunks) == 0 {
		b.clock.advance(b.eofStep)
		b.eofStep = 0
		return 0, io.EOF
	}
	b.clock.advance(b.step)
	n := copy(p, b.chunks[0])
	if n == len(b.chunks[0]) {
		b.chunks = b.chunks[1:]
	} else {
		b.chunks[0] = b.chunks[0][n:]
	}
	return n, nil
}

func (b *tickingBody) Close() error { return nil }

// rangedStub answers the registry ping with 200 and the blob GET, which must
// carry a Range from offset have, with a 206 whose body is tickingBody.
type rangedStub struct {
	t     *testing.T
	body  []byte
	have  int64
	chunk int
	clock *leaseClock
	step  time.Duration
	// eofStep: see tickingBody.eofStep.
	eofStep time.Duration
}

func (s *rangedStub) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := &http.Response{Request: r, Header: http.Header{}, ProtoMajor: 1, ProtoMinor: 1}
	if !strings.Contains(r.URL.Path, "/blobs/") {
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp, nil
	}
	if want := "bytes=" + strconv.FormatInt(s.have, 10) + "-"; r.Header.Get("Range") != want {
		s.t.Errorf("blob GET Range = %q, want %q", r.Header.Get("Range"), want)
	}
	rest := s.body[s.have:]
	var chunks [][]byte
	for len(rest) > 0 {
		n := min(s.chunk, len(rest))
		chunks = append(chunks, rest[:n])
		rest = rest[n:]
	}
	size := int64(len(s.body))
	resp.StatusCode = http.StatusPartialContent
	resp.Header.Set("Content-Range", "bytes "+strconv.FormatInt(s.have, 10)+"-"+
		strconv.FormatInt(size-1, 10)+"/"+strconv.FormatInt(size, 10))
	resp.ContentLength = size - s.have
	resp.Body = &tickingBody{chunks: chunks, clock: s.clock, step: s.step, eofStep: s.eofStep}
	return resp, nil
}

// TestResumedTransferRenewsThePullLease pins that the ranged resume path
// renews the pull's lease on arriving bytes as the whole-layer path does: a
// resumed body whose chunks each take more than a quarter TTL, and more than
// the TTL in total, leaves the layer still leased once it is committed.
func TestResumedTransferRenewsThePullLease(t *testing.T) {
	const (
		ttl   = time.Minute
		have  = 1024
		chunk = 1024
		parts = 4
	)
	step := ttl/4 + time.Second // parts*step > ttl

	body := bytes.Repeat([]byte("resumed-layer-"), (have+parts*chunk)/14+1)[:have+parts*chunk]
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	size := int64(len(body))

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := &leaseClock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	cache.now = clock.now

	dir := filepath.Join(t.TempDir(), "partials")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h, err := ggcrv1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partialPath(dir, h), body[:have], 0o600); err != nil {
		t.Fatal(err)
	}

	fetch := func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
		t.Error("the manifest fetcher was called")
		return nil, io.ErrUnexpectedEOF
	}
	p, err := NewPuller(cache, fetch, NoLocalIndex{},
		WithFreeBytes(fixedFreeBytes(64<<30)),
		WithPartialStore(&registryfetch.PartialStore{Dir: dir}))
	if err != nil {
		t.Fatal(err)
	}
	src := BlobSource{
		Ref: "stub.invalid/test/app:v1",
		Registry: registryfetch.Registry{
			Transport: &rangedStub{t: t, body: body, have: have, chunk: chunk, clock: clock, step: step},
			PlainHTTP: true,
		},
	}

	lease := cache.AcquireLease([]string{digest}, ttl)
	defer lease.Release()
	start := clock.now()
	whole := func(io.Writer) error {
		t.Error("the resumable layer was fetched whole")
		return io.ErrUnexpectedEOF
	}
	if _, err := p.resumeBlob(context.Background(), src, digest, size, whole, lease); err != nil {
		t.Fatalf("resumeBlob: %v", err)
	}
	if !cache.Has(digest) {
		t.Fatal("the resumed layer is not in the cache")
	}
	if elapsed := clock.now().Sub(start); elapsed <= ttl {
		t.Fatalf("the transfer took %v on the cache clock, want more than the %v TTL", elapsed, ttl)
	}
	if !cache.leaseHas(digest) {
		t.Fatalf("the pull lease lapsed during a resumed transfer of %v (TTL %v)", clock.now().Sub(start), ttl)
	}
}

// TestResumedCommitRenewsThePullLease pins that the commit callbacks of the
// resume path renew the lease before hashing: time that passes after the last
// arriving bytes (the zero-byte EOF read renews nothing) is covered by a
// renewal at the start of the commit, on the clone route.
func TestResumedCommitRenewsThePullLease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		replay bool
	}{
		{"clone", false},
		{"replay", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const (
				ttl   = time.Minute
				have  = 1024
				chunk = 1024
			)
			body := bytes.Repeat([]byte("resumed-layer-"), (have+chunk)/14+1)[:have+chunk]
			sum := sha256.Sum256(body)
			digest := "sha256:" + hex.EncodeToString(sum[:])

			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			clock := &leaseClock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
			cache.now = clock.now
			if tc.replay {
				// Another volume: CommitFromLocal answers ErrBlobNotLocal and
				// Resume falls back to the Commit callback and its replay. Time
				// passes inside the refused clone attempt, after the renewal
				// before CommitFile, so only the renewal in Commit covers it.
				cache.sameVolume = func(_, _ os.FileInfo) bool {
					clock.advance(ttl/4 + time.Second)
					return false
				}
			}
			spy := spyOnVolume(cache)

			dir := filepath.Join(t.TempDir(), "partials")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			h, err := ggcrv1.NewHash(digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(partialPath(dir, h), body[:have], 0o600); err != nil {
				t.Fatal(err)
			}
			fetch := func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
				t.Error("the manifest fetcher was called")
				return nil, io.ErrUnexpectedEOF
			}
			p, err := NewPuller(cache, fetch, NoLocalIndex{},
				WithFreeBytes(fixedFreeBytes(64<<30)),
				WithPartialStore(&registryfetch.PartialStore{Dir: dir}))
			if err != nil {
				t.Fatal(err)
			}
			eof := ttl/4 + time.Second // past the throttle, well inside the TTL
			src := BlobSource{
				Ref: "stub.invalid/test/app:v1",
				Registry: registryfetch.Registry{
					Transport: &rangedStub{t: t, body: body, have: have, chunk: chunk, clock: clock, step: time.Second, eofStep: eof},
					PlainHTTP: true,
				},
			}

			lease := cache.AcquireLease([]string{digest}, ttl)
			defer lease.Release()
			whole := func(io.Writer) error {
				t.Error("the resumable layer was fetched whole")
				return io.ErrUnexpectedEOF
			}
			if _, err := p.resumeBlob(context.Background(), src, digest, int64(len(body)), whole, lease); err != nil {
				t.Fatalf("resumeBlob: %v", err)
			}
			calls, same := spy.seen()
			if calls != 1 {
				t.Fatalf("the clone path's volume check ran %d times, want 1", calls)
			}
			switch {
			case tc.replay && same:
				t.Fatal("the volume check passed: the replay route was not forced")
			case !tc.replay && runtime.GOOS == "darwin" && !same:
				t.Skip("the temp dir and the partial are not on one clonable volume")
			case !tc.replay && runtime.GOOS == "darwin":
				// The volume check passed, so the clone route ran: the staging dir
				// is empty again.
				if names := stageEntries(t, cache); len(names) != 0 {
					t.Fatalf("staging dir holds %q after the clone commit", names)
				}
			}
			cache.leaseMu.Lock()
			expires := lease.expires
			cache.leaseMu.Unlock()
			if want := clock.now().Add(ttl); !expires.Equal(want) {
				t.Fatalf("lease expires %v after the commit, want %v (renewed at commit start)", expires.Sub(clock.now()), ttl)
			}
		})
	}
}
