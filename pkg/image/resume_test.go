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
	"errors"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/registryfetch"
)

// cutRegistry is a plain-HTTP in-memory registry holding one image whose
// layer blob it serves itself: the first cut GETs of that blob stop after cutAt
// bytes, the first badRange ranged GETs are answered with a Content-Range
// that is not the one asked for, and every layer GET's Range header is
// recorded. With wholeOn200 set, an uncut GET ignores its Range header and
// is answered with a plain 200 and the whole body.
type cutRegistry struct {
	host     string
	ref      string
	layer    ggcrv1.Hash
	size     int64
	cutAt    int64
	body     []byte
	mu       sync.Mutex
	cuts     int      // GETs still to cut
	stalls   int      // cut GETs that hold the connection instead of dropping it
	badRange int      // ranged GETs still to answer with a wrong Content-Range
	overrun  int      // uncut GETs still to answer 200 with one byte past the blob
	ranges   []string // the Range header of every layer GET, in order
	// wholeOn200 makes every uncut GET ignore Range and answer 200 whole.
	wholeOn200 bool
	// hold, when not nil, keeps every served layer GET waiting until it is
	// closed; inflight counts the GETs waiting, maxInflight its peak and
	// arrivals every GET that reached the hold. allHeld is closed the first
	// time holdWant GETs wait on hold at once.
	hold        chan struct{}
	holdWant    int
	allHeld     chan struct{}
	inflight    int
	maxInflight int
	arrivals    int
	// release frees every stalled GET; the fixture closes it at cleanup.
	release chan struct{}
}

// holdServes makes every later served layer GET wait until the returned hold
// channel is closed. The returned all channel is closed by the fake itself
// the moment want GETs are waiting on hold at the same time.
func (c *cutRegistry) holdServes(want int) (hold, all chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hold = make(chan struct{})
	c.holdWant = want
	c.allHeld = make(chan struct{})
	return c.hold, c.allHeld
}

// held reports how many layer GETs reached the hold, and the peak waiting on
// it at once.
func (c *cutRegistry) held() (arrivals, peak int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.arrivals, c.maxInflight
}

// stall makes the next n layer GETs send cutAt bytes, flush, and then hold the
// connection open, sending nothing more, until the client goes away.
func (c *cutRegistry) stall(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cuts = n
	c.stalls = n
}

// arm sets the fixture's fault counters under its mutex.
func (c *cutRegistry) arm(cuts, badRange int, wholeOn200 bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cuts = cuts
	c.badRange = badRange
	c.wholeOn200 = wholeOn200
}

func newCutRegistry(t *testing.T, cutAt int64) *cutRegistry {
	t.Helper()
	img, err := random.Image(64<<10, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	img = withPlatform(t, img, "darwin", "arm64", "")
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	mfst, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	c := &cutRegistry{layer: mfst.Layers[0].Digest, size: mfst.Layers[0].Size, cutAt: cutAt, body: body,
		release: make(chan struct{})}
	if int64(len(body)) != c.size || cutAt <= 0 || cutAt >= c.size {
		t.Fatalf("fixture: layer %d bytes, descriptor %d, cut at %d", len(body), c.size, cutAt)
	}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	layerPath := "/v2/test/app/blobs/" + c.layer.String()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != layerPath || r.Method != http.MethodGet {
			store.ServeHTTP(w, r)
			return
		}
		c.mu.Lock()
		c.ranges = append(c.ranges, r.Header.Get("Range"))
		cut := c.cuts > 0
		if cut {
			c.cuts--
		}
		stall := cut && c.stalls > 0
		if stall {
			c.stalls--
		}
		bad := !cut && c.badRange > 0 && r.Header.Get("Range") != ""
		if bad {
			c.badRange--
		}
		over := !cut && !bad && c.overrun > 0
		if over {
			c.overrun--
		}
		whole := !cut && !bad && c.wholeOn200
		hold := c.hold
		if hold != nil && !cut {
			c.inflight++
			c.arrivals++
			c.maxInflight = max(c.maxInflight, c.inflight)
			if c.inflight == c.holdWant {
				select {
				case <-c.allHeld:
				default:
					close(c.allHeld)
				}
			}
		}
		c.mu.Unlock()
		if hold != nil && !cut {
			select {
			case <-hold:
			case <-r.Context().Done():
			}
			c.mu.Lock()
			c.inflight--
			c.mu.Unlock()
		}
		if over {
			// No Content-Length: the body runs one byte past the descriptor size.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(c.body)
			_, _ = w.Write([]byte{0x5a})
			return
		}
		if whole {
			w.Header().Set("Content-Length", strconv.FormatInt(c.size, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(c.body)
			return
		}
		if bad {
			// The whole blob, labelled as a range from 0: not the offset asked for.
			w.Header().Set("Content-Range", "bytes 0-"+strconv.FormatInt(c.size-1, 10)+"/"+strconv.FormatInt(c.size, 10))
			w.Header().Set("Content-Length", strconv.FormatInt(c.size, 10))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(c.body)
			return
		}
		if cut {
			w.Header().Set("Content-Length", strconv.FormatInt(c.size, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(c.body[:c.cutAt])
			w.(http.Flusher).Flush()
			if stall {
				// The body stops moving; the connection stays open.
				select {
				case <-c.release:
				case <-r.Context().Done():
				}
				return
			}
			panic(http.ErrAbortHandler) // the connection drops mid-body
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(c.body))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	// Registered after srv.Close, so it runs first and frees a stalled handler.
	t.Cleanup(func() { close(c.release) })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.host = u.Host
	c.ref = c.host + "/test/app:v1"
	r, err := name.ParseReference(c.ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return c
}

func (c *cutRegistry) takeRanges() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.ranges
	c.ranges = nil
	return out
}

// resumePuller is a Puller over c with a direct plain-HTTP blob route and a
// partial store in dir.
func resumePuller(t *testing.T, c *cutRegistry, cache *Cache, partials *registryfetch.PartialStore) *Puller {
	t.Helper()
	return resumePullerVia(t, cache, partials, http.DefaultTransport)
}

// resumePullerVia is resumePuller with blob GETs sent over rt.
func resumePullerVia(t *testing.T, cache *Cache, partials *registryfetch.PartialStore, rt http.RoundTripper) *Puller {
	t.Helper()
	fetch := func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, err
		}
		return remoteFetch(ctx, r, ref, cred, policy, remote.WithTransport(http.DefaultTransport))
	}
	blobs := func(ref string, cred *RegistryCredential) (BlobSource, error) {
		r, err := name.ParseReference(ref)
		if err != nil {
			return BlobSource{}, err
		}
		return BlobSource{
			Ref:        r.Name(),
			Registry:   registryfetch.Registry{Transport: rt, PlainHTTP: true},
			Credential: cred.registryfetchCredential(),
		}, nil
	}
	p, err := NewPuller(cache, fetch, NoLocalIndex{},
		WithFreeBytes(fixedFreeBytes(64<<30)),
		WithRegistryBlobSource(blobs, nil),
		WithPartialStore(partials))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func partialPath(dir string, d ggcrv1.Hash) string {
	return filepath.Join(dir, "sha256-"+d.Hex+".partial")
}

func pullAlways(p *Puller, ref string) (*PullResult, error) {
	return p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
}

// verifyLayer re-hashes the committed layer blob against its digest.
func verifyLayer(t *testing.T, cache *Cache, c *cutRegistry) {
	t.Helper()
	path, err := cache.BlobPath(c.layer.String())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("committed layer: %v", err)
	}
	defer f.Close()
	got, n, err := ggcrv1.SHA256(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != c.layer || n != c.size {
		t.Fatalf("committed layer is %s (%d bytes), want %s (%d)", got, n, c.layer, c.size)
	}
}

// layerBytesEqual reads the committed layer blob and compares it byte for
// byte with the body the registry served.
func layerBytesEqual(t *testing.T, cache *Cache, c *cutRegistry) {
	t.Helper()
	path, err := cache.BlobPath(c.layer.String())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("committed layer: %v", err)
	}
	if !bytes.Equal(got, c.body) {
		t.Fatalf("committed layer bytes differ from the served body (%d bytes, want %d)", len(got), len(c.body))
	}
}

// TestPullResumesCutLayerWithRange pins the resumable layer fetch: a pull cut
// mid-layer keeps the bytes it received, the next pull asks for the rest with
// a Range request and completes with the layer verifying, and a partial whose
// bytes are wrong is refused by the digest check, removed, and not resumed.
func TestPullResumesCutLayerWithRange(t *testing.T) {
	const cutAt = 4096

	t.Run("cut layer resumes from the bytes received", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 0, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		fi, err := os.Stat(partialPath(dir, c.layer))
		if err != nil {
			t.Fatalf("no partial after the cut pull: %v", err)
		}
		if fi.Size() != cutAt {
			t.Fatalf("partial holds %d bytes, want %d", fi.Size(), cutAt)
		}
		if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
			t.Fatalf("first pull layer Range headers = %q, want one GET with none", got)
		}

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("second pull: %v", err)
		}
		res.Lease.Release()
		want := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"
		if got := c.takeRanges(); len(got) != 1 || got[0] != want {
			t.Fatalf("second pull layer Range headers = %q, want [%q]", got, want)
		}
		verifyLayer(t, cache, c)
		layerBytesEqual(t, cache, c)
		if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial survived its commit: %v", err)
		}
	})

	t.Run("wrong partial is refused, removed, and restarted from 0", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		if err := store.EnsureDir(); err != nil {
			t.Fatal(err)
		}
		bad := bytes.Repeat([]byte{0xA5}, cutAt)
		if err := os.WriteFile(partialPath(dir, c.layer), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		p := resumePuller(t, c, cache, store)

		_, err = pullAlways(p, c.ref)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("pull over a wrong partial: err = %v, want ErrDigestMismatch", err)
		}
		want := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"
		if got := c.takeRanges(); len(got) != 1 || got[0] != want {
			t.Fatalf("pull over a wrong partial Range headers = %q, want [%q]", got, want)
		}
		if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("poisoned partial was not removed: %v", err)
		}
		if cache.Has(c.layer.String()) {
			t.Fatal("a layer that failed its digest check is in the cache")
		}

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull after the poisoned partial: %v", err)
		}
		res.Lease.Release()
		if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
			t.Fatalf("pull after the poisoned partial Range headers = %q, want one GET from 0", got)
		}
		verifyLayer(t, cache, c)
	})

	t.Run("wrong range answer removes the partial and fetches the layer whole", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 1, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		p := resumePuller(t, c, cache, store)

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		if got := store.Bytes(c.layer.String(), c.size); got != cutAt {
			t.Fatalf("partial holds %d bytes after the cut pull, want %d", got, cutAt)
		}
		c.takeRanges()

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull over a wrong range answer: %v", err)
		}
		res.Lease.Release()
		verifyLayer(t, cache, c)
		part := filepath.Join(dir, strings.Replace(c.layer.String(), ":", "-", 1)+".partial")
		if _, err := os.Lstat(part); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial %s after the wrong range answer: err %v, want not exist", part, err)
		}
		ranged := 0
		for _, r := range c.takeRanges() {
			if r != "" {
				ranged++
			}
		}
		if ranged != 1 {
			t.Fatalf("pull over a wrong range answer made %d ranged requests, want 1", ranged)
		}
	})
}

// bodyCount is a RoundTripper that reports, by closing reached, the moment the
// consumer of a response body to a GET for path has read want bytes of it.
type bodyCount struct {
	rt      http.RoundTripper
	path    string
	want    int64
	once    sync.Once
	reached chan struct{}
}

func (b *bodyCount) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.rt.RoundTrip(r)
	if err != nil || r.Method != http.MethodGet || r.URL.Path != b.path {
		return resp, err
	}
	resp.Body = &countedBody{ReadCloser: resp.Body, b: b}
	return resp, nil
}

// countedBody counts one response body's bytes for its bodyCount.
type countedBody struct {
	io.ReadCloser
	b *bodyCount
	n int64
}

func (c *countedBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	if c.n >= c.b.want {
		c.b.once.Do(func() { close(c.b.reached) })
	}
	return n, err
}

// TestPullResumeStalledBodyKeepsPartial pins the stall watchdog on the resumed
// fetch: a layer body that sends cutAt bytes and then stops moving, with the
// connection held open, fails the pull with ErrLayerBodyStalled once the
// watchdog fires; the stall is not a verdict on the bytes, so the partial keeps
// exactly the cutAt bytes, and the next pull resumes from there with a Range
// request and commits a layer that verifies. The watchdog runs on the fake
// timer; nothing waits on the wall clock.
func TestPullResumeStalledBodyKeepsPartial(t *testing.T) {
	const cutAt = 4096
	c := newCutRegistry(t, cutAt)
	c.stall(1)
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "partials")
	count := &bodyCount{rt: http.DefaultTransport, path: "/v2/test/app/blobs/" + c.layer.String(),
		want: cutAt, reached: make(chan struct{})}
	p := resumePullerVia(t, cache, &registryfetch.PartialStore{Dir: dir}, count)
	ft := newFakeTimer()
	p.stallAfterFunc = ft.afterFunc

	done := make(chan error, 1)
	go func() {
		res, err := pullAlways(p, c.ref)
		if res != nil && res.Lease != nil {
			res.Lease.Release()
		}
		done <- err
	}()
	// Fire nothing until the watchdog's reader has taken all cutAt bytes, so the
	// fire can only cut the silence after them. A pull that ends first fails
	// below; a pull that never ends is caught by go test -timeout.
	var first error
	ended := false
	select {
	case first = <-done:
		ended = true
	case <-count.reached:
	}
	for !ended {
		select {
		case first = <-done:
			ended = true
		case <-ft.armed:
			ft.advance(p.stallWindow())
		}
	}
	if !errors.Is(first, ErrLayerBodyStalled) {
		t.Fatalf("first pull error = %v, want ErrLayerBodyStalled", first)
	}
	fi, err := os.Stat(partialPath(dir, c.layer))
	if err != nil {
		t.Fatalf("no partial after the stalled pull: %v", err)
	}
	if fi.Size() != cutAt {
		t.Fatalf("partial holds %d bytes after the stall, want %d", fi.Size(), cutAt)
	}
	if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
		t.Fatalf("first pull layer Range headers = %q, want one GET with none", got)
	}

	// The fake timer is never advanced again, so the healthy resumed body
	// cannot be cut.
	res, err := pullAlways(p, c.ref)
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	res.Lease.Release()
	want := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"
	if got := c.takeRanges(); len(got) != 1 || got[0] != want {
		t.Fatalf("second pull layer Range headers = %q, want [%q]", got, want)
	}
	verifyLayer(t, cache, c)
	if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial survived its commit: %v", err)
	}
}

// TestPullResumeOverrunEmptiesThePartial pins the overrun branch: a registry
// whose body runs past the descriptor size fails the pull with ErrBlobTooLarge
// and leaves no bytes in the partial, so the next pull fetches from 0 with no
// Range instead of resuming over a body known to be wrong.
func TestPullResumeOverrunEmptiesThePartial(t *testing.T) {
	c := newCutRegistry(t, 4096)
	c.mu.Lock()
	c.overrun = 1
	c.mu.Unlock()
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "partials")
	store := &registryfetch.PartialStore{Dir: dir}
	p := resumePuller(t, c, cache, store)

	if _, err := pullAlways(p, c.ref); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("pull over an overlong body: err = %v, want ErrBlobTooLarge", err)
	}
	if cache.Has(c.layer.String()) {
		t.Fatal("an overlong layer is in the cache")
	}
	if got := store.Bytes(c.layer.String(), c.size); got != 0 {
		t.Fatalf("partial holds %d bytes after an overlong body, want 0", got)
	}
	c.takeRanges()

	res, err := pullAlways(p, c.ref)
	if err != nil {
		t.Fatalf("pull after the overlong body: %v", err)
	}
	res.Lease.Release()
	if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
		t.Fatalf("pull after the overlong body Range headers = %q, want one GET from 0", got)
	}
	verifyLayer(t, cache, c)
}

// TestPullResumesRestartsOn200ToRange pins the restart branch of the resumable
// layer fetch: a registry that answers the resume's Range request with a plain
// 200 and the whole body makes the pull drop the partial's prefix and write
// the body from 0, so the committed layer is the body and not prefix+body.
func TestPullResumesRestartsOn200ToRange(t *testing.T) {
	const cutAt = 4096
	c := newCutRegistry(t, cutAt)
	c.arm(1, 0, true)
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "partials")
	p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})

	if _, err := pullAlways(p, c.ref); err == nil {
		t.Fatal("first pull succeeded through a cut layer")
	}
	fi, err := os.Stat(partialPath(dir, c.layer))
	if err != nil {
		t.Fatalf("no partial after the cut pull: %v", err)
	}
	if fi.Size() != cutAt {
		t.Fatalf("partial holds %d bytes, want %d", fi.Size(), cutAt)
	}

	res, err := pullAlways(p, c.ref)
	if err != nil {
		t.Fatalf("pull over a 200 answer to a Range request: %v", err)
	}
	res.Lease.Release()
	ranged := 0
	for _, r := range c.takeRanges() {
		if r != "" {
			ranged++
		}
	}
	if ranged != 1 {
		t.Fatalf("pulls made %d ranged requests, want 1", ranged)
	}
	verifyLayer(t, cache, c)
	layerBytesEqual(t, cache, c)
	if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial survived its commit: %v", err)
	}
}

// TestPullResumesFallsBackOnPartialStoreEnv pins that a partial store whose
// own environment is unusable does not fail the pull: the layer is fetched
// whole and verifies. A done context is not retried whole.
func TestPullResumesFallsBackOnPartialStoreEnv(t *testing.T) {
	t.Run("partial dir parent does not exist", func(t *testing.T) {
		c := newCutRegistry(t, 4096)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "missing", "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull over a partial dir with no parent: %v", err)
		}
		if out := logs.String(); !strings.Contains(out, "level=WARN") ||
			!strings.Contains(out, "partial store unusable") ||
			strings.Contains(out, "possibleTampering") || strings.Contains(out, "level=ERROR") {
			t.Fatalf("missing parent must log at Warn without the tampering field:\n%s", out)
		}
		res.Lease.Release()
		verifyLayer(t, cache, c)
	})

	t.Run("partial path is a directory", func(t *testing.T) {
		c := newCutRegistry(t, 4096)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		if err := store.EnsureDir(); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(partialPath(dir, c.layer), 0o700); err != nil {
			t.Fatal(err)
		}
		p := resumePuller(t, c, cache, store)
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull over a partial path that is a directory: %v", err)
		}
		if out := logs.String(); !strings.Contains(out, "level=ERROR") ||
			!strings.Contains(out, "possibleTampering=true") {
			t.Fatalf("a directory where the partial belongs must log at Error with possibleTampering:\n%s", out)
		}
		res.Lease.Release()
		verifyLayer(t, cache, c)
	})

	t.Run("cancelled context does not fall back", func(t *testing.T) {
		c := newCutRegistry(t, 4096)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "missing", "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// whole would succeed without the network, so only the context
		// guard can make this fail.
		whole := func(w io.Writer) error {
			_, werr := w.Write(c.body)
			return werr
		}
		_, err = p.resumeBlob(ctx, BlobSource{}, c.layer.String(), c.size, nil, whole)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("resumeBlob with a cancelled context: err = %v, want context.Canceled", err)
		}
		if cache.Has(c.layer.String()) {
			t.Fatal("a cancelled pull committed the layer whole")
		}

		_, err = p.Pull(ctx, c.ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pull with a cancelled context: err = %v, want context.Canceled", err)
		}
	})
}

// stageEntries lists the cache's local staging directory: nil when it was
// never created, which is the mark of a commit that did not go through
// CommitFromLocal.
func stageEntries(t *testing.T, cache *Cache) []string {
	t.Helper()
	d, err := os.Open(filepath.Join(cache.Root(), localStageDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	if names == nil {
		names = []string{}
	}
	return names
}

// volumeSpy wraps the cache's sameVolume seam with a recorder that delegates
// to the real check, so a test can tell whether the clone path was reached
// and whether it judged the source and the store to share a volume.
type volumeSpy struct {
	mu    sync.Mutex
	calls int
	last  bool
}

func spyOnVolume(cache *Cache) *volumeSpy {
	s := &volumeSpy{}
	real := cache.sameVolume
	if real == nil {
		real = sameDevice
	}
	cache.sameVolume = func(src, store os.FileInfo) bool {
		ok := real(src, store)
		s.mu.Lock()
		s.calls++
		s.last = ok
		s.mu.Unlock()
		return ok
	}
	return s
}

func (s *volumeSpy) seen() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.last
}

// TestPullResumeCommitsByClone pins the in-place commit of a resumed layer on
// one APFS volume: the complete partial is cloned into the cache's staging
// dir and the clone re-hashed, rather than replayed into a second temp file.
// A partial whose tail is wrong is refused with the digest mismatch, and
// leaves no blob, no clone in the staging dir and no partial.
func TestPullResumeCommitsByClone(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("clonefile is darwin only")
	}
	const cutAt = 4096

	t.Run("cut layer commits through a clone", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 0, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))
		spy := spyOnVolume(cache)

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("resumed pull: %v", err)
		}
		res.Lease.Release()
		verifyLayer(t, cache, c)
		layerBytesEqual(t, cache, c)
		calls, same := spy.seen()
		if calls > 0 && !same {
			t.Skip("the temp dir and the partial are not on one clonable volume")
		}
		if calls == 0 {
			t.Fatal("the clone path never reached its volume check: the layer was not committed by clone")
		}
		if out := logs.String(); strings.Contains(out, "replaying") {
			t.Fatalf("the resumed layer was replayed, not cloned:\n%s", out)
		}
		if _, err := os.Lstat(partialPath(dir, c.layer)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial survived its commit: %v", err)
		}
		names := stageEntries(t, cache)
		if names == nil {
			t.Fatal("no staging dir: the resumed layer was not committed by clone")
		}
		if len(names) != 0 {
			t.Fatalf("staging dir holds %q after the commit, want it empty", names)
		}
	})

	t.Run("another volume replays quietly", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 0, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cache.sameVolume = func(_, _ os.FileInfo) bool { return false }
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		c.takeRanges()

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("resumed pull across volumes: %v", err)
		}
		res.Lease.Release()
		if got := c.takeRanges(); len(got) == 0 {
			t.Fatal("resumed pull sent no Range header: the layer was fetched whole, not resumed")
		}
		verifyLayer(t, cache, c)
		layerBytesEqual(t, cache, c)
		if _, err := os.Lstat(partialPath(dir, c.layer)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial survived its replayed commit: %v", err)
		}
		if out := logs.String(); strings.Contains(out, "level=ERROR") {
			t.Fatalf("another volume is the quiet fallback, but an Error was logged:\n%s", out)
		}
	})

	t.Run("clone-stage refusal replays into CommitBlob", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 0, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		c.takeRanges()
		// A staging dir of a mode other than 0700 is refused by
		// openStageDir with an error that is not ErrBlobNotLocal and says
		// nothing about the partial's bytes.
		stage := filepath.Join(cache.Root(), localStageDir)
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o755); err != nil {
			t.Fatal(err)
		}

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("resumed pull over a refused staging dir: %v", err)
		}
		res.Lease.Release()
		if got := c.takeRanges(); len(got) == 0 {
			t.Fatal("resumed pull sent no Range header: the layer was fetched whole, not resumed")
		}
		verifyLayer(t, cache, c)
		layerBytesEqual(t, cache, c)
		if _, err := os.Lstat(partialPath(dir, c.layer)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial survived its replayed commit: %v", err)
		}
		if names := stageEntries(t, cache); len(names) != 0 {
			t.Fatalf("refused staging dir holds %q, want it empty", names)
		}
		out := logs.String()
		const line = "layer partial not committed by clone; replaying it"
		if n := strings.Count(out, line); n != 1 ||
			!strings.Contains(out, "level=ERROR msg=\""+line+"\"") ||
			!strings.Contains(out, "possibleTampering=true") {
			t.Fatalf("clone-stage refusal must be logged once at Error with possibleTampering (%d lines):\n%s", n, out)
		}
	})

	t.Run("tampered tail is refused and leaves nothing", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.arm(1, 0, false)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		var logs bytes.Buffer
		p.log = slog.New(slog.NewTextHandler(&logs, nil))

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		c.takeRanges()
		// Complete the partial with a tail whose last byte is flipped, so the
		// next pull commits it without a transfer.
		if fi, err := os.Stat(partialPath(dir, c.layer)); err != nil || fi.Size() != cutAt {
			t.Fatalf("partial before the tail is appended: size %v, err %v, want exactly %d bytes", fi, err, cutAt)
		}
		tail := bytes.Clone(c.body[cutAt:])
		tail[len(tail)-1] ^= 0xFF
		f, err := os.OpenFile(partialPath(dir, c.layer), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(tail); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		_, err = pullAlways(p, c.ref)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("pull over a tampered tail: err = %v, want ErrDigestMismatch", err)
		}
		if got := c.takeRanges(); len(got) != 0 {
			t.Fatalf("pull over a complete partial fetched the layer: Range headers %q", got)
		}
		// The clone's digest verdict is final: it is not replayed into
		// CommitBlob as a clone-stage refusal would be.
		if out := logs.String(); strings.Contains(out, "not committed by clone") {
			t.Fatalf("a digest mismatch from the clone was treated as a clone-stage refusal:\n%s", out)
		}
		if cache.Has(c.layer.String()) {
			t.Fatal("a layer that failed its digest check is in the cache")
		}
		names := stageEntries(t, cache)
		if names == nil {
			t.Fatal("no staging dir: the tampered partial was not checked by clone")
		}
		if len(names) != 0 {
			t.Fatalf("staging dir holds %q after a refused commit, want it empty", names)
		}
		if _, err := os.Lstat(partialPath(dir, c.layer)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("poisoned partial was not removed: %v", err)
		}
	})
}

// TestPullResumeConcurrentSameLayer pins resume under contention: with a cut
// partial on disk, several pulls of the same layer run at once over one
// partial store, every layer GET held open until all are in flight. Exactly
// one pull resumes the partial with a Range request; the rest fetch the layer
// whole rather than reading the partial another pull is still growing. Every
// pull succeeds with the layer verifying byte for byte, and no partial or
// staging file is left behind.
func TestPullResumeConcurrentSameLayer(t *testing.T) {
	const (
		cutAt   = 4096
		pullers = 6
	)
	resumed := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"

	// run seeds a cut partial through pulls[0], then runs every pull at once
	// and returns each one's error.
	run := func(t *testing.T, c *cutRegistry, dir string, pulls []*Puller) []error {
		t.Helper()
		c.arm(1, 0, false)
		if _, err := pullAlways(pulls[0], c.ref); err == nil {
			t.Fatal("seeding pull succeeded through a cut layer")
		}
		fi, err := os.Stat(partialPath(dir, c.layer))
		if err != nil || fi.Size() != cutAt {
			t.Fatalf("partial after the cut pull: %v, err %v, want %d bytes", fi, err, cutAt)
		}
		c.takeRanges()

		// Every pull is expected to have its own layer GET waiting at once, in
		// both subtests: nothing in the pull path coalesces pulls of one
		// digest. PartialStore.Claim never blocks, so the pulls that lose the
		// claim fall back to writeBlob at once (resumeBlob); CommitBlob takes
		// no per-digest lock, and its only shortcut, a blob already committed,
		// cannot apply while every GET is still held. A shared Cache therefore
		// changes nothing here: waiting for fewer GETs would let the pulls run
		// one after another unnoticed.
		want := len(pulls)
		hold, allHeld := c.holdServes(want)
		released := false
		release := func() {
			if !released {
				released = true
				close(hold)
			}
		}
		defer release()
		errs := make([]error, len(pulls))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, p := range pulls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				res, err := pullAlways(p, c.ref)
				if err == nil {
					res.Lease.Release()
				}
				errs[i] = err
			}()
		}
		close(start)
		// Release only once the fake has seen every expected GET waiting at
		// the same time. The deadline is a hang guard, generous enough for a
		// loaded machine under -race; reaching it fails the test, it never
		// releases the hold early.
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		select {
		case <-allHeld:
		case <-timer.C:
			release()
			wg.Wait()
			arrived, peak := c.held()
			t.Fatalf("only %d of %d layer GETs reached the registry within the deadline (peak %d at once): the pulls did not overlap", arrived, want, peak)
		}
		release()
		wg.Wait()
		if _, peak := c.held(); peak < want {
			t.Fatalf("at most %d layer GETs were in flight at once, want %d: the pulls did not overlap", peak, want)
		}
		return errs
	}

	// leftovers fails on any entry in the partial dir or the staging dir.
	leftovers := func(t *testing.T, dir string, caches ...*Cache) {
		t.Helper()
		names, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(names) != 0 {
			t.Fatalf("partial dir holds %v after every pull, want it empty", names)
		}
		for _, cache := range caches {
			if names := stageEntries(t, cache); len(names) != 0 {
				t.Fatalf("staging dir holds %q after every pull, want it empty", names)
			}
		}
	}

	// oneResume fails unless exactly one layer GET was the resume from cutAt
	// and no other GET asked for a range.
	oneResume := func(t *testing.T, c *cutRegistry) {
		t.Helper()
		got := c.takeRanges()
		n := 0
		for _, r := range got {
			switch r {
			case resumed:
				n++
			case "":
			default:
				t.Fatalf("layer GET asked for %q, want only %q or none (all: %q)", r, resumed, got)
			}
		}
		if n != 1 {
			t.Fatalf("%d layer GETs resumed the partial, want exactly 1 (all: %q)", n, got)
		}
	}

	t.Run("one puller", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})
		pulls := make([]*Puller, pullers)
		for i := range pulls {
			pulls[i] = p
		}
		for i, err := range run(t, c, dir, pulls) {
			if err != nil {
				t.Errorf("pull %d: %v", i, err)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		oneResume(t, c)
		verifyLayer(t, cache, c)
		layerBytesEqual(t, cache, c)
		leftovers(t, dir, cache)
	})

	t.Run("a cache per puller over one partial store", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		pulls := make([]*Puller, pullers)
		caches := make([]*Cache, pullers)
		for i := range pulls {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			caches[i] = cache
			pulls[i] = resumePuller(t, c, cache, store)
		}
		for i, err := range run(t, c, dir, pulls) {
			if err != nil {
				t.Errorf("pull %d: %v", i, err)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		oneResume(t, c)
		for _, cache := range caches {
			verifyLayer(t, cache, c)
			layerBytesEqual(t, cache, c)
		}
		leftovers(t, dir, caches...)
	})
}
