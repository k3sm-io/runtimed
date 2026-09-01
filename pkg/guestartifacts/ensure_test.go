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

package guestartifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Fixtures. Every test in this file runs against an in-memory fetcher and a
// t.TempDir cache: no socket is opened and no byte leaves the process, which is
// what lets the whole verification matrix — including the failures — run in the
// unit tier.
// ============================================================================

const testReleaseURL = "https://example.invalid/guest/v6.18.48-abc"

var (
	testKernelBytes    = []byte("k3sm test guest kernel Image\n")
	testInitramfsBytes = []byte("k3sm test guest initramfs cpio\n")
)

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testPin is the pin matching the fixture bytes above.
func testPin() GuestKernelPin {
	return GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     hashOf(testKernelBytes),
		InitramfsSHA256: hashOf(testInitramfsBytes),
		ReleaseURL:      testReleaseURL,
		Cmdline:         "console=hvc0 reboot=k panic=1",
	}
}

// pinFor builds a pin over arbitrary artifact bytes, so a test can stage more
// than one distinct set in a cache.
func pinFor(kernel, initramfs []byte) GuestKernelPin {
	return GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     hashOf(kernel),
		InitramfsSHA256: hashOf(initramfs),
		ReleaseURL:      testReleaseURL,
		Cmdline:         "console=hvc0 reboot=k panic=1",
	}
}

// fakeFetcher serves bytes from memory and counts what was asked for.
//
// The call count is as load-bearing as the bytes: "the cache was used" is not
// observable from the returned paths — a correct ensure and a cache-ignoring one
// return the same two paths with the same two digests — so the only witness that
// a warm cache was honoured is that nothing was fetched.
type fakeFetcher struct {
	mu sync.Mutex
	// bodies maps an artifact basename to the bytes served for it.
	bodies map[string][]byte
	// errs maps an artifact basename to an error returned instead of bytes.
	errs map[string]error
	// block, when set for a basename, makes Fetch wait for the context instead
	// of serving, modelling a request that never gets a response.
	block map[string]bool
	// stall, when set for a basename, serves the body one byte at a time
	// forever, modelling a transfer that starts and then goes nowhere.
	stall map[string]bool
	calls map[string]int
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		bodies: map[string][]byte{
			ImageFileName:     testKernelBytes,
			InitramfsFileName: testInitramfsBytes,
		},
		errs:  map[string]error{},
		block: map[string]bool{},
		stall: map[string]bool{},
		calls: map[string]int{},
	}
}

func (f *fakeFetcher) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	name := filepath.Base(url)
	f.mu.Lock()
	f.calls[name]++
	body, haveBody := f.bodies[name]
	err := f.errs[name]
	block := f.block[name]
	stall := f.stall[name]
	f.mu.Unlock()

	if !strings.HasPrefix(url, testReleaseURL+"/") {
		return nil, fmt.Errorf("fake fetcher: unexpected url %q", url)
	}
	if err != nil {
		return nil, err
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if !haveBody {
		return nil, fmt.Errorf("fake fetcher: nothing published at %q", url)
	}
	if stall {
		return io.NopCloser(&trickleReader{}), nil
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (f *fakeFetcher) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeFetcher) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

// trickleReader never ends: it yields one byte per read, forever. It models a
// transfer that is technically progressing and will never finish, which is the
// case a per-read idle timeout would miss and a total deadline catches.
type trickleReader struct{}

func (t *trickleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	time.Sleep(time.Millisecond)
	return 1, nil
}

// stageSet writes a valid, self-consistent cached set for pin p.
func stageSet(t *testing.T, dir string, p GuestKernelPin, kernel, initramfs []byte) string {
	t.Helper()
	setDir := filepath.Join(dir, p.SetDigest())
	if err := os.MkdirAll(setDir, 0o755); err != nil {
		t.Fatalf("stage the set dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(setDir, ImageFileName), kernel, 0o644); err != nil {
		t.Fatalf("stage the kernel: %v", err)
	}
	if err := os.WriteFile(filepath.Join(setDir, InitramfsFileName), initramfs, 0o644); err != nil {
		t.Fatalf("stage the initramfs: %v", err)
	}
	return setDir
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// setDirs lists the 64-hex set directories present in a cache root.
func setDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the cache dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && IsValidDigest(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// tempFiles lists the partial-download temp files present in a cache root.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the cache dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// ============================================================================
// The core matrix.
// ============================================================================

func TestEnsureGuestArtifacts(t *testing.T) {
	tests := []struct {
		name string
		// setup stages the cache before the ensure and may adjust the fetcher.
		setup func(t *testing.T, dir string, f *fakeFetcher)
		// pin overrides the pin under test; nil means testPin().
		pin *GuestKernelPin
		// dir overrides the cache dir; empty means the test's temp dir.
		dir string
		// nilFetcher passes a nil Fetcher, the caller-error the seam must
		// refuse rather than dereference.
		nilFetcher bool
		wantErr    error
		// wantErrMsg is a substring of the error, for the cases with no sentinel.
		wantErrMsg string
		// wantFetches counts fetches per artifact basename. An absent key means
		// "expect zero", asserted explicitly so a stray fetch cannot hide.
		wantFetches map[string]int
		// wantInstalled asserts both artifacts are present and verify.
		wantInstalled bool
	}{
		{
			name:          "a cold cache fetches and installs both artifacts",
			wantFetches:   map[string]int{ImageFileName: 1, InitramfsFileName: 1},
			wantInstalled: true,
		},
		{
			name: "a warm cache fetches nothing",
			setup: func(t *testing.T, dir string, _ *fakeFetcher) {
				stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
			},
			wantFetches:   map[string]int{},
			wantInstalled: true,
		},
		{
			name: "a corrupt cached kernel is re-fetched and its sibling is not",
			setup: func(t *testing.T, dir string, _ *fakeFetcher) {
				set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
				corrupt := append([]byte(nil), testKernelBytes...)
				corrupt[0] ^= 0xff
				if err := os.WriteFile(filepath.Join(set, ImageFileName), corrupt, 0o644); err != nil {
					t.Fatalf("corrupt the cached kernel: %v", err)
				}
			},
			wantFetches:   map[string]int{ImageFileName: 1},
			wantInstalled: true,
		},
		{
			name: "a truncated cached initramfs is re-fetched",
			setup: func(t *testing.T, dir string, _ *fakeFetcher) {
				set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
				if err := os.Truncate(filepath.Join(set, InitramfsFileName), 3); err != nil {
					t.Fatalf("truncate the cached initramfs: %v", err)
				}
			},
			wantFetches:   map[string]int{InitramfsFileName: 1},
			wantInstalled: true,
		},
		{
			name: "an empty cached artifact is re-fetched",
			setup: func(t *testing.T, dir string, _ *fakeFetcher) {
				set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
				if err := os.WriteFile(filepath.Join(set, ImageFileName), nil, 0o644); err != nil {
					t.Fatalf("empty the cached kernel: %v", err)
				}
			},
			wantFetches:   map[string]int{ImageFileName: 1},
			wantInstalled: true,
		},
		{
			name: "bytes off the wire that do not match the pin install nothing",
			setup: func(t *testing.T, _ string, f *fakeFetcher) {
				wrong := append([]byte(nil), testKernelBytes...)
				wrong[len(wrong)-1] ^= 0x01
				f.bodies[ImageFileName] = wrong
			},
			wantErr:     ErrDigestMismatch,
			wantFetches: map[string]int{ImageFileName: 1},
		},
		{
			name: "a fetch error is returned and nothing is installed",
			setup: func(t *testing.T, _ string, f *fakeFetcher) {
				f.errs[ImageFileName] = errors.New("no route to host")
			},
			wantErrMsg:  "no route to host",
			wantFetches: map[string]int{ImageFileName: 1},
		},
		{
			name: "an unminted pin is refused before anything is fetched",
			pin: func() *GuestKernelPin {
				p := testPin()
				p.ImageSHA256, p.InitramfsSHA256 = "", ""
				return &p
			}(),
			wantErr:     ErrPinIncomplete,
			wantFetches: map[string]int{},
		},
		{
			name: "a malformed pin digest is refused before anything is fetched",
			pin: func() *GuestKernelPin {
				p := testPin()
				p.InitramfsSHA256 = "deadbeef"
				return &p
			}(),
			wantErr:     ErrPinIncomplete,
			wantFetches: map[string]int{},
		},
		{
			name:        "a relative cache dir is refused",
			dir:         "relative/cache",
			wantErrMsg:  "is not an absolute path",
			wantFetches: map[string]int{},
		},
		{
			name:        "a nil fetcher is refused",
			nilFetcher:  true,
			wantErrMsg:  "no fetcher was supplied",
			wantFetches: map[string]int{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeFetcher()
			if tc.setup != nil {
				tc.setup(t, dir, f)
			}
			pin := testPin()
			if tc.pin != nil {
				pin = *tc.pin
			}
			cacheDir := dir
			if tc.dir != "" {
				cacheDir = tc.dir
			}
			var fetcher Fetcher = f
			if tc.nilFetcher {
				fetcher = nil
			}

			got, err := EnsureGuestArtifacts(context.Background(), cacheDir, pin, fetcher)

			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("EnsureGuestArtifacts error = %v, want errors.Is %v", err, tc.wantErr)
				}
			case tc.wantErrMsg != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Fatalf("EnsureGuestArtifacts error = %v, want it to mention %q", err, tc.wantErrMsg)
				}
			default:
				if err != nil {
					t.Fatalf("EnsureGuestArtifacts: %v", err)
				}
			}

			for _, name := range []string{ImageFileName, InitramfsFileName} {
				if got, want := f.count(name), tc.wantFetches[name]; got != want {
					t.Errorf("fetched %s %d times, want %d", name, got, want)
				}
			}

			if tc.wantErr != nil || tc.wantErrMsg != "" {
				// Nothing unverified may be left at a final path, and no temp
				// file may survive a failed fetch.
				setDir := filepath.Join(dir, pin.SetDigest())
				if IsValidDigest(pin.ImageSHA256) && exists(filepath.Join(setDir, ImageFileName)) {
					if !bytes.Equal(readFile(t, filepath.Join(setDir, ImageFileName)), testKernelBytes) {
						t.Error("a failed ensure left unverified bytes at the kernel's final path")
					}
				}
				if n := tempFiles(t, dir); len(n) != 0 {
					t.Errorf("a failed ensure left temp files behind: %v", n)
				}
				return
			}

			if !tc.wantInstalled {
				return
			}
			setDir := filepath.Join(dir, pin.SetDigest())
			if want := filepath.Join(setDir, ImageFileName); got.KernelPath != want {
				t.Errorf("KernelPath = %q, want %q", got.KernelPath, want)
			}
			if want := filepath.Join(setDir, InitramfsFileName); got.InitramfsPath != want {
				t.Errorf("InitramfsPath = %q, want %q", got.InitramfsPath, want)
			}
			if got.Cmdline != pin.Cmdline {
				t.Errorf("Cmdline = %q, want %q", got.Cmdline, pin.Cmdline)
			}
			if b := readFile(t, got.KernelPath); !bytes.Equal(b, testKernelBytes) {
				t.Errorf("the installed kernel is %q, want the pinned bytes", b)
			}
			if b := readFile(t, got.InitramfsPath); !bytes.Equal(b, testInitramfsBytes) {
				t.Errorf("the installed initramfs is %q, want the pinned bytes", b)
			}
			if err := verifySetDir(setDir); err != nil {
				t.Errorf("the installed set does not verify against its own name: %v", err)
			}
			if n := tempFiles(t, dir); len(n) != 0 {
				t.Errorf("a successful ensure left temp files behind: %v", n)
			}
		})
	}
}

// TestEnsureGuestArtifactsIsIdempotent pins the property the daemon depends on:
// ensure runs on every start, and the second run must neither fetch nor rewrite.
func TestEnsureGuestArtifactsIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	f := newFakeFetcher()
	first, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if got := f.total(); got != 2 {
		t.Fatalf("first ensure made %d fetches, want 2", got)
	}
	second, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if got := f.total(); got != 2 {
		t.Errorf("second ensure made %d fetches in total, want the first run's 2", got)
	}
	if first != second {
		t.Errorf("second ensure returned %+v, want the first run's %+v", second, first)
	}
}

// TestEnsureGuestArtifactsCleansPartialDownloads covers the crash-safety half:
// a temp file left by a process that died mid-fetch is inert (it is never at a
// final path, so nothing can boot it) and is swept on the next successful run.
func TestEnsureGuestArtifactsCleansPartialDownloads(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, tempPrefix+"crashed")
	if err := os.WriteFile(stale, []byte("half a kernel"), 0o644); err != nil {
		t.Fatalf("stage the stale temp file: %v", err)
	}
	// A stray non-temp, non-set file must survive: this package owns the set
	// dirs and its own temps, not the directory.
	keep := filepath.Join(dir, "README")
	if err := os.WriteFile(keep, []byte("operator note"), 0o644); err != nil {
		t.Fatalf("stage the stray file: %v", err)
	}

	if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), newFakeFetcher()); err != nil {
		t.Fatalf("EnsureGuestArtifacts: %v", err)
	}
	if exists(stale) {
		t.Error("a stale partial download survived a successful ensure")
	}
	if !exists(keep) {
		t.Error("ensure deleted a file it does not own")
	}
}

// TestEnsureGuestArtifactsFetchTimeout asserts the deadline is honoured on both
// halves of a fetch — the request that never answers, and the body that starts
// and never ends.
func TestEnsureGuestArtifactsFetchTimeout(t *testing.T) {
	tests := []struct {
		name  string
		apply func(f *fakeFetcher)
	}{
		{
			name:  "the request never answers",
			apply: func(f *fakeFetcher) { f.block[ImageFileName] = true },
		},
		{
			name:  "the body starts and never ends",
			apply: func(f *fakeFetcher) { f.stall[ImageFileName] = true },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeFetcher()
			tc.apply(f)

			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := EnsureGuestArtifacts(ctx, dir, testPin(), f)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("EnsureGuestArtifacts error = %v, want errors.Is context.DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed > 10*time.Second {
				t.Fatalf("EnsureGuestArtifacts took %s to honour an 80ms deadline", elapsed)
			}
			if n := tempFiles(t, dir); len(n) != 0 {
				t.Errorf("a timed-out ensure left temp files behind: %v", n)
			}
			if s := setDirs(t, dir); len(s) != 0 {
				t.Errorf("a timed-out ensure installed a set: %v", s)
			}
		})
	}
}

// TestEnsureGuestArtifactsRetention pins the N-1 policy: after a successful
// ensure the cache holds the active set and at most one previous one.
func TestEnsureGuestArtifactsRetention(t *testing.T) {
	t.Run("three older sets collapse to the newest one", func(t *testing.T) {
		dir := t.TempDir()
		var old []GuestKernelPin
		base := time.Now().Add(-72 * time.Hour)
		for i := range 3 {
			p := pinFor([]byte(fmt.Sprintf("old kernel %d", i)), []byte(fmt.Sprintf("old initramfs %d", i)))
			set := stageSet(t, dir, p, []byte(fmt.Sprintf("old kernel %d", i)), []byte(fmt.Sprintf("old initramfs %d", i)))
			// Distinct, deterministic mtimes: newest is i == 2.
			when := base.Add(time.Duration(i) * time.Hour)
			if err := os.Chtimes(set, when, when); err != nil {
				t.Fatalf("set the mtime of a staged set: %v", err)
			}
			old = append(old, p)
		}
		// Non-set clutter must survive the prune untouched.
		clutter := filepath.Join(dir, "not-a-set")
		if err := os.MkdirAll(clutter, 0o755); err != nil {
			t.Fatalf("stage the clutter dir: %v", err)
		}

		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), newFakeFetcher()); err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}

		got := setDirs(t, dir)
		want := map[string]bool{testPin().SetDigest(): true, old[2].SetDigest(): true}
		if len(got) != len(want) {
			t.Fatalf("cache holds %d sets (%v), want exactly 2 (active + newest previous)", len(got), got)
		}
		for _, name := range got {
			if !want[name] {
				t.Errorf("cache retained %s, which is neither the active set nor the newest previous one", name)
			}
		}
		if !exists(clutter) {
			t.Error("the prune deleted a directory that is not a set")
		}
	})

	t.Run("a corrupt previous set is discarded and the next newest is kept", func(t *testing.T) {
		dir := t.TempDir()
		base := time.Now().Add(-72 * time.Hour)
		newer := pinFor([]byte("newer kernel"), []byte("newer initramfs"))
		newerSet := stageSet(t, dir, newer, []byte("newer kernel"), []byte("newer initramfs"))
		older := pinFor([]byte("older kernel"), []byte("older initramfs"))
		olderSet := stageSet(t, dir, older, []byte("older kernel"), []byte("older initramfs"))
		if err := os.Chtimes(olderSet, base, base); err != nil {
			t.Fatalf("set the older mtime: %v", err)
		}
		when := base.Add(time.Hour)
		// Corrupt the NEWER one after staging, then restore its mtime so the
		// prune still considers it first.
		if err := os.WriteFile(filepath.Join(newerSet, ImageFileName), []byte("rot"), 0o644); err != nil {
			t.Fatalf("corrupt the newer set: %v", err)
		}
		if err := os.Chtimes(newerSet, when, when); err != nil {
			t.Fatalf("set the newer mtime: %v", err)
		}

		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), newFakeFetcher()); err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if exists(newerSet) {
			t.Error("a corrupt previous set was retained")
		}
		if !exists(olderSet) {
			t.Error("the newest VERIFYING previous set was discarded along with the corrupt one")
		}
		if !exists(filepath.Join(dir, testPin().SetDigest(), ImageFileName)) {
			t.Error("the active set is missing after the prune")
		}
	})

	t.Run("a failed ensure prunes nothing", func(t *testing.T) {
		dir := t.TempDir()
		var staged []string
		for i := range 3 {
			k, ir := []byte(fmt.Sprintf("k%d", i)), []byte(fmt.Sprintf("i%d", i))
			staged = append(staged, stageSet(t, dir, pinFor(k, ir), k, ir))
		}
		f := newFakeFetcher()
		f.errs[ImageFileName] = errors.New("publisher unreachable")

		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f); err == nil {
			t.Fatal("EnsureGuestArtifacts succeeded with an unreachable publisher")
		}
		for _, s := range staged {
			if !exists(s) {
				t.Errorf("a failed ensure deleted the cached set %s", filepath.Base(s))
			}
		}
	})
}

// ============================================================================
// Mutation legs. Each one takes a state that a verification-free implementation
// would happily accept — bytes on disk that are not the bytes that were pinned —
// and asserts ensure notices. They are named Mutation* so hack/acceptance/B108.sh
// can assert every one of them ran, not merely that the package passed.
// ============================================================================

func TestMutations(t *testing.T) {
	t.Run("MutationCachedKernelByteFlipped", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeFetcher()
		set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
		mutated := append([]byte(nil), testKernelBytes...)
		mutated[len(mutated)/2] ^= 0x01
		if err := os.WriteFile(filepath.Join(set, ImageFileName), mutated, 0o644); err != nil {
			t.Fatalf("mutate the cached kernel: %v", err)
		}
		got, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
		if err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if f.count(ImageFileName) != 1 {
			t.Fatalf("a single flipped byte did not trigger a re-fetch (fetches: %d)", f.count(ImageFileName))
		}
		if b := readFile(t, got.KernelPath); !bytes.Equal(b, testKernelBytes) {
			t.Error("the mutated kernel was not replaced by the pinned bytes")
		}
	})

	t.Run("MutationCachedInitramfsByteFlipped", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeFetcher()
		set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
		mutated := append([]byte(nil), testInitramfsBytes...)
		mutated[0] ^= 0x80
		if err := os.WriteFile(filepath.Join(set, InitramfsFileName), mutated, 0o644); err != nil {
			t.Fatalf("mutate the cached initramfs: %v", err)
		}
		got, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
		if err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if f.count(InitramfsFileName) != 1 {
			t.Fatalf("a single flipped byte did not trigger a re-fetch (fetches: %d)", f.count(InitramfsFileName))
		}
		if f.count(ImageFileName) != 0 {
			t.Error("mutating the initramfs also re-fetched the kernel")
		}
		if b := readFile(t, got.InitramfsPath); !bytes.Equal(b, testInitramfsBytes) {
			t.Error("the mutated initramfs was not replaced by the pinned bytes")
		}
	})

	t.Run("MutationCachedKernelAppended", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeFetcher()
		set := stageSet(t, dir, testPin(), testKernelBytes, testInitramfsBytes)
		appended := append(append([]byte(nil), testKernelBytes...), 0x00)
		if err := os.WriteFile(filepath.Join(set, ImageFileName), appended, 0o644); err != nil {
			t.Fatalf("append to the cached kernel: %v", err)
		}
		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f); err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if f.count(ImageFileName) != 1 {
			t.Fatal("a trailing appended byte did not trigger a re-fetch")
		}
	})

	t.Run("MutationServedKernelByteFlipped", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeFetcher()
		served := append([]byte(nil), testKernelBytes...)
		served[1] ^= 0x20
		f.bodies[ImageFileName] = served

		_, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("EnsureGuestArtifacts error = %v, want errors.Is ErrDigestMismatch", err)
		}
		if exists(filepath.Join(dir, testPin().SetDigest(), ImageFileName)) {
			t.Error("bytes that failed verification were installed at the final path")
		}
		if n := tempFiles(t, dir); len(n) != 0 {
			t.Errorf("a rejected download left temp files behind: %v", n)
		}
	})

	t.Run("MutationServedInitramfsTruncated", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeFetcher()
		f.bodies[InitramfsFileName] = testInitramfsBytes[:len(testInitramfsBytes)-1]

		_, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), f)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("EnsureGuestArtifacts error = %v, want errors.Is ErrDigestMismatch", err)
		}
		if exists(filepath.Join(dir, testPin().SetDigest(), InitramfsFileName)) {
			t.Error("a truncated download was installed at the final path")
		}
	})

	t.Run("MutationRetainedSetContentFlipped", func(t *testing.T) {
		dir := t.TempDir()
		prev := pinFor([]byte("previous kernel"), []byte("previous initramfs"))
		prevSet := stageSet(t, dir, prev, []byte("previous kernel"), []byte("previous initramfs"))
		mutated := []byte("previous kernel!")
		if err := os.WriteFile(filepath.Join(prevSet, ImageFileName), mutated, 0o644); err != nil {
			t.Fatalf("mutate the retained set: %v", err)
		}
		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), newFakeFetcher()); err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if exists(prevSet) {
			t.Error("a retained set whose contents no longer hash to its own name was kept")
		}
		if err := verifySetDir(filepath.Join(dir, testPin().SetDigest())); err != nil {
			t.Errorf("the active set was disturbed by the retained set's mutation: %v", err)
		}
	})

	t.Run("MutationRetainedSetRenamedToAnotherDigest", func(t *testing.T) {
		dir := t.TempDir()
		prev := pinFor([]byte("previous kernel"), []byte("previous initramfs"))
		prevSet := stageSet(t, dir, prev, []byte("previous kernel"), []byte("previous initramfs"))
		// Same bytes, a name that lies about them: content addressing must be
		// checked, not assumed from the path.
		liar := filepath.Join(dir, strings.Repeat("c", 64))
		if err := os.Rename(prevSet, liar); err != nil {
			t.Fatalf("rename the retained set: %v", err)
		}
		if _, err := EnsureGuestArtifacts(context.Background(), dir, testPin(), newFakeFetcher()); err != nil {
			t.Fatalf("EnsureGuestArtifacts: %v", err)
		}
		if exists(liar) {
			t.Error("a set directory whose name does not match its contents was retained")
		}
	})
}

// ============================================================================
// HTTPFetcher — the parts provable without a socket.
// ============================================================================

func TestHTTPFetcherTimeout(t *testing.T) {
	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"unset takes the default", 0, DefaultFetchTimeout},
		{"negative takes the default", -time.Second, DefaultFetchTimeout},
		{"a set budget is honoured", 45 * time.Second, 45 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &HTTPFetcher{Timeout: tc.set}
			if got := f.fetchTimeout(); got != tc.want {
				t.Fatalf("fetchTimeout() = %s, want %s", got, tc.want)
			}
		})
	}
	// The one property worth pinning about the default itself: it is a TOTAL
	// budget, and a budget short enough to strand a large artifact on a slow
	// link is a self-inflicted outage.
	if DefaultFetchTimeout < time.Minute {
		t.Errorf("DefaultFetchTimeout is %s, which is too short a total budget for a kernel-sized artifact", DefaultFetchTimeout)
	}
}

// TestHTTPFetcherSatisfiesFetcher is a compile-time assertion in test form: the
// production implementation must remain usable where the seam is.
func TestHTTPFetcherSatisfiesFetcher(t *testing.T) {
	var _ Fetcher = (*HTTPFetcher)(nil)
	var _ Fetcher = (*fakeFetcher)(nil)
}

// ============================================================================
// HTTPFetcher hardening: the https-only rule and the body cap. Both are
// provable without a socket — the scheme is refused before one is opened, and
// the cap lives in a body wrapper that reads from memory just as well as from a
// response.
// ============================================================================

func TestHTTPFetcherRejectsNonHTTPSURL(t *testing.T) {
	// Each of these must be refused before any connection is attempted, which is
	// also why this test needs no network: reaching the transport at all would
	// be the bug.
	refused := []struct{ name, url string }{
		{"plaintext is refused, never downgraded to", "http://example.invalid/guest/Image"},
		{"a local file url is refused", "file:///var/tmp/Image"},
		{"an ftp url is refused", "ftp://example.invalid/Image"},
		{"a bare path names no scheme and is refused", "/var/tmp/Image"},
		{"an empty url is refused", ""},
	}
	f := &HTTPFetcher{}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := f.Fetch(context.Background(), tc.url)
			if err == nil {
				_ = rc.Close()
				t.Fatalf("Fetch(%q) succeeded, want a refusal", tc.url)
			}
			if !errors.Is(err, ErrInsecureArtifactURL) {
				t.Fatalf("Fetch(%q) error = %v, want errors.Is ErrInsecureArtifactURL", tc.url, err)
			}
		})
	}

	t.Run("an https url with a host is allowed", func(t *testing.T) {
		// The positive case is asserted on the check rather than on Fetch: a
		// Fetch that got past the check would open a socket, which is the one
		// thing no test in this package does.
		if err := checkArtifactURL(testReleaseURL + "/" + ImageFileName); err != nil {
			t.Fatalf("checkArtifactURL rejected an https url: %v", err)
		}
	})

	t.Run("an https url with no host is refused", func(t *testing.T) {
		if err := checkArtifactURL("https:///Image"); !errors.Is(err, ErrInsecureArtifactURL) {
			t.Fatalf("checkArtifactURL error = %v, want errors.Is ErrInsecureArtifactURL", err)
		}
	})
}

// capFetcher serves bytes through the same cappedBody wrapper HTTPFetcher.Fetch
// applies, so an end-to-end ensure exercises the production cap rather than a
// test-only imitation of it.
type capFetcher struct {
	body []byte
	max  int64
}

func (c capFetcher) Fetch(_ context.Context, _ string) (io.ReadCloser, error) {
	return newCappedBody(io.NopCloser(bytes.NewReader(c.body)), c.max), nil
}

func TestHTTPFetcherBodyCap(t *testing.T) {
	t.Run("the shipped cap is MaxArtifactBytes", func(t *testing.T) {
		if maxArtifactBytes != int64(MaxArtifactBytes) {
			t.Fatalf("maxArtifactBytes = %d, want MaxArtifactBytes (%d)", maxArtifactBytes, int64(MaxArtifactBytes))
		}
		if MaxArtifactBytes != 512<<20 {
			t.Fatalf("MaxArtifactBytes = %d, want 512 MiB", int64(MaxArtifactBytes))
		}
	})

	t.Run("a body under the cap reads whole", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 7)
		got, err := io.ReadAll(newCappedBody(io.NopCloser(bytes.NewReader(body)), 16))
		if err != nil {
			t.Fatalf("read a body under the cap: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("read %d bytes, want %d", len(got), len(body))
		}
	})

	t.Run("a body exactly at the cap reads whole", func(t *testing.T) {
		// The boundary the cap+1 limit exists to get right: at the cap is a
		// legal artifact, one byte past it is not.
		body := bytes.Repeat([]byte("b"), 16)
		got, err := io.ReadAll(newCappedBody(io.NopCloser(bytes.NewReader(body)), 16))
		if err != nil {
			t.Fatalf("read a body exactly at the cap: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("read %d bytes, want %d", len(got), len(body))
		}
	})

	t.Run("a body one byte over the cap is an error", func(t *testing.T) {
		body := bytes.Repeat([]byte("c"), 17)
		got, err := io.ReadAll(newCappedBody(io.NopCloser(bytes.NewReader(body)), 16))
		if !errors.Is(err, ErrArtifactTooLarge) {
			t.Fatalf("error = %v, want errors.Is ErrArtifactTooLarge", err)
		}
		if int64(len(got)) > 16 {
			t.Fatalf("the reader handed back %d bytes, more than the %d-byte cap", len(got), 16)
		}
	})

	t.Run("an over-cap body installs nothing", func(t *testing.T) {
		dir := t.TempDir()
		_, err := EnsureGuestArtifacts(context.Background(), dir,
			testPin(), capFetcher{body: bytes.Repeat([]byte("d"), 4096), max: 8})
		if !errors.Is(err, ErrArtifactTooLarge) {
			t.Fatalf("EnsureGuestArtifacts error = %v, want errors.Is ErrArtifactTooLarge", err)
		}
		if s := setDirs(t, dir); len(s) != 0 {
			t.Errorf("an over-cap fetch installed a set: %v", s)
		}
		if n := tempFiles(t, dir); len(n) != 0 {
			t.Errorf("an over-cap fetch left temp files behind: %v", n)
		}
	})
}
