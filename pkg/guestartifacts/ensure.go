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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
)

// DefaultFetchTimeout bounds ONE artifact fetch end to end — connect, headers
// and body. It is a total budget rather than a per-read idle timeout because the
// failure this guards against is a node whose vm capability never resolves: a
// stalled fetch that trickles a byte a minute defeats an idle timeout forever
// while defeating the operator just as thoroughly.
const DefaultFetchTimeout = 2 * time.Minute

// tempPrefix marks a partially-fetched artifact. It is dot-prefixed and
// distinguishable from a 64-hex set directory, so a crash mid-fetch leaves
// something the retention pass can recognise as garbage rather than as a cached
// set.
const tempPrefix = ".ensure-"

// Fetcher retrieves an artifact by url.
//
// It is declared HERE, at the consumer, and holds one method, because that is
// the entire dependency ensure has on the network: everything else — digest
// verification, atomic install, retention — is this package's own and must stay
// testable with no socket in the process. A production implementation is
// HTTPFetcher below.
//
// The returned reader is the caller's to close.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (io.ReadCloser, error)
}

// HTTPFetcher is the production Fetcher: a plain HTTPS GET under a total
// timeout.
//
// It carries no retry and no resume, deliberately. A guest artifact fetch that
// failed is not an outage a daemon should paper over — the caller's contract
// (see EnsureGuestArtifacts) is to degrade the node's vm capability and try
// again on the next ensure, which is a retry with a sane period and an operator
// visible state, rather than a hidden loop inside a fetch.
type HTTPFetcher struct {
	// Client is the http client used. Nil means http.DefaultClient.
	Client *http.Client
	// Timeout is the total budget for one fetch, covering the body read. Zero
	// or negative means DefaultFetchTimeout.
	Timeout time.Duration
}

// fetchTimeout resolves the effective total budget for one fetch.
func (f *HTTPFetcher) fetchTimeout() time.Duration {
	if f.Timeout <= 0 {
		return DefaultFetchTimeout
	}
	return f.Timeout
}

// Fetch performs the GET and returns the response body.
//
// The timeout is applied by deriving a context, NOT by http.Client.Timeout, so
// that it also bounds the body read the caller has not started yet: the derived
// context's cancel rides on the returned reader and fires when the caller closes
// it. A non-2xx response is an error with the body closed, never a reader over
// an error page that would then fail digest verification with a misleading
// "digest mismatch".
func (f *HTTPFetcher) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, f.fetchTimeout())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build the request for %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, nil
}

// cancelOnClose releases a fetch's derived context when its body is closed, so
// the timeout does not outlive the transfer it bounds.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// EnsureGuestArtifacts materialises the pinned guest kernel and initramfs into
// the node-local cache rooted at dir, and returns the paths a vm pod boots from.
//
// # The caller's contract on error
//
// AN ERROR FROM THIS FUNCTION MEANS "THE VM CAPABILITY IS OFF ON THIS NODE",
// NEVER "THE DAEMON IS BROKEN". A node with no network, an unminted pin, or a
// publisher outage must still run every native pod it has; the only thing it may
// not do is boot a guest. Callers therefore degrade — leave the vm backend's
// artifact locator unset, so CreateVM fails each vm pod closed with
// sandbox.ErrGuestArtifactsUnavailable — and must not abort daemon start.
//
// # What it guarantees
//
// The returned paths exist and their bytes hash to the pin, verified on THIS
// call. Verification is unconditional and repeated on every start, not cached in
// a marker file: a marker records what was true when it was written, and the
// event worth catching is bit rot or tampering after that moment. The cost is
// two sha256 passes over roughly a hundred megabytes, once per daemon start.
//
// A file that fails verification is removed and re-fetched. A fetch that fails
// returns the error having touched nothing but its own temp file — no cached
// set, active or retained, is disturbed by a failed fetch, so a node offline
// today still boots the set it verified yesterday if that set is still pinned.
//
// # Concurrency
//
// One dir has one writer. Two concurrent calls over the same dir may each remove
// the other's temp file; the daemon calls this once, at start.
func EnsureGuestArtifacts(ctx context.Context, dir string, pin GuestKernelPin, f Fetcher) (sandbox.GuestArtifacts, error) {
	var zero sandbox.GuestArtifacts
	if !filepath.IsAbs(dir) {
		return zero, fmt.Errorf("ensure the guest artifacts: the cache dir %q is not an absolute path", dir)
	}
	if f == nil {
		return zero, errors.New("ensure the guest artifacts: no fetcher was supplied")
	}
	if err := validatePin(pin.KernelVersion, pin); err != nil {
		return zero, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return zero, fmt.Errorf("create the guest artifact cache %s: %w", dir, err)
	}

	set := pin.SetDigest()
	setDir := filepath.Join(dir, set)
	want := []struct{ name, digest string }{
		{ImageFileName, pin.ImageSHA256},
		{InitramfsFileName, pin.InitramfsSHA256},
	}
	for _, a := range want {
		if err := ensureArtifact(ctx, dir, setDir, a.name, a.digest, pin.ReleaseURL, f); err != nil {
			return zero, err
		}
	}

	// Housekeeping runs only after both artifacts are verified present, so a
	// failed ensure is provably side-effect-free on every other entry.
	sweepTemps(ctx, dir)
	pruneSets(ctx, dir, set)

	return sandbox.GuestArtifacts{
		KernelPath:    filepath.Join(setDir, ImageFileName),
		InitramfsPath: filepath.Join(setDir, InitramfsFileName),
		Cmdline:       pin.Cmdline,
	}, nil
}

// ensureArtifact makes setDir/name exist with the given digest, fetching it if
// it is absent or does not verify.
//
// The removal on mismatch is scoped to the OFFENDING FILE, not to the set
// directory: its sibling has its own digest and its own verification, and
// deleting a good hundred-megabyte artifact because its partner rotted would
// turn one re-fetch into two on a node whose bandwidth is the reason the cache
// exists.
func ensureArtifact(ctx context.Context, dir, setDir, name, digest, releaseURL string, f Fetcher) error {
	final := filepath.Join(setDir, name)
	switch got, err := digestFile(final); {
	case err == nil && got == digest:
		return nil
	case err == nil:
		slog.WarnContext(ctx, "cached guest artifact failed verification; re-fetching",
			"path", final, "want", digest, "got", got)
		if err := os.Remove(final); err != nil {
			return fmt.Errorf("remove the corrupt guest artifact %s: %w", final, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// Absent is the ordinary first-boot case, not a fault.
	default:
		slog.WarnContext(ctx, "cached guest artifact could not be read; re-fetching", "path", final, "err", err)
		if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the unreadable guest artifact %s: %w", final, err)
		}
	}

	url := strings.TrimSuffix(releaseURL, "/") + "/" + name
	if err := fetchVerified(ctx, dir, final, url, digest, f); err != nil {
		return err
	}
	return nil
}

// fetchVerified downloads url into a temp file in dir, verifies the WHOLE body
// against digest, and only then renames it to final.
//
// The order is the point. A file at the final path is a file some other process
// may boot, so nothing unverified may ever appear there — not briefly, not
// during a crash. Verifying after the rename would leave exactly that window,
// and a crash inside it leaves a permanently-poisoned cache entry that the next
// start would find, verify, and correctly reject — one re-fetch later than
// necessary and one boot of the wrong kernel earlier than acceptable.
func fetchVerified(ctx context.Context, dir, final, url, digest string, f Fetcher) error {
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create a temp file for %s: %w", url, err)
	}
	tmpName := tmp.Name()
	// The temp file is removed on every path that does not rename it away;
	// after a successful rename the Remove is a no-op miss, which is why the
	// error is dropped.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	body, err := f.Fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch the guest artifact %s: %w", url, err)
	}
	defer func() { _ = body.Close() }()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), &ctxReader{ctx: ctx, r: body}); err != nil {
		return fmt.Errorf("download the guest artifact %s: %w", url, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("the guest artifact at %s hashes to %s, want %s: %w", url, got, digest, ErrDigestMismatch)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush the guest artifact downloaded from %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close the guest artifact downloaded from %s: %w", url, err)
	}
	// 0644: the cache is world-readable by design — it holds published release
	// bytes whose integrity comes from the digest, never from its permissions.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("set the mode of the guest artifact downloaded from %s: %w", url, err)
	}
	// The set directory is created HERE, immediately before the rename, and not
	// before the fetch: a fetch that fails must leave no trace, and an empty
	// 64-hex directory is a trace with a meaning — the retention pass reads it
	// as a cached set, and verifySetDir would then have to distinguish "corrupt"
	// from "never populated".
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return fmt.Errorf("create the guest artifact set dir %s: %w", filepath.Dir(final), err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("install the guest artifact at %s: %w", final, err)
	}
	syncDir(filepath.Dir(final))
	syncDir(dir)
	return nil
}

// ctxReader aborts a copy when the context is done.
//
// io.Copy has no context, and the reader it is handed here comes from a Fetcher
// the caller supplied, which may be anything. Checking between reads is what
// makes the deadline in EnsureGuestArtifacts' contract true for EVERY fetcher
// rather than only for the http one whose request carries the context.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	if err == nil {
		if cerr := c.ctx.Err(); cerr != nil {
			return n, cerr
		}
	}
	return n, err
}

// digestFile returns the hex sha256 of the file at path.
func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifySetDir reports whether a cached set directory is internally consistent:
// re-hashing the two artifacts it holds must reproduce the set digest its own
// name is.
//
// This is the check that makes a RETAINED set verifiable at all. Ensure holds a
// pin for the ACTIVE set only — a previous set's per-artifact digests are not in
// this build's source and cannot be — so the only statement left about it is the
// one its directory name makes about itself, and SetDigest is constructed so
// that statement is checkable.
func verifySetDir(setDir string) error {
	name := filepath.Base(setDir)
	img, err := digestFile(filepath.Join(setDir, ImageFileName))
	if err != nil {
		return err
	}
	initrd, err := digestFile(filepath.Join(setDir, InitramfsFileName))
	if err != nil {
		return err
	}
	if got := (GuestKernelPin{ImageSHA256: img, InitramfsSHA256: initrd}).SetDigest(); got != name {
		return fmt.Errorf("the cached set %s re-hashes to %s: %w", name, got, ErrDigestMismatch)
	}
	return nil
}

// sweepTemps removes partially-fetched artifacts left by an earlier crash.
//
// It runs on the SUCCESS path only, for the same reason retention does: a failed
// ensure must be provably side-effect-free outside its own temp file, and a
// sweep that ran first would be a write on the way to a failure.
func sweepTemps(ctx context.Context, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.WarnContext(ctx, "could not sweep partial guest artifact downloads", "dir", dir, "err", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			slog.WarnContext(ctx, "could not remove a partial guest artifact download", "path", filepath.Join(dir, e.Name()), "err", err)
		}
	}
}

// pruneSets enforces the retention policy: the active set, plus at most one
// previous set, and nothing else.
//
// ONE PREVIOUS IS KEPT because a digest bump ships in a binary, so rolling that
// binary back must not also mean re-downloading the kernel it boots — the
// rollback would then depend on the network being up at exactly the moment
// something is already wrong. TWO would be a cache policy; one is a rollback.
//
// The retained candidate is the NEWEST other set that verifies. A candidate that
// does not verify is deleted silently rather than reported: it is a convenience,
// not a promise, and a node that fails its start because a set it is not booting
// has rotted has traded a small loss for a large one.
//
// Prune failures never fail the ensure. Both artifacts are already verified in
// place by the time this runs; a directory that could not be deleted is disk
// spent, not a boot at risk.
func pruneSets(ctx context.Context, dir, active string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.WarnContext(ctx, "could not apply guest artifact retention", "dir", dir, "err", err)
		return
	}
	type candidate struct {
		name string
		mod  time.Time
	}
	var others []candidate
	for _, e := range entries {
		// Only 64-hex directories are sets. Anything else in the cache root —
		// a temp file, an operator's note — is not this function's to delete.
		if !e.IsDir() || e.Name() == active || !IsValidDigest(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			slog.WarnContext(ctx, "could not stat a cached guest artifact set", "name", e.Name(), "err", err)
			continue
		}
		others = append(others, candidate{name: e.Name(), mod: info.ModTime()})
	}
	sort.Slice(others, func(i, j int) bool {
		if others[i].mod.Equal(others[j].mod) {
			return others[i].name > others[j].name
		}
		return others[i].mod.After(others[j].mod)
	})

	kept := false
	for _, c := range others {
		path := filepath.Join(dir, c.name)
		if !kept {
			if err := verifySetDir(path); err == nil {
				kept = true
				continue
			}
			slog.WarnContext(ctx, "discarding a corrupt retained guest artifact set", "name", c.name)
		}
		if err := os.RemoveAll(path); err != nil {
			slog.WarnContext(ctx, "could not remove a superseded guest artifact set", "path", path, "err", err)
		}
	}
	syncDir(dir)
}

// syncDir fsyncs a directory so a rename or unlink within it survives a power
// loss. A failure is narrated and swallowed: the caller has already verified the
// bytes it returns, and durability of the DIRECTORY ENTRY is a property the next
// start re-establishes by re-fetching.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		slog.Warn("could not open the guest artifact cache dir to flush it", "dir", dir, "err", err)
		return
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		slog.Warn("could not flush the guest artifact cache dir", "dir", dir, "err", err)
	}
}
