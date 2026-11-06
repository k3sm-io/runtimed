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
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/image"
)

// reservations is the in-process space ledger shared by concurrent pulls. mu
// guards held and is held across a reservation's whole check, including its one
// reclaim pass, so two pulls can never both pass a check that only one fits.
type reservations struct {
	mu   sync.Mutex
	held uint64
}

// reservation is one pull's claim on the ledger. release is idempotent.
type reservation struct {
	r    *reservations
	n    uint64
	once sync.Once
}

func (r *reservation) release() {
	r.once.Do(func() {
		r.r.mu.Lock()
		r.r.held -= r.n
		r.r.mu.Unlock()
	})
}

// Reserved returns the bytes currently reserved by in-flight pulls.
func (p *Puller) Reserved() uint64 {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	return p.resv.held
}

// partialPath is where the partial of digest lives. digest has already passed
// the sha256 pattern, so the name is a fixed, path-safe token.
func (p *Puller) partialPath(digest string) string {
	return filepath.Join(p.cfg.PartialDir, strings.Replace(digest, ":", "-", 1)+".partial")
}

// ensurePartialDir creates the partial dir (0700) when absent and refuses one
// that is not a directory (a file, a symlink planted in its place) or is
// writable by group or other, as the image index refuses its artifact
// namespace: a partial dir another principal can write lets it choose the
// bytes a resume continues from.
func (p *Puller) ensurePartialDir() error {
	dir := p.cfg.PartialDir
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create partial dir: %w", err)
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("stat partial dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (mode %v)", ErrPartialDir, dir, fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or other (mode %v)", ErrPartialDir, dir, fi.Mode().Perm())
	}
	return nil
}

// partialBytes is how much of b is already in its partial file (never more
// than b.size: an overlong partial is restarted, so it counts as nothing).
func (p *Puller) partialBytes(b blob) int64 {
	fi, err := os.Lstat(p.partialPath(b.digest))
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > b.size {
		return 0
	}
	return fi.Size()
}

// spaceNeeded is what a pull of missing may still add to the volume: the rest
// of every download, plus the commit-time copy of the largest blobs that can be
// committing at once (CommitBlob writes its own temp from the partial).
//
// The sizes are capped by checkManifest, so this cannot wrap for a manifest
// that passed it; the arithmetic is checked anyway, because a wrapped sum is a
// zero reservation that bypasses the floor.
func (p *Puller) spaceNeeded(missing []blob) (uint64, error) {
	var need uint64
	add := func(n int64) error {
		if n < 0 {
			return fmt.Errorf("negative size %d: %w", n, ErrSizeOverflow)
		}
		sum, carry := bits.Add64(need, uint64(n), 0)
		if carry != 0 {
			return ErrSizeOverflow
		}
		need = sum
		return nil
	}
	sizes := make([]int64, 0, len(missing))
	for _, b := range missing {
		if err := add(b.size - p.partialBytes(b)); err != nil {
			return 0, err
		}
		sizes = append(sizes, b.size)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] > sizes[j] })
	for i := 0; i < len(sizes) && i < p.cfg.MaxConcurrentLayers; i++ {
		if err := add(sizes[i]); err != nil {
			return 0, err
		}
	}
	return need, nil
}

// addChecked is a+b, refusing a wrap.
func addChecked(a, b uint64) (uint64, error) {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, ErrSizeOverflow
	}
	return sum, nil
}

// reserve claims space for missing before the first byte, running one reclaim
// pass when short, and refuses with ErrInsufficientSpace when still short.
func (p *Puller) reserve(ctx context.Context, missing []blob) (*reservation, error) {
	need, err := p.spaceNeeded(missing)
	if err != nil {
		return nil, err
	}
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	claimed, err := addChecked(p.resv.held, need)
	if err != nil {
		return nil, err
	}
	want, err := addChecked(p.cfg.FloorBytes, claimed)
	if err != nil {
		return nil, err
	}
	fits := func() (uint64, bool, error) {
		free, err := p.cfg.FreeBytes(p.cfg.StorePath)
		if err != nil {
			return 0, false, fmt.Errorf("%w: %w", image.ErrFreeSpaceUnknown, bound(err))
		}
		return free, free >= want, nil
	}
	_, ok, err := fits()
	if err != nil {
		return nil, err
	}
	if !ok {
		if _, rerr := p.deps.Reclaimer.ReclaimUnderPressure(ctx, image.ReclaimConfig{
			HighFreeBytes: want, TargetFreeBytes: want, FreeBytes: p.cfg.FreeBytes, Log: p.log,
		}); rerr != nil {
			p.log.Warn("artifact pull: reclaim pass failed", "err", rerr)
		}
		free, ok, err := fits()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("need %d bytes, %d free, %d reserved by other pulls, floor %d: %w",
				need, free, p.resv.held, p.cfg.FloorBytes, ErrInsufficientSpace)
		}
	}
	p.resv.held = claimed
	return &reservation{r: &p.resv, n: need}, nil
}

// fetchAll transfers and commits every blob in missing, at most
// MaxConcurrentLayers at a time across the whole process. The first failure
// cancels the rest; partials of the cancelled transfers survive for a retry.
func (p *Puller) fetchAll(ctx context.Context, ref string, cred *image.RegistryCredential, missing []blob, _ *reservation) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg    sync.WaitGroup
		errMu sync.Mutex
		first error
	)
	for _, b := range missing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.fetchOne(ctx, ref, cred, b); err != nil {
				errMu.Lock()
				if first == nil {
					first = err
					cancel()
				}
				errMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}

// claim makes this goroutine the only writer of digest's partial, waiting for
// another pull's transfer of the same digest to end first. The returned func
// ends the claim.
func (p *Puller) claim(ctx context.Context, digest string) (func(), error) {
	for {
		p.inflightMu.Lock()
		ch, busy := p.inflight[digest]
		if !busy {
			done := make(chan struct{})
			p.inflight[digest] = done
			p.inflightMu.Unlock()
			return func() {
				p.inflightMu.Lock()
				delete(p.inflight, digest)
				p.inflightMu.Unlock()
				close(done)
			}, nil
		}
		p.inflightMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// fetchOne brings one blob into the cache: resume its partial with a Range
// request, then commit it through CommitBlob, which re-hashes it.
func (p *Puller) fetchOne(ctx context.Context, ref string, cred *image.RegistryCredential, b blob) error {
	end, err := p.claim(ctx, b.digest)
	if err != nil {
		return err
	}
	defer end()
	if p.deps.Blobs.Has(b.digest) {
		return nil // another pull committed it while this one waited
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.sem }()

	if err := p.ensurePartialDir(); err != nil {
		return err
	}
	path := p.partialPath(b.digest)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open partial %s: %w", b.digest, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat partial %s: %w", b.digest, err)
	}
	have := fi.Size()
	if have > b.size {
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("reset partial %s: %w", b.digest, err)
		}
		have = 0
	}
	if have < b.size {
		if err := p.transfer(ctx, ref, cred, b, f, have); err != nil {
			return err
		}
	}
	_, err = p.deps.Blobs.CommitBlob(b.digest, b.size, func(w io.Writer) error {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		_, err := io.Copy(w, struct{ io.Reader }{f})
		return err
	})
	if err != nil {
		if errors.Is(err, image.ErrDigestMismatch) || errors.Is(err, image.ErrBlobTooLarge) {
			// A poisoned partial must not survive to be resumed.
			_ = os.Remove(path) // the commit error is the one reported
		}
		return fmt.Errorf("commit %s: %w", b.digest, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.log.Warn("artifact pull: remove committed partial", "digest", b.digest, "err", err)
	}
	return nil
}

// transfer appends the rest of b to f from offset have. A failure leaves what
// arrived in f, synced, for the next attempt to resume.
//
// A watchdog cancels the transfer when no byte arrives for the stall timeout,
// from the request through the last read of the body; every byte re-arms it.
// There is no overall deadline: a transfer that keeps moving is never cut off.
func (p *Puller) transfer(ctx context.Context, ref string, cred *image.RegistryCredential, b blob, f *os.File, have int64) error {
	tctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := p.cfg.StallTimeout
	timer := p.cfg.afterFunc(stall, func() { cancel(ErrBlobStalled) })
	defer timer.Stop()
	stalled := func(at int64, err error) error {
		if ctx.Err() == nil && errors.Is(context.Cause(tctx), ErrBlobStalled) {
			return fmt.Errorf("fetch %s at %d: no byte for %v: %w: %w", b.digest, at, stall, ErrBlobTransfer, ErrBlobStalled)
		}
		return err
	}
	body, start, err := p.deps.Fetcher.Blob(tctx, ref, cred, b.digest, have)
	if err != nil {
		return stalled(have, fmt.Errorf("fetch %s from %d: %w: %w", b.digest, have, ErrBlobTransfer, bound(err)))
	}
	defer body.Close()
	switch {
	case start == have:
	case start == 0:
		// The server ignored the Range and sent the whole blob.
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("reset partial %s: %w", b.digest, err)
		}
		have = 0
	default:
		return fmt.Errorf("fetch %s: asked for offset %d, got %d: %w", b.digest, have, start, ErrBlobTransfer)
	}
	if _, err := f.Seek(have, io.SeekStart); err != nil {
		return fmt.Errorf("seek partial %s: %w", b.digest, err)
	}
	progress := &progressReader{r: body, moved: func() { timer.Reset(stall) }}
	n, cerr := io.Copy(struct{ io.Writer }{f}, io.LimitReader(progress, b.size-have+1))
	serr := f.Sync()
	if have+n > b.size {
		_ = f.Truncate(0) // an overrun is the server's fault; restart clean
		return fmt.Errorf("fetch %s: more than %d bytes: %w", b.digest, b.size, image.ErrBlobTooLarge)
	}
	if cerr != nil {
		return stalled(have+n, fmt.Errorf("fetch %s at %d: %w: %w", b.digest, have+n, ErrBlobTransfer, bound(cerr)))
	}
	if serr != nil {
		return fmt.Errorf("sync partial %s: %w", b.digest, serr)
	}
	if have+n < b.size {
		return fmt.Errorf("fetch %s: body ended at %d of %d: %w", b.digest, have+n, b.size, ErrBlobTransfer)
	}
	return nil
}

// progressReader calls moved after every read that returned bytes.
type progressReader struct {
	r     io.Reader
	moved func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.moved()
	}
	return n, err
}
