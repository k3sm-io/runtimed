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
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/image"
)

// Reserved returns the bytes currently reserved by in-flight pulls on the
// puller's ledger, the image pull's included when the daemon shares one.
func (p *Puller) Reserved() uint64 {
	return p.ledger.Reserved()
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
// committing at once (CommitBlob writes its own temp from the partial). Bytes
// already in a partial are already off free space and are not counted twice.
//
// The sizes are capped by checkManifest, so this cannot wrap for a manifest
// that passed it; image.SpaceNeeded checks the arithmetic anyway, because a
// wrapped sum is a zero reservation that bypasses the floor.
func (p *Puller) spaceNeeded(missing []blob) (uint64, error) {
	blobs := make([]image.BlobSpace, 0, len(missing))
	for _, b := range missing {
		blobs = append(blobs, image.BlobSpace{Size: b.size, Have: p.partialBytes(b)})
	}
	return image.SpaceNeeded(blobs, p.cfg.MaxConcurrentLayers)
}

// reserve claims space for missing on the shared ledger before the first byte,
// running one reclaim pass when short, and refuses with ErrInsufficientSpace
// when still short (image.SpaceLedger.Reserve).
func (p *Puller) reserve(ctx context.Context, missing []blob) (*image.Reservation, error) {
	need, err := p.spaceNeeded(missing)
	if err != nil {
		return nil, err
	}
	return p.ledger.Reserve(ctx, image.SpaceClaim{
		Need:       need,
		Path:       p.cfg.StorePath,
		FloorBytes: p.cfg.FloorBytes,
		FreeBytes:  p.cfg.FreeBytes,
		TotalBytes: p.cfg.TotalBytes,
		Reclaimer:  p.deps.Reclaimer,
		Log:        p.log,
	})
}

// fetchAll transfers and commits every blob in missing, at most
// MaxConcurrentLayers at a time across the whole process. The first failure
// cancels the rest; partials of the cancelled transfers survive for a retry.
//
// renew is called on every read that returns bytes, from every transfer; it
// keeps the pull's lease alive while its bytes arrive. Nil means no lease.
func (p *Puller) fetchAll(ctx context.Context, ref string, cred *image.RegistryCredential, missing []blob, _ *image.Reservation, renew func()) error {
	if renew == nil {
		renew = func() {}
	}
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
			if err := p.fetchOne(ctx, ref, cred, b, renew); err != nil {
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
// request, then commit it through CommitBlob, which re-hashes it. renew is
// passed to transfer.
func (p *Puller) fetchOne(ctx context.Context, ref string, cred *image.RegistryCredential, b blob, renew func()) error {
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
		if err := p.transfer(ctx, ref, cred, b, f, have, renew); err != nil {
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
// Every byte also calls renew (non-nil), so the pull's lease outlives a slow
// transfer for as long as it keeps moving; a stalled one renews nothing.
func (p *Puller) transfer(ctx context.Context, ref string, cred *image.RegistryCredential, b blob, f *os.File, have int64, renew func()) error {
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
	progress := &progressReader{r: body, moved: func() {
		timer.Reset(stall)
		renew()
	}}
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
