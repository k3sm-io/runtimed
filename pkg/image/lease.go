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
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultLeaseTTL bounds how long an unreleased lease can pin blobs against
// reclaim.
//
// A lease is an IN-PROCESS root, not a durable one: a single-writer daemon that
// dies mid-pull aborts the pull anyway, so there is nothing to reclaim across a
// restart and no crash-reclaim rule to get wrong. The TTL exists for the other
// failure: a caller that takes a lease and never releases it would pin its
// subtree forever, and the component that would notice is the GC the stale lease
// has just disabled. Expiry makes that failure self-healing and time-bounded
// instead of permanent.
const DefaultLeaseTTL = 15 * time.Minute

// Lease pins a set of blob digests against reclaim while an ingest is in flight.
//
// It closes the window the content-addressed store cannot close on its own: a
// blob is committed (or found already present) before the reference that makes
// it reachable is recorded, so between those two moments the blob is on disk and
// named by nothing. A concurrent prune would compute it unreachable and delete
// the layer of the pull that is still running. The lease is therefore acquired
// over the whole manifest digest set before the presence check — not before the
// first write — because a cache HIT writes nothing at all, and the hit path is
// exactly where the blob is old enough for a grace window to have expired.
//
// A Lease is safe for concurrent use and Release is idempotent; the zero value
// and a nil *Lease both Release as no-ops so a caller that never took one, or
// took one from a failed pull, needs no branch.
//
// A pull keeps its lease alive while bytes arrive (Renew, Reader): the TTL
// bounds how long a lease outlives the last read that returned bytes, not how
// long a slow pull may take. Renewal is driven by the reads themselves, so
// nothing runs on the lease's behalf once the pull stops reading: a pull that
// ends, by success, failure or cancellation, stops renewing in the same
// instant, and an unreleased lease lapses one TTL after its last renewal.
//
// Two limits follow from renewing on reads. Work that reads nothing through a
// Reader does not renew: the clone and re-hash of a local or partial copy
// (CommitFromLocal) and the replay of a partial into CommitBlob. And nothing
// caps the total: a body that keeps delivering bytes, however slowly, keeps
// its lease. The layer stall watchdog (newLayerBody) ends a body that goes
// silent for its window, which is shorter than DefaultLeaseTTL, so a silent
// pull fails before its lease lapses; it does not bound a slow drip.
type Lease struct {
	c       *Cache
	id      uint64
	digests []string
	// ttl is the TTL the lease was acquired with; immutable after
	// AcquireLease. Renew extends expires by it.
	ttl time.Duration

	// expires and lastRenew are guarded by c.leaseMu.
	expires time.Time
	// lastRenew is when expires was last set (at AcquireLease, then by each
	// effective Renew); Renew is throttled against it.
	lastRenew time.Time

	// acquired is the instant AcquireLease created the lease (the same now as
	// the first expires); immutable after AcquireLease. It anchors
	// lastRenewOffset so the fast path measures elapsed time with now.Sub,
	// which uses the monotonic reading when present.
	acquired time.Time
	// lastRenewOffset mirrors lastRenew as lastRenew.Sub(acquired) in
	// nanoseconds (zero at AcquireLease). It is written only under c.leaseMu
	// (with lastRenew) and read without it by Renew's fast path, which uses it
	// purely as an early exit: the locked check stays the authority on whether
	// a renewal happens. An offset rather than wall-clock unix nanoseconds
	// keeps the early exit on the same monotonic clock as the locked check and
	// the expiry, so a wall-clock step backwards cannot suppress renewals.
	lastRenewOffset atomic.Int64

	once sync.Once
}

// Renew extends the lease to now plus its TTL. It is nil-safe and throttled:
// a call less than a quarter of the TTL after the last renewal changes nothing
// and returns before taking c.leaseMu (an atomic read of lastRenewOffset), so a
// per-read caller neither takes the lock per read nor contends with a reclaim
// pass. Only a call past the throttle window takes the lock, sweeps expired
// leases and re-checks the throttle there.
//
// A lease that has already lapsed, or was released, is never revived: Renew
// is a no-op unless this very lease is still in the cache's lease table and
// its expiry has not passed. A lapsed lease may already have let a reclaim
// pass take its blobs, so reviving it would claim a protection it no longer
// gives.
func (l *Lease) Renew() {
	if l == nil || l.c == nil {
		return
	}
	c := l.c
	// Fast path: inside the throttle window the locked check below would
	// return without effect, so skip the lock. A stale read can only send the
	// call on to the locked path, never past it.
	if c.now().Sub(l.acquired)-time.Duration(l.lastRenewOffset.Load()) < l.ttl/4 {
		return
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	c.expireLeasesLocked()
	if cur, ok := c.leases[l.id]; !ok || cur != l {
		return
	}
	now := c.now()
	if now.Sub(l.lastRenew) < l.ttl/4 {
		return
	}
	if exp := now.Add(l.ttl); exp.After(l.expires) {
		l.expires = exp
	}
	l.lastRenew = now
	l.lastRenewOffset.Store(int64(now.Sub(l.acquired)))
}

// Reader wraps r so every read that returns bytes renews the lease. A
// zero-byte read renews nothing. It is nil-safe: a nil lease's reader reads r
// unchanged.
func (l *Lease) Reader(r io.Reader) io.Reader {
	return &renewingReader{l: l, r: r}
}

// renewingReader is Lease.Reader's wrapper.
type renewingReader struct {
	l *Lease
	r io.Reader
}

func (rr *renewingReader) Read(b []byte) (int, error) {
	n, err := rr.r.Read(b)
	if n > 0 {
		rr.l.Renew()
	}
	return n, err
}

// Digests returns the digests this lease pins (a copy).
func (l *Lease) Digests() []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l.digests))
	copy(out, l.digests)
	return out
}

// Release drops the lease. It is idempotent and nil-safe.
func (l *Lease) Release() {
	if l == nil || l.c == nil {
		return
	}
	l.once.Do(func() {
		l.c.leaseMu.Lock()
		defer l.c.leaseMu.Unlock()
		delete(l.c.leases, l.id)
	})
}

// AcquireLease pins digests against reclaim until the returned lease is released
// or ttl elapses, whichever comes first. A non-positive ttl means DefaultLeaseTTL.
//
// Digests are taken verbatim and are not validated here: a lease is a pure
// over-approximation of what must survive, so an unparseable entry can only
// protect a blob that does not exist. Validating (and thereby possibly dropping)
// an entry is the one change that could make a lease under-approximate, which is
// the direction that loses data.
func (c *Cache) AcquireLease(digests []string, ttl time.Duration) *Lease {
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	held := make([]string, len(digests))
	copy(held, digests)

	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	c.nextLease++
	if c.leaseWatch != nil {
		for _, d := range held {
			c.leaseWatch[d] = struct{}{}
		}
	}
	now := c.now()
	l := &Lease{c: c, id: c.nextLease, digests: held, ttl: ttl, expires: now.Add(ttl), lastRenew: now, acquired: now}
	c.leases[l.id] = l
	return l
}

// beginLeaseWatch starts collecting the digests of every lease acquired from
// now on (see Cache.leaseWatch). Its only caller is executePrune, which takes
// pruneMu itself for the whole pass, so at most one watch is open at a time
// and begin/end never nest.
func (c *Cache) beginLeaseWatch() {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	c.leaseWatch = make(map[string]struct{})
}

// endLeaseWatch stops collecting lease digests.
func (c *Cache) endLeaseWatch() {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	c.leaseWatch = nil
}

// leaseWatchNamesLocked reports whether a lease acquired since the watch began
// (or since the watch was last reset) names d. The caller holds leaseMu. Its
// only caller is executePrune's critical section (unlinkUnlessLeased), which
// resets the watch in that same section when it is about to re-read its pins,
// so a lease acquired during that re-read lands in the fresh watch.
func (c *Cache) leaseWatchNamesLocked(d string) bool {
	_, ok := c.leaseWatch[d]
	return ok
}

// leasedDigests returns the set of digests currently pinned by a live lease,
// dropping leases whose TTL has passed.
func (c *Cache) leasedDigests() map[string]bool {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	c.expireLeasesLocked()
	out := make(map[string]bool)
	for _, l := range c.leases {
		for _, d := range l.digests {
			out[d] = true
		}
	}
	return out
}

// leaseHasLocked reports whether a live lease pins digest, dropping leases
// whose TTL has passed exactly as leasedDigests does. The caller holds leaseMu,
// which is how executePrune makes a blob's lease check and its unlink one
// critical section with respect to AcquireLease. It allocates nothing, so a
// per-blob check costs one scan of the live leases rather than a copy of their
// set.
func (c *Cache) leaseHasLocked(digest string) bool {
	c.expireLeasesLocked()
	for _, l := range c.leases {
		for _, d := range l.digests {
			if d == digest {
				return true
			}
		}
	}
	return false
}

// expireLeasesLocked deletes every lease whose TTL has passed. The caller holds
// leaseMu. It is the one statement of the expiry rule.
func (c *Cache) expireLeasesLocked() {
	now := c.now()
	for id, l := range c.leases {
		if now.After(l.expires) {
			delete(c.leases, id)
		}
	}
}
