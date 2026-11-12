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
	"sync"
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
type Lease struct {
	c       *Cache
	id      uint64
	digests []string
	expires time.Time

	once sync.Once
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
	l := &Lease{c: c, id: c.nextLease, digests: held, expires: c.now().Add(ttl)}
	c.leases[l.id] = l
	return l
}

// beginLeaseWatch starts collecting the digests of every lease acquired from
// now on (see Cache.leaseWatch). It is called under pruneMu, which every
// executePrune caller takes for the whole pass, so at most one watch is open
// at a time and begin/end never nest.
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

// takeIfNamed reports whether a lease acquired since the watch began (or
// since the last time takeIfNamed returned true) names d. When it does, the
// watch is reset to empty in the same leaseMu critical section, so the caller
// re-reads its pins AFTER the reset and a lease acquired during that re-read
// lands in the fresh set.
func (c *Cache) takeIfNamed(d string) bool {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if _, ok := c.leaseWatch[d]; !ok {
		return false
	}
	c.leaseWatch = make(map[string]struct{})
	return true
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

// leaseHas reports whether a live lease pins digest, dropping leases whose TTL
// has passed exactly as leasedDigests does. It allocates nothing, so a per-blob
// re-check costs one scan of the live leases rather than a copy of their set.
func (c *Cache) leaseHas(digest string) bool {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	return c.leaseHasLocked(digest)
}

// leaseHasLocked is leaseHas for a caller that already holds leaseMu, which is
// how executePrune makes a blob's lease check and its unlink one critical
// section with respect to AcquireLease.
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
