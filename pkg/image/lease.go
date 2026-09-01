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
	l := &Lease{c: c, id: c.nextLease, digests: held, expires: c.now().Add(ttl)}
	c.leases[l.id] = l
	return l
}

// leasedDigests returns the set of digests currently pinned by a live lease,
// dropping leases whose TTL has passed.
func (c *Cache) leasedDigests() map[string]bool {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	now := c.now()
	out := make(map[string]bool)
	for id, l := range c.leases {
		if now.After(l.expires) {
			delete(c.leases, id)
			continue
		}
		for _, d := range l.digests {
			out[d] = true
		}
	}
	return out
}
