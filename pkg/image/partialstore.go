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
	"log/slog"
	"path/filepath"
	"time"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// PartialSubdir is the directory (<root>/image-partial) a layer cut mid-fetch
// keeps the bytes it already received in, so the next pull of that layer asks
// only for the rest with a Range request. It is a sibling of blobs/, never a
// child: everything under blobs/ is content-addressed and verified, and a
// partial is neither until it is committed. A pod able to read here reads
// another workload's layer mid-transfer; one able to write here makes every
// resume of that layer fail its digest check (CommitBlob re-hashes the whole
// blob, so it cannot choose the bytes committed). pkg/sandbox mirrors the name
// as ImagePartialSubdir and denies it to every pod.
const PartialSubdir = "image-partial"

// PartialStoreMaxBytes caps the summed size of the files in the partial store
// (registryfetch.PartialStore.MaxBytes). It is DefaultReclaimHighFreeBytes on
// purpose: a store of kept partials larger than the free-space floor reclaim
// defends would be the thing pushing the node under it. A layer whose own
// size exceeds the cap is fetched whole, from byte 0, with no partial kept.
const PartialStoreMaxBytes = int64(DefaultReclaimHighFreeBytes)

// PartialMaxAge is how old (by mtime) a partial must be before the sweep at
// daemon start and at each reclaim pass removes it. A cut pull is normally
// retried within seconds; a day-old partial belongs to a pull nobody retried.
const PartialMaxAge = 24 * time.Hour

// partialDir is where the partial store lives.
func (c *Cache) partialDir() string { return filepath.Join(c.root, PartialSubdir) }

// OpenPartialStore returns the cache's one partial store, building it on the
// first call: <root>/PartialSubdir, created 0700 when absent and refused when
// it is not a private directory this euid owns (registryfetch EnsureDir),
// capped at PartialStoreMaxBytes, then swept once (PartialMaxAge, on the
// cache's clock). A refused directory is logged at Error and disables the
// store for the cache's life: the call returns nil, and a puller handed nil
// fetches every layer from byte 0, exactly as without a store. The daemon
// keeps running either way; the store is an optimisation.
//
// Later calls return the same store (or nil) and ignore log; the store logs
// to the logger of the first call. A nil log discards.
func (c *Cache) OpenPartialStore(log *slog.Logger) *registryfetch.PartialStore {
	c.partialOnce.Do(func() {
		if log == nil {
			log = slog.New(slog.DiscardHandler)
		}
		s := &registryfetch.PartialStore{Dir: c.partialDir(), Log: log, MaxBytes: PartialStoreMaxBytes}
		if err := s.EnsureDir(); err != nil {
			log.Error("image partial store disabled; every layer is fetched from byte 0",
				"dir", s.Dir, "err", err)
			return
		}
		c.partials.Store(s)
		c.sweepPartials(c.now(), log)
	})
	return c.partials.Load()
}

// sweepPartials removes the partials older than PartialMaxAge at now that no
// running pull has claimed, and any stale foreign file beside them, best
// effort: a failure is logged and stops nothing. It takes no cache lock (the
// store guards its own claims), so it runs outside pruneMu and leaseMu. A
// cache whose store is not open sweeps nothing.
func (c *Cache) sweepPartials(now time.Time, log *slog.Logger) {
	s := c.partials.Load()
	if s == nil {
		return
	}
	removed, err := s.Sweep(now, PartialMaxAge)
	if err != nil {
		log.Warn("image partial sweep incomplete", "dir", s.Dir, "removed", removed, "err", err)
		return
	}
	if removed > 0 {
		log.Info("image partial sweep removed stale partials", "dir", s.Dir, "removed", removed)
	}
}

// partialBytes is what the partial store holds, by stat alone (Usage): no
// partial is opened to measure it. A cache whose store is not open holds none.
func (c *Cache) partialBytes() (int64, error) {
	s := c.partials.Load()
	if s == nil {
		return 0, nil
	}
	return s.Usage()
}
