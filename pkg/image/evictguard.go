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

import "fmt"

// evictHooks returns the executor seams of the eviction path: a guard that
// reads the classified roots once per executor call and drops every blob they
// name, then runs afterPlan; and an unlink seam that decides each blob through
// unlinkUnlessLeased. cfg's UntrackedPod is passed to every roots read, as
// Cache.roots documents, and cfg's afterPlan, when non-nil, runs after the
// guard's roots read.
//
// Lock order: the executor holds pruneMu around both seams, and
// unlinkUnlessLeased takes leaseMu inside it, then operatorMu inside leaseMu
// (through OperatorImageRoots). No path takes them in another order.
func (c *Cache) evictHooks(cfg *ReclaimConfig) *pruneHooks {
	untracked, afterPlan := cfg.UntrackedPod, cfg.afterPlan
	return &pruneHooks{
		guard: func() (map[string]evictReason, error) {
			roots, err := c.classifiedRoots(untracked)
			if err != nil {
				return nil, err
			}
			drop := rootedReasons(roots)
			if afterPlan != nil {
				afterPlan()
			}
			return drop, nil
		},
		unlink: func(digest string, remove func() error) (bool, evictReason, error) {
			return c.unlinkUnlessLeased(digest, remove, untracked)
		},
	}
}

// rootedReasons maps every blob digest roots names to why it is kept:
// evictRooted for an operator root or an artifact record, otherwise evictInUse
// for a per-pod record or a pod hold. A rooted blob a pod also names is
// evictRooted, as refineEvictRooted labels it. A nil set names none.
func rootedReasons(roots *rootSet) map[string]evictReason {
	out := make(map[string]evictReason)
	for d := range roots.inUseDigests() {
		out[d] = evictInUse
	}
	for d := range roots.rootedDigests() {
		out[d] = evictRooted
	}
	return out
}

// unlinkUnlessLeased removes one blob unless something now holds it. It holds
// leaseMu across the whole decision and the unlink:
//
//  1. a live lease naming digest keeps it (evictLeased);
//  2. the roots are read again for digest (blobRootedNow); a root naming it
//     keeps it (evictRooted or evictInUse), and a read error keeps it and is
//     returned, so the executor records a typed failure with the blob on disk;
//  3. otherwise remove is called.
//
// AcquireLease takes leaseMu, so a pull that leases the blob after this check
// sees the unlink and re-fetches. Root writers record a root before they
// release their lease, and Release takes leaseMu, so a root written and its
// lease released after the guard's pass-level read is seen by step 2.
func (c *Cache) unlinkUnlessLeased(digest string, remove func() error, untracked UntrackedPodFunc) (bool, evictReason, error) {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.leasedLocked(digest) {
		return false, evictLeased, nil
	}
	why, rooted, err := c.blobRootedNow(digest, untracked)
	if err != nil {
		return false, "", fmt.Errorf("per-blob roots read: %w", err)
	}
	if rooted {
		return false, why, nil
	}
	return true, "", remove()
}

// blobRootedNow is the per-blob roots check, the one place that decides how
// roots are consulted before an unlink. It re-reads the whole classified root
// set on every call, unconditionally. A cheaper rule (re-reading only when
// some signal says the roots may have changed since the guard's read) would
// replace the read below with a check of that signal; any such signal must
// also catch a root written by a holder whose lease expired unreleased, and a
// root written with no lease at all.
func (c *Cache) blobRootedNow(digest string, untracked UntrackedPodFunc) (evictReason, bool, error) {
	roots, err := c.classifiedRoots(untracked)
	if err != nil {
		return "", false, err
	}
	why, ok := rootedReasons(roots)[digest]
	return why, ok, nil
}

// leasedLocked reports whether a live lease names digest, dropping expired
// leases as leasedDigests does. The caller holds leaseMu.
func (c *Cache) leasedLocked(digest string) bool {
	now := c.now()
	held := false
	for id, l := range c.leases {
		if now.After(l.expires) {
			delete(c.leases, id)
			continue
		}
		for _, d := range l.digests {
			if d == digest {
				held = true
			}
		}
	}
	return held
}
