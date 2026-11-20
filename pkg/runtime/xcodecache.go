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

package runtime

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/xcodecache"
)

// podHomeName is the pod's home directory, one subdirectory of its data volume.
// The cache checks its parts out under it at create and publishes them from it
// at delete.
//
// TODO(xcode-defaults): share this const with the HOME/CFFIXED_USER_HOME
// defaulting once both changes are on main; both name the same "home".
const podHomeName = "home"

// podHomeDir is the pod's home in its data volume.
func podHomeDir(dataVol string) string { return filepath.Join(dataVol, podHomeName) }

// xcodeCacheState is the daemon's view of the node's Xcode build cache: the
// store, and the developer dir's Xcode build, read once per dir (a node fact
// that cannot change while the daemon runs, like the developer dir itself).
type xcodeCacheState struct {
	mu     sync.Mutex
	builds map[string]xcodeBuild
	// fs, when non-nil, replaces the APFS clone and swap (a test seam).
	fs xcodecache.FS
	// runCommit, when non-nil, runs a staged publish's commit in place of a
	// new goroutine (a test seam: the tests run it synchronously).
	runCommit func(func())
}

type xcodeBuild struct {
	build string
	err   error
}

func (r *Runtime) xcodeCacheStore() xcodecache.Store {
	return xcodecache.Store{Root: filepath.Join(r.cfg.Root, sandbox.XcodeCacheSubdir), FS: r.xcodeCache.fs}
}

// xcodeBuildFor returns the Xcode build of developerDir, reading it once.
func (r *Runtime) xcodeBuildFor(developerDir string) (string, error) {
	r.xcodeCache.mu.Lock()
	defer r.xcodeCache.mu.Unlock()
	if b, ok := r.xcodeCache.builds[developerDir]; ok {
		return b.build, b.err
	}
	build, err := xcodecache.ReadBuildVersion(developerDir)
	if r.xcodeCache.builds == nil {
		r.xcodeCache.builds = map[string]xcodeBuild{}
	}
	r.xcodeCache.builds[developerDir] = xcodeBuild{build: build, err: err}
	return build, err
}

// xcodeCacheEntry returns the cache entry a pod asked for, and false when it
// asked for none or the request cannot be honoured. It degrades and never
// fails: a pod that asked for a cache it cannot have starts cold, and the
// reason is logged once per create (the k3sm provider can validate the key
// itself with xcodecache.ValidKey and put the reason on the pod as an Event).
//
// The cache is honoured only on a pod granted a full Xcode, because the snapshot
// is keyed by that Xcode's build, and a pod without the grant cannot run
// xcodebuild at all.
func (r *Runtime) xcodeCacheEntry(box *runtimev1.PodBox) (xcodecache.Entry, bool) {
	key, asked := box.GetAnnotations()[xcodecache.Annotation]
	if !asked {
		return xcodecache.Entry{}, false
	}
	log := r.log.With("pod", box.GetPodId(), "namespace", box.GetNamespace(), "name", box.GetName(),
		"annotation", xcodecache.Annotation, "key", key)
	dir := box.GetSandboxProfile().GetXcodeToolchainDir()
	if dir == "" {
		log.Warn("xcode cache skipped: the pod has no Xcode toolchain grant (k3sm.io/xcode-toolchain on a node with Xcode)")
		return xcodecache.Entry{}, false
	}
	build, err := r.xcodeBuildFor(dir)
	if err != nil {
		log.Warn("xcode cache skipped: cannot read the Xcode build", "developer_dir", dir, "err", err)
		return xcodecache.Entry{}, false
	}
	e := xcodecache.Entry{Namespace: box.GetNamespace(), Key: key, Build: build}
	if err := e.Validate(); err != nil {
		log.Warn("xcode cache skipped", "err", err)
		return xcodecache.Entry{}, false
	}
	return e, true
}

// checkoutXcodeCache clones the pod's cache entry, when it has one, into the
// pod's home. createPod calls it once, after the profile is compiled (so the
// toolchain dir it keys on has been validated) and before the fsGroup walk (so
// the clone gets the same ownership as the rest of the data volume). A re-attach
// after a daemon restart never runs createPod, so a pod is never checked out
// twice. Any failure leaves the pod cold and is logged; it never fails the
// create.
func (r *Runtime) checkoutXcodeCache(box *runtimev1.PodBox, dataVol string) {
	e, ok := r.xcodeCacheEntry(box)
	if !ok {
		return
	}
	log := r.log.With("pod", box.GetPodId(), "namespace", e.Namespace, "key", e.Key, "xcode_build", e.Build)
	home := podHomeDir(dataVol)
	if err := os.MkdirAll(home, 0o700); err != nil {
		log.Warn("xcode cache checkout skipped: create the pod home", "err", err)
		return
	}
	start := time.Now()
	parts, err := r.xcodeCacheStore().Checkout(e, home)
	if err != nil {
		log.Warn("xcode cache checkout failed; the build starts cold for what was not cloned",
			"cloned", parts, "err", err)
		return
	}
	if len(parts) == 0 {
		log.Info("xcode cache: no snapshot yet; the build starts cold")
		return
	}
	log.Info("xcode cache checked out", "parts", parts, "took", time.Since(start).String())
}

// stageXcodeCache stages a publish of the pod's home when the pod asked for a
// cache and succeeded, and returns the commit to run once the pod's directory
// may be gone (nil when there is nothing to commit). DeletePod calls it after
// every process of the pod is stopped and swept and before the pod directory is
// removed: the staging clone needs the home, the commit (which may wait on a
// reader's lock) does not, so the delete never waits on another pod's checkout.
//
// succeeded is the pod's phase as DeletePod found it, before it stopped
// anything: SUCCEEDED means every main container had already exited 0 on its
// own (recomputePhaseLocked). A pod deleted while running, a failed one and a
// re-attached one (whose exits cannot be read) never publish.
func (r *Runtime) stageXcodeCache(box *runtimev1.PodBox, dataVol string, succeeded bool) func() {
	if !succeeded {
		return nil
	}
	e, ok := r.xcodeCacheEntry(box)
	if !ok {
		return nil
	}
	log := r.log.With("pod", box.GetPodId(), "namespace", e.Namespace, "key", e.Key, "xcode_build", e.Build)
	store := r.xcodeCacheStore()
	incoming, parts, err := store.Stage(e, podHomeDir(dataVol), box.GetPodId())
	if err != nil {
		log.Warn("xcode cache publish skipped: stage", "err", err)
		return nil
	}
	if incoming == "" {
		return nil
	}
	return func() {
		start := time.Now()
		if err := store.Commit(e, incoming); err != nil {
			log.Warn("xcode cache publish failed; the previous snapshot stays", "err", err)
			return
		}
		log.Info("xcode cache published", "parts", parts, "took", time.Since(start).String())
	}
}
