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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Per-pod Darwin user temp and cache dirs. sandbox/userdirs.go has the
// mechanism; this file is its lifecycle.
//
// confstr(_CS_DARWIN_USER_TEMP_DIR|_CS_DARWIN_USER_CACHE_DIR) names the daemon
// uid's shared /var/folders trees, which a pod may not touch. With
// DIRHELPER_USER_DIR_SUFFIX=k3sm.<pod id> it names <T>/k3sm.<pod id> and
// <C>/k3sm.<pod id> instead, and runtimed makes those two paths symlinks into
// the pod's own data volume:
//
//	<T>/k3sm.<pod id> -> <data volume>/tmp/darwin-user-temp
//	<C>/k3sm.<pod id> -> <data volume>/tmp/darwin-user-cache
//
// The profile grants file-read-metadata on the two link paths and nothing else
// in the shared trees, so the pod resolves its own links, writes land in its
// own data volume, and it can neither list, create, replace nor remove a link.
//
// ORDER IS THE SAFETY PROPERTY. dirhelper mkdirs a missing <T>/<suffix> itself,
// even for a confined caller (measured: Seatbelt does not stop it), and marks
// the directory sunlnk + com.apple.rootless, so neither the pod nor runtimed can
// ever remove it or put a link in its place. A process must therefore never
// carry the suffix unless the link already exists. So:
//
//   - the links are made at create, before any container exists, and made again
//     (ensurePodUserDirLinks) at every spawn and exec, because the OS empties T
//     at boot;
//   - containerEnv injects the suffix only when both links exist and point at
//     this pod's targets right now (podUserDirLinksReady), and otherwise injects
//     nothing, so the pod gets the platform answer and fails closed (EPERM)
//     exactly as before this change;
//   - the suffix is runtime-owned: a spec value is dropped.
//
// Re-ensuring touches ONLY the links in T and C, which no pod can write. The
// targets inside the data volume are made once, at create, before any container
// runs: after that the pod owns that tree and could have planted a symlink in
// it, and runtimed (unconfined, same uid) must not mkdir through it.
//
// Ceilings, recorded rather than hidden: platform binaries (/usr/bin/swift is
// the xcrun shim) and hardened-runtime binaries ignore the suffix; a container
// that runs as another uid gets that uid's trees and no links (fail closed); a
// link the OS purges while a process is running is re-made only at the next
// spawn or exec; and a pod whose id would make an unusable suffix (it holds
// "..") gets none. Same-node pods still share one uid, so these dirs are 0700
// against other local uids, not against another pod: untrusted tenancy belongs
// on the vm RuntimeClass.

// userDirSuffixEnv is the variable libSystem's dirhelper reads.
const userDirSuffixEnv = sandbox.UserDirSuffixEnv

// The two link targets, inside the pod temp dir.
const (
	podUserTempName  = "darwin-user-temp"
	podUserCacheName = "darwin-user-cache"
)

// errUserDirLinkOccupied reports a link path held by something that is not a
// symlink: almost always a directory dirhelper made (SIP-protected, so it can
// never be replaced). The pod then keeps the platform answer.
var errUserDirLinkOccupied = errors.New("per-pod user dir link path is occupied by a non-link")

// darwinUserDirs is the node user's two shared trees, resolved once by New.
// The zero value means the feature is off.
type darwinUserDirs struct {
	temp, cache string
	// uid is the uid the two trees belong to (this daemon's euid when they were
	// resolved). A container that runs as another uid asks confstr about that
	// uid's trees, where no link exists, so it gets no suffix.
	uid int
}

func (d darwinUserDirs) on() bool { return d.temp != "" && d.cache != "" }

// resolveDarwinUserDirs asks probe for the trees and canonicalises them
// (Seatbelt matches resolved paths: /var/folders is /private/var/folders). Any
// failure turns the feature off with one log line; it never fails New.
func resolveDarwinUserDirs(probe func() (string, string, error), log interface {
	Info(string, ...any)
}) darwinUserDirs {
	if probe == nil {
		return darwinUserDirs{}
	}
	temp, cache, err := probe()
	if err == nil {
		temp, err = filepath.EvalSymlinks(temp)
	}
	if err == nil {
		cache, err = filepath.EvalSymlinks(cache)
	}
	if err != nil {
		log.Info("per-pod darwin user dirs off: pods keep the platform temp and cache dir answer", "err", err)
		return darwinUserDirs{}
	}
	return darwinUserDirs{temp: temp, cache: cache, uid: os.Geteuid()}
}

// podUserDirTargets are the two directories in the pod's data volume the links
// point at.
func podUserDirTargets(dataVol string) (temp, cache string) {
	return filepath.Join(podTmpDir(dataVol), podUserTempName), filepath.Join(podTmpDir(dataVol), podUserCacheName)
}

// podUserDirSuffix is the pod's suffix, and false when the feature is off or
// the pod id would make a suffix dirhelper refuses.
func (r *Runtime) podUserDirSuffix(podID string) (string, bool) {
	if !r.userDirs.on() {
		return "", false
	}
	return sandbox.UserDirSuffix(podID)
}

// podUserDirLinks returns the pod's two link paths.
func (r *Runtime) podUserDirLinks(podID string) (temp, cache string, ok bool) {
	sfx, ok := r.podUserDirSuffix(podID)
	if !ok {
		return "", "", false
	}
	return filepath.Join(r.userDirs.temp, sfx), filepath.Join(r.userDirs.cache, sfx), true
}

// provisionPodUserDirs makes the two link targets in the data volume. Create
// time only (see the file comment for why it is never repeated).
func provisionPodUserDirs(dataVol string) error {
	temp, cache := podUserDirTargets(dataVol)
	for _, d := range []string{temp, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create pod user dir %s: %w", d, err)
		}
	}
	return nil
}

// ensurePodUserDirLinks makes (or repairs) the pod's two links. It is
// best-effort by contract: a failure is logged and the pod simply gets no
// suffix (podUserDirLinksReady then reports false), which is the earlier
// behaviour, never a failed spawn.
func (r *Runtime) ensurePodUserDirLinks(box *runtimev1.PodBox) {
	tempLink, cacheLink, ok := r.podUserDirLinks(box.GetPodId())
	if !ok {
		return
	}
	dataVol, err := r.rootfsPath(box)
	if err != nil {
		return
	}
	tempTarget, cacheTarget := podUserDirTargets(dataVol)
	for _, l := range [][2]string{{tempLink, tempTarget}, {cacheLink, cacheTarget}} {
		if err := ensureSymlink(l[0], l[1]); err != nil {
			r.log.Warn("per-pod darwin user dir link not made; the pod keeps the platform answer",
				"pod", box.GetPodId(), "link", l[0], "err", err)
		}
	}
}

// ensureSymlink makes link a symlink to target. An existing link to target is
// left alone; a symlink to anything else is replaced atomically (a fresh link
// under a random name, renamed over it); anything that is not a symlink is
// never touched and is reported as errUserDirLinkOccupied.
func ensureSymlink(link, target string) error {
	err := os.Symlink(target, link)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		return err
	}
	cur, rerr := os.Readlink(link)
	if rerr != nil {
		return fmt.Errorf("%w: %s", errUserDirLinkOccupied, link)
	}
	if cur == target {
		return nil
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := link + ".k3sm-new-" + hex.EncodeToString(nonce[:])
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// podUserDirLinksReady reports whether both of the pod's links exist and point
// at its targets right now. It reads, never writes, which is what keeps
// containerEnv a pure environment builder.
func (r *Runtime) podUserDirLinksReady(box *runtimev1.PodBox) (string, bool) {
	sfx, ok := r.podUserDirSuffix(box.GetPodId())
	if !ok {
		return "", false
	}
	dataVol, err := r.rootfsPath(box)
	if err != nil {
		return "", false
	}
	tempTarget, cacheTarget := podUserDirTargets(dataVol)
	for _, l := range [][2]string{
		{filepath.Join(r.userDirs.temp, sfx), tempTarget},
		{filepath.Join(r.userDirs.cache, sfx), cacheTarget},
	} {
		if cur, err := os.Readlink(l[0]); err != nil || cur != l[1] {
			return "", false
		}
	}
	return sfx, true
}

// containerRunsAsUserDirsUID reports whether c runs as the uid the trees were
// resolved for: the daemon's own uid when no drop is requested (resolveCredential
// treats 0 as "inherit", i.e. the daemon identity).
func (r *Runtime) containerRunsAsUserDirsUID(box *runtimev1.PodBox, c *runtimev1.Container) bool {
	cred := resolveCredential(box, c)
	uid := r.userDirs.uid
	if cred.Drop && cred.UID != 0 {
		uid = cred.UID
	}
	return uid == r.userDirs.uid
}

// removePodUserDirLinks removes the pod's two links when they are symlinks. A
// non-link at either path is left alone (it is not runtimed's).
func (r *Runtime) removePodUserDirLinks(podID string) {
	tempLink, cacheLink, ok := r.podUserDirLinks(podID)
	if !ok {
		return
	}
	for _, l := range []string{tempLink, cacheLink} {
		if _, err := os.Readlink(l); err == nil {
			if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
				r.log.Warn("remove per-pod darwin user dir link", "pod", podID, "link", l, "err", err)
			}
		}
	}
}

// sweepDanglingUserDirLinks removes k3sm.* symlinks in the two trees whose
// target is gone: the links of pods deleted while this daemon was down. A link
// whose target exists (an adopted pod) and anything that is not a symlink are
// left alone.
func (r *Runtime) sweepDanglingUserDirLinks() {
	if !r.userDirs.on() {
		return
	}
	for _, dir := range []string{r.userDirs.temp, r.userDirs.cache} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.Type()&fs.ModeSymlink == 0 || !strings.HasPrefix(e.Name(), sandbox.UserDirSuffixPrefix) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
				_ = os.Remove(p)
			}
		}
	}
}
