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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The Xcode pod defaults: what a pod whose xcode_toolchain_dir grant took
// effect gets so that xcodebuild, SwiftPM and XcodeGen work without the
// workload knowing any of k3sm's gotchas in advance. Each was a real failure in
// a studio pod (Xcode 27.1, the yureisha App), and each is injected only when
// the spec or image does not set the name, the house rule TMPDIR, the module
// cache and DEVELOPER_DIR follow.
//
//   - HOME. A native pod has none. Xcode and SwiftPM then fall back to
//     getpwuid's home, /var/lib/k3sm, which the pod cannot write: "You don't
//     have permission to save the file 'repositories' in the folder
//     'SourcePackages'". The pod gets its own, in its data volume.
//   - CFFIXED_USER_HOME. Xcode resolves its home through CoreFoundation, which
//     ignores $HOME and honours only this variable (and only in an
//     unrestricted process, which the shadow xcodebuild copy is). It is set to
//     the effective HOME, the pod's own or the one the spec named. The default
//     DerivedData, ~/Library/Developer/Xcode/DerivedData, then lands in the data
//     volume at a real path, the same inside and outside the pod, which a mount
//     path is not (the path-rebase shim rewrites those, and Xcode's build
//     database then fails with "unable to attach DB").
//   - USER and LOGNAME. XcodeGen stops with "Couldn't find current username".
//   - PATH, only when none is set: the developer dir's tools first, so
//     xcodebuild resolves to $DEVELOPER_DIR/usr/bin/xcodebuild (which the shim
//     swaps for the node's copy) rather than the /usr/bin trampoline, a platform
//     binary that starts xcodebuild without the copy.
//
// Pods without the grant are unchanged: no home, no variables.
const (
	podHomeName    = "home"
	homeEnv        = "HOME"
	cfFixedHomeEnv = "CFFIXED_USER_HOME"
	userEnv        = "USER"
	logNameEnv     = "LOGNAME"
	pathEnv        = "PATH"

	// podGitConfigName is the git configuration provisioned in the pod home.
	podGitConfigName = ".gitconfig"
)

// podGitConfig is the pod home's git configuration. safe.directory=* turns
// off git's repository-ownership check for this pod's git only. The check
// protects a user from running a repository's configuration (hooks,
// core.fsmonitor) that another user planted; in a pod the repository is the
// pod's own or a host path the operator shared with it, and anything it
// could run, the pod could already run as the same uid in the same sandbox.
// Without it SwiftPM and a plain clone of a host-shared repository both stop
// with "detected dubious ownership" (the host files belong to the operator,
// the pod runs as _k3sm).
const podGitConfig = "# Provisioned by k3sm for a pod with the k3sm.io/xcode-toolchain grant.\n" +
	"[safe]\n\tdirectory = *\n"

// podHomeDir is the pod's home: one subdirectory of the pod data volume, and
// the single derivation of that path.
func podHomeDir(dataVol string) string { return filepath.Join(dataVol, podHomeName) }

// provisionPodHome creates the pod home (0700, like the pod temp dir) and its
// git configuration. An existing configuration is left alone, so a pod
// re-attached after a daemon restart keeps whatever its workload changed.
func provisionPodHome(dataVol string) error {
	home := podHomeDir(dataVol)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("create pod home %s: %w", home, err)
	}
	p := filepath.Join(home, podGitConfigName)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create pod git config %s: %w", p, err)
	}
	if _, err := f.WriteString(podGitConfig); err != nil {
		_ = f.Close()
		return fmt.Errorf("write pod git config %s: %w", p, err)
	}
	return f.Close()
}

// lookupUserName names a uid. A var so a test can state the host fact.
var lookupUserName = func(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// xcodePodPath is the PATH an Xcode pod with none gets.
func xcodePodPath(developerDir string) string {
	return filepath.Join(developerDir, "usr", "bin") + ":" +
		filepath.Join(developerDir, "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin") +
		":/usr/bin:/bin:/usr/sbin:/sbin"
}

// xcodeEnv returns the Xcode pod defaults for c, given the base environment the
// spec and image supply. It returns nothing for a pod without the grant.
func (r *Runtime) xcodeEnv(box *runtimev1.PodBox, c *runtimev1.Container, base []string) ([]string, error) {
	dir := box.GetSandboxProfile().GetXcodeToolchainDir()
	if dir == "" {
		return nil, nil
	}
	dataVol, err := r.rootfsPath(box)
	if err != nil {
		return nil, err
	}
	var env []string
	home, ok := baseEnvValue(base, homeEnv)
	if !ok {
		home = podHomeDir(dataVol)
		env = append(env, homeEnv+"="+home)
	}
	if !envHasName(base, cfFixedHomeEnv) {
		env = append(env, cfFixedHomeEnv+"="+home)
	}
	if !envHasName(base, userEnv) || !envHasName(base, logNameEnv) {
		uid := os.Geteuid()
		if cred := resolveCredential(box, c); cred.Drop && cred.UID != 0 {
			uid = cred.UID
		}
		if name, err := lookupUserName(uid); err == nil && name != "" {
			if !envHasName(base, userEnv) {
				env = append(env, userEnv+"="+name)
			}
			if !envHasName(base, logNameEnv) {
				env = append(env, logNameEnv+"="+name)
			}
		} else {
			r.log.Warn("xcode pod: no user name for the container's uid; USER and LOGNAME are not set",
				"pod", box.GetPodId(), "uid", uid, "err", err)
		}
	}
	if !envHasName(base, pathEnv) {
		devDir := dir
		if v, ok := baseEnvValue(base, developerDirEnv); ok && v != "" {
			devDir = v
		}
		env = append(env, pathEnv+"="+xcodePodPath(devDir))
	}
	return env, nil
}

// baseEnvValue returns the value env (in "K=V" form) sets for name, and
// whether it sets one. The last entry wins, as it does for the child.
func baseEnvValue(env []string, name string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == name {
			val, found = v, true
		}
	}
	return val, found
}
