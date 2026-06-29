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

package supervisor

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ChownForFSGroup recursively sets group ownership of root to gid and makes it
// group-accessible, so a pod that drops to a non-root uid (with fsGroup in its
// supplemental groups — see Credential.Groups) can still read and write its
// volumes (M2.3 securityContext.fsGroup). It mirrors the kubelet fsGroup
// volume-ownership pass.
//
// It MUST run ROOT-SIDE in the daemon, BEFORE the privilege drop in the exec-shim
// (RunLaunchSequence): once a pod process has dropped its uid it can no longer
// chown, and once it is sandboxed it cannot either. The supervisor performs it
// synchronously before posix_spawn, which is strictly before the exec-shim drops
// — so the "before the drop" ordering is guaranteed by the process flow.
//
// Directories additionally get the setgid bit so files created later inherit the
// group. Symlinks are chowned (lchown) but not chmod'd (a symlink mode is
// meaningless and Chmod would follow the link). A gid <= 0 is rejected: 0 (wheel)
// is never a valid fsGroup target and a negative gid is a programming error.
func ChownForFSGroup(root string, gid int) error {
	if gid <= 0 {
		return fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// lchown keeps uid (-1) and sets the group; it does not follow symlinks.
		if err := os.Lchown(path, -1, gid); err != nil {
			return fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // do not chmod a symlink
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		// Grant the group the same rwx the owner has (so an fsGroup member can use
		// the volume); dirs also get the setgid bit for group inheritance.
		mode |= (mode & 0o700) >> 3
		newMode := info.Mode()&^fs.FileMode(0o777) | mode
		if d.IsDir() {
			newMode |= os.ModeSetgid
		}
		if err := os.Chmod(path, newMode); err != nil {
			return fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return nil
	})
}
