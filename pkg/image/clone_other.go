//go:build !darwin

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
	"errors"
	"os"
	"path/filepath"
	"time"
)

// APFSCloner off darwin has no APFS CoW; it byte-copies. It exists so the
// package builds and unit-tests run on non-darwin CI; production is darwin-only.
type APFSCloner struct{}

// Clone byte-copies src to dst (cow is always false off darwin).
func (APFSCloner) Clone(src, dst string) (bool, error) {
	if err := byteCopyFile(src, dst); err != nil {
		return false, err
	}
	return false, nil
}

// CloneOnly off darwin has no clonefile, so every clone is refused as
// unsupported (IsCloneUnsupported) without copying.
type CloneOnly struct{}

// Clone refuses: there is no copy-on-write clone off darwin.
func (CloneOnly) Clone(src, dst string) (bool, error) {
	return false, &os.LinkError{Op: "clonefile", Old: src, New: dst, Err: errors.ErrUnsupported}
}

// cloneFileAt off darwin has no fclonefileat, so every clone is refused as
// unsupported (IsCloneUnsupported) without copying.
func cloneFileAt(_, _ *os.File, name string) error {
	return &os.PathError{Op: "fclonefileat", Path: name, Err: errors.ErrUnsupported}
}

// scrubClone off darwin has no file flags to clear; no clone is ever made
// there (cloneFileAt refuses), so it is never reached with one.
func scrubClone(*os.File) error { return nil }

// hasACL off darwin reports no ACL; no clone is ever made there.
func hasACL(*os.File) (bool, error) { return false, nil }

// clearFlags off darwin has no file flags to clear.
func clearFlags(string) error { return nil }

// statusChanged off darwin falls back to the modification time.
func statusChanged(fi os.FileInfo) time.Time { return fi.ModTime() }

// renameFromStage off darwin renames by path; no clone is ever made there.
func renameFromStage(stage *os.File, name, dst string) error {
	return os.Rename(filepath.Join(stage.Name(), name), dst)
}

// assertNoQuarantine is a no-op off darwin (no com.apple.quarantine concept).
func assertNoQuarantine(string) error { return nil }
