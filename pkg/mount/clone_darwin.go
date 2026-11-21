//go:build darwin

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

package mount

import "golang.org/x/sys/unix"

// clonefileAt makes dstName under dstDir an APFS copy-on-write clone of the
// regular file srcName under srcDir (clonefileat(2)), not following a link at
// srcName. The staging dir and the destination live on the same volume (the
// per-pod dir), so the clone is CoW in the common case; cloneFileAt
// byte-copies when the volumes cannot clone.
func clonefileAt(srcDir int, srcName string, dstDir int, dstName string) error {
	return unix.Clonefileat(srcDir, srcName, dstDir, dstName, unix.CLONE_NOFOLLOW)
}
