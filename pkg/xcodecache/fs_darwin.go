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

package xcodecache

import "golang.org/x/sys/unix"

// apfsFS clones with clonefile(2), which copies a whole directory tree
// copy-on-write in one call on APFS, and swaps with renamex_np(RENAME_SWAP).
type apfsFS struct{}

func (apfsFS) CloneTree(src, dst string) error {
	return unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
}

func (apfsFS) Swap(a, b string) error {
	return unix.RenamexNp(a, b, unix.RENAME_SWAP)
}
