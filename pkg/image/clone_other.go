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

// assertNoQuarantine is a no-op off darwin (no com.apple.quarantine concept).
func assertNoQuarantine(string) error { return nil }
