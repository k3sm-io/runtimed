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

package supervisor

import "golang.org/x/sys/unix"

// RestrictedPlatformFile reports whether path names a regular file carrying
// the SIP SF_RESTRICTED file flag, the proxy the path shim uses for "dyld
// scrubs DYLD_* from it". stat follows symlinks (so /bin/sh's target is what
// is judged) and opens nothing: a reported name is untrusted, and stat on it
// cannot block or read pod data. A pod cannot set SF_RESTRICTED, so a file it
// built at a lookalike path is rejected.
func RestrictedPlatformFile(path string) bool {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Flags&unix.SF_RESTRICTED != 0
}
