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

package execshim

import "strings"

// hasNUL reports whether path or any argv/env element contains a NUL byte. Such
// a string cannot cross into C intact (it would be truncated at the NUL), so the
// marked exec is skipped and unix.Exec refuses it with EINVAL.
func hasNUL(path string, argv, env []string) bool {
	if strings.IndexByte(path, 0) >= 0 {
		return true
	}
	for _, list := range [][]string{argv, env} {
		for _, s := range list {
			if strings.IndexByte(s, 0) >= 0 {
				return true
			}
		}
	}
	return false
}
