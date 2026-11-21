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

package mount

import "errors"

// clonefileAt is unsupported off darwin, where there is no APFS clone:
// cloneFileAt byte-copies instead. runtimed targets darwin/arm64, so this
// exists only so the package builds and unit-tests run on a non-darwin host.
func clonefileAt(int, string, int, string) error { return errors.ErrUnsupported }
