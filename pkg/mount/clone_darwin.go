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

import "k3sm.io/runtimed/pkg/image"

// defaultCloner is the production Cloner used to copy a selected subPath element
// into the rebased mount path: an APFS copy-on-write clone (unix.Clonefile) with a
// byte-copy fallback on EXDEV/ENOTSUP. The staging dir and the destination live on
// the same volume (the per-pod dir), so the clone is CoW in the common case.
func defaultCloner() image.Cloner { return image.APFSCloner{} }
