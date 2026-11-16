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

package volume

// ExposeACL grants and revokes one host account's access to an exposure
// directory (k3sm.io/runtimed/pkg/hostshare Exposure). The runtime calls it as
// the directory's owner; runtimed does not import the code that sets ACLs, so
// the node (k3sm) wires one. A runtime with no ExposeACL refuses every pod
// with an exposure volume: it never exposes data it cannot scope.
type ExposeACL interface {
	// Grant adds to dir an inheritable allow entry for uid: read access, or
	// read and write when readWrite (and then the same entry for the owner,
	// so the owner keeps access to what uid creates).
	Grant(dir string, uid uint32, readWrite bool) error
	// Revoke removes uid's entries from dir itself. dir is mode 0700, so
	// without its entry uid can no longer reach anything below it.
	Revoke(dir string, uid uint32) error
}
