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

// Package keystorepaths is the one home of the keystore's path names under a
// k3sm data root: the name prefix every keystore entry there carries, its run
// and socket directories, and the socket path.
//
// Both ends read these names: the server that creates the files and binds the
// socket, and the runtime's pod profile (pkg/sandbox), which denies every pod
// each of them. One spelling means a renamed path cannot leave the deny
// behind.
//
// The package is a leaf: it imports only the standard library and has no cgo,
// so a caller (the keystore itself) takes on none of the sandbox's
// dependencies. TestLeafImportsOnlyTheStandardLibrary pins that.
package keystorepaths
