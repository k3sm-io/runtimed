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

// Package shadowset is the one declared list of host binaries a k3sm node
// keeps an ad-hoc re-signed "shadow" copy of, and the exec paths each copy
// stands in for.
//
// # Why copies exist
//
// Nearly every binary under /bin and /usr/bin carries the SIP SF_RESTRICTED
// flag and is a platform binary, so dyld scrubs DYLD_* from its environment. A
// pod process that execs one loses the path-rebase and DNS interposers for
// that process and every descendant: a mounted absolute path resolves to the
// host path instead of the pod's volume. A re-signed copy of the same binary is
// neither restricted nor platform, so the interposers stay loaded.
//
// # Three consumers, one list
//
//   - the node installer copies each Entry.Source to <shadow dir>/<Entry.Copy>
//     and re-signs it;
//   - the runtime (pkg/runtime shadowRewrite) swaps a container's main exec
//     of any Entry.Hosts path for the copy;
//   - the path-rebase interposer (shim/pathrebase_shim.c) does the same at
//     every execve/posix_spawn inside the pod, from shim/shadow_table.h, which
//     is GENERATED from this list (go generate; see gen/) and pinned
//     byte-for-byte by the generator's staleness test.
//
// The list is declared here and nowhere else. Changing it means: edit
// entries, run go generate, and reinstall the node so the installer makes the
// new copies (a copy that is missing is simply not used: the host binary runs,
// exactly as before).
//
// This package imports nothing, so every consumer (including a different
// module's installer) can depend on it without pulling the runtime in.
package shadowset

//go:generate go run ./gen ../../shim/shadow_table.h
