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

// Package hostshare is the node's allowlist of host paths a native pod may
// mount with a hostPath volume, and the one decision over it.
//
// The model is the one recorded for hostPath on this node class: the set of
// shareable host paths is configured on the NODE, by its administrator, and is
// never derived from the pod spec. A pod spec is attacker-shaped input, and the
// runtime's gRPC socket is reachable from a pod that shares the daemon's uid, so
// a request that carried its own permission would carry nothing. The allowlist
// therefore lives in a root-owned file (DefaultFile) that neither the node
// daemons (which run unprivileged) nor any pod can write, and Load refuses a
// file that someone other than root could have written.
//
// A native pod has no mount namespace, so a share is visible only at its own
// host path: a hostPath volume is granted only when every container mounts it
// at exactly that path, with no subPath. Nothing is copied, linked or rebased;
// the pod's Seatbelt profile is what makes the path reachable, and it is the
// boundary (pkg/sandbox emits the grant after its protected denies, so a share
// under /Users is the one exception to the /Users deny the node admin made).
//
// Delegation. The root-owned file may also delegate a prefix to one user
// account (Delegation). That user keeps their own entries under the prefix in
// a file they own, UserFile, inside a directory root made for them beside the
// node's file, so adding a share needs no root. The user's file is not
// trusted: LoadEffective re-checks every line of it against the root-owned
// delegation on every read (CheckDelegated: inside the prefix, no symlink,
// every component owned by the delegated uid, the prefix the same directory
// root named, the usual refusals). Removing the delegation from the root-owned
// file drops every entry the user made at the next create. A pod runs as the
// node's own user, which is never delegable, and can write neither file.
//
// Namespaces. A share line may name the namespaces whose pods it admits
// (namespaces=<n1>,<n2>,..., each a namespace name or a prefix pattern ending
// in one '*'); a line naming none is node-wide, as every line was before. The
// decision considers only the lines that admit the pod's namespace; among
// them the most specific path wins, then, on one path, the line naming the
// namespace most specifically (an exact name, then the longer pattern, then
// node-wide), and read-write only between lines equally specific. A
// refusal names the pod's namespace but never another one. A delegation may
// cap the namespaces its user's lines name: a line within the cap is admitted
// as written, a line naming none takes the cap, and a line outside it is
// dropped. A malformed namespaces= field fails the file, so a line is never
// read as node-wide by mistake.
//
// What a share does NOT change: the pod's processes still run as the node's
// unprivileged user, so writing into a share also needs the host's file
// permissions to allow that user (the documented setup grants it with an
// inheritable ACL). Files the pod creates are owned by that user.
package hostshare
