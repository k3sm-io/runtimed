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

// Package wasmhost is the seam between the runtime daemon and the WebAssembly
// host process that runs a pod of the "wasm" RuntimeClass.
//
// A wasm pod is a native pod whose process is the k3sm-wasmhost helper: the
// daemon's start path builds a LaunchSpec against its own Bounds, writes it to
// a daemon-owned file, and rewrites the container argv to the helper plus
// exactly --spec=<path> and --pod-dir=<dir> (HostArgs). The helper
// (cmd/k3sm-wasmhost, not yet built) calls ParseArgs and ReadLaunchSpec, then
// hands the Validated result to an Engine, which takes its directories and its
// module through OpenPreopens. The builder and the parser live in this one
// package so the two ends cannot drift: there is no second encoding of the
// flags or the file anywhere else.
//
// This package is pure Go and must stay so. The wasmtime engine is cgo and lives
// in a subpackage that only the helper binary imports; the daemon links this
// package (the spec builder) and nothing of the engine. The import guard
// TestWasmtimeIsNotReachableFromTheDaemon pins that split.
// wasmhosttest.FakeEngine lets other packages' unit tests drive the seam
// without linking cgo.
//
// # Trust
//
// The launch spec is a trust boundary. The daemon decides which host
// directories a guest may reach; the helper, running confined as the pod, must
// not be able to widen that set by reading something the daemon did not write.
// So the spec is a closed, versioned, strictly decoded document read only from
// a file the helper's own uid owns in a directory nobody else may write:
// unknown, duplicate or case-variant keys, trailing data, a wrong version or an
// oversized file are refused. Containment is anchored to Bounds that never come
// from the spec (the pod directory and the persistent-volume root); every path
// is checked for shape and, on disk, for symlinked components; no writable
// preopen may overlap another; and an Engine only ever receives a Validated
// value, which nothing outside this package can construct without running
// Validate, and opens what it names through descriptors. The preopen list is
// typed and ordered: exactly one rootfs preopen at guest path "/" first, then
// volume preopens. There are no listeners, ports or sockets in the spec: a wasm
// guest has no inbound networking.
//
// A wasm pod shares the node's one OS trust domain. A guest that escapes the
// engine through a wasmtime or Cranelift bug holds what any native pod holds:
// the _k3sm identity under that pod's Seatbelt profile. wasm is not a tenant
// boundary; untrusted workloads belong in the "vm" RuntimeClass.
//
// # Stopping
//
// The helper owns the stop-grace timer. It turns its own SIGTERM into a
// cancellation of the context it passed to Engine.Run, and the engine stops
// the guest on that cancellation, inside the pod's termination grace period.
//
// Image scope: the ceiling is a single-platform wasi/wasm32 image manifest. A
// multi-platform index is beyond it.
package wasmhost
