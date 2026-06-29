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

// Package runtime implements the k3sm node runtime: the in-process realization of
// the apis runtime/v1 RuntimeServer. It wires the three subsystems —
// k3sm.io/runtimed/pkg/image (OCI pull → content-addressed cache → clonefile
// materialize → ad-hoc sign + signature-policy gate), k3sm.io/runtimed/pkg/sandbox
// (default-deny SBPL generation + the exec-shim Backend), and
// k3sm.io/runtimed/pkg/supervisor (posix_spawn + kqueue reaping) — behind the
// pod-granular gRPC contract.
//
// In M1 the Runtime is consumed in-process (k3sm imports it as a library); it is
// built against the M1 proto so the M2 daemon split is a relocation, not a
// redesign. It satisfies runtimev1.RuntimeServer:
//
//	var _ runtimev1.RuntimeServer = (*Runtime)(nil)
//
// CreatePod is the spine: validate the PodBox → materialize each container's
// rootfs (clonefile) → ad-hoc sign → enforce the SignaturePolicy gate BEFORE
// exec → generate+validate the per-pod SBPL → spawn each container through the
// exec-shim Backend (DYLD_INSERT_LIBRARIES carried through) → track status,
// streamed to WatchPodStatus subscribers. The runtime FAILS CLOSED if the
// sandbox backend is unavailable (it refuses to start the pod, never runs it
// unconfined).
package runtime
