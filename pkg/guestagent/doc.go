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

// Package guestagent is the in-guest half of the k3sm vm-pod boundary: the
// guest/v1 GuestAgent service that answers Health, ContainerEvents, Exec, Logs,
// Stats and Stop for the ONE pod its micro-VM booted.
//
// It is the far end of a route that already exists. pkg/runtime has shipped the
// host side — execGuest, getLogsGuest, vmPodStats, watchGuestContainerEvents —
// since B101/B107, and until this package existed those routes could only be
// exercised against in-process fakes: nothing anywhere answered the RPCs, and
// guest.proto's api_version handshake had a constant on neither side. This is that
// far end, and APIVersion is that constant.
//
// # Where it runs, and what that costs
//
// It is served over AF_VSOCK by cmd/k3sm-guest-init, PID 1 of the guest. The
// transport is the guest's only channel to the outside: there is no network path
// to it, and the per-pod VM host process relays it to a runtimed-PRIVATE unix
// socket that no pod's sandbox profile ever allows.
//
// # The five seams
//
// Everything the server needs from the running guest arrives through five small
// consumer interfaces — Runner, Sampler, Logs, Execer and Statusr — plus the
// concrete Events fan-out. That shape is not decoration: it is what lets the whole
// service, including its pod-id enforcement and its bounds, be driven under
// `go test -race` on darwin with no VM, no Linux and no cgroup hierarchy. The real
// implementations live in cmd/k3sm-guest-init, behind GOOS=linux.
//
// # Single pod, asserted not assumed
//
// One VM hosts exactly one pod, so every request is implicitly scoped. Requests
// still carry pod_id and the server REJECTS any that is not the pod it booted
// (guest.proto: "the id is an assertion the caller reached the guest it meant to
// reach, not a selector over several"). `container` is the real selector within
// the pod, and it is resolved against what the pod declared.
//
// # Trust direction
//
// The host treats everything this agent returns as guest-controlled data. That is
// the host's business, but it has a consequence here: this package must not
// AMPLIFY. Reads are bounded, ring buffers are bounded, event queues are bounded
// and drop rather than grow, and no unbounded guest-shaped string is relayed.
package guestagent
