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

// Package crilog writes a container's output to disk in the CRI log format —
// the on-disk contract between a container runtime and the kubelet.
//
// One line per chunk:
//
//	<RFC3339Nano> <stdout|stderr> <P|F> <content>\n
//
// The reader (k8s.io/cri-client/pkg/logs, which the k3sm node re-implements)
// concatenates consecutive P chunks into one logical line and treats an F chunk
// as that line's end. A line longer than MaxLineBytes is therefore split rather
// than truncated: nothing is dropped, and a reader reassembles it exactly.
//
// # The division of labour this package sits inside
//
// runtimed is the log WRITER and only the writer. It opens the file the node
// named (PodBox.log_directory), appends to it, and reopens it on request
// (ReopenContainerLog) when the node rotates it. It never reads a log file,
// never rotates one, never deletes one, and keeps no in-memory copy of a
// container's output. The node (k3sm's provider) owns the directory tree, the
// reader `kubectl logs` is served from, the rotation manager and every deletion
// — the same split the kubelet and containerd have upstream.
//
// # Provenance
//
// The chunking semantics are a port of containerd's CRI logger
// (internal/cri/io/logger.go, Apache-2.0) and the P/F tag vocabulary is
// kubernetes' CRI constants (staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/
// constants.go, Apache-2.0). Both are reproduced here in Go rather than
// imported because neither upstream module is a dependency of this repo and
// both carry a CRI proto surface k3sm does not speak.
package crilog
