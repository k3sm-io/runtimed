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

// Package execsession runs one `kubectl exec` session: it wires a started
// command's stdio to an exec stream, carries stdin and terminal resizes the
// other way, and reports the command's exit as the stream's last frame.
//
// It is a leaf that imports no pkg/runtime type, because two servers run the
// same session: the node runtime daemon, for a container it spawned directly,
// and a container's resident shim, which serves shimv1.ContainerShim.Exec with
// the very runtime/v1 messages. Stream is the method set both generated stream
// types share.
//
// Session lifetime invariant: a session is bounded by its stream. A caller
// builds the command with exec.CommandContext(stream.Context(), ...), so the
// command is killed when the stream ends, and every goroutine here ends with
// the command's output or the stream.
package execsession
