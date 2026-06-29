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

package supervisor

import "context"

// NodeNetwork is the M1 single-node PodNetwork: every pod shares the node IP (no
// per-pod lo0 alias yet). It is the no-op seam darwin-net replaces with real IPAM
// + a Service proxy in a later milestone.
type NodeNetwork struct {
	// IP is the node IP handed to every pod. Empty yields the loopback default.
	IP string
}

// Setup returns the node IP for podID (single-node: the pod IP is the node IP).
func (n NodeNetwork) Setup(_ context.Context, _ string) (string, error) {
	if n.IP == "" {
		return "127.0.0.1", nil
	}
	return n.IP, nil
}
