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
