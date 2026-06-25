package mount

import "context"

// Resolver supplies the byte content for ConfigMap/Secret-backed volume sources
// and mints ServiceAccount tokens. The runtime proto carries only the source
// reference (name / audience), not the data, because runtimed never talks to the
// apiserver: the provider (k3sm), which holds the apiserver client, supplies a
// Resolver, and unit tests supply a fake. Defined at the consumer per the k3sm
// Go standards (small, fakeable seam).
//
// namespace is the pod's namespace (PodBox.namespace); name is the referenced
// object's name. A missing source should be reported as an error wrapping
// os.ErrNotExist so the materializer can honor an `optional: true` source by
// skipping it (any other error fails the pod).
type Resolver interface {
	// ConfigMap returns the key→bytes data of a ConfigMap.
	ConfigMap(ctx context.Context, namespace, name string) (map[string][]byte, error)
	// Secret returns the key→bytes data of a Secret.
	Secret(ctx context.Context, namespace, name string) (map[string][]byte, error)
	// ServiceAccountToken mints a bound token for the pod's ServiceAccount with
	// the requested audience and TTL (the in-pod-kubectl path). The provider's
	// implementation knows which ServiceAccount the pod uses; audience "" defaults
	// to the apiserver.
	ServiceAccountToken(ctx context.Context, namespace, audience string, expirationSeconds int64) (string, error)
}
