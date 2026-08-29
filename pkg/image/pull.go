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

package image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// RegistryCredential is a private-registry pull credential (an imagePullSecret,
// M2.6). It is consumed ONLY by the pull client (passed to the registry transport
// as an Authorization header) and is NEVER written to disk / the pod dir — the
// M2.6 security invariant. The provider resolves it from the referenced
// docker-config Secret and supplies it via the runtime's CredentialResolver seam;
// the proto carries only a LocalObjectReference, never the bytes.
//
// The fields mirror a docker-config auth entry; either Username+Password or one of
// the token forms is set. The zero value authenticates anonymously.
type RegistryCredential struct {
	// Username and Password are basic-auth credentials.
	Username string
	// Password pairs with Username.
	Password string
	// Auth is the base64("username:password") form a docker config stores.
	Auth string
	// IdentityToken is an OAuth2 refresh/identity token (token-based registries).
	IdentityToken string
	// RegistryToken is a bearer token sent directly to the registry.
	RegistryToken string
}

// authenticator converts the credential to a go-containerregistry Authenticator.
func (c *RegistryCredential) authenticator() authn.Authenticator {
	return authn.FromConfig(authn.AuthConfig{
		Username:      c.Username,
		Password:      c.Password,
		Auth:          c.Auth,
		IdentityToken: c.IdentityToken,
		RegistryToken: c.RegistryToken,
	})
}

// FetchFunc resolves an image reference to a go-containerregistry image, using
// cred for private-registry auth (nil = anonymous) and policy to decide WHICH
// platform of a multi-platform image to resolve. The production fetcher is
// RemoteFetch (a registry pull); tests inject an in-memory image so pull/cache
// logic is exercised with no network.
//
// policy is a per-call argument (see PlatformPolicy): the effective sandbox
// backend is decided per pod, so it cannot be fixed at Puller construction.
type FetchFunc func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error)

// RemoteFetch fetches ref from a remote registry, resolving a multi-platform
// image to the one manifest policy allows. It is the production FetchFunc, and
// it is GLUE: every decision it makes lives in the pure, exported seams of
// platform.go (Candidates / SelectManifest / VerifyConfigPlatform).
//
// When cred is non-nil it authenticates with that credential (the
// imagePullSecret, M2.6); the credential lives only in this transport, never on
// disk.
//
// It closes every re-entry point for go-containerregistry's implicit
// linux/amd64 default (remote.makeOptions seeds options.platform with it):
//
//   - remote.WithPlatform is never passed, and remote.Image is never called on a
//     tag/ambiguous reference — the index is traversed explicitly here;
//   - Descriptor.Image() is called ONLY after the descriptor's media type is
//     asserted to be an image type, never on an index (where it would resolve
//     the child by the defaulted platform);
//   - ImageIndex.Image(hash) is never called (same defaulting);
//   - the selected child is re-resolved by EXPLICIT DIGEST
//     (ref.Context().Digest(...)), which go-containerregistry verifies against
//     the bytes it received;
//   - the resolved image's own config is verified last, so a mislabelled index
//     entry cannot smuggle a foreign-platform image through.
func RemoteFetch(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
	want, err := Candidates(policy)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, boundErr(err))
	}
	opts := []remote.Option{remote.WithContext(ctx)}
	if cred != nil {
		opts = append(opts, remote.WithAuth(cred.authenticator()))
	}
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, boundErr(err))
	}
	img, err := resolveImage(r, desc, want, opts)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	// The child's own config is the authority — an index descriptor's platform
	// is unsigned parent metadata (see VerifyConfigPlatform).
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("pull %q: image config: %w", ref, boundErr(err))
	}
	if _, err := VerifyConfigPlatform(cfg, want); err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	return img, nil
}

// resolveImage turns the fetched manifest descriptor into the one image want
// allows: an index is traversed explicitly, a single manifest is taken as-is
// (and verified by the caller), anything else is refused.
//
// Every error it returns is already bounded — either a k3sm platform error or a
// third-party one passed through boundErr — so the caller re-wraps it without a
// second bound.
func resolveImage(r name.Reference, desc *remote.Descriptor, want []Platform, opts []remote.Option) (ggcrv1.Image, error) {
	switch {
	case desc.MediaType.IsIndex():
		var idx ggcrv1.IndexManifest
		if err := json.Unmarshal(desc.Manifest, &idx); err != nil {
			// An index whose bytes do not parse can never yield a runnable
			// manifest, so the verdict is TERMINAL (ErrNoPlatformMatch) and the
			// json/ggcr message is quoted as bounded DATA rather than adopted:
			// v1.Hash's parser formats the whole offending digest string into
			// its error, and the index body is capped only by ggcr's 100 MiB
			// manifest limit.
			return nil, fmt.Errorf("parse image index: %v: %w", boundErr(err), ErrNoPlatformMatch)
		}
		selected, err := SelectManifest(&idx, want)
		if err != nil {
			return nil, err
		}
		return imageByDigest(r.Context().Digest(selected.Digest.String()), opts)
	case desc.MediaType.IsImage():
		// Safe: Descriptor.Image() applies the (defaulted) platform ONLY on the
		// index branch, which this is not.
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("resolve image manifest: %w", boundErr(err))
		}
		return img, nil
	default:
		// Decided verdict: REFUSE anything else rather than guess. This covers
		// the legacy Docker schema-1 types (which carry no platform information
		// at all) and a registry that serves a manifest with a missing or
		// unrecognised Content-Type — the OCI distribution spec requires that
		// header, and go-containerregistry's alternative (assume "image" and
		// warn) is precisely the kind of guess this item removes. The error
		// names the media type, so the case is diagnosable.
		return nil, fmt.Errorf("unsupported manifest media type %s: %w",
			quoteBounded(string(desc.MediaType), maxMediaTypeLen), ErrNoPlatformMatch)
	}
}

// imageByDigest resolves one index child by its EXPLICIT digest.
// go-containerregistry verifies the returned bytes against that digest, and the
// media type is re-asserted here so an index can never reach Descriptor.Image()
// (where the linux/amd64 default would resolve a child for us).
//
// name.Repository.Digest does not itself validate the string. What makes that
// safe is a two-part invariant on the digest reaching it:
//
//   - a PRESENT digest key was validated by v1.Hash.UnmarshalJSON during
//     json.Unmarshal of the index (known algorithm, hex body, exact length);
//   - an ABSENT digest key never invokes UnmarshalJSON at all — it leaves the
//     ZERO v1.Hash, which renders as ":" — so selectableChild rejects a child
//     with an empty algorithm or hex before selection can reach here.
func imageByDigest(ref name.Digest, opts []remote.Option) (ggcrv1.Image, error) {
	d, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch child %s: %w", quoteBounded(ref.DigestStr(), maxDigestLen), boundErr(err))
	}
	if !d.MediaType.IsImage() {
		return nil, fmt.Errorf("child %s served media type %s: %w",
			quoteBounded(ref.DigestStr(), maxDigestLen),
			quoteBounded(string(d.MediaType), maxMediaTypeLen), ErrNestedIndex)
	}
	img, err := d.Image()
	if err != nil {
		return nil, fmt.Errorf("resolve child %s: %w", quoteBounded(ref.DigestStr(), maxDigestLen), boundErr(err))
	}
	return img, nil
}

// PullResult reports the outcome of a Pull: the resolved manifest (as the apis
// type) and whether every blob was already cached (a full cache hit).
type PullResult struct {
	// Manifest is the pulled image manifest in the shared apis form.
	Manifest *runtimev1.ImageManifest
	// CacheHit is true when the config and all layers were already cached (no
	// blob was newly written) — i.e. a second pull of the same content.
	CacheHit bool

	// Lease pins this result's blobs against image GC and is returned HELD. The
	// caller releases it once it has recorded the reference that makes those
	// blobs reachable (Cache.RecordPodImage) — not before, or the window between
	// "the blob is on disk" and "something names it" reopens, and that is exactly
	// the window a concurrent reclaim would delete into.
	//
	// It is nil-safe: Release on a nil *Lease is a no-op, so a caller that fails
	// before recording, or a test that ignores the field, needs no branch. An
	// unreleased lease EXPIRES (DefaultLeaseTTL) rather than pinning the store
	// forever, so forgetting it costs a bounded delay in reclaim, never a leak.
	Lease *Lease
}

// ErrImageNotPresent is the decided verdict for a reference that is not present
// on this node under a policy that forbids fetching it (IMAGE_PULL_POLICY_NEVER).
// No registry round trip has been made when it is returned.
//
// It is deliberately a PLAIN sentinel and not a classified pull failure: the
// kubelet waiting-reason taxonomy (ErrImageNeverPull and its siblings) is a
// separate deliverable that consumes this sentinel with errors.Is — the wrapped
// chain out of Pull is the contract it builds on.
var ErrImageNotPresent = errors.New("image not present locally and the pull policy forbids fetching it")

// LocalIndex answers presence-BY-REFERENCE for the node: it records which
// references have been resolved locally, keyed (reference x platform), which the
// content-addressed blob store cannot answer on its own (blobs are keyed by
// digest, and a reference resolves to a digest only by asking a registry).
//
// It is a consumer-side seam, per the standards: the Puller states exactly what
// it needs to decide IfNotPresent/Never and to keep the record current.
// FileIndex is the production implementation; NoLocalIndex is the explicit
// "this node records nothing".
//
// Its entries are EDGES, never reachability roots — see FileIndex — so an
// implementation may never be consulted by the image GC.
type LocalIndex interface {
	// Lookup returns the manifest recorded for ref under policy's platform, and
	// ok=false when the reference has not been recorded.
	//
	// An index that cannot be READ returns an error, which is NOT a miss: a miss
	// would fail Never for an image that is present, and would send an
	// IfNotPresent pod to the registry at exactly the moment the operator asked
	// it not to go. The caller propagates the error instead.
	Lookup(ctx context.Context, ref string, policy PlatformPolicy) (manifest *runtimev1.ImageManifest, ok bool, err error)

	// Record records that ref resolved to manifest for platform.
	//
	// The Puller calls it ONLY after a pull has fully succeeded, with the
	// manifest IT resolved and verified and after every blob was committed. That
	// is the contract that keeps a recorded reference honest: an index written
	// from anything else — bytes re-fetched at lookup time, a manifest recorded
	// before its blobs landed — could report an image present that this node
	// never verified.
	Record(ctx context.Context, ref string, platform Platform, manifest *runtimev1.ImageManifest) error
}

// NoLocalIndex is the LocalIndex that records nothing: every reference is absent.
//
// The daemon's production binding is FileIndex; this one is for a caller that
// deliberately keeps no record (an ingest path with no presence question to
// answer, a test that wants the cold-node behavior). It is named rather than a
// nil check so such a call site says so. Its consequences are the safe ones:
// IfNotPresent degrades to the legacy pull-through (identical to the pre-M12
// behavior), and Never — which by definition never fetches — has no local image
// to run and fails with ErrImageNotPresent.
type NoLocalIndex struct{}

// Lookup reports every reference absent.
func (NoLocalIndex) Lookup(context.Context, string, PlatformPolicy) (*runtimev1.ImageManifest, bool, error) {
	return nil, false, nil
}

// Record discards the record. Under-recording is the SAFE direction — it can
// only send a pull to the registry that a record would have served locally, and
// can never make presence lie.
func (NoLocalIndex) Record(context.Context, string, Platform, *runtimev1.ImageManifest) error {
	return nil
}

// Puller pulls OCI images into a Cache using a FetchFunc, honoring the
// per-container imagePullPolicy against a LocalIndex.
type Puller struct {
	cache *Cache
	fetch FetchFunc
	index LocalIndex
}

// NewPuller returns a Puller writing into cache, fetching via fetch, and deciding
// presence-by-reference via index.
//
// All three arguments are REQUIRED: a nil fetch is an error, never a silent
// default to RemoteFetch. Which fetcher runs is the decision that chooses which
// platform's bytes land in the cache, so it is spelled out at the call site that
// makes it (runtime.New passes image.RemoteFetch) rather than substituted here.
// An implicit default is the exact shape of bug this package exists to remove —
// and it also hides the binding from tests, which then cannot tell a production
// wiring from a mis-wiring. index is required for the same reason: a caller with
// no index passes NoLocalIndex explicitly, so "this node cannot decide presence
// by reference yet" is stated rather than inferred from a nil field.
func NewPuller(cache *Cache, fetch FetchFunc, index LocalIndex) (*Puller, error) {
	if cache == nil {
		return nil, errors.New("image puller: cache is required")
	}
	if fetch == nil {
		return nil, errors.New("image puller: fetch is required (the production fetcher is image.RemoteFetch)")
	}
	if index == nil {
		return nil, errors.New("image puller: index is required (pass image.NoLocalIndex{} when the node has none)")
	}
	return &Puller{cache: cache, fetch: fetch, index: index}, nil
}

// Pull fetches ref and stores its config + layer blobs in the content-addressed
// cache, returning the manifest and whether it was a full cache hit. Blobs
// already present are not re-written, so the second pull of identical content
// reports CacheHit == true (acceptance M1.1-a1). cred (M2.6) is the imagePullSecret
// credential used for the registry fetch; it is confined to the fetch transport
// and never written to the cache or pod dir.
//
// policy selects WHICH platform of a multi-platform image is pulled. It is a
// per-call argument because the sandbox backend is resolved per pod; a zero
// policy fails closed here, before any round trip (see PlatformPolicy). The
// fetched image's own config is verified against the policy before a single blob
// is written, so the cache never holds bytes this node cannot run. The blob CAS
// is unaffected — digests are already per-platform.
//
// pull is the container's stamped imagePullPolicy and is OBEYED AS GIVEN:
//
//   - ALWAYS re-resolves the reference on every call, even for a reference this
//     node already has (cached blobs are still reused; it is the resolution that
//     must be fresh);
//   - IF_NOT_PRESENT returns the locally recorded image with ZERO registry
//     traffic, and falls through to a pull only on a miss — so a warm node
//     starts pods through a registry outage;
//   - NEVER makes no fetch attempt at all: a locally absent reference is
//     ErrImageNotPresent;
//   - UNSPECIFIED is the legacy pull-through — the pre-M12 behavior, which is
//     what an old provider that never stamps the field must keep getting. It is
//     never read as an implicit NEVER.
//
// This function NEVER derives a policy from the image tag. Defaulting
// (`:latest`/untagged -> Always) belongs to the embedded apiserver, which stamps
// it on the pod spec; the provider forwards that value verbatim and it arrives
// here already decided. A second derivation point would be free to disagree with
// the stamped spec, and `kubectl get pod -o yaml` would stop describing what the
// node did.
func (p *Puller) Pull(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy, pull runtimev1.ImagePullPolicy) (_ *PullResult, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The policy is resolved BEFORE any round trip (a zero policy fails closed
	// with no network at all) AND before the presence decision, so an invalid
	// platform policy is refused on every path rather than only the fetching
	// ones. The image's own config is verified against it HERE — at the choke
	// point every pull traverses — not only inside one FetchFunc. RemoteFetch
	// verifies it too, because it is exported and independently callable; but a
	// FetchFunc is a SEAM, and a fetcher that omits the check (or a test fake
	// that returns a platform-less image) must not be able to put
	// foreign-platform bytes in the cache.
	want, err := Candidates(policy)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	if pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT ||
		pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER {
		mfst, lease, present, err := p.presentLocally(ctx, ref, policy)
		if err != nil {
			return nil, err
		}
		if present {
			// No blob was written and no registry was contacted. The lease comes
			// back HELD — see PullResult.Lease.
			return &PullResult{Manifest: mfst, CacheHit: true, Lease: lease}, nil
		}
		if pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER {
			return nil, fmt.Errorf("image %q: %w", ref, ErrImageNotPresent)
		}
	}

	img, err := p.fetch(ctx, ref, cred, policy)
	if err != nil {
		return nil, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("pull %q: image config: %w", ref, boundErr(err))
	}
	// The platform the image's OWN config declares, as verified against this
	// pod's candidates — that is the half of the index key the reference does not
	// carry, and taking it from the verifier means the recorded key can only ever
	// be a platform this pull proved runnable here.
	resolved, err := VerifyConfigPlatform(cfg, want)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	wroteAny := false

	// The MANIFEST is resolved before any blob is written, because it — not the
	// object that hands over the bytes — is where every claimed digest comes from
	// (B129). img.ConfigName() and layer.Digest() are NOT used as claimed values:
	// go-containerregistry's partial helpers derive both by hashing the very
	// content being checked when the implementation carries no descriptor, so
	// comparing against them would prove self-consistency, not authenticity, and
	// could never fail in exactly the seam-swap this check exists to catch. The
	// manifest descriptors are additionally what the digest-pinned re-resolution
	// in imageByDigest anchored.
	mfst, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", ref, boundErr(err))
	}

	// LEASE THE WHOLE DIGEST SET before a single blob is even looked at — not
	// before the first WRITE. CommitBlob returns (false, nil) on a cache hit
	// without touching the file, so a blob this pull depends on can already be
	// present, already be old, and be named by nothing: deletable by a concurrent
	// reclaim during the very pull that needs it. The caller releases the lease
	// after it records the reference (PullResult.Lease); a failure below releases
	// it here, since a pull that returns an error records nothing.
	lease := p.cache.AcquireLease(manifestDescriptorDigests(mfst), 0)
	defer func() {
		if retErr != nil {
			lease.Release()
		}
	}()

	// Config blob.
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", ref, boundErr(err))
	}
	wrote, err := p.writeBlob(mfst.Config.Digest.String(), mfst.Config.Size, func(w io.Writer) error {
		_, werr := w.Write(rawCfg)
		return werr
	})
	if err != nil {
		return nil, err
	}
	wroteAny = wroteAny || wrote

	out := &runtimev1.ImageManifest{
		Reference:   ref,
		MediaType:   string(mfst.MediaType),
		Config:      descriptorFromGGCR(mfst.Config),
		Annotations: mfst.Annotations,
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layers %q: %w", ref, boundErr(err))
	}
	// The loop pairs layers[i] with mfst.Layers[i], so a divergence between the
	// two lists is refused here rather than indexed past (it used to panic on a
	// longer layer list, and silently mis-pair on an equal-length reordering — the
	// reordering is now also caught by the per-blob digest check below).
	if len(layers) != len(mfst.Layers) {
		return nil, fmt.Errorf("pull %q: image has %d layers but its manifest lists %d: %w",
			ref, len(layers), len(mfst.Layers), ErrManifestInconsistent)
	}
	for i, layer := range layers {
		desc := mfst.Layers[i]
		wrote, err := p.writeBlob(desc.Digest.String(), desc.Size, func(w io.Writer) error {
			rc, oerr := layer.Compressed()
			if oerr != nil {
				return oerr
			}
			defer rc.Close()
			_, cerr := io.Copy(w, rc)
			return cerr
		})
		if err != nil {
			return nil, err
		}
		wroteAny = wroteAny || wrote
		out.Layers = append(out.Layers, descriptorFromGGCR(desc))
	}

	// Record the reference LAST: every blob it names is now committed and
	// digest-verified, and the manifest recorded is the one this pull resolved —
	// never bytes re-read at lookup time. Recording earlier would let a lookup
	// answer "present" for a pull that had not finished writing.
	//
	// The entry is an EDGE, not a root (see FileIndex): it makes nothing
	// reachable, so it neither replaces the lease nor delays its release, and a
	// blob it names is still reclaimable the moment no pod records it.
	//
	// A failed record FAILS THE PULL. The blobs are on disk and re-pulling is
	// idempotent, so nothing is lost; and the two ways this can fail — the index
	// tree is unwritable, or it is not the tree this daemon owns
	// (ErrIndexNotOwned) — are exactly the conditions under which a LOOKUP must
	// not be believed either. Continuing would keep serving pods from an index
	// this daemon has just discovered it cannot maintain.
	if err := p.index.Record(ctx, ref, resolved, out); err != nil {
		return nil, fmt.Errorf("pull %q: record image index: %w", ref, err)
	}

	return &PullResult{Manifest: out, CacheHit: !wroteAny, Lease: lease}, nil
}

// manifestDescriptorDigests is every blob digest a go-containerregistry manifest
// names (config + layers), read from the MANIFEST DESCRIPTORS — the same values
// the blobs are committed under, so the lease and the commits structurally cannot
// name different content.
func manifestDescriptorDigests(mfst *ggcrv1.Manifest) []string {
	out := make([]string, 0, len(mfst.Layers)+1)
	out = append(out, mfst.Config.Digest.String())
	for _, l := range mfst.Layers {
		out = append(out, l.Digest.String())
	}
	return out
}

// presentLocally reports whether ref is on this node for policy's platform: the
// index must have recorded it AND every blob its manifest names must still be in
// the content-addressed store.
//
// The second half is not belt-and-braces. Presence-by-reference and the bytes
// have independent lifetimes (the cache GC evicts blobs), and a stale index entry
// would otherwise start a container whose layers are gone — so a recorded
// reference with missing blobs is a MISS, which sends IfNotPresent back to the
// registry and fails Never honestly.
func (p *Puller) presentLocally(ctx context.Context, ref string, policy PlatformPolicy) (*runtimev1.ImageManifest, *Lease, bool, error) {
	mfst, ok, err := p.index.Lookup(ctx, ref, policy)
	if err != nil {
		return nil, nil, false, fmt.Errorf("image index lookup %q: %w", ref, err)
	}
	if !ok || mfst == nil {
		return nil, nil, false, nil
	}
	// LEASE BEFORE THE PRESENCE CHECK, not after it. This path writes nothing at
	// all, so there is no commit to hang a pin on and no mtime change for a grace
	// window to notice: the blobs are old, present, and — until the caller records
	// the reference — named by nothing. Checking presence first and leasing second
	// would leave the whole check-then-use interval open to a reclaim that deletes
	// the very blobs just found present.
	lease := p.cache.AcquireLease(manifestDigests(mfst), 0)
	if !p.cache.Has(mfst.GetConfig().GetDigest()) {
		lease.Release()
		return nil, nil, false, nil
	}
	for _, l := range mfst.GetLayers() {
		if !p.cache.Has(l.GetDigest()) {
			lease.Release()
			return nil, nil, false, nil
		}
	}
	return mfst, lease, true, nil
}

// manifestDigests is every blob digest a resolved manifest names — the config
// plus the layers, which is exactly what the content-addressed store holds for an
// image (the manifest itself is never committed as a blob).
func manifestDigests(mfst *runtimev1.ImageManifest) []string {
	out := make([]string, 0, len(mfst.GetLayers())+1)
	if d := mfst.GetConfig().GetDigest(); d != "" {
		out = append(out, d)
	}
	for _, l := range mfst.GetLayers() {
		if d := l.GetDigest(); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// writeBlob commits the blob for digest via fill, verifying the bytes against
// digest. size is the descriptor's declared size (the CommitBlob resource guard).
// It returns whether a new blob was written (false == cache hit for this blob).
//
// It is a THIN DELEGATION to Cache.CommitBlob, deliberately: the CAS integrity
// invariant has exactly one home, and that home is on *Cache — reachable by any
// ingest path (B117's tarball ingest links this package in-process) rather than
// locked behind a *Puller, whose constructor requires a FetchFunc an ingest path
// has no business supplying.
func (p *Puller) writeBlob(digest string, size int64, fill func(io.Writer) error) (wrote bool, err error) {
	return p.cache.CommitBlob(digest, size, fill)
}

// descriptorFromGGCR converts a go-containerregistry descriptor to the apis type.
func descriptorFromGGCR(d ggcrv1.Descriptor) *runtimev1.Descriptor {
	out := &runtimev1.Descriptor{
		MediaType:   string(d.MediaType),
		Digest:      d.Digest.String(),
		Size:        d.Size,
		Urls:        d.URLs,
		Annotations: d.Annotations,
	}
	if d.Platform != nil {
		out.Platform = &runtimev1.Platform{
			Os:           d.Platform.OS,
			Architecture: d.Platform.Architecture,
			Variant:      d.Platform.Variant,
			OsVersion:    d.Platform.OSVersion,
		}
	}
	return out
}
