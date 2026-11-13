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
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/registryfetch"
)

// RegistryCredential is a private-registry pull credential (an imagePullSecret).
// It is consumed only by the pull client (passed to the registry transport
// as an Authorization header) and is never written to disk / the pod dir — the
// security invariant. The provider resolves it from the referenced
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

// registryfetchCredential converts the credential to the registryfetch form,
// field for field, so a direct blob fetch authenticates exactly as
// authenticator() does for the image fetch. A nil credential stays nil, which
// registryfetch reads as anonymous, as remoteFetch does.
func (c *RegistryCredential) registryfetchCredential() *registryfetch.Credential {
	if c == nil {
		return nil
	}
	return &registryfetch.Credential{
		Username:      c.Username,
		Password:      c.Password,
		Auth:          c.Auth,
		IdentityToken: c.IdentityToken,
		RegistryToken: c.RegistryToken,
	}
}

// registryTransport is the transport a registry round trip that pins none of
// its own is made over: the header-bounded externalTransport (a clone of
// http.DefaultTransport, so its proxy function, dial and TLS timeouts and the
// system TLS roots, plus responseHeaderTimeout), or go-containerregistry's
// remote.DefaultTransport when externalTransport is nil because
// http.DefaultTransport was replaced. RemoteFetch and RemoteMirrorFetch pass
// it to remote.WithTransport, which is last-wins, so it must carry the header
// bound itself or it would undo the one remoteFetch installs first. ggcr wraps
// it in its retry (and debug logger) layer, because it is not a
// transport.Wrapper. It is named here so the direct blob route (BlobSource)
// and the image fetch share one dial, TLS, proxy and header-bound story.
func registryTransport() http.RoundTripper {
	if tr := externalTransport(); tr != nil {
		return tr
	}
	return remote.DefaultTransport
}

// BlobSource is the direct registry route to one reference's blobs: the
// transport, scheme and credential the image fetch for that reference uses,
// in the form registryfetch.Registry.Blob takes.
//
// Ref is the reference as registryfetch should be handed it: fully qualified
// (registry, repository and tag or digest spelled out), because registryfetch
// parses with name.StrictValidation while the image fetch accepts a short
// name ("ubuntu"). It names the registry and repository the image fetch
// dialled, so Credential is never presented to a different host.
type BlobSource struct {
	Ref        string
	Registry   registryfetch.Registry
	Credential *registryfetch.Credential
}

// LogValue is the slog form of a BlobSource: the reference, the plain-HTTP flag
// and whether a credential is present, never the credential's secret fields.
// It is a value-receiver method so that a BlobSource and a pointer to one both
// log redacted, and it does not read Credential's fields at all, so the
// redaction holds whether Credential stays a pointer or becomes a value.
func (s BlobSource) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("ref", s.Ref),
		slog.Bool("plainHTTP", s.Registry.PlainHTTP),
		slog.Bool("credential", s.Credential != nil),
	)
}

// String renders the same redacted form as LogValue, for %v and %+v.
func (s BlobSource) String() string {
	return fmt.Sprintf("BlobSource{ref=%s plainHTTP=%t credential=%t}", s.Ref, s.Registry.PlainHTTP, s.Credential != nil)
}

// GoString renders the same redacted form for %#v.
func (s BlobSource) GoString() string { return s.String() }

// BlobSourceFunc yields the BlobSource for ref fetched with cred. It is the
// direct-blob counterpart of a FetchFunc and must yield the transport, scheme
// and credential that FetchFunc uses for the same arguments; RemoteBlobSource
// is the counterpart of RemoteFetch.
type BlobSourceFunc func(ref string, cred *RegistryCredential) (BlobSource, error)

// RemoteBlobSource is the BlobSourceFunc paired with RemoteFetch:
// registryTransport, the scheme go-containerregistry infers for ref's registry
// (PlainHTTP false, so no name.Insecure, exactly as RemoteFetch parses), and
// cred converted field for field (nil stays anonymous).
func RemoteBlobSource(ref string, cred *RegistryCredential) (BlobSource, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return BlobSource{}, fmt.Errorf("parse reference %q: %w: %w", ref, ErrInvalidReference, boundErr(err))
	}
	return BlobSource{
		Ref:        r.Name(),
		Registry:   registryfetch.Registry{Transport: registryTransport()},
		Credential: cred.registryfetchCredential(),
	}, nil
}

// FetchFunc resolves an image reference to a go-containerregistry image, using
// cred for private-registry auth (nil = anonymous) and policy to decide which
// platform of a multi-platform image to resolve. The production fetcher is
// RemoteFetch (a registry pull); tests inject an in-memory image so pull/cache
// logic is exercised with no network.
//
// policy is a per-call argument (see PlatformPolicy): the effective sandbox
// backend is decided per pod, so it cannot be fixed at Puller construction.
type FetchFunc func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error)

// ErrInvalidReference is the decided verdict for an image reference that is not
// a well-formed OCI reference at all. It is terminal: no round trip was made and
// no retry can help, because parsing the same string again yields the same
// answer — which is what separates it from every other pull failure.
//
// It exists so a consumer can classify the failure with errors.Is instead of
// matching go-containerregistry's message text (GO-STANDARDS §Errors); the
// runtime maps it to the kubelet's InvalidImageName waiting reason. The parser's
// own error stays in the chain, bounded (boundErr), because it names the
// offending reference and a caller-supplied string is DATA, never a message to
// adopt.
var ErrInvalidReference = errors.New("image reference does not parse")

// RemoteFetch fetches ref from a remote registry, resolving a multi-platform
// image to the one manifest policy allows. It is the production FetchFunc, and
// it is GLUE: every decision it makes lives in the pure, exported seams of
// platform.go (Candidates / SelectManifest / VerifyConfigPlatform).
//
// When cred is non-nil it authenticates with that credential (the
// imagePullSecret); the credential lives only in this transport, never on
// disk.
//
// It closes every re-entry point for go-containerregistry's implicit
// linux/amd64 default (remote.makeOptions seeds options.platform with it):
//
//   - remote.WithPlatform is never passed, and remote.Image is never called on a
//     tag/ambiguous reference — the index is traversed explicitly here;
//   - Descriptor.Image() is called only after the descriptor's media type is
//     asserted to be an image type, never on an index (where it would resolve
//     the child by the defaulted platform);
//   - ImageIndex.Image(hash) is never called (same defaulting);
//   - the selected child is re-resolved by explicit DIGEST
//     (ref.Context().Digest(...)), which go-containerregistry verifies against
//     the bytes it received;
//   - the resolved image's own config is verified last, so a mislabelled index
//     entry cannot smuggle a foreign-platform image through.
func RemoteFetch(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w: %w", ref, ErrInvalidReference, boundErr(err))
	}
	return splitFetch(ctx, r, ref, cred, policy, registryTransport())
}

// splitFetch is remoteFetch over tr split by origin (registryfetch's
// OriginSplit, the transport Session uses for blobs): cred authenticates only
// requests to r's registry, and a redirect to another host goes over plain tr,
// so neither the credential nor that host's 401 challenge reaches the token
// logic. cred rides the split transport, so remoteFetch gets none.
func splitFetch(ctx context.Context, r name.Reference, ref string, cred *RegistryCredential, policy PlatformPolicy, tr http.RoundTripper) (ggcrv1.Image, error) {
	reg := registryfetch.Registry{Transport: tr}
	rt, err := reg.OriginSplit(ctx, r.Context(), cred.registryfetchCredential())
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, boundErr(err))
	}
	return remoteFetch(ctx, r, ref, nil, policy, remote.WithTransport(rt))
}

// remoteFetch is the registry round trip shared by every fetcher: RemoteFetch,
// RemoteInsecureFetch, RemoteMirrorFetch and the flat registry's endpointFetch.
// r is the ALREADY-PARSED reference (a cluster mirror and an admitted cluster
// registry parse with name.Insecure, see Mirror.PlainHTTP), and ref is the reference as the caller
// spells it, used only in messages.
//
// Sharing it is deliberate: every fail-closed property documented on RemoteFetch
// is a property of THIS function, so the mirror path cannot drift into a second
// fetcher with a weaker platform story.
//
// extra carries a transport a caller pins (the flat registry's endpoint dial and
// trust anchor); it is appended after the defaults, the header-bounded external
// transport included, so it wins and rides every round trip, the index children
// included.
func remoteFetch(ctx context.Context, r name.Reference, ref string, cred *RegistryCredential, policy PlatformPolicy, extra ...remote.Option) (ggcrv1.Image, error) {
	want, err := Candidates(policy)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	rctx, disarm, cancel := resolveContext(ctx, resolveTimeout)
	opts := []remote.Option{remote.WithContext(rctx)}
	// The header-bounded transport goes BEFORE extra: go-containerregistry
	// applies options in order and WithTransport is a plain assignment, so a
	// caller's own transport (the flat registry's restricted dial) still wins.
	if tr := externalTransport(); tr != nil {
		opts = append(opts, remote.WithTransport(tr))
	}
	opts = append(opts, extra...)
	if cred != nil {
		opts = append(opts, remote.WithAuth(cred.authenticator()))
	}
	img, err := resolveRemote(r, ref, want, opts)
	if err == nil && !disarm() {
		// The bound fired after the last resolve round trip returned but before
		// it could be disarmed: rctx is cancelled, so the image's layer fetches
		// would fail. Report the bound rather than hand that image on.
		err = context.Cause(rctx)
	}
	if err != nil {
		cancel()
		if ctx.Err() == nil && errors.Is(context.Cause(rctx), errResolveBound) {
			// %v, not %w, for the cause: it wraps context.Canceled, and a
			// registry that stopped answering is about the host, not a caller
			// that gave up (see mirrorFallbackEligible).
			return nil, fmt.Errorf("pull %q: %w after %s: %v", ref, ErrPullResolveTimeout, resolveTimeout, err)
		}
		return nil, err
	}
	return img, nil
}

// ErrPullResolveTimeout is returned (wrapped) when resolving a reference (the
// manifest or index, the selected child and the image config, with any token
// round trip they need) does not finish within the resolve bound. It is an
// ordinary fetch failure; a cancelled caller context is reported as that
// cancellation, never as this.
var ErrPullResolveTimeout = errors.New("image: pull resolve timed out")

// defaultResolveTimeout bounds the resolve step of one pull. Every round trip
// in it moves a few kilobytes, so two minutes is far above any healthy
// registry and below the time a stuck one would otherwise hold the pull.
const defaultResolveTimeout = 2 * time.Minute

// resolveTimeout is the resolve bound remoteFetch applies; tests shorten it.
var resolveTimeout = defaultResolveTimeout

// errResolveBound is the cancellation cause resolveContext records when the
// bound fires; remoteFetch turns it into ErrPullResolveTimeout.
var errResolveBound = errors.New("resolve bound elapsed")

// resolveContext derives the context the resolve round trips run under: it is
// cancelled when parent is, and also when d elapses before disarm is called.
//
// It is a disarmable bound rather than context.WithTimeout because
// go-containerregistry keeps the context of the options a descriptor was
// fetched with inside the lazy image it returns, and fetches every layer under
// it. A deadline would cap those later layer fetches, and a deferred cancel
// would fail them outright. disarm stops the timer once the resolve is done
// (it reports false if the timer already fired), after which the context ends
// only with parent, so the layer fetches keep the caller's own lifetime.
// cancel releases the context on a failed resolve; on success it is left for
// parent to end, as the image still uses it.
func resolveContext(parent context.Context, d time.Duration) (ctx context.Context, disarm func() bool, cancel func()) {
	c, cancelCause := context.WithCancelCause(parent)
	t := time.AfterFunc(d, func() { cancelCause(errResolveBound) })
	return c, t.Stop, func() { t.Stop(); cancelCause(context.Canceled) }
}

// externalTransport is the transport an external registry pull uses: a clone
// of http.DefaultTransport (its proxy function and dial and TLS timeouts kept)
// that also bounds the wait for response headers. It is built once, so pulls
// share its connection pool, and the global is never mutated. It is nil when
// http.DefaultTransport is not an *http.Transport (a test or embedder replaced
// it), in which case the library's default stays in place. It is a variable
// so a test can install a fresh onceExternalTransport after changing the bound.
var externalTransport = onceExternalTransport()

// onceExternalTransport returns a function that builds the external transport
// on first use, reading responseHeaderTimeout then, and returns that one
// transport on every later call.
func onceExternalTransport() func() http.RoundTripper {
	return sync.OnceValue(func() http.RoundTripper {
		if tr := newExternalTransport(responseHeaderTimeout); tr != nil {
			return tr
		}
		return nil
	})
}

// externalMaxIdleConnsPerHost is the idle connection cap per registry host, the
// value go-containerregistry's own default transport uses (http.Transport's
// zero value would mean 2, too few for parallel layer fetches).
const externalMaxIdleConnsPerHost = 50

// newExternalTransport clones http.DefaultTransport with the given header
// bound, or returns nil when the default is not an *http.Transport.
func newExternalTransport(headerTimeout time.Duration) *http.Transport {
	def, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil
	}
	tr := def.Clone()
	tr.ResponseHeaderTimeout = headerTimeout
	tr.MaxIdleConnsPerHost = externalMaxIdleConnsPerHost
	return tr
}

// resolveRemote is the resolve step of remoteFetch: fetch the manifest, select
// and resolve the one image want allows, and verify its config.
func resolveRemote(r name.Reference, ref string, want []Platform, opts []remote.Option) (ggcrv1.Image, error) {
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
		img, err := imageByDigest(r.Context().Digest(selected.Digest.String()), opts)
		if err != nil {
			return nil, err
		}
		// The index's own digest is what the reference pointed at, and it is
		// known only here: carry it with the child so ingest can record it
		// (ImageManifest.index_digest). go-containerregistry computed it from
		// the bytes it received, and verified them against it when the
		// reference was pinned by digest.
		return indexChild{Image: img, index: desc.Digest.String()}, nil
	case desc.MediaType.IsImage():
		// Safe: Descriptor.Image() applies the (defaulted) platform only on the
		// index branch, which this is not.
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("resolve image manifest: %w", boundErr(err))
		}
		return img, nil
	default:
		// Decided verdict: refuse anything else rather than guess. This covers
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

// indexChild is an image selected out of a multi-platform index, carrying the
// digest of the index it was selected from. It is the one way a fetcher hands
// that digest to ingest without widening FetchFunc: ingest asks for it with
// resolvedIndexDigest, and every other method is the child's own.
type indexChild struct {
	ggcrv1.Image
	index string
}

// resolvedIndexDigest is the digest of the index img was selected from, or ""
// when img was not reached through one (a single manifest, a test fake, an
// image built in memory).
func resolvedIndexDigest(img ggcrv1.Image) string {
	if c, ok := img.(indexChild); ok {
		return c.index
	}
	return ""
}

// imageByDigest resolves one index child by its explicit digest.
// go-containerregistry verifies the returned bytes against that digest, and the
// media type is re-asserted here so an index can never reach Descriptor.Image()
// (where the linux/amd64 default would resolve a child for us).
//
// name.Repository.Digest does not itself validate the string. What makes that
// safe is a two-part invariant on the digest reaching it:
//
//   - a present digest key was validated by v1.Hash.UnmarshalJSON during
//     json.Unmarshal of the index (known algorithm, hex body, exact length);
//   - an absent digest key never invokes UnmarshalJSON at all — it leaves the
//     zero v1.Hash, which renders as ":" — so selectableChild rejects a child
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

	// Fetched reports whether this result required a REGISTRY ROUND TRIP: true
	// when the reference was resolved against a registry (the upstream one, this
	// node's own ingest registry, or a cluster mirror), false when it was served
	// from the local index without contacting anything.
	//
	// It is NOT CacheHit inverted, and the two must not be conflated. CacheHit
	// answers "did this pull write any blob", which is false for an Always pull
	// of content already on disk — a pull that did contact a registry, re-resolve
	// the tag and could have found a different digest. Fetched answers the
	// question a consumer building the kubelet's Pulled event asks instead:
	// "Successfully pulled image %q in %v" describes a round trip, and "Container
	// image %q already present on machine" describes its absence. Reporting the
	// second for an Always pull would tell an operator no registry was consulted
	// when one was.
	Fetched bool

	// Descriptor is the resolved manifest's OWN content descriptor: media type,
	// digest (what a user reads as the image id) and size.
	//
	// It is reported because nothing downstream can re-derive it: the store
	// commits config and layer blobs and never the manifest, so a caller that
	// wanted the image id would have to re-encode the manifest and would get a
	// different digest. Nil only when the index recorded no manifest (an entry
	// written before this store retained them).
	Descriptor *runtimev1.Descriptor

	// Platform is the platform half of the index key this pull resolved to —
	// the entry the pull recorded, so a caller can read back exactly what was
	// written. It is not ImageManifest.platform, which is populated only when the
	// reference came through a multi-platform index.
	Platform Platform

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
// It is deliberately a plain sentinel and not a classified pull failure: the
// runtime maps it to the kubelet waiting reason (ErrImageNeverPull and its
// siblings, pullFailureReason in pkg/runtime) with errors.Is — the wrapped chain
// out of Pull is the contract.
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
// Its entries are edges, never reachability roots — see FileIndex — so an
// implementation may never be consulted by the image GC.
type LocalIndex interface {
	// Lookup returns the ENTRY recorded for ref under policy's platform, and
	// ok=false when the reference has not been recorded.
	//
	// An index that cannot be READ returns an error, which is not a miss: a miss
	// would fail Never for an image that is present, and would send an
	// IfNotPresent pod to the registry at exactly the moment the operator asked
	// it not to go. The caller propagates the error instead.
	Lookup(ctx context.Context, ref string, policy PlatformPolicy) (entry IndexEntry, ok bool, err error)

	// Record records the entry: that its reference resolved to its manifest for
	// its platform.
	//
	// The Puller calls it only after a pull has fully succeeded, with the
	// manifest IT resolved and verified and after every blob was committed. That
	// is the contract that keeps a recorded reference honest: an index written
	// from anything else — bytes re-fetched at lookup time, a manifest recorded
	// before its blobs landed — could report an image present that this node
	// never verified.
	Record(ctx context.Context, entry IndexEntry) error
}

// NoLocalIndex is the LocalIndex that records nothing: every reference is absent.
//
// The daemon's production binding is FileIndex; this one is for a caller that
// deliberately keeps no record (an ingest path with no presence question to
// answer, a test that wants the cold-node behavior). It is named rather than a
// nil check so such a call site says so. Its consequences are the safe ones:
// IfNotPresent degrades to the legacy pull-through (identical to the behavior
// before the local image index existed), and Never — which by definition never fetches — has no local image
// to run and fails with ErrImageNotPresent.
type NoLocalIndex struct{}

// Lookup reports every reference absent.
func (NoLocalIndex) Lookup(context.Context, string, PlatformPolicy) (IndexEntry, bool, error) {
	return IndexEntry{}, false, nil
}

// Record discards the record. Under-recording is the safe direction — it can
// only send a pull to the registry that a record would have served locally, and
// can never make presence lie.
func (NoLocalIndex) Record(context.Context, IndexEntry) error {
	return nil
}

// Puller pulls OCI images into a Cache using a FetchFunc, honoring the
// per-container imagePullPolicy against a LocalIndex.
type Puller struct {
	cache *Cache
	fetch FetchFunc
	index LocalIndex

	// floorBytes and freeBytes are the disk-pressure admission seam (pullgate.go).
	// Both zero values mean the production defaults, which are fail-closed.
	floorBytes uint64
	freeBytes  FreeBytesFunc

	// mirrors and mirrorFetch are the CLUSTER MIRROR fallback (mirror.go), set
	// together by WithMirrors and both nil by default — a nil pair is a node with
	// no cluster to fall back to, and restores the pre-mirror behavior exactly.
	mirrors     MirrorSource
	mirrorFetch MirrorFetchFunc

	// clusterRegistryHosts is the raw list WithClusterRegistries was given and
	// clusterRegistries is its validated membership set, built once by NewPuller
	// so a malformed authority is a construction error rather than a spelling
	// that silently never matches. clusterFetch is the plain-HTTP fetcher those
	// authorities are dialled with; all three are set together or not at all
	// (see WithClusterRegistries, and the half-wiring refusal in NewPuller).
	clusterRegistryHosts []string
	clusterRegistries    clusterRegistrySet
	clusterFetch         FetchFunc

	// localRegistry is this node's own ingest registry authority, consulted
	// FIRST for a reference that names no registry (WithLocalRegistry). Empty —
	// the default — switches the whole bare-name behavior off.
	localRegistry string

	// flatConfig is what WithFlatRegistry was given and flat its validated form,
	// built by NewPuller; nil switches the flat-name mapping off (flatregistry.go).
	flatConfig FlatRegistry
	flat       *flatRegistry

	// log reports mirror fallback (WithPullLogger). Nil discards. The primary
	// path logs nothing, so a puller without a logger is silent as before.
	log *slog.Logger

	// localBlobs is a same-volume blob store consulted before each blob is
	// fetched (WithLocalBlobSource). Nil — the default — fetches every blob.
	localBlobs LocalBlobSource

	// layerStallWindow is how long a layer body may deliver no byte before its
	// fetch is aborted with ErrLayerBodyStalled (stallread.go). Zero means
	// defaultLayerStallWindow; tests set it directly.
	layerStallWindow time.Duration

	// remoteBlobs and mirrorBlobs are the direct blob routes paired with fetch
	// and mirrorFetch (WithRegistryBlobSource); nil yields no route for that
	// path. The flat registry's route is its own (flatRegistry.blobs), because
	// its transport is built here, not injected.
	remoteBlobs BlobSourceFunc
	mirrorBlobs MirrorBlobSourceFunc

	// partials keeps the layer bytes a cut fetch already received, so the next
	// pull resumes with a Range request (WithPartialStore). Nil — the default —
	// fetches every layer from byte 0.
	partials *registryfetch.PartialStore
}

// primaryBlobSource yields the direct blob route for ref on the primary path
// (primaryFetch), fetched with cred. ok is false when the path has none: no
// WithRegistryBlobSource, or an authority WithClusterRegistries admitted,
// whose plain-HTTP fetcher has no paired route.
func (p *Puller) primaryBlobSource(ref string, cred *RegistryCredential) (_ BlobSource, ok bool, _ error) {
	if p.remoteBlobs == nil || p.configuredClusterRegistry(ref) {
		return BlobSource{}, false, nil
	}
	src, err := p.remoteBlobs(ref, cred)
	if err != nil {
		return BlobSource{}, false, err
	}
	return src, true, nil
}

// NewPuller returns a Puller writing into cache, fetching via fetch, and deciding
// presence-by-reference via index.
//
// All three arguments are required: a nil fetch is an error, never a silent
// default to RemoteFetch. Which fetcher runs is the decision that chooses which
// platform's bytes land in the cache, so it is spelled out at the call site that
// makes it (runtime.New passes image.RemoteFetch) rather than substituted here.
// An implicit default is the exact shape of bug this package exists to remove —
// and it also hides the binding from tests, which then cannot tell a production
// wiring from a mis-wiring. index is required for the same reason: a caller with
// no index passes NoLocalIndex explicitly, so "this node cannot decide presence
// by reference yet" is stated rather than inferred from a nil field.
//
// opts adjust only the disk-pressure admission seam, whose defaults are
// fail-closed and therefore safe to leave implicit — see PullerOption.
func NewPuller(cache *Cache, fetch FetchFunc, index LocalIndex, opts ...PullerOption) (*Puller, error) {
	if cache == nil {
		return nil, errors.New("image puller: cache is required")
	}
	if fetch == nil {
		return nil, errors.New("image puller: fetch is required (the production fetcher is image.RemoteFetch)")
	}
	if index == nil {
		return nil, errors.New("image puller: index is required (pass image.NoLocalIndex{} when the node has none)")
	}
	p := &Puller{cache: cache, fetch: fetch, index: index}
	for _, o := range opts {
		o(p)
	}
	// A HALF-WIRED mirror fallback is refused rather than ignored: either half
	// alone silently disables the whole mechanism, and a node that believed it
	// was mirroring would discover it was not only when a peer's image failed to
	// start. See WithMirrors.
	if (p.mirrors == nil) != (p.mirrorFetch == nil) {
		return nil, errors.New("image puller: WithMirrors needs both a source and a fetcher (the production fetcher is image.RemoteMirrorFetch)")
	}
	// The ADMITTED CLUSTER REGISTRIES, on the same terms: a set with no fetcher
	// would name authorities nothing can dial with the transport they need, and a
	// fetcher with no set would be a plain-HTTP path nothing can reach. Both are
	// silent failures — the first dials HTTPS at a plain-HTTP registry, the
	// second does nothing at all — so neither is accepted.
	if (len(p.clusterRegistryHosts) > 0) != (p.clusterFetch != nil) {
		return nil, errors.New("image puller: WithClusterRegistries needs both a non-empty authority set and a fetcher (the production fetcher is image.RemoteInsecureFetch)")
	}
	set, err := newClusterRegistrySet(p.clusterRegistryHosts)
	if err != nil {
		return nil, fmt.Errorf("image puller: %w", err)
	}
	p.clusterRegistries = set
	// The node's own ingest registry must be CLUSTER-LOCAL, and it is checked
	// after the set above is built because an admitted authority is one of the
	// two ways it can be. The requirement is what makes the two properties
	// WithLocalRegistry documents structural rather than advisory: the attempt is
	// dialled with the transport that authority calls for, and a miss against it
	// is brokered to the cluster mirrors like any other cluster-local miss.
	if p.localRegistry != "" {
		if err := validateRegistryAuthority("local registry host", p.localRegistry); err != nil {
			return nil, fmt.Errorf("image puller: %w", err)
		}
		if !p.clusterLocalAuthority(p.localRegistry) {
			return nil, fmt.Errorf("image puller: local registry host %s is neither a loopback spelling nor an authority admitted by WithClusterRegistries",
				quoteBounded(p.localRegistry, maxMirrorHostLen))
		}
	}
	// The flat registry is validated last: its aliases must be cluster-local, and
	// an admitted cluster registry is one of the ways an authority can be.
	flat, err := p.newFlatRegistry(p.flatConfig)
	if err != nil {
		return nil, fmt.Errorf("image puller: %w", err)
	}
	p.flat = flat
	return p, nil
}

// Pull fetches ref and stores its config + layer blobs in the content-addressed
// cache, returning the manifest and whether it was a full cache hit. Blobs
// already present are not re-written, so the second pull of identical content
// reports CacheHit == true. cred is the imagePullSecret
// credential used for the registry fetch; it is confined to the fetch transport
// and never written to the cache or pod dir.
//
// policy selects which platform of a multi-platform image is pulled. It is a
// per-call argument because the sandbox backend is resolved per pod; a zero
// policy fails closed here, before any round trip (see PlatformPolicy). The
// fetched image's own config is verified against the policy before a single blob
// is written, so the cache never holds bytes this node cannot run. The blob CAS
// is unaffected — digests are already per-platform.
//
// pull is the container's stamped imagePullPolicy and is OBEYED AS GIVEN:
//
//   - always re-resolves the reference on every call, even for a reference this
//     node already has (cached blobs are still reused; it is the resolution that
//     must be fresh);
//   - IF_NOT_PRESENT returns the locally recorded image with zero registry
//     traffic, and falls through to a pull only on a miss — so a warm node
//     starts pods through a registry outage;
//   - never makes no fetch attempt at all: a locally absent reference is
//     ErrImageNotPresent;
//   - UNSPECIFIED is the legacy pull-through — the behavior before pull-policy
//     honoring existed, which is
//     what an old provider that never stamps the field must keep getting. It is
//     never read as an implicit never.
//
// Under DISK PRESSURE on the store volume, a pull that would FETCH is refused
// before any round trip with ErrPullRefusedDiskPressure; a warm IfNotPresent or
// Never serve is unaffected (see admitFetch).
//
// When the node has CLUSTER MIRRORS wired (WithMirrors) and the primary fetch
// misses a reference into this node's own ingest registry, the peers are
// consulted in turn and the same digest-verified commit path runs over whichever
// one has the content — see pullFromMirrors. The reference recorded is always
// the one asked for. A node with no MirrorSource never enters that path, and its
// behavior on a failed fetch is unchanged: the primary error, verbatim.
//
// "This node's own ingest registry" means a loopback spelling always, plus any
// authority the consumer admitted with WithClusterRegistries — a Service DNS
// name or VIP that names the same registry. A reference carrying an admitted
// authority is fetched over plain HTTP (see RemoteInsecureFetch) and brokered
// identically to the loopback spelling of the same pull.
//
// When the node has a LOCAL INGEST REGISTRY wired (WithLocalRegistry) and ref
// names no registry at all, that registry is consulted FIRST and the upstream
// reference is used only on a miss — so a locally loaded image answers a bare
// name, the kind/k3d local-image precedent. It is off by default and applies to
// no reference that names a registry of its own; see WithLocalRegistry for the
// full statement of the divergence and its bounds.
//
// When the node has the FLAT REGISTRY mapped (WithFlatRegistry), a reference
// naming the cluster's one registry name, or one of its aliases, is fetched from
// the configured endpoint and recorded under that one name, and a bare name the
// node's own registry answers is recorded under it too; see FlatRegistry. A
// PUBLIC reference on such a node is still pulled from its own registry first;
// only when that registry cannot be reached is the cluster registry's copy at
// "<flat registry>/<host>/<path>" consulted, and the result is recorded under the
// reference as written (publicmirror.go).
//
// This function never derives a policy from the image tag. Defaulting
// (`:latest`/untagged -> Always) belongs to the embedded apiserver, which stamps
// it on the pod spec; the provider forwards that value verbatim and it arrives
// here already decided. A second derivation point would be free to disagree with
// the stamped spec, and `kubectl get pod -o yaml` would stop describing what the
// node did.
func (p *Puller) Pull(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy, pull runtimev1.ImagePullPolicy) (*PullResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The policy is resolved before any round trip (a zero policy fails closed
	// with no network at all) and before the presence decision, so an invalid
	// platform policy is refused on every path rather than only the fetching
	// ones. The image's own config is verified against it here — at the choke
	// point every pull traverses — not only inside one FetchFunc. RemoteFetch
	// verifies it too, because it is exported and independently callable; but a
	// FetchFunc is a SEAM, and a fetcher that omits the check (or a test fake
	// that returns a platform-less image) must not be able to put
	// foreign-platform bytes in the cache.
	want, err := Candidates(policy)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	// The FLAT REGISTRY spelling (flatregistry.go): an alias of the cluster's
	// one registry name is that name, and a bare name the node's own registry
	// answers is too. flatRef is "" when neither applies.
	flatRef, explicitFlat := p.flatCanonical(ref)
	if !explicitFlat {
		flatRef, _ = p.flatBareName(ref)
	}

	if pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT ||
		pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER {
		entry, lease, present, err := p.presentAs(ctx, policy, flatRef, ref)
		if err != nil {
			return nil, err
		}
		if present {
			// No blob was written and no registry was contacted. The lease comes
			// back HELD — see PullResult.Lease. The manifest descriptor is the one
			// the entry recorded, never one re-derived here: the store holds no
			// manifest blob to hash, so re-deriving it would report a different
			// image id for a warm serve than the pull that recorded it did.
			return &PullResult{
				Manifest: entry.Manifest,
				CacheHit: true,
				// The one path that answers without a round trip, stated
				// explicitly rather than left to the zero value: this is the
				// fact a consumer reports as "already present on machine".
				Fetched:    false,
				Descriptor: entry.Descriptor,
				Platform:   entry.Platform,
				Lease:      lease,
			}, nil
		}
		if pull == runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER {
			return nil, fmt.Errorf("image %q: %w", ref, ErrImageNotPresent)
		}
	}

	// DISK-PRESSURE ADMISSION, at the one choke point every fetching path
	// traverses and before the fetch, so a refused pull performs no registry
	// traffic at all. It sits after the presence decision on purpose: a reference
	// already on this node is served under pressure, because answering presence
	// writes nothing (see admitFetch).
	//
	// always is refused here even when every blob happens to be cached. That is
	// deliberate and it is not over-blocking: always means re-resolve the
	// reference, and whether the resolved digest is one this node already holds
	// is knowable only by making the very round trip being refused. Serving the
	// recorded content instead would silently answer IfNotPresent for a pod that
	// asked for always.
	if err := p.admitFetch(ref); err != nil {
		return nil, err
	}

	// The FLAT REGISTRY, from its endpoint and under its one name. An explicit
	// spelling of it is answered there and nowhere else; a bare name it does not
	// have continues upstream, exactly as the local-registry attempt below does.
	if flatRef != "" {
		if explicitFlat {
			return p.pullFromFlatRegistry(ctx, flatRef, cred, policy, want)
		}
		res, ferr := p.pullFromFlatRegistry(ctx, flatRef, nil, policy, want)
		if ferr == nil || !mirrorFallbackEligible(ferr) {
			return res, ferr
		}
		p.logger().Debug("the flat registry does not have this bare name; continuing upstream",
			"ref", ref, "flatRef", flatRef, "error", ferr)
		return p.fetchUpstreamOrMirror(ctx, ref, cred, policy, want)
	}

	// LOCAL INGEST REGISTRY FIRST, and only for a reference that names no
	// registry at all (localregistry.go). A node with no local registry
	// configured never enters this path, and its resolution of a bare name is
	// bit-identical to what it always was.
	if p.localRegistryApplies(ref) {
		res, lerr := p.pullFromLocalRegistry(ctx, ref, policy, want)
		if !errors.Is(lerr, errLocalRegistryMiss) {
			// A hit, or a definitive refusal from this node's own registry. The
			// sentinel never escapes: the caller sees the image or that verdict.
			return res, lerr
		}
		p.logger().Debug("the node's ingest registry does not have this reference; continuing upstream",
			"ref", ref, "localRegistry", p.localRegistry, "error", lerr)
	}

	// A PUBLIC reference on a node with the flat registry mapped: upstream
	// first, and the cluster registry's copy only when upstream is unreachable
	// (publicmirror.go). A cluster-local reference never enters it.
	if p.publicMirrorApplies(ref) {
		return p.fetchUpstreamOrMirror(ctx, ref, cred, policy, want)
	}

	img, err := p.primaryFetch(ctx, ref, cred, policy)
	if err != nil {
		// CLUSTER MIRROR FALLBACK (mirror.go). It engages only when this node has
		// peers wired, the reference names this node's OWN ingest registry, and
		// the primary answer was a miss or an unreachable registry — otherwise
		// mirrorCandidates returns nothing and the primary error stands verbatim,
		// which is the whole of the behavior on a node with no MirrorSource.
		if mirrors := p.mirrorCandidates(ref, err); len(mirrors) > 0 {
			return p.pullFromMirrors(ctx, ref, ref, policy, want, mirrors, err)
		}
		return nil, err
	}
	return p.ingestVia(ctx, ref, img, want, p.resumeSource(ref, cred))
}

// resumeSource is the blob route ingest resumes ref's layers through, fetched
// with cred: the primary path's BlobSource, when the puller has both that
// route and a partial store. Nil otherwise, and ingest then reads each layer
// from the fetched image, as it does without either. A route that cannot be
// built is also nil (logged at Warn, since it is misconfiguration): the layer still arrives over the image
// fetch, and CommitBlob verifies it either way.
func (p *Puller) resumeSource(ref string, cred *RegistryCredential) *BlobSource {
	if p.partials == nil {
		return nil
	}
	src, ok, err := p.primaryBlobSource(ref, cred)
	if err != nil {
		p.logger().Warn("no resumable blob route for this reference; fetching layers whole",
			"ref", ref, "error", err)
		return nil
	}
	if !ok {
		return nil
	}
	return &src
}

// ingest is ingestVia with no blob route: every layer is read from img.
func (p *Puller) ingest(ctx context.Context, ref string, img ggcrv1.Image, want []Platform) (*PullResult, error) {
	return p.ingestVia(ctx, ref, img, want, nil)
}

// ingestVia commits one fetched image into the store under ref and records it: the
// platform re-verification, the lease over the whole digest set, every config
// and layer blob, and the index entry — everything after the bytes are in hand.
//
// It is split from Pull because the CLUSTER MIRROR fallback needs it per
// candidate: a peer that serves content this node refuses (a blob that does not
// hash to the digest its manifest claims) must be a per-mirror failure the loop
// walks past, and that verdict is only reachable HERE, at the commit, not at the
// fetch. Splitting it also makes the all-or-nothing property structural — the
// deferred release below returns the lease on every failing path, so a rejected
// candidate leaves the store exactly as it found it.
//
// ref is the reference the pull was ASKED for, never the mirror-rewritten one:
// it is what the manifest reports and what the index records.
//
// src, when not nil, is the direct blob route for ref (resumeSource): each
// layer then comes through the partial store (resumeBlob) rather than from
// img, and a cut transfer is resumed by the next pull.
func (p *Puller) ingestVia(ctx context.Context, ref string, img ggcrv1.Image, want []Platform, src *BlobSource) (_ *PullResult, retErr error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("pull %q: image config: %w", ref, boundErr(err))
	}
	// The platform the image's own config declares, as verified against this
	// pod's candidates — that is the half of the index key the reference does not
	// carry, and taking it from the verifier means the recorded key can only ever
	// be a platform this pull proved runnable here.
	resolved, err := VerifyConfigPlatform(cfg, want)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	wroteAny := false

	// The MANIFEST is resolved before any blob is written, because it — not the
	// object that hands over the bytes — is where every claimed digest comes
	// from. img.ConfigName() and layer.Digest() are not used as claimed values:
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
	// The manifest's OWN bytes and digest, captured here for the index to retain
	// (see IndexEntry.ManifestRaw). They are read from the same resolved image
	// the descriptors above came from, so the retained bytes and the committed
	// blobs describe one image by construction. The store commits no manifest
	// blob, so this is the only place they can be captured at all.
	rawMfst, err := img.RawManifest()
	if err != nil {
		return nil, fmt.Errorf("raw manifest %q: %w", ref, boundErr(err))
	}
	mfstDigest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("manifest digest %q: %w", ref, boundErr(err))
	}

	// LEASE the whole DIGEST SET before a single blob is even looked at — not
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
		// The index this manifest was selected from, when the reference
		// resolved through one: the digest the reference pointed at, which a
		// container's image_id publishes. Empty for a single manifest. It is
		// recorded with the manifest, so a warm serve reports the same value.
		IndexDigest: resolvedIndexDigest(img),
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
		whole := func(w io.Writer) error {
			rc, oerr := layer.Compressed()
			if oerr != nil {
				return oerr
			}
			body := newStallReader(rc, p.stallWindow())
			defer body.Close()
			_, cerr := io.Copy(w, body)
			return cerr
		}
		var wrote bool
		if src != nil {
			wrote, err = p.resumeBlob(ctx, *src, desc.Digest.String(), desc.Size, whole)
		} else {
			wrote, err = p.writeBlob(desc.Digest.String(), desc.Size, whole)
		}
		if err != nil {
			return nil, err
		}
		wroteAny = wroteAny || wrote
		out.Layers = append(out.Layers, descriptorFromGGCR(desc))
	}

	// Record the reference last: every blob it names is now committed and
	// digest-verified, and the manifest recorded is the one this pull resolved —
	// never bytes re-read at lookup time. Recording earlier would let a lookup
	// answer "present" for a pull that had not finished writing.
	//
	// The entry is an EDGE, not a root (see FileIndex): it makes nothing
	// reachable, so it neither replaces the lease nor delays its release, and a
	// blob it names is still reclaimable the moment no pod records it.
	//
	// A failed record FAILS the PULL. The blobs are on disk and re-pulling is
	// idempotent, so nothing is lost; and the two ways this can fail — the index
	// tree is unwritable, or it is not the tree this daemon owns
	// (ErrIndexNotOwned) — are exactly the conditions under which a LOOKUP must
	// not be believed either. Continuing would keep serving pods from an index
	// this daemon has just discovered it cannot maintain.
	desc := &runtimev1.Descriptor{
		MediaType: string(mfst.MediaType),
		Digest:    mfstDigest.String(),
		Size:      int64(len(rawMfst)),
	}
	if err := p.index.Record(ctx, IndexEntry{
		Reference:   ref,
		Platform:    resolved,
		Manifest:    out,
		Descriptor:  desc,
		ManifestRaw: rawMfst,
	}); err != nil {
		return nil, fmt.Errorf("pull %q: record image index: %w", ref, err)
	}

	return &PullResult{
		Manifest: out,
		CacheHit: !wroteAny,
		// ingest is reached only with bytes in hand, and it is the ONE
		// constructor every fetching path funnels through — the upstream fetch,
		// the node's ingest registry, and each cluster-mirror candidate — so
		// this is where "a registry was contacted" is true for all three at
		// once. It stays true when !wroteAny: the round trip happened whether or
		// not it produced a new blob.
		Fetched:    true,
		Descriptor: desc,
		Platform:   resolved,
		Lease:      lease,
	}, nil
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

// presentAs is presentLocally over the spellings a reference may have been
// recorded under, in order; an empty spelling is skipped. The first one present
// wins, so the flat registry's name is preferred and an entry recorded under the
// written spelling (before the flat mapping existed, or by an image load) still
// serves.
func (p *Puller) presentAs(ctx context.Context, policy PlatformPolicy, refs ...string) (IndexEntry, *Lease, bool, error) {
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		entry, lease, ok, err := p.presentLocally(ctx, r, policy)
		if err != nil || ok {
			return entry, lease, ok, err
		}
	}
	return IndexEntry{}, nil, false, nil
}

// presentLocally reports whether ref is on this node for policy's platform: the
// index must have recorded it and every blob its manifest names must still be in
// the content-addressed store. It returns the whole recorded entry, so a warm
// serve reports the manifest descriptor and key platform the pull recorded
// rather than a re-derivation of them.
//
// The second half is not belt-and-braces. Presence-by-reference and the bytes
// have independent lifetimes (the cache GC evicts blobs), and a stale index entry
// would otherwise start a container whose layers are gone — so a recorded
// reference with missing blobs is a miss, which sends IfNotPresent back to the
// registry and fails Never honestly.
func (p *Puller) presentLocally(ctx context.Context, ref string, policy PlatformPolicy) (IndexEntry, *Lease, bool, error) {
	entry, ok, err := p.index.Lookup(ctx, ref, policy)
	if err != nil {
		return IndexEntry{}, nil, false, fmt.Errorf("image index lookup %q: %w", ref, err)
	}
	mfst := entry.Manifest
	if !ok || mfst == nil {
		return IndexEntry{}, nil, false, nil
	}
	// LEASE before the presence check, not after it. This path writes nothing at
	// all, so there is no commit to hang a pin on and no mtime change for a grace
	// window to notice: the blobs are old, present, and — until the caller records
	// the reference — named by nothing. Checking presence first and leasing second
	// would leave the whole check-then-use interval open to a reclaim that deletes
	// the very blobs just found present.
	lease := p.cache.AcquireLease(manifestDigests(mfst), 0)
	if !p.cache.Has(mfst.GetConfig().GetDigest()) {
		lease.Release()
		return IndexEntry{}, nil, false, nil
	}
	for _, l := range mfst.GetLayers() {
		if !p.cache.Has(l.GetDigest()) {
			lease.Release()
			return IndexEntry{}, nil, false, nil
		}
	}
	return entry, lease, true, nil
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
// ingest path (the tarball-ingest path links this package in-process) rather than
// locked behind a *Puller, whose constructor requires a FetchFunc an ingest path
// has no business supplying.
//
// With a LocalBlobSource (WithLocalBlobSource) the blob is first offered to
// Cache.CommitFromLocal, which clones and re-hashes it; fill — the network
// fetch — runs only when that does not commit it. ErrBlobNotLocal falls back
// quietly. Any other refusal (a local copy whose bytes contradict the digest)
// is logged at Warn before falling back, so a tampered store is never hidden
// behind a successful pull.
func (p *Puller) writeBlob(digest string, size int64, fill func(io.Writer) error) (wrote bool, err error) {
	if wrote, ok := p.commitLocal(digest, size); ok {
		return wrote, nil
	}
	return p.cache.CommitBlob(digest, size, fill)
}

// stallWindow is the layer-body progress window: layerStallWindow, or
// defaultLayerStallWindow when unset.
func (p *Puller) stallWindow() time.Duration {
	if p.layerStallWindow > 0 {
		return p.layerStallWindow
	}
	return defaultLayerStallWindow
}

// commitLocal offers digest to the LocalBlobSource, when there is one. ok is
// true when that committed it (wrote as CommitFromLocal reports); otherwise
// the caller fetches it, and a refusal other than ErrBlobNotLocal has been
// logged at Warn (see writeBlob).
func (p *Puller) commitLocal(digest string, size int64) (wrote, ok bool) {
	if p.localBlobs == nil {
		return false, false
	}
	wrote, lerr := p.cache.CommitFromLocal(digest, size, p.localBlobs)
	switch {
	case lerr == nil:
		return wrote, true
	case errors.Is(lerr, ErrBlobNotLocal):
	default:
		p.logger().Warn("local blob store copy refused, fetching from the registry",
			"digest", quoteBounded(digest, maxDigestLen), "err", lerr)
	}
	return false, false
}

// resumeBlob is writeBlob for a layer with a direct blob route: the size-byte
// blob digest is fetched through the puller's partial store, so the bytes a
// cut transfer received stay on disk and the next pull asks src for the rest
// with a Range request. size and digest are the manifest descriptor's, the
// same claimed values writeBlob takes.
//
// The partial is claimed first, so one digest has one writer; a digest
// another pull is already resuming, one that is not sha256, or a partial
// store over its budget falls back to writeBlob with whole, the same fill
// ingest uses without a route. A held claim is then offered to the
// LocalBlobSource and checked against the cache before any byte is fetched.
//
// The complete partial is committed through CommitFromLocal, as a one-shot
// read-only LocalBlobSource: it is cloned into the cache's staging dir, the
// clone is re-hashed against digest and renamed into place only on a match,
// so the blob is not written a second time. When it cannot be cloned there
// (another volume, no clone support: ErrBlobNotLocal), or the clone path
// refuses for any reason that is not a verdict on the bytes (logged at Error,
// since a staging dir of the wrong mode or owner may be tampering), the
// partial is replayed into CommitBlob instead, which re-hashes all of it. Either way a mismatch or
// an overrun condemns the partial and Resume removes it, so the next pull
// starts from byte 0. Nothing about the hash is carried from one attempt to
// the next.
//
// A ranged answer that is not the bytes asked for (ErrBlobRange: a server or
// proxy that mishandles Range) would fail the same way on every later pull
// resuming from the same offset, so the partial is removed, under the claim,
// and the layer is fetched whole by writeBlob within this pull. Transfer also
// empties the file it was handed, so a failed Remove still leaves a
// zero-length partial that the next resume starts from byte 0, with no Range
// header.
func (p *Puller) resumeBlob(ctx context.Context, src BlobSource, digest string, size int64, whole func(io.Writer) error) (wrote bool, err error) {
	release, cerr := p.partials.Claim(digest)
	if cerr != nil {
		p.logger().Debug("layer partial not claimable; fetching it whole",
			"digest", quoteBounded(digest, maxDigestLen), "error", cerr)
		return p.writeBlob(digest, size, whole)
	}
	defer release()
	if wrote, ok := p.commitLocal(digest, size); ok {
		return wrote, nil
	}
	if p.cache.Has(digest) {
		return false, nil
	}
	// reached is set the moment Resume hands control to Transfer or Commit:
	// an error with reached false came from the store's own setup (admit,
	// directory, open, stat, seek) before a byte of this attempt moved.
	var reached bool
	from := size // the offset resumed from; size when Commit runs without a Transfer
	err = p.partials.Resume(registryfetch.Fill{
		Digest: digest,
		Size:   size,
		Transfer: func(f *os.File, have int64) error {
			reached = true
			from = have
			err := transferBlob(ctx, src, digest, size, f, have, p.stallWindow())
			if errors.Is(err, registryfetch.ErrBlobRange) {
				if terr := f.Truncate(0); terr != nil {
					return errors.Join(err, fmt.Errorf("reset partial %s: %w", digest, terr))
				}
			}
			return err
		},
		CommitFile: func(f *os.File) error {
			reached = true
			w, err := p.cache.CommitFromLocal(digest, size, &partialBlob{digest: digest, f: f})
			switch {
			case err == nil:
				wrote = w
				return nil
			case errors.Is(err, ErrBlobNotLocal):
				return fmt.Errorf("%w: %w", registryfetch.ErrCommitFileUnsupported, err)
			case errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrBlobTooLarge):
				// A verdict on the bytes: Poisoned condemns the partial.
				return err
			default:
				// A refusal of the clone path itself (a staging dir of the
				// wrong mode, owner or ACL, a mkdir, stat, scrub, chmod or
				// sync failure) says nothing about the partial, and would
				// repeat on every pull; CommitBlob re-hashes the replay.
				p.logger().Error("layer partial not committed by clone; replaying it",
					"digest", digest, "error", err, "possibleTampering", true)
				return fmt.Errorf("%w: %w", registryfetch.ErrCommitFileUnsupported, err)
			}
		},
		Commit: func(replay func(io.Writer) error) error {
			reached = true
			w, err := p.cache.CommitBlob(digest, size, replay)
			wrote = w
			return err
		},
		Poisoned: func(err error) bool {
			return errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrBlobTooLarge)
		},
	})
	switch {
	case errors.Is(err, registryfetch.ErrPartialCap):
		// Admit refused before the store was touched; a layer over the
		// per-partial cap is misconfiguration, not load.
		p.logger().Warn("layer partial over the per-partial cap; fetching it whole",
			"digest", digest, "error", err)
		return p.writeBlob(digest, size, whole)
	case errors.Is(err, registryfetch.ErrPartialBudget):
		// Admit refused before the store was touched.
		p.logger().Debug("layer partial over budget; fetching it whole",
			"digest", digest, "error", err)
		return p.writeBlob(digest, size, whole)
	case errors.Is(err, registryfetch.ErrBlobRange):
		// The claim is still held: release is deferred above.
		if rerr := p.partials.Remove(digest); rerr != nil {
			p.logger().Warn("layer partial not removed after a wrong range answer",
				"digest", digest, "error", rerr)
		}
		p.logger().Warn("layer range answer is not the one asked for; partial removed, fetching it whole",
			"digest", digest, "error", err)
		return p.writeBlob(digest, size, whole)
	case err != nil && !reached && partialEnvErr(err):
		// The store could not be set up and nothing of this attempt was
		// transferred or committed: the partial store is an optimisation, so
		// its own environment must not fail a pull that works without it. A
		// pull whose context is done is not retried whole.
		if cerr := ctx.Err(); cerr != nil {
			return false, fmt.Errorf("layer %s: %w (partial store: %w)", digest, cerr, err)
		}
		if errors.Is(err, registryfetch.ErrPartialDir) || errors.Is(err, registryfetch.ErrPartialFile) {
			// A planted owner, mode, symlink or special file is not an
			// ordinary environment fault.
			p.logger().Error("layer partial store unusable; fetching it whole",
				"digest", digest, "error", err, "possibleTampering", true)
		} else {
			p.logger().Warn("layer partial store unusable; fetching it whole",
				"digest", digest, "error", err)
		}
		return p.writeBlob(digest, size, whole)
	case err == nil && reached && from > 0:
		p.logger().Info("layer resumed from a partial",
			"digest", digest, "size", size, "offset", from)
	}
	return wrote, err
}

// partialBlob is the LocalBlobSource resumeBlob commits a complete partial
// through: it offers f, the read-only O_NOFOLLOW descriptor Resume reopened,
// once and for digest only. CommitFromLocal closes the file it is handed;
// Resume closes it again, which is harmless.
type partialBlob struct {
	digest string
	f      *os.File
	used   bool
}

// OpenBlob returns the partial for its own digest, the first time only.
func (b *partialBlob) OpenBlob(digest string) (*os.File, int64, error) {
	if b.used || digest != b.digest {
		return nil, 0, ErrBlobNotLocal
	}
	b.used = true
	fi, err := b.f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat partial %s: %w", digest, err)
	}
	return b.f, fi.Size(), nil
}

// partialEnvErr reports whether err from PartialStore.Resume names the
// store's own environment: a partial dir that is not a private directory, a
// partial path that is not a regular file, or a partial dir or file that
// could not be created or opened (a missing parent, permission, a read-only
// filesystem). Network, transfer, digest and size errors do not match.
func partialEnvErr(err error) bool {
	return errors.Is(err, registryfetch.ErrPartialDir) ||
		errors.Is(err, registryfetch.ErrPartialFile) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, syscall.EROFS)
}

// transferBlob appends the rest of the size-byte blob digest to f from offset
// have, over src. A server that answers from 0 instead (a 200 to the Range
// request) restarts the partial: f is truncated and written from 0. A failure
// leaves what arrived in f, synced, for the next pull to resume. A body that
// runs past size is refused with ErrBlobTooLarge and f is emptied; the real
// route's body (registryfetch.Registry.Blob) already stops at size with an
// error, so there the partial stays at size and the next pull verifies it in
// CommitBlob or removes it. The body is read through the same progress
// watchdog as a whole-layer fetch: a body that delivers no byte for window is
// closed and the transfer fails with ErrLayerBodyStalled, keeping what arrived.
func transferBlob(ctx context.Context, src BlobSource, digest string, size int64, f *os.File, have int64, window time.Duration) error {
	rc, start, err := src.Registry.Blob(ctx, src.Ref, src.Credential, digest, size, have)
	if err != nil {
		return fmt.Errorf("fetch blob %s from %d: %w", digest, have, err)
	}
	body := newStallReader(rc, window)
	defer body.Close()
	switch {
	case start == have:
	case start == 0:
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("reset partial %s: %w", digest, err)
		}
		have = 0
	default:
		return fmt.Errorf("fetch blob %s: asked for offset %d, got %d: %w", digest, have, start, registryfetch.ErrBlobRange)
	}
	if _, err := f.Seek(have, io.SeekStart); err != nil {
		return fmt.Errorf("seek partial %s: %w", digest, err)
	}
	n, cerr := io.Copy(struct{ io.Writer }{f}, io.LimitReader(body, size-have+1))
	serr := f.Sync()
	if have+n > size {
		_ = f.Truncate(0) // the overrun error is the one reported
		return fmt.Errorf("fetch blob %s: more than %d bytes: %w", digest, size, ErrBlobTooLarge)
	}
	if cerr != nil {
		return fmt.Errorf("fetch blob %s at %d: %w", digest, have+n, boundErr(cerr))
	}
	if serr != nil {
		return fmt.Errorf("sync partial %s: %w", digest, serr)
	}
	if have+n < size {
		return fmt.Errorf("fetch blob %s: body ended at %d of %d: %w", digest, have+n, size, io.ErrUnexpectedEOF)
	}
	return nil
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
