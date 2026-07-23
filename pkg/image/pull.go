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
	"os"
	"path/filepath"

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
}

// Puller pulls OCI images into a Cache using a FetchFunc.
type Puller struct {
	cache *Cache
	fetch FetchFunc
}

// NewPuller returns a Puller writing into cache and fetching via fetch.
//
// Both arguments are REQUIRED: a nil fetch is an error, never a silent default
// to RemoteFetch. Which fetcher runs is the decision that chooses which
// platform's bytes land in the cache, so it is spelled out at the call site that
// makes it (runtime.New passes image.RemoteFetch) rather than substituted here.
// An implicit default is the exact shape of bug this package exists to remove —
// and it also hides the binding from tests, which then cannot tell a production
// wiring from a mis-wiring.
func NewPuller(cache *Cache, fetch FetchFunc) (*Puller, error) {
	if cache == nil {
		return nil, errors.New("image puller: cache is required")
	}
	if fetch == nil {
		return nil, errors.New("image puller: fetch is required (the production fetcher is image.RemoteFetch)")
	}
	return &Puller{cache: cache, fetch: fetch}, nil
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
func (p *Puller) Pull(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (*PullResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The policy is resolved BEFORE any round trip (a zero policy fails closed
	// with no network at all), and the image's own config is verified against it
	// HERE — at the choke point every pull traverses — not only inside one
	// FetchFunc. RemoteFetch verifies it too, because it is exported and
	// independently callable; but a FetchFunc is a SEAM, and a fetcher that
	// omits the check (or a test fake that returns a platform-less image) must
	// not be able to put foreign-platform bytes in the cache.
	want, err := Candidates(policy)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	img, err := p.fetch(ctx, ref, cred, policy)
	if err != nil {
		return nil, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("pull %q: image config: %w", ref, boundErr(err))
	}
	if _, err := VerifyConfigPlatform(cfg, want); err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	wroteAny := false

	// Config blob.
	cfgDigest, err := img.ConfigName()
	if err != nil {
		return nil, fmt.Errorf("config digest %q: %w", ref, boundErr(err))
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", ref, boundErr(err))
	}
	wrote, err := p.writeBlob(cfgDigest.String(), func(w io.Writer) error {
		_, werr := w.Write(rawCfg)
		return werr
	})
	if err != nil {
		return nil, err
	}
	wroteAny = wroteAny || wrote

	mfst, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", ref, boundErr(err))
	}

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
	for i, layer := range layers {
		dig, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("layer %d digest %q: %w", i, ref, boundErr(err))
		}
		wrote, err := p.writeBlob(dig.String(), func(w io.Writer) error {
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
		out.Layers = append(out.Layers, descriptorFromGGCR(mfst.Layers[i]))
	}

	return &PullResult{Manifest: out, CacheHit: !wroteAny}, nil
}

// writeBlob writes the blob for digest via fill, atomically (temp+rename), unless
// it already exists. It returns whether a new blob was written (false == cache
// hit for this blob).
func (p *Puller) writeBlob(digest string, fill func(io.Writer) error) (wrote bool, err error) {
	dst, err := p.cache.blobPath(digest)
	if err != nil {
		return false, err
	}
	if _, serr := os.Stat(dst); serr == nil {
		return false, nil // cache hit
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, fmt.Errorf("mkdir blob dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".blob-*")
	if err != nil {
		return false, fmt.Errorf("temp blob: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := fill(tmp); err != nil {
		// fill streams REGISTRY bytes (layer.Compressed / io.Copy), so its error
		// is third-party content — bounded, never adopted.
		tmp.Close()
		return false, fmt.Errorf("write blob %s: %w", digest, boundErr(err))
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close blob %s: %w", digest, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return false, fmt.Errorf("commit blob %s: %w", digest, err)
	}
	return true, nil
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
