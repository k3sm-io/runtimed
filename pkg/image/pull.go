package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/google/go-containerregistry/pkg/name"

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
// cred for private-registry auth (nil = anonymous). The production fetcher is
// RemoteFetch (a registry pull); tests inject an in-memory image so pull/cache
// logic is exercised with no network.
type FetchFunc func(ctx context.Context, ref string, cred *RegistryCredential) (ggcrv1.Image, error)

// RemoteFetch fetches ref from a remote registry. It is the production FetchFunc.
// When cred is non-nil it authenticates with that credential (the imagePullSecret,
// M2.6); the credential lives only in this transport, never on disk.
func RemoteFetch(ctx context.Context, ref string, cred *RegistryCredential) (ggcrv1.Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	opts := []remote.Option{remote.WithContext(ctx)}
	if cred != nil {
		opts = append(opts, remote.WithAuth(cred.authenticator()))
	}
	img, err := remote.Image(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
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

// NewPuller returns a Puller writing into cache and fetching via fetch
// (RemoteFetch if nil).
func NewPuller(cache *Cache, fetch FetchFunc) *Puller {
	if fetch == nil {
		fetch = RemoteFetch
	}
	return &Puller{cache: cache, fetch: fetch}
}

// Pull fetches ref and stores its config + layer blobs in the content-addressed
// cache, returning the manifest and whether it was a full cache hit. Blobs
// already present are not re-written, so the second pull of identical content
// reports CacheHit == true (acceptance M1.1-a1). cred (M2.6) is the imagePullSecret
// credential used for the registry fetch; it is confined to the fetch transport
// and never written to the cache or pod dir.
func (p *Puller) Pull(ctx context.Context, ref string, cred *RegistryCredential) (*PullResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	img, err := p.fetch(ctx, ref, cred)
	if err != nil {
		return nil, err
	}

	wroteAny := false

	// Config blob.
	cfgDigest, err := img.ConfigName()
	if err != nil {
		return nil, fmt.Errorf("config digest %q: %w", ref, err)
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", ref, err)
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
		return nil, fmt.Errorf("manifest %q: %w", ref, err)
	}

	out := &runtimev1.ImageManifest{
		Reference:   ref,
		MediaType:   string(mfst.MediaType),
		Config:      descriptorFromGGCR(mfst.Config),
		Annotations: mfst.Annotations,
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layers %q: %w", ref, err)
	}
	for i, layer := range layers {
		dig, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("layer %d digest %q: %w", i, ref, err)
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
		tmp.Close()
		return false, fmt.Errorf("write blob %s: %w", digest, err)
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
