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

package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/registryfetch"
)

// RegistryFetcher is the production Fetcher. Transport is the cluster
// registry's own transport (image.ArtifactTransport), which dials only the
// registry host and trusts only its CA; PlainHTTP is that hop's scheme.
type RegistryFetcher struct {
	Transport http.RoundTripper
	PlainHTTP bool
}

// registry is the registryfetch.Registry f stands for.
func (f *RegistryFetcher) registry() *registryfetch.Registry {
	return &registryfetch.Registry{Transport: f.Transport, PlainHTTP: f.PlainHTTP}
}

// fetchCredential is cred as registryfetch takes it.
func fetchCredential(cred *image.RegistryCredential) *registryfetch.Credential {
	if cred == nil {
		return nil
	}
	return &registryfetch.Credential{
		Username: cred.Username, Password: cred.Password, Auth: cred.Auth,
		IdentityToken: cred.IdentityToken, RegistryToken: cred.RegistryToken,
	}
}

// errTransportRequired is what a RegistryFetcher without a Transport returns.
var errTransportRequired = errors.New("artifact fetcher: transport is required")

// fetchErr maps registryfetch's sentinels to the ones this package's callers
// match, keeping the message: an unparsable reference is ErrInvalidReference.
func fetchErr(err error) error {
	var re *registryfetch.ReferenceError
	switch {
	case errors.As(err, &re):
		return fmt.Errorf("%w: %w", ErrInvalidReference, re.Err)
	case errors.Is(err, registryfetch.ErrTransportRequired):
		return errTransportRequired
	}
	return err
}

// manifestAccept is every manifest type the registry may answer with. The
// index and docker types are accepted on the wire only so PullArtifact can
// refuse them by name rather than see a 404.
var manifestAccept = strings.Join([]string{
	mediaTypeOCIManifest, mediaTypeOCIIndex, mediaTypeDockerManifest, mediaTypeDockerList,
}, ", ")

// Manifest fetches the manifest ref names with its own bounded read: at most
// MaxManifestBytes+1 bytes are ever read from the body, so a hostile registry
// cannot make the root daemon buffer more than the cap before the refusal.
// PullArtifact verifies a by-digest reference against the bytes.
func (f *RegistryFetcher) Manifest(ctx context.Context, ref string, cred *image.RegistryCredential) ([]byte, string, error) {
	r, client, err := f.client(ctx, ref, cred)
	if err != nil {
		return nil, "", err
	}
	repo := r.Context()
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", repo.Registry.Scheme(), repo.RegistryStr(), repo.RepositoryStr(), r.Identifier())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", bound(err)
	}
	req.Header.Set("Accept", manifestAccept)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("manifest: %w", bound(err))
	}
	defer resp.Body.Close()
	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, "", fmt.Errorf("manifest: %w", bound(err))
	}
	if resp.ContentLength > MaxManifestBytes {
		return nil, "", fmt.Errorf("manifest of %d bytes, at most %d: %w", resp.ContentLength, MaxManifestBytes, ErrManifestTooLarge)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifestBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("manifest: %w", bound(err))
	}
	if len(raw) > MaxManifestBytes {
		return nil, "", fmt.Errorf("manifest over %d bytes: %w", MaxManifestBytes, ErrManifestTooLarge)
	}
	return raw, resp.Header.Get("Content-Type"), nil
}

// client parses ref and returns an authenticated client for its repository,
// scoped to pull, over the cluster registry's own transport.
func (f *RegistryFetcher) client(ctx context.Context, ref string, cred *image.RegistryCredential) (name.Reference, *http.Client, error) {
	r, c, err := f.registry().Session(ctx, ref, fetchCredential(cred))
	return r, c, fetchErr(err)
}

// Blob opens the size-byte blob digest in ref's repository from offset, with a
// Range request when offset > 0 (registryfetch.Registry.Blob).
func (f *RegistryFetcher) Blob(ctx context.Context, ref string, cred *image.RegistryCredential, digest string, size, offset int64) (io.ReadCloser, int64, error) {
	body, start, err := f.registry().Blob(ctx, ref, fetchCredential(cred), digest, size, offset)
	return body, start, fetchErr(err)
}
