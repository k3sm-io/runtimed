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
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"k3sm.io/runtimed/pkg/image"
)

// RegistryFetcher is the production Fetcher. Transport is the cluster
// registry's own transport (image.ArtifactTransport), which dials only the
// registry host and trusts only its CA; PlainHTTP is that hop's scheme.
type RegistryFetcher struct {
	Transport http.RoundTripper
	PlainHTTP bool
}

func (f *RegistryFetcher) parse(ref string) (name.Reference, error) {
	opts := []name.Option{name.StrictValidation}
	if f.PlainHTTP {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}
	return r, nil
}

func authenticator(cred *image.RegistryCredential) authn.Authenticator {
	if cred == nil {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{
		Username: cred.Username, Password: cred.Password, Auth: cred.Auth,
		IdentityToken: cred.IdentityToken, RegistryToken: cred.RegistryToken,
	})
}

// Manifest fetches the manifest ref names. go-containerregistry verifies the
// bytes of a by-digest reference; PullArtifact re-checks it anyway.
func (f *RegistryFetcher) Manifest(ctx context.Context, ref string, cred *image.RegistryCredential) ([]byte, string, error) {
	if f.Transport == nil {
		return nil, "", errors.New("artifact fetcher: transport is required")
	}
	r, err := f.parse(ref)
	if err != nil {
		return nil, "", err
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithTransport(f.Transport), remote.WithAuth(authenticator(cred)))
	if err != nil {
		return nil, "", fmt.Errorf("%s", image.QuoteBounded(err.Error(), 512))
	}
	return desc.Manifest, string(desc.MediaType), nil
}

// Blob opens digest in ref's repository from offset, with a Range request when
// offset > 0. A 200 to a Range request restarts at 0; a 416 is retried once
// without a Range.
func (f *RegistryFetcher) Blob(ctx context.Context, ref string, cred *image.RegistryCredential, digest string, offset int64) (io.ReadCloser, int64, error) {
	if f.Transport == nil {
		return nil, 0, errors.New("artifact fetcher: transport is required")
	}
	r, err := f.parse(ref)
	if err != nil {
		return nil, 0, err
	}
	repo := r.Context()
	rt, err := transport.NewWithContext(ctx, repo.Registry, authenticator(cred), f.Transport,
		[]string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, 0, fmt.Errorf("registry auth: %s", image.QuoteBounded(err.Error(), 512))
	}
	client := &http.Client{Transport: rt}
	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", repo.Registry.Scheme(), repo.RegistryStr(), repo.RepositoryStr(), digest)
	get := func(from int64) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if from > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
		}
		return client.Do(req)
	}
	resp, err := get(offset)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && offset > 0 {
		resp.Body.Close()
		offset = 0
		if resp, err = get(0); err != nil {
			return nil, 0, err
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, 0, nil
	case http.StatusPartialContent:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != offset {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("blob %s: Content-Range %s does not start at %d",
				digest, image.QuoteBounded(resp.Header.Get("Content-Range"), 128), offset)
		}
		return resp.Body, start, nil
	}
	defer resp.Body.Close()
	if err := transport.CheckError(resp, http.StatusOK, http.StatusPartialContent); err != nil {
		return nil, 0, fmt.Errorf("blob %s: %s", digest, image.QuoteBounded(err.Error(), 512))
	}
	return nil, 0, fmt.Errorf("blob %s: status %d", digest, resp.StatusCode)
}

// contentRangeStart parses the first byte of "bytes <first>-<last>/<size>".
func contentRangeStart(v string) (int64, bool) {
	rest, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(first, 10, 64)
	return n, err == nil && n >= 0
}
