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
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
)

// TestManifestFetchCarriesTheCredential is the positive side of
// TestManifestFetchRedirectDoesNotReachTokenLogic: with the manifest and config
// fetch on the origin-split transport (and go-containerregistry's anonymous
// layer stacked over it), a registry that REQUIRES auth still serves a private
// image. Basic: every manifest/config request it accepted carried the Basic
// credential. Bearer: the token endpoint issues "good" only for the basic
// credential and "anon" otherwise, and the registry never sees "Bearer anon" on
// a manifest.
func TestManifestFetchCarriesTheCredential(t *testing.T) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	for _, tc := range []struct {
		name         string
		bearer       bool
		foreignRealm bool
	}{
		{name: "basic"},
		{name: "bearer", bearer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			seed := httptest.NewServer(store)
			defer seed.Close()
			img := testImage(t, "darwin", "arm64", "")
			pushImage(t, strings.TrimPrefix(seed.URL, "http://"), "repo/x", img)

			var (
				mu       sync.Mutex
				accepted []string // Authorization on each accepted manifest/config request
				anon     []string // manifest requests that carried Bearer anon
			)
			tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tok := "anon"
				if r.Header.Get("Authorization") == basic {
					tok = "good"
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token":"` + tok + `"}`))
			})
			reg := httptest.NewServer(nil)
			defer reg.Close()
			realm := reg.URL + "/token"
			if tc.foreignRealm {
				ts := httptest.NewServer(tokenHandler)
				defer ts.Close()
				realm = ts.URL + "/token"
			}
			want := basic
			challenge := `Basic realm="r"`
			if tc.bearer {
				want = "Bearer good"
				challenge = `Bearer realm="` + realm + `",service="x"`
			}
			reg.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h := r.Header.Get("Authorization")
				if r.URL.Path == "/token" && !tc.foreignRealm {
					tokenHandler.ServeHTTP(w, r)
					return
				}
				isManifest := strings.Contains(r.URL.Path, "/manifests/")
				if isManifest && h == "Bearer anon" {
					mu.Lock()
					anon = append(anon, r.Method+" "+r.URL.Path)
					mu.Unlock()
				}
				if h != want || (tc.bearer && r.URL.Path == "/v2/") {
					scope := ""
					if tc.bearer && r.URL.Path != "/v2/" {
						scope = `,scope="repository:repo/x:pull"`
					}
					w.Header().Set("WWW-Authenticate", challenge+scope)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if isManifest || strings.Contains(r.URL.Path, "/blobs/") {
					mu.Lock()
					accepted = append(accepted, h)
					mu.Unlock()
				}
				store.ServeHTTP(w, r)
			})

			ref := strings.TrimPrefix(reg.URL, "http://") + "/repo/x:v1"
			cred := &RegistryCredential{Username: "alice", Password: "pw"}
			got, err := RemoteFetch(context.Background(), ref, cred, nativePolicy())
			if err != nil {
				t.Fatalf("RemoteFetch with the credential: %v", err)
			}
			if _, err := got.ConfigFile(); err != nil {
				t.Fatalf("config: %v", err)
			}
			if g, w := mustDigest(t, got), mustDigest(t, img); g != w {
				t.Errorf("digest = %s, want %s", g, w)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(accepted) == 0 {
				t.Fatal("registry accepted no manifest/config request")
			}
			for _, h := range accepted {
				if h != want {
					t.Errorf("accepted request carried %q, want %q", h, want)
				}
			}
			if len(anon) != 0 {
				t.Errorf("manifest requests carried Bearer anon: %q", anon)
			}
		})
	}
}
