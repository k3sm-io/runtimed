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

package guestartifacts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

const (
	testStoreHost    = "registry.k3sm.test:5000"
	testStoreVersion = "v6.18.48-0123456789ab"
)

// fakeStore is an in-memory cluster store: a manifest per reference, mapping
// each layer's file path to its declared digest, and blobs by digest. It
// records every reference pulled and every digest opened, because "no byte
// was written before verification" and "the store was asked for exactly the
// pinned digests" are only observable from the calls.
type fakeStore struct {
	mu        sync.Mutex
	manifests map[string]map[string]string
	blobs     map[string][]byte
	pullErr   error
	pulled    []string
	opened    []string
	released  int
}

func newFakeStore() *fakeStore {
	return &fakeStore{manifests: map[string]map[string]string{}, blobs: map[string][]byte{}}
}

// publish stores the guest artifact for (version, pin) with the given bytes
// under the digests the pin names, which is what an honest server does.
func (s *fakeStore) publish(t *testing.T, version string, pin GuestKernelPin, kernel, initramfs []byte) {
	t.Helper()
	art, err := NewStoreArtifact(version, pin)
	if err != nil {
		t.Fatalf("store artifact: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	layers := map[string]string{}
	for _, l := range art.Layers {
		layers[l.FileName] = l.Digest
	}
	s.manifests[art.Reference(testStoreHost)] = layers
	s.blobs["sha256:"+pin.ImageSHA256] = kernel
	s.blobs["sha256:"+pin.InitramfsSHA256] = initramfs
}

func (s *fakeStore) PullGuest(_ context.Context, ref string) (map[string]string, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pulled = append(s.pulled, ref)
	if s.pullErr != nil {
		return nil, nil, s.pullErr
	}
	m, ok := s.manifests[ref]
	if !ok {
		return nil, nil, fmt.Errorf("manifest %s: not found", ref)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out, func() {
		s.mu.Lock()
		s.released++
		s.mu.Unlock()
	}, nil
}

func (s *fakeStore) OpenBlob(digest string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opened = append(s.opened, digest)
	b, ok := s.blobs[digest]
	if !ok {
		return nil, fmt.Errorf("blob %s: %w", digest, os.ErrNotExist)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (s *fakeStore) counts() (pulled, opened, released int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pulled), len(s.opened), s.released
}

// assertUntouched fails unless the cache root was never created: the proof
// that a refused pull wrote nothing to the guest-artifacts cache.
func assertUntouched(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		entries, _ := os.ReadDir(dir)
		t.Fatalf("the guest-artifacts cache was written before verification: stat err %v, entries %v", err, entries)
	}
}

func TestEnsureFromClusterStoreByPinnedDigest(t *testing.T) {
	t.Run("the seam names the repository, the type and the pin's digests", func(t *testing.T) {
		pin, err := Lookup(ActiveGuestKernel)
		if err != nil {
			t.Fatalf("lookup the active pin: %v", err)
		}
		art, err := ClusterStoreArtifact(ActiveGuestKernel)
		if err != nil {
			t.Fatalf("ClusterStoreArtifact: %v", err)
		}
		if GuestStoreRepository != "k3sm-system/guest" || art.Repository != GuestStoreRepository {
			t.Errorf("repository = %q", art.Repository)
		}
		if art.Tag != ActiveGuestKernel {
			t.Errorf("tag = %q, want the pin identity %q", art.Tag, ActiveGuestKernel)
		}
		if art.ArtifactType != artifactv1.ArtifactTypeGuest {
			t.Errorf("artifactType = %q", art.ArtifactType)
		}
		want := []StoreLayer{
			{MediaType: artifactv1.MediaTypeGuestKernel, Digest: "sha256:" + pin.ImageSHA256, FileName: ImageFileName},
			{MediaType: artifactv1.MediaTypeGuestInitramfs, Digest: "sha256:" + pin.InitramfsSHA256, FileName: InitramfsFileName},
		}
		if len(art.Layers) != len(want) {
			t.Fatalf("layers = %+v, want %+v", art.Layers, want)
		}
		for i := range want {
			if art.Layers[i] != want[i] {
				t.Errorf("layer %d = %+v, want %+v", i, art.Layers[i], want[i])
			}
		}
		if got := art.Reference("reg:5000"); got != "reg:5000/k3sm-system/guest:"+ActiveGuestKernel {
			t.Errorf("reference = %q", got)
		}
		for _, l := range art.Layers {
			if !artifactv1.GuestAllowSet().AllowsLayer(art.ArtifactType, l.MediaType) {
				t.Errorf("layer %s is outside the guest allow-set", l.MediaType)
			}
			if err := artifactv1.ValidatePath(l.FileName); err != nil {
				t.Errorf("layer file name %q: %v", l.FileName, err)
			}
		}
	})

	t.Run("a cold cache is filled from the store by the pinned digests", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
		pin := testPin()
		st := newFakeStore()
		st.publish(t, testStoreVersion, pin, testKernelBytes, testInitramfsBytes)

		got, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, pin, testStoreHost, st)
		if err != nil {
			t.Fatalf("ensure from the store: %v", err)
		}
		if b := readFile(t, got.KernelPath); !bytes.Equal(b, testKernelBytes) {
			t.Errorf("kernel bytes = %q", b)
		}
		if b := readFile(t, got.InitramfsPath); !bytes.Equal(b, testInitramfsBytes) {
			t.Errorf("initramfs bytes = %q", b)
		}
		if want := filepath.Join(dir, pin.SetDigest(), ImageFileName); got.KernelPath != want {
			t.Errorf("kernel path = %q, want %q", got.KernelPath, want)
		}
		if got.Cmdline != pin.Cmdline {
			t.Errorf("cmdline = %q", got.Cmdline)
		}
		if want := testStoreHost + "/k3sm-system/guest:" + testStoreVersion; len(st.pulled) != 1 || st.pulled[0] != want {
			t.Errorf("pulled %v, want exactly [%s]", st.pulled, want)
		}
		for _, d := range st.opened {
			if d != "sha256:"+pin.ImageSHA256 && d != "sha256:"+pin.InitramfsSHA256 {
				t.Errorf("opened a blob the pin does not name: %s", d)
			}
		}
		if _, _, released := st.counts(); released != 1 {
			t.Errorf("the pull was released %d times, want 1", released)
		}
		if temps := tempFiles(t, dir); len(temps) != 0 {
			t.Errorf("temp files left: %v", temps)
		}
		for _, p := range []string{got.KernelPath, got.InitramfsPath} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o644 {
				t.Errorf("%s mode = %v, want 0644", p, fi.Mode().Perm())
			}
		}

		// Warm: a verified set needs no store at all, so a worker whose server
		// is down still boots the set it verified.
		st.pullErr = errors.New("server unreachable")
		if _, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, pin, testStoreHost, st); err != nil {
			t.Fatalf("warm ensure: %v", err)
		}
		if pulled, _, _ := st.counts(); pulled != 1 {
			t.Errorf("a warm cache contacted the store (%d pulls)", pulled)
		}
	})

	t.Run("a store without the pin fails closed naming the pin", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
		st := newFakeStore()
		st.publish(t, "v6.18.40-ffffffffffff", pinFor([]byte("old k"), []byte("old i")), []byte("old k"), []byte("old i"))

		_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, testPin(), testStoreHost, st)
		if !errors.Is(err, ErrNotInClusterStore) {
			t.Fatalf("err = %v, want ErrNotInClusterStore", err)
		}
		var se *ClusterStoreError
		if !errors.As(err, &se) {
			t.Fatalf("err = %T, want *ClusterStoreError", err)
		}
		if se.Version != testStoreVersion {
			t.Errorf("error names version %q, want %q", se.Version, testStoreVersion)
		}
		if !strings.Contains(err.Error(), testStoreVersion) {
			t.Errorf("message does not name the pin: %v", err)
		}
		assertUntouched(t, dir)
	})

	t.Run("a refused argument never reaches the store", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
		st := newFakeStore()
		bad := testPin()
		bad.ImageSHA256 = ""
		for name, call := range map[string]func() error{
			"relative dir": func() error {
				_, err := EnsureGuestArtifactsFromStore(context.Background(), "rel", testStoreVersion, testPin(), testStoreHost, st)
				return err
			},
			"no store": func() error {
				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, testPin(), testStoreHost, nil)
				return err
			},
			"no registry host": func() error {
				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, testPin(), "", st)
				return err
			},
			"unminted pin": func() error {
				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, bad, testStoreHost, st)
				return err
			},
			"version not a tag": func() error {
				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, "v6/../x", testPin(), testStoreHost, st)
				return err
			},
		} {
			if err := call(); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		if pulled, _, _ := st.counts(); pulled != 0 {
			t.Errorf("%d pulls for refused arguments", pulled)
		}
		assertUntouched(t, dir)
	})
}

func TestWrongDigestFromStoreRefused(t *testing.T) {
	pin := testPin()

	t.Run("bytes that do not hash to the pin", func(t *testing.T) {
		for _, which := range []string{ImageFileName, InitramfsFileName} {
			t.Run(which, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
				st := newFakeStore()
				k, i := testKernelBytes, testInitramfsBytes
				if which == ImageFileName {
					k = []byte("someone else's kernel\n")
				} else {
					i = []byte("someone else's initramfs\n")
				}
				// The manifest declares the pinned digests; the bytes lie.
				st.publish(t, testStoreVersion, pin, k, i)

				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, pin, testStoreHost, st)
				if !errors.Is(err, ErrDigestMismatch) {
					t.Fatalf("err = %v, want ErrDigestMismatch", err)
				}
				var se *ClusterStoreError
				if !errors.As(err, &se) || se.Version != testStoreVersion {
					t.Errorf("err = %v, want a *ClusterStoreError naming %s", err, testStoreVersion)
				}
				assertUntouched(t, dir)
				if _, _, released := st.counts(); released != 1 {
					t.Errorf("the refused pull was released %d times, want 1", released)
				}
			})
		}
	})

	t.Run("a manifest declaring other digests", func(t *testing.T) {
		for name, mutate := range map[string]func(map[string]string){
			"kernel digest":    func(m map[string]string) { m[ImageFileName] = "sha256:" + hashOf([]byte("x")) },
			"initramfs digest": func(m map[string]string) { m[InitramfsFileName] = "sha256:" + hashOf([]byte("y")) },
			"unprefixed":       func(m map[string]string) { m[ImageFileName] = pin.ImageSHA256 },
			"layer missing":    func(m map[string]string) { delete(m, InitramfsFileName) },
			"extra layer":      func(m map[string]string) { m["extra"] = "sha256:" + pin.ImageSHA256 },
			"swapped": func(m map[string]string) {
				m[ImageFileName], m[InitramfsFileName] = m[InitramfsFileName], m[ImageFileName]
			},
		} {
			t.Run(name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
				st := newFakeStore()
				st.publish(t, testStoreVersion, pin, testKernelBytes, testInitramfsBytes)
				for _, m := range st.manifests {
					mutate(m)
				}
				_, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, pin, testStoreHost, st)
				if !errors.Is(err, ErrDigestMismatch) {
					t.Fatalf("err = %v, want ErrDigestMismatch", err)
				}
				if _, opened, _ := st.counts(); opened != 0 {
					t.Errorf("%d blobs opened for a manifest that does not match the pin", opened)
				}
				assertUntouched(t, dir)
			})
		}
	})

	t.Run("a corrupt cached file is replaced from the store", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), GuestArtifactsSubdir)
		setDir := stageSet(t, dir, pin, []byte("rotted"), testInitramfsBytes)
		st := newFakeStore()
		st.publish(t, testStoreVersion, pin, testKernelBytes, testInitramfsBytes)
		got, err := EnsureGuestArtifactsFromStore(context.Background(), dir, testStoreVersion, pin, testStoreHost, st)
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if b := readFile(t, filepath.Join(setDir, ImageFileName)); !bytes.Equal(b, testKernelBytes) || got.KernelPath != filepath.Join(setDir, ImageFileName) {
			t.Errorf("kernel not replaced: %q", b)
		}
	})
}
