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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The cluster-store half of the package. The server ensures the pinned set
// from its release host (EnsureGuestArtifacts) and publishes it to its own
// registry; a worker takes it from there (EnsureGuestArtifactsFromStore) and
// never contacts the release host. Identity stays in pins.go: the store is
// transport, and every byte a worker installs hashes to a digest this build
// carries in source.

// GuestStoreRepository is the cluster-registry repository the server publishes
// the guest artifact to. The tag is the pin's composite identity.
const GuestStoreRepository = "k3sm-system/guest"

// ociTag is the OCI distribution tag grammar. A pin identity that is not a tag
// cannot name a store artifact, and is refused rather than escaped.
var ociTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// StoreLayer is one layer of the published guest artifact.
type StoreLayer struct {
	// MediaType is the layer media type, from the guest allow-set.
	MediaType string
	// Digest is "sha256:" plus the pin's hex digest for this artifact.
	Digest string
	// FileName is the layer's file path inside the artifact, carried as the
	// org.opencontainers.image.title annotation: ImageFileName or
	// InitramfsFileName.
	FileName string
}

// StoreArtifact is everything that names the guest artifact in the cluster
// store, derived from a pin. The publisher and the worker both take it from
// here, so the two sides cannot disagree on a name, a type or a digest.
type StoreArtifact struct {
	// Repository is GuestStoreRepository.
	Repository string
	// Tag is the pin's composite identity (for example ActiveGuestKernel).
	Tag string
	// ArtifactType is the manifest artifactType, artifactv1.ArtifactTypeGuest.
	ArtifactType string
	// Layers are the kernel layer then the initramfs layer, both raw.
	Layers []StoreLayer
}

// Reference is the tag reference of the artifact in the registry at host
// (host:port, no scheme).
func (a StoreArtifact) Reference(host string) string {
	return host + "/" + a.Repository + ":" + a.Tag
}

// ClusterStoreArtifact returns the store names for the declared pin version,
// with every fail-closed rule of Lookup. The publisher calls it with
// ActiveGuestKernel.
func ClusterStoreArtifact(version string) (StoreArtifact, error) {
	pin, err := Lookup(version)
	if err != nil {
		return StoreArtifact{}, err
	}
	return NewStoreArtifact(version, pin)
}

// NewStoreArtifact derives the store names for an explicit (version, pin) pair.
// It refuses a pin validatePin refuses and a version that is not an OCI tag.
func NewStoreArtifact(version string, pin GuestKernelPin) (StoreArtifact, error) {
	if err := validatePin(version, pin); err != nil {
		return StoreArtifact{}, err
	}
	if !ociTag.MatchString(version) {
		return StoreArtifact{}, fmt.Errorf("the guest kernel version %q is not a registry tag: %w", version, ErrPinIncomplete)
	}
	return StoreArtifact{
		Repository:   GuestStoreRepository,
		Tag:          version,
		ArtifactType: artifactv1.ArtifactTypeGuest,
		Layers: []StoreLayer{
			{MediaType: artifactv1.MediaTypeGuestKernel, Digest: "sha256:" + pin.ImageSHA256, FileName: ImageFileName},
			{MediaType: artifactv1.MediaTypeGuestInitramfs, Digest: "sha256:" + pin.InitramfsSHA256, FileName: InitramfsFileName},
		},
	}, nil
}

// ClusterStore is the worker's transport to the server's registry, declared
// at the consumer. Its production implementation is artifact.GuestStore,
// which pulls through the artifact puller's guest entry point, so the guest
// allow-set, the cluster-host check and the blob cache's re-hash all apply
// before this package sees a byte.
type ClusterStore interface {
	// PullGuest fetches the guest artifact ref names into the node's blob
	// cache and returns its layers as file path to "sha256:<hex>" digest.
	// release unpins the blobs; it is non-nil whenever err is nil.
	PullGuest(ctx context.Context, ref string) (layers map[string]string, release func(), err error)
	// OpenBlob opens a cached blob by digest for reading.
	OpenBlob(digest string) (io.ReadCloser, error)
}

// LayerExpectingStore is a ClusterStore that refuses the artifact before
// fetching any blob unless its manifest declares exactly want: the same file
// names, the pinned digests, and sizes within MaxArtifactBytes. The production
// store (artifact.GuestStore) implements it, and EnsureGuestArtifactsFromStore
// prefers it over PullGuest, so a hostile registry cannot make a worker
// download and cache anything the pin does not name. The after-pull checks
// still run either way.
type LayerExpectingStore interface {
	ClusterStore
	// PullGuestLayers is PullGuest with the expected layers checked against
	// the manifest before the first blob request.
	PullGuestLayers(ctx context.Context, ref string, want []StoreLayer) (layers map[string]string, release func(), err error)
}

// ErrNotInClusterStore reports that the pinned guest artifact could not be
// obtained from the cluster store: the server does not hold the pin, or the
// worker cannot reach it. From a worker's position the two are one event, and
// there is no fallback to the release host for either: the server must be
// upgraded to the pin, or reached, first. Compare with errors.Is.
var ErrNotInClusterStore = errors.New("guestartifacts: the pinned guest artifact is not available from the cluster store")

// ClusterStoreError is every failure of EnsureGuestArtifactsFromStore after
// its arguments are accepted. It names the pin and the reference; Err carries
// ErrNotInClusterStore or ErrDigestMismatch.
type ClusterStoreError struct {
	// Version is the pin's composite identity.
	Version string
	// Reference is the store reference that was pulled.
	Reference string
	// Err is the cause.
	Err error
}

func (e *ClusterStoreError) Error() string {
	return fmt.Sprintf("guest kernel %s from the cluster store (%s), with no release-host fallback: %v", e.Version, e.Reference, e.Err)
}

func (e *ClusterStoreError) Unwrap() error { return e.Err }

// EnsureGuestArtifactsFromStore is EnsureGuestArtifacts for a worker: the same
// cache, layout, retention and caller contract on error, with the server's
// cluster store as the only source.
//
// A set already in the cache that verifies against pin is returned without
// contacting the store. Otherwise the artifact is pulled by its tag
// reference, and refused unless its layers are exactly the two pinned digests
// under their two file names; each blob is then hashed against the pin before
// anything is written to dir, and copied in through the same
// temp-verify-rename install a release fetch uses, hashed again on the way.
// A refusal leaves dir as it found it.
func EnsureGuestArtifactsFromStore(ctx context.Context, dir, version string, pin GuestKernelPin, registryHost string, store ClusterStore) (sandbox.GuestArtifacts, error) {
	var zero sandbox.GuestArtifacts
	if !filepath.IsAbs(dir) {
		return zero, fmt.Errorf("ensure the guest artifacts from the cluster store: the cache dir %q is not an absolute path", dir)
	}
	if store == nil {
		return zero, errors.New("ensure the guest artifacts from the cluster store: no store was supplied")
	}
	if registryHost == "" {
		return zero, errors.New("ensure the guest artifacts from the cluster store: no registry host was supplied")
	}
	art, err := NewStoreArtifact(version, pin)
	if err != nil {
		return zero, err
	}

	set := pin.SetDigest()
	setDir := filepath.Join(dir, set)
	result := sandbox.GuestArtifacts{
		KernelPath:    filepath.Join(setDir, ImageFileName),
		InitramfsPath: filepath.Join(setDir, InitramfsFileName),
		Cmdline:       pin.Cmdline,
	}
	var stale []StoreLayer
	for _, l := range art.Layers {
		if got, err := digestFile(filepath.Join(setDir, l.FileName)); err != nil || "sha256:"+got != l.Digest {
			stale = append(stale, l)
		}
	}
	if len(stale) == 0 {
		sweepTemps(ctx, dir)
		pruneSets(ctx, dir, set)
		return result, nil
	}

	ref := art.Reference(registryHost)
	fail := func(err error) error { return &ClusterStoreError{Version: version, Reference: ref, Err: err} }

	var (
		layers  map[string]string
		release func()
	)
	if es, ok := store.(LayerExpectingStore); ok {
		layers, release, err = es.PullGuestLayers(ctx, ref, art.Layers)
	} else {
		layers, release, err = store.PullGuest(ctx, ref)
	}
	if err != nil {
		return zero, fail(fmt.Errorf("%w: %w", ErrNotInClusterStore, err))
	}
	if release != nil {
		defer release()
	}
	if err := matchLayers(layers, art.Layers); err != nil {
		return zero, fail(err)
	}
	// Verify every needed blob before the first write to dir: a store that
	// declares the pinned digests and serves other bytes is refused here,
	// with the cache untouched.
	for _, l := range stale {
		if err := verifyBlob(ctx, store, l); err != nil {
			return zero, fail(err)
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return zero, fmt.Errorf("create the guest artifact cache %s: %w", dir, err)
	}
	for _, l := range stale {
		final := filepath.Join(setDir, l.FileName)
		if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
			return zero, fmt.Errorf("remove the stale guest artifact %s: %w", final, err)
		}
		what := ref + "@" + l.Digest
		hexDigest := l.Digest[len("sha256:"):]
		if err := installVerified(ctx, dir, final, what, hexDigest, func() (io.ReadCloser, error) {
			return openCapped(store, l.Digest)
		}); err != nil {
			if errors.Is(err, ErrDigestMismatch) {
				return zero, fail(err)
			}
			return zero, err
		}
	}

	sweepTemps(ctx, dir)
	pruneSets(ctx, dir, set)
	return result, nil
}

// matchLayers refuses a pulled artifact whose layers are not exactly the
// pinned ones: the same file names, each with its pinned digest, and nothing
// else.
func matchLayers(got map[string]string, want []StoreLayer) error {
	if len(got) != len(want) {
		return fmt.Errorf("the store artifact has %d layers, the pin names %d: %w", len(got), len(want), ErrDigestMismatch)
	}
	for _, l := range want {
		d, ok := got[l.FileName]
		if !ok {
			return fmt.Errorf("the store artifact has no %s layer: %w", l.FileName, ErrDigestMismatch)
		}
		if d != l.Digest {
			return fmt.Errorf("the store artifact's %s layer is %.80q, the pin names %s: %w", l.FileName, d, l.Digest, ErrDigestMismatch)
		}
	}
	return nil
}

// verifyBlob hashes one blob from the store against its pinned digest.
func verifyBlob(ctx context.Context, store ClusterStore, l StoreLayer) error {
	body, err := openCapped(store, l.Digest)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, &ctxReader{ctx: ctx, r: body}); err != nil {
		return fmt.Errorf("read the %s blob %s: %w", l.FileName, l.Digest, err)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != l.Digest {
		return fmt.Errorf("the %s blob hashes to %s, the pin names %s: %w", l.FileName, got, l.Digest, ErrDigestMismatch)
	}
	return nil
}

// openCapped opens a blob from the store under the same size cap a release
// fetch has.
func openCapped(store ClusterStore, digest string) (io.ReadCloser, error) {
	rc, err := store.OpenBlob(digest)
	if err != nil {
		return nil, fmt.Errorf("open the blob %s from the node cache: %w", digest, err)
	}
	return newCappedBody(rc, maxArtifactBytes), nil
}
