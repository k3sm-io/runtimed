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
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// pressurePuller builds a Puller whose free-space sampler is a fake returning
// (free, ferr), with the given threshold.
func pressurePuller(t *testing.T, cache *Cache, fetch FetchFunc, free uint64, ferr error, threshold uint64) *Puller {
	t.Helper()
	p, err := NewPuller(cache, fetch,
		WithMinFreeBytes(threshold),
		WithFreeBytesFunc(func(string) (uint64, error) { return free, ferr }))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	return p
}

// pressureImage is a small platform-correct fixture image.
func pressureImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return withPlatform(t, img, "darwin", "arm64", "")
}

// shrinkLayerImage lies about its first layer's manifest-declared size (the
// lying-registry shape: stream more bytes than the manifest discloses).
type shrinkLayerImage struct {
	ggcrv1.Image
}

func (s shrinkLayerImage) Manifest() (*ggcrv1.Manifest, error) {
	m, err := s.Image.Manifest()
	if err != nil {
		return nil, err
	}
	clone := *m
	clone.Layers = append([]ggcrv1.Descriptor{}, m.Layers...)
	clone.Layers[0].Size = 1
	return &clone, nil
}

// TestDiskPressureStopsNewPulls is the B114 disk-pressure gate: the pull path
// refuses new blob writes fail-closed under (or unable to sample) free-space
// pressure, reserves the manifest-declared size, and hard-caps every blob
// stream at that declared size.
func TestDiskPressureStopsNewPulls(t *testing.T) {
	t.Run("ample free space admits the pull", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: pressureImage(t)}
		p := pressurePuller(t, cache, ff.fetch, 1<<40, nil, DefaultMinFreeBytes)
		res, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
		if err != nil {
			t.Fatalf("pull with ample space: %v", err)
		}
		if !cache.Has(res.ManifestDigest) || !cache.Has(res.Manifest.Config.Digest) {
			t.Error("blobs not cached after admitted pull")
		}
	})

	t.Run("free below threshold refuses with the numbers", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: pressureImage(t)}
		const free, threshold = 12345, 67890
		p := pressurePuller(t, cache, ff.fetch, free, nil, threshold)
		_, err = p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
		if !errors.Is(err, ErrDiskPressure) {
			t.Fatalf("want ErrDiskPressure, got %v", err)
		}
		// The on-call one-liner: observed free bytes and threshold in the message.
		for _, num := range []string{fmt.Sprint(free), fmt.Sprint(threshold)} {
			if !strings.Contains(err.Error(), num) {
				t.Errorf("refusal message %q does not name %s", err, num)
			}
		}
	})

	t.Run("statfs error fails closed with a distinct error", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: pressureImage(t)}
		p := pressurePuller(t, cache, ff.fetch, 0, errors.New("volume is dying"), 1)
		_, err = p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
		if !errors.Is(err, ErrDiskSpaceUnknown) {
			t.Fatalf("want ErrDiskSpaceUnknown, got %v", err)
		}
		if errors.Is(err, ErrDiskPressure) {
			t.Error("sampling failure must be DISTINCT from a measured shortage")
		}
		if !strings.Contains(err.Error(), "volume is dying") {
			t.Errorf("refusal %q does not name the sampling failure", err)
		}
	})

	t.Run("declared size reservation crosses the threshold", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: pressureImage(t)}
		// Free is just above the threshold, but the very first blob (the
		// persisted manifest, a few hundred bytes) declares more than the slack.
		const threshold = 1 << 20
		p := pressurePuller(t, cache, ff.fetch, threshold+10, nil, threshold)
		_, err = p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
		if !errors.Is(err, ErrDiskPressure) {
			t.Fatalf("want ErrDiskPressure from the declared-size reservation, got %v", err)
		}
	})

	t.Run("stream exceeding declared size errors", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: shrinkLayerImage{Image: pressureImage(t)}}
		p := pressurePuller(t, cache, ff.fetch, 1<<40, nil, 1)
		_, err = p.Pull(context.Background(), "example.com/liar:v1", nil, nativePolicy())
		if !errors.Is(err, ErrOversizeBlob) {
			t.Fatalf("want ErrOversizeBlob, got %v", err)
		}
	})

	t.Run("decision boundary", func(t *testing.T) {
		cases := []struct {
			name                      string
			free, declared, threshold uint64
			want                      bool
		}{
			{"exact-at-threshold zero declared", 100, 0, 100, false},
			{"exact-at-threshold one byte", 100, 1, 100, true},
			{"one under threshold", 99, 0, 100, true},
			{"declared fits exactly", 101, 1, 100, false},
			{"declared crosses by one", 101, 2, 100, true},
			{"all zero", 0, 0, 0, false},
			{"zero free one declared", 0, 1, 0, true},
			{"max free max declared", math.MaxUint64, math.MaxUint64, 1, true},
			{"max free no threshold", math.MaxUint64, 100, 0, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := shouldStopPulls(tc.free, tc.declared, tc.threshold); got != tc.want {
					t.Errorf("shouldStopPulls(%d, %d, %d) = %v, want %v", tc.free, tc.declared, tc.threshold, got, tc.want)
				}
			})
		}
	})
}
