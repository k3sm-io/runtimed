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
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

// deepCache returns a Cache rooted several levels below a temp dir, plus that
// temp dir. The depth matters: a traversal via the digest's ALGORITHM half
// escapes UPWARD out of the blob root, so the assertion "nothing was created
// outside the blob root" needs somewhere above the root to observe.
func deepCache(t *testing.T) (c *Cache, outside string) {
	t.Helper()
	outside = t.TempDir()
	root := filepath.Join(outside, "a", "b", "k3sm")
	c, err := NewCache(root)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c, outside
}

// treeOf lists every path under root, relative and sorted — the observable a
// "no filesystem artifact was created" assertion compares before and after.
func treeOf(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel+"|"+d.Type().String())
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

// writeAll is a fill that writes b in one call.
func writeAll(b []byte) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := w.Write(b)
		return err
	}
}

// blobDirEntries lists the blob directory for digest's algorithm, which must be
// EMPTY after a rejected commit — the temp file is gone and the destination was
// never created.
func blobDirEntries(t *testing.T, c *Cache, algo string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(c.blobsDir(), algo))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read blob dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// fakeLayer is a layer that is INTERNALLY SELF-CONSISTENT about the wrong bytes:
// Compressed(), Digest() and Size() all describe payload. The image's manifest
// descriptor still names the original layer, so this fixture is exactly the
// tautology case — a checker that took its "claimed" digest from the layer (as
// writeBlob's caller did before B129) would compare the payload against a digest
// derived FROM the payload and always pass.
type fakeLayer struct {
	ggcrv1.Layer
	payload []byte
}

func (l fakeLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.payload)), nil
}

func (l fakeLayer) Digest() (ggcrv1.Hash, error) {
	h, _, err := ggcrv1.SHA256(bytes.NewReader(l.payload))
	return h, err
}

func (l fakeLayer) Size() (int64, error) { return int64(len(l.payload)), nil }

// lyingImage serves substituted layer bytes while its Manifest() (inherited)
// keeps naming the ORIGINAL descriptors. The substituted payload is the same
// LENGTH as the layer it replaces, so the size resource guard cannot be what
// rejects it — the digest comparison must be.
type lyingImage struct {
	ggcrv1.Image
}

// shortManifestImage reports MORE layers than its manifest lists — the shape that
// used to index past mfst.Layers and PANIC inside the root daemon.
type shortManifestImage struct {
	ggcrv1.Image
}

func (i shortManifestImage) Manifest() (*ggcrv1.Manifest, error) {
	m, err := i.Image.Manifest()
	if err != nil {
		return nil, err
	}
	trimmed := *m
	trimmed.Layers = append([]ggcrv1.Descriptor(nil), m.Layers[:len(m.Layers)-1]...)
	return &trimmed, nil
}

func (i lyingImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := i.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]ggcrv1.Layer, len(ls))
	for j, l := range ls {
		sz, serr := l.Size()
		if serr != nil {
			return nil, serr
		}
		out[j] = fakeLayer{Layer: l, payload: bytes.Repeat([]byte{0xAA}, int(sz))}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

// TestWriteBlobRejectsDigestMismatch is the B129 gate: the content-addressed
// store verifies every blob against its claimed digest AT THE COMMIT POINT, in
// one exported home (Cache.CommitBlob) that Puller.writeBlob merely delegates to.
//
// EVERY assertion the gate makes is a subtest of THIS function — the item is run
// as `go test -run '^TestWriteBlobRejectsDigestMismatch$'`, so anything parked in
// a sibling Test... would not be gate-proving.
//
// The rows drive Cache.CommitBlob DIRECTLY with a fake fill, not through Pull
// with a fake FetchFunc. A fetcher-driven table structurally cannot reach the
// config-blob call site: for any ordinary go-containerregistry image
// ConfigName() IS the sha256 of RawConfigFile(), so the config path cannot be
// handed mismatched bytes, and a layer-only fix would pass such a table. One
// through-Pull row is kept as a WIRING witness (the error surfaces out of Pull
// rather than being swallowed), never as the whole table.
//
// Behaviour at main, for each row:
//
//	correct bytes commit                      → committed (already green)
//	digest-mismatched bytes                   → COMMITTED under the claimed name (RED)
//	short stream                              → COMMITTED under the claimed name (RED)
//	oversized stream                          → COMMITTED, unbounded bytes first (RED)
//	"../../etc:passwd"                        → MkdirAll'd <root>/../etc as root (RED)
//	layer contradicting its manifest descriptor → COMMITTED via Pull (RED)
//	cache hit / regular-file cache hit        → see each row
func TestWriteBlobRejectsDigestMismatch(t *testing.T) {
	t.Run("commits correct bytes", func(t *testing.T) {
		c, _ := deepCache(t)
		want := []byte("the actual blob payload")
		dig := digestOf(want)

		wrote, err := c.CommitBlob(dig, int64(len(want)), writeAll(want))
		if err != nil {
			t.Fatalf("CommitBlob(correct bytes): %v", err)
		}
		if !wrote {
			t.Error("CommitBlob reported a cache hit for a blob that was not cached")
		}
		if !c.Has(dig) {
			t.Fatalf("blob %s not cached after a successful commit", dig)
		}
		p, err := c.BlobPath(dig)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read committed blob: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("committed blob = %q, want %q", got, want)
		}
	})

	// THE row that transitions. Asserting only "an error was returned" + "the
	// temp file is gone" is satisfied by a compare-then-rename-anyway diff (the
	// rename consumes the temp, so the removal assertion passes too). The
	// DESTINATION path is the only observable that distinguishes rejected from
	// rejected-but-committed.
	t.Run("rejects digest mismatch and commits nothing", func(t *testing.T) {
		c, _ := deepCache(t)
		claimed := digestOf([]byte("what the manifest says"))
		actual := []byte("what the fetcher actually produced")

		wrote, err := c.CommitBlob(claimed, int64(len(actual)), writeAll(actual))
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("CommitBlob(mismatched bytes) err = %v, want ErrDigestMismatch", err)
		}
		if wrote {
			t.Error("CommitBlob reported a write for a rejected blob")
		}
		if c.Has(claimed) {
			t.Error("the rejected blob is present at its destination path")
		}
		if ents := blobDirEntries(t, c, "sha256"); len(ents) != 0 {
			t.Errorf("blob dir is not empty after a rejection: %v", ents)
		}
		// REGRESSION PIN, not red-before evidence: the temp file is removed. This
		// clause was already green before B129 (the deferred os.Remove predates
		// this change), which is exactly why it cannot be the gate's decisive
		// assertion — a compare-then-rename-anyway diff satisfies it, because the
		// rename consumes the temp file.
		for _, e := range blobDirEntries(t, c, "sha256") {
			if strings.HasPrefix(e, ".blob-") {
				t.Errorf("temp file %q survived the rejection", e)
			}
		}
	})

	// An input-shape row over the SAME mechanism, not a distinct branch: fewer
	// bytes simply hash differently. It deliberately introduces no second error
	// class.
	t.Run("rejects a short stream", func(t *testing.T) {
		c, _ := deepCache(t)
		full := []byte("a complete layer payload, all of it")
		claimed := digestOf(full)

		wrote, err := c.CommitBlob(claimed, int64(len(full)), writeAll(full[:10]))
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("CommitBlob(short stream) err = %v, want ErrDigestMismatch", err)
		}
		if wrote || c.Has(claimed) {
			t.Errorf("a short stream was committed (wrote=%v, cached=%v)", wrote, c.Has(claimed))
		}
		if ents := blobDirEntries(t, c, "sha256"); len(ents) != 0 {
			t.Errorf("blob dir is not empty after a rejection: %v", ents)
		}
	})

	// The RESOURCE GUARD (distinct from the integrity check): a mismatch is only
	// knowable at EOF, so an unbounded stream could fill the cache volume — which
	// on a single-Mac cluster also holds the kine datastore — before the hash
	// could reject it.
	t.Run("rejects an oversized stream", func(t *testing.T) {
		c, _ := deepCache(t)
		declared := []byte("exactly this much was declared")
		claimed := digestOf(declared)
		flood := bytes.Repeat([]byte{'x'}, len(declared)*100)

		wrote, err := c.CommitBlob(claimed, int64(len(declared)), writeAll(flood))
		if !errors.Is(err, ErrBlobTooLarge) {
			t.Fatalf("CommitBlob(oversized) err = %v, want ErrBlobTooLarge", err)
		}
		if wrote || c.Has(claimed) {
			t.Errorf("an oversized stream was committed (wrote=%v, cached=%v)", wrote, c.Has(claimed))
		}
		if ents := blobDirEntries(t, c, "sha256"); len(ents) != 0 {
			t.Errorf("blob dir is not empty after a rejection: %v", ents)
		}
	})

	// Fail-closed on the digest STRING, before any side effect. The pre-B129
	// blobPath sanitized only the hex half, so the algorithm half flowed into
	// filepath.Join unchecked: "../../etc:passwd" resolved to <root>/../etc/passwd,
	// which pull.go then MkdirAll'd 0755 as the root LaunchDaemon before any
	// hashing could reject it. Asserting only "an error was returned" would not
	// distinguish "rejected before any side effect" from "rejected after MkdirAll".
	t.Run("rejects unsupported or malformed digests with no side effect", func(t *testing.T) {
		hex64 := strings.Repeat("ab", 32)
		cases := []struct {
			name   string
			digest string
			want   error
		}{
			// Algorithm half — the traversal vector.
			{"traversal via algorithm", "../../etc:passwd", ErrUnsupportedDigestAlgorithm},
			{"dotdot algorithm", "..:x", ErrUnsupportedDigestAlgorithm},
			{"embedded traversal", "a/../../b:c", ErrUnsupportedDigestAlgorithm},
			{"absolute algorithm", "/etc:passwd", ErrUnsupportedDigestAlgorithm},
			// Algorithm half — not allowlisted.
			{"sha512 not allowlisted", "sha512:" + strings.Repeat("cd", 64), ErrUnsupportedDigestAlgorithm},
			{"md5", "md5:" + strings.Repeat("ef", 16), ErrUnsupportedDigestAlgorithm},
			{"algorithm case is significant", "SHA256:" + hex64, ErrUnsupportedDigestAlgorithm},
			// Shape / body.
			{"empty", "", ErrInvalidDigest},
			{"bare hex, no algorithm", hex64, ErrInvalidDigest},
			{"empty algorithm", ":" + hex64, ErrInvalidDigest},
			{"empty body", "sha256:", ErrInvalidDigest},
			{"short body", "sha256:deadbeef", ErrInvalidDigest},
			{"long body", "sha256:" + hex64 + "ab", ErrInvalidDigest},
			{"uppercase hex body", "sha256:" + strings.ToUpper(hex64), ErrInvalidDigest},
			{"non-hex body", "sha256:" + strings.Repeat("zz", 32), ErrInvalidDigest},
			{"traversal in body", "sha256:../../../etc/passwd", ErrInvalidDigest},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c, outside := deepCache(t)
				before := treeOf(t, outside)

				filled := false
				wrote, err := c.CommitBlob(tc.digest, 16, func(w io.Writer) error {
					filled = true
					_, werr := w.Write([]byte("payload"))
					return werr
				})
				if !errors.Is(err, tc.want) {
					t.Fatalf("CommitBlob(%q) err = %v, want %v", tc.digest, err, tc.want)
				}
				if wrote {
					t.Error("CommitBlob reported a write for a rejected digest")
				}
				if filled {
					t.Error("fill ran for a rejected digest (rejection must precede any side effect)")
				}
				if after := treeOf(t, outside); !equalTrees(before, after) {
					t.Errorf("filesystem changed under a rejected digest:\nbefore %v\nafter  %v", before, after)
				}
				// blobPath must not hand out a path either — every path-building
				// caller (Has, B117's ingest) inherits the same allowlist.
				if p, perr := c.BlobPath(tc.digest); perr == nil {
					t.Errorf("blobPath(%q) returned %q, want an error", tc.digest, p)
				}
				if c.Has(tc.digest) {
					t.Errorf("Has(%q) reported a hit for a rejected digest", tc.digest)
				}
			})
		}
	})

	// The documented CEILING, made executable rather than left as folklore:
	// verification happens at WRITE time only. A blob already on disk is trusted
	// on its NAME — including every blob written before B129, which this repo
	// never hashed. Verify-on-read is deliberately not done here (it is O(image
	// bytes) on the hot path and would regress the M1.1-a1 cache-hit acceptance
	// path); the natural closer is M11.2-d7, the unpacker.
	t.Run("cache hit skips verification (the documented ceiling)", func(t *testing.T) {
		c, _ := deepCache(t)
		dig := digestOf([]byte("the honest bytes"))
		p, err := c.BlobPath(dig)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		garbage := []byte("NOT the bytes this digest names")
		if err := os.WriteFile(p, garbage, 0o644); err != nil {
			t.Fatal(err)
		}

		wrote, err := c.CommitBlob(dig, 64, writeAll([]byte("the honest bytes")))
		if err != nil {
			t.Fatalf("CommitBlob over an existing blob: %v", err)
		}
		if wrote {
			t.Error("CommitBlob rewrote an already-cached blob")
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, garbage) {
			t.Errorf("the cached blob was rewritten: got %q, want the pre-existing %q", got, garbage)
		}
	})

	// A directory (or any non-regular file) at the blob path is NOT a blob.
	// Accepting one as a cache hit would let a planted directory suppress the
	// write forever — the fast path used to be a bare os.Stat.
	t.Run("cache hit requires a regular file", func(t *testing.T) {
		c, _ := deepCache(t)
		dig := digestOf([]byte("blocked by a directory"))
		p, err := c.BlobPath(dig)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "planted"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		// Assert the SPECIFIC outcome, not merely "some error": accepting any error
		// pins no forward behaviour, so a later change that turned this into a
		// silent success or a different failure would stay green.
		wrote, err := c.CommitBlob(dig, 22, writeAll([]byte("blocked by a directory")))
		if err == nil {
			t.Errorf("CommitBlob over a directory = (wrote=%v, nil), want a rename failure", wrote)
		}
		if wrote {
			t.Error("CommitBlob reported wrote=true over a directory")
		}
		if c.Has(dig) {
			t.Error("Has reported a hit for a directory at the blob path")
		}
	})

	// F1: os.Stat FOLLOWS symlinks, so a bare Stat+IsRegular would accept a
	// symlink→regular as a cached blob — suppressing verification forever for that
	// digest and pointing every downstream reader (materialize, the M11.2-d7
	// unpacker) at bytes outside the cache root, as root. Lstat is what makes the
	// doc comment true.
	t.Run("a symlink at the blob path is not a cache hit", func(t *testing.T) {
		c, _ := deepCache(t)
		body := []byte("real blob bytes")
		dig := digestOf(body)
		p, err := c.BlobPath(dig)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("attacker-controlled"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, p); err != nil {
			t.Fatal(err)
		}
		if c.Has(dig) {
			t.Error("Has accepted a symlink as a cached blob")
		}
		wrote, err := c.CommitBlob(dig, int64(len(body)), writeAll(body))
		if err != nil {
			t.Fatalf("CommitBlob over a symlink: %v", err)
		}
		if !wrote {
			t.Error("a symlink was treated as a cache hit; verification was skipped")
		}
		// rename(2) replaces the symlink, so the store self-heals to real bytes.
		got, err := os.ReadFile(p)
		if err != nil || string(got) != string(body) {
			t.Errorf("blob = %q, %v; want the committed bytes (the symlink must be replaced)", got, err)
		}
		if out, _ := os.ReadFile(outside); string(out) != "attacker-controlled" {
			t.Error("the symlink target was written through, not replaced")
		}
	})

	// F2: size 0 is a REAL cap (the empty blob), not "no cap" — only the explicit
	// SizeUnknown sentinel opts out. A `size > 0` guard would silently disable the
	// cap for any descriptor declaring zero.
	t.Run("size 0 caps rather than disabling the guard", func(t *testing.T) {
		c, _ := deepCache(t)
		dig := digestOf([]byte("not empty"))
		if _, err := c.CommitBlob(dig, 0, writeAll([]byte("not empty"))); !errors.Is(err, ErrBlobTooLarge) {
			t.Errorf("CommitBlob(size=0, non-empty body) err = %v, want ErrBlobTooLarge", err)
		}
		if c.Has(dig) {
			t.Error("an over-cap blob was committed")
		}
		empty := digestOf(nil)
		if _, err := c.CommitBlob(empty, 0, writeAll(nil)); err != nil {
			t.Errorf("CommitBlob(size=0, empty body) = %v, want the empty blob to commit", err)
		}
	})

	// F8: a fill that DISCARDS its write error must not let an oversized input be
	// relabelled as a poisoned blob — the two imply different remediations.
	t.Run("an oversized stream stays ErrBlobTooLarge even if fill swallows the error", func(t *testing.T) {
		c, _ := deepCache(t)
		dig := digestOf([]byte("declared short"))
		swallow := func(w io.Writer) error {
			_, _ = w.Write([]byte("declared short")) // error deliberately discarded
			return nil
		}
		_, err := c.CommitBlob(dig, 4, swallow)
		if !errors.Is(err, ErrBlobTooLarge) {
			t.Errorf("err = %v, want ErrBlobTooLarge (not a digest mismatch)", err)
		}
		if errors.Is(err, ErrDigestMismatch) {
			t.Error("an oversized input was reported as a poisoned blob")
		}
		if c.Has(dig) {
			t.Error("an over-cap blob was committed")
		}
	})

	// WIRING witness (supplement, not the table): the claimed digest comes from
	// the MANIFEST DESCRIPTOR, and the rejection propagates out of Pull rather
	// than being swallowed.
	//
	// The fixture's layer is self-consistent about the wrong bytes — its Digest()
	// IS the sha256 of what its Compressed() serves — so a checker that took the
	// claimed digest from the layer (img.ConfigName()/layer.Digest(), the
	// pre-B129 sources) would compare the bytes against a digest derived from
	// those same bytes and could never fail. Only the manifest descriptor
	// disagrees.
	t.Run("pull rejects a layer contradicting its manifest descriptor", func(t *testing.T) {
		base, err := random.Image(512, 2)
		if err != nil {
			t.Fatalf("random image: %v", err)
		}
		img := lyingImage{Image: withPlatform(t, base, "darwin", "arm64", "")}
		ff := &fakeFetch{img: img}

		c, _ := deepCache(t)
		p := mustPuller(t, c, ff.fetch)

		res, err := p.Pull(context.Background(), "example.com/lying:v1", nil, nativePolicy())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("Pull(lying layer) = (%+v, %v), want ErrDigestMismatch", res, err)
		}
		// The honest descriptor digests must not be cached — the substituted
		// bytes were rejected, and the fixture's own (self-consistent) digest must
		// not have been used as the storage key either.
		mfst, err := img.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range mfst.Layers {
			if c.Has(d.Digest.String()) {
				t.Errorf("layer %s was committed despite contradicting bytes", d.Digest)
			}
		}
		layers, err := img.Layers()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range layers {
			d, derr := l.Digest()
			if derr != nil {
				t.Fatal(derr)
			}
			if c.Has(d.String()) {
				t.Errorf("substituted bytes were committed under their OWN digest %s", d)
			}
		}
	})

	// F3: a self-contradictory manifest is NOT a poisoned blob — no blob was
	// hashed, so ErrDigestMismatch's message would be false. The two sentinels stay
	// distinguishable because the remediations differ: reject the source vs
	// quarantine the blob.
	t.Run("a manifest disagreeing about its layer count is ErrManifestInconsistent", func(t *testing.T) {
		base, err := random.Image(512, 2)
		if err != nil {
			t.Fatalf("random image: %v", err)
		}
		img := shortManifestImage{Image: withPlatform(t, base, "darwin", "arm64", "")}
		ff := &fakeFetch{img: img}

		c, _ := deepCache(t)
		p := mustPuller(t, c, ff.fetch)

		res, err := p.Pull(context.Background(), "example.com/arity:v1", nil, nativePolicy())
		if !errors.Is(err, ErrManifestInconsistent) {
			t.Fatalf("Pull(layer-count divergence) = (%+v, %v), want ErrManifestInconsistent", res, err)
		}
		if errors.Is(err, ErrDigestMismatch) {
			t.Error("a manifest inconsistency was reported as a blob digest mismatch")
		}
	})
}

// equalTrees compares two sorted path listings.
func equalTrees(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
