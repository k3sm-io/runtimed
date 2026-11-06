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
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// panickingSource serves prefix and then panics with value. It sits under a real
// decompressor, so a panic it raises unwinds through the decoder exactly as one
// raised by the decoder itself does, and it can only reach the unpacker's recover
// if the decode runs on the caller's goroutine: on any other goroutine it would
// kill the test binary.
type panickingSource struct {
	prefix []byte
	value  any
}

func (s *panickingSource) Read(p []byte) (int, error) {
	if len(s.prefix) > 0 {
		n := copy(p, s.prefix)
		s.prefix = s.prefix[n:]
		return n, nil
	}
	panic(s.value)
}

// panickingByter has the Bytes and Len methods that make zstd.NewReader start
// decoding at construction, and panics from them.
type panickingByter struct{ panickingSource }

func (s *panickingByter) Bytes() []byte { panic(s.value) }
func (s *panickingByter) Len() int      { panic(s.value) }

// panicAfterReader passes n bytes of r and then panics with value. It stands
// between the decompressor and the applier, so a panic it raises unwinds through
// archive/tar and the applier and through nothing below them.
type panicAfterReader struct {
	r     io.Reader
	n     int
	value any
}

func (r *panicAfterReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		panic(r.value)
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	n, err := r.r.Read(p)
	r.n -= n
	return n, err
}

// fakeDecoder is a decoder whose Read and Close are supplied by the case.
type fakeDecoder struct {
	read  func(p []byte) (int, error)
	close func() error
}

func (d *fakeDecoder) Read(p []byte) (int, error) { return d.read(p) }

func (d *fakeDecoder) Close() error {
	if d.close == nil {
		return nil
	}
	return d.close()
}

// panicStringer panics when rendered, so the recover's own rendering of a panic
// value is exercised against a value that fights back.
type panicStringer struct{}

func (panicStringer) String() string { panic("rendering the panic value") }

// deepPanic panics from n frames down.
func deepPanic(n int) {
	if n == 0 {
		panic("deep")
	}
	deepPanic(n - 1)
}

// commitLayerImage commits a one-layer image whose layer blob is the given bytes,
// so a case can pick the compression and the media type.
func commitLayerImage(t *testing.T, c *Cache, plain, blob []byte, mediaType string) *runtimev1.ImageManifest {
	t.Helper()
	sum := func(b []byte) string {
		h, _, err := ggcrv1.SHA256(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		return h.String()
	}
	commit := func(b []byte) string {
		d := sum(b)
		if _, err := c.CommitBlob(d, int64(len(b)), func(w io.Writer) error {
			_, werr := w.Write(b)
			return werr
		}); err != nil {
			t.Fatal(err)
		}
		return d
	}
	cfg := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + sum(plain) + `"]}}`)
	return &runtimev1.ImageManifest{
		Reference: "example.com/panic:v1",
		Config:    &runtimev1.Descriptor{Digest: commit(cfg), Size: int64(len(cfg))},
		Layers: []*runtimev1.Descriptor{{
			Digest:    commit(blob),
			Size:      int64(len(blob)),
			MediaType: mediaType,
		}},
	}
}

// layerFixture is one tar in the compressions the cases read it through.
type layerFixture struct {
	plain, gz, zs []byte
}

func newLayerFixture(t *testing.T) layerFixture {
	t.Helper()
	plain := buildTar(t, []tarSpec{
		{name: "first", mode: 0o644, data: strings.Repeat("first entry ", 4096)},
		{name: "app", mode: 0o755, data: strings.Repeat("layer content ", 4096)},
	})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return layerFixture{plain: plain, gz: gz.Bytes(), zs: zstdCompress(t, plain)}
}

// unpackSeeingPanics runs Unpack and reports a panic that reached its caller,
// which is the failure these tests exist to catch.
func unpackSeeingPanics(t *testing.T, u *Unpacker, mfst *runtimev1.ImageManifest, policy UnpackPolicy) (tree *Tree, err error) {
	t.Helper()
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("a panic reached the caller: %s", quoteBounded(fmt.Sprint(v), 80))
			err = fmt.Errorf("panicked")
		}
	}()
	return u.Unpack(context.Background(), mfst, policy)
}

// stagingDirs lists the staging trees left in the two tree stores.
func stagingDirs(t *testing.T, c *Cache) []string {
	t.Helper()
	var out []string
	for _, root := range []string{c.UnpackedRoot(), c.SnapshotsRoot()} {
		entries, err := os.ReadDir(root)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tree-") {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

// assertRefused pins the outcome every panic must have: the malformed-layer
// verdict, no staging tree left behind, and nothing committed at the key.
func assertRefused(t *testing.T, c *Cache, u *Unpacker, mfst *runtimev1.ImageManifest, policy UnpackPolicy, err error) {
	t.Helper()
	if !errors.Is(err, ErrLayerMalformed) {
		t.Errorf("unpack error = %v, want ErrLayerMalformed", err)
	}
	if left := stagingDirs(t, c); len(left) != 0 {
		t.Errorf("staging trees left behind: %v", left)
	}
	loc, lerr := u.locate(mfst, policy)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if _, serr := os.Stat(loc.dir); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("a tree is committed at the key: stat error = %v", serr)
	}
}

// panicLog is a logger capturing JSON records.
type panicLog struct{ buf bytes.Buffer }

func (l *panicLog) logger() *slog.Logger { return slog.New(slog.NewJSONHandler(&l.buf, nil)) }

// records decodes what was logged.
func (l *panicLog) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(l.buf.String()) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// assertLoggedStack pins that exactly one bounded stack reached the log, naming
// the frame that panicked, and that none of it reached the error.
func assertLoggedStack(t *testing.T, l *panicLog, err error, frame string) {
	t.Helper()
	recs := l.records(t)
	if len(recs) != 1 {
		t.Fatalf("logged %d records, want 1: %s", len(recs), l.buf.String())
	}
	if recs[0]["level"] != "ERROR" {
		t.Errorf("log level = %v, want ERROR", recs[0]["level"])
	}
	stack, _ := recs[0]["stack"].(string)
	if !strings.Contains(stack, frame) {
		t.Errorf("logged stack does not name %q: %s", frame, stack)
	}
	if len(stack) > maxLayerPanicStackBytes {
		t.Errorf("logged stack is %d bytes, want <= %d", len(stack), maxLayerPanicStackBytes)
	}
	if err == nil {
		return
	}
	for _, leak := range []string{"goroutine ", ".go:", frame} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error text carries stack content %q: %s", leak, err)
		}
	}
}

// TestLayerDecoderPanicIsMalformed pins that a panic raised while constructing or
// running a layer decoder comes back from Unpack as ErrLayerMalformed, with the
// staging tree removed, and never unwinds the caller.
func TestLayerDecoderPanicIsMalformed(t *testing.T) {
	fx := newLayerFixture(t)

	// The real decoders, with the panic rising from beneath them. The zstd
	// cases are also the tripwire for WithDecoderConcurrency(1).
	type source func() io.Reader
	prefixed := func(b []byte) source {
		return func() io.Reader { return &panickingSource{prefix: bytes.Clone(b), value: "decoder state is gone"} }
	}
	for _, tc := range []struct {
		name      string
		mediaType string
		blob      []byte
		src       source
	}{
		{"zstd_construction", mediaTypeOCILayerZstd, fx.zs, func() io.Reader {
			return &panickingByter{panickingSource{value: "decoder state is gone"}}
		}},
		{"zstd_first_read", mediaTypeOCILayerZstd, fx.zs, prefixed(nil)},
		{"zstd_mid_stream", mediaTypeOCILayerZstd, fx.zs, prefixed(fx.zs[:len(fx.zs)/2])},
		{"gzip_construction", mediaTypeOCILayerGzip, fx.gz, prefixed(nil)},
		{"gzip_after_header", mediaTypeOCILayerGzip, fx.gz, prefixed(fx.gz[:10])},
		{"gzip_mid_stream", mediaTypeOCILayerGzip, fx.gz, prefixed(fx.gz[:len(fx.gz)/2])},
		{"docker_gzip_mid_stream", mediaTypeDockerLayerGzip, fx.gz, prefixed(fx.gz[:len(fx.gz)/2])},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log panicLog
			c, u := newTestUnpacker(t, WithUnpackLogger(log.logger()))
			u.decompress = func(mediaType string, _ io.Reader) (io.ReadCloser, error) {
				return decompressLayer(mediaType, tc.src())
			}
			mfst := commitLayerImage(t, c, fx.plain, tc.blob, tc.mediaType)
			_, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy())
			assertRefused(t, c, u, mfst, LinuxUnpackPolicy(), err)
			assertLoggedStack(t, &log, err, "panicking")
		})
	}

	// A panic while releasing the decoder, on a layer that otherwise applied and
	// verified, must not let the tree commit. A panic in Close on the way out of
	// a panic in Read must not escape either.
	for _, tc := range []struct {
		name      string
		readPanic bool
	}{
		{"close_after_a_clean_read", false},
		{"close_during_a_read_panic", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, u := newTestUnpacker(t)
			u.decompress = func(string, io.Reader) (io.ReadCloser, error) {
				r := bytes.NewReader(fx.plain)
				return &fakeDecoder{
					read: func(p []byte) (int, error) {
						if tc.readPanic {
							panic("read on a broken decoder")
						}
						return r.Read(p)
					},
					close: func() error { panic("close on a broken decoder") },
				}, nil
			}
			mfst := commitLayerImage(t, c, fx.plain, fx.zs, mediaTypeOCILayerZstd)
			_, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy())
			assertRefused(t, c, u, mfst, LinuxUnpackPolicy(), err)
		})
	}

	// The panic value is foreign text on its way to a Pod status: it is bounded
	// and escaped whatever it is, and rendering it cannot raise a second panic.
	for _, tc := range []struct {
		name  string
		raise func(p []byte)
		want  string
	}{
		{"oversized_hostile_string", func([]byte) {
			panic(strings.Repeat("\x1b[31m\nforged log line ", 1<<16))
		}, `\x1b[31m\nforged log line`},
		{"error_value", func([]byte) { panic(errors.New("huffman table is empty")) }, "huffman table is empty"},
		{"runtime_error", func(p []byte) { _ = p[len(p)+1] }, "index out of range"},
		{"stringer_that_panics", func([]byte) { panic(panicStringer{}) }, "PANIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log panicLog
			c, u := newTestUnpacker(t, WithUnpackLogger(log.logger()))
			u.decompress = func(string, io.Reader) (io.ReadCloser, error) {
				return &fakeDecoder{read: func(p []byte) (int, error) {
					tc.raise(p)
					return len(p), nil
				}}, nil
			}
			mfst := commitLayerImage(t, c, fx.plain, fx.zs, mediaTypeOCILayerZstd)
			_, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy())
			assertRefused(t, c, u, mfst, LinuxUnpackPolicy(), err)
			if err == nil {
				return
			}
			msg := err.Error()
			if limit := 4*maxWrappedErrLen + 512; len(msg) > limit {
				t.Errorf("error message is %d bytes, want <= %d", len(msg), limit)
			}
			if strings.ContainsAny(msg, "\x1b\n") {
				t.Errorf("error message carries raw control bytes: %q", msg)
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error message %q does not name %q", msg, tc.want)
			}
			if logged := log.buf.Len(); logged > 2*maxLayerPanicStackBytes+8*maxWrappedErrLen {
				t.Errorf("the log record is %d bytes", logged)
			}
		})
	}

	t.Run("a_deep_stack_is_bounded_in_the_log", func(t *testing.T) {
		var log panicLog
		c, u := newTestUnpacker(t, WithUnpackLogger(log.logger()))
		u.decompress = func(string, io.Reader) (io.ReadCloser, error) {
			return &fakeDecoder{read: func([]byte) (int, error) {
				deepPanic(100000)
				return 0, nil
			}}, nil
		}
		mfst := commitLayerImage(t, c, fx.plain, fx.zs, mediaTypeOCILayerZstd)
		_, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy())
		assertRefused(t, c, u, mfst, LinuxUnpackPolicy(), err)
		assertLoggedStack(t, &log, err, "deepPanic")
	})

	t.Run("clean_streams_pass_through_and_log_nothing", func(t *testing.T) {
		for _, tc := range []struct {
			mediaType string
			blob      []byte
		}{
			{mediaTypeOCILayerZstd, fx.zs},
			{mediaTypeOCILayerGzip, fx.gz},
		} {
			var log panicLog
			c, u := newTestUnpacker(t, WithUnpackLogger(log.logger()))
			mfst := commitLayerImage(t, c, fx.plain, tc.blob, tc.mediaType)
			if _, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy()); err != nil {
				t.Errorf("unpack %q: %v", tc.mediaType, err)
			}
			if log.buf.Len() != 0 {
				t.Errorf("a clean %q unpack logged: %s", tc.mediaType, log.buf.String())
			}
		}
	})
}

// TestLayerApplierPanicIsMalformed pins that a panic from archive/tar or the
// applier, on the same untrusted bytes, gets the decoder's verdict: the
// malformed-layer error, the partial tree removed, nothing committed, and an
// unpacker that can still build the same key afterwards.
func TestLayerApplierPanicIsMalformed(t *testing.T) {
	fx := newLayerFixture(t)
	policies := []struct {
		name   string
		policy UnpackPolicy
	}{
		{"native", NativeUnpackPolicy()},
		{"linux", LinuxUnpackPolicy()},
	}
	for _, p := range policies {
		for _, tc := range []struct {
			name  string
			frame string
			apply func(t *testing.T, c *Cache) func(*LayerApplier, context.Context, io.Reader) error
		}{
			{
				// The whole layer is on disk in staging when the applier panics, so
				// removing the tree is something the test can see happen.
				name:  "applier_over_a_partial_tree",
				frame: "TestLayerApplierPanicIsMalformed",
				apply: func(t *testing.T, c *Cache) func(*LayerApplier, context.Context, io.Reader) error {
					return func(a *LayerApplier, ctx context.Context, r io.Reader) error {
						if err := a.Apply(ctx, r); err != nil {
							t.Errorf("apply: %v", err)
						}
						if _, err := a.root.Stat("app"); err != nil {
							t.Errorf("the partial tree holds no app: %v", err)
						}
						if len(stagingDirs(t, c)) != 1 {
							t.Errorf("staging trees during the apply = %v, want one", stagingDirs(t, c))
						}
						panic("applier state is gone")
					}
				},
			},
			{
				name:  "archive_tar_between_entries",
				frame: "archive/tar",
				apply: func(*testing.T, *Cache) func(*LayerApplier, context.Context, io.Reader) error {
					return func(a *LayerApplier, ctx context.Context, r io.Reader) error {
						return a.Apply(ctx, &panicAfterReader{r: r, value: "tar read"})
					}
				},
			},
			{
				name:  "applier_inside_an_entry",
				frame: "applyRegular",
				apply: func(*testing.T, *Cache) func(*LayerApplier, context.Context, io.Reader) error {
					return func(a *LayerApplier, ctx context.Context, r io.Reader) error {
						return a.Apply(ctx, &panicAfterReader{r: r, n: 512 + 64, value: "entry read"})
					}
				},
			},
		} {
			t.Run(p.name+"/"+tc.name, func(t *testing.T) {
				var log panicLog
				c, u := newTestUnpacker(t, WithUnpackLogger(log.logger()))
				u.applyTar = tc.apply(t, c)
				mfst := commitLayerImage(t, c, fx.plain, fx.zs, mediaTypeOCILayerZstd)
				_, err := unpackSeeingPanics(t, u, mfst, p.policy)
				assertRefused(t, c, u, mfst, p.policy, err)
				assertLoggedStack(t, &log, err, tc.frame)

				u.applyTar = (*LayerApplier).Apply
				tree, err := unpackSeeingPanics(t, u, mfst, p.policy)
				if err != nil {
					t.Fatalf("unpack after the panic: %v", err)
				}
				if _, err := os.Stat(tree.Rootfs + "/app"); err != nil {
					t.Errorf("the tree built after the panic holds no app: %v", err)
				}
			})
		}
	}

	// A panic rising through applyRegular's copy must not strand the file it was
	// writing. Counted over several rounds, with one before the baseline so the
	// runtime's own first-use descriptors are not read as a leak.
	t.Run("the_open_entry_file_is_closed", func(t *testing.T) {
		openFDs := func() int {
			entries, err := os.ReadDir("/dev/fd")
			if err != nil {
				t.Skipf("cannot count descriptors: %v", err)
			}
			return len(entries)
		}
		c, u := newTestUnpacker(t)
		u.applyTar = func(a *LayerApplier, ctx context.Context, r io.Reader) error {
			return a.Apply(ctx, &panicAfterReader{r: r, n: 512 + 64, value: "entry read"})
		}
		mfst := commitLayerImage(t, c, fx.plain, fx.zs, mediaTypeOCILayerZstd)
		if _, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy()); !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("unpack error = %v, want ErrLayerMalformed", err)
		}
		before := openFDs()
		for range 8 {
			if _, err := unpackSeeingPanics(t, u, mfst, LinuxUnpackPolicy()); !errors.Is(err, ErrLayerMalformed) {
				t.Fatalf("unpack error = %v, want ErrLayerMalformed", err)
			}
		}
		if after := openFDs(); after > before {
			t.Errorf("open descriptors went from %d to %d over 8 panics", before, after)
		}
	})
}
