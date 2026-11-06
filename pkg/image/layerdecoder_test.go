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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// panickingSource serves prefix on its first Read and panics with value on
// every later one. It sits under a real decompressor, so a panic it raises
// unwinds through the decoder exactly as one raised by the decoder itself does,
// and it can only reach the guard if the decode runs on the caller's goroutine:
// on any other goroutine it would kill the test binary.
type panickingSource struct {
	prefix []byte
	value  any
	reads  int
}

func (s *panickingSource) Read(p []byte) (int, error) {
	s.reads++
	if len(s.prefix) > 0 {
		n := copy(p, s.prefix)
		s.prefix = s.prefix[n:]
		return n, nil
	}
	panic(s.value)
}

// fakeDecoder is a decoder whose Read and Close are supplied by the case.
type fakeDecoder struct {
	read   func(p []byte) (int, error)
	close  func() error
	closes int
}

func (d *fakeDecoder) Read(p []byte) (int, error) { return d.read(p) }

func (d *fakeDecoder) Close() error {
	d.closes++
	if d.close == nil {
		return nil
	}
	return d.close()
}

// panicStringer panics when rendered, so the guard's own rendering of a panic
// value is exercised against a value that fights back.
type panicStringer struct{}

func (panicStringer) String() string { panic("rendering the panic value") }

// callerSees runs fn and reports a panic that reached its caller, which is the
// failure this test exists to catch.
func callerSees(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("%s: a panic reached the caller: %s", what, quoteBounded(fmt.Sprint(v), 80))
		}
	}()
	fn()
}

// TestLayerDecoderPanicIsMalformed pins that a panic raised while decompressing
// a layer comes back as ErrLayerMalformed, stays failed, and never unwinds the
// caller.
func TestLayerDecoderPanicIsMalformed(t *testing.T) {
	payload := buildTar(t, []tarSpec{{name: "app", mode: 0o755, data: strings.Repeat("layer content ", 4096)}})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	zs := zstdCompress(t, payload)

	// The real decoders: the panic rises through decompressLayer's own return
	// value. The zstd cases are also the tripwire for WithDecoderConcurrency(1).
	realDecoders := []struct {
		name      string
		mediaType string
		prefix    []byte
	}{
		{"zstd_first_read", mediaTypeOCILayerZstd, nil},
		{"zstd_mid_stream", mediaTypeOCILayerZstd, zs[:len(zs)/2]},
		// gzip reads its 10-byte header at construction, so its source has to
		// survive that far before it panics.
		{"gzip_after_header", mediaTypeOCILayerGzip, gz.Bytes()[:10]},
		{"gzip_mid_stream", mediaTypeOCILayerGzip, gz.Bytes()[:len(gz.Bytes())/2]},
		{"docker_gzip_mid_stream", mediaTypeDockerLayerGzip, gz.Bytes()[:len(gz.Bytes())/2]},
	}
	for _, tc := range realDecoders {
		t.Run(tc.name, func(t *testing.T) {
			src := &panickingSource{prefix: bytes.Clone(tc.prefix), value: "decoder state is gone"}
			rc, err := decompressLayer(tc.mediaType, src)
			if err != nil {
				t.Fatalf("decompressLayer: %v", err)
			}
			var readErr error
			callerSees(t, "read", func() { _, readErr = io.ReadAll(rc) })
			if !errors.Is(readErr, ErrLayerMalformed) {
				t.Errorf("read error = %v, want ErrLayerMalformed", readErr)
			}

			reads := src.reads
			var n int
			callerSees(t, "read after the panic", func() { n, readErr = rc.Read(make([]byte, 16)) })
			if n != 0 || !errors.Is(readErr, ErrLayerMalformed) {
				t.Errorf("read after the panic = (%d, %v), want (0, ErrLayerMalformed)", n, readErr)
			}
			if src.reads != reads {
				t.Errorf("read after the panic re-entered the decoder: source reads went from %d to %d", reads, src.reads)
			}

			callerSees(t, "close", func() { _ = rc.Close() })
			callerSees(t, "second close", func() { _ = rc.Close() })
		})
	}

	// The panic value is foreign text on its way to a Pod status: it is bounded
	// and escaped whatever it is, and rendering it cannot raise a second panic.
	values := []struct {
		name  string
		value func(p []byte)
		want  string
	}{
		{"oversized_hostile_string", func([]byte) {
			panic(strings.Repeat("\x1b[31m\nforged log line ", 1<<16))
		}, `\x1b[31m\nforged log line`},
		{"error_value", func([]byte) { panic(errors.New("huffman table is empty")) }, "huffman table is empty"},
		{"runtime_error", func(p []byte) { _ = p[len(p)+1] }, "index out of range"},
		{"stringer_that_panics", func([]byte) { panic(panicStringer{}) }, "PANIC"},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			rc := guardLayerDecoder(&fakeDecoder{read: func(p []byte) (int, error) {
				tc.value(p)
				return len(p), nil
			}})
			var (
				n   int
				err error
			)
			callerSees(t, "read", func() { n, err = rc.Read(make([]byte, 16)) })
			if n != 0 || !errors.Is(err, ErrLayerMalformed) {
				t.Fatalf("read = (%d, %v), want (0, ErrLayerMalformed)", n, err)
			}
			msg := err.Error()
			if limit := 4*maxWrappedErrLen + 128; len(msg) > limit {
				t.Errorf("error message is %d bytes, want <= %d", len(msg), limit)
			}
			if strings.ContainsAny(msg, "\x1b\n") {
				t.Errorf("error message carries raw control bytes: %q", msg)
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error message %q does not name %q", msg, tc.want)
			}
		})
	}

	t.Run("close_releases_the_decoder_once_after_a_read_panic", func(t *testing.T) {
		dec := &fakeDecoder{read: func([]byte) (int, error) { panic("boom") }}
		rc := guardLayerDecoder(dec)
		callerSees(t, "read", func() { _, _ = rc.Read(make([]byte, 1)) })
		var first, second error
		callerSees(t, "close", func() { first = rc.Close() })
		callerSees(t, "second close", func() { second = rc.Close() })
		if !errors.Is(first, ErrLayerMalformed) || !errors.Is(second, ErrLayerMalformed) {
			t.Errorf("close errors = %v, %v, want ErrLayerMalformed from both", first, second)
		}
		if dec.closes != 1 {
			t.Errorf("decoder closed %d times, want 1", dec.closes)
		}
	})

	t.Run("panic_in_close", func(t *testing.T) {
		dec := &fakeDecoder{
			read:  func([]byte) (int, error) { return 0, io.EOF },
			close: func() error { panic("close on a broken decoder") },
		}
		rc := guardLayerDecoder(dec)
		var err error
		callerSees(t, "close", func() { err = rc.Close() })
		if !errors.Is(err, ErrLayerMalformed) {
			t.Errorf("close error = %v, want ErrLayerMalformed", err)
		}
		callerSees(t, "read after a close panic", func() { _, err = rc.Read(make([]byte, 1)) })
		if !errors.Is(err, ErrLayerMalformed) {
			t.Errorf("read after a close panic error = %v, want ErrLayerMalformed", err)
		}
		callerSees(t, "second close", func() { err = rc.Close() })
		if !errors.Is(err, ErrLayerMalformed) || dec.closes != 1 {
			t.Errorf("second close = %v after %d decoder closes, want ErrLayerMalformed after 1", err, dec.closes)
		}
	})

	// The applier reads the decoder at two places with two wrappings, between
	// entries and inside one, and the verdict has to survive both.
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"apply_between_entries", nil},
		{"apply_inside_an_entry", payload[:512+64]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &panickingSource{prefix: bytes.Clone(tc.prefix), value: "boom"}
			rc := guardLayerDecoder(&fakeDecoder{read: src.Read})
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			a, err := NewLayerApplier(root, LinuxUnpackPolicy(), ApplyLimits{})
			if err != nil {
				t.Fatal(err)
			}
			var applyErr error
			callerSees(t, "apply", func() { applyErr = a.Apply(context.Background(), rc) })
			if !errors.Is(applyErr, ErrLayerMalformed) {
				t.Errorf("apply error = %v, want ErrLayerMalformed", applyErr)
			}
		})
	}

	// A healthy stream is untouched. The guard must also hide the decoder's
	// WriteTo: io.Copy prefers it, and a decode entered through it would run
	// outside the guard.
	t.Run("clean_streams_pass_through", func(t *testing.T) {
		for _, tc := range []struct {
			mediaType  string
			compressed []byte
		}{
			{mediaTypeOCILayerZstd, zs},
			{mediaTypeOCILayerGzip, gz.Bytes()},
		} {
			rc, err := decompressLayer(tc.mediaType, bytes.NewReader(tc.compressed))
			if err != nil {
				t.Fatalf("decompressLayer(%q): %v", tc.mediaType, err)
			}
			if _, ok := rc.(io.WriterTo); ok {
				t.Errorf("the reader for %q exposes io.WriterTo", tc.mediaType)
			}
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Errorf("read %q: %v", tc.mediaType, err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("%q did not round-trip the layer", tc.mediaType)
			}
			if err := rc.Close(); err != nil {
				t.Errorf("close %q: %v", tc.mediaType, err)
			}
		}
	})
}
