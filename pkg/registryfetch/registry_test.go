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

package registryfetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry serves one blob. cutAt > 0 makes the first un-Ranged GET
// declare the full length, send cutAt bytes and drop the connection.
type fakeRegistry struct {
	data  []byte
	cutAt int
	// rangeStatus overrides the answer to a Range request (0: 206).
	rangeStatus int
	// contentRange overrides the 206 Content-Range header.
	contentRange string
	// plainStatus overrides the answer to an un-Ranged GET (0: 200), with
	// plainContentRange as its Content-Range when it is a 206.
	plainStatus       int
	plainContentRange string
	// extra is sent after the blob, to model a body longer than its size.
	extra []byte

	mu        sync.Mutex
	ranges    []string
	encodings []string
	cut       bool
}

func (r *fakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.Contains(req.URL.Path, "/blobs/") {
		http.NotFound(w, req)
		return
	}
	rg := req.Header.Get("Range")
	r.mu.Lock()
	r.ranges = append(r.ranges, rg)
	r.encodings = append(r.encodings, req.Header.Get("Accept-Encoding"))
	cut := r.cutAt > 0 && !r.cut && rg == ""
	if cut {
		r.cut = true
	}
	r.mu.Unlock()
	if rg == "" && r.plainStatus != 0 {
		if r.plainContentRange != "" {
			w.Header().Set("Content-Range", r.plainContentRange)
		}
		w.WriteHeader(r.plainStatus)
		_, _ = w.Write(r.data)
		return
	}
	if rg == "" {
		if r.extra != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(bytes.Clone(r.data), r.extra...))
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(r.data)))
		w.WriteHeader(http.StatusOK)
		if cut {
			_, _ = w.Write(r.data[:r.cutAt])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // drop the connection mid-body
		}
		_, _ = w.Write(r.data)
		return
	}
	from, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
	if err != nil || from > len(r.data) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	switch r.rangeStatus {
	case 0, http.StatusPartialContent:
	case http.StatusOK:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(r.data)
		return
	default:
		w.WriteHeader(r.rangeStatus)
		return
	}
	cr := r.contentRange
	if cr == "" {
		cr = fmt.Sprintf("bytes %d-%d/%d", from, len(r.data)-1, len(r.data))
	}
	w.Header().Set("Content-Range", cr)
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(append(bytes.Clone(r.data[from:]), r.extra...))
}

func (r *fakeRegistry) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ranges...)
}

func (r *fakeRegistry) acceptEncodings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.encodings...)
}

func serve(t *testing.T, fr *fakeRegistry) (*Registry, string) {
	t.Helper()
	srv := httptest.NewServer(fr)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	return &Registry{Transport: http.DefaultTransport, PlainHTTP: true}, host + "/models/tiny:v1"
}

func blobData(n int) ([]byte, string) {
	data := bytes.Repeat([]byte("0123456789abcdef"), n/16+1)[:n]
	sum := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(sum[:])
}

// verifyCommit re-hashes the replayed partial against digest and size.
func verifyCommit(digest string, size int64, got *[]byte) func(func(io.Writer) error) error {
	return func(replay func(io.Writer) error) error {
		var buf bytes.Buffer
		if err := replay(&buf); err != nil {
			return err
		}
		sum := sha256.Sum256(buf.Bytes())
		if d := "sha256:" + hex.EncodeToString(sum[:]); d != digest || int64(buf.Len()) != size {
			return fmt.Errorf("got %s (%d bytes), want %s (%d bytes)", d, buf.Len(), digest, size)
		}
		*got = buf.Bytes()
		return nil
	}
}

// TestBlobResumesFromPartialWithRange: the first GET is cut at N bytes and
// leaves them in the partial; the second request carries Range from N, and the
// joined partial re-hashes to the digest.
func TestBlobResumesFromPartialWithRange(t *testing.T) {
	const size, cutAt = 64 << 10, 20000
	data, digest := blobData(size)
	fr := &fakeRegistry{data: data, cutAt: cutAt}
	reg, ref := serve(t, fr)
	store := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	var got []byte
	fill := Fill{
		Digest: digest, Size: size,
		Transfer: func(f *os.File, have int64) error {
			body, start, err := reg.Blob(context.Background(), ref, nil, digest, size, have)
			if err != nil {
				return err
			}
			defer body.Close()
			if start != have {
				return fmt.Errorf("start %d, asked %d", start, have)
			}
			if _, err := f.Seek(have, io.SeekStart); err != nil {
				return err
			}
			_, err = io.Copy(f, body)
			return err
		},
		Commit:   verifyCommit(digest, size, &got),
		Poisoned: func(error) bool { return true },
	}
	if err := store.Resume(fill); err == nil {
		t.Fatal("first Resume succeeded over a cut connection")
	}
	if have := store.Bytes(digest, size); have != cutAt {
		t.Fatalf("partial holds %d bytes after the cut, want %d", have, cutAt)
	}
	if err := store.Resume(fill); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("committed bytes differ from the blob")
	}
	if want := []string{"", "bytes=" + strconv.Itoa(cutAt) + "-"}; fmt.Sprint(fr.seen()) != fmt.Sprint(want) {
		t.Fatalf("Range headers = %q, want %q", fr.seen(), want)
	}
	if _, err := os.Lstat(store.path(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed partial still present: %v", err)
	}
}

func TestBlobRangeAnsweredWith200RestartsAtZero(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref := serve(t, &fakeRegistry{data: data, rangeStatus: http.StatusOK})
	body, start, err := reg.Blob(context.Background(), ref, nil, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if start != 0 {
		t.Fatalf("start = %d, want 0", start)
	}
	if b, _ := io.ReadAll(body); !bytes.Equal(b, data) {
		t.Fatal("body is not the whole blob")
	}
}

func TestBlob416RetriesWithoutRange(t *testing.T) {
	data, digest := blobData(1000)
	fr := &fakeRegistry{data: data, rangeStatus: http.StatusRequestedRangeNotSatisfiable}
	reg, ref := serve(t, fr)
	body, start, err := reg.Blob(context.Background(), ref, nil, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if start != 0 {
		t.Fatalf("start = %d, want 0", start)
	}
	if want := []string{"bytes=300-", ""}; fmt.Sprint(fr.seen()) != fmt.Sprint(want) {
		t.Fatalf("Range headers = %q, want %q", fr.seen(), want)
	}
}

func TestBlobContentRangeMustStartAtOffset(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref := serve(t, &fakeRegistry{data: data, contentRange: "bytes 0-999/1000"})
	if _, _, err := reg.Blob(context.Background(), ref, nil, digest, 1000, 300); err == nil ||
		!errors.Is(err, ErrBlobRange) {
		t.Fatalf("err = %v, want a Content-Range refusal", err)
	}
}

func TestBlobErrorStatusIsReported(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref := serve(t, &fakeRegistry{data: data, rangeStatus: http.StatusForbidden})
	if _, _, err := reg.Blob(context.Background(), ref, nil, digest, 1000, 300); err == nil {
		t.Fatal("a 403 was accepted")
	}
}

func TestBlobRefusesBadReferenceAndMissingTransport(t *testing.T) {
	reg := &Registry{Transport: http.DefaultTransport, PlainHTTP: true}
	_, _, err := reg.Blob(context.Background(), "NOT A REF", nil, "sha256:00", 1, 0)
	var re *ReferenceError
	if !errors.Is(err, ErrInvalidReference) || !errors.As(err, &re) {
		t.Fatalf("err = %v, want ErrInvalidReference", err)
	}
	if _, _, err := (&Registry{}).Blob(context.Background(), "h/r:t", nil, "sha256:00", 1, 0); !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("err = %v, want ErrTransportRequired", err)
	}
}

// TestBlobContentRangeIsStrict: a 206 to "bytes=5-" for a 10-byte blob is
// accepted only with exactly "bytes 5-9/10".
func TestBlobContentRangeIsStrict(t *testing.T) {
	data, digest := blobData(10)
	for _, tc := range []struct {
		cr string
		ok bool
	}{
		{"bytes 5-9/10", true},
		{"bytes 5-", false},
		{"bytes 5-9/*", false},
		{"bytes +5-9/10", false},
		{"bytes 5-8/10", false},
		{"bytes 5-9/11", false},
		{"bytes 05-9/10", false},
		{"bytes 5-09/10", false},
		{"bytes 5-9/010", false},
		{"bytes  5-9/10", false},
		{"Bytes 5-9/10", false},
		{"bytes 4-9/10", false},
		{"bytes 5-9/10/10", false},
		{"bytes 5-9-9/10", false},
		{"bytes 5-99999999999999999999/10", false},
	} {
		t.Run(tc.cr, func(t *testing.T) {
			reg, ref := serve(t, &fakeRegistry{data: data, contentRange: tc.cr})
			body, start, err := reg.Blob(context.Background(), ref, nil, digest, 10, 5)
			if !tc.ok {
				if err == nil {
					body.Close()
					t.Fatalf("Content-Range %q accepted", tc.cr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Content-Range %q refused: %v", tc.cr, err)
			}
			defer body.Close()
			if b, err := io.ReadAll(body); start != 5 || err != nil || !bytes.Equal(b, data[5:]) {
				t.Fatalf("start %d body %q err %v, want 5 %q", start, b, err, data[5:])
			}
		})
	}
}

// TestBlob416Retry: after a 416 the one retry without a Range must be a 200,
// or a 206 that is the whole object from 0.
func TestBlob416Retry(t *testing.T) {
	data, digest := blobData(10)
	for _, tc := range []struct {
		name   string
		status int
		cr     string
		ok     bool
	}{
		{"416 again", http.StatusRequestedRangeNotSatisfiable, "", false},
		{"206 whole object", http.StatusPartialContent, "bytes 0-9/10", true},
		{"206 a prefix", http.StatusPartialContent, "bytes 0-4/10", false},
		{"206 the asked range", http.StatusPartialContent, "bytes 5-9/10", false},
		{"206 no Content-Range", http.StatusPartialContent, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRegistry{data: data, rangeStatus: http.StatusRequestedRangeNotSatisfiable,
				plainStatus: tc.status, plainContentRange: tc.cr}
			reg, ref := serve(t, fr)
			body, start, err := reg.Blob(context.Background(), ref, nil, digest, 10, 5)
			if want := []string{"bytes=5-", ""}; fmt.Sprint(fr.seen()) != fmt.Sprint(want) {
				t.Fatalf("Range headers = %q, want %q", fr.seen(), want)
			}
			if !tc.ok {
				if err == nil {
					body.Close()
					t.Fatal("retry answer accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer body.Close()
			if b, err := io.ReadAll(body); start != 0 || err != nil || !bytes.Equal(b, data) {
				t.Fatalf("start %d body %q err %v, want the whole blob from 0", start, b, err)
			}
		})
	}
}

func TestParseContentRange(t *testing.T) {
	for _, tc := range []struct {
		in                 string
		first, last, total int64
		ok                 bool
	}{
		{"bytes 300-999/1000", 300, 999, 1000, true},
		{"bytes 0-0/1", 0, 0, 1, true},
		{"bytes 0-9223372036854775806/9223372036854775807", 0, 9223372036854775806, 9223372036854775807, true},
		{"bytes 0-1/9223372036854775808", 0, 0, 0, false},
		{"bytes -1-2/3", 0, 0, 0, false},
		{"bytes x-2/3", 0, 0, 0, false},
		{"bytes 1-2/-3", 0, 0, 0, false},
		{"bytes 1-2/", 0, 0, 0, false},
		{"bytes -2/3", 0, 0, 0, false},
		{"bytes 300", 0, 0, 0, false},
		{"bytes 00-1/2", 0, 0, 0, false},
		{"bytes 1-2/3 ", 0, 0, 0, false},
		{"bytes 1-2/*", 0, 0, 0, false},
		{"bytes 1-2/3\x00", 0, 0, 0, false},
		{"bytes \u0661-2/3", 0, 0, 0, false},
		{"items 300-999/1000", 0, 0, 0, false},
		{"bytes 5-4/10", 0, 0, 0, false},
		{"bytes 0-10/10", 0, 0, 0, false},
		{"bytes 0-0/0", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	} {
		first, last, total, ok := parseContentRange(tc.in)
		if ok != tc.ok || ok && (first != tc.first || last != tc.last || total != tc.total) {
			t.Errorf("parseContentRange(%q) = %d,%d,%d,%v; want %d,%d,%d,%v",
				tc.in, first, last, total, ok, tc.first, tc.last, tc.total, tc.ok)
		}
	}
}

// TestBlobBodyStopsAtSize: a body longer than size-start is an error from
// Read once the size is reached, never more bytes and never a silent cut.
func TestBlobBodyStopsAtSize(t *testing.T) {
	data, digest := blobData(1000)
	for _, tc := range []struct {
		name   string
		offset int64
	}{
		{"200", 0},
		{"206", 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg, ref := serve(t, &fakeRegistry{data: data, extra: []byte("x")})
			body, start, err := reg.Blob(context.Background(), ref, nil, digest, 1000, tc.offset)
			if err != nil {
				t.Fatal(err)
			}
			defer body.Close()
			b, err := io.ReadAll(body)
			if !errors.Is(err, ErrBlobOverrun) {
				t.Fatalf("read err = %v, want ErrBlobOverrun", err)
			}
			if start != tc.offset || !bytes.Equal(b, data[start:]) {
				t.Fatalf("start %d, %d bytes read; want %d and the rest of the blob", start, len(b), tc.offset)
			}
		})
	}
}

// TestBlobExactBodyReadsToEOF: the ceiling does not turn a body of exactly
// size-start bytes into an error.
func TestBlobExactBodyReadsToEOF(t *testing.T) {
	data, digest := blobData(1000)
	for _, offset := range []int64{0, 300} {
		reg, ref := serve(t, &fakeRegistry{data: data})
		body, start, err := reg.Blob(context.Background(), ref, nil, digest, 1000, offset)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(body)
		body.Close()
		if err != nil || !bytes.Equal(b, data[start:]) {
			t.Fatalf("offset %d: %d bytes, err %v", offset, len(b), err)
		}
	}
}

func TestBlobAsksForIdentityEncoding(t *testing.T) {
	data, digest := blobData(1000)
	fr := &fakeRegistry{data: data, rangeStatus: http.StatusRequestedRangeNotSatisfiable}
	reg, ref := serve(t, fr)
	body, _, err := reg.Blob(context.Background(), ref, nil, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	if got := fr.acceptEncodings(); fmt.Sprint(got) != fmt.Sprint([]string{"identity", "identity"}) {
		t.Fatalf("Accept-Encoding = %q, want identity on both requests", got)
	}
}

func TestBlobRefusesOffsetOutsideSize(t *testing.T) {
	reg := &Registry{Transport: http.DefaultTransport, PlainHTTP: true}
	for _, tc := range [][2]int64{{-1, 0}, {10, -1}, {10, 11}} {
		if _, _, err := reg.Blob(context.Background(), "h/r:t", nil, "sha256:00", tc[0], tc[1]); !errors.Is(err, ErrBlobRange) {
			t.Errorf("size %d offset %d: err = %v, want ErrBlobRange", tc[0], tc[1], err)
		}
	}
}

func TestForeignErrorTextIsBounded(t *testing.T) {
	long := strings.Repeat("\x00", 2*maxForeignErrBytes)
	cause := errors.New(long)
	err := bound(cause)
	if !errors.Is(err, cause) {
		t.Fatal("bound hides the cause from errors.Is")
	}
	if len(err.Error()) > 8*maxForeignErrBytes || !strings.HasSuffix(err.Error(), "...") {
		t.Fatalf("bounded text is %d bytes, not cut", len(err.Error()))
	}
}

func TestCredentialRedacts(t *testing.T) {
	c := Credential{
		Username: "alice", Password: "pw-SECRET-1", Auth: "auth-SECRET-2",
		IdentityToken: "idt-SECRET-3", RegistryToken: "rt-SECRET-4",
	}
	secrets := []string{c.Password, c.Auth, c.IdentityToken, c.RegistryToken}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("login", "cred", c, "ptr", &c)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("login", "cred", c, "ptr", &c)
	outs := map[string]string{
		"%v":      fmt.Sprintf("%v", c),
		"%+v":     fmt.Sprintf("%+v", c),
		"%#v":     fmt.Sprintf("%#v", c),
		"%s":      fmt.Sprintf("%s", c),
		"ptr %v":  fmt.Sprintf("%v", &c),
		"ptr %+v": fmt.Sprintf("%+v", &c),
		"ptr %#v": fmt.Sprintf("%#v", &c),
		"text":    text.String(),
		"json":    js.String(),
	}
	for name, out := range outs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s output leaks %q: %s", name, s, out)
			}
		}
		if !strings.Contains(out, "alice") {
			t.Errorf("%s output lost the username: %s", name, out)
		}
	}
}
