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

	mu     sync.Mutex
	ranges []string
	cut    bool
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
	cut := r.cutAt > 0 && !r.cut && rg == ""
	if cut {
		r.cut = true
	}
	r.mu.Unlock()
	if rg == "" {
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
	_, _ = w.Write(r.data[from:])
}

func (r *fakeRegistry) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ranges...)
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
			body, start, err := reg.Blob(context.Background(), ref, nil, digest, have)
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
	body, start, err := reg.Blob(context.Background(), ref, nil, digest, 300)
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
	body, start, err := reg.Blob(context.Background(), ref, nil, digest, 300)
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
	if _, _, err := reg.Blob(context.Background(), ref, nil, digest, 300); err == nil ||
		!strings.Contains(err.Error(), "does not start at 300") {
		t.Fatalf("err = %v, want a Content-Range refusal", err)
	}
}

func TestBlobErrorStatusIsReported(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref := serve(t, &fakeRegistry{data: data, rangeStatus: http.StatusForbidden})
	if _, _, err := reg.Blob(context.Background(), ref, nil, digest, 300); err == nil {
		t.Fatal("a 403 was accepted")
	}
}

func TestBlobRefusesBadReferenceAndMissingTransport(t *testing.T) {
	reg := &Registry{Transport: http.DefaultTransport, PlainHTTP: true}
	_, _, err := reg.Blob(context.Background(), "NOT A REF", nil, "sha256:00", 0)
	var re *ReferenceError
	if !errors.Is(err, ErrInvalidReference) || !errors.As(err, &re) {
		t.Fatalf("err = %v, want ErrInvalidReference", err)
	}
	if _, _, err := (&Registry{}).Blob(context.Background(), "h/r:t", nil, "sha256:00", 0); !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("err = %v, want ErrTransportRequired", err)
	}
}

func TestContentRangeStart(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"bytes 300-999/1000", 300, true},
		{"bytes 0-0/1", 0, true},
		{"bytes -1-2/3", 0, false},
		{"bytes x-2/3", 0, false},
		{"bytes 300", 0, false},
		{"items 300-999/1000", 0, false},
		{"", 0, false},
	} {
		got, ok := contentRangeStart(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("contentRangeStart(%q) = %d,%v; want %d,%v", tc.in, got, ok, tc.want, tc.ok)
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
