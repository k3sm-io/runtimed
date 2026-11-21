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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// partialFixtureNow is the fixed clock the partial-store tests run on.
var partialFixtureNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// writePartial writes a size-byte partial for a digest of hex digit h into
// dir and sets its mtime.
func writePartial(t *testing.T, dir string, h byte, size int, mtime time.Time) string {
	t.Helper()
	p := filepath.Join(dir, "sha256-"+strings.Repeat(string(h), 64)+".partial")
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return p
}

// openedPartialCache is a cache on the fixed clock with its partial store open.
func openedPartialCache(t *testing.T) (*Cache, *registryfetch.PartialStore) {
	t.Helper()
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return partialFixtureNow }
	s := c.OpenPartialStore(nil)
	if s == nil {
		t.Fatal("partial store refused in a fresh temp root")
	}
	return c, s
}

// TestOpenPartialStore pins where the store lives and how it is built: one
// store per cache, at <root>/image-partial beside blobs/ (never under it),
// private, capped at PartialStoreMaxBytes, and swept at open on the cache's
// clock.
func TestOpenPartialStore(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return partialFixtureNow }
	dir := filepath.Join(c.Root(), PartialSubdir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := writePartial(t, dir, 'a', 3, partialFixtureNow.Add(-PartialMaxAge-time.Minute))
	fresh := writePartial(t, dir, 'b', 3, partialFixtureNow.Add(-time.Minute))

	s := c.OpenPartialStore(nil)
	if s == nil {
		t.Fatal("OpenPartialStore = nil for a private dir")
	}
	if s.Dir != dir || filepath.Dir(s.Dir) != c.Root() || strings.HasPrefix(s.Dir, c.BlobStoreDir()+string(filepath.Separator)) {
		t.Fatalf("store dir = %q, want %q (a child of the root, beside blobs/)", s.Dir, dir)
	}
	if s.MaxBytes != PartialStoreMaxBytes || PartialStoreMaxBytes != 5<<30 {
		t.Fatalf("MaxBytes = %d (cap const %d), want 5 GiB", s.MaxBytes, PartialStoreMaxBytes)
	}
	if again := c.OpenPartialStore(nil); again != s {
		t.Fatal("a second OpenPartialStore built a second store")
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale partial survived the open sweep: %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatalf("fresh partial removed by the open sweep: %v", err)
	}
}

// TestOpenPartialStoreRefusedDirDisablesStore: a store directory EnsureDir
// refuses is logged at Error and disables the store (nil), so the puller
// fetches every layer whole; the cache, StoreBytes and reclaim still work.
func TestOpenPartialStoreRefusedDirDisablesStore(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, path string)
	}{
		{"a regular file in its place", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a group-writable dir", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"a symlink in its place", func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tc.plant(t, filepath.Join(c.Root(), PartialSubdir))
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			if s := c.OpenPartialStore(log); s != nil {
				t.Fatalf("OpenPartialStore = %+v over a refused dir, want nil", s)
			}
			if !strings.Contains(buf.String(), "level=ERROR") || !strings.Contains(buf.String(), "image partial store disabled") {
				t.Fatalf("refusal not logged at Error: %q", buf.String())
			}
			if s := c.OpenPartialStore(log); s != nil {
				t.Fatal("a later OpenPartialStore enabled a refused store")
			}
			if _, err := c.StoreBytes(); err != nil {
				t.Fatalf("StoreBytes with the store disabled: %v", err)
			}
			if _, err := c.ReclaimUnderPressure(context.Background(), ReclaimConfig{FreeBytes: fixedFreeBytes(64 << 30)}); err != nil {
				t.Fatalf("reclaim with the store disabled: %v", err)
			}
		})
	}
}

// TestReclaimSweepsStalePartials: each reclaim pass, triggered or not, first
// sweeps the partial store on its clock: a partial older than PartialMaxAge
// goes, a fresh one stays. A dry run sweeps nothing.
func TestReclaimSweepsStalePartials(t *testing.T) {
	c, s := openedPartialCache(t)
	stale := writePartial(t, s.Dir, 'a', 3, partialFixtureNow.Add(-PartialMaxAge-time.Minute))
	fresh := writePartial(t, s.Dir, 'b', 3, partialFixtureNow.Add(-PartialMaxAge+time.Minute))
	cfg := ReclaimConfig{
		FreeBytes: fixedFreeBytes(64 << 30), // above the floor: the prune is not triggered
		Now:       func() time.Time { return partialFixtureNow },
	}

	dry := cfg
	dry.DryRun = true
	if _, err := c.ReclaimUnderPressure(context.Background(), dry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Fatalf("a dry-run pass removed a stale partial: %v", err)
	}

	rep, err := c.ReclaimUnderPressure(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Triggered {
		t.Fatal("fixture: the pass was meant to stay untriggered")
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale partial survived the reclaim pass: %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatalf("fresh partial removed by the reclaim pass: %v", err)
	}
}

// TestStoreBytesCountsPartials: the partial store's bytes are counted in
// StoreBytes and as ClassPartial in StoreBytesByClass, and a forced prune,
// whose rule knows nothing of partials, frees none of them.
func TestStoreBytesCountsPartials(t *testing.T) {
	c, s := openedPartialCache(t)
	base, err := c.StoreBytes()
	if err != nil {
		t.Fatal(err)
	}
	p := writePartial(t, s.Dir, 'a', 700, partialFixtureNow.Add(-time.Minute))
	writePartial(t, s.Dir, 'b', 300, partialFixtureNow.Add(-time.Minute))
	got, err := c.StoreBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got-base != 1000 {
		t.Fatalf("StoreBytes grew by %d with 1000 partial bytes", got-base)
	}
	classes, err := c.StoreBytesByClass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if classes[ClassPartial] != 1000 {
		t.Fatalf("ClassPartial = %d, want 1000 (classes %v)", classes[ClassPartial], classes)
	}
	var sum int64
	for _, n := range classes {
		sum += n
	}
	if sum != got {
		t.Fatalf("classes sum to %d, StoreBytes is %d", sum, got)
	}
	if IsArtifactClass(ClassPartial) {
		t.Fatal("ClassPartial reads as an artifact class")
	}
	if _, err := c.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		Force:     true,
		FreeBytes: fixedFreeBytes(64 << 30),
		Now:       func() time.Time { return partialFixtureNow },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("a forced prune removed a fresh partial: %v", err)
	}
}

// TestSweepSparesClaimedPartialOfRunningPull: a reclaim pass that runs while
// a pull is resuming a layer leaves that layer's partial alone, however old,
// because the pull holds the digest's Claim for the whole Resume; an
// unclaimed partial of the same age in the same pass is removed, and the
// resumed pull then completes from the bytes the sweep spared.
func TestSweepSparesClaimedPartialOfRunningPull(t *testing.T) {
	const cutAt = 4096
	c := newCutRegistry(t, cutAt)
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := cache.OpenPartialStore(nil)
	if store == nil {
		t.Fatal("partial store refused")
	}
	p := resumePuller(t, c, cache, store)

	c.arm(1, 0, false)
	if _, err := pullAlways(p, c.ref); err == nil {
		t.Fatal("first pull succeeded through a cut layer")
	}
	held := partialPath(store.Dir, c.layer)
	sweepAt := time.Now().Add(2 * PartialMaxAge) // both partials are stale at this instant
	other := writePartial(t, store.Dir, 'e', 10, time.Now())
	c.takeRanges()

	hold, allHeld := c.holdServes(1)
	done := make(chan error, 1)
	go func() {
		res, err := pullAlways(p, c.ref)
		if err == nil {
			res.Lease.Release()
		}
		done <- err
	}()
	<-allHeld // the resumed GET is in flight: Resume runs, under the Claim

	if _, err := store.Claim(c.layer.String()); !errors.Is(err, registryfetch.ErrPartialClaimed) {
		close(hold)
		<-done
		t.Fatalf("Claim during the running Resume = %v, want ErrPartialClaimed", err)
	}
	if _, err := cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		FreeBytes: fixedFreeBytes(64 << 30),
		Now:       func() time.Time { return sweepAt },
	}); err != nil {
		close(hold)
		<-done
		t.Fatal(err)
	}
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
		close(hold)
		<-done
		t.Fatalf("control: the unclaimed stale partial survived the sweep: %v", err)
	}
	if fi, err := os.Lstat(held); err != nil || fi.Size() != cutAt {
		close(hold)
		<-done
		t.Fatalf("the running pull's partial after the sweep: %v, %v; want %d bytes kept", fi, err, cutAt)
	}

	close(hold)
	if err := <-done; err != nil {
		t.Fatalf("resumed pull: %v", err)
	}
	if got := c.takeRanges(); len(got) != 1 || got[0] != "bytes=4096-" {
		t.Fatalf("resumed pull Range headers = %q, want one from the spared bytes", got)
	}
	verifyLayer(t, cache, c)
}

// TestResumeHoldsClaim pins, over the source of the packages that own a
// layer partial store, that nothing reaches a partial's bytes except the
// puller under the digest's Claim: every PartialStore Resume is in a function
// that first takes the Claim on the same store and defers its release, so a
// sweep (which spares only claimed digests) can never unlink a partial a
// Resume is writing. Bytes and Usage measure by lstat and open nothing.
func TestResumeHoldsClaim(t *testing.T) {
	type site struct{ file, fn string }
	var resumes []site
	for _, dir := range []string{".", "../runtime"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, pkg := range pkgs {
			for fname, f := range pkg.Files {
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok || fd.Body == nil {
						continue
					}
					checkResumeUnderClaim(t, fset, fname, fd, func() { resumes = append(resumes, site{fname, fd.Name.Name}) })
				}
			}
		}
	}
	if len(resumes) == 0 {
		t.Fatal("no PartialStore Resume found; the scan does not see the puller")
	}
}

// checkResumeUnderClaim fails t for any Resume call in fd on a receiver
// spelled "...partials" that is not preceded, in fd, by a Claim on the same
// receiver and a deferred call of the release that Claim returned. found runs
// once per Resume seen.
func checkResumeUnderClaim(t *testing.T, fset *token.FileSet, fname string, fd *ast.FuncDecl, found func()) {
	t.Helper()
	type claim struct {
		recv    string
		release string
		pos     token.Pos
	}
	var claims []claim
	deferred := map[string]token.Pos{}
	recvOf := func(call *ast.CallExpr, method string) (string, bool) {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return "", false
		}
		var b strings.Builder
		var render func(e ast.Expr)
		render = func(e ast.Expr) {
			switch x := e.(type) {
			case *ast.Ident:
				b.WriteString(x.Name)
			case *ast.SelectorExpr:
				render(x.X)
				b.WriteString("." + x.Sel.Name)
			default:
				b.WriteString("?")
			}
		}
		render(sel.X)
		return b.String(), true
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && len(x.Lhs) >= 1 {
				if call, ok := x.Rhs[0].(*ast.CallExpr); ok {
					if recv, ok := recvOf(call, "Claim"); ok {
						if id, ok := x.Lhs[0].(*ast.Ident); ok {
							claims = append(claims, claim{recv: recv, release: id.Name, pos: x.Pos()})
						}
					}
				}
			}
		case *ast.DeferStmt:
			if id, ok := x.Call.Fun.(*ast.Ident); ok {
				if _, seen := deferred[id.Name]; !seen {
					deferred[id.Name] = x.Pos()
				}
			}
		case *ast.CallExpr:
			recv, ok := recvOf(x, "Resume")
			if !ok || !strings.HasSuffix(recv, "partials") {
				return true
			}
			found()
			where := fset.Position(x.Pos())
			held := false
			for _, c := range claims {
				if c.recv == recv && c.pos < x.Pos() {
					if dp, ok := deferred[c.release]; ok && dp > c.pos && dp < x.Pos() {
						held = true
					}
				}
			}
			if !held {
				t.Errorf("%s: %s calls %s.Resume without first taking %s.Claim and deferring its release (%s:%d)",
					filepath.Base(fname), fd.Name.Name, recv, recv, filepath.Base(where.Filename), where.Line)
			}
		}
		return true
	})
}

// TestStoreBytesSurvivesUnmeasurablePartialDir: a partial dir replaced after
// the store was opened (by a symlink or a file) is logged and counted as
// zero, and StoreBytes and StoreBytesByClass still report the blob and tree
// total with no error.
func TestStoreBytesSurvivesUnmeasurablePartialDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace func(t *testing.T, path string)
	}{
		{"a symlink", func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatal(err)
			}
		}},
		{"a regular file", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			s := c.OpenPartialStore(slog.New(slog.NewTextHandler(&buf, nil)))
			if s == nil {
				t.Fatal("partial store refused")
			}
			if _, err := c.CommitBlob(digestOf([]byte("blob")), 4, func(w io.Writer) error {
				_, err := io.WriteString(w, "blob")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			writePartial(t, s.Dir, 'a', 100, partialFixtureNow)
			want, err := c.StoreBytes()
			if err != nil {
				t.Fatal(err)
			}
			want -= 100 // the blob and tree total, without the partial
			if want != 4 {
				t.Fatalf("fixture: blob and tree total %d, want 4", want)
			}
			if err := os.RemoveAll(s.Dir); err != nil {
				t.Fatal(err)
			}
			tc.replace(t, s.Dir)

			got, err := c.StoreBytes()
			if err != nil || got != want {
				t.Fatalf("StoreBytes = %d, %v; want %d, nil", got, err, want)
			}
			classes, err := c.StoreBytesByClass(context.Background())
			if err != nil {
				t.Fatalf("StoreBytesByClass: %v", err)
			}
			if _, ok := classes[ClassPartial]; ok {
				t.Fatalf("ClassPartial reported over an unmeasurable dir: %v", classes)
			}
			if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "image partial store not measured") {
				t.Fatalf("unmeasurable partial dir not logged at Warn: %q", buf.String())
			}
		})
	}
}
