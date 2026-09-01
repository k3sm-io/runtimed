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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGuestKernelPinLiteralsCarryValidDigests reads this package's own source
// and checks every GuestKernelPin composite literal in it.
//
// # Why source and not values
//
// The runtime table is one map, and a test over it can only see the entries that
// map holds. A pin literal that was added to a different table, commented into a
// second var block, or written into a helper that nothing calls yet is invisible
// to a value test and perfectly visible here — and it is exactly the shape a
// half-finished digest bump takes. The walk is over the AST rather than over a
// regexp for the ordinary reason: a text scraper matches inside comments and
// strings, and a check that starts passing for the wrong reason is worse than no
// check.
//
// # What it asserts
//
// For every pin literal found, each digest field is either empty — the honest
// unminted state, which Complete() reports as false and Lookup refuses — or
// exactly 64 lowercase hex characters. It also refuses a half-minted pair, since
// one digest without the other names an artifact set that cannot be assembled.
//
// # Why the count is fatal
//
// A walk that finds nothing proves nothing, and "no invalid digests" is
// trivially true of a file with no pins in it. The found == 0 fatal is what
// makes a renamed type, a restructured table, or a deleted pin fail loudly
// instead of quietly.
func TestGuestKernelPinLiteralsCarryValidDigests(t *testing.T) {
	files := parsePackageSource(t, ".")
	found := 0
	for path, file := range files {
		for _, lit := range guestKernelPinLiterals(file) {
			found++
			base := filepath.Base(path)
			img, imgOK := pinDigestField(t, base, lit, "ImageSHA256")
			initrd, initrdOK := pinDigestField(t, base, lit, "InitramfsSHA256")
			if !imgOK || !initrdOK {
				continue
			}
			for _, d := range []struct{ field, digest string }{
				{"ImageSHA256", img},
				{"InitramfsSHA256", initrd},
			} {
				if d.digest != "" && !IsValidDigest(d.digest) {
					t.Errorf("%s: a GuestKernelPin literal declares %s = %q, which is neither empty nor 64 lowercase hex characters",
						base, d.field, d.digest)
				}
			}
			if (img == "") != (initrd == "") {
				t.Errorf("%s: a GuestKernelPin literal is half-minted (ImageSHA256 %q, InitramfsSHA256 %q); "+
					"a set needs both digests or neither", base, img, initrd)
			}
		}
	}
	if found == 0 {
		t.Fatal("found no GuestKernelPin composite literals in this package's source — the walk measured nothing, " +
			"so its verdict is vacuous (was the pin table renamed or removed?)")
	}
}

// parsePackageSource parses every non-test .go file in dir, keyed by path.
func parsePackageSource(t *testing.T, dir string) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the package dir %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	files := make(map[string]*ast.File)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files[path] = f
	}
	if len(files) == 0 {
		t.Fatalf("no non-test .go files under %s", dir)
	}
	return files
}

// guestKernelPinLiterals returns the value literals of every
// map[string]GuestKernelPin composite literal in file.
//
// The walk is deliberately scoped to map values, which is what a pin table is.
// Element literals are written with the type ELIDED (`{KernelVersion: …}`), so
// they carry no Ident to match on and are recognisable only through the
// enclosing map's value type — matching the map is therefore the only way to
// find them at all.
//
// A GuestKernelPin literal that is not a map value is out of scope, and that is
// a decision rather than an oversight: ensure.go legitimately constructs a
// transient GuestKernelPin from digests it has just computed
// (verifySetDir's SetDigest call), whose fields are variables and not literals a
// reviewer could check. Counting that as a pin would make this walk fail on
// correct code, which is the fastest way to get a check deleted. A pin table is
// a map; this checks maps.
func guestKernelPinLiterals(file *ast.File) []*ast.CompositeLit {
	const typeName = "GuestKernelPin"
	var out []*ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		mt, ok := cl.Type.(*ast.MapType)
		if !ok {
			return true
		}
		if id, ok := mt.Value.(*ast.Ident); !ok || id.Name != typeName {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if elem, ok := kv.Value.(*ast.CompositeLit); ok {
				out = append(out, elem)
			}
		}
		return true
	})
	return out
}

// pinDigestField extracts one string-literal field from a pin literal.
//
// An absent field reads as empty, matching Go's own zero value. A field whose
// value is not a plain string literal — a constant reference, a concatenation, a
// function call — is a hard failure rather than a skip: a digest that cannot be
// read off the page cannot be reviewed on the page either, and this walk exists
// to make review mechanical.
func pinDigestField(t *testing.T, file string, lit *ast.CompositeLit, field string) (string, bool) {
	t.Helper()
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			t.Errorf("%s: a GuestKernelPin literal sets %s to something other than a string literal; "+
				"a pinned digest must be readable in the source", file, field)
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil {
			t.Errorf("%s: a GuestKernelPin literal sets %s to an unquotable literal %s: %v", file, field, bl.Value, err)
			return "", false
		}
		return s, true
	}
	return "", true
}
