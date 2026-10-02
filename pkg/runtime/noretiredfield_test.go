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

package runtime

import (
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoProductionReadOfRootfsField is the structural half of the retired
// PodBox field 4: no production file in this module may name the generated Go
// accessor for it, so no code path can read a caller-supplied rootfs path, now
// or after a future edit. It scans every non-test .go file under the module
// root as tokens (so build tags do not hide a file) and fails on
//
//   - an identifier spelled exactly RootfsPath or GetRootfsPath, and
//   - a comment or string literal containing the proto field's name, except
//     inside retiredRootfsField's own doc comment, which is the one place that
//     says what field 4 was.
//
// The comment rule keeps prose from inviting a reader back to the field: every
// other mention says "field 4" or "the retired PodBox field".
func TestNoProductionReadOfRootfsField(t *testing.T) {
	const fieldName = "rootfs" + "_path"
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.mod")); err != nil {
		t.Fatalf("%s is not the module root: %v", moduleRoot, err)
	}
	podGo := filepath.Join(moduleRoot, "pkg", "runtime", "pod.go")
	exemptStart, exemptEnd := detectorDocSpan(t, podGo)

	var scanned []string
	err = filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != moduleRoot && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned = append(scanned, path)
		rel, _ := filepath.Rel(moduleRoot, path)

		fset := token.NewFileSet()
		file := fset.AddFile(path, fset.Base(), len(src))
		var s scanner.Scanner
		s.Init(file, src, func(pos token.Position, msg string) {
			t.Errorf("%s: scan error: %s", pos, msg)
		}, scanner.ScanComments)
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			switch tok {
			case token.IDENT:
				if lit == "RootfsPath" || lit == "GetRootfsPath" {
					t.Errorf("%s: identifier %s names the retired PodBox field", rel+":"+strconv.Itoa(fset.Position(pos).Line), lit)
				}
			case token.COMMENT, token.STRING, token.CHAR:
				if !strings.Contains(lit, fieldName) {
					continue
				}
				off := file.Offset(pos)
				if path == podGo && off >= exemptStart && off+len(lit) <= exemptEnd {
					continue
				}
				t.Errorf("%s: %s mentions %s outside retiredRootfsField's doc comment", rel+":"+strconv.Itoa(fset.Position(pos).Line), tok, fieldName)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", moduleRoot, err)
	}

	// Non-vacuity: a walk rooted at the wrong directory, or one that silently
	// skipped the package that used to read the field, would pass trivially.
	if len(scanned) < 50 {
		t.Fatalf("scanned %d production files under %s, want at least 50", len(scanned), moduleRoot)
	}
	found := false
	for _, p := range scanned {
		if p == podGo {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s was not scanned", podGo)
	}
}

// detectorDocSpan returns the byte offsets of retiredRootfsField's doc comment
// in path, failing the test when the function or its doc is missing.
func detectorDocSpan(t *testing.T, path string) (start, end int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "retiredRootfsField" {
			continue
		}
		if fn.Doc == nil {
			t.Fatalf("%s: retiredRootfsField has no doc comment", path)
		}
		return fset.Position(fn.Doc.Pos()).Offset, fset.Position(fn.Doc.End()).Offset
	}
	t.Fatalf("%s: retiredRootfsField not found", path)
	return 0, 0
}
