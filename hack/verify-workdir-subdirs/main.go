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

// Command verify-workdir-subdirs is the static completeness half of the
// work-dir deny-set contract that pkg/runtime's
// TestEveryDaemonPrivateSubdirIsDenied only pins by hand: that test's
// everyDaemonPrivateSubdir list is a MAINTAINED enumeration (Go has no way to
// enumerate a package's exported consts at run time from within that package
// itself), so a brand-new FooSubdir const wired into neither list stays green
// forever. This command closes that gap from the outside, by parsing the
// source instead of running it.
//
// It parses every non-test .go file under pkg/image, pkg/guestartifacts and
// pkg/sandbox — RAW, with go/parser, never through a build-tag-aware loader —
// and collects every top-level exported `*Subdir` string const, including
// ones behind a //go:build constraint (a gated file must not be silently
// skipped: pkg/sandbox pairs several *_darwin.go/*_other.go files and either
// half could carry the next one). It then parses
// pkg/runtime/workdirdeny_test.go and collects every package-qualified
// selector expression matching the same name shape, resolved through that
// file's own imports. Every declared const must appear among the referenced
// ones, or the run fails naming the miss.
//
// Deliberately one-directional: it does not check that every reference names
// a const that still exists, because the compiler already fails a build on a
// reference to a deleted one.
//
// No allowlist for a pod-visible `*Subdir` exists here, on purpose: today
// every exported `*Subdir` const in these three packages is daemon-private,
// so none needs one. The one exemption in the deny-set contract —
// <WorkDir>/storage, the PVC parent — is a bare string literal inside
// pkg/runtime, not a `*Subdir` const, so it is outside this scanner's input
// by construction and needs no carve-out. If a future package ever exports a
// deliberately pod-visible `*Subdir` const, add its name to an allowlist
// here, with the reason, rather than silencing the finding at the call site.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// subdirConstName matches an exported `*Subdir` const identifier: an
// uppercase-initial name ending in the literal "Subdir". A lowercase
// `fooSubdir` (package-private, never reachable from another package's
// deny-list assembly) does not match.
var subdirConstName = regexp.MustCompile(`^[A-Z]\w*Subdir$`)

// scanPkgDirs are the work-dir-root-relative package directories this
// verifier treats as owners of daemon-private `*Subdir` consts — the same
// three packages TestEveryDaemonPrivateSubdirIsDenied's doc comment names as
// the reason that test lives in pkg/runtime.
var scanPkgDirs = []string{"pkg/image", "pkg/guestartifacts", "pkg/sandbox"}

// defaultTestFile is the work-dir-root-relative path of the test file that
// must reference every declared `*Subdir` const.
const defaultTestFile = "pkg/runtime/workdirdeny_test.go"

// subdirConst identifies one declared or referenced `*Subdir` const by the
// base name of the package directory that owns it (e.g. "image", not the
// full "pkg/image") and its identifier. The package-directory-basename form
// is what lets a declaration found by walking pkg/image and a reference found
// by resolving an `image.` selector in the test file compare equal without
// either side knowing the other's full path.
type subdirConst struct {
	pkg  string
	name string
}

func (c subdirConst) String() string { return c.pkg + "." + c.name }

func main() {
	root := flag.String("root", "", "the work-dir root containing pkg/image, pkg/guestartifacts and pkg/sandbox (default: the working directory)")
	testFile := flag.String("test-file", defaultTestFile, "path of the test file that must reference every *Subdir const (relative to --root unless absolute)")
	selfTest := flag.Bool("self-test", false, "run the fixture self-test instead of the live check")
	flag.Parse()

	if *selfTest {
		if err := runSelfTest(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	r := *root
	if r == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-workdir-subdirs: getwd: %v\n", err)
			os.Exit(1)
		}
		r = wd
	}

	tf := *testFile
	if !filepath.IsAbs(tf) {
		tf = filepath.Join(r, tf)
	}

	missing, err := check(r, tf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-workdir-subdirs: %v\n", err)
		os.Exit(1)
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "verify-workdir-subdirs: %s does not reference every *Subdir const declared in %s:\n", tf, strings.Join(scanPkgDirs, ", "))
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  %s\n", m)
		}
		os.Exit(1)
	}
	fmt.Printf("OK: %s references every *Subdir const declared in %s\n", tf, strings.Join(scanPkgDirs, ", "))
}

// check reports every *Subdir const declared under root's scanPkgDirs that
// testFilePath does not reference, sorted for a stable report. An empty,
// non-nil-error result means complete.
func check(root, testFilePath string) ([]subdirConst, error) {
	declared, err := collectDeclared(root, scanPkgDirs)
	if err != nil {
		return nil, err
	}
	referenced, err := collectReferencedFile(testFilePath)
	if err != nil {
		return nil, err
	}

	var missing []subdirConst
	for c := range declared {
		if !referenced[c] {
			missing = append(missing, c)
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].pkg != missing[j].pkg {
			return missing[i].pkg < missing[j].pkg
		}
		return missing[i].name < missing[j].name
	})
	return missing, nil
}

// collectDeclared walks every non-test .go file directly under root/relDir,
// for each relDir in relDirs, and returns the set of exported `*Subdir`
// string consts each declares.
func collectDeclared(root string, relDirs []string) (map[subdirConst]bool, error) {
	out := map[subdirConst]bool{}
	fset := token.NewFileSet()
	for _, rel := range relDirs {
		dir := filepath.Join(root, filepath.FromSlash(rel))
		pkgBase := pathpkg.Base(pathpkg.Clean(filepath.ToSlash(rel)))

		matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", dir, err)
		}
		sort.Strings(matches)
		if len(matches) == 0 {
			return nil, fmt.Errorf("no .go files found under %s — the scanned package set may be stale", dir)
		}

		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			names, err := declaredSubdirConsts(fset, path, src)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			for _, name := range names {
				out[subdirConst{pkg: pkgBase, name: name}] = true
			}
		}
	}
	return out, nil
}

// declaredSubdirConsts parses one Go source file — RAW; go/parser has no
// notion of build constraints, so a //go:build-gated file is parsed exactly
// like an ungated one — and returns the exported `*Subdir` identifiers it
// declares as string consts at the top level.
//
// src follows go/parser.ParseFile's convention: nil reads filename from disk,
// a []byte/string/io.Reader is parsed as given (the shape main_test.go's
// inline-snippet cases use, and testdata's on-disk fixtures never need).
func declaredSubdirConsts(fset *token.FileSet, filename string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !subdirConstName.MatchString(name.Name) {
					continue
				}
				// An iota-continuation ValueSpec in a const block carries no
				// Values of its own (they are implicit repeats of the prior
				// spec) — skip rather than mis-index.
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				out = append(out, name.Name)
			}
		}
	}
	return out, nil
}

// collectReferencedFile reads and parses the file at path and returns the set
// of *Subdir consts it references. A missing file is reported as an error —
// a moved or renamed test file must fail the check, not report a vacuous
// green with zero references found.
func collectReferencedFile(path string) (map[subdirConst]bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	fset := token.NewFileSet()
	return referencedSubdirConsts(fset, path, src)
}

// referencedSubdirConsts parses one Go source file and returns the set of
// *Subdir consts it references via a package-qualified selector expression
// (pkgIdent.FooSubdir), with pkgIdent resolved through the file's own
// top-level import declarations — so an aliased import is followed
// correctly, and a dot or blank import (which cannot express a qualified
// selector, or has no importer-visible name) is ignored.
//
// ast.Inspect walks only nodes reachable from the file's Decls — a comment
// mentioning a const's name is not part of that tree (comments live in
// f.Comments, never visited here), and a const name spelled inside an
// unrelated string literal is not a *ast.SelectorExpr — so neither counts as
// a reference.
func referencedSubdirConsts(fset *token.FileSet, filename string, src any) (map[subdirConst]bool, error) {
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	aliasToPkg := map[string]string{}
	for _, imp := range f.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		base := pathpkg.Base(pathpkg.Clean(importPath))
		alias := base
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == "_" || alias == "." {
			continue
		}
		aliasToPkg[alias] = base
	}

	refs := map[subdirConst]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkg, ok := aliasToPkg[id.Name]
		if !ok || !subdirConstName.MatchString(sel.Sel.Name) {
			return true
		}
		refs[subdirConst{pkg: pkg, name: sel.Sel.Name}] = true
		return true
	})
	return refs, nil
}

// runSelfTest proves the two collectors and check() against the fixtures
// under testdata/: complete/ (every declared *Subdir const is referenced by
// its fake test file) must report GREEN, and incomplete/ (the same fixture
// plus one StraySubdir const mentioned only in a comment of the fake test
// file) must report RED naming StraySubdir.
func runSelfTest() error {
	dataDir, err := selfTestDataDir()
	if err != nil {
		return err
	}

	failures := 0
	run := func(fixture string, wantMissing func([]subdirConst) (ok bool, why string)) {
		root := filepath.Join(dataDir, fixture)
		testFile := filepath.Join(root, filepath.FromSlash(defaultTestFile))
		missing, err := check(root, testFile)
		if err != nil {
			fmt.Printf("  FAIL  %s fixture: %v\n", fixture, err)
			failures++
			return
		}
		ok, why := wantMissing(missing)
		if !ok {
			fmt.Printf("  FAIL  %s fixture: %s (missing: %v)\n", fixture, why, missing)
			failures++
			return
		}
		fmt.Printf("  PASS  %s fixture (missing: %v)\n", fixture, missing)
	}

	run("complete", func(missing []subdirConst) (bool, string) {
		if len(missing) != 0 {
			return false, "expected GREEN (no missing consts)"
		}
		return true, ""
	})

	run("incomplete", func(missing []subdirConst) (bool, string) {
		for _, m := range missing {
			if m.name == "StraySubdir" {
				return true, ""
			}
		}
		return false, "expected RED naming StraySubdir"
	})

	if failures > 0 {
		return fmt.Errorf("FAIL: verify-workdir-subdirs self-test: %d check(s) failed", failures)
	}
	fmt.Println("OK: verify-workdir-subdirs self-test green")
	return nil
}

// selfTestDataDir returns the testdata/ directory beside this source file.
// runtime.Caller(0) resolves at compile time to this file's own path, so it
// is correct regardless of the process's working directory — including under
// `go run`, whose working directory is the caller's, not this package's.
func selfTestDataDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("verify-workdir-subdirs: runtime.Caller(0) failed; cannot locate testdata/")
	}
	return filepath.Join(filepath.Dir(file), "testdata"), nil
}
