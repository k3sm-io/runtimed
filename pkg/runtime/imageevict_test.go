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
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// evictKeepReasonValues maps every EvictKeepReason constant pkg/image's
// non-test source declares for this build, by name, to its value. It reads the
// source so a reason added there is seen here without anyone remembering to
// list it.
func evictKeepReasonValues(t *testing.T) map[string]image.EvictKeepReason {
	t.Helper()
	dir := filepath.Join("..", "image")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		if ok, err := build.Default.MatchFile(dir, n); err != nil || !ok {
			if err != nil {
				t.Fatalf("match %s: %v", n, err)
			}
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		files = append(files, f)
	}
	vals, err := typedStringConsts(fset, files, "EvictKeepReason")
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	if len(vals) == 0 {
		t.Fatalf("found no EvictKeepReason constants under %s", dir)
	}
	out := make(map[string]image.EvictKeepReason, len(vals))
	for name, v := range vals {
		out[name] = image.EvictKeepReason(v)
	}
	return out
}

// emptyImporter satisfies every import with an empty package, so
// typedStringConsts can type-check one package's files without loading its
// dependencies. A use of an imported name is then a type error the checker
// reports and typedStringConsts ignores; a constant that depends on one has no
// known value, which typedStringConsts does report.
type emptyImporter struct{}

func (emptyImporter) Import(path string) (*types.Package, error) {
	pkg := types.NewPackage(path, filepath.Base(path))
	pkg.MarkComplete()
	return pkg, nil
}

// typedStringConsts type-checks files as one package and returns every
// package-level constant whose type is the package's own named type typeName,
// by name, to its string value. go/types resolves the forms a syntactic walk
// misses: a conversion (X = T("x")), an implicit repeat in a const block, a
// constant built from another one, and a spec with too few values, which is
// an error here rather than a panic.
func typedStringConsts(fset *token.FileSet, files []*ast.File, typeName string) (map[string]string, error) {
	conf := types.Config{Importer: emptyImporter{}, Error: func(error) {}}
	pkg, _ := conf.Check("evictconsts", fset, files, nil)
	if pkg == nil {
		return nil, errors.New("type-check returned no package")
	}
	scope := pkg.Scope()
	out := make(map[string]string)
	for _, name := range scope.Names() {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		named, ok := c.Type().(*types.Named)
		if !ok || named.Obj().Pkg() != pkg || named.Obj().Name() != typeName {
			continue
		}
		if c.Val().Kind() != constant.String {
			return nil, fmt.Errorf("%s constant %s has no known string value (%s)", typeName, name, c.Val())
		}
		out[name] = constant.StringVal(c.Val())
	}
	return out, nil
}

// TestEvictTypedStringConsts proves the collector the completeness check stands on
// over the declaration forms a syntactic walk would miss or panic on.
func TestEvictTypedStringConsts(t *testing.T) {
	const decls = "type R string\n\ntype Other string\n\n"
	cases := []struct {
		name    string
		imports string
		src     string
		want    map[string]string
		wantErr bool
	}{
		{name: "explicit type", src: `const A R = "a"`, want: map[string]string{"A": "a"}},
		{name: "conversion", src: `const A = R("a")`, want: map[string]string{"A": "a"}},
		{name: "implicit repeat", src: "const (\n\tA R = \"a\"\n\tB\n)", want: map[string]string{"A": "a", "B": "a"}},
		{name: "several names in one spec", src: `const A, B R = "a", "b"`, want: map[string]string{"A": "a", "B": "b"}},
		{name: "built from another constant", src: "const A R = \"a\"\nconst B = A + \"-b\"", want: map[string]string{"A": "a", "B": "a-b"}},
		{name: "raw string", src: "const A R = `a`", want: map[string]string{"A": "a"}},
		{name: "untyped and other types are not collected", src: "const A = \"a\"\nconst B Other = \"b\"\nconst C string = \"c\"", want: map[string]string{}},
		{name: "function-local constants are not collected", src: "func f() R {\n\tconst A R = \"a\"\n\treturn A\n}", want: map[string]string{}},
		{name: "too few values is an error, not a panic", src: `const A, B R = "a"`, wantErr: true},
		{name: "a value from an unloaded import is an error", imports: `import "example.com/q"`, src: "const A R = R(q.X)", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "p.go", "package p\n\n"+tc.imports+"\n\n"+decls+tc.src+"\n", 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := typedStringConsts(fset, []*ast.File{f}, "R")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("typedStringConsts = %v, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("typedStringConsts: %v", err)
			}
			if !maps.Equal(got, tc.want) {
				t.Fatalf("typedStringConsts = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestEvictSkipReasonMapping pins the map from every kept reason onto the
// wire enum, and fails when pkg/image gains a reason this table does not name.
func TestEvictSkipReasonMapping(t *testing.T) {
	cases := []struct {
		name   string
		reason image.EvictKeepReason
		want   runtimev1.EvictSkipReason
		sent   bool
	}{
		{"EvictKeptRooted", image.EvictKeptRooted, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_ROOTED, true},
		{"EvictKeptInUse", image.EvictKeptInUse, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_IN_USE, true},
		{"EvictKeptLeased", image.EvictKeptLeased, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_LEASED, true},
		{"EvictKeptShared", image.EvictKeptShared, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED, true},
		{"EvictKeptYoung", image.EvictKeptYoung, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG, true},
		// A failure, carried by the INTERNAL status, never a kept reason.
		{"EvictKeptUnlinkFailed", image.EvictKeptUnlinkFailed, runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, sent := evictSkipReason(tc.reason)
			if got != tc.want || sent != tc.sent {
				t.Fatalf("evictSkipReason(%q) = %v, %v; want %v, %v", tc.reason, got, sent, tc.want, tc.sent)
			}
		})
	}

	t.Run("every pkg/image reason is in the table", func(t *testing.T) {
		listed := make(map[string]image.EvictKeepReason, len(cases))
		for _, tc := range cases {
			listed[tc.name] = tc.reason
		}
		declared := evictKeepReasonValues(t)
		var missing []string
		for name, v := range declared {
			if lv, ok := listed[name]; !ok || lv != v {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Fatalf("pkg/image declares EvictKeepReason %v with no row here: map it in evictSkipReason and add the row", missing)
		}
		if len(declared) != len(listed) {
			t.Fatalf("table lists %d reasons, pkg/image declares %d", len(listed), len(declared))
		}
	})

	t.Run("every wire value but UNSPECIFIED is reached", func(t *testing.T) {
		reached := make(map[runtimev1.EvictSkipReason]bool)
		for _, tc := range cases {
			if got, sent := evictSkipReason(tc.reason); sent {
				reached[got] = true
			}
		}
		for n, name := range runtimev1.EvictSkipReason_name {
			v := runtimev1.EvictSkipReason(n)
			if v == runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED {
				continue
			}
			if !reached[v] {
				t.Errorf("wire value %s is reached from no pkg/image reason", name)
			}
		}
	})

	t.Run("an unknown reason is not sent", func(t *testing.T) {
		for _, r := range []image.EvictKeepReason{"", "something-new"} {
			if got, sent := evictSkipReason(r); sent || got != runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED {
				t.Errorf("evictSkipReason(%q) = %v, %v; want UNSPECIFIED, false", r, got, sent)
			}
		}
	})
}

// TestEvictStatusError pins the status each eviction outcome maps to, and that
// only the three FAILED_PRECONDITION refusals carry an ErrorInfo detail.
func TestEvictStatusError(t *testing.T) {
	const blob = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	removedOne := &image.EvictResult{Removed: []string{blob}}
	cases := []struct {
		name       string
		res        *image.EvictResult
		err        error
		wantCode   codes.Code
		wantReason string // "" means no ErrorInfo detail
		msgHas     string // "" means no check
		msgLacks   string // "" means no check
	}{
		{name: "ok", res: &image.EvictResult{}, wantCode: codes.OK},
		{name: "ok with every kept reason but unlink-failed", res: &image.EvictResult{Kept: []image.EvictKept{
			{Digest: blob, Reason: image.EvictKeptRooted},
			{Digest: blob, Reason: image.EvictKeptInUse},
			{Digest: blob, Reason: image.EvictKeptLeased},
			{Digest: blob, Reason: image.EvictKeptShared},
			{Digest: blob, Reason: image.EvictKeptYoung},
		}}, wantCode: codes.OK},
		{name: "in use", err: fmt.Errorf("pod p1: %w", errEvictImageInUse),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonImageInUse},
		{name: "reference ambiguous", err: fmt.Errorf("resolve: %w", image.ErrIndexEntryAmbiguous),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonReferenceAmbiguous},
		{name: "roots incomplete", err: fmt.Errorf("evict: %w", image.ErrRootsIncomplete),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "roots incomplete with an empty partial result", res: &image.EvictResult{}, err: image.ErrRootsIncomplete,
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "roots incomplete after an unlink", res: removedOne, err: image.ErrRootsIncomplete,
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "roots incomplete after an unlink with never-attempted blobs", res: &image.EvictResult{
			Removed: []string{blob},
			Kept:    []image.EvictKept{{Digest: blob, Reason: image.EvictKeptUnlinkFailed}},
		}, err: fmt.Errorf("evict: %w", image.ErrRootsIncomplete),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "roots incomplete beside a nil result", res: nil, err: errors.Join(image.ErrRootsIncomplete, errors.New("outcome")),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "untyped error after an unlink", res: removedOne, err: errors.New("disk on fire"),
			wantCode: codes.Internal},
		{name: "unlink failed", res: &image.EvictResult{Removed: []string{blob}, Kept: []image.EvictKept{
			{Digest: blob, Reason: image.EvictKeptYoung},
			{Digest: blob, Reason: image.EvictKeptUnlinkFailed},
		}}, wantCode: codes.Internal},
		{name: "not found carries no detail", err: image.ErrIndexEntryNotFound, wantCode: codes.NotFound},
		{name: "invalid digest carries no detail", err: image.ErrInvalidDigest, wantCode: codes.InvalidArgument},
		{name: "free space unknown carries no detail", err: image.ErrFreeSpaceUnknown, wantCode: codes.Unavailable},
		{name: "corrupt index entry carries no detail", err: image.ErrIndexEntryCorrupt, wantCode: codes.FailedPrecondition},
		{name: "cancelled", err: context.Canceled, wantCode: codes.Canceled},
		{name: "untyped error", err: errors.New("disk on fire"), wantCode: codes.Internal},

		// A refusal beside an explicit nil result: still the refusal, and the
		// message names no unlinked count.
		{name: "in use beside a nil result", res: nil, err: fmt.Errorf("pod p1: %w", errEvictImageInUse),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonImageInUse, msgLacks: "unlinked"},
		{name: "reference ambiguous beside a nil result", res: nil, err: image.ErrIndexEntryAmbiguous,
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonReferenceAmbiguous, msgLacks: "unlinked"},
		{name: "roots incomplete beside a nil result names no count", res: nil, err: image.ErrRootsIncomplete,
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete, msgLacks: "unlinked"},
		{name: "roots incomplete after an unlink names the count", res: removedOne, err: image.ErrRootsIncomplete,
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete, msgHas: "1 blob(s) were unlinked"},

		// Two sentinels joined: the first refusal in evictRefusalReason's order
		// (in use, ambiguous, roots incomplete) names the detail, and a refusal
		// outranks a non-refusal sentinel.
		{name: "joined in use and roots incomplete", err: errors.Join(image.ErrRootsIncomplete, errEvictImageInUse),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonImageInUse},
		{name: "joined ambiguous and roots incomplete", err: errors.Join(image.ErrRootsIncomplete, image.ErrIndexEntryAmbiguous),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonReferenceAmbiguous},
		{name: "joined not found and roots incomplete", err: errors.Join(image.ErrIndexEntryNotFound, image.ErrRootsIncomplete),
			wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete},
		{name: "joined not found and invalid digest carries no detail", err: errors.Join(image.ErrIndexEntryNotFound, image.ErrInvalidDigest),
			wantCode: codes.NotFound},

		// Context errors keep their own codes and carry no detail.
		{name: "deadline exceeded", err: context.DeadlineExceeded, wantCode: codes.DeadlineExceeded},
		{name: "wrapped deadline exceeded after an unlink", res: removedOne, err: fmt.Errorf("evict: %w", context.DeadlineExceeded),
			wantCode: codes.DeadlineExceeded},
		{name: "wrapped cancelled", err: fmt.Errorf("evict: %w", context.Canceled), wantCode: codes.Canceled},

		// No error and no result is OK.
		{name: "nil error with nil result", res: nil, err: nil, wantCode: codes.OK},

		// Only unlink-failed kept blobs, nothing removed: INTERNAL, counted.
		{name: "only unlink-failed kept blobs", res: &image.EvictResult{Kept: []image.EvictKept{
			{Digest: blob, Reason: image.EvictKeptUnlinkFailed},
			{Digest: blob, Reason: image.EvictKeptUnlinkFailed},
		}}, wantCode: codes.Internal, msgHas: "2 target blob(s) could not be unlinked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evictStatusError(tc.res, tc.err)
			if tc.wantCode == codes.OK {
				if got != nil {
					t.Fatalf("evictStatusError = %v; want nil", got)
				}
				return
			}
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("evictStatusError = %v; not a gRPC status", got)
			}
			if st.Code() != tc.wantCode {
				t.Fatalf("code = %v; want %v (%v)", st.Code(), tc.wantCode, st.Message())
			}
			if tc.msgHas != "" && !strings.Contains(st.Message(), tc.msgHas) {
				t.Fatalf("message = %q; want it to contain %q", st.Message(), tc.msgHas)
			}
			if tc.msgLacks != "" && strings.Contains(st.Message(), tc.msgLacks) {
				t.Fatalf("message = %q; want it not to contain %q", st.Message(), tc.msgLacks)
			}
			var infos []*errdetails.ErrorInfo
			for _, d := range st.Details() {
				info, ok := d.(*errdetails.ErrorInfo)
				if !ok {
					t.Fatalf("unexpected detail %T: %v", d, d)
				}
				infos = append(infos, info)
			}
			if tc.wantReason == "" {
				if len(infos) != 0 {
					t.Fatalf("details = %v; want none", infos)
				}
				return
			}
			if len(infos) != 1 {
				t.Fatalf("details = %v; want one ErrorInfo", infos)
			}
			if infos[0].GetReason() != tc.wantReason || infos[0].GetDomain() != runtimev1.EvictErrorInfoDomain {
				t.Fatalf("ErrorInfo = %s/%s; want %s/%s", infos[0].GetDomain(), infos[0].GetReason(),
					runtimev1.EvictErrorInfoDomain, tc.wantReason)
			}
			// evictRefusalStatus sets reason and domain only; pin that it sets
			// no metadata, so a key added later is a deliberate change here.
			if md := infos[0].GetMetadata(); len(md) != 0 {
				t.Fatalf("ErrorInfo metadata = %v; want none", md)
			}
		})
	}
}
