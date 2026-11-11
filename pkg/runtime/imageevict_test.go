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
	"go/parser"
	"go/token"
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
// non-test source declares, by name, to its value. It reads the source so a
// reason added there is seen here without anyone remembering to list it.
func evictKeepReasonValues(t *testing.T) map[string]image.EvictKeepReason {
	t.Helper()
	dir := filepath.Join("..", "image")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	out := make(map[string]image.EvictKeepReason)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				typ, ok := vs.Type.(*ast.Ident)
				if !ok || typ.Name != "EvictKeepReason" {
					continue
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: EvictKeepReason %s is not a string literal", n, name.Name)
					}
					out[name.Name] = image.EvictKeepReason(strings.Trim(lit.Value, "\"`"))
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("found no EvictKeepReason constants under %s", dir)
	}
	return out
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
		})
	}
}
