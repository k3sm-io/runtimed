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

package main

import (
	"go/token"
	"sort"
	"testing"
)

func TestDeclaredSubdirConsts(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "exported string const is collected",
			src:  "package image\n\nconst FooSubdir = \"foo\"\n",
			want: []string{"FooSubdir"},
		},
		{
			name: "a lowercase fooSubdir is ignored",
			src:  "package image\n\nconst fooSubdir = \"foo\"\n",
			want: nil,
		},
		{
			name: "a non-string const is ignored",
			src:  "package image\n\nconst NumSubdir = 3\n",
			want: nil,
		},
		{
			name: "a name not ending in Subdir is ignored",
			src:  "package image\n\nconst FooDir = \"foo\"\n",
			want: nil,
		},
		{
			name: "a //go:build-gated file is still parsed",
			src:  "//go:build darwin\n\npackage sandbox\n\nconst VMReapSubdir = \"vmreap\"\n",
			want: []string{"VMReapSubdir"},
		},
		{
			name: "a const block collects every matching member",
			src: `package sandbox

const (
	ServerSubdir = "server"
	AgentSubdir  = "agent"
	notASubdir   = "run"
)
`,
			want: []string{"ServerSubdir", "AgentSubdir"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			got, err := declaredSubdirConsts(fset, tc.name+".go", tc.src)
			if err != nil {
				t.Fatalf("declaredSubdirConsts: %v", err)
			}
			assertSameNames(t, got, tc.want)
		})
	}
}

func TestReferencedSubdirConsts(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want []subdirConst
	}{
		{
			name: "a package-qualified selector is a reference",
			src: `package runtime

import "example.com/pkg/image"

func use() {
	_ = image.IndexSubdir
}
`,
			want: []subdirConst{{pkg: "image", name: "IndexSubdir"}},
		},
		{
			name: "a comment-only mention is not a reference",
			src: `package runtime

import "example.com/pkg/image"

// IndexSubdir is mentioned here only, never in code: StraySubdir too.
func use() {
	_ = image.OperatorSubdir
}
`,
			want: []subdirConst{{pkg: "image", name: "OperatorSubdir"}},
		},
		{
			name: "an aliased import is resolved through the alias",
			src: `package runtime

import img "example.com/pkg/image"

func use() {
	_ = img.IndexSubdir
}
`,
			want: []subdirConst{{pkg: "image", name: "IndexSubdir"}},
		},
		{
			name: "a selector on an unimported identifier is ignored",
			src: `package runtime

func use(image struct{ IndexSubdir string }) {
	_ = image.IndexSubdir
}
`,
			want: nil,
		},
		{
			name: "a selector whose member does not match the Subdir shape is ignored",
			src: `package runtime

import "example.com/pkg/image"

func use() {
	_ = image.SomeOtherField
}
`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			got, err := referencedSubdirConsts(fset, tc.name+".go", tc.src)
			if err != nil {
				t.Fatalf("referencedSubdirConsts: %v", err)
			}
			assertSameConsts(t, got, tc.want)
		})
	}
}

func assertSameNames(t *testing.T, got, want []string) {
	t.Helper()
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func assertSameConsts(t *testing.T, got map[subdirConst]bool, want []subdirConst) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("got %v, want %v (missing %s)", got, want, w)
		}
	}
}
