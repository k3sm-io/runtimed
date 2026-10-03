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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/shadowset"
)

// repoFile is a path relative to the runtimed repo root (go test runs in
// pkg/shadowset/gen).
func repoFile(rel string) string {
	return filepath.Join("..", "..", "..", rel)
}

// TestShadowTableIsCurrent is the staleness gate: the committed
// shim/shadow_table.h must be byte-for-byte what the generator emits from the
// shadowset list today, so the interposer and the runtime read one list.
func TestShadowTableIsCurrent(t *testing.T) {
	got, err := os.ReadFile(repoFile("shim/shadow_table.h"))
	if err != nil {
		t.Fatal(err)
	}
	if want := render(shadowset.Entries()); !bytes.Equal(got, want) {
		t.Fatalf("shim/shadow_table.h is stale: run go generate ./pkg/shadowset\n--- committed\n%s\n--- generated\n%s", got, want)
	}
}

// TestShimIncludesTheTable proves the interposer reads the generated table and
// carries no hand-written rows of its own beside it.
func TestShimIncludesTheTable(t *testing.T) {
	src, err := os.ReadFile(repoFile("shim/pathrebase_shim.c"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "#include \"shadow_table.h\"") {
		t.Error("shim/pathrebase_shim.c does not include shadow_table.h")
	}
	if strings.Contains(body, "k3sm_shadow_map[] =") {
		t.Error("shim/pathrebase_shim.c defines its own k3sm_shadow_map rows")
	}
	if !strings.Contains(body, "K3SM_SHADOW_COPY_MAX") {
		t.Error("shim/pathrebase_shim.c does not bound the shadow directory by K3SM_SHADOW_COPY_MAX")
	}
}

// TestRenderShape pins the rows: one per exec path, aliases included, and the
// bound equal to the longest copy name.
func TestRenderShape(t *testing.T) {
	out := string(render([]shadowset.Entry{
		{Copy: "bash", Hosts: []string{"/bin/sh", "/bin/bash"}, Shell: true},
		{Copy: "readlink", Hosts: []string{"/usr/bin/readlink"}},
	}))
	for _, want := range []string{
		`    {"/bin/sh", "bash"},` + "\n",
		`    {"/bin/bash", "bash"},` + "\n",
		`    {"/usr/bin/readlink", "readlink"},` + "\n",
		"#define K3SM_SHADOW_COPY_MAX 8\n",
		"DO NOT EDIT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered header lacks %q:\n%s", want, out)
		}
	}
}
