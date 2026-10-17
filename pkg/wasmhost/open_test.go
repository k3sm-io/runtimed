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

package wasmhost

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPreopensOpensByDescriptor(t *testing.T) {
	f := newFixture(t)
	v, err := BuildLaunchSpec(f.bounds(), f.input())
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenPreopens(v)
	if err != nil {
		t.Fatalf("OpenPreopens: %v", err)
	}
	defer func() { _ = o.Close() }()
	if len(o.Preopens) != 2 || o.Preopens[0].Kind != PreopenRootfs || o.Preopens[1].HostPath != f.data {
		t.Fatalf("preopens = %+v", o.Preopens)
	}
	for _, p := range o.Preopens {
		fi, err := p.Dir.Stat()
		if err != nil || !fi.IsDir() {
			t.Fatalf("preopen %s is not an open directory: %v %v", p.HostPath, fi, err)
		}
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(o.Module, head); err != nil || string(head) != "\x00asm" {
		t.Fatalf("module read = %q, %v", head, err)
	}
	// Renaming the module away after the open does not change what the
	// descriptor reads: the engine acts on what was opened.
	if err := os.Rename(f.module, f.module+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Module.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(o.Module, head); err != nil || string(head) != "\x00asm" {
		t.Fatalf("module read after the rename = %q, %v", head, err)
	}
}

// TestOpenPreopensRefusesASwapAfterValidate pins the TOCTOU close: a component
// replaced by a symlink between Validate and the open fails the open instead
// of redirecting it.
func TestOpenPreopensRefusesASwapAfterValidate(t *testing.T) {
	swap := func(t *testing.T, path, target string) {
		t.Helper()
		if err := os.Rename(path, path+".orig"); err != nil {
			t.Fatal(err)
		}
		mustSymlink(t, target, path)
	}
	cases := []struct {
		name string
		swap func(t *testing.T, f fixture)
	}{
		{"the rootfs", func(t *testing.T, f fixture) { swap(t, f.rootfs, filepath.Join(f.sibling, "rootfs")) }},
		{"a dir above the module", func(t *testing.T, f fixture) {
			swap(t, filepath.Join(f.rootfs, "app"), filepath.Join(f.sibling, "rootfs", "app"))
		}},
		{"the module", func(t *testing.T, f fixture) {
			other := filepath.Join(f.sibling, "rootfs", "app", "main.wasm")
			mustWrite(t, other)
			swap(t, f.module, other)
		}},
		{"a volume root", func(t *testing.T, f fixture) { swap(t, f.claimRoot, f.sibling) }},
		{"a volume leaf", func(t *testing.T, f fixture) { swap(t, f.data, f.sibling) }},
		{"the pod dir bound itself", func(t *testing.T, f fixture) { swap(t, f.podDir, f.sibling) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			v, err := BuildLaunchSpec(f.bounds(), f.input())
			if err != nil {
				t.Fatal(err)
			}
			tc.swap(t, f)
			o, err := OpenPreopens(v)
			t.Log(err)
			if !errors.Is(err, ErrInvalidSpec) {
				if o != nil {
					_ = o.Close()
				}
				t.Fatalf("OpenPreopens after the swap = %v, want ErrInvalidSpec", err)
			}
		})
	}
	t.Run("a module swapped for a directory", func(t *testing.T) {
		f := newFixture(t)
		v, err := BuildLaunchSpec(f.bounds(), f.input())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(f.module); err != nil {
			t.Fatal(err)
		}
		mustMkdir(t, f.module)
		if _, err := OpenPreopens(v); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("OpenPreopens = %v, want ErrInvalidSpec", err)
		}
	})
	t.Run("the zero Validated", func(t *testing.T) {
		if _, err := OpenPreopens(Validated{}); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("OpenPreopens = %v, want ErrInvalidSpec", err)
		}
	})
}
