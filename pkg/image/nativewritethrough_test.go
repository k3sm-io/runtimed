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
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// TestNativeLayerNeverWritesThroughAContainedLink pins, for the native unpack
// policy, that a later layer naming a path through a CONTAINED link an earlier
// layer planted (l -> d, up -> .) never creates, links or alters anything
// outside the unpack root. Each variant is its own image. The inside-or-refused
// outcome of each case is pinned so a change in either direction is visible.
func TestNativeLayerNeverWritesThroughAContainedLink(t *testing.T) {
	layer1 := []tarSpec{
		{name: "d", typ: tar.TypeDir, mode: 0o755},
		{name: "l", typ: tar.TypeSymlink, link: "d"},
		{name: "up", typ: tar.TypeSymlink, link: "."},
	}
	withF := []tarSpec{{name: "d/f", mode: 0o644, data: "inside"}}

	for _, tc := range []struct {
		name   string
		layers [][]tarSpec
		// wantInside lists paths that must exist under the rootfs when the
		// unpack succeeds; empty with wantErr set means refused.
		wantInside []string
		wantErr    bool
		wantEscape bool
	}{
		{name: "file_through_link", layers: [][]tarSpec{{{name: "l/f", mode: 0o644, data: "x"}}}, wantInside: []string{"d/f"}},
		{name: "dir_through_link", layers: [][]tarSpec{{{name: "l/sub", typ: tar.TypeDir, mode: 0o755}}}, wantInside: []string{"d/sub"}},
		{name: "hardlink_target_through_link", layers: [][]tarSpec{withF, {{name: "hl", typ: tar.TypeLink, link: "l/f"}}}, wantInside: []string{"d/f", "hl"}},
		{name: "hardlink_target_climbs_out", layers: [][]tarSpec{{{name: "hl2", typ: tar.TypeLink, link: "up/../../canary"}}}, wantErr: true, wantEscape: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outside := t.TempDir()
			canary := filepath.Join(outside, "canary")
			want := []byte("canary-bytes")
			if err := os.WriteFile(canary, want, 0o644); err != nil {
				t.Fatal(err)
			}
			c, u := newTestUnpacker(t)
			all := [][]tarSpec{layer1}
			all = append(all, tc.layers...)
			gl := make([]ggcrv1.Layer, 0, len(all))
			for _, s := range all {
				gl = append(gl, layerFrom(t, s))
			}
			m := commitImage(t, c, imageFrom(t, gl...))
			tree, err := u.Unpack(context.Background(), m, NativeUnpackPolicy())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Unpack succeeded, want a refusal")
				}
				if tc.wantEscape && !errors.Is(err, ErrLayerEscapes) {
					t.Errorf("error = %v, want ErrLayerEscapes", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unpack: %v", err)
				}
				for _, p := range tc.wantInside {
					if _, lerr := os.Lstat(filepath.Join(tree.Rootfs, p)); lerr != nil {
						t.Errorf("%s not under the root: %v", p, lerr)
					}
				}
			}
			got, err := os.ReadFile(canary)
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("canary = %q, %v; want unchanged", got, err)
			}
			ents, err := os.ReadDir(outside)
			if err != nil || len(ents) != 1 {
				t.Errorf("directory outside the root holds %d entries (err %v), want only the canary", len(ents), err)
			}
		})
	}
}
