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
	"fmt"
	"testing"
	"time"
)

// TestInUseDigestsPodRootNamesConfigAndEveryLayer pins the premise of
// EvictImage's in-use refusal (it refuses only when every target blob is in
// use): a pod record written for an image with a config and N layers yields
// an in-use set holding the config digest and all N layer digests, and
// ImageRoot.Digests names exactly those.
func TestInUseDigestsPodRootNamesConfigAndEveryLayer(t *testing.T) {
	for _, n := range []int{1, 3, 8} {
		t.Run(fmt.Sprintf("%d layers", n), func(t *testing.T) {
			f := newGCFixture(t)
			root := ImageRoot{Reference: "app:v1", Config: f.blob("pod config", time.Hour)}
			for i := range n {
				root.Layers = append(root.Layers, f.blob(fmt.Sprintf("pod layer %d", i), time.Hour))
			}
			want := append([]string{root.Config}, root.Layers...)
			if got := root.Digests(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("Digests = %v, want %v", got, want)
			}
			f.pod("pod-a", root)
			inUse, err := f.cache.InUseDigests(nil)
			if err != nil {
				t.Fatalf("InUseDigests: %v", err)
			}
			for _, d := range want {
				if _, ok := inUse[d]; !ok {
					t.Errorf("in-use set lacks %s", d)
				}
			}
			if len(inUse) != len(want) {
				t.Errorf("in-use set = %v, want exactly %v", inUse, want)
			}
		})
	}
}
