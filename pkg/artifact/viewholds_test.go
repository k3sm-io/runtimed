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

package artifact

import (
	"context"
	"testing"
)

// TestViewsHasHoldSource pins HasHoldSource: true only for a Views built with
// ViewsConfig.Holds, false without one and for a nil Views, so a caller can
// refuse to wire a RemoveIfOrphan that would consult no pod hold.
func TestViewsHasHoldSource(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name  string
		holds HoldReader
		want  bool
	}{
		{name: "with the index as hold source", holds: e.index, want: true},
		{name: "without a hold source", holds: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root(), Cloner: cowCopier{}, Holds: tc.holds}, e.cache, e.index)
			if err != nil {
				t.Fatalf("NewViews: %v", err)
			}
			if got := v.HasHoldSource(); got != tc.want {
				t.Errorf("HasHoldSource = %v, want %v", got, tc.want)
			}
		})
	}
	if (*Views)(nil).HasHoldSource() {
		t.Error("nil Views reports a hold source")
	}
}
