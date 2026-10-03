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

package execshim

import (
	"errors"
	"reflect"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

type recDrop struct{ calls []string }

func (r *recDrop) Setgid(int) error       { r.calls = append(r.calls, "setgid"); return nil }
func (r *recDrop) Initgroups([]int) error { r.calls = append(r.calls, "initgroups"); return nil }
func (r *recDrop) Setuid(int) error       { r.calls = append(r.calls, "setuid"); return nil }
func (r *recDrop) chown(p string, _, _ int) error {
	r.calls = append(r.calls, "chown "+p)
	return nil
}

func TestDropShim(t *testing.T) {
	drop := supervisor.Credential{UID: 501, GID: 20, Groups: []int{20}, Drop: true}
	t.Run("no drop changes nothing", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, supervisor.Credential{}, 0, "/d"); err != nil || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want none", err, r.calls)
		}
	})
	t.Run("root drops after chowning its artifacts", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, drop, 0, "/d", "/l"); err != nil {
			t.Fatal(err)
		}
		want := []string{"chown /d", "chown /l", "setgid", "initgroups", "setuid"}
		if !reflect.DeepEqual(r.calls, want) {
			t.Fatalf("calls %v, want %v", r.calls, want)
		}
	})
	t.Run("an unprivileged shim refuses a drop", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, drop, 501, "/d"); err == nil || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want a refusal and no call", err, r.calls)
		}
	})
	t.Run("a failed chown stops before any identity change", func(t *testing.T) {
		r := &recDrop{}
		boom := errors.New("boom")
		err := dropShim(r, func(string, int, int) error { return boom }, drop, 0, "/d")
		if !errors.Is(err, boom) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v", err, r.calls)
		}
	})
}
