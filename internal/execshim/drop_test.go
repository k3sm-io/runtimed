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

// noHostGroups is the group lookup the drop tests run under: the host assigns
// no gid a group, so the verdicts do not hang on the Mac's own groups.
func noHostGroups(int) (string, bool, error) { return "", false, nil }

func TestDropShim(t *testing.T) {
	drop := supervisor.Credential{UID: 300, GID: 300, Groups: []int{300}, Drop: true}
	svc := supervisor.ServiceIdentity{UID: 250, GID: 250, Known: true}
	t.Run("no drop changes nothing", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, supervisor.Credential{}, 0, svc, noHostGroups, "/d"); err != nil || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want none", err, r.calls)
		}
	})
	t.Run("root drops after chowning its artifacts", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, drop, 0, svc, noHostGroups, "/d", "/l"); err != nil {
			t.Fatal(err)
		}
		want := []string{"chown /d", "chown /l", "setgid", "initgroups", "setuid"}
		if !reflect.DeepEqual(r.calls, want) {
			t.Fatalf("calls %v, want %v", r.calls, want)
		}
	})
	t.Run("an unprivileged shim refuses a drop", func(t *testing.T) {
		r := &recDrop{}
		if err := dropShim(r, r.chown, drop, 300, svc, noHostGroups, "/d"); err == nil || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want a refusal and no call", err, r.calls)
		}
	})
	t.Run("a drop to a login-range uid is refused before any call", func(t *testing.T) {
		r := &recDrop{}
		to := supervisor.Credential{UID: 501, GID: 300, Groups: []int{300}, Drop: true}
		if err := dropShim(r, r.chown, to, 0, svc, noHostGroups, "/d"); !errors.Is(err, supervisor.ErrPodUIDRefused) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want ErrPodUIDRefused and no call", err, r.calls)
		}
	})
	t.Run("a drop into staff is refused before any call", func(t *testing.T) {
		r := &recDrop{}
		to := supervisor.Credential{UID: 300, GID: 300, Groups: []int{300, 20}, Drop: true}
		if err := dropShim(r, r.chown, to, 0, svc, noHostGroups, "/d"); !errors.Is(err, supervisor.ErrPodGroupRefused) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want ErrPodGroupRefused and no call", err, r.calls)
		}
	})
	t.Run("a drop to the service uid is refused before any call", func(t *testing.T) {
		r := &recDrop{}
		to := supervisor.Credential{UID: svc.UID, GID: 300, Groups: []int{300}, Drop: true}
		if err := dropShim(r, r.chown, to, 0, svc, noHostGroups, "/d"); !errors.Is(err, supervisor.ErrPodUIDRefused) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v, want ErrPodUIDRefused and no call", err, r.calls)
		}
	})
	t.Run("a failed chown stops before any identity change", func(t *testing.T) {
		r := &recDrop{}
		boom := errors.New("boom")
		err := dropShim(r, func(string, int, int) error { return boom }, drop, 0, svc, noHostGroups, "/d")
		if !errors.Is(err, boom) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v", err, r.calls)
		}
	})
}
