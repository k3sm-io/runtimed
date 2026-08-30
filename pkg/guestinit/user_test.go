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

package guestinit

import (
	"errors"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// testPasswd and testGroup are a small, realistic pair of databases from a
// container image (the postgres images ship exactly this shape).
const (
	testPasswd = "# comment\n" +
		"root:x:0:0:root:/root:/bin/sh\n" +
		"malformed-line\n" +
		"postgres:x:999:999:PostgreSQL:/var/lib/postgresql:/bin/sh\n"
	testGroup = "root:x:0:\n" +
		"postgres:x:999:\n" +
		"pgdata:x:2000:postgres\n"
)

// TestResolveUser pins the OCI USER-spec resolution the guest performs against
// the container's own rootfs databases.
func TestResolveUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		user    string
		want    Ident
		wantErr error
	}{
		{name: "empty means root", user: "", want: Ident{UID: 0, GID: 0}},
		{name: "a numeric uid is used verbatim", user: "1000", want: Ident{UID: 1000, GID: 0}},
		{name: "uid:gid", user: "1000:2000", want: Ident{UID: 1000, GID: 2000}},
		{name: "a name takes its passwd gid", user: "postgres", want: Ident{UID: 999, GID: 999}},
		{name: "name:group", user: "postgres:pgdata", want: Ident{UID: 999, GID: 2000}},
		{name: "name:gid", user: "postgres:2000", want: Ident{UID: 999, GID: 2000}},
		{name: "uid:group", user: "1000:pgdata", want: Ident{UID: 1000, GID: 2000}},
		{name: "an unknown user fails closed", user: "nobody", wantErr: ErrNoSuchUser},
		{name: "an unknown group fails closed", user: "postgres:nope", wantErr: ErrNoSuchUser},
		{name: "an out-of-range uid is refused", user: "4294967296", wantErr: ErrInvalidSpec},
		{name: "an empty user part is refused", user: ":2000", wantErr: ErrInvalidSpec},
		{name: "an empty group part is refused", user: "postgres:", wantErr: ErrInvalidSpec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveUser(tc.user, testPasswd, testGroup)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ResolveUser(%q) error = %v, want %v", tc.user, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveUser(%q): %v", tc.user, err)
			}
			if got.UID != tc.want.UID || got.GID != tc.want.GID {
				t.Fatalf("ResolveUser(%q) = %+v, want %+v", tc.user, got, tc.want)
			}
		})
	}

	t.Run("a numeric uid resolves without any passwd file", func(t *testing.T) {
		t.Parallel()
		// A scratch image has no /etc/passwd; a numeric USER must still run.
		got, err := ResolveUser("65532:65532", "", "")
		if err != nil {
			t.Fatalf("ResolveUser: %v", err)
		}
		if got.UID != 65532 || got.GID != 65532 {
			t.Fatalf("ident = %+v, want 65532:65532", got)
		}
	})

	t.Run("a malformed id is an error, not a name lookup", func(t *testing.T) {
		t.Parallel()
		_, err := ResolveUser("99x9", testPasswd, testGroup)
		if !errors.Is(err, ErrNoSuchUser) {
			t.Fatalf("error = %v, want the token reported as an unresolvable name", err)
		}
	})

	t.Run("a malformed passwd line does not stop the pod", func(t *testing.T) {
		t.Parallel()
		// testPasswd carries a junk line ahead of the entry being resolved.
		got, err := ResolveUser("postgres", testPasswd, testGroup)
		if err != nil || got.UID != 999 {
			t.Fatalf("ResolveUser = (%+v, %v), want the pod's own image junk skipped", got, err)
		}
	})
}

// TestContainerIdent pins the identity a container actually starts with,
// including the fsGroup union that makes group-owned volume files reachable.
func TestContainerIdent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		container  *guestv1.GuestContainer
		fsGroup    int64
		wantGroups []int64
		wantErr    error
	}{
		{
			name:       "fsGroup joins the supplementary groups",
			container:  &guestv1.GuestContainer{Name: "c", Uid: 999, Gid: 999, SupplementalGids: []int64{999}},
			fsGroup:    2000,
			wantGroups: []int64{999, 2000},
		},
		{
			name:       "duplicates collapse and the set is sorted",
			container:  &guestv1.GuestContainer{Name: "c", SupplementalGids: []int64{2000, 10, 2000, 10}},
			fsGroup:    2000,
			wantGroups: []int64{10, 2000},
		},
		{
			name:       "a zero fsGroup adds nothing",
			container:  &guestv1.GuestContainer{Name: "c", SupplementalGids: []int64{10}},
			fsGroup:    0,
			wantGroups: []int64{10},
		},
		{
			name:      "a negative supplementary gid is refused",
			container: &guestv1.GuestContainer{Name: "c", SupplementalGids: []int64{-1}},
			wantErr:   ErrInvalidSpec,
		},
		{
			name:      "an out-of-range uid is refused rather than truncated",
			container: &guestv1.GuestContainer{Name: "c", Uid: 1 << 32},
			wantErr:   ErrInvalidSpec,
		},
		{
			name:      "a nil container is refused",
			container: nil,
			wantErr:   ErrInvalidSpec,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ContainerIdent(tc.container, tc.fsGroup)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ContainerIdent: %v", err)
			}
			if len(got.Groups) != len(tc.wantGroups) {
				t.Fatalf("groups = %v, want %v", got.Groups, tc.wantGroups)
			}
			for i, g := range tc.wantGroups {
				if got.Groups[i] != g {
					t.Fatalf("groups = %v, want %v", got.Groups, tc.wantGroups)
				}
			}
		})
	}
}
