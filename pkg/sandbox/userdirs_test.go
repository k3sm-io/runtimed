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

package sandbox

import (
	"errors"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func TestUserDirSuffix(t *testing.T) {
	cases := []struct {
		id   string
		want string
		ok   bool
	}{
		{"8f3c1d2e-0000-4000-8000-000000000001", "k3sm.8f3c1d2e-0000-4000-8000-000000000001", true},
		{"pod.a", "k3sm.pod.a", true},
		// dirhelper silently answers the unsuffixed tree for these (measured),
		// so they must get no suffix at all.
		{"a..b", "", false},
		{"a/b", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := UserDirSuffix(tc.id)
		if got != tc.want || ok != tc.ok {
			t.Errorf("UserDirSuffix(%q) = %q, %v; want %q, %v", tc.id, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGenerateUserDirLinkGrant(t *testing.T) {
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}
	const uid = "8f3c1d2e-0000-4000-8000-000000000001"
	dirs := UserDirs{Temp: "/private/var/folders/xy/abc/T", Cache: "/private/var/folders/xy/abc/C"}
	tempLink := `(literal "/private/var/folders/xy/abc/T/k3sm.` + uid + `")`
	cacheLink := `(literal "/private/var/folders/xy/abc/C/k3sm.` + uid + `")`

	t.Run("granted as two metadata literals and nothing else", func(t *testing.T) {
		prof, err := Generate(sp, GenerateOptions{PodUID: uid, UserDirs: dirs})
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(prof); err != nil {
			t.Fatal(err)
		}
		rules := ruleLines(prof)
		for _, want := range []string{tempLink, cacheLink} {
			if strings.Count(rules, want) != 1 {
				t.Errorf("want exactly one %s:\n%s", want, prof)
			}
		}
		// Nothing on the shared trees themselves, and no subpath, read-data or
		// write anywhere under /var/folders: the links resolve into the data
		// volume, which is the only place data moves.
		for _, bad := range []string{
			`(literal "/private/var/folders/xy/abc/T")`,
			`(literal "/private/var/folders/xy/abc/C")`,
			`(subpath "/private/var/folders`,
			`(subpath "/var/folders`,
		} {
			if strings.Contains(rules, bad) {
				t.Errorf("profile carries %s:\n%s", bad, prof)
			}
		}
		// The literals sit in a file-read-metadata allow, never file-read* or
		// file-write*.
		i := strings.Index(prof, tempLink)
		head := prof[:i]
		if j := strings.LastIndex(head, "(allow "); j < 0 || !strings.HasPrefix(head[j:], "(allow file-read-metadata") {
			t.Errorf("the link literal is not under (allow file-read-metadata …):\n%s", prof)
		}
	})

	t.Run("the /var spelling also renders the /private form Seatbelt matches", func(t *testing.T) {
		prof, err := Generate(sp, GenerateOptions{PodUID: uid, UserDirs: UserDirs{Temp: "/var/folders/xy/abc/T", Cache: "/var/folders/xy/abc/C"}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(prof, tempLink) || !strings.Contains(prof, cacheLink) {
			t.Errorf("missing the /private form:\n%s", prof)
		}
	})

	for _, tc := range []struct {
		name string
		uid  string
		dirs UserDirs
	}{
		{"no dirs", uid, UserDirs{}},
		{"no pod uid", "", dirs},
		{"only one dir", uid, UserDirs{Temp: dirs.Temp}},
		{"unusable suffix", "a..b", dirs},
	} {
		t.Run("nothing granted: "+tc.name, func(t *testing.T) {
			prof, err := Generate(sp, GenerateOptions{PodUID: tc.uid, UserDirs: tc.dirs})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(prof, "k3sm.") && strings.Contains(prof, "/var/folders") {
				t.Errorf("a user-dir grant was rendered:\n%s", prof)
			}
		})
	}
}

func TestGenerateRefusesBadUserDirs(t *testing.T) {
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}
	const uid = "p1"
	for _, tc := range []struct {
		name string
		dirs UserDirs
	}{
		{"relative", UserDirs{Temp: "var/folders/x/T", Cache: "/private/var/folders/x/C"}},
		{"not a T dir", UserDirs{Temp: "/private/var/folders/x/Q", Cache: "/private/var/folders/x/C"}},
		{"unclean", UserDirs{Temp: "/private/var/folders/x/../x/T", Cache: "/private/var/folders/x/C"}},
		{"quote", UserDirs{Temp: "/private/var/fol\"ders/x/T", Cache: "/private/var/folders/x/C"}},
		{"under the pods root", UserDirs{Temp: "/var/lib/k3sm/pods/T", Cache: "/private/var/folders/x/C"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(sp, GenerateOptions{PodUID: uid, UserDirs: tc.dirs})
			if !errors.Is(err, ErrInvalidUserDirLink) {
				t.Fatalf("Generate err = %v, want ErrInvalidUserDirLink", err)
			}
		})
	}
}
