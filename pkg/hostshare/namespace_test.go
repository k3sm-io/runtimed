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

package hostshare

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestEntryNamespaceParseAndFormat pins the share line's namespaces= field:
// a valid list parses and round-trips, a line without it is node-wide as
// before, and any malformed field fails the whole file rather than leaving a
// node-wide line behind.
func TestEntryNamespaceParseAndFormat(t *testing.T) {
	t.Parallel()
	in := "rw /Users/dev/Code namespaces=yurei-system\n" +
		"ro /Users/dev/Code/app namespaces=yurei-p-*,app\n" +
		"rw /opt/w\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Mode: ModeReadWrite, Path: "/Users/dev/Code", Namespaces: []string{"yurei-system"}},
		{Mode: ModeReadOnly, Path: "/Users/dev/Code/app", Namespaces: []string{"yurei-p-*", "app"}},
		{Mode: ModeReadWrite, Path: "/opt/w"},
	}
	if len(got) != len(want) {
		t.Fatalf("Parse = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i].String() || !slices.Equal(got[i].Namespaces, want[i].Namespaces) {
			t.Errorf("entry %d = %#v, want %#v", i, got[i], want[i])
		}
	}
	if len(got[2].Namespaces) != 0 {
		t.Errorf("a line with no namespaces= field got %v, want node-wide", got[2].Namespaces)
	}
	again, err := Parse(strings.NewReader(string(Format(got))))
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 3 || string(Format(again)) != string(Format(got)) {
		t.Errorf("Format round trip = %v", again)
	}
	if !strings.Contains(string(Format(got)), "ro /Users/dev/Code/app namespaces=app,yurei-p-*\n") {
		t.Errorf("Format = %q, want the namespaces sorted on the line", Format(got))
	}
	for _, line := range []string{
		"rw /opt/w namespaces=",                  // empty list is not node-wide
		"rw /opt/w namespaces=,a",                // empty name
		"rw /opt/w namespaces=a,",                // trailing comma
		"rw /opt/w namespaces=a,a",               // duplicate
		"rw /opt/w namespaces=Prod",              // not a DNS-1123 label
		"rw /opt/w namespaces=-a",                // leading dash
		"rw /opt/w namespaces=a-",                // trailing dash on an exact name
		"rw /opt/w namespaces=*",                 // a bare wildcard is node-wide in disguise
		"rw /opt/w namespaces=a**",               // two stars
		"rw /opt/w namespaces=a*b",               // star inside
		"rw /opt/w namespaces=*a",                // leading star
		"rw /opt/w namespaces=a_b",               // underscore
		"rw /opt/w ns=a",                         // wrong key
		"rw /opt/w namespaces=a extra",           // too many fields
		"rw /opt/w namespace=a",                  // wrong key spelling
		"rw /opt/w namespaces=" + long(64),       // over 63 bytes
		"rw /opt/w namespaces=" + long(63) + "*", // a pattern whose prefix fills a label
		"rw /opt/w namespaces=" + many(33),       // too many names
	} {
		if _, err := Parse(strings.NewReader(line + "\n")); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("Parse(%q) = %v, want ErrInvalidEntry", line, err)
		}
		if _, err := ParseFile(strings.NewReader("rw /opt/ok\n" + line + "\n")); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("ParseFile(%q) = %v, want ErrInvalidEntry (the file fails, no line survives node-wide)", line, err)
		}
	}
	if err := ValidateEntry(Entry{Mode: ModeReadWrite, Path: "/opt/w", Namespaces: []string{"ok", "BAD"}}); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("ValidateEntry(bad namespace) = %v, want ErrInvalidEntry", err)
	}
	if _, err := Parse(strings.NewReader("rw /opt/w namespaces=" + long(63) + "\n")); err != nil {
		t.Errorf("Parse(63-byte name) = %v, want nil", err)
	}
}

func long(n int) string { return strings.Repeat("a", n) }

func many(n int) string {
	var ns []string
	for i := range n {
		ns = append(ns, fmt.Sprintf("n%d", i))
	}
	return strings.Join(ns, ",")
}

// TestAuthorizeNamespace is the gate's core: a share line naming namespaces
// admits a hostPath only from a pod in one of them (an exact name or a prefix
// pattern), refuses every other namespace with ErrNotShared naming the pod's
// namespace and no other, and a line naming none admits every namespace.
func TestAuthorizeNamespace(t *testing.T) {
	t.Parallel()
	const code = "/Users/dev/Code"
	fs := fakeFS{kinds: map[string]string{
		code:            "dir",
		code + "/app":   "dir",
		code + "/other": "dir",
		"/Volumes/data": "dir",
	}}
	entries := []Entry{
		{Mode: ModeReadWrite, Path: code, Namespaces: []string{"yurei-system"}},
		{Mode: ModeReadWrite, Path: code + "/app", Namespaces: []string{"app", "yurei-p-*"}},
		{Mode: ModeReadOnly, Path: "/Volumes/data"},
	}
	for _, tc := range []struct {
		ns, path string
		ro       bool
	}{
		{"yurei-system", code, false},
		{"yurei-system", code + "/other", false},
		{"yurei-system", code + "/app", false},
		{"app", code + "/app", false},
		{"yurei-p-app", code + "/app", false},
		{"default", "/Volumes/data", true},
		{"app", "/Volumes/data", true},
	} {
		t.Run("grant/"+tc.ns+tc.path, func(t *testing.T) {
			t.Parallel()
			got, err := authorize(entries, tc.ns, hostPathBox(tc.path, "", tc.path, "", tc.ro), fs)
			if err != nil || len(got) != 1 || got[0].Path != tc.path {
				t.Fatalf("authorize(%s, %s) = %v, %v, want a grant", tc.ns, tc.path, got, err)
			}
		})
	}
	for _, tc := range []struct{ ns, path string }{
		{"app", code},
		{"app", code + "/other"},
		{"default", code + "/app"},
		{"yurei-p", code + "/app"},
		{"yurei-p-", code + "/app"}, // not a namespace name, so no pattern admits it
		{"yurei-q-app", code + "/app"},
		{"yurei-systems", code},
		{"", code},
		{"", code + "/app"},
	} {
		t.Run("refuse/"+tc.ns+tc.path, func(t *testing.T) {
			t.Parallel()
			_, err := authorize(entries, tc.ns, hostPathBox(tc.path, "", tc.path, ""), fs)
			if !errors.Is(err, ErrNotShared) {
				t.Fatalf("authorize(%q, %s) = %v, want ErrNotShared", tc.ns, tc.path, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, fmt.Sprintf("namespace %q", tc.ns)) {
				t.Errorf("refusal %q does not name the pod's namespace %q", msg, tc.ns)
			}
			// The only quoted name besides the volume is the pod's own namespace.
			rest := strings.Replace(strings.Replace(msg, fmt.Sprintf("namespace %q", tc.ns), "", 1), `volume "code"`, "", 1)
			for _, other := range []string{"yurei-system", "yurei-p-", "app\"", "app,"} {
				if strings.Contains(rest, other) {
					t.Errorf("refusal %q reveals another namespace (%s)", msg, other)
				}
			}
		})
	}
	t.Run("node_wide_line_admits_every_namespace", func(t *testing.T) {
		t.Parallel()
		nw := []Entry{{Mode: ModeReadWrite, Path: code}}
		for _, ns := range []string{"", "default", "yurei-system", "anything"} {
			if _, err := authorize(nw, ns, hostPathBox(code+"/app", "", code+"/app", ""), fs); err != nil {
				t.Errorf("authorize(node-wide, %q) = %v, want a grant", ns, err)
			}
		}
	})
	t.Run("invalid_namespaces_admit_nothing", func(t *testing.T) {
		t.Parallel()
		bad := []Entry{{Mode: ModeReadWrite, Path: code, Namespaces: []string{"Bad Name"}}}
		if _, err := authorize(bad, "default", hostPathBox(code, "", code, ""), fs); !errors.Is(err, ErrNotShared) {
			t.Errorf("authorize(entry with an invalid namespace) = %v, want ErrNotShared, never node-wide", err)
		}
	})
}

// TestMatchNamespaceMostSpecific pins that the most-specific-wins and rw/ro
// rules run only among the entries that admit the pod's namespace: a
// namespace's narrower ro line narrows that namespace alone.
func TestMatchNamespaceMostSpecific(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{Mode: ModeReadWrite, Path: "/Users/dev/Code"},
		{Mode: ModeReadOnly, Path: "/Users/dev/Code/secrets", Namespaces: []string{"untrusted"}},
		{Mode: ModeReadOnly, Path: "/Volumes/data", Namespaces: []string{"a"}},
		{Mode: ModeReadWrite, Path: "/Volumes/data", Namespaces: []string{"b"}},
	}
	for _, tc := range []struct {
		ns, path string
		want     Mode
	}{
		{"untrusted", "/Users/dev/Code/secrets/k", ModeReadOnly},
		{"other", "/Users/dev/Code/secrets/k", ModeReadWrite},
		{"a", "/Volumes/data/x", ModeReadOnly},
		{"b", "/Volumes/data/x", ModeReadWrite},
	} {
		got, ok := match(entries, tc.ns, tc.path, "Directory")
		if !ok || got.Mode != tc.want {
			t.Errorf("match(%s, %s) = %v %v, want mode %s", tc.ns, tc.path, got, ok, tc.want)
		}
	}
	if got, ok := match(entries, "c", "/Volumes/data/x", "Directory"); ok {
		t.Errorf("match(c, /Volumes/data/x) = %v, want no entry", got)
	}
}

// TestDelegationNamespaceCap pins the delegation's namespaces= cap: it parses
// and round-trips, an invalid cap fails the file, and an uncapped delegation
// keeps today's five-field line.
func TestDelegationNamespaceCap(t *testing.T) {
	t.Parallel()
	in := "delegate uid=501 user=dev modes=rw,socket namespaces=yurei-p-*,yurei-system /Users/dev/Code\n" +
		"delegate uid=502 user=ops modes=ro /Users/ops/Code\n"
	f, err := ParseFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Delegations) != 2 || !slices.Equal(f.Delegations[0].Namespaces, []string{"yurei-p-*", "yurei-system"}) || len(f.Delegations[1].Namespaces) != 0 {
		t.Fatalf("ParseFile = %+v", f.Delegations)
	}
	out := string(FormatFile(f))
	if !strings.Contains(out, in[:strings.Index(in, "\n")+1]) || !strings.Contains(out, "delegate uid=502 user=ops modes=ro /Users/ops/Code\n") {
		t.Errorf("FormatFile = %q, want both lines as written", out)
	}
	again, err := ParseFile(strings.NewReader(out))
	if err != nil || len(again.Delegations) != 2 || again.Delegations[0].String() != f.Delegations[0].String() {
		t.Errorf("round trip = %+v, %v", again, err)
	}
	for _, line := range []string{
		"delegate uid=501 user=dev modes=rw namespaces= /Users/dev/Code",
		"delegate uid=501 user=dev modes=rw namespaces=* /Users/dev/Code",
		"delegate uid=501 user=dev modes=rw namespaces=a,a /Users/dev/Code",
		"delegate uid=501 user=dev modes=rw namespaces=A /Users/dev/Code",
		"delegate uid=501 user=dev modes=rw ns=a /Users/dev/Code",
		"delegate uid=501 user=dev namespaces=a modes=rw /Users/dev/Code",
		"delegate uid=501 user=dev modes=rw namespaces=a /Users/dev/Code extra",
	} {
		if _, err := ParseFile(strings.NewReader(line + "\n")); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("ParseFile(%q) = %v, want ErrInvalidEntry", line, err)
		}
	}
}

// TestNamespaceWithinCap pins the containment rule between a delegated
// entry's namespaces and its delegation's cap.
func TestNamespaceWithinCap(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		entry, cap []string
		ok         bool
	}{
		{nil, nil, true},
		{[]string{"a"}, nil, true},
		{nil, []string{"a"}, true}, // inherits the cap
		{[]string{"a"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a"}, false},
		{[]string{"yurei-p-x"}, []string{"yurei-p-*"}, true},
		{[]string{"yurei-p-x*"}, []string{"yurei-p-*"}, true},
		{[]string{"yurei-p-*"}, []string{"yurei-p-*"}, true},
		{[]string{"yurei-*"}, []string{"yurei-p-*"}, false},
		{[]string{"yurei-p-*"}, []string{"yurei-p-x"}, false},
		{[]string{"yurei-q"}, []string{"yurei-p-*"}, false},
		{[]string{"yurei-system"}, []string{"yurei-p-*", "yurei-system"}, true},
	} {
		err := namespacesWithin(tc.entry, tc.cap)
		if (err == nil) != tc.ok {
			t.Errorf("namespacesWithin(%v, %v) = %v, want ok=%v", tc.entry, tc.cap, err, tc.ok)
		}
	}
}

// TestCheckDelegatedNamespace pins that `k3sm share add` and the node refuse
// a delegated entry naming a namespace outside the delegation's cap.
func TestCheckDelegatedNamespace(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := filepath.Join(f.prefix, "app")
	d := f.delegation()
	d.Namespaces = []string{"proj-*"}
	for _, ns := range [][]string{nil, {"proj-a"}, {"proj-a", "proj-b"}, {"proj-a*"}} {
		if err := f.l.checkDelegated(d, Entry{Mode: ModeReadWrite, Path: app, Namespaces: ns}); err != nil {
			t.Errorf("checkDelegated(namespaces %v under cap proj-*) = %v, want nil", ns, err)
		}
	}
	for _, ns := range [][]string{{"other"}, {"proj-a", "other"}, {"pro*"}} {
		err := f.l.checkDelegated(d, Entry{Mode: ModeReadWrite, Path: app, Namespaces: ns})
		if !errors.Is(err, ErrNotDelegated) {
			t.Errorf("checkDelegated(namespaces %v under cap proj-*) = %v, want ErrNotDelegated", ns, err)
		}
	}
	// An uncapped delegation lets the user name any namespace.
	if err := f.l.checkDelegated(f.delegation(), Entry{Mode: ModeReadWrite, Path: app, Namespaces: []string{"other"}}); err != nil {
		t.Errorf("checkDelegated(uncapped) = %v, want nil", err)
	}
}

// TestLoadEffectiveNamespace pins the node's reading of a capped delegation:
// an entry within the cap is admitted as written, an entry naming none
// inherits the cap, and an entry outside it is dropped with a reason.
func TestLoadEffectiveNamespace(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app, src := filepath.Join(f.prefix, "app"), filepath.Join(f.prefix, "app", "src")
	d := f.delegation()
	d.Namespaces = []string{"proj-*"}
	f.writeNode(t, File{Delegations: []Delegation{d}})
	f.writeUser(t, "rw "+app+" namespaces=proj-a\nro "+src+"\nrw "+f.prefix+" namespaces=yurei-system\n")
	eff, err := f.l.loadEffective(f.nodeFile)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Mode: ModeReadWrite, Path: app, Namespaces: []string{"proj-a"}},
		{Mode: ModeReadOnly, Path: src, Namespaces: []string{"proj-*"}},
	}
	if len(eff.Entries) != len(want) {
		t.Fatalf("Entries = %v, want %v", eff.Entries, want)
	}
	for i := range want {
		if eff.Entries[i].String() != want[i].String() {
			t.Errorf("entry %d = %v, want %v", i, eff.Entries[i], want[i])
		}
		if uid, ok := eff.Owner(eff.Entries[i]); !ok || uid != f.uid {
			t.Errorf("Owner(%v) = %d %v, want %d", eff.Entries[i], uid, ok, f.uid)
		}
	}
	if len(eff.Dropped) != 1 || eff.Dropped[0].Entry.Path != f.prefix || !strings.Contains(eff.Dropped[0].Reason, "namespace") {
		t.Errorf("Dropped = %+v, want the out-of-cap line with a namespace reason", eff.Dropped)
	}
	// The inherited cap is what the node enforces.
	fs := fakeFS{kinds: map[string]string{src: "dir"}}
	if _, err := authorize(eff.Entries, "proj-b", hostPathBox(src, "", src, "", true), fs); err != nil {
		t.Errorf("authorize(proj-b, inherited cap) = %v, want a grant", err)
	}
	if _, err := authorize(eff.Entries, "default", hostPathBox(src, "", src, "", true), fs); !errors.Is(err, ErrNotShared) {
		t.Errorf("authorize(default, inherited cap) = %v, want ErrNotShared", err)
	}
}

// TestAuthorizeNamespaceSamePathModes pins two lines for one path with
// different modes and namespace sets: the controller's namespace keeps
// read-write while every project namespace gets the tree read-only. Where
// the sets overlap (yurei-system also matches yurei-*), the existing
// precedence decides: between two lines for the same path, read-write wins.
func TestAuthorizeNamespaceSamePathModes(t *testing.T) {
	t.Parallel()
	const code = "/Users/dev/Code"
	in := "rw " + code + " namespaces=yurei-system\nro " + code + " namespaces=yurei-*\nrw " + code + "/app namespaces=yurei-app\n"
	entries, err := Parse(strings.NewReader(in))
	if err != nil || len(entries) != 3 {
		t.Fatalf("Parse(two lines for one path) = %v, %v, want both kept", entries, err)
	}
	if again, err := Parse(strings.NewReader(string(Format(entries)))); err != nil || len(again) != 3 {
		t.Errorf("Format round trip = %v, %v, want both lines for %s kept", again, err, code)
	}
	fs := fakeFS{kinds: map[string]string{code: "dir", code + "/app": "dir", code + "/lib": "dir"}}
	for _, tc := range []struct {
		name, ns, path string
		ro             bool
		want           *Grant // nil: refused
	}{
		{"project_ro_admitted", "yurei-foo", code, true, &Grant{Volume: "code", Path: code, ReadOnly: true}},
		{"project_ro_below", "yurei-foo", code + "/lib", true, &Grant{Volume: "code", Path: code + "/lib", ReadOnly: true}},
		{"project_rw_refused", "yurei-foo", code, false, nil},
		{"system_rw", "yurei-system", code, false, &Grant{Volume: "code", Path: code}},
		{"system_ro_mount", "yurei-system", code, true, &Grant{Volume: "code", Path: code, ReadOnly: true}},
		{"own_repo_rw", "yurei-app", code + "/app", false, &Grant{Volume: "code", Path: code + "/app"}},
		{"own_root_still_ro", "yurei-app", code, false, nil},
		{"default_refused", "default", code, true, nil},
		{"default_refused_rw", "default", code, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := authorize(entries, tc.ns, hostPathBox(tc.path, "", tc.path, "", tc.ro), fs)
			if tc.want == nil {
				if !errors.Is(err, ErrNotShared) {
					t.Fatalf("authorize(%s, %s, ro=%v) = %v, %v, want ErrNotShared", tc.ns, tc.path, tc.ro, got, err)
				}
				return
			}
			if err != nil || len(got) != 1 {
				t.Fatalf("authorize(%s, %s, ro=%v) = %v, %v, want one grant", tc.ns, tc.path, tc.ro, got, err)
			}
			g := got[0]
			g.Entry = Entry{}
			if !reflect.DeepEqual(g, *tc.want) {
				t.Errorf("grant = %+v, want %+v", g, *tc.want)
			}
		})
	}
	if e, ok := match(entries, "yurei-system", code, "Directory"); !ok || e.Mode != ModeReadWrite {
		t.Errorf("match(yurei-system) = %v %v, want the rw line (read-write wins on one path)", e, ok)
	}
}
