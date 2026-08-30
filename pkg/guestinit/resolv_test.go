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
	"fmt"
	"strings"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// TestRenderResolvConfIsMuslSafe pins the rendering rules that keep a pod's
// DNS working on an alpine (musl) image as well as a glibc one.
func TestRenderResolvConfIsMuslSafe(t *testing.T) {
	t.Parallel()

	t.Run("the golden pod's config renders in query order", func(t *testing.T) {
		t.Parallel()
		got, warnings := RenderResolvConf(goldenSpec().GetResolvConf())
		want := "nameserver 10.43.0.10\n" +
			"search default.svc.cluster.local svc.cluster.local cluster.local\n" +
			"options ndots:5\n"
		if !strings.HasSuffix(got, want) {
			t.Fatalf("resolv.conf =\n%s\nwant it to end with\n%s", got, want)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none for a config within every resolver limit", warnings)
		}
		if !strings.HasPrefix(got, "#") {
			t.Error("resolv.conf does not start with the generated-file comment")
		}
	})

	t.Run("options are still emitted even though musl ignores ndots", func(t *testing.T) {
		t.Parallel()
		got, _ := RenderResolvConf(&guestv1.ResolvConf{
			Nameservers: []string{"10.43.0.10"},
			Options:     []string{"ndots:5", "edns0"},
		})
		if !strings.Contains(got, "options ndots:5 edns0\n") {
			t.Fatalf("resolv.conf = %q, want the options line preserved for glibc images", got)
		}
	})

	t.Run("nameservers past the resolver limit are dropped with a warning", func(t *testing.T) {
		t.Parallel()
		got, warnings := RenderResolvConf(&guestv1.ResolvConf{
			Nameservers: []string{"10.43.0.10", "10.43.0.11", "10.43.0.12", "10.43.0.13"},
		})
		if n := strings.Count(got, "nameserver "); n != maxNameservers {
			t.Errorf("%d nameserver lines, want %d", n, maxNameservers)
		}
		if strings.Contains(got, "10.43.0.13") {
			t.Error("a nameserver past the resolver limit was emitted")
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "10.43.0.13") {
			t.Errorf("warnings = %v, want one naming the dropped nameserver", warnings)
		}
	})

	t.Run("too many search domains are truncated from the tail", func(t *testing.T) {
		t.Parallel()
		searches := []string{
			"default.svc.cluster.local", "svc.cluster.local", "cluster.local",
			"a.example", "b.example", "c.example", "d.example",
		}
		got, warnings := RenderResolvConf(&guestv1.ResolvConf{Searches: searches})
		line := searchLine(t, got)
		fields := strings.Fields(line)[1:]
		if len(fields) != maxSearchDomains {
			t.Fatalf("%d search domains emitted, want %d", len(fields), maxSearchDomains)
		}
		if fields[0] != "default.svc.cluster.local" {
			t.Errorf("first search domain = %q; truncation must drop the TAIL so the pod's own namespace survives", fields[0])
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "d.example") {
			t.Errorf("warnings = %v, want one naming the dropped domain", warnings)
		}
	})

	t.Run("an over-long search line is truncated to fit", func(t *testing.T) {
		t.Parallel()
		// Six domains that are individually legal but together exceed the
		// 256-byte line a resolver will parse. musl discards the WHOLE line,
		// so emitting it would take out the pod's DNS entirely.
		var searches []string
		for i := range 6 {
			searches = append(searches, fmt.Sprintf("%s%d.svc.cluster.local", strings.Repeat("n", 40), i))
		}
		got, warnings := RenderResolvConf(&guestv1.ResolvConf{Searches: searches})
		line := searchLine(t, got)
		if len(line)+1 > maxSearchLineBytes {
			t.Fatalf("search line is %d bytes, want at most %d", len(line)+1, maxSearchLineBytes)
		}
		if len(warnings) == 0 {
			t.Error("an over-long search list was truncated silently")
		}
		if !strings.Contains(line, searches[0]) {
			t.Error("truncation dropped the head of the search list rather than the tail")
		}
	})

	t.Run("an empty config renders no directive lines", func(t *testing.T) {
		t.Parallel()
		got, warnings := RenderResolvConf(nil)
		for _, directive := range []string{"nameserver", "search", "options"} {
			if strings.Contains(got, directive) {
				t.Errorf("empty config emitted a %s line: %q", directive, got)
			}
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none", warnings)
		}
	})
}

// searchLine extracts the rendered search directive.
func searchLine(t *testing.T, resolvConf string) string {
	t.Helper()
	for _, l := range strings.Split(resolvConf, "\n") {
		if strings.HasPrefix(l, "search ") {
			return l
		}
	}
	t.Fatalf("no search line in:\n%s", resolvConf)
	return ""
}

// TestRenderHostsAndHostname pins the other two files in the /etc bind set.
func TestRenderHostsAndHostname(t *testing.T) {
	t.Parallel()

	t.Run("loopback entries are always present", func(t *testing.T) {
		t.Parallel()
		got := RenderHosts("web-0", "")
		for _, want := range []string{"127.0.0.1\tlocalhost\n", "::1\tlocalhost"} {
			if !strings.Contains(got, want) {
				t.Errorf("hosts is missing %q:\n%s", want, got)
			}
		}
		if strings.Contains(got, "web-0") {
			t.Error("the pod's own name was written with no leased address to point it at")
		}
	})

	t.Run("the leased address maps the pod hostname", func(t *testing.T) {
		t.Parallel()
		got := RenderHosts("web-0", "192.168.64.7")
		if !strings.Contains(got, "192.168.64.7\tweb-0\n") {
			t.Errorf("hosts is missing the pod entry:\n%s", got)
		}
	})

	t.Run("hostname is a single terminated line", func(t *testing.T) {
		t.Parallel()
		if got := RenderHostname("web-0"); got != "web-0\n" {
			t.Fatalf("hostname = %q, want %q", got, "web-0\n")
		}
	})
}

// TestParseMemTotal pins the meminfo parse, including the failure that must
// NOT become an unbounded overlay upper.
func TestParseMemTotal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"a real meminfo", "MemTotal:        2027220 kB\nMemFree:  100 kB\n", 2027220 * 1024},
		{"leading lines are skipped", "Slab: 1 kB\nMemTotal: 1024 kB\n", 1024 * 1024},
		{"absent MemTotal is unknown", "MemFree: 100 kB\n", 0},
		{"unparseable value is unknown", "MemTotal: lots kB\n", 0},
		{"an unexpected unit is unknown", "MemTotal: 1024 MB\n", 0},
		{"empty input is unknown", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ParseMemTotal(tc.in); got != tc.want {
				t.Fatalf("ParseMemTotal = %d, want %d", got, tc.want)
			}
			if tc.want == 0 && UpperSizeBytes(ParseMemTotal(tc.in), 2) != DefaultUpperSizeBytes {
				t.Error("an unreadable meminfo did not fall back to the default upper bound")
			}
		})
	}
}
