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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fixture is an on-disk node layout: two pod dirs (ours and a sibling), our
// rootfs holding a module, and one persistent volume under a storage root.
type fixture struct {
	base, podDir, sibling, rootfs, module, storage, claimRoot, data string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	f := fixture{
		base:    base,
		podDir:  filepath.Join(base, "pods", "a"),
		sibling: filepath.Join(base, "pods", "b"),
		storage: filepath.Join(base, "storage"),
	}
	f.rootfs = filepath.Join(f.podDir, "rootfs")
	f.module = filepath.Join(f.rootfs, "app", "main.wasm")
	f.claimRoot = filepath.Join(f.storage, "ns")
	f.data = filepath.Join(f.claimRoot, "claim")
	for _, d := range []string{filepath.Dir(f.module), f.data, filepath.Join(f.sibling, "rootfs", "app")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.module, []byte("\x00asm\x01\x00\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) bounds() Bounds { return Bounds{PodDir: f.podDir, VolumeRoot: f.storage} }

func (f fixture) input() BuildInput {
	return BuildInput{
		Rootfs:           f.rootfs,
		Module:           f.module,
		Volumes:          []VolumeMount{{GuestPath: "/data", HostPath: f.data, Root: f.claimRoot}},
		MemoryLimitBytes: 128 << 20,
		Argv:             []string{"main.wasm", "--serve", "x"},
		Workdir:          "/app",
		Env:              []string{"PATH=/bin", "EMPTY=", "dotted.name-1=a=b"},
	}
}

func (f fixture) spec(t *testing.T) LaunchSpec {
	t.Helper()
	v, err := BuildLaunchSpec(f.bounds(), f.input())
	if err != nil {
		t.Fatalf("BuildLaunchSpec: %v", err)
	}
	return v.Spec()
}

func TestBuildLaunchSpecOrdersPreopensAndRoundTrips(t *testing.T) {
	f := newFixture(t)
	in := f.input()
	in.Workdir = ""
	v, err := BuildLaunchSpec(f.bounds(), in)
	if err != nil {
		t.Fatalf("BuildLaunchSpec: %v", err)
	}
	want := []Preopen{
		{Kind: PreopenRootfs, GuestPath: "/", HostPath: f.rootfs},
		{Kind: PreopenVolume, GuestPath: "/data", HostPath: f.data, Root: f.claimRoot},
	}
	if got := v.Preopens(); !reflect.DeepEqual(got, want) {
		t.Fatalf("preopens = %+v, want %+v", got, want)
	}
	if v.Workdir() != "/" {
		t.Fatalf("empty workdir defaulted to %q, want /", v.Workdir())
	}

	// The accessors hand out copies: mutating one cannot reach the Validated.
	v.Argv()[0] = "evil"
	v.Env()[0] = "evil=1"
	v.Preopens()[0].HostPath = "/"
	if v.Argv()[0] != "main.wasm" || v.Env()[0] != "PATH=/bin" || v.Preopens()[0].HostPath != f.rootfs {
		t.Fatal("a Validated accessor exposed its backing storage")
	}

	path := filepath.Join(f.podDir, "wasmhost.spec.json")
	if err := WriteLaunchSpec(path, v); err != nil {
		t.Fatalf("WriteLaunchSpec: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("spec mode %v, want 0600", fi.Mode().Perm())
	}
	got, err := ReadLaunchSpec(path, Bounds{PodDir: f.podDir, VolumeRoot: f.storage})
	if err != nil {
		t.Fatalf("ReadLaunchSpec: %v", err)
	}
	if got.Bounds() != f.bounds() {
		t.Fatalf("bounds = %+v, want %+v", got.Bounds(), f.bounds())
	}
	if !reflect.DeepEqual(got.Spec(), v.Spec()) {
		t.Fatalf("round trip = %+v, want %+v", got.Spec(), v.Spec())
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f fixture, s *LaunchSpec)
	}{
		{"version zero", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Version = 0 }},
		{"version two", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Version = 2 }},
		{"relative module", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Module = "app/main.wasm" }},
		{"module with NUL", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Module += "\x00" }},
		{"module with dotdot", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Module = f.rootfs + "/app/../app/main.wasm"
		}},
		{"module with dot", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs + "/./app/main.wasm" }},
		{"module with double slash", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs + "//app/main.wasm" }},
		{"module with control char", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs + "/app/m\nain.wasm" }},
		{"module path over bound", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Module = f.rootfs + "/" + strings.Repeat("a", MaxPathBytes)
		}},
		{"module outside rootfs", func(t *testing.T, f fixture, s *LaunchSpec) {
			p := filepath.Join(f.storage, "x.wasm")
			mustWrite(t, p)
			s.Module = p
		}},
		{"module is the rootfs", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs }},
		{"module missing", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs + "/app/gone.wasm" }},
		{"module is a directory", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Module = f.rootfs + "/app" }},
		{"module is a symlink", func(t *testing.T, f fixture, s *LaunchSpec) {
			link := filepath.Join(f.rootfs, "app", "link.wasm")
			mustSymlink(t, f.module, link)
			s.Module = link
		}},
		{"module under a symlinked dir", func(t *testing.T, f fixture, s *LaunchSpec) {
			mustSymlink(t, filepath.Join(f.rootfs, "app"), filepath.Join(f.rootfs, "alias"))
			s.Module = filepath.Join(f.rootfs, "alias", "main.wasm")
		}},
		{"no preopens", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens = nil }},
		{"too many preopens", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			for i := len(s.Preopens); i <= MaxPreopens; i++ {
				p := s.Preopens[1]
				p.GuestPath = "/v" + strings.Repeat("x", i)
				s.Preopens = append(s.Preopens, p)
			}
		}},
		{"volume first", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			s.Preopens[0], s.Preopens[1] = s.Preopens[1], s.Preopens[0]
		}},
		{"rootfs not at slash", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[0].GuestPath = "/root" }},
		{"rootfs with a root", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Preopens[0].Root = f.rootfs }},
		{"second rootfs", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Kind = PreopenRootfs }},
		{"unknown kind", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Kind = "listener" }},
		{"empty kind", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Kind = "" }},
		{"volume at slash", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].GuestPath = "/" }},
		{"relative guest path", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].GuestPath = "data" }},
		{"guest path with dotdot", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].GuestPath = "/data/../etc" }},
		{"duplicate guest path", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			s.Preopens = append(s.Preopens, s.Preopens[1])
		}},
		{"volume root is the filesystem root", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Root = "/" }},
		{"volume root above the bounds", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Preopens[1].Root = f.base }},
		{"volume root above the pod dir", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].Root = filepath.Dir(f.podDir)
			s.Preopens[1].HostPath = filepath.Join(f.sibling, "rootfs")
		}},
		{"volume in a sibling pod's dir", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].Root = f.sibling
			s.Preopens[1].HostPath = filepath.Join(f.sibling, "rootfs")
		}},
		{"rootfs is the filesystem root", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[0].HostPath = "/"
		}},
		{"rootfs outside the bounds", func(t *testing.T, f fixture, s *LaunchSpec) {
			other := filepath.Join(f.base, "elsewhere", "rootfs")
			mustMkdir(t, filepath.Join(other, "app"))
			mustWrite(t, filepath.Join(other, "app", "main.wasm"))
			s.Preopens[0].HostPath = other
			s.Module = filepath.Join(other, "app", "main.wasm")
		}},
		{"rootfs in a sibling pod's dir", func(t *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[0].HostPath = filepath.Join(f.sibling, "rootfs")
			s.Module = filepath.Join(f.sibling, "rootfs", "app", "main.wasm")
			mustWrite(t, s.Module)
		}},
		{"writable volume inside the rootfs", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[0].ReadOnly = true
			s.Preopens[1].Root = f.rootfs
			s.Preopens[1].HostPath = filepath.Join(f.rootfs, "app")
		}},
		{"writable volume containing the rootfs", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[0].ReadOnly = true
			s.Preopens[1].Root = f.podDir
			s.Preopens[1].HostPath = f.podDir
		}},
		{"writable rootfs over a read-only volume inside it", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].Root = f.rootfs
			s.Preopens[1].HostPath = filepath.Join(f.rootfs, "app")
			s.Preopens[1].ReadOnly = true
		}},
		{"two views of one host dir, one writable", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			p := s.Preopens[1]
			p.GuestPath = "/data2"
			p.ReadOnly = true
			s.Preopens = append(s.Preopens, p)
		}},
		{"writable volume nested in a read-only volume", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].ReadOnly = true
			s.Preopens[1].HostPath = f.claimRoot
			p := s.Preopens[1]
			p.GuestPath = "/inner"
			p.HostPath = f.data
			p.ReadOnly = false
			s.Preopens = append(s.Preopens, p)
		}},
		{"env without =", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"NOVALUE"} }},
		{"env with an empty name", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"=x"} }},
		{"env name with a control char", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"A\tB=x"} }},
		{"env name not ASCII", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"Ä=x"} }},
		{"env name with NUL", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"A\x00=x"} }},
		{"env value with NUL", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"A=x\x00y"} }},
		{"env value not UTF-8", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Env = []string{"A=\xff"} }},
		{"too many env entries", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			s.Env = make([]string, MaxEnvEntries+1)
			for i := range s.Env {
				s.Env[i] = "A=1"
			}
		}},
		{"env over the byte bound", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			s.Env = []string{"A=" + strings.Repeat("a", MaxEnvBytes)}
		}},
		{"volume without root", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Root = "" }},
		{"volume relative root", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Preopens[1].Root = "storage" }},
		{"volume outside its root", func(_ *testing.T, f fixture, s *LaunchSpec) { s.Preopens[1].HostPath = f.rootfs }},
		{"volume sibling of its root", func(t *testing.T, f fixture, s *LaunchSpec) {
			sib := f.claimRoot + "2"
			mustMkdir(t, sib)
			s.Preopens[1].HostPath = sib
		}},
		{"volume host path with dotdot", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].HostPath = f.storage + "/ns/../../rootfs"
		}},
		{"volume through a symlinked component", func(t *testing.T, f fixture, s *LaunchSpec) {
			mustSymlink(t, f.sibling, filepath.Join(f.claimRoot, "evil"))
			s.Preopens[1].HostPath = filepath.Join(f.claimRoot, "evil", "rootfs")
		}},
		{"volume root is a symlink", func(t *testing.T, f fixture, s *LaunchSpec) {
			mustSymlink(t, f.sibling, filepath.Join(f.storage, "evilroot"))
			s.Preopens[1].Root = filepath.Join(f.storage, "evilroot")
			s.Preopens[1].HostPath = filepath.Join(f.storage, "evilroot", "rootfs")
		}},
		{"volume leaf is a symlink", func(t *testing.T, f fixture, s *LaunchSpec) {
			mustSymlink(t, f.sibling, filepath.Join(f.claimRoot, "leaf"))
			s.Preopens[1].HostPath = filepath.Join(f.claimRoot, "leaf")
		}},
		{"rootfs under a symlinked pod-dir component", func(t *testing.T, f fixture, s *LaunchSpec) {
			mustSymlink(t, filepath.Join(f.sibling, "rootfs"), filepath.Join(f.podDir, "alias"))
			s.Preopens[0].HostPath = filepath.Join(f.podDir, "alias")
			s.Module = filepath.Join(f.podDir, "alias", "app", "main.wasm")
		}},
		{"volume missing", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[1].HostPath = filepath.Join(f.claimRoot, "gone")
		}},
		{"volume is a file", func(t *testing.T, f fixture, s *LaunchSpec) {
			p := filepath.Join(f.claimRoot, "file")
			mustWrite(t, p)
			s.Preopens[1].HostPath = p
		}},
		{"rootfs is a symlink", func(t *testing.T, f fixture, s *LaunchSpec) {
			link := f.rootfs + "-link"
			mustSymlink(t, f.rootfs, link)
			s.Preopens[0].HostPath = link
			s.Module = link + "/app/main.wasm"
		}},
		{"rootfs missing", func(_ *testing.T, f fixture, s *LaunchSpec) {
			s.Preopens[0].HostPath = f.rootfs + "-gone"
			s.Module = f.rootfs + "-gone/app/main.wasm"
		}},
		{"relative workdir", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Workdir = "app" }},
		{"empty workdir", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Workdir = "" }},
		{"workdir with dotdot", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Workdir = "/app/.." }},
		{"zero memory", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.MemoryLimitBytes = 0 }},
		{"memory over the maximum", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.MemoryLimitBytes = MaxMemoryLimitBytes + 1 }},
		{"empty argv", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Argv = nil }},
		{"too many argv entries", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Argv = make([]string, MaxArgvEntries+1) }},
		{"argv over the byte bound", func(_ *testing.T, _ fixture, s *LaunchSpec) {
			s.Argv = []string{"m", strings.Repeat("a", MaxArgvBytes)}
		}},
		{"argv with NUL", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Argv = []string{"m", "a\x00b"} }},
		{"argv not UTF-8", func(_ *testing.T, _ fixture, s *LaunchSpec) { s.Argv = []string{"m", "\xff"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			s := f.spec(t)
			tc.mutate(t, f, &s)
			v, err := s.Validate(f.bounds())
			t.Log(err)
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("Validate = %v, want ErrInvalidSpec", err)
			}
			if v.Valid() {
				t.Fatal("a refused spec came back Valid")
			}
		})
	}
}

func TestValidateAdmitsBoundaryValues(t *testing.T) {
	f := newFixture(t)
	s := f.spec(t)
	s.MemoryLimitBytes = MaxMemoryLimitBytes
	s.Argv = []string{strings.Repeat("a", MaxArgvBytes)}
	s.Env = []string{"A=" + strings.Repeat("a", MaxEnvBytes-2)}
	s.Preopens[1].HostPath = s.Preopens[1].Root // a volume at its own root
	s.Preopens[1].ReadOnly = true
	// Two read-only views of one host dir do not alias anything writable.
	p := s.Preopens[1]
	p.GuestPath = "/data2"
	s.Preopens = append(s.Preopens, p)
	if _, err := s.Validate(f.bounds()); err != nil {
		t.Fatalf("Validate at the bounds: %v", err)
	}
	// A volume rooted in the pod dir (an emptyDir) is under a bound too.
	s.Preopens[1].Root = f.podDir
	s.Preopens[1].HostPath = filepath.Join(f.podDir, "empty")
	s.Preopens = s.Preopens[:2]
	mustMkdir(t, s.Preopens[1].HostPath)
	if _, err := s.Validate(Bounds{PodDir: f.podDir}); err != nil {
		t.Fatalf("Validate with a pod-dir volume and no volume root: %v", err)
	}
}

func TestValidateRefusesBadBounds(t *testing.T) {
	f := newFixture(t)
	s := f.spec(t)
	for name, b := range map[string]Bounds{
		"zero bounds":             {},
		"pod dir is /":            {PodDir: "/", VolumeRoot: f.storage},
		"relative pod dir":        {PodDir: "pods/a", VolumeRoot: f.storage},
		"pod dir not clean":       {PodDir: f.podDir + "/", VolumeRoot: f.storage},
		"volume root is /":        {PodDir: f.podDir, VolumeRoot: "/"},
		"relative volume root":    {PodDir: f.podDir, VolumeRoot: "storage"},
		"no volume root for a pv": {PodDir: f.podDir},
		"a sibling pod's dir":     {PodDir: f.sibling, VolumeRoot: f.storage},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Validate(b); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("Validate(%+v) = %v, want ErrInvalidSpec", b, err)
			}
		})
	}
}

func TestIsAtOrUnder(t *testing.T) {
	cases := []struct {
		p, dir string
		want   bool
	}{
		{"/a", "/a", true},
		{"/a/b", "/a", true},
		{"/ab", "/a", false},
		{"/b", "/a", false},
		{"/anything", "/", true},
		{"/", "/", true},
		{"/a", "/a/b", false},
	}
	for _, tc := range cases {
		if got := isAtOrUnder(tc.p, tc.dir); got != tc.want {
			t.Errorf("isAtOrUnder(%q, %q) = %v, want %v", tc.p, tc.dir, got, tc.want)
		}
	}
}

// writeSpecFile writes body as a spec file in the pod dir, mode 0600.
func writeSpecFile(t *testing.T, f fixture, body string) string {
	t.Helper()
	p := filepath.Join(f.podDir, "spec.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadLaunchSpecIsStrict(t *testing.T) {
	f := newFixture(t)
	good, err := encodeSpec(f.spec(t))
	if err != nil {
		t.Fatal(err)
	}
	goodJSON := strings.TrimSpace(string(good))
	noPreopens := f.spec(t)
	noPreopens.Preopens = nil
	nullPreopens, err := encodeSpec(noPreopens)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"unknown field", strings.Replace(goodJSON, `{"version":1,`, `{"version":1,"listeners":[8080],`, 1)},
		{"unknown preopen field", strings.Replace(goodJSON, `"kind":"volume",`, `"kind":"volume","port":80,`, 1)},
		{"duplicate key", strings.Replace(goodJSON, `{"version":1,`, `{"version":1,"workdir":"/",`, 1)},
		{"duplicate key in a preopen", strings.Replace(goodJSON, `"kind":"volume",`, `"kind":"volume","readOnly":true,`, 1)},
		{"case-variant key", strings.Replace(goodJSON, `"module":`, `"Module":`, 1)},
		{"case-variant key beside the real one", strings.Replace(goodJSON, `{"version":1,`, `{"version":1,"MODULE":"/x",`, 1)},
		{"case-variant preopen key", strings.Replace(goodJSON, `"hostPath":`, `"HostPath":`, 1)},
		{"object inside argv", strings.Replace(goodJSON, `"argv":[`, `"argv":[{"a":1},`, 1)},
		{"array where a scalar belongs", strings.Replace(goodJSON, `"workdir":"/app"`, `"workdir":["/app"]`, 1)},
		{"trailing garbage", goodJSON + " x"},
		{"trailing second object", goodJSON + goodJSON},
		{"trailing brace", goodJSON + "}"},
		{"wrong version", strings.Replace(goodJSON, `"version":1`, `"version":2`, 1)},
		{"missing version", strings.Replace(goodJSON, `"version":1,`, ``, 1)},
		{"not json", "not json"},
		{"empty", ""},
		{"array", "[]"},
		{"null preopens", string(nullPreopens)},
		{"fails validation", strings.Replace(goodJSON, `"memoryLimitBytes":134217728`, `"memoryLimitBytes":0`, 1)},
		{"oversized", goodJSON + strings.Repeat(" ", maxSpecBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == goodJSON {
				t.Fatal("the mutation did not apply; the case is vacuous")
			}
			_, err := ReadLaunchSpec(writeSpecFile(t, f, tc.body), f.bounds())
			t.Log(err)
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("ReadLaunchSpec = %v, want ErrInvalidSpec", err)
			}
		})
	}
	t.Run("the good body reads", func(t *testing.T) {
		if _, err := ReadLaunchSpec(writeSpecFile(t, f, goodJSON+"\n\n"), f.bounds()); err != nil {
			t.Fatalf("ReadLaunchSpec: %v", err)
		}
	})
	t.Run("the reader's own bounds are what count", func(t *testing.T) {
		p := writeSpecFile(t, f, goodJSON)
		if _, err := ReadLaunchSpec(p, Bounds{PodDir: f.sibling, VolumeRoot: f.storage}); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("ReadLaunchSpec under a sibling's bounds = %v, want ErrInvalidSpec", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := ReadLaunchSpec(filepath.Join(f.podDir, "gone"), f.bounds())
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("ReadLaunchSpec = %v, want ErrNotExist", err)
		}
	})
}

func TestReadLaunchSpecRefusesAnUnsafeFile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f fixture, good string) string
	}{
		{"a symlink to a good spec", func(t *testing.T, f fixture, good string) string {
			target := writeSpecFile(t, f, good)
			link := filepath.Join(f.podDir, "link.json")
			mustSymlink(t, target, link)
			return link
		}},
		{"a group-writable spec", func(t *testing.T, f fixture, good string) string {
			p := writeSpecFile(t, f, good)
			mustChmod(t, p, 0o620)
			return p
		}},
		{"an other-writable spec", func(t *testing.T, f fixture, good string) string {
			p := writeSpecFile(t, f, good)
			mustChmod(t, p, 0o602)
			return p
		}},
		{"a directory", func(t *testing.T, f fixture, _ string) string {
			p := filepath.Join(f.podDir, "dir.json")
			mustMkdir(t, p)
			return p
		}},
		{"a group-writable directory", func(t *testing.T, f fixture, good string) string {
			p := writeSpecFile(t, f, good)
			mustChmod(t, f.podDir, 0o770)
			return p
		}},
		{"an other-writable directory", func(t *testing.T, f fixture, good string) string {
			p := writeSpecFile(t, f, good)
			mustChmod(t, f.podDir, 0o757)
			return p
		}},
		{"a relative path", func(_ *testing.T, _ fixture, _ string) string { return "spec.json" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			good, err := encodeSpec(f.spec(t))
			if err != nil {
				t.Fatal(err)
			}
			_, err = ReadLaunchSpec(tc.setup(t, f, string(good)), f.bounds())
			t.Log(err)
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("ReadLaunchSpec = %v, want ErrInvalidSpec", err)
			}
		})
	}
}

// TestCheckSpecFileRefusesAnotherOwner covers the owner check, which a test
// cannot reach through a real file without root.
func TestCheckSpecFileRefusesAnotherOwner(t *testing.T) {
	f := newFixture(t)
	fi, err := os.Stat(writeSpecFile(t, f, "{}"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSpecFile(fi, os.Geteuid()); err != nil {
		t.Fatalf("checkSpecFile for the owner = %v", err)
	}
	if err := checkSpecFile(fi, os.Geteuid()+1); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("checkSpecFile for another uid = %v, want ErrInvalidSpec", err)
	}
}

// TestKeySchemaMatchesTheStructTags keeps checkKeys' exact key set in step
// with the json tags the struct decode uses.
func TestKeySchemaMatchesTheStructTags(t *testing.T) {
	tags := func(v any) []string {
		var out []string
		ty := reflect.TypeOf(v)
		for i := 0; i < ty.NumField(); i++ {
			name, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
			out = append(out, name)
		}
		slices.Sort(out)
		return out
	}
	keys := func(s *keySchema) []string {
		out := slices.Collect(maps.Keys(s.fields))
		slices.Sort(out)
		return out
	}
	if got, want := keys(specKeys), tags(LaunchSpec{}); !slices.Equal(got, want) {
		t.Errorf("spec keys %v, struct tags %v", got, want)
	}
	if got, want := keys(preopenKey), tags(Preopen{}); !slices.Equal(got, want) {
		t.Errorf("preopen keys %v, struct tags %v", got, want)
	}
}

// TestMaximalSpecFitsTheReadBound pins the justification of maxSpecBytes: the
// largest spec Validate's bounds admit, with every string at its worst JSON
// escaping, still encodes under the bound, so the bound refuses only files
// this package did not write.
func TestMaximalSpecFitsTheReadBound(t *testing.T) {
	// Paths may not carry control characters, so their worst escape is two
	// bytes per byte (a quote or a backslash). argv and env values may: six
	// bytes per byte.
	path := func(c byte) string { return "/" + strings.Repeat(string(c), MaxPathBytes-1) }
	s := LaunchSpec{
		Version:          SpecVersion,
		Module:           path('"'),
		Workdir:          path('\\'),
		MemoryLimitBytes: MaxMemoryLimitBytes,
	}
	for range MaxPreopens {
		s.Preopens = append(s.Preopens, Preopen{
			Kind: PreopenVolume, GuestPath: path('"'), HostPath: path('\\'), Root: path('"'), ReadOnly: true,
		})
	}
	for range MaxArgvEntries {
		s.Argv = append(s.Argv, strings.Repeat("\x01", MaxArgvBytes/MaxArgvEntries))
	}
	for range MaxEnvEntries {
		s.Env = append(s.Env, "A="+strings.Repeat("\x01", MaxEnvBytes/MaxEnvEntries-2))
	}
	raw, err := encodeSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxSpecBytes {
		t.Fatalf("a maximal spec encodes to %d bytes, over the %d-byte read bound", len(raw), maxSpecBytes)
	}
	t.Logf("maximal spec: %d of %d bytes", len(raw), maxSpecBytes)
}

func TestWriteLaunchSpec(t *testing.T) {
	t.Run("refuses the zero Validated", func(t *testing.T) {
		err := WriteLaunchSpec(filepath.Join(t.TempDir(), "spec.json"), Validated{})
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("WriteLaunchSpec = %v, want ErrInvalidSpec", err)
		}
	})
	t.Run("refuses a relative path", func(t *testing.T) {
		f := newFixture(t)
		v, err := BuildLaunchSpec(f.bounds(), f.input())
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteLaunchSpec("spec.json", v); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("WriteLaunchSpec = %v, want ErrInvalidSpec", err)
		}
	})
	for name, mode := range map[string]os.FileMode{"group-writable": 0o770, "other-writable": 0o757} {
		t.Run("refuses a "+name+" directory", func(t *testing.T) {
			f := newFixture(t)
			v, err := BuildLaunchSpec(f.bounds(), f.input())
			if err != nil {
				t.Fatal(err)
			}
			mustChmod(t, f.podDir, mode)
			if err := WriteLaunchSpec(filepath.Join(f.podDir, "spec.json"), v); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("WriteLaunchSpec = %v, want ErrInvalidSpec", err)
			}
		})
	}
	t.Run("replaces a symlink rather than following it", func(t *testing.T) {
		f := newFixture(t)
		v, err := BuildLaunchSpec(f.bounds(), f.input())
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(f.podDir, "target")
		mustWrite(t, target)
		p := filepath.Join(f.podDir, "spec.json")
		mustSymlink(t, target, p)
		if err := WriteLaunchSpec(p, v); err != nil {
			t.Fatalf("WriteLaunchSpec: %v", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "x" {
			t.Fatalf("the symlink target was written: %q", b)
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("spec path is not a regular file after the write: %v %v", fi, err)
		}
	})
}

func TestParseArgs(t *testing.T) {
	for _, want := range []HostArgs{
		{SpecPath: "/var/run/pod/wasmhost.spec.json", PodDir: "/var/run/pod"},
		{SpecPath: "/var/run/pod/wasmhost.spec.json", PodDir: "/var/run/pod", VolumeRoot: "/var/lib/k3sm/storage"},
	} {
		args := want.Args()
		got, err := ParseArgs(args)
		if err != nil || got != want {
			t.Fatalf("ParseArgs(%q) = %+v, %v; want %+v", args, got, err, want)
		}
		slices.Reverse(args)
		if got, err := ParseArgs(args); err != nil || got != want {
			t.Fatalf("ParseArgs(%q) in reverse order = %+v, %v", args, got, err)
		}
		if got.Bounds() != (Bounds{PodDir: want.PodDir, VolumeRoot: want.VolumeRoot}) {
			t.Fatalf("Bounds() = %+v", got.Bounds())
		}
	}
	refused := [][]string{
		nil,
		{},
		{"--spec=/a"},
		{"--pod-dir=/p"},
		{"--spec", "/a"},
		{"--spec=", "--pod-dir=/p"},
		{"--spec=relative", "--pod-dir=/p"},
		{"--spec=/a/../b", "--pod-dir=/p"},
		{"--spec=/a", "--pod-dir=relative"},
		{"--spec=/a", "--pod-dir=/"},
		{"--spec=/a", "--pod-dir=/p/"},
		{"-spec=/a", "--pod-dir=/p"},
		{"--SPEC=/a", "--pod-dir=/p"},
		{"--spec=/a", "--spec=/b"},
		{"--pod-dir=/p", "--pod-dir=/q"},
		{"--spec=/a", "--volume-root=/v"},
		{"--pod-dir=/p", "--volume-root=/v"},
		{"--spec=/a", "--pod-dir=/p", "--volume-root=/v", "--volume-root=/w"},
		{"--spec=/a", "--pod-dir=/p", "--volume-root=/v", "--volume-root=/v"},
		{"--spec=/a", "--pod-dir=/p", "--volume-root=v"},
		{"--spec=/a", "--pod-dir=/p", "--volume-root=/"},
		{"--spec=/a", "--pod-dir=/p", "--volume-root="},
		{"--spec=/a", "--pod-dir=/p", "--volume-root=/v/../w"},
		{"--spec=/a", "--pod-dir=/p", "guest-arg"},
		{"--spec=/a", "--pod-dir=/p", "--"},
		{"--", "--spec=/a"},
		{"--module=/a.wasm", "--pod-dir=/p"},
		{"--spec=/a\x00", "--pod-dir=/p"},
	}
	for _, args := range refused {
		if a, err := ParseArgs(args); !errors.Is(err, ErrUsage) {
			t.Errorf("ParseArgs(%q) = %+v, %v; want ErrUsage", args, a, err)
		}
	}
}

// TestHostArgsVolumeRootGatesPersistentVolumes runs the host's path end to end:
// the daemon writes a spec with a persistent volume, and the host reads it
// with the bounds its own argv carries.
func TestHostArgsVolumeRootGatesPersistentVolumes(t *testing.T) {
	f := newFixture(t)
	v, err := BuildLaunchSpec(f.bounds(), f.input())
	if err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(f.podDir, "wasmhost.spec.json")
	if err := WriteLaunchSpec(spec, v); err != nil {
		t.Fatal(err)
	}
	read := func(a HostArgs) error {
		parsed, err := ParseArgs(a.Args())
		if err != nil {
			return err
		}
		_, err = ReadLaunchSpec(parsed.SpecPath, parsed.Bounds())
		return err
	}
	with := HostArgs{SpecPath: spec, PodDir: f.podDir, VolumeRoot: f.storage}
	if err := read(with); err != nil {
		t.Fatalf("a PV pod with --volume-root: %v", err)
	}
	without := HostArgs{SpecPath: spec, PodDir: f.podDir}
	if err := read(without); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("a PV pod without --volume-root = %v, want ErrInvalidSpec", err)
	}
	elsewhere := HostArgs{SpecPath: spec, PodDir: f.podDir, VolumeRoot: f.sibling}
	if err := read(elsewhere); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("a PV pod with another --volume-root = %v, want ErrInvalidSpec", err)
	}
}

// TestSpecNeverInsideAWritablePreopen pins that a guest can never write its own
// spec: with the rootfs equal to the pod dir, a spec under it is refused by
// both the writer and the reader while the rootfs is writable, and admitted
// when it is read-only.
func TestSpecNeverInsideAWritablePreopen(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("readOnly=%v", readOnly), func(t *testing.T) {
			f := newFixture(t)
			in := f.input()
			in.Rootfs = f.podDir
			in.RootfsReadOnly = readOnly
			v, err := BuildLaunchSpec(f.bounds(), in)
			if err != nil {
				t.Fatal(err)
			}
			spec := filepath.Join(f.podDir, "wasmhost.spec.json")
			werr := WriteLaunchSpec(spec, v)
			raw, err := encodeSpec(v.Spec())
			if err != nil {
				t.Fatal(err)
			}
			_, rerr := ReadLaunchSpec(writeSpecFile(t, f, string(raw)), f.bounds())
			if readOnly {
				if werr != nil || rerr != nil {
					t.Fatalf("read-only rootfs: write %v, read %v; want both admitted", werr, rerr)
				}
				return
			}
			if !errors.Is(werr, ErrInvalidSpec) || !errors.Is(rerr, ErrInvalidSpec) {
				t.Fatalf("writable rootfs: write %v, read %v; want both ErrInvalidSpec", werr, rerr)
			}
		})
	}
	t.Run("a writable volume holding the spec", func(t *testing.T) {
		f := newFixture(t)
		in := f.input()
		emptyDir := filepath.Join(f.podDir, "volumes", "scratch")
		mustMkdir(t, emptyDir)
		in.Volumes = []VolumeMount{{GuestPath: "/scratch", HostPath: emptyDir, Root: emptyDir}}
		v, err := BuildLaunchSpec(f.bounds(), in)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteLaunchSpec(filepath.Join(emptyDir, "spec.json"), v); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("WriteLaunchSpec into a writable volume = %v, want ErrInvalidSpec", err)
		}
	})
}

func mustChmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
