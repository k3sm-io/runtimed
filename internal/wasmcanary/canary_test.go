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

package wasmcanary

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func goodObjects() []ObjectBuildVersions {
	return []ObjectBuildVersions{
		{Object: "libwasmtime.a(wasmtime-a.o)", Records: []BuildVersion{{Command: LCBuildVersion, Platform: PlatformMacOS, MinOS: MachOVersion{11, 0, 0}}}},
		{Object: "libwasmtime.a(old.o)", Records: []BuildVersion{{Command: LCVersionMinMacOSX, MinOS: MachOVersion{10, 12, 0}}}},
		{Object: "k3sm-wasmhost", Records: []BuildVersion{{Command: LCBuildVersion, Platform: PlatformMacOS, MinOS: MachOVersion{26, 4, 1}}}},
	}
}

func goodCanary(t *testing.T) Input {
	return Input{
		NM:      readTestdata(t, "nm-good.txt"),
		ConfH:   readTestdata(t, "conf-good.h"),
		Objects: goodObjects(),
	}
}

func TestCheckPasses(t *testing.T) {
	if f := Check(goodCanary(t)); f != nil {
		t.Fatalf("CheckCanary on the good fixture = %v, want a pass", f)
	}
}

func TestCheckFails(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(in *Input)
		want   error
		detail string
	}{
		{"missing add_wasip2", func(in *Input) {
			in.NM = dropLines(in.NM, "_wasmtime_component_linker_add_wasip2")
		}, ErrMissingSymbol, "wasmtime_component_linker_add_wasip2"},
		{"missing add_wasi_http", func(in *Input) {
			in.NM = dropLines(in.NM, "_wasmtime_component_linker_add_wasi_http")
		}, ErrMissingSymbol, "wasmtime_component_linker_add_wasi_http"},
		{"add_wasip2 only undefined", func(in *Input) {
			in.NM = dropLines(in.NM, "T _wasmtime_component_linker_add_wasip2") + "                 U _wasmtime_component_linker_add_wasip2\n"
		}, ErrMissingSymbol, "wasmtime_component_linker_add_wasip2"},
		{"add_wasip2 only as a prefix of another symbol", func(in *Input) {
			in.NM = strings.ReplaceAll(in.NM, "_add_wasip2\n", "_add_wasip2_extra\n")
		}, ErrMissingSymbol, "wasmtime_component_linker_add_wasip2"},
		{"empty nm", func(in *Input) { in.NM = "" }, ErrMissingSymbol, "wasmtime_component_linker_add_wasip2"},
		{"WASI undefined", func(in *Input) {
			in.ConfH = strings.Replace(in.ConfH, "#define WASMTIME_FEATURE_WASI\n", "/* #undef WASMTIME_FEATURE_WASI */\n", 1)
		}, ErrMissingFeature, "WASMTIME_FEATURE_WASI"},
		{"WASI_HTTP undefined", func(in *Input) {
			in.ConfH = strings.Replace(in.ConfH, "#define WASMTIME_FEATURE_WASI_HTTP\n", "/* #undef WASMTIME_FEATURE_WASI_HTTP */\n", 1)
		}, ErrMissingFeature, "WASMTIME_FEATURE_WASI_HTTP"},
		{"COMPONENT_MODEL commented out", func(in *Input) {
			in.ConfH = strings.Replace(in.ConfH, "#define WASMTIME_FEATURE_COMPONENT_MODEL\n", "// #define WASMTIME_FEATURE_COMPONENT_MODEL\n", 1)
		}, ErrMissingFeature, "WASMTIME_FEATURE_COMPONENT_MODEL"},
		{"WASI_HTTP inside a block comment", func(in *Input) {
			in.ConfH = strings.Replace(in.ConfH, "#define WASMTIME_FEATURE_WASI_HTTP\n", "/*\n#define WASMTIME_FEATURE_WASI_HTTP\n*/\n", 1)
		}, ErrMissingFeature, "WASMTIME_FEATURE_WASI_HTTP"},
		{"WASI defined to 0", func(in *Input) {
			in.ConfH = strings.Replace(in.ConfH, "#define WASMTIME_FEATURE_WASI\n", "#define WASMTIME_FEATURE_WASI 0\n", 1)
		}, ErrMissingFeature, "WASMTIME_FEATURE_WASI"},
		{"archive member minos 27", func(in *Input) {
			in.Objects[0].Records[0].MinOS = MachOVersion{27, 0, 0}
		}, ErrMinOSTooNew, "wasmtime-a.o"},
		{"binary minos 27.1", func(in *Input) {
			in.Objects[2].Records[0].MinOS = MachOVersion{27, 1, 0}
		}, ErrMinOSTooNew, "k3sm-wasmhost"},
		{"LC_VERSION_MIN_MACOSX 27", func(in *Input) {
			in.Objects[1].Records[0].MinOS = DecodeMachOVersion(0x001b0000)
		}, ErrMinOSTooNew, "LC_VERSION_MIN_MACOSX"},
		{"an object with no record", func(in *Input) {
			in.Objects[1].Records = nil
		}, ErrNoBuildVersion, "old.o"},
		{"no objects at all", func(in *Input) { in.Objects = nil }, ErrNoBuildVersion, "no objects"},
		{"a member with only a non-macOS record", func(in *Input) {
			in.Objects[0].Records[0].Platform = 2 // PLATFORM_IOS
		}, ErrNoBuildVersion, "wasmtime-a.o"},
		{"a macOS 27 record beside a non-macOS one", func(in *Input) {
			in.Objects[0].Records = append(in.Objects[0].Records, BuildVersion{Command: LCBuildVersion, Platform: 2, MinOS: MachOVersion{11, 0, 0}})
			in.Objects[0].Records[0].MinOS = MachOVersion{27, 0, 0}
		}, ErrMinOSTooNew, "wasmtime-a.o"},
		{"an unknown load command", func(in *Input) {
			in.Objects[0].Records[0].Command = "LC_VERSION_MIN_IPHONEOS"
		}, ErrBadLoadCommand, "LC_VERSION_MIN_IPHONEOS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := goodCanary(t)
			tc.mutate(&in)
			fails := Check(in)
			if len(fails) == 0 {
				t.Fatal("CheckCanary passed a broken input")
			}
			for _, f := range fails {
				if errors.Is(f, tc.want) && strings.Contains(f.Error(), tc.detail) {
					return
				}
			}
			t.Fatalf("CheckCanary = %v; want a %v naming %q", fails, tc.want, tc.detail)
		})
	}
}

func TestMinOSBoundary(t *testing.T) {
	cases := []struct {
		v    MachOVersion
		pass bool
	}{
		{MachOVersion{11, 0, 0}, true},
		{MachOVersion{26, 0, 0}, true},
		{MachOVersion{26, 99, 99}, true},
		{MachOVersion{27, 0, 0}, false},
		{MachOVersion{100, 0, 0}, false},
	}
	for _, tc := range cases {
		for _, cmd := range []LoadCommand{LCBuildVersion, LCVersionMinMacOSX} {
			got := CheckMinOS([]ObjectBuildVersions{{Object: "o", Records: []BuildVersion{{Command: cmd, Platform: PlatformMacOS, MinOS: tc.v}}}})
			if (got == nil) != tc.pass {
				t.Errorf("%s minos %s: failures %v, want pass=%v", cmd, tc.v, got, tc.pass)
			}
		}
	}
}

// TestNonMacOSRecordIsNotHeldToTheCeiling pins that the macOS ceiling applies
// only to platform macOS: an iOS 27 record beside a good macOS one passes.
func TestNonMacOSRecordIsNotHeldToTheCeiling(t *testing.T) {
	got := CheckMinOS([]ObjectBuildVersions{{Object: "o", Records: []BuildVersion{
		{Command: LCBuildVersion, Platform: PlatformMacOS, MinOS: MachOVersion{11, 0, 0}},
		{Command: LCBuildVersion, Platform: 2, MinOS: MachOVersion{27, 0, 0}},
	}}})
	if got != nil {
		t.Fatalf("CheckMinOS = %v, want a pass", got)
	}
}

// TestRequiredListsAreFresh pins that a caller mutating a returned list cannot
// weaken the next check.
func TestRequiredListsAreFresh(t *testing.T) {
	RequiredSymbols()[0] = "x"
	RequiredFeatures()[0] = "x"
	if RequiredSymbols()[0] == "x" || RequiredFeatures()[0] == "x" {
		t.Fatal("a required list is shared mutable state")
	}
}

func TestDecodeMachOVersion(t *testing.T) {
	cases := map[uint32]MachOVersion{
		0x000b0000: {11, 0, 0},
		0x001a0401: {26, 4, 1},
		0x001b0000: {27, 0, 0},
		0x000a0c00: {10, 12, 0},
	}
	for raw, want := range cases {
		if got := DecodeMachOVersion(raw); got != want {
			t.Errorf("DecodeMachOVersion(%#x) = %s, want %s", raw, got, want)
		}
	}
}

func dropLines(s, substr string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
