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
	"fmt"
	"regexp"
	"strings"
)

// RequiredSymbols returns the C entry points the helper links, without the
// Mach-O leading underscore. It returns a fresh slice on every call.
func RequiredSymbols() []string {
	return []string{
		"wasmtime_component_linker_add_wasip2",
		"wasmtime_component_linker_add_wasi_http",
	}
}

// RequiredFeatures returns the conf.h feature defines the archive must have
// been built with: WASI (preview 1 and 2), wasi:http, and the component model
// the component linker belongs to. It returns a fresh slice on every call.
func RequiredFeatures() []string {
	return []string{
		"WASMTIME_FEATURE_WASI",
		"WASMTIME_FEATURE_WASI_HTTP",
		"WASMTIME_FEATURE_COMPONENT_MODEL",
	}
}

// MaxMinOSMajor is the newest macOS major an object may require. The release
// must run on macOS 26, so an object built for macOS 27 or later fails.
const MaxMinOSMajor = 26

// PlatformMacOS is the Mach-O LC_BUILD_VERSION platform value for macOS
// (PLATFORM_MACOS).
const PlatformMacOS uint32 = 1

// The named canary failures. Every Failure wraps exactly one of them.
var (
	ErrMissingSymbol  = errors.New("canary: required symbol not defined")
	ErrMissingFeature = errors.New("canary: required conf.h feature not defined")
	ErrMinOSTooNew    = errors.New("canary: minimum macOS newer than supported")
	ErrNoBuildVersion = errors.New("canary: no macOS build-version load command")
	ErrBadLoadCommand = errors.New("canary: unknown build-version load command")
)

// LoadCommand names the Mach-O load command a minimum OS version came from.
type LoadCommand string

const (
	// LCBuildVersion is LC_BUILD_VERSION (its minos field).
	LCBuildVersion LoadCommand = "LC_BUILD_VERSION"
	// LCVersionMinMacOSX is the older LC_VERSION_MIN_MACOSX (its version
	// field).
	LCVersionMinMacOSX LoadCommand = "LC_VERSION_MIN_MACOSX"
)

// MachOVersion is a Mach-O X.Y.Z version.
type MachOVersion struct {
	Major, Minor, Patch uint32
}

// DecodeMachOVersion decodes the packed xxxx.yy.zz nibble encoding Mach-O uses
// for minos and LC_VERSION_MIN_* versions.
func DecodeMachOVersion(v uint32) MachOVersion {
	return MachOVersion{Major: v >> 16, Minor: (v >> 8) & 0xff, Patch: v & 0xff}
}

// String formats v as X.Y.Z.
func (v MachOVersion) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// BuildVersion is one minimum-OS record of a Mach-O object.
type BuildVersion struct {
	Command LoadCommand
	// Platform is the LC_BUILD_VERSION platform (PlatformMacOS for macOS). An
	// LC_VERSION_MIN_MACOSX record is macOS by definition; its Platform is
	// ignored.
	Platform uint32
	MinOS    MachOVersion
}

func (r BuildVersion) macOS() bool {
	return r.Command == LCVersionMinMacOSX || r.Platform == PlatformMacOS
}

// ObjectBuildVersions is every minimum-OS record of one Mach-O object: an
// archive member, or a linked binary.
type ObjectBuildVersions struct {
	// Object names the member or binary, for the failure message.
	Object string
	// Records are its LC_BUILD_VERSION and LC_VERSION_MIN_MACOSX commands.
	Records []BuildVersion
}

// Input is everything the canary decides over.
type Input struct {
	// NM is the output of `nm -gU` over the archive (BSD format, member
	// headers included).
	NM string
	// ConfH is the text of the archive's wasmtime/conf.h.
	ConfH string
	// Objects are the build-version records of every archive member and of
	// the linked helper binary.
	Objects []ObjectBuildVersions
}

// Failure is one named canary failure. errors.Is matches its sentinel.
type Failure struct {
	Err    error
	Detail string
}

func (f Failure) Error() string { return f.Err.Error() + ": " + f.Detail }

// Unwrap returns the sentinel.
func (f Failure) Unwrap() error { return f.Err }

// Check returns every failure of in, or nil when the canary passes. A pass is
// necessary, not sufficient (see the package comment).
func Check(in Input) []Failure {
	var out []Failure
	out = append(out, CheckSymbols(in.NM)...)
	out = append(out, CheckFeatures(in.ConfH)...)
	out = append(out, CheckMinOS(in.Objects)...)
	return out
}

// CheckSymbols fails for each RequiredSymbols entry that `nm -gU`
// output does not list as a defined external text symbol (type T).
func CheckSymbols(nm string) []Failure {
	defined := map[string]bool{}
	for _, line := range strings.Split(nm, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasSuffix(line, ":") {
			continue // blank, or an "archive(member.o):" header
		}
		typ, name := f[len(f)-2], f[len(f)-1]
		if typ != "T" {
			continue
		}
		defined[strings.TrimPrefix(name, "_")] = true
	}
	var out []Failure
	for _, s := range RequiredSymbols() {
		if !defined[s] {
			out = append(out, Failure{Err: ErrMissingSymbol, Detail: s})
		}
	}
	return out
}

var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`//[^\n]*`)
)

// CheckFeatures fails for each RequiredFeatures entry conf.h does
// not #define. A define inside a comment (the "/* #undef X */" form conf.h uses
// for an absent feature) does not count, nor does "#define X 0".
func CheckFeatures(confH string) []Failure {
	text := lineComment.ReplaceAllString(blockComment.ReplaceAllString(confH, " "), "")
	defined := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "#")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 || f[0] != "define" {
			continue
		}
		if len(f) >= 3 && f[2] == "0" {
			continue
		}
		defined[f[1]] = true
	}
	var out []Failure
	for _, d := range RequiredFeatures() {
		if !defined[d] {
			out = append(out, Failure{Err: ErrMissingFeature, Detail: d})
		}
	}
	return out
}

// CheckMinOS fails for an object with no macOS build-version record, a record
// of an unknown load command, or a macOS record whose minimum major exceeds
// MaxMinOSMajor (26.x passes, 27.0 fails). The ceiling is a macOS one: a
// record for another platform is not held to it, but it does not count as the
// object's macOS record either. An empty object list fails: there is nothing
// to vouch for.
func CheckMinOS(objects []ObjectBuildVersions) []Failure {
	if len(objects) == 0 {
		return []Failure{{Err: ErrNoBuildVersion, Detail: "no objects"}}
	}
	var out []Failure
	for _, o := range objects {
		sawMacOS := false
		for _, r := range o.Records {
			switch r.Command {
			case LCBuildVersion, LCVersionMinMacOSX:
			default:
				out = append(out, Failure{Err: ErrBadLoadCommand, Detail: fmt.Sprintf("%s: %q", o.Object, r.Command)})
				continue
			}
			if !r.macOS() {
				continue
			}
			sawMacOS = true
			if r.MinOS.Major > MaxMinOSMajor {
				out = append(out, Failure{
					Err:    ErrMinOSTooNew,
					Detail: fmt.Sprintf("%s: %s minos %s > %d", o.Object, r.Command, r.MinOS, MaxMinOSMajor),
				})
			}
		}
		if !sawMacOS {
			out = append(out, Failure{Err: ErrNoBuildVersion, Detail: o.Object})
		}
	}
	return out
}
