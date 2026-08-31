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
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE C-LEVEL COUNTERPART OF pkg/vmhost's IMPORT GUARD.
//
// TestVZIsNotReachableFromTheDaemon proves no daemon package IMPORTS
// github.com/Code-Hex/vz. It is blind to this file's subject: vm_darwin.m already
// links Virtualization.framework INTO THE DAEMON (vm_darwin.go's #cgo LDFLAGS), so
// a VM-construction call added there would put the boot path inside the unentitled
// daemon while `go list -deps` stayed perfectly clean — and the failure mode is not
// a compile error but an uncaught NSException → SIGABRT that takes the daemon down
// on every node that is not entitled, which is every node.
//
// So the .m file is guarded by SOURCE SCAN, on two axes:
//
//   - the ENTRY-POINT COUNT, which vm_darwin.m's own header comment calls
//     "load-bearing, not prose" and asks a reviewer to audit the attack surface
//     against. A count that is a sentence is a count that goes stale; this test
//     makes the sentence executable, in BOTH files, against the actual
//     declarations and definitions.
//   - the FORBIDDEN SELECTORS, the construction/boot half of
//     Virtualization.framework. Everything the shim is allowed to do is a class
//     property read or a Security.framework call; nothing it is allowed to do
//     allocates a VZ object.
//
// Both scans are pure functions over source text so they are table-tested against
// planted violations below — a scanner that has never been shown to go red is a
// scanner nobody has checked.

// forbiddenVZSelectors are the Objective-C messages that CONSTRUCT or DRIVE a
// virtual machine. Each is the entry to a code path that requires
// com.apple.security.virtualization, which this process deliberately does not
// carry: sending one raises an uncaught NSException the @try/@catch in the shim
// does NOT reliably contain (the framework aborts inside its own queue), so the
// daemon dies rather than reporting a capability.
//
// The list is the CONSTRUCTION surface, not every VZ symbol: the shim legitimately
// names VZVirtualMachine (for +isSupported) and VZLinuxRosettaDirectoryShare (for
// +availability), and a blanket "no VZ identifier" rule would ban the four probes
// the file exists for.
var forbiddenVZSelectors = []string{
	"initWithConfiguration:",
	"startWithCompletionHandler:",
	"stopWithCompletionHandler:",
	"requestStopWithError:",
	"resumeWithCompletionHandler:",
	"pauseWithCompletionHandler:",
	"VZVirtualMachineConfiguration",
	"VZLinuxBootLoader",
	"VZVirtioFileSystemDeviceConfiguration",
	"VZVirtioSocketDeviceConfiguration",
	"VZNATNetworkDeviceAttachment",
	"initWithError:",
	"installRosetta",
}

// countWords maps the spelled-out entry-point counts the two files' comments use.
// Spelled out rather than numeric because that is how the comments are written,
// and rewriting them to digits to please a test would be the test dictating the
// prose instead of checking it.
var countWords = map[string]int{
	"ONE": 1, "TWO": 2, "THREE": 3, "FOUR": 4,
	"FIVE": 5, "SIX": 6, "SEVEN": 7, "EIGHT": 8,
}

// statedEntryPointCount extracts the count a file's comment CLAIMS ("the FOUR C
// entry points", "it declares FOUR entry points"). ok is false when no such
// sentence is present, which is itself a failure: the inventory sentence is the
// thing being checked, so its absence is not a pass.
func statedEntryPointCount(src string) (int, bool) {
	flat := strings.Join(strings.Fields(strings.ReplaceAll(src, "//", " ")), " ")
	re := regexp.MustCompile(`\b(ONE|TWO|THREE|FOUR|FIVE|SIX|SEVEN|EIGHT)\b(?:\s+\w+){0,2}\s+entry\s+points?\b`)
	m := re.FindStringSubmatch(flat)
	if m == nil {
		return 0, false
	}
	n, ok := countWords[m[1]]
	return n, ok
}

// entryPointNames returns the k3sm_vz_* C entry points a source file declares or
// defines. It matches the one shape the shim uses — a file-scope `int k3sm_vz_…(`
// — which is exactly what the header declares and the .m defines, so a fifth entry
// point cannot arrive without being counted.
func entryPointNames(src string) []string {
	re := regexp.MustCompile(`(?m)^int\s+(k3sm_vz_[A-Za-z0-9_]+)\s*\(`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// scanForbiddenSelectors returns one finding per forbidden selector present in
// src's CODE, naming the selector and the 1-based line it sits on.
//
// COMMENTS ARE BLANKED FIRST, and that is not a convenience. The shim's whole
// value as a reviewed artifact is that it EXPLAINS what it refuses to do — its
// header names +installRosetta…, -initWithError: and VZVirtualMachineConfiguration
// precisely to record why each is absent. A scanner that fired on that prose would
// force the explanations out of the file to stay green, which would trade the
// documentation for the check that documents nothing.
func scanForbiddenSelectors(src string) []string {
	code := stripCComments(src)
	var out []string
	for i, line := range strings.Split(code, "\n") {
		for _, sel := range forbiddenVZSelectors {
			if strings.Contains(line, sel) {
				out = append(out, fmt.Sprintf("line %d: %s", i+1, sel))
			}
		}
	}
	return out
}

// stripCComments blanks C/Obj-C comments while PRESERVING LINE STRUCTURE, so a
// finding's reported line number is the line in the real file. Both forms are
// handled (`//` to end of line, `/* */` across lines); a `//` inside a string
// literal would over-blank, which fails toward silence on a line that a selector
// could hide in — acceptable only because the paired entry-point inventory above
// independently bounds what this file may contain at all.
func stripCComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	const (
		codeState = iota
		lineComment
		blockComment
	)
	state := codeState
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case codeState:
			if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				state = lineComment
				b.WriteString("  ")
				i++
				continue
			}
			if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				state = blockComment
				b.WriteString("  ")
				i++
				continue
			}
			b.WriteByte(c)
		case lineComment:
			if c == '\n' {
				state = codeState
				b.WriteByte(c)
				continue
			}
			b.WriteByte(' ')
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = codeState
				b.WriteString("  ")
				i++
				continue
			}
			if c == '\n' {
				b.WriteByte(c)
				continue
			}
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// TestVMShimEntryPointInventory asserts the .m and .h agree with each other AND
// with their own stated count. The three-way agreement is the point: a new entry
// point added to the .m alone is caught by the .h comparison, and one added to
// both while the prose stays at FOUR is caught by the stated count — which is the
// number a reviewer actually reads.
func TestVMShimEntryPointInventory(t *testing.T) {
	t.Parallel()
	m := mustReadShim(t, "vm_darwin.m")
	h := mustReadShim(t, "vm_darwin.h")

	defined := entryPointNames(m)
	declared := entryPointNames(h)
	if len(defined) == 0 {
		t.Fatal("vm_darwin.m defines no k3sm_vz_* entry point; either the shim was gutted or this scan no longer matches its shape")
	}
	if len(defined) != len(declared) {
		t.Errorf("vm_darwin.m defines %d entry points %v but vm_darwin.h declares %d %v; the header is the audited INVENTORY and must list exactly what the shim implements",
			len(defined), defined, len(declared), declared)
	}
	for _, name := range defined {
		if !contains(declared, name) {
			t.Errorf("vm_darwin.m defines %s, which vm_darwin.h does not declare", name)
		}
	}

	for _, f := range []struct {
		name string
		src  string
	}{{"vm_darwin.m", m}, {"vm_darwin.h", h}} {
		stated, ok := statedEntryPointCount(f.src)
		if !ok {
			t.Errorf("%s carries no \"<COUNT> entry points\" sentence; that sentence IS the audited inventory (see this file's doc), so its absence is a failure, not a pass", f.name)
			continue
		}
		if stated != len(defined) {
			t.Errorf("%s says %d entry points but the shim has %d %v; bump the count in BOTH vm_darwin.m and vm_darwin.h — a stale count is how a fifth one arrives unreviewed",
				f.name, stated, len(defined), defined)
		}
	}
}

// TestVMShimHasNoVMConstruction asserts the shim contains no VM-construction or
// VM-driving selector. It is the assertion that keeps vm_darwin.m a PROBE file:
// the daemon links Virtualization.framework, so the only thing standing between it
// and a SIGABRT on an unentitled host is that nothing here ever builds a machine.
func TestVMShimHasNoVMConstruction(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"vm_darwin.m", "vm_darwin.h"} {
		src := mustReadShim(t, name)
		if findings := scanForbiddenSelectors(src); len(findings) > 0 {
			t.Errorf("%s reaches Virtualization.framework's CONSTRUCTION surface: %s.\n"+
				"The daemon is deliberately unentitled, so constructing a VZ object here raises an uncaught NSException -> SIGABRT on every node. "+
				"The machine is built by the separately-entitled k3sm-vmhost helper (pkg/vmhost); move the code there.",
				name, strings.Join(findings, "; "))
		}
	}
}

// TestVMShimScannersGoRed is the NON-VACUITY proof for both scanners above. The
// real files pass by construction, so a scan that could never fail would be
// indistinguishable from one that always passes; these planted sources are the
// evidence that a violation is actually detected.
func TestVMShimScannersGoRed(t *testing.T) {
	t.Parallel()

	t.Run("a planted construction selector is found", func(t *testing.T) {
		planted := "int k3sm_vz_boot(void) {\n\tVZVirtualMachine *vm = [[VZVirtualMachine alloc] initWithConfiguration:cfg];\n\t[vm startWithCompletionHandler:^(NSError *e){}];\n\treturn 0;\n}\n"
		findings := scanForbiddenSelectors(planted)
		if len(findings) < 2 {
			t.Fatalf("scanForbiddenSelectors found %d findings %v in a source that constructs and starts a VM; want at least 2", len(findings), findings)
		}
	})

	t.Run("a clean source is not flagged", func(t *testing.T) {
		clean := "int k3sm_vz_supported(void) {\n\treturn [VZVirtualMachine isSupported] ? 1 : 0;\n}\n"
		if findings := scanForbiddenSelectors(clean); len(findings) != 0 {
			t.Errorf("scanForbiddenSelectors flagged a pure +isSupported probe: %v; the four real probes must stay legal or the scan bans the file it guards", findings)
		}
	})

	t.Run("a fifth entry point desyncs the stated count", func(t *testing.T) {
		planted := "// it declares FOUR entry points\nint k3sm_vz_a(void);\nint k3sm_vz_b(void);\nint k3sm_vz_c(void);\nint k3sm_vz_d(void);\nint k3sm_vz_e(void);\n"
		stated, ok := statedEntryPointCount(planted)
		if !ok {
			t.Fatal("statedEntryPointCount did not read the planted sentence")
		}
		if got := len(entryPointNames(planted)); got == stated {
			t.Fatalf("entry-point count %d equals the stated %d on a source with a smuggled fifth entry point; the count check is vacuous", got, stated)
		}
	})

	t.Run("a selector named only in a comment is not a violation", func(t *testing.T) {
		documented := "// deliberately NOT granted: -initWithError:, which CONSTRUCTS a share.\n/* nor [vm startWithCompletionHandler:] */\nint k3sm_vz_supported(void) { return 0; }\n"
		if findings := scanForbiddenSelectors(documented); len(findings) != 0 {
			t.Errorf("scanForbiddenSelectors flagged prose that explains an absence: %v", findings)
		}
	})

	t.Run("a selector on the same line as a trailing comment is still found", func(t *testing.T) {
		mixed := "\n\n[vm startWithCompletionHandler:^{}]; // boot it\n"
		findings := scanForbiddenSelectors(mixed)
		if len(findings) != 1 || !strings.HasPrefix(findings[0], "line 3:") {
			t.Errorf("findings = %v; want exactly one on line 3 (comment blanking must preserve line numbers and must not hide code)", findings)
		}
	})

	t.Run("a missing inventory sentence is reported as absent", func(t *testing.T) {
		if _, ok := statedEntryPointCount("int k3sm_vz_a(void);\n"); ok {
			t.Error("statedEntryPointCount reported a count for a source with no inventory sentence; absence must be distinguishable from agreement")
		}
	})
}

// mustReadShim reads one of the cgo shim sources. They are read from disk rather
// than embedded so the scan sees the file a reviewer sees, including on the
// CGO_ENABLED=0 lane where the shim does not compile at all — which is precisely a
// lane where a bad edit would otherwise go unnoticed.
func mustReadShim(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
