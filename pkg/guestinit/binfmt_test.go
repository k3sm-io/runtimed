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
)

// TestRosettaBinfmtLine pins the registration line field by field. The kernel
// parses it positionally and matches the magic byte for byte, so every field
// here is load-bearing and none may be reformatted.
func TestRosettaBinfmtLine(t *testing.T) {
	t.Parallel()
	reg := RosettaBinfmt()

	t.Run("the line has the kernel's seven colon-delimited fields", func(t *testing.T) {
		t.Parallel()
		// The grammar is :name:type:offset:magic:mask:interpreter:flags, so a
		// leading empty field plus seven values.
		fields := strings.Split(reg.Line, ":")
		if len(fields) != 8 {
			t.Fatalf("line has %d colon-delimited fields, want 8:\n%s", len(fields), reg.Line)
		}
		want := []string{
			"", RosettaBinfmtName, "M", "", rosettaMagic, rosettaMask,
			RosettaInterpreter, RosettaBinfmtFlags,
		}
		for i := range want {
			if fields[i] != want[i] {
				t.Errorf("field %d = %q, want %q", i, fields[i], want[i])
			}
		}
	})

	t.Run("the magic and mask select ELF64 little-endian x86-64", func(t *testing.T) {
		t.Parallel()
		magic, mask := decodeEscaped(t, rosettaMagic), decodeEscaped(t, rosettaMask)
		if len(magic) != len(mask) {
			t.Fatalf("magic decodes to %d bytes and mask to %d; the kernel requires equal lengths",
				len(magic), len(mask))
		}
		if len(magic) != 20 {
			t.Fatalf("magic decodes to %d bytes, want the 20-byte ELF header prefix", len(magic))
		}
		want := map[int]struct {
			what string
			b    byte
		}{
			0:  {"ELF magic byte 0", 0x7f},
			1:  {"'E'", 'E'},
			2:  {"'L'", 'L'},
			3:  {"'F'", 'F'},
			4:  {"EI_CLASS = ELFCLASS64", 2},
			5:  {"EI_DATA = ELFDATA2LSB", 1},
			6:  {"EI_VERSION = EV_CURRENT", 1},
			16: {"e_type = ET_EXEC", 2},
			18: {"e_machine = EM_X86_64 low byte", 0x3e},
		}
		for off, w := range want {
			if magic[off] != w.b {
				t.Errorf("magic[%d] (%s) = %#x, want %#x", off, w.what, magic[off], w.b)
			}
		}
		// The mask must let a PIE through: ET_DYN (3) and ET_EXEC (2) have to
		// compare equal after masking, which is what clearing bit 0 of byte 16
		// does. An image whose entrypoint is a PIE is the common case.
		if mask[16] != 0xfe {
			t.Fatalf("mask[16] = %#x, want 0xfe so ET_DYN matches alongside ET_EXEC", mask[16])
		}
		if magic[16]&mask[16] != 3&mask[16] {
			t.Error("a PIE (ET_DYN) does not match the registration")
		}
		// EI_OSABI legitimately varies between images (SYSV, GNU, ...) and is
		// masked off entirely, or a glibc-built binary and a musl-built one
		// would not both match.
		if mask[7] != 0 {
			t.Errorf("mask[7] = %#x, want 0 (EI_OSABI varies per image)", mask[7])
		}
		if mask[0] != 0xff || mask[1] != 0xff || mask[2] != 0xff || mask[3] != 0xff {
			t.Errorf("mask[0:4] = % #x, want the ELF magic matched exactly", mask[0:4])
		}
	})

	t.Run("every flag letter is present", func(t *testing.T) {
		t.Parallel()
		// P preserves argv[0] (busybox dispatches on it), O hands the
		// interpreter an open fd (the container is chrooted, so a path would
		// not resolve), C takes credentials from the target binary, and F
		// pins the interpreter at registration so guest root cannot swap it.
		for _, flag := range []string{"P", "O", "C", "F"} {
			if !strings.Contains(RosettaBinfmtFlags, flag) {
				t.Errorf("flags %q dropped %q", RosettaBinfmtFlags, flag)
			}
		}
		if RosettaBinfmtFlags != "POCF" {
			t.Fatalf("flags = %q, want POCF", RosettaBinfmtFlags)
		}
	})

	t.Run("the interpreter share is mounted read-only before registration", func(t *testing.T) {
		t.Parallel()
		if reg.ShareMount.Target != RosettaMountPoint || reg.ShareMount.FSType != "virtiofs" {
			t.Errorf("share mount = %+v, want a virtiofs at %s", reg.ShareMount, RosettaMountPoint)
		}
		if !hasOption(reg.ShareMount.Options, OptionReadOnly) {
			t.Error("the Rosetta share is not mounted read-only")
		}
		if !strings.HasPrefix(RosettaInterpreter, RosettaMountPoint+"/") {
			t.Errorf("interpreter %q does not live in the share the plan mounts", RosettaInterpreter)
		}
		if reg.RegisterPath != BinfmtRegisterPath ||
			!strings.HasPrefix(BinfmtRegisterPath, BinfmtMiscMountPoint+"/") {
			t.Errorf("register path %q is not inside the binfmt_misc mount", reg.RegisterPath)
		}
	})

	t.Run("binfmt_misc is in the pseudo mount set the registration needs", func(t *testing.T) {
		t.Parallel()
		if _, ok := findMount(PseudoMounts(), BinfmtMiscMountPoint); !ok {
			t.Fatalf("no pseudo mount at %s; the registration write would fail with ENOENT", BinfmtMiscMountPoint)
		}
	})
}

// decodeEscaped turns a binfmt_misc \xNN escape string into the bytes the
// kernel will match against. The registration is written as escapes, so the
// test has to decode it to say anything about the header it selects.
func decodeEscaped(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); {
		if s[i] == '\\' {
			if i+3 >= len(s) || s[i+1] != 'x' {
				t.Fatalf("malformed escape at offset %d in %q", i, s)
			}
			var b byte
			if _, err := fmt.Sscanf(s[i+2:i+4], "%02x", &b); err != nil {
				t.Fatalf("malformed hex escape at offset %d in %q: %v", i, s, err)
			}
			out = append(out, b)
			i += 4
			continue
		}
		out = append(out, s[i])
		i++
	}
	return out
}
