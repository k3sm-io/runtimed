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

import "strings"

// The Rosetta share and interpreter.
//
// RosettaShareTag is the virtiofs tag the host attaches the
// VZLinuxRosettaDirectoryShare under. Like SpecShareTag it is a host/guest
// convention rather than a guest/v1 field: GuestSpec.rosetta says only WHETHER
// the share is attached. The host-side VM builder imports these constants.
const (
	RosettaShareTag    = "rosetta"
	RosettaMountPoint  = "/media/rosetta"
	RosettaInterpreter = RosettaMountPoint + "/rosetta"

	// BinfmtMiscMountPoint is where the kernel's binfmt_misc filesystem is
	// mounted, and BinfmtRegisterPath is the file a registration line is
	// written to.
	BinfmtMiscMountPoint = "/proc/sys/fs/binfmt_misc"
	BinfmtRegisterPath   = BinfmtMiscMountPoint + "/register"

	// RosettaBinfmtName is the registration's name, which becomes the control
	// file BinfmtMiscMountPoint/<name>.
	RosettaBinfmtName = "rosetta"
)

// The ELF64 x86-64 magic and mask binfmt_misc matches an executable against.
//
// The magic is the first 20 bytes of an ELF header pinned to: ELFCLASS64
// (\x02), ELFDATA2LSB (\x01), EV_CURRENT (\x01), e_type ET_EXEC/ET_DYN (\x02)
// and e_machine EM_X86_64 (\x3e). The mask zeroes the bytes that legitimately
// vary — the OS/ABI byte, the ABI version, the padding, and the high byte of
// e_type so both ET_EXEC and ET_DYN match. These are the same two strings the
// kernel documentation and qemu's binfmt registration use; they are matched
// byte-for-byte by the kernel, so neither may be "tidied".
const (
	rosettaMagic = `\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00`
	rosettaMask  = `\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`
)

// RosettaBinfmtFlags is the flag string of the registration: P, O, C, F.
//
// every LETTER IS LOAD-BEARING. This is recorded at the site because the
// string looks like an incantation and each letter has been removed by
// somebody "simplifying" a binfmt line before:
//
//	P — preserve-argv[0]. The interpreter receives the original argv[0] rather
//	    than the interpreter's path. Multi-call binaries (busybox, and every
//	    image whose entrypoint dispatches on argv[0]) select their behaviour
//	    from it, so without P an x86-64 busybox becomes a different program.
//
//	O — open-binary. The kernel passes the target binary as an already-OPEN
//	    file descriptor instead of a path for the interpreter to re-open. A
//	    container is chrooted into its own composed rootfs, so the path the
//	    kernel would hand over does not resolve from where the interpreter
//	    runs; without O every translated exec inside a container fails.
//
//	C — credentials from the binary. Permission and credential decisions are
//	    taken from the TARGET binary rather than from the interpreter, which is
//	    what keeps a non-executable or unreadable file from becoming runnable
//	    by virtue of being handed to an interpreter that is. C implies O.
//
//	F — fix-binary. The interpreter is opened at registration time and the
//	    kernel holds that open file for the life of the registration. Two
//	    consequences, both wanted: the interpreter needs no path inside any
//	    container's mount view, and — the security one — a guest root that
//	    later replaces /media/rosetta/rosetta cannot swap the interpreter that
//	    every subsequent x86-64 exec in the guest runs through. Without F the
//	    registration is a path resolved at exec time, i.e. an in-guest
//	    root-to-every-future-exec hook.
const RosettaBinfmtFlags = "POCF"

// BinfmtRegistration is the plan for making linux/amd64 payloads executable in
// the guest: mount the Rosetta share, then write one line to the kernel.
//
// The order is not cosmetic. The F flag means the kernel opens the interpreter
// while it processes the registration write, so the share must already be
// mounted; a registration written first fails with ENOENT.
type BinfmtRegistration struct {
	// Name is the registration's name (the control file under
	// BinfmtMiscMountPoint).
	Name string

	// ShareMount mounts the Rosetta interpreter share.
	ShareMount MountStep

	// RegisterPath is the kernel file Line is written to.
	RegisterPath string

	// Line is the registration line, written verbatim and in one write(2).
	Line string
}

// RosettaBinfmt returns the registration plan for the Rosetta interpreter.
//
// The line's grammar is :name:type:offset:magic:mask:interpreter:flags — type
// M for a magic match, and an empty offset, which means 0 (an ELF header
// starts at byte 0). The empty field is correct, not a missing value.
func RosettaBinfmt() BinfmtRegistration {
	return BinfmtRegistration{
		Name: RosettaBinfmtName,
		ShareMount: MountStep{
			Source: RosettaShareTag, Target: RosettaMountPoint, FSType: "virtiofs",
			Options:     []MountOption{OptionReadOnly, OptionNoSuid, OptionNoDev},
			MkdirTarget: true,
			Why:         "the Rosetta interpreter share; mounted BEFORE registration because the F flag opens it then",
		},
		RegisterPath: BinfmtRegisterPath,
		Line: strings.Join([]string{
			"", RosettaBinfmtName, "M", "", rosettaMagic, rosettaMask,
			RosettaInterpreter, RosettaBinfmtFlags,
		}, ":"),
	}
}
