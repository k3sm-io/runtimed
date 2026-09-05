#ifndef K3SM_VM_DARWIN_H
#define K3SM_VM_DARWIN_H

// Safe Virtualization.framework + entitlement probes for the vm sandbox backend,
// plus k3sm_vz_rosetta_availability and k3sm_vz_static_code_entitled. This
// header is the INVENTORY of that surface: it declares FOUR entry
// points and NONE constructs or boots a VM — instantiating a VZVirtualMachine on a
// non-entitled host raises an uncaught Obj-C exception (NSInternalInconsistency) ->
// SIGABRT, which would take down the daemon. All four are wrapped in @try/@catch +
// @autoreleasepool in vm_darwin.m and use only PUBLIC API (Virtualization.framework
// is public, so this is NOT a libsandbox SPI canary case). Adding a fifth means
// bumping the count here AND in vm_darwin.m.

// k3sm_vz_supported returns 1 if +[VZVirtualMachine isSupported] is YES, else 0.
// isSupported is a hardware/OS-capability query that does NOT construct a VM.
int k3sm_vz_supported(void);

// k3sm_vz_has_entitlement returns 1 if THIS process's static code signature
// carries com.apple.security.virtualization == true (read via Security.framework's
// SecCodeCopySigningInformation), else 0. It never touches Virtualization.framework.
int k3sm_vz_has_entitlement(void);

// k3sm_vz_rosetta_availability return values: the RAW 3-valued
// VZLinuxRosettaAvailability enum (values pinned to Apple's, so the mapping is a
// straight switch) plus a distinct QUERY_FAILED sentinel. The three real states are
// kept apart rather than collapsed to a bool because the guest-Rosetta
// RuntimeCondition carries a distinct machine Reason per state — "this Mac cannot
// do Rosetta for Linux at all" and "it can, but the payload is not installed" are
// different operator actions.
enum k3sm_vz_rosetta_state {
	// Query failed: an Obj-C exception, or an enum value Apple added after this
	// shim was written. Fails CLOSED (never reported as available).
	K3SM_VZ_ROSETTA_QUERY_FAILED = -1,
	// VZLinuxRosettaAvailabilityNotSupported — the host cannot do Rosetta for
	// Linux (also the non-arm64 compile lane's answer; see vm_darwin.m).
	K3SM_VZ_ROSETTA_NOT_SUPPORTED = 0,
	// VZLinuxRosettaAvailabilityNotInstalled — supported, payload absent.
	K3SM_VZ_ROSETTA_NOT_INSTALLED = 1,
	// VZLinuxRosettaAvailabilityInstalled — supported AND installed.
	K3SM_VZ_ROSETTA_INSTALLED = 2,
};

// k3sm_vz_rosetta_availability returns the host's Rosetta-for-Linux (GUEST
// translation) availability as one of enum k3sm_vz_rosetta_state. It reads ONLY the
// +[VZLinuxRosettaDirectoryShare availability] CLASS property, which is
// entitlement-free, non-raising, and — unlike -initWithError: — constructs no
// object. It deliberately never calls +installRosetta...: those PROMPT the user,
// which is fatal in a GUI-less root daemon.
int k3sm_vz_rosetta_availability(void);

// k3sm_vz_static_code_entitled returns 1 if the code AT PATH (the k3sm-vmhost
// helper, not this process) has a signature that passes SecStaticCodeCheckValidity
// AND carries com.apple.security.virtualization == true, else 0. It never touches
// Virtualization.framework.
//
// The VALIDITY check is not belt-and-braces: an entitlements plist is readable from
// a binary whose signature is BROKEN (edited after signing, or a bad-architecture
// slice), and macOS would refuse to launch that helper. Reading only the plist would
// therefore label the node vm-capable on a host where every vm pod fails at spawn,
// which is precisely the "a node must not advertise a capability it lacks" rule.
// A path that does not exist, or is not code, is 0 — never an error the caller has
// to interpret.
int k3sm_vz_static_code_entitled(const char *path);

#endif // K3SM_VM_DARWIN_H
