//go:build darwin && cgo

// Obj-C shim for the vm sandbox backend's SAFE availability probes (M5.1). It is
// isolated here so the only Objective-C / Virtualization.framework surface the
// rest of runtimed sees is the two C entry points in vm_darwin.h. NEITHER entry
// point constructs or boots a VZVirtualMachine — doing so without the
// com.apple.security.virtualization entitlement raises an uncaught NSException →
// SIGABRT, so both are additionally wrapped in @try/@catch and @autoreleasepool.
//
// The live VM boot (a VZVirtualMachineConfiguration on a per-VM serial dispatch
// queue, behind an opaque handle) is the LAB-GATED remainder and is NOT here.

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>

#include "vm_darwin.h"

// k3sm_vz_supported — SAFE host-capability probe. +[VZVirtualMachine isSupported]
// queries hardware/OS support WITHOUT constructing a VM, so it cannot raise the
// entitlement exception; still wrapped defensively.
int k3sm_vz_supported(void) {
	@autoreleasepool {
		@try {
			return [VZVirtualMachine isSupported] ? 1 : 0;
		} @catch (NSException *e) {
			return 0;
		}
	}
}

// k3sm_vz_has_entitlement — reads THIS process's static code-signing entitlements
// via Security.framework (all public API) and reports whether
// com.apple.security.virtualization is present and true. It never touches
// Virtualization.framework, so it cannot trigger the VM-construction exception.
int k3sm_vz_has_entitlement(void) {
	@autoreleasepool {
		@try {
			SecCodeRef self = NULL;
			if (SecCodeCopySelf(kSecCSDefaultFlags, &self) != errSecSuccess || self == NULL) {
				return 0;
			}
			CFDictionaryRef info = NULL;
			OSStatus st = SecCodeCopySigningInformation(
				(SecStaticCodeRef)self, kSecCSRequirementInformation, &info);
			CFRelease(self);
			if (st != errSecSuccess || info == NULL) {
				return 0;
			}
			int ok = 0;
			CFDictionaryRef ents =
				(CFDictionaryRef)CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
			if (ents != NULL && CFGetTypeID(ents) == CFDictionaryGetTypeID()) {
				CFBooleanRef v = (CFBooleanRef)CFDictionaryGetValue(
					ents, CFSTR("com.apple.security.virtualization"));
				if (v != NULL && CFGetTypeID(v) == CFBooleanGetTypeID() && CFBooleanGetValue(v)) {
					ok = 1;
				}
			}
			CFRelease(info);
			return ok;
		} @catch (NSException *e) {
			return 0;
		}
	}
}

// k3sm_vz_rosetta_availability — SAFE, ENTITLEMENT-FREE guest-Rosetta capability
// probe (B103). It reads the +[VZLinuxRosettaDirectoryShare availability] CLASS
// property and nothing else:
//
//   - it is NOT -initWithError:, which CONSTRUCTS a directory share;
//   - it is NOT +installRosettaWithCompletionHandler: / +installRosettaIfNeeded:,
//     which the SDK header documents as PROMPTING THE USER — fatal in a GUI-less
//     daemon;
//   - it needs no entitlement and links no framework beyond the three already in
//     vm_darwin.go's #cgo LDFLAGS (empirically: Installed returned from an
//     ad-hoc-signed, zero-entitlement arm64 binary with no NSException).
//
// The ARCH GUARD is required, not defensive: the SDK wraps the WHOLE of
// VZLinuxRosettaDirectoryShare.h in #ifdef __arm64__, so a direct class reference
// fails to COMPILE at -arch x86_64 ("unknown receiver"). Returning NOT_SUPPORTED
// there is also semantically right — Rosetta for Linux is Apple-Silicon-only.
int k3sm_vz_rosetta_availability(void) {
#ifdef __arm64__
	@autoreleasepool {
		@try {
			switch ([VZLinuxRosettaDirectoryShare availability]) {
			case VZLinuxRosettaAvailabilityNotSupported:
				return K3SM_VZ_ROSETTA_NOT_SUPPORTED;
			case VZLinuxRosettaAvailabilityNotInstalled:
				return K3SM_VZ_ROSETTA_NOT_INSTALLED;
			case VZLinuxRosettaAvailabilityInstalled:
				return K3SM_VZ_ROSETTA_INSTALLED;
			}
			// An enum value Apple added after this shim was written: fail closed.
			return K3SM_VZ_ROSETTA_QUERY_FAILED;
		} @catch (NSException *e) {
			return K3SM_VZ_ROSETTA_QUERY_FAILED;
		}
	}
#else
	return K3SM_VZ_ROSETTA_NOT_SUPPORTED;
#endif
}
