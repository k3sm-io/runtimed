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
