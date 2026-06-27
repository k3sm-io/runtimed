#ifndef K3SM_VM_DARWIN_H
#define K3SM_VM_DARWIN_H

// Safe Virtualization.framework + entitlement probes for the vm sandbox backend
// (M5.1). NEITHER constructs nor boots a VM: instantiating a VZVirtualMachine on a
// non-entitled host raises an uncaught Obj-C exception (NSInternalInconsistency) →
// SIGABRT, which would take down the daemon. Both probes are wrapped in
// @try/@catch + @autoreleasepool in vm_darwin.m and use only PUBLIC API
// (Virtualization.framework is public, so this is NOT a libsandbox SPI canary case).

// k3sm_vz_supported returns 1 if +[VZVirtualMachine isSupported] is YES, else 0.
// isSupported is a hardware/OS-capability query that does NOT construct a VM.
int k3sm_vz_supported(void);

// k3sm_vz_has_entitlement returns 1 if THIS process's static code signature
// carries com.apple.security.virtualization == true (read via Security.framework's
// SecCodeCopySigningInformation), else 0. It never touches Virtualization.framework.
int k3sm_vz_has_entitlement(void);

#endif // K3SM_VM_DARWIN_H
