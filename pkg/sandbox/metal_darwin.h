#ifndef K3SM_METAL_DARWIN_H
#define K3SM_METAL_DARWIN_H

#include <stdint.h>

// FUNCTIONAL Metal probe for the daemon's GPU facts (M8.2-d4). This header is the
// INVENTORY of that surface: it declares ONE entry point, it uses only PUBLIC
// Metal.framework API (so this is NOT a libsandbox SPI canary case), and the
// implementation in metal_darwin.m wraps everything in @autoreleasepool + @try/@catch
// so a driver-side Obj-C exception can never take down the daemon it is probed from.
// Adding a second entry point means bumping the count here AND in metal_darwin.m.
//
// WHY FUNCTIONAL AND NOT A NIL-CHECK. MTLCreateSystemDefaultDevice returns a
// NON-NIL paravirtual device inside a VZ guest (including GitHub-hosted macOS
// runners), so "the pointer is not nil" would make every VM node advertise a GPU it
// cannot give a pod. The probe therefore compiles a kernel, builds a pipeline,
// dispatches it, and CHECKS THE RESULTS — and separately reports whether the device
// identifies as paravirtual, because "the GPU worked" and "this is a real GPU" are
// different questions and a VM can answer yes to the first.

// k3sm_metal_reason values — the probe outcome, mapped 1:1 to the MetalReason*
// tokens in metal.go. Each distinct outcome gets its own value; none is reused.
enum k3sm_metal_reason {
	K3SM_METAL_OK = 0,               // compile + dispatch + correct results
	K3SM_METAL_NO_DEVICE = 1,        // MTLCreateSystemDefaultDevice returned nil
	K3SM_METAL_PARAVIRTUAL = 2,      // a device, but the VZ paravirtual one
	K3SM_METAL_COMPILE_FAILED = 3,   // library/function/pipeline construction failed
	K3SM_METAL_DISPATCH_FAILED = 4,  // the command buffer did not complete
	K3SM_METAL_WRONG_RESULT = 5,     // it completed and computed the wrong values
};

// k3sm_metal_facts is what one probe run observed. device_name is NUL-terminated
// and truncated to fit; it is a diagnostic string, never a scheduling input.
typedef struct {
	int reason;                              // enum k3sm_metal_reason
	int functional;                          // 1 iff reason == K3SM_METAL_OK
	int paravirtual;                         // 1 iff the device is the VZ paravirtual GPU
	uint64_t recommended_max_working_set;    // MTLDevice.recommendedMaxWorkingSetSize
	char device_name[128];
} k3sm_metal_facts;

// k3sm_metal_probe runs the functional probe and fills out. It returns the same
// value as out->reason. It never raises: every Obj-C exception is caught and
// reported as a failing reason (fail closed).
int k3sm_metal_probe(k3sm_metal_facts *out);

#endif /* K3SM_METAL_DARWIN_H */
