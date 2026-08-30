//go:build darwin && cgo

// Obj-C shim for the FUNCTIONAL Metal probe behind runtimed's GPU facts (M8.2-d4).
// It is isolated here so the only Objective-C / Metal.framework surface the rest of
// runtimed sees is the ONE C entry point in metal_darwin.h.
//
// The COUNT is load-bearing, not prose: this comment and metal_darwin.h are the
// stated inventory a reviewer audits the Metal surface against, so adding an entry
// point means bumping the count in BOTH places.
//
// Everything runs inside @autoreleasepool and @try/@catch: this code executes in the
// root-or-_k3sm daemon's own process at construction time, and an uncaught Obj-C
// exception from a GPU driver would abort the daemon rather than degrade one fact.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <string.h>

#include "metal_darwin.h"

// k3sm_probe_kernel is the smallest kernel that proves the whole pipeline works:
// it compiles (so the Metal front-end ran), it dispatches (so the command queue and
// the GPU are live), and it writes a value derived from the thread index (so the
// caller can tell "the dispatch completed" from "the dispatch computed the right
// answer" — a distinction a memset-to-zero buffer would hide).
static NSString *const k3sm_probe_kernel =
	@"#include <metal_stdlib>\n"
	 "using namespace metal;\n"
	 "kernel void k3sm_probe(device uint *out [[buffer(0)]],\n"
	 "                       uint i [[thread_position_in_grid]]) {\n"
	 "  out[i] = i * 7u + 1u;\n"
	 "}\n";

// k3sm_probe_threads is the dispatch width. Four is enough to catch an
// index-independent write (a device that filled the buffer with one constant would
// pass a single-element check).
enum { k3sm_probe_threads = 4 };

// k3sm_is_paravirtual reports whether name identifies Apple's VZ paravirtual GPU.
//
// It is a NAME match, and that is a deliberate, documented choice rather than an
// oversight: Metal exposes no "am I virtual" property, and the paravirtual device
// can COMPLETE the functional probe on recent macOS — so the functional leg alone
// would advertise a GPU on every VM node. The name is Apple's own, stable across
// the VZ releases k3sm targets, and matched case-insensitively on the substring so
// a decorated variant still trips it. If Apple renames it, this fails OPEN for that
// one leg — which is why the node-facing consequence is also gated by the operator
// -visible chip facts and by the sandbox backend scoping in metal.go.
static int k3sm_is_paravirtual(NSString *name) {
	if (name == nil) {
		return 0;
	}
	return [name rangeOfString:@"Paravirtual" options:NSCaseInsensitiveSearch].location != NSNotFound ? 1 : 0;
}

int k3sm_metal_probe(k3sm_metal_facts *out) {
	if (out == NULL) {
		return K3SM_METAL_NO_DEVICE;
	}
	memset(out, 0, sizeof(*out));
	out->reason = K3SM_METAL_NO_DEVICE;

	@autoreleasepool {
		@try {
			id<MTLDevice> device = MTLCreateSystemDefaultDevice();
			if (device == nil) {
				return out->reason = K3SM_METAL_NO_DEVICE;
			}
			NSString *name = [device name];
			if (name != nil) {
				strncpy(out->device_name, [name UTF8String], sizeof(out->device_name) - 1);
			}
			out->recommended_max_working_set = (uint64_t)[device recommendedMaxWorkingSetSize];
			out->paravirtual = k3sm_is_paravirtual(name);
			if (out->paravirtual) {
				// Report the paravirtual verdict WITHOUT dispatching: the answer is
				// already decided, and running a compute workload inside a guest to
				// learn nothing new is a cost with no consumer.
				return out->reason = K3SM_METAL_PARAVIRTUAL;
			}

			NSError *err = nil;
			id<MTLLibrary> lib = [device newLibraryWithSource:k3sm_probe_kernel options:nil error:&err];
			if (lib == nil) {
				return out->reason = K3SM_METAL_COMPILE_FAILED;
			}
			id<MTLFunction> fn = [lib newFunctionWithName:@"k3sm_probe"];
			if (fn == nil) {
				return out->reason = K3SM_METAL_COMPILE_FAILED;
			}
			id<MTLComputePipelineState> pipeline =
				[device newComputePipelineStateWithFunction:fn error:&err];
			if (pipeline == nil) {
				return out->reason = K3SM_METAL_COMPILE_FAILED;
			}
			id<MTLCommandQueue> queue = [device newCommandQueue];
			id<MTLBuffer> buffer = [device newBufferWithLength:sizeof(uint32_t) * k3sm_probe_threads
			                                          options:MTLResourceStorageModeShared];
			if (queue == nil || buffer == nil) {
				return out->reason = K3SM_METAL_DISPATCH_FAILED;
			}
			id<MTLCommandBuffer> cmd = [queue commandBuffer];
			id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
			if (cmd == nil || enc == nil) {
				return out->reason = K3SM_METAL_DISPATCH_FAILED;
			}
			[enc setComputePipelineState:pipeline];
			[enc setBuffer:buffer offset:0 atIndex:0];
			[enc dispatchThreads:MTLSizeMake(k3sm_probe_threads, 1, 1)
			  threadsPerThreadgroup:MTLSizeMake(k3sm_probe_threads, 1, 1)];
			[enc endEncoding];
			[cmd commit];
			[cmd waitUntilCompleted];
			if ([cmd status] != MTLCommandBufferStatusCompleted || [cmd error] != nil) {
				return out->reason = K3SM_METAL_DISPATCH_FAILED;
			}
			const uint32_t *got = (const uint32_t *)[buffer contents];
			for (uint32_t i = 0; i < k3sm_probe_threads; i++) {
				if (got[i] != i * 7u + 1u) {
					return out->reason = K3SM_METAL_WRONG_RESULT;
				}
			}
			out->functional = 1;
			return out->reason = K3SM_METAL_OK;
		} @catch (NSException *e) {
			// A driver-side exception is an ABSENT capability, never a daemon fault.
			out->functional = 0;
			return out->reason = K3SM_METAL_DISPATCH_FAILED;
		}
	}
}
