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

package image

import (
	"errors"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestUnpackPolicyForCoversEverySandboxBackend walks the generated enum map, so
// a backend added to the proto cannot slip past the dialect decision: every
// value must have an explicit row here, VM is the only linux backend, and an
// out-of-range value fails closed.
func TestUnpackPolicyForCoversEverySandboxBackend(t *testing.T) {
	type outcome int
	const (
		native outcome = iota + 1
		linux
		unsupported
	)
	want := map[runtimev1.SandboxBackend]outcome{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED:     unsupported,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC:   native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC: native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL:         native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_VM:              linux,
		// Today's error is an incidental default: a wasm image stops in the
		// puller before any unpack. Flip this row deliberately when the wasm
		// pull path lands.
		runtimev1.SandboxBackend_SANDBOX_BACKEND_WASM: unsupported,
	}

	var maxValue int32
	linuxCount := 0
	for v, name := range runtimev1.SandboxBackend_name {
		maxValue = max(maxValue, v)
		backend := runtimev1.SandboxBackend(v)
		exp, ok := want[backend]
		if !ok {
			t.Errorf("sandbox backend %s (%d) has no row in the want table: decide that backend's layer dialect before adding it", name, v)
			continue
		}
		got, err := UnpackPolicyFor(backend)
		switch exp {
		case unsupported:
			if !errors.Is(err, ErrUnsupportedLayerSemantics) {
				t.Errorf("UnpackPolicyFor(%s) = %+v, %v; want ErrUnsupportedLayerSemantics", name, got, err)
			}
		case native, linux:
			wantPolicy := NativeUnpackPolicy()
			if exp == linux {
				wantPolicy = LinuxUnpackPolicy()
			}
			if err != nil || got != wantPolicy {
				t.Errorf("UnpackPolicyFor(%s) = %+v, %v; want %+v", name, got, err, wantPolicy)
			}
		}
		if err == nil && got == LinuxUnpackPolicy() {
			linuxCount++
			if backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
				t.Errorf("UnpackPolicyFor(%s) yields the linux policy; only SANDBOX_BACKEND_VM may", name)
			}
		}
	}
	if linuxCount != 1 {
		t.Errorf("%d backends yield the linux policy, want exactly 1 (SANDBOX_BACKEND_VM)", linuxCount)
	}

	outOfRange := runtimev1.SandboxBackend(maxValue + 1)
	if _, err := UnpackPolicyFor(outOfRange); !errors.Is(err, ErrUnsupportedLayerSemantics) {
		t.Errorf("UnpackPolicyFor(%d) error = %v, want ErrUnsupportedLayerSemantics", int32(outOfRange), err)
	}
}

// TestTreeKeyBindsDialect pins that the dialect is an input to the tree key: the
// same manifest unpacked under the native and the linux policy names two
// distinct trees, so one dialect's tree is never served for the other.
func TestTreeKeyBindsDialect(t *testing.T) {
	mfst := &runtimev1.ImageManifest{
		Config: &runtimev1.Descriptor{Digest: "sha256:" + hexOf('a')},
		Layers: []*runtimev1.Descriptor{{Digest: "sha256:" + hexOf('1')}},
	}
	nativeKey, err := TreeKey(mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("TreeKey native: %v", err)
	}
	linuxKey, err := TreeKey(mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("TreeKey linux: %v", err)
	}
	if nativeKey == linuxKey {
		t.Fatalf("TreeKey is %q under both the native and the linux policy; the dialect must be bound into the key", nativeKey)
	}
}
