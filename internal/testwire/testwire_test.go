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

package testwire

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestWithWireField4LandsField4 pins that the helper is not a no-op: the exact
// injected value is readable as field 4, by number while the descriptor still
// declares it and from the unknown-field bytes once it does not. It reads only
// through reflection and the wire, so it compiles in both schema phases.
func TestWithWireField4LandsField4(t *testing.T) {
	for _, tc := range []struct {
		name, value string
	}{
		{"absolute path", "/var/lib/k3sm/pods/victim/rootfs"},
		{"empty-looking spaces", "  "},
		{"long value", strings.Repeat("x", 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &runtimev1.PodBox{PodId: "pod-a", Name: "a", Namespace: "ns"}
			out := WithWireField4(t, in, tc.value)

			if out.GetPodId() != "pod-a" || out.GetName() != "a" || out.GetNamespace() != "ns" {
				t.Fatalf("the helper lost the box's own fields: %v", out)
			}
			if _, ok := field4(t, in); ok {
				t.Fatal("the helper modified its input box")
			}
			got, ok := field4(t, out)
			if !ok {
				t.Fatal("field 4 is absent after WithWireField4")
			}
			if got != tc.value {
				t.Fatalf("field 4 = %q, want the injected %q", got, tc.value)
			}
		})
	}
}

// field4 reads field 4 from m the way a schema-agnostic reader must: by
// descriptor number when declared, else by decoding the unknown-field bytes.
func field4(t *testing.T, box *runtimev1.PodBox) (string, bool) {
	t.Helper()
	m := box.ProtoReflect()
	if fd := m.Descriptor().Fields().ByNumber(4); fd != nil {
		if !m.Has(fd) {
			return "", false
		}
		if n := len(m.GetUnknown()); n != 0 {
			t.Errorf("field 4 is declared but %d unknown bytes remain", n)
		}
		return m.Get(fd).String(), true
	}
	var (
		val   string
		found bool
	)
	b := m.GetUnknown()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatalf("unknown bytes do not parse: %v", protowire.ParseError(n))
		}
		fv := protowire.ConsumeFieldValue(num, typ, b[n:])
		if fv < 0 {
			t.Fatalf("unknown field %d does not parse: %v", num, protowire.ParseError(fv))
		}
		if num == 4 {
			if typ != protowire.BytesType {
				t.Fatalf("unknown field 4 has wire type %v, want BytesType", typ)
			}
			v, _ := protowire.ConsumeBytes(b[n:])
			val, found = string(v), true
		}
		b = b[n+fv:]
	}
	return val, found
}
