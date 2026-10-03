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

// Package testwire builds PodBox fixtures that carry bytes a current Go
// producer cannot set through the generated struct. Its one helper appends
// PodBox field 4 (a retired path field) on the wire, so a test can model an
// old producer, or a hostile caller, sending it — against an apis release that
// still declares the field and against one that has removed it, with the same
// source. It is internal and imported only by tests.
package testwire

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// WithWireField4 returns a fresh PodBox equal to box plus field 4 carrying
// value as a length-delimited string, exactly as a producer would have encoded
// it. While the schema declares field 4 the value lands in that field; once the
// field is removed it lands in the unknown-field set. box is not modified.
func WithWireField4(t testing.TB, box *runtimev1.PodBox, value string) *runtimev1.PodBox {
	t.Helper()
	b, err := proto.Marshal(box)
	if err != nil {
		t.Fatalf("testwire: marshal PodBox: %v", err)
	}
	b = protowire.AppendTag(b, 4, protowire.BytesType)
	b = protowire.AppendString(b, value)
	out := &runtimev1.PodBox{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatalf("testwire: unmarshal PodBox with field 4: %v", err)
	}
	return out
}
