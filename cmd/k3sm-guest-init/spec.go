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

package main

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	guestv1 "k3sm.io/apis/guest/v1"
)

// decodeSpec decodes the host-written guest-spec.json.
//
// Unknown fields are REJECTED (DiscardUnknown: false), and that refusal is a
// safety property, not a style choice. The host writes the proto-JSON encoding
// of GuestSpec, and proto-JSON omits a field left at its zero value, so a host
// that does not use a newer field boots an older guest normally — while a host
// that DOES set it boots an older guest into this error instead of into a pod
// that silently ignored what it was asked to do (a guest-private mount exposed
// to every container, a sidecar waited on forever, an image user run as root).
// Relaxing it would turn every future guest/v1 field into a silent drop on skew.
//
// It lives in an untagged file so the refusal is tested on every platform the
// repo's tests run on, not only inside the guest build.
func decodeSpec(raw []byte) (*guestv1.GuestSpec, error) {
	spec := &guestv1.GuestSpec{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, spec); err != nil {
		return nil, fmt.Errorf("decode guest spec: %w", err)
	}
	return spec, nil
}
