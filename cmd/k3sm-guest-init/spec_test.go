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
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	guestv1 "k3sm.io/apis/guest/v1"
)

// TestReadSpecRejectsUnknownField pins the premise every new guest/v1 field's
// skew safety rests on: the guest refuses a spec carrying a key it does not
// know, and a field left at its zero value is absent from the encoding, so an
// older guest boots a spec that does not use a newer field and refuses one
// that does. If the decoder ever started discarding unknown keys, an older
// guest would silently ignore guest_private, sidecar or image_user instead of
// failing the boot.
func TestReadSpecRejectsUnknownField(t *testing.T) {
	known := &guestv1.GuestSpec{
		Hostname: "p", AgentPort: 1024,
		Containers: []*guestv1.GuestContainer{{Name: "c", RootfsTag: "k3sm.rootfs", Command: []string{"/bin/sh"}}},
		Mounts: []*guestv1.GuestMount{{
			TagOrSource: "k3sm.proj", Target: "/run/k3sm/shares/k3sm.proj",
			Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, ReadOnly: true,
		}},
	}
	raw, err := protojson.Marshal(known)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a known spec decodes", func(t *testing.T) {
		got, err := decodeSpec(raw)
		if err != nil {
			t.Fatalf("decodeSpec: %v", err)
		}
		if !proto.Equal(got, known) {
			t.Errorf("decoded %v, want %v", got, known)
		}
	})

	t.Run("zero-valued new fields are absent and decode", func(t *testing.T) {
		for _, key := range []string{`"guestPrivate"`, `"sidecar"`, `"imageUser"`} {
			if strings.Contains(string(raw), key) {
				t.Errorf("an unset field is encoded: %s in %s", key, raw)
			}
		}
	})

	t.Run("an unknown key is refused", func(t *testing.T) {
		for _, bad := range []string{
			`{"hostname":"p","agentPort":1024,"fromTheFuture":true}`,
			`{"hostname":"p","agentPort":1024,"containers":[{"name":"c","notAField":"x"}]}`,
			`{"hostname":"p","agentPort":1024,"mounts":[{"target":"/x","notAField":true}]}`,
		} {
			if _, err := decodeSpec([]byte(bad)); err == nil {
				t.Errorf("decodeSpec accepted %s", bad)
			}
		}
	})
}
