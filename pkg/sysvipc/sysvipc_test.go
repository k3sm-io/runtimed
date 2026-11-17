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

package sysvipc

import (
	"reflect"
	"testing"
)

func TestParseIpcs(t *testing.T) {
	out := []byte(`IPC status from <running system> as of Mon Nov 16 22:14:13 EST 2026
T     ID     KEY        MODE       OWNER    GROUP
Message Queues:
q  65536 0x00000000 --rw-------     miko    staff

T     ID     KEY        MODE       OWNER    GROUP
Shared Memory:
m 589824 0x200b69c8 --rw-------     miko    staff
m 1048577 0x00000000 --rw-------    _k3sm   _k3sm

T     ID     KEY        MODE       OWNER    GROUP
Semaphores:
s 589825 0x200b69ca --ra-------     miko    staff
`)
	got, err := parseIpcs(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []Ref{{Msg, 65536}, {Shm, 589824}, {Shm, 1048577}, {Sem, 589825}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIpcs = %v, want %v", got, want)
	}
}

func TestParseIpcsEmptyAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     int
		wantErr  bool
	}{
		{"no objects", "IPC status\nT ID KEY\nMessage Queues:\n\nT ID KEY\nShared Memory:\n\nSemaphores:\n", 0, false},
		{"a section title missing: unknown format", "IPC status\nT ID KEY\nShared Memory:\n\nSemaphores:\n", 0, true},
		{"empty output", "", 0, true},
		{"a row without a numeric id", "Message Queues:\nShared Memory:\nm abc 0x0 --rw------- a b\nSemaphores:\n", 0, true},
		{"a negative id", "Message Queues:\nShared Memory:\nSemaphores:\ns -1 0x0 --ra------- a b\n", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIpcs([]byte(tc.in))
			if (err != nil) != tc.wantErr || len(got) != tc.want {
				t.Errorf("parseIpcs(%q) = %v, %v; want %d refs, err=%v", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}
