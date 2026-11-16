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

package hostshare

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func TestExposeGrantParseRoundTrip(t *testing.T) {
	in := "rw /Users/dev/Code\nexpose uid=501 user=miko namespaces=yurei-system,tools access=read-write\nexpose uid=502 user=dev namespaces=dev access=read\n"
	f, err := ParseFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Exposes) != 2 || f.Exposes[0].UID != 501 || !f.Exposes[0].ReadWrite || f.Exposes[1].ReadWrite {
		t.Fatalf("Exposes = %+v", f.Exposes)
	}
	back, err := ParseFile(strings.NewReader(string(FormatFile(f))))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(back.Exposes) != fmt.Sprint(f.Exposes) || len(back.Entries) != 1 {
		t.Errorf("round trip = %+v, want %+v", back, f)
	}
}

func TestExposeGrantRefusals(t *testing.T) {
	for _, line := range []string{
		"expose uid=20 user=staffer namespaces=a access=read",        // system uid
		"expose uid=501 user=mi/ko namespaces=a access=read",         // bad name
		"expose uid=501 user=miko namespaces= access=read",           // no namespace
		"expose uid=501 user=miko namespaces=Bad_NS access=read",     // not a label
		"expose uid=501 user=miko namespaces=a access=write",         // bad access
		"expose uid=501 user=miko namespaces=a",                      // short
		"expose user=miko uid=501 namespaces=a access=read",          // order
		"expose uid=501 user=miko namespaces=../x access=read-write", // traversal
	} {
		if _, err := ParseFile(strings.NewReader(line + "\n")); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("%q: err = %v, want ErrInvalidEntry", line, err)
		}
	}
	if _, err := Parse(strings.NewReader("expose uid=501 user=miko namespaces=a access=read\n")); err == nil {
		t.Error("a user file accepted an exposure grant")
	}
}

func TestExposeDirValidatesComponents(t *testing.T) {
	got, err := ExposeDir("/var/lib/k3sm", "yurei-system", "yureid-0", "sockets")
	if err != nil || got != "/var/lib/k3sm/expose/yurei-system/yureid-0/sockets" {
		t.Fatalf("ExposeDir = %q, %v", got, err)
	}
	for _, c := range [][4]string{
		{"var/lib", "ns", "p", "v"},
		{"/var/lib/../x", "ns", "p", "v"},
		{"/r", "..", "p", "v"},
		{"/r", "ns", "..", "v"},
		{"/r", "ns", "a/b", "v"},
		{"/r", "ns", ".hidden", "v"},
		{"/r", "ns", "p", "V"},
		{"/r", "ns", "", "v"},
		{"/r", "ns", "p", "a.b"},
	} {
		if _, err := ExposeDir(c[0], c[1], c[2], c[3]); !errors.Is(err, ErrNotExposed) {
			t.Errorf("ExposeDir%v err = %v, want ErrNotExposed", c, err)
		}
	}
}

func exposeBox(ns string, x *runtimev1.ExposeVolumeSource, mount *runtimev1.VolumeMount) *runtimev1.PodBox {
	if mount == nil {
		mount = &runtimev1.VolumeMount{Name: "sockets", MountPath: "/var/run/app"}
	}
	return &runtimev1.PodBox{
		Namespace:  ns,
		Name:       "app-0",
		Volumes:    []*runtimev1.Volume{{Name: "sockets", Expose: x}, {Name: "unused", Expose: x}},
		Containers: []*runtimev1.Container{{Name: "c", VolumeMounts: []*runtimev1.VolumeMount{mount}}},
	}
}

func TestAuthorizeExposures(t *testing.T) {
	grants := []ExposeGrant{{UID: 501, User: "miko", Namespaces: []string{"yurei-system"}, ReadWrite: true}, {UID: 502, User: "dev", Namespaces: []string{"dev"}}}
	names := func(uid uint32) (string, error) {
		switch uid {
		case 501:
			return "miko", nil
		case 502:
			return "dev", nil
		}
		return "", errors.New("no such uid")
	}
	x := &runtimev1.ExposeVolumeSource{User: "miko", Uid: 501, ReadWrite: true}
	got, err := AuthorizeExposures(grants, exposeBox("yurei-system", x, nil), "/var/lib/k3sm", names)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Dir != "/var/lib/k3sm/expose/yurei-system/app-0/sockets" || !got[0].ReadWrite || got[0].UID != 501 {
		t.Fatalf("got %+v (the unmounted volume must be ignored)", got)
	}
	for name, c := range map[string]struct {
		ns    string
		x     *runtimev1.ExposeVolumeSource
		mount *runtimev1.VolumeMount
	}{
		"ungranted namespace": {"other", x, nil},
		"renamed account":     {"yurei-system", &runtimev1.ExposeVolumeSource{User: "mikoold", Uid: 501, ReadWrite: true}, nil},
		"recycled uid":        {"yurei-system", &runtimev1.ExposeVolumeSource{User: "miko", Uid: 503}, nil},
		"system uid":          {"yurei-system", &runtimev1.ExposeVolumeSource{User: "root", Uid: 0}, nil},
		"over the cap":        {"dev", &runtimev1.ExposeVolumeSource{User: "dev", Uid: 502, ReadWrite: true}, nil},
		"subPath":             {"yurei-system", x, &runtimev1.VolumeMount{Name: "sockets", MountPath: "/m", SubPath: "s"}},
		"readOnly mount":      {"yurei-system", x, &runtimev1.VolumeMount{Name: "sockets", MountPath: "/m", ReadOnly: true}},
		"bad namespace":       {"../etc", x, nil},
	} {
		if _, err := AuthorizeExposures(grants, exposeBox(c.ns, c.x, c.mount), "/var/lib/k3sm", names); !errors.Is(err, ErrNotExposed) {
			t.Errorf("%s: err = %v, want ErrNotExposed", name, err)
		}
	}
	read := &runtimev1.ExposeVolumeSource{User: "dev", Uid: 502}
	if got, err := AuthorizeExposures(grants, exposeBox("dev", read, nil), "/var/lib/k3sm", names); err != nil || len(got) != 1 || got[0].ReadWrite {
		t.Errorf("read exposure under a read grant = %+v, %v", got, err)
	}
}
