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

package sandbox

import (
	"errors"
	"strings"
	"testing"
)

// TestVMSpecValidateHostname pins the VMSpec trust-boundary contract every vm
// backend inherits: empty, or at most MaxVMHostnameBytes bytes of [a-z0-9.-].
func TestVMSpecValidateHostname(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		wantErr  string // substring; empty means the spec is accepted
	}{
		{name: "empty", hostname: ""},
		{name: "short-name", hostname: "web-0"},
		{name: "fqdn", hostname: "web-0.web.ns.svc.cluster.local"},
		{name: "exactly-64-bytes", hostname: strings.Repeat("a", 31) + "." + strings.Repeat("b", 32)},
		{name: "65-bytes", hostname: strings.Repeat("a", 65), wantErr: "Hostname is 65 bytes"},
		{name: "uppercase", hostname: "Web-0", wantErr: "byte 0x57 at offset 0"},
		{name: "underscore", hostname: "web_0", wantErr: "byte 0x5f at offset 3"},
		{name: "slash", hostname: "a/b", wantErr: "byte 0x2f"},
		{name: "nul", hostname: "a\x00b", wantErr: "byte 0x00"},
		{name: "63-byte-label", hostname: strings.Repeat("a", 63)},
		{name: "64-byte-label", hostname: strings.Repeat("a", 64), wantErr: "64-byte label at offset 0"},
		{name: "lone-dot", hostname: ".", wantErr: "empty label at offset 0"},
		{name: "double-dot", hostname: "..", wantErr: "empty label at offset 0"},
		{name: "inner-empty-label", hostname: "a..b", wantErr: "empty label at offset 2"},
		{name: "leading-dot", hostname: ".web", wantErr: "empty label at offset 0"},
		{name: "trailing-dot", hostname: "web.", wantErr: "empty label at offset 4"},
		{name: "leading-dash", hostname: "-web", wantErr: "starting or ending with '-' at offset 0"},
		{name: "trailing-dash", hostname: "web-", wantErr: "starting or ending with '-' at offset 0"},
		{name: "label-leading-dash", hostname: "web.-ns", wantErr: "starting or ending with '-' at offset 4"},
		{name: "label-trailing-dash", hostname: "web-.ns", wantErr: "starting or ending with '-' at offset 0"},
		{name: "non-ascii", hostname: "w\xc3\xa9b", wantErr: "byte 0xc3 at offset 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VMSpec{PodID: "p", Hostname: tc.hostname}.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidVMSpec) {
				t.Fatalf("Validate() = %v, want ErrInvalidVMSpec", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidateVMSpecRefusesABadHostname pins the defence-in-depth layer: the vm
// backend's own validateVMSpec refuses a bad hostname even when its caller
// skipped VMSpec.Validate, so deleting that call fails here.
func TestValidateVMSpecRefusesABadHostname(t *testing.T) {
	spec := VMSpec{
		PodID:           "p",
		PodDir:          "/var/lib/k3sm/pods/p",
		AgentSocketPath: "/var/lib/k3sm/pods/p/agent.sock",
	}
	if err := validateVMSpec(spec); err != nil {
		t.Fatalf("validateVMSpec(valid spec) = %v, want nil", err)
	}
	spec.Hostname = "Web-0"
	err := validateVMSpec(spec)
	if !errors.Is(err, ErrInvalidVMSpec) || !strings.Contains(err.Error(), "Hostname") {
		t.Fatalf("validateVMSpec(bad hostname) = %v, want an ErrInvalidVMSpec naming Hostname", err)
	}
}

// TestVMSpecValidateFQDN pins the FQDN half of the trust-boundary check: empty,
// or a DNS-1123 subdomain of at most MaxVMFQDNBytes bytes whose first label is
// the hostname's first label.
func TestVMSpecValidateFQDN(t *testing.T) {
	long := "web-0" + strings.Repeat("."+strings.Repeat("a", 60), 5) // 310 bytes
	cases := []struct {
		name     string
		hostname string
		fqdn     string
		wantErr  string // substring; empty means the spec is accepted
	}{
		{name: "empty", hostname: "web-0"},
		{name: "empty-with-no-hostname", hostname: ""},
		{name: "subdomain", hostname: "web-0", fqdn: "web-0.web.ns.svc.cluster.local"},
		{name: "set-hostname-as-fqdn", hostname: "web-0.web.ns.svc.cluster.local", fqdn: "web-0.web.ns.svc.cluster.local"},
		{name: "first-label-differs", hostname: "a", fqdn: "b.web.ns.svc.cluster.local", wantErr: "does not start with the hostname's first label"},
		{name: "no-hostname", hostname: "", fqdn: "web-0.web.ns.svc.cluster.local", wantErr: "does not start with the hostname's first label"},
		{name: "uppercase", hostname: "web-0", fqdn: "web-0.Web.ns", wantErr: "FQDN for pod \"p\" has byte 0x57"},
		{name: "trailing-dot", hostname: "web-0", fqdn: "web-0.web.", wantErr: "empty label"},
		{name: "too-long", hostname: "web-0", fqdn: long, wantErr: "the limit is 253"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VMSpec{PodID: "p", Hostname: tc.hostname, FQDN: tc.fqdn}.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidVMSpec) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an ErrInvalidVMSpec containing %q", err, tc.wantErr)
			}
		})
	}
}
