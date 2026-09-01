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
	"os"
	"strings"
	"testing"
)

// TestEntitlementsAreAMFIParseable pins a failure mode that is invisible in every
// other check.
//
// codesign reads an entitlements plist with AMFI's XML parser, which is STRICTER
// than the one behind `plutil -lint`: AMFI rejects an XML comment. A commented
// plist therefore lints clean, and then signing fails with
//
//	Failed to parse entitlements: AMFIUnserializeXML: syntax error near line N
//
// while `codesign --verify --strict` still reports the BINARY AS VALIDLY SIGNED —
// because the signature is fine. It simply carries no entitlements. The only
// downstream symptom is VMBackend.Available() reporting false on a Mac that is
// perfectly capable, with nothing anywhere saying why.
//
// This was not hypothetical: the file shipped with a 30-line explanatory comment
// and silently signed away its own entitlement until an end-to-end signing check
// on real hardware caught it. The rationale now lives in this command's doc
// comment, where it cannot break signing. Keep the plist minimal.
func TestEntitlementsAreAMFIParseable(t *testing.T) {
	t.Parallel()
	const path = "vmhost.entitlements"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := string(b)

	if strings.Contains(s, "<!--") {
		t.Errorf("%s contains an XML comment; AMFI's parser rejects one and codesign will "+
			"attach NO entitlements while still verifying as validly signed. Put the "+
			"explanation in the command's Go doc comment instead.", path)
	}

	// The set is exactly one key. Every entitlement here is authority the process
	// parsing a tenant's guest console output also gains, so a silent addition is
	// the thing worth failing a build over.
	if !strings.Contains(s, "com.apple.security.virtualization") {
		t.Errorf("%s no longer grants com.apple.security.virtualization — the helper cannot create a VM without it", path)
	}
	for _, forbidden := range []string{
		"allow-jit",
		"allow-unsigned-executable-memory",
		"disable-executable-page-protection",
		"disable-library-validation",
		"com.apple.vm.networking",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("%s grants %q. The hypervisor runs the guest; this process does not "+
				"execute guest code and is NAT-attached, never bridged. See the doc comment "+
				"in main.go for why each of these is excluded.", path, forbidden)
		}
	}
}
