//go:build darwin && cgo

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

package spicanary

import (
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
)

// TestPosixSemStanzaCompiles is the grammar canary for the per-pod semaphore
// grant: the exact stanza Generate emits, under the profile base every pod
// profile starts with, must compile on this macOS. The runtime probes the same
// compile and omits the grant when it fails (semaphores denied), so without
// this test a grammar change would only show as pods losing semaphores.
// Measured on macOS 27.0.1; a 26 host confirms it there.
func TestPosixSemStanzaCompiles(t *testing.T) {
	stanza, err := sandbox.PosixSemStanza("/k3sm.0123abcd.")
	if err != nil {
		t.Fatal(err)
	}
	base := "(version 1)\n(deny default)\n(import \"system.sb\")\n"
	if !sbplCompiles(base) {
		t.Fatal("the bare profile base does not compile; the grammar check below would mean nothing")
	}
	if !sbplCompiles(base + stanza) {
		t.Fatalf("libsandbox rejects the semaphore stanza; pods will run with semaphores denied:\n%s", stanza)
	}
	if sbplCompiles(base + "(allow ipc-posix-sem (no-such-filter \"x\"))\n") {
		t.Fatal("libsandbox accepted an unknown filter; the compile check cannot tell a good spelling from a bad one")
	}
}
