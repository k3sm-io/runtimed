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

package supervisor

import (
	"os"
	"testing"
)

// TestPhysFootprinterSelf exercises the real proc_pid_rusage cgo binding against
// THIS process (root-free, deterministic): a live process has a non-zero
// ri_phys_footprint. This proves the binding links and reads a sane value — the
// production memory sampler depends on it (the symbol itself is canaried in
// internal/spicanary). The OOMKilled-on-a-real-limit path is the m2.sh e2e.
func TestPhysFootprinterSelf(t *testing.T) {
	fp, err := PhysFootprinter{}.Footprint(os.Getpid())
	if err != nil {
		t.Fatalf("Footprint(self): %v", err)
	}
	if fp == 0 {
		t.Fatal("self ri_phys_footprint = 0, want > 0 (a live process has a footprint)")
	}
	t.Logf("self ri_phys_footprint = %d bytes", fp)
}

// TestPhysFootprinterDeadPidErrors confirms a sample of a non-existent pid returns
// an error (ESRCH), which the sampler treats as "skip this pid".
func TestPhysFootprinterDeadPidErrors(t *testing.T) {
	// pid 0x7FFFFFFE is effectively never live; proc_pid_rusage → ESRCH.
	if _, err := (PhysFootprinter{}).Footprint(0x7FFFFFFE); err == nil {
		t.Fatal("Footprint(non-existent pid) = nil error, want ESRCH")
	}
}
