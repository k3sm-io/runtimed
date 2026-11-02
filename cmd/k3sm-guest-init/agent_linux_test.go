//go:build linux

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
	"context"
	"testing"

	"k3sm.io/runtimed/pkg/guestagent"
)

// TestCgroupSamplerDelegatesToSampleLeaf pins Sample's call into sampleLeaf on
// the container's own leaf under the sampler's root. The darwin tests reach
// sampleLeaf directly, so only this test sees a Sample that stops calling it
// or calls it on the wrong directory.
func TestCgroupSamplerDelegatesToSampleLeaf(t *testing.T) {
	root := t.TempDir()
	sampleFixture(t, root, "app", goodSampleFiles())
	s := &cgroupSampler{root: root}

	got, err := s.Sample(context.Background(), "app")
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	want := guestagent.ContainerSample{CPUUsageUsec: 4200, MemoryWorkingSetBytes: 10485760 - 2097152, MemoryHighEvents: 7}
	if got != want {
		t.Fatalf("Sample = %+v, want %+v", got, want)
	}
}
