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

package guestartifacts

import (
	"os"
	"strings"
	"testing"
)

// normalizeDoc strips "//" comment markers and collapses all whitespace so a
// phrase matches however the doc comment wraps it.
func normalizeDoc(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "//", " ")), " ")
}

// TestInitramfsDocMatchesKernelConfig pins the "why uncompressed" paragraph in
// doc.go to the guest kernel config: the kernel accepts every initrd
// decompressor, so the doc must not claim otherwise.
func TestInitramfsDocMatchesKernelConfig(t *testing.T) {
	cfgBytes, err := os.ReadFile("../../hack/guest-kernel/kernel.config")
	if err != nil {
		t.Fatalf("read kernel.config: %v", err)
	}
	docBytes, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}

	lines := map[string]bool{}
	for _, l := range strings.Split(string(cfgBytes), "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	doc := normalizeDoc(string(docBytes))

	for _, c := range []string{"GZIP", "BZIP2", "LZMA", "XZ", "LZO", "LZ4", "ZSTD"} {
		want := "CONFIG_RD_" + c + "=y"
		t.Run("kernel enables "+want, func(t *testing.T) {
			if !lines[want] {
				t.Errorf("kernel.config has no exact line %q", want)
			}
		})
	}

	t.Run("doc drops the false decompressor claim", func(t *testing.T) {
		const stale = "without any of the initrd decompressors"
		if strings.Contains(doc, normalizeDoc(stale)) {
			t.Errorf("doc.go still claims %q, contradicting kernel.config", stale)
		}
	})

	t.Run("doc states the measured trade", func(t *testing.T) {
		const want = "costs at least 10 ms"
		if !strings.Contains(doc, want) {
			t.Errorf("doc.go does not contain %q", want)
		}
	})
}
