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

import "testing"

// TestResourceSymbolsWantList names every userspace-resource symbol the
// runtime depends on and resolves each one on its own through
// dlsym(RTLD_DEFAULT). The aggregate TestResourceSymbolsResolve can only say
// that the set linked; this list is red for the one name that went missing.
// The negative case proves the lookup can say no, so a green run is not a
// lookup that answers yes to everything.
func TestResourceSymbolsWantList(t *testing.T) {
	want := []string{
		"proc_pid_rusage",
		"memorystatus_control",
		"posix_spawnattr_setpcontrol_np",
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			if !symbolResolves(name) {
				t.Fatalf("%s does not resolve (an OS update may have removed it)", name)
			}
		})
	}
	t.Run("absent-symbol-does-not-resolve", func(t *testing.T) {
		if symbolResolves("k3sm_spicanary_no_such_symbol") {
			t.Fatal("dlsym resolved a symbol that does not exist; the want-list proves nothing")
		}
	})
}
