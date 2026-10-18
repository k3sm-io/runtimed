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

package runtime

import (
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/sandbox"
)

// TestContainerEnvSemPrefix pins the shim's semaphore prefix: published with
// the shim (mounts, or a shadow set), derived from the pod UID exactly as the
// profile grant is, absent when no shim is inserted, and never taken from the
// spec.
func TestContainerEnvSemPrefix(t *testing.T) {
	want, err := sandbox.PosixSemPrefix("pod-sem")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mounts []string
		shadow bool
		set    bool
	}{
		{"mounts", []string{"/etc/nats"}, false, true},
		{"shadow-set", nil, true, true},
		{"no-shim", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{})
			rt.cfg.PathShimPath = testShim
			if tc.shadow {
				rt.cfg.ShadowBinDir = t.TempDir()
			}
			box, c := mountingBox(t, rt, "pod-sem", tc.mounts...)
			// A spec value is dropped: only the pod UID derives the prefix.
			c.Env = append(c.Env, &runtimev1.EnvVar{Name: semPrefixEnv, Value: "/k3sm.ffffffff."})
			env := mustEnv(t, rt, box, c)
			got, ok := envValue(env, semPrefixEnv)
			if ok != tc.set || (tc.set && got != want) {
				t.Errorf("%s = %q (set %v), want %q (set %v); env = %v", semPrefixEnv, got, ok, want, tc.set, env)
			}
		})
	}
}
