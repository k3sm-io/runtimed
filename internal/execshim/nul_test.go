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

package execshim

import "testing"

func TestHasNUL(t *testing.T) {
	cases := []struct {
		name string
		path string
		argv []string
		env  []string
		want bool
	}{
		{"clean", "/bin/sleep", []string{"/bin/sleep", "1"}, []string{"A=b"}, false},
		{"empty", "", nil, nil, false},
		{"nul-in-path", "/bin/sl\x00eep", []string{"x"}, nil, true},
		{"nul-in-argv", "/bin/sleep", []string{"/bin/sleep", "1\x002"}, nil, true},
		{"nul-in-env", "/bin/sleep", []string{"/bin/sleep"}, []string{"A=b", "C=\x00"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasNUL(tc.path, tc.argv, tc.env); got != tc.want {
				t.Errorf("hasNUL = %v, want %v", got, tc.want)
			}
		})
	}
}
