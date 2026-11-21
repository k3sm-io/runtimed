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

package registryfetch

import (
	"strconv"
	"testing"
)

// FuzzParseContentRange feeds parseContentRange registry-controlled header
// text. It must never panic, and a value it accepts must be a satisfied range
// (first <= last < total, none negative) that formats back to the exact input,
// so no second spelling of one range is ever accepted. Seeds live in
// testdata/fuzz/FuzzParseContentRange.
func FuzzParseContentRange(f *testing.F) {
	for _, s := range []string{
		"bytes 300-999/1000",
		"bytes 0-0/1",
		"bytes 00-1/2",
		"bytes +1-2/3",
		"bytes 0-1/9223372036854775808",
		"bytes 1--2/3",
		"bytes 1-2/3 ",
		"",
		"bytes 1-2/*",
		"items 1-2/3",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		first, last, total, ok := parseContentRange(in)
		if !ok {
			if first != 0 || last != 0 || total != 0 {
				t.Fatalf("parseContentRange(%q) refused but returned %d,%d,%d", in, first, last, total)
			}
			return
		}
		if first < 0 || first > last || last >= total {
			t.Fatalf("parseContentRange(%q) accepted %d-%d/%d, not a satisfied range", in, first, last, total)
		}
		canon := "bytes " + strconv.FormatInt(first, 10) + "-" + strconv.FormatInt(last, 10) + "/" + strconv.FormatInt(total, 10)
		if canon != in {
			t.Fatalf("parseContentRange(%q) accepted a non-canonical spelling of %q", in, canon)
		}
	})
}
