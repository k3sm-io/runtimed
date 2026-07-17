//go:build !darwin

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

// ProcStartTimeNano is unavailable off darwin (the runtime targets macOS; this
// stub keeps cross-compiles building). It reports no identity.
func ProcStartTimeNano(pid int) (startUnixNano int64, ok bool) {
	return 0, false
}

// ProcGroupStartsNano is unavailable off darwin. It reports ok=false (cannot
// inspect), which the startup pod reap treats as "keep the record, retry" —
// never as an empty group — so a cross-built binary never signals blindly.
func ProcGroupStartsNano(pgid int) (memberStartsNano []int64, ok bool) {
	return nil, false
}
