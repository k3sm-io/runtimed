//go:build !(darwin && cgo)

/*
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
*/

package sandbox

// ProbeWritePolicy is unavailable without darwin and cgo: every query fails
// (ok=false), which callers treat as "not the pod's".
func ProbeWritePolicy(pid int, path string) (sandboxed, allowed, ok bool) {
	return false, false, false
}
