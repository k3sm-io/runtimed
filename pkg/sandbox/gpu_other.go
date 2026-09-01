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

package sandbox

// probeHostFacts is the off-PLATFORM host-facts read: the darwin sysctls do not
// exist elsewhere, so every fact is absent. The zero value is the honest answer and
// it never decides availability on its own (see DeriveGPUFacts).
func probeHostFacts() HostFacts { return HostFacts{} }
