//go:build !(darwin && cgo)

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

// sandboxSymbolsResolve is only meaningful on darwin+cgo (where libsandbox is
// linked); off it the canary is vacuously satisfied so the package builds for
// non-darwin CI.
func sandboxSymbolsResolve() bool { return true }

// resourceSymbolsResolve mirrors sandboxSymbolsResolve for the M2 resource SPI:
// only meaningful on darwin+cgo, vacuously satisfied elsewhere.
func resourceSymbolsResolve() bool { return true }
