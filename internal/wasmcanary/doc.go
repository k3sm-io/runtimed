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

// Package wasmcanary is the decision core of the build-time canary over the
// wasmtime archive the wasm host links and over the linked helper binary. It is
// pure: callers run nm, read conf.h and parse the Mach-O load commands, and hand
// the results here. It is internal and linked by no daemon package; the
// release tooling that runs it lands with the archive.
//
// The canary is NECESSARY BUT NOT SUFFICIENT. A pass proves the archive
// exports the WASI 0.2 and wasi:http component-linker entry points, was built
// with the features they need, and targets macOS 26 or older; it does not
// prove a guest can serve an incoming request. The wasmtime C API cannot
// dispatch an incoming wasi:http request at all (its handler rejects every
// host-built argument), so a green canary never means serving works.
package wasmcanary
