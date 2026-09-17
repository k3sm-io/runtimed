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

// Package pathsafe is the one home for path checks that must not follow
// symlinks.
//
// The daemon creates, stamps and deletes trees it addresses by STRING —
// <state-root>/run/vm/<pod>, <podDir>/k3sm.proj, <podDir>/k3sm.spec — and every
// syscall it then makes on such a string resolves each component, so a check
// that the string is in the right tree says nothing about where the syscall
// lands. RefuseSymlinkedPath is what bounds the place rather than the name.
//
// It is a package of its own, and deliberately a small one, because its callers
// sit in two others that must not depend on each other: pkg/mount writes a vm
// pod's share roots and credential content BEFORE pkg/sandbox boots the guest.
// Homing the check in either would make one import the other — and pkg/sandbox
// carries cgo (Seatbelt, Metal, the darwin SPI shims), which has no business in
// the volume renderer. So this package imports nothing but the standard library
// and will keep that property: anything needing a k3sm type does not belong here.
package pathsafe
