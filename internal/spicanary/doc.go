// Package spicanary is the home of runtimed's CI symbol-canary: a test that asserts the
// private/deprecated Darwin SPI k3sm depends on still resolves on the current macOS, so an
// OS update that removes a symbol fails CI loudly instead of at runtime (DESIGN §8 risk #1).
//
// This is a convention stub today (M0). The full canary lands at runtimed:M2.4 alongside the
// real backends that use these symbols:
//
//   - libsandbox:  sandbox_compile_string / sandbox_apply / sandbox_free_error   (Seatbelt)
//   - libsystem:   memorystatus_control                                          (jetsam probe)
//   - libc:        clonefile / clonefileat                                       (APFS CoW)
//
// At M2 this package gains canary_darwin.go (cgo: take the address of each symbol so the
// package fails to LINK if one vanishes) plus a dlsym fallback that names the missing symbol,
// and a TestSymbolsResolve run by the workspace hack/ci.sh and the macOS CI on every OS beta.
// The canary sits beside the swappable sandbox.Backend so the "engine is replaceable"
// mitigation stays concrete.
package spicanary
