// Package spicanary is the home of runtimed's CI symbol-canary: a test that asserts the
// private/deprecated Darwin SPI k3sm depends on still resolves on the current macOS, so an
// OS update that removes a symbol fails CI loudly instead of at runtime (DESIGN §8 risk #1).
//
// M1 lands the libsandbox half (canary_darwin.go), since the M1 Seatbelt exec-shim
// links it; the remaining symbols are added with the backends that use them:
//
//   - libsandbox:  sandbox_compile_string / sandbox_apply / sandbox_free_error   (Seatbelt)   — M1, here
//   - libsystem:   memorystatus_control                                          (jetsam probe) — M2
//   - libc:        clonefile / clonefileat                                       (APFS CoW)   — covered via golang.org/x/sys/unix.Clonefile
//
// canary_darwin.go (cgo) takes the address of each libsandbox symbol so the package fails to
// LINK if one vanishes; TestSymbolsResolve runs from the standard go-test gate, the workspace
// hack/ci.sh, and the macOS CI on every OS beta. The canary sits beside the swappable
// sandbox.Backend so the "engine is replaceable" mitigation stays concrete.
package spicanary
