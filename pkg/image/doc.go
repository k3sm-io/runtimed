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

// Package image pulls OCI image artifacts into a content-addressed cache and
// materializes them into a pod's rootfs as native files runnable in place at
// host paths (k3sm/docs/DESIGN.md §5a).
//
// Pipeline:
//
//   - Select: choose WHICH manifest of a multi-platform image to pull, from an
//     explicit per-pull PlatformPolicy (platform.go). Fail-closed: a
//     platform-less index child is UNKNOWN and never a candidate, a single
//     manifest is verified against its own config, and no match yields
//     ErrNoPlatformMatch naming the platforms the image does offer — there is
//     no path on which go-containerregistry's implicit linux/amd64 default can
//     fire. platform.go is pure, GOOS-agnostic and cgo-free: the Rosetta
//     capabilities it consumes are INPUTS, and probing for them belongs to
//     B103, not here.
//   - Pull: fetch an OCI image by reference into a content-addressed blob cache
//     under /var/lib/k3sm (default; configurable). Blobs are keyed by digest, so
//     a second pull of the same content is a cache hit. Every blob is re-hashed
//     against the digest its MANIFEST DESCRIPTOR claims before it is committed —
//     see Cache.CommitBlob, the single home of that invariant, and the ceiling
//     below.
//   - Materialize: copy the cached payload into the per-pod rootfs using APFS
//     copy-on-write via golang.org/x/sys/unix.Clonefile. The cache and pod
//     rootfs MUST be on the same APFS volume for the clone to succeed; on EXDEV
//     (cross-device) or ENOTSUP (non-APFS) the copier falls back to copyfile /
//     byte-copy. Materialization is idempotent and asserts no
//     com.apple.quarantine xattr is left on the result.
//   - Sign: ad-hoc codesign pulled Mach-O binaries (codesign -s - -f) STRIPPING
//     hardened-runtime and library-validation flags, so a later DYLD insert (the
//     darwin-net DNS shim) can load. Hardened runtime would block the insert.
//   - SignaturePolicy gate: enforce runtimev1.SignaturePolicy before exec.
//     UNSPECIFIED is fail-closed (refuse to run).
//
// CoW and codesign touch Darwin specifics; the cgo-free Clonefile binding lives
// behind cowCopy (clonefile_darwin.go) so callers stay platform-agnostic.
//
// # The CAS verification ceiling
//
// Cache.CommitBlob is the ONE place the content-addressed store checks that the
// bytes it commits hash to the digest they are named by, and it is deliberately a
// WRITE-time check only. Three limits follow, and none of them is hidden:
//
//   - The cache-hit fast path is an os.Stat of a regular file. A blob already on
//     disk is trusted on its NAME, and every downstream reader (materialize, the
//     unpacker) trusts the on-disk bytes.
//   - Every blob written BEFORE this check existed was never hashed by this repo
//     at all, so an existing cache carries unverified content indefinitely.
//   - The check proves the fetcher did not corrupt or substitute what the network
//     gave it. It does NOT authenticate the image: a wholly hostile FetchFunc
//     supplies the manifest the claimed digests come from, so it can make both
//     sides agree. Authenticity is a signature problem (SignaturePolicy), not a
//     CAS problem.
//
// Verify-on-read is NOT the answer and is deliberately absent: it is O(image
// bytes) on the hot path and would regress the M1.1-a1 cache-hit acceptance path.
// The natural closer is M11.2-d7, the unpacker, which already reads each blob
// once per rootfs creation and can hash it there for free.
//
// # Non-Mach-O payloads and the signature gate
//
// The codesign/spctl SignaturePolicy gate is a MACH-O control: it asks the
// kernel's code-signing machinery about a Mach-O image. It is therefore
// MEANINGLESS for a linux ELF payload destined for a vm pod — spctl has nothing
// to assess and would either error or vacuously pass.
//
// This must NEVER be resolved by adding a "skip the signature gate for a
// non-Mach-O payload" branch. Such a branch is a fail-open switch a hostile or
// merely mislabelled image can flip: the payload's format is attacker-chosen
// data, so "it isn't Mach-O" would become a way to bypass the gate entirely,
// and the same branch would silently disarm the gate for a Mach-O image that
// merely failed to parse.
//
// The SUBSTITUTE control for a Linux payload is a different mechanism, not a
// weakened one: per-layer diffID re-verification when the rootfs is built (so
// the bytes are self-authenticating against the manifest that was pulled) plus
// the pinned guest TCB (kernel + init), per B100.
// Platform selection (platform.go) is the upstream half of that chain: it is
// what guarantees the payload being verified is the one this node asked for.
package image
