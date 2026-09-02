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
//   - Select: choose which manifest of a multi-platform image to pull, from an
//     explicit per-pull PlatformPolicy (platform.go). Fail-closed: a
//     platform-less index child is unknown and never a candidate, a single
//     manifest is verified against its own config, and no match yields
//     ErrNoPlatformMatch naming the platforms the image does offer — there is
//     no path on which go-containerregistry's implicit linux/amd64 default can
//     fire. platform.go is pure, GOOS-agnostic and cgo-free: the Rosetta
//     capabilities it consumes are INPUTS, and probing for them belongs to
//     B103, not here.
//
//   - Pull: fetch an OCI image by reference into a content-addressed blob cache
//     under /var/lib/k3sm (default; configurable). Blobs are keyed by digest, so
//     a second pull of the same content is a cache hit. Every blob is re-hashed
//     against the digest its MANIFEST DESCRIPTOR claims before it is committed —
//     see Cache.CommitBlob, the single home of that invariant, and the ceiling
//     below.
//
//   - Mirror (fallback): when the node's OWN ingest registry misses a
//     node-relative reference (localhost:<port>/...), consult the peer ingest
//     registries the embedding control plane advertises over the wireguard mesh
//     (mirror.go) and pull the same content from whichever peer has it. Only the
//     registry authority of the reference is rewritten, the index records the
//     reference the pod asked for, and every blob still passes the same
//     verification — a mirror is transport, never identity or trust. A peer
//     serving content that fails verification is walked past, not accepted. A
//     node with no MirrorSource (every standalone daemon) never enters this path.
//
//   - Record: write the (reference x platform) -> manifest entry to the on-disk
//     index (index.go) once the pull has fully succeeded, so this node can
//     answer presence BY REFERENCE — which the digest-keyed blob store cannot.
//     That record is what makes imagePullPolicy IfNotPresent serve a warm
//     reference with zero registry traffic and Never satisfiable at all. Index
//     entries are edges, never reachability roots: they can never protect a blob
//     from the GC, whose root set stays daemon-authored (see FileIndex,
//     ImageRoot).
//
//   - Ingest: admit an archive that arrived from outside the registry path — a
//     `docker save` tar or a tarred OCI layout streamed by `k3sm image
//     load`/`import` (load.go). It reduces to the same store primitives Pull
//     uses, in a strict order: every blob is re-hashed against the digest the
//     archive's own manifest claims for it before a lease is taken or anything
//     is committed, so a mismatch rejects the whole load and leaves the store
//     untouched — not even the blobs that verified. The reference is recorded
//     last. The docker-save leg's per-blob check is self-consistency (that
//     format's descriptors are synthesized from the bytes); the OCI-layout leg
//     is the one where the claim genuinely descends from a document whose own
//     digest is pinned. Loaded images are provenance-free by design: no
//     SignaturePolicy is evaluated here.
//
//   - Unpack: apply the image's layer blobs, in manifest order, into one tree
//     (unpack.go, tarapply.go), staged and committed by a single os.Rename so a
//     failed unpack commits nothing. The apply is containment-checked twice over
//     — an os.Root anchored at the tree, plus a name/link-target sanitizer — and
//     every layer's compressed digest and decompressed diffID are re-verified on
//     the one read before the commit.
//
//     The DIALECT (LayerSemantics, part of the key) decides both the rules and
//     the store. The NATIVE dialect files under <root>/unpacked keyed by
//     (config digest x layer digests x policy): whiteouts are ordinary files,
//     an absolute symlink is refused, nothing is recorded, because the tree is
//     cloned verbatim into a pod rootfs with no chroot around it. The LINUX
//     dialect (linuxlayer.go) files under <root>/snapshots keyed by the OCI
//     CHAIN ID: OCI whiteouts are interpreted, absolute symlinks are admitted
//     (the guest chroots into the tree), the tar's true uid/gid/mode goes to an
//     ownership sidecar the guest re-applies, and two paths the destination
//     volume would merge into one file — measured by probing that volume, not
//     assumed — are refused fail-closed.
//
//   - MergeRunSpec: merge the image config's Entrypoint/Cmd/Env/WorkingDir/User
//     with a container's pod spec per the k8s four-quadrant table, with $(VAR)
//     expansion and upstream's runAsNonRoot rule (runspec.go). It is the one
//     producer of a pulled container's argv.
//
//   - Materialize: copy the unpacked tree into the per-pod rootfs using APFS
//     copy-on-write via golang.org/x/sys/unix.Clonefile. The cache and pod
//     rootfs must be on the same APFS volume for the clone to succeed; on EXDEV
//     (cross-device) or ENOTSUP (non-APFS) the copier falls back to copyfile /
//     byte-copy. Materialization is idempotent and asserts no
//     com.apple.quarantine xattr is left on the result.
//
//   - Sign: ad-hoc codesign pulled Mach-O binaries (codesign -s - -f) STRIPPING
//     hardened-runtime and library-validation flags, so a later DYLD insert (the
//     darwin-net DNS shim) can load. Hardened runtime would block the insert.
//
//   - SignaturePolicy gate: enforce runtimev1.SignaturePolicy before exec.
//     UNSPECIFIED is fail-closed (refuse to run).
//
// CoW and codesign touch Darwin specifics; the cgo-free Clonefile binding lives
// behind cowCopy (clonefile_darwin.go) so callers stay platform-agnostic.
//
// # The CAS verification ceiling
//
// Cache.CommitBlob is the one place the content-addressed store checks that the
// bytes it commits hash to the digest they are named by, and it is deliberately a
// WRITE-time check only. Three limits follow, and none of them is hidden:
//
//   - The cache-hit fast path is an os.Stat of a regular file. A blob already on
//     disk is trusted on its NAME by every reader that does not itself re-hash it.
//   - Every blob written before this check existed was never hashed by this repo
//     at all, so an existing cache carries unverified content indefinitely.
//   - The check proves the fetcher did not corrupt or substitute what the network
//     gave it. It does not authenticate the image: a wholly hostile FetchFunc
//     supplies the manifest the claimed digests come from, so it can make both
//     sides agree. Authenticity is a signature problem (SignaturePolicy), not a
//     CAS problem.
//
// A general verify-on-read is still deliberately absent — it is O(image bytes) on
// the hot path and would regress the M1.1-a1 cache-hit acceptance. What M11.2-d7
// closes is the path that MATTERS, for free: Unpacker.Unpack already streams every
// blob of an image end to end to build the tree, so it re-hashes each one against
// its manifest descriptor (ErrDigestMismatch) and each layer's decompressed bytes
// against the config's diffID (ErrDiffIDMismatch) on that single read. So a blob
// corrupted or substituted on disk after it was committed is caught before it is
// unpacked, and therefore before a pod can execute it. The ceiling that remains is
// exactly the third bullet above: content-addressing is not authenticity.
//
// # Non-Mach-O payloads and the signature gate
//
// The codesign/spctl SignaturePolicy gate is a MACH-O control: it asks the
// kernel's code-signing machinery about a Mach-O image. It is therefore
// MEANINGLESS for a linux ELF payload destined for a vm pod — spctl has nothing
// to assess and would either error or vacuously pass.
//
// This must never be resolved by adding a "skip the signature gate for a
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
