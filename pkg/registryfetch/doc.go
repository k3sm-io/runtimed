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

// Package registryfetch is the resumable blob download from an OCI registry:
// the ranged blob GET and the on-disk partial file a transfer resumes from.
//
// # Ranged GET
//
// Registry.Blob opens a blob from an offset, with a Range request when the
// offset is past zero. A 200 to a Range request means the server sent the
// whole blob, so the returned start is 0 and the caller restarts its partial;
// a 206 must carry a Content-Range starting exactly at the offset asked for;
// a 416 is retried once without a Range. Registry.Session is the
// authenticated, pull-scoped client the GET runs on, exported so a caller can
// issue its own bounded reads (a manifest) over the same transport.
//
// # Partial store
//
// PartialStore keeps one partial file per digest under one directory. Its
// guards are the reason it exists:
//
//   - The file name is derived from a digest that must match
//     sha256:<64 hex>, so it is a fixed, path-safe token.
//   - The directory is created 0700 when absent and refused when it is not a
//     directory (a file, or a symlink planted in its place), is writable by
//     group or other, or is not owned by the effective uid: a partial dir
//     another principal can write or own lets it choose the bytes a resume
//     continues from.
//   - The partial is opened O_NOFOLLOW|O_NONBLOCK and must be a regular file
//     by fstat of the opened descriptor (ErrPartialFile), so a symlink, a
//     FIFO or a directory in its place is refused without blocking.
//   - The transfer is handed the partial positioned at its current length,
//     and restarts it itself when the source answers from another offset;
//     after it the file must be exactly the blob's size (ErrPartialLength),
//     a short one kept for the next resume and a long one cut to the size,
//     so a whole blob appended to a prefix is never committed.
//   - A complete partial is replayed whole to the caller's commit, which
//     re-hashes it; when the commit reports the bytes poisoned (a digest
//     mismatch, an overrun), or fails with no poison test given, the partial
//     is removed, so a poisoned prefix never survives to be resumed.
//
// Three opt-in helpers serve a caller that shares one store across
// concurrent pulls; a caller that uses none of them sees no change. Claim
// gives one writer per digest within a store, without blocking; its refusal
// says whether the digest is held (ErrPartialClaimed, retryable) or malformed
// (ErrInvalidDigest, never retryable). Admit checks MaxBytes over the regular
// files in the directory before a partial grows (ErrPartialBudget); it fails
// closed on a negative or over-cap size and sums without overflow. A zero
// MaxBytes means no cap; a negative one is refused (ErrPartialCap). Sweep
// removes old, unclaimed partials, matching only the store's own file-name
// grammar and unlinking relative to a descriptor of the directory opened
// O_NOFOLLOW, so it never follows a link. The stall watchdog and the blob
// cache itself belong to the caller.
//
// Their limits are part of the contract:
//
//   - Sweep protects only claimed digests. Every Resume caller that shares a
//     store with a Sweep must hold the digest's Claim for the whole Resume,
//     or Sweep can remove the partial out from under it.
//   - Admit is advisory: it holds nothing between its check and the growth,
//     so two concurrent Admits can both pass. It counts every regular file in
//     the directory, whatever its name, by apparent size.
//   - The directory's parent path is trusted (root-owned, or writable only by
//     this principal). O_NOFOLLOW covers only the last path component.
//
// # Errors
//
// Foreign error text (registry, transport) is bounded and ASCII-quoted; the
// cause stays visible to errors.Is. ErrInvalidReference and ErrPartialDir are
// carried by *ReferenceError and *PartialDirError so a caller can re-wrap the
// detail under its own sentinel without changing the message.
//
// The package imports only the standard library, golang.org/x/sys/unix and
// go-containerregistry's authn, name and transport packages, and must stay a
// leaf: anything needing a k3sm type does not belong here.
package registryfetch
