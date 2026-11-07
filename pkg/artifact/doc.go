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

// Package artifact fetches platform-less OCI artifacts (a ModelPack model, a
// wasm module) from the cluster registry into the node's content-addressed
// cache. It is the SECOND entry point beside the image path (pkg/image), never
// a relaxation of it: the image path keeps refusing an artifact with
// ErrNoPlatformMatch, and this path refuses an image, because an OCI image
// config is in no artifact allow-set.
//
// The two paths share only three seams, each a small interface defined here and
// satisfied by pkg/image: BlobCommitter (Cache.CommitBlob, the one home of the
// re-hash invariant), Leaser (the in-flight lease that keeps a blob from being
// reclaimed between its commit and its record) and the transport
// (image.ArtifactTransport, behind Fetcher). The index record goes through
// Recorder, a distinct artifact/ namespace in the image FileIndex.
//
// # Fail-closed rules
//
//   - The allow-set comes from artifactv1.AllowSetFor(policy); UNSPECIFIED and
//     unknown policies are refused.
//   - The reference must name the configured cluster registry host; any other
//     host is refused before any request.
//   - The manifest is at most MaxManifestBytes, is an OCI image manifest (a
//     bare index is refused), and carries at most MaxLayers layers.
//   - The artifact type is artifactType, or the config mediaType when that is
//     empty. An OCI image config is never accepted.
//   - Tar layers (.tar, +gzip, +zstd) are refused; every layer media type must
//     be in the allow-set for the artifact type.
//   - Every layer carries a file path (org.cncf.model.filepath, else
//     org.opencontainers.image.title), validated by artifactv1.ValidatePath, and
//     the set by artifactv1.ValidatePathSet. The one exception is a wasm
//     artifact of exactly one application/wasm layer with neither annotation,
//     whose module is given the path module.wasm; no other type has a default.
//   - Every blob is committed through CommitBlob against its descriptor digest
//     and size; the artifact is recorded only after every one commits.
//
// # Resume and reservation
//
// A layer downloads into a partial file keyed by its digest under
// Config.PartialDir. A failed transfer leaves the partial in place, so the next
// call (in this process or after a daemon restart) continues it with a Range
// request; a server that answers 200 instead of 206 restarts it from zero. A
// complete partial is streamed through CommitBlob, which re-hashes it, and
// removed. A partial whose bytes fail the digest is removed, so a poisoned
// prefix never survives to a retry. At most Config.MaxConcurrentLayers (2)
// layers transfer at once, and one digest is never written by two pulls at once.
//
// Before the first byte, the pull reserves the bytes it may still add to the
// volume: the remaining download of every uncached blob plus the commit-time
// copy of the largest blobs that can be committing at once (CommitBlob writes a
// fresh temp from the partial). Reservations are held in-process across
// concurrent pulls and measured against free space minus Config.FloorBytes;
// bytes already in partial files are already off free space and are not
// counted twice. If short, one ReclaimUnderPressure pass runs and the check is
// repeated; still short is ErrInsufficientSpace.
//
// # Views
//
// Views (view.go) turns a recorded artifact into what a pod reads: a
// directory under <cache>/artifacts/<manifest-hex>/<PathSetKey(paths)> holding
// each selected layer under its file path. Each file is an APFS clone of the
// cache blob, a distinct inode sharing its blocks, so the view's mode and owner
// are its own and not the blob's (a hardlink would share them). The cloner is
// clone-only (image.CloneOnly): a volume that cannot clone (a different
// volume, a non-APFS filesystem) is ErrCrossVolume before any byte is copied,
// never a silent copy of a model, and NewViews refuses a views root on another
// device than the blob store at start. A view is built in a staging directory
// beside it, files 0444 and directories 0555 there, and renamed into place.
// Views are a rebuildable cache and are not fsynced: at daemon start, staging
// left by a crash is reaped and a published view that is not read-only is
// removed, to be rebuilt on next use.
//
// # Lifetime
//
// The artifact record is a GC root (image.Cache.Roots): while it exists, the
// cache never prunes or reclaims the blobs it names. Views.Forget removes the
// record, and with the last record of a manifest, that manifest's views; the
// blobs are then collectable like any unreferenced blob. The views of a
// manifest no record names any more (its record was replaced for a new
// manifest) are removed by the image prune (Views.SweepOrphans) and at start.
package artifact
