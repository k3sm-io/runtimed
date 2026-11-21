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

import "path/filepath"

// The daemon-private work-dir subtrees, in one place.
//
// Every directory a confined pod must never read or write is named by exactly
// one of the two ordered lists below, and resolvePosture builds the deny-set by
// iterating them — so a tree added to a list gets its validation rejection, its
// emitted (deny ...) in both firmlink forms, and its line in the rendered
// ";; PROTECTED:" header at once. Nothing enumerates these names by hand.
//
// Some of the names are owned by another package (pkg/image, pkg/guestartifacts)
// and are MIRRORED here as consts rather than imported: pkg/guestartifacts
// imports pkg/sandbox, so importing it back would be a cycle, and pkg/sandbox is
// deliberately a leaf — the SBPL generator must not grow a dependency on the
// image store to be able to deny it. The mirrors are kept honest mechanically
// rather than by convention: pkg/runtime imports all three packages and
// TestEveryDaemonPrivateSubdirIsDenied asserts each mirror equals the const it
// mirrors AND that every exported *Subdir in those packages appears in one of
// the lists. A new *Subdir const anywhere means a new entry there and here.
//
// <WorkDir>/storage is the one documented exemption: it is the parent of every
// pod's legitimate PVC dir and the denies are emitted after the PV allows, so
// denying it would clobber every legitimate write grant (see resolvePosture).

const (
	// ImageIndexSubdir mirrors image.IndexSubdir: the ref->digest index
	// (<WorkDir>/index) recording what this daemon pulled and verified. A pod
	// able to write here can make a reference resolve to another image's blobs,
	// which is what IfNotPresent then serves with no registry traffic.
	ImageIndexSubdir = "index"
	// ImageOperatorSubdir mirrors image.OperatorSubdir: the operator
	// reachability record (<WorkDir>/operator) the image GC reads to decide what
	// is collectable. A pod able to write here chooses what the GC deletes.
	ImageOperatorSubdir = "operator"
	// ImageUnpackedSubdir mirrors image.UnpackedSubdir: the per-image unpacked
	// trees (<WorkDir>/unpacked) every pod rootfs is APFS-cloned from. A tree is
	// verified when it is committed and never re-verified at clone time, so a pod
	// able to write here chooses the bytes the next pod executes.
	ImageUnpackedSubdir = "unpacked"
	// ImageSnapshotsSubdir mirrors image.SnapshotsSubdir: the ChainID-keyed
	// snapshot store (<WorkDir>/snapshots) the Linux dialect's guest rootfs
	// shares are named by. Same unverified-at-use property as unpacked/.
	ImageSnapshotsSubdir = "snapshots"
	// ImageIngestSubdir mirrors image.IngestSubdir: the staging dir
	// (<WorkDir>/ingest) a streamed archive is read through before its blobs are
	// digest-verified into the store.
	ImageIngestSubdir = "ingest"
	// GuestArtifactsSubdir mirrors guestartifacts.GuestArtifactsSubdir: the
	// sha-keyed guest-artifact cache (<WorkDir>/guest-artifacts) holding the
	// pinned kernel and initramfs every vm pod boots. The artifacts are verified
	// when the set is ensured, so write access here is an availability attack on
	// every vm pod on the node — a corrupted set makes the vm capability fail
	// closed until an operator clears it by hand.
	GuestArtifactsSubdir = "guest-artifacts"
	// ArtifactPartialSubdir is the staging dir (<WorkDir>/artifact-partial)
	// resumable OCI artifact layers download into before their digest is
	// verified and they are committed to the blob store. A pod able to read here
	// reads another workload's model weights mid-transfer; one able to write
	// here makes every resume of that layer fail its digest check.
	ArtifactPartialSubdir = "artifact-partial"
	// ImagePartialSubdir mirrors image.PartialSubdir: the staging dir
	// (<WorkDir>/image-partial) an image layer cut mid-fetch keeps its received
	// bytes in until the next pull resumes and commits it. A pod able to read
	// here reads another workload's layer mid-transfer; one able to write here
	// makes every resume of that layer fail its digest check.
	ImagePartialSubdir = "image-partial"
	// ArtifactViewsSubdir is the root (<WorkDir>/artifacts) of the read-only
	// artifact views: one directory of cloned files per manifest and path set.
	// The root is denied as a whole; a pod is granted the one view directory it
	// mounts, never the root, so it cannot open a file in another model's view
	// or reach a view still being built in a staging directory beside it.
	ArtifactViewsSubdir = "artifacts"
	// XcodeCacheSubdir is the per-node Xcode build cache
	// (<WorkDir>/xcode-cache/<namespace>/<key>/<Xcode build>/home-cache, see
	// pkg/xcodecache). Only the daemon reads or writes it: a pod receives a
	// private copy-on-write clone inside its own data volume at create and never
	// reaches the shared snapshot, so a pod cannot read another namespace's
	// build products or write a snapshot directly. What a pod that succeeded
	// leaves in its home is published for its own namespace and key (see
	// pkg/xcodecache on that trust boundary).
	XcodeCacheSubdir = "xcode-cache"
)

// ReapStoreSubdirs returns the work-dir-relative reap-store dirs, in deny order:
// the stores whose records drive a ROOT-PRIVILEGED action against a process
// group or a run dir — podreap's kill(-pgid) (pkg/runtime) and vmreap's helper
// SIGKILL plus the RemoveAll of the record's run dir (vmreap.go). A forged
// record is therefore not a disclosure but a primitive, which is why these are
// stated apart from the merely daemon-private trees below.
//
// The returned slice is freshly allocated, so a caller cannot mutate the
// deny-set by holding on to it.
func ReapStoreSubdirs() []string {
	return []string{PodReapSubdir, VMReapSubdir}
}

// SharedVolumeTempSubdir is the directory at a volume's root where Foundation
// stages atomic writes for files on that volume when it is not the user temp
// dir's volume (<volume root>/.TemporaryItems/folders.<uid>). The work-dir's and
// the work volume's are denied to every pod (resolvePosture); the runtime has
// the path-rebase shim point each pod at a path in its own tree instead.
const SharedVolumeTempSubdir = ".TemporaryItems"

// SharedVolumeTempDir returns the shared replacement directory of the volume
// mounted at mountPoint (as statfs spells it), and false for the root and data
// volumes, where Foundation uses the user temp dir instead, and for an empty
// mount point. It is the one definition the profile's deny and the runtime's
// rebase are both built from.
func SharedVolumeTempDir(mountPoint string) (string, bool) {
	switch mountPoint {
	case "", "/", "/System/Volumes/Data":
		return "", false
	}
	return filepath.Join(mountPoint, SharedVolumeTempSubdir), true
}

// DaemonTreeSubdirs returns the work-dir-relative daemon-private and
// control-plane trees, in deny order: the control-plane state (server), the
// node-agent state (agent), the daemon sockets + mesh key (run), the
// content-addressed blob store (blobs), the status record dir (status), the
// per-pod SBPL staging dir (sbpl), the five image-store siblings (index,
// operator, unpacked, snapshots, ingest), the guest-artifact cache
// (guest-artifacts), the artifact download staging dir (artifact-partial), the
// image layer download staging dir (image-partial), the artifact views root
// (artifacts) and the retained consoles of failed vm boots
// (vmboot-failures), which hold other pods' guest output, and the shared
// Xcode build cache (xcode-cache), which holds every namespace's build products.
//
// The returned slice is freshly allocated, so a caller cannot mutate the
// deny-set by holding on to it.
func DaemonTreeSubdirs() []string {
	return []string{
		ServerSubdir,
		AgentSubdir,
		RunSubdir,
		BlobsSubdir,
		StatusSubdir,
		ProfileSubdir,
		ImageIndexSubdir,
		ImageOperatorSubdir,
		ImageUnpackedSubdir,
		ImageSnapshotsSubdir,
		ImageIngestSubdir,
		GuestArtifactsSubdir,
		ArtifactPartialSubdir,
		ImagePartialSubdir,
		ArtifactViewsSubdir,
		VMBootFailureSubdir,
		XcodeCacheSubdir,
	}
}
