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

// DaemonTreeSubdirs returns the work-dir-relative daemon-private and
// control-plane trees, in deny order: the control-plane state (server), the
// node-agent state (agent), the daemon sockets + mesh key (run), the
// content-addressed blob store (blobs), the per-pod SBPL staging dir (sbpl), the
// five image-store siblings (index, operator, unpacked, snapshots, ingest) and
// the guest-artifact cache (guest-artifacts).
//
// The returned slice is freshly allocated, so a caller cannot mutate the
// deny-set by holding on to it.
func DaemonTreeSubdirs() []string {
	return []string{
		ServerSubdir,
		AgentSubdir,
		RunSubdir,
		BlobsSubdir,
		ProfileSubdir,
		ImageIndexSubdir,
		ImageOperatorSubdir,
		ImageUnpackedSubdir,
		ImageSnapshotsSubdir,
		ImageIngestSubdir,
		GuestArtifactsSubdir,
	}
}
