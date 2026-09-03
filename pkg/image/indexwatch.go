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

package image

import (
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// IndexChangeOp is what happened to one (reference x platform) index entry.
type IndexChangeOp int

const (
	// IndexRecorded is an entry written: a pull, an ingest, or a tag. It is
	// reported for a REPLACEMENT of an existing key as well as for a new one —
	// Record replaces by key, and an observer that treated a replacement as a
	// no-op would keep serving the previous manifest digest for a name that now
	// resolves elsewhere.
	IndexRecorded IndexChangeOp = iota
	// IndexRemoved is an entry deleted: an untag. It is reported only when an
	// entry was actually there to delete — Remove reports false for an absent
	// key, and a notification for a removal that removed nothing would be a
	// change that never happened.
	IndexRemoved
)

// String renders the operation for logs.
func (o IndexChangeOp) String() string {
	switch o {
	case IndexRecorded:
		return "recorded"
	case IndexRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// IndexChange describes one COMMITTED mutation of the local image index.
//
// It is a fact about a change that has already happened: it is delivered after
// the entry is durably written or unlinked, never before, so an observer that
// reads the index on receipt sees at least the state the change announced.
type IndexChange struct {
	// Op is what happened.
	Op IndexChangeOp
	// Reference is the pull reference the entry is keyed under — the spelling
	// the user asked for, never a rewritten mirror or node-registry spelling.
	Reference string
	// Platform is the other half of the entry's key — exactly the key the
	// mutation wrote or unlinked (Record normalises before it files, Remove
	// unlinks the key it was handed), so an observer can look the entry up with
	// it and get the record the change is about.
	Platform Platform
	// Descriptor is the manifest descriptor the entry now resolves to.
	//
	// Set for IndexRecorded when the recorded entry carried one (it is optional
	// — see IndexEntry.Descriptor). ALWAYS nil for IndexRemoved: a removal is
	// keyed, and reading the entry back to describe what vanished would be a
	// second, racing read of a record that is already gone. An observer that
	// needs the full picture takes a snapshot; this type reports only what the
	// mutation itself knew.
	Descriptor *runtimev1.Descriptor
}

// IndexObserver is notified after the local image index changes.
//
// It is a CONSUMER-SIDE seam per the standards, and it is deliberately the
// narrowest one that answers the question an embedder actually has — "did what
// this node holds just change?" — because that is the whole of what this package
// may know. runtimed neither reads nor writes an apiserver, so an observer here
// learns nothing about one: the embedding control plane (k3sm) supplies an
// implementation that does whatever publishing it wants, and this package stays
// unable to name that destination.
//
// A nil observer is the default and the complete, correct standalone behavior:
// nothing is called, and the index behaves exactly as it did before this seam
// existed.
//
// # The contract an implementation must honour
//
// ImageIndexChanged is called SYNCHRONOUSLY, on the goroutine that performed the
// mutation, after the mutation is committed and after every file handle the
// mutation used is closed. It holds no lock of this package's — FileIndex takes
// none, its writes being atomic temp+rename — so an implementation may call back
// into the index (List, Lookup) without deadlocking.
//
// It must NOT BLOCK. A pull, a load and an untag all sit behind it, so an
// observer that does slow work inline stalls the RPC that caused the change. An
// implementation that needs to do real work should hand the change to its own
// buffered worker and return; delivery is therefore best-effort by construction
// and an observer must be able to recover from a missed change by taking a
// snapshot (Runtime.ImageIndexSnapshot), never by assuming it saw every event.
//
// It must not PANIC. The mutation has already committed when it runs, so a
// panic here does not corrupt the index — but it does unwind the caller's RPC,
// which is a failure the operator would read as a broken pull.
type IndexObserver interface {
	// ImageIndexChanged reports one committed mutation of the local index.
	ImageIndexChanged(change IndexChange)
}

// FileIndexOption adjusts a FileIndex at construction.
type FileIndexOption func(*FileIndex)

// WithIndexObserver notifies obs after every committed index mutation.
//
// It is a CONSTRUCTION-time option and there is deliberately no setter: the
// observer is then immutable for the index's lifetime, which is what makes the
// notification path lock-free and race-free without a mutex on the hot path of
// every pull. A daemon has exactly one embedder, wired once at startup, so the
// flexibility a setter would buy is flexibility nothing needs.
//
// A nil obs is the default and disables notification entirely.
func WithIndexObserver(obs IndexObserver) FileIndexOption {
	return func(x *FileIndex) { x.observer = obs }
}

// notify delivers one change to the observer, if there is one.
//
// It is called from the exported mutators AFTER the inner write has returned and
// its os.Root has been closed, which is the whole reason those mutators are thin
// wrappers around unexported bodies: a notification fired from inside the write
// would run with the index directory still open and, more importantly, would run
// before the mutation was structurally complete.
func (x *FileIndex) notify(c IndexChange) {
	if x.observer == nil {
		return
	}
	x.observer.ImageIndexChanged(c)
}
