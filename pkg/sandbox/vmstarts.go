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

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Guest container start times, kept beside the helper record.
//
// A vm container's running.startedAt is the host time at which the runtime
// first folded the guest's start of that run. The guest's own clock is never
// used for it (see pkg/runtime's applyGuestContainerEvent), so after a daemon
// restart the guest's replay cannot supply it: the next daemon would stamp the
// replay time, and the container would read as restarted. The start is
// therefore persisted here, in the same daemon-private store as the helper's
// record, and the adopting daemon seeds it back.
//
// It is a SEPARATE file (<pgid>.starts), not a field of the record, because
// the record must not be rewritten while its helper lives: the owning daemon
// holds an flock on the record's open file, which a rename-over would detach
// from the path (a second runtime could then lock the new file and adopt the
// helper beside its owner), and an in-place rewrite torn by a crash would turn
// the record into a quarantined file, leaving a live guest that no sweep can
// name. This file drives no signal and no delete: losing it only loses the
// start times, and a container then reports the time its start was folded
// again, which is what every daemon reported before this file existed.
//
// The file is bound to one helper instance by the helper's start time, so a
// file left behind for a pgid the kernel later recycles is never read for the
// new helper.

// vmStartsExt is the container-start file's extension. It is deliberately not
// ".json": listVMProcRecords reads every *.json in the store as a record.
const vmStartsExt = ".starts"

// vmStartsTmpExt is appended to a container-start file's path for the temp
// file it is written through.
const vmStartsTmpExt = ".tmp"

// maxVMStartsFileBytes bounds the read of a container-start file.
const maxVMStartsFileBytes = 1 << 20

// VMContainerStart is the start of a guest container's current run, as the
// runtime first folded it: the guest pid of the run and the host time, in Unix
// nanoseconds, at which the runtime observed the start.
type VMContainerStart struct {
	Pid           int32 `json:"pid"`
	StartUnixNano int64 `json:"startUnixNano"`
}

// vmContainerStarts is the on-disk shape of a container-start file.
type vmContainerStarts struct {
	// HelperStartUnixNano is the start of the helper instance the file
	// belongs to (vmProcRecord.StartUnixNano).
	HelperStartUnixNano int64                       `json:"helperStartUnixNano"`
	Containers          map[string]VMContainerStart `json:"containers"`
}

// vmStartsPath is the container-start file of the helper with pgid, or "" when
// the store is disabled.
func (b *VMBackend) vmStartsPath(pgid int) string {
	root := b.vmReapRoot()
	if root == "" {
		return ""
	}
	return filepath.Join(root, strconv.Itoa(pgid)+vmStartsExt)
}

// removeVMStarts drops the helper's container-start file. Best-effort, like
// removeVMProcRecord: a leftover file is bound to a helper start no new helper
// can have.
func (b *VMBackend) removeVMStarts(pgid int) {
	if path := b.vmStartsPath(pgid); path != "" {
		_ = os.Remove(path)
	}
}

// liveHelper returns the pod's live helper, or nil.
func (b *VMBackend) liveHelper(podID string) *vmProc {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.live[podID]
}

// readVMStarts reads the container-start file of vp, or an empty set when
// there is none or it belongs to another helper instance.
func (b *VMBackend) readVMStarts(vp *vmProc) (map[string]VMContainerStart, error) {
	path := b.vmStartsPath(vp.pgid)
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxVMStartsFileBytes))
	if err != nil {
		return nil, err
	}
	var file vmContainerStarts
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.HelperStartUnixNano != vp.startUnixNano {
		return nil, nil
	}
	return file.Containers, nil
}

// RecordVMContainerStart persists the start of a guest container's current run
// for the pod's live helper, replacing the container's earlier entry. A pod
// with no live helper, or a backend with no state root, records nothing.
func (b *VMBackend) RecordVMContainerStart(podID, container string, start VMContainerStart) error {
	vp := b.liveHelper(podID)
	if vp == nil {
		return nil
	}
	path := b.vmStartsPath(vp.pgid)
	if path == "" {
		return nil
	}
	b.startsMu.Lock()
	defer b.startsMu.Unlock()
	starts, err := b.readVMStarts(vp)
	if err != nil {
		// An unreadable file is replaced: it holds nothing this helper can use.
		b.logger().Warn("replacing an unreadable vm container-start file", "pod", podID, "path", path, "err", err)
		starts = nil
	}
	if starts == nil {
		starts = map[string]VMContainerStart{}
	}
	starts[container] = start
	data, err := json.Marshal(vmContainerStarts{HelperStartUnixNano: vp.startUnixNano, Containers: starts})
	if err != nil {
		return fmt.Errorf("marshal the container starts of pod %s: %w", podID, err)
	}
	if err := writeVMStartsFile(path, data); err != nil {
		return fmt.Errorf("persist the container starts of pod %s: %w", podID, err)
	}
	return nil
}

// writeVMStartsFile replaces path with data durably and without following a
// symlink: a fresh temp file (O_EXCL|O_NOFOLLOW, a stale one removed first
// unless it is a symlink, which is refused), written and fsynced, renamed over
// path, and the directory fsynced so the rename survives a crash.
func writeVMStartsFile(path string, data []byte) error {
	tmp := path + vmStartsTmpExt
	if fi, err := os.Lstat(tmp); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing the temp file %s: it is a symlink", tmp)
		}
		if err := os.Remove(tmp); err != nil {
			return fmt.Errorf("remove the stale temp file %s: %w", tmp, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect the temp file %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit %s: %w", path, err)
	}
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open the store directory to sync it: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync the store directory: %w", err)
	}
	return nil
}

// sweepStrayVMStarts removes, from the record store, every container-start
// temp file and every container-start file whose record no longer exists:
// what a daemon that died between the two removals, or mid-write, left
// behind. It holds startsMu, so a write an adopted pod's fold has in flight
// is never cut under it. ReapOrphanVMs calls it after the records are settled.
func (b *VMBackend) sweepStrayVMStarts() {
	root := b.vmReapRoot()
	if root == "" {
		return
	}
	b.startsMu.Lock()
	defer b.startsMu.Unlock()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(root, name)
		switch {
		case strings.HasSuffix(name, vmStartsExt+vmStartsTmpExt):
			_ = os.Remove(path)
		case strings.HasSuffix(name, vmStartsExt):
			record := filepath.Join(root, strings.TrimSuffix(name, vmStartsExt)+".json")
			if _, err := os.Lstat(record); errors.Is(err, os.ErrNotExist) {
				_ = os.Remove(path)
			}
		}
	}
}

// VMContainerStarts returns the persisted container starts of the pod's live
// helper, keyed by container name: what an adopting daemon seeds its statuses
// with. It is empty for a pod with no live helper, for a helper whose file is
// absent (a helper spawned before the file existed, or one whose containers
// never started), and for a file that belongs to another helper instance.
func (b *VMBackend) VMContainerStarts(podID string) map[string]VMContainerStart {
	vp := b.liveHelper(podID)
	if vp == nil {
		return nil
	}
	b.startsMu.Lock()
	defer b.startsMu.Unlock()
	starts, err := b.readVMStarts(vp)
	if err != nil {
		b.logger().Warn("the vm container-start file cannot be read; the containers report their replay time as their start",
			"pod", podID, "err", err)
		return nil
	}
	return starts
}
