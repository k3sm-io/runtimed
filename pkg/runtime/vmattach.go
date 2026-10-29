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

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// vm pod re-attachment after a daemon restart.
//
// A vm pod's one host process is its k3sm-vmhost helper, and the helper
// survives a daemon exit (Close detaches it). attachVMPod is AttachPod's vm
// branch: it asks the vm backend to adopt the helper (sandbox AdoptVM, whose
// fail-closed predicate decides; a refusal leaves the helper to the startup
// sweep, which kills it as before) and rebuilds, from the spec the caller
// passes, what this daemon keeps for a running vm pod:
//
//   - the pod record and its published identity (the pod IP the node passes,
//     else the GuestNetworker's);
//   - one CRI log writer per container, on the instance file the previous
//     daemon was writing (the highest on disk), and its follower, resuming from
//     the last line already in that file so nothing the guest retained is
//     written twice;
//   - the ContainerEvents fold, which the guest answers with a replay of every
//     container's current state (the late-subscribe snapshot), so the statuses
//     are rebuilt from the guest itself, never guessed;
//   - the guest lease watcher and the helper exit watch.
//
// What is not rebuilt, and is said rather than invented: the image-pull outcome
// per container (no pull happened in this daemon's life, so the field is
// absent), and the container ids, which the replayed starts mint afresh because
// the fold stamps them with host time.
//
// The image ID IS rebuilt, from the LOCAL image index only (localVMImageID): the
// container's reference is resolved as a never-pull would resolve it, so no
// registry is contacted, and the digested reference is the one the create-time
// pull published. An image the index no longer holds leaves the ID empty; the
// attach does not fail over a status field.
//
// The container START is rebuilt, from the vm backend's persisted starts
// (vmContainerStartStore): each container's entry is seeded with the start and
// guest pid of the run its predecessor folded, and the replay of that same run
// keeps the seeded start, so a re-attached container does not read as
// restarted. COMPATIBILITY WINDOW: a helper whose starts were never persisted
// (spawned by a daemon from before they were, or a backend without the store)
// has nothing to seed, and its containers report the time the replay was
// folded, which is what every re-attach reported before; that start is
// persisted then, so the next restart keeps it.

// ErrVMHelperUnadoptable reports a vm pod whose recorded helper is still running
// its guest but is not owned by this runtime: another runtime holds the helper's
// record (sandbox.ErrVMHelperHeld), or the startup sweep was deferred
// (DeferVMSweep) and the helper was left running unadopted. AttachPod returns it
// wrapped together with ErrNothingToAttach, and CreatePod refuses such a pod
// with it, so the node never boots a second guest beside the live one.
//
// FAIL CLOSED, and the cost is stated: the pod is neither adopted nor created
// until the helper is adopted or stopped, which the next daemon start decides
// (or `k3sm stop`, which stops every recorded helper). A caller keeps the
// pod's address reserved meanwhile, because the live guest still answers on
// it.
var ErrVMHelperUnadoptable = errors.New("runtime: a live vm host helper for the pod cannot be adopted or stopped by this runtime")

// unadoptedHelperProber is the optional vm backend capability that names a
// pod's live helper this runtime does not own. *sandbox.VMBackend has it.
type unadoptedHelperProber interface {
	UnadoptedHelper(podID string) (pid int, ok bool)
}

// vmContainerStartStore is the optional vm backend capability that persists
// each guest container's start beside the helper's record (sandbox
// vmstarts.go), so a daemon that adopts the helper reports the container's real
// start. *sandbox.VMBackend has it; a backend without it persists nothing, and
// its re-attached containers report the time the guest's replay was folded.
// It is optional, not part of VMBackend, so consumers' own VMBackend fakes keep
// compiling.
type vmContainerStartStore interface {
	RecordVMContainerStart(podID, container string, start sandbox.VMContainerStart) error
	VMContainerStarts(podID string) map[string]sandbox.VMContainerStart
}

// The shipped backend must persist the starts, or every re-attach reports a
// moved start again.
var _ vmContainerStartStore = (*sandbox.VMBackend)(nil)

// refuseBesideUnadoptedHelper returns ErrVMHelperUnadoptable (wrapped) for a vm
// pod whose recorded helper is alive and unowned, and nil otherwise.
func (r *Runtime) refuseBesideUnadoptedHelper(box *runtimev1.PodBox) error {
	if box.GetSandboxProfile().GetBackend() != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return nil
	}
	pr, ok := r.vmBackend.(unadoptedHelperProber)
	if !ok {
		return nil
	}
	pid, live := pr.UnadoptedHelper(box.GetPodId())
	if !live {
		return nil
	}
	r.log.Warn("not creating a vm pod while an earlier helper it cannot adopt still runs its guest",
		"pod", box.GetPodId(), "pid", pid)
	return fmt.Errorf("create pod %s: helper pid %d: %w", box.GetPodId(), pid, ErrVMHelperUnadoptable)
}

// attachedVMPodMessage is the status message of a vm pod re-attached after a
// daemon restart.
const attachedVMPodMessage = "re-attached after a runtime daemon restart: the guest kept running"

// attachVMPod re-attaches a vm pod whose helper survived a daemon restart. See
// the file header; the ordering contract is AttachPod's.
func (r *Runtime) attachVMPod(ctx context.Context, box *runtimev1.PodBox) (*runtimev1.PodStatus, error) {
	podID := box.GetPodId()
	podIP := box.GetPodIp()
	if podIP == "" {
		if nc := r.guestNetworkConfig(podID); nc.PodIP.IsValid() {
			podIP = nc.PodIP.String()
		}
	}
	if podIP == "" {
		// The vm spine has no IPAM of its own, and a pod without its published
		// address is unroutable; createVMPod refuses one too.
		return nil, fmt.Errorf("attach pod %s: no pod IP to keep: %w", podID, ErrNothingToAttach)
	}
	if err := r.vmBackend.AdoptVM(ctx, podID); err != nil {
		if errors.Is(err, sandbox.ErrVMHelperHeld) {
			return nil, fmt.Errorf("attach pod %s: %w: %w: %w", podID, ErrNothingToAttach, ErrVMHelperUnadoptable, err)
		}
		return nil, fmt.Errorf("attach pod %s: %w: %w", podID, ErrNothingToAttach, err)
	}

	var starts map[string]sandbox.VMContainerStart
	if store, ok := r.vmBackend.(vmContainerStartStore); ok {
		starts = store.VMContainerStarts(podID)
	}

	attachedAt := time.Now()
	podCtx, podCancel := context.WithCancel(context.Background())
	p := &pod{
		box:        box,
		backend:    runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
		phase:      runtimev1.PodPhase_POD_PHASE_RUNNING,
		message:    attachedVMPodMessage,
		podIP:      podIP,
		supCtx:     podCtx,
		cancel:     podCancel,
		adopted:    true,
		attachedAt: attachedAt,
	}
	ordered := vmContainerOrder(box)
	p.guestLogs = make(map[string]*crilog.Writer, len(ordered))
	p.guestLogResume = make(map[string]time.Time, len(ordered))
	p.guestAwaitingReplay = make(map[string]bool, len(ordered))
	for _, c := range ordered {
		name := c.spec.GetName()
		logDir := containerLogDir(box.GetLogDirectory(), name)
		// The instance the previous daemon was writing is the highest on disk:
		// one below the number a NEW instance would take. The status count
		// starts there too, so count and file name agree as they did.
		instance := int32(0)
		if next, err := restartCountFromLogDir(logDir); err == nil && next > 0 {
			instance = next - 1
		}
		path := filepath.Join(logDir, containerLogFile(instance))
		st := p.guestContainerLocked(name, c.spec.GetImage())
		st.RestartCount = instance
		st.ImageId = r.localVMImageID(ctx, podID, name, c.spec.GetImage())
		p.guestAwaitingReplay[name] = true
		if s, ok := starts[name]; ok && s.StartUnixNano != 0 {
			// The run the previous daemon folded. It is held beside the entry,
			// not written into its state: until the guest's replay says what
			// the container is, the entry stays stateless, as it was.
			if p.guestSeededStarts == nil {
				p.guestSeededStarts = map[string]sandbox.VMContainerStart{}
			}
			p.guestSeededStarts[name] = s
		}
		w, err := crilog.Open(path)
		if err != nil {
			r.log.Error("vm container output will not be recorded: its log file could not be re-opened",
				"pod", podID, "container", name, "path", path, "err", err)
			continue
		}
		p.guestLogs[name] = w
		st.LogPath = w.Path()
		if at, ok := lastCRILogStamp(path); ok {
			p.guestLogResume[name] = at
		}
	}
	recordEphemeralNotStartedLocked(p)

	// Register under r.mu in one step with the podReapStarted check, as the
	// host-process branch does. A pod that cannot be installed has had its
	// helper adopted already, and the startup sweep will not see it again, so
	// it is stopped here, at once: the kill the sweep would have done.
	r.mu.Lock()
	if r.podReapStarted {
		r.mu.Unlock()
		podCancel()
		r.closeContainerLogs(p)
		if err := r.vmBackend.StopVM(ctx, podID, 0); err != nil {
			r.log.Warn("stop an adopted vm host helper whose attach lost the race to the startup reap", "pod", podID, "err", err)
		}
		return nil, fmt.Errorf("attach pod %s: the startup reap began during the attach: %w", podID, ErrNothingToAttach)
	}
	if cur, ok := r.pods[podID]; ok {
		r.mu.Unlock()
		podCancel()
		r.closeContainerLogs(p)
		return r.podStatus(cur), nil
	}
	r.pods[podID] = p
	r.mu.Unlock()

	for _, c := range ordered {
		if p.guestLogs[c.spec.GetName()] != nil {
			r.startGuestLogFollower(p, c.spec.GetName())
		}
	}
	go r.watchVMPodEvents(podCtx, p)
	go r.watchVMHelperExit(podCtx, p)
	r.armGuestLeaseWatcher(p)

	st := r.podStatus(p)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED, st)
	return st, nil
}

// localVMImageID returns the image_id a re-attached vm container publishes:
// repoDigestImageID over ref resolved against this node's LOCAL image index, or
// empty when the index cannot answer. It pulls under IMAGE_PULL_POLICY_NEVER,
// which the puller answers from its index without a registry round trip (and
// without credentials, which a presence check does not need), so a daemon
// restart never turns into image traffic. The lease the answer comes back
// holding is released at once: the pod's own image record, written when the pod
// was created, is what keeps the blobs reachable, and nothing is recorded here.
//
// Every failure, an image the index no longer holds included, is an empty ID
// and a debug line, never an attach failure: the guest is running regardless,
// and an empty image_id is the visible degradation repoDigestImageID documents.
func (r *Runtime) localVMImageID(ctx context.Context, podID, name, ref string) string {
	if ref == "" {
		return ""
	}
	res, err := r.puller.Pull(ctx, ref, nil,
		pullPolicy(runtimev1.SandboxBackend_SANDBOX_BACKEND_VM),
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER)
	if err != nil {
		r.log.Debug("re-attached vm container reports no image id: its image is not in the local index",
			"pod", podID, "container", name, "image", ref, "err", err)
		return ""
	}
	res.Lease.Release()
	return repoDigestImageID(ref, res)
}

// lastCRILogStamp returns the timestamp of the last complete line in a CRI log
// file, reading only its tail, and whether there was one.
func lastCRILogStamp(path string) (time.Time, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return time.Time{}, false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return time.Time{}, false
	}
	const window = 64 << 10
	off := max(fi.Size()-window, 0)
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return time.Time{}, false
	}
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	} else if off > 0 {
		return time.Time{}, false // one line longer than the window: no start in view
	}
	stamp, _, ok := bytes.Cut(buf, []byte{' '})
	if !ok {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, string(stamp))
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}
