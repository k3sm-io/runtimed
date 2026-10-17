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
		return nil, fmt.Errorf("attach pod %s: %w: %w", podID, ErrNothingToAttach, err)
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
