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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"k3sm.io/runtimed/pkg/crilog"
)

// the CONTAINER LOG, host side: where a container's file lives, how its
// instance number is chosen, and the live fan-out `kubectl attach` reads from.
//
// runtimed is the WRITER and nothing else. It opens the file the node named
// (PodBox.log_directory), appends CRI-format lines to it, and reopens it when
// the node rotates it. It never reads one back, never rotates one, never
// deletes one, and keeps no in-memory copy of a container's output — the
// 256 KiB ring that used to serve GetLogs is gone, along with the truncation
// and the eviction it forced. The node owns the directory tree, the reader
// `kubectl logs` is served from, rotation, and every deletion, which is the
// same split the kubelet and containerd have upstream.

// logInstanceRe matches a container log file name: the instance number, plus
// whatever suffix rotation appended (`.20260913-103000`, `.gz`).
//
// The suffix arm is why this is a regexp rather than a TrimSuffix: after the
// node rotates, the highest-numbered file on disk may be `3.log.20260913-103000.gz`
// and nothing named plain `3.log` exists. A pattern that only matched `<n>.log`
// would read that directory as empty and hand the next container instance the
// number 0, whose file the rotated one would then be mistaken for by the very
// reader this numbering exists to serve. Ported from the kubelet's
// calcRestartCountByLogDir (pkg/kubelet/kuberuntime).
var logInstanceRe = regexp.MustCompile(`^(\d+)\.log(\..*)?$`)

// containerLogFile is the CRI log file name for instance n.
func containerLogFile(n int32) string { return strconv.FormatInt(int64(n), 10) + ".log" }

// containerLogDir is the directory holding one container's instance files:
// <PodBox.log_directory>/<container>. The node creates it; runtimed derives the
// same path rather than being told it twice.
func containerLogDir(logDirectory, container string) string {
	return filepath.Join(logDirectory, container)
}

// restartCountFromLogDir returns the instance number a NEW container instance
// should take given what is already in dir: one past the highest number found,
// or 0 when the directory is empty or absent.
//
// It is the kubelet's cold-start restart-count recovery (calcRestartCountByLogDir)
// performed by the writer, because on k3sm the writer is what picks the file
// name. Without it a daemon restart would re-open `0.log` for a container that
// had already run three times, appending the new instance's output onto the old
// instance's file — so `kubectl logs --previous` would serve a file holding two
// runs, and the status restart_count would disagree with the disk.
//
// An unreadable directory yields 0 with the error, which the caller logs and
// proceeds on: refusing to start a container because its log directory could
// not be listed would turn a cosmetic numbering problem into a pod failure.
func restartCountFromLogDir(dir string) (int32, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // a container that has never run: instance 0
		}
		return 0, fmt.Errorf("read container log dir %s: %w", dir, err)
	}
	highest := int32(-1)
	for _, e := range entries {
		m := logInstanceRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, perr := strconv.ParseInt(m[1], 10, 32)
		if perr != nil {
			continue // a number no int32 can hold is not an instance this daemon wrote
		}
		if int32(n) > highest {
			highest = int32(n)
		}
	}
	return highest + 1, nil
}

// logChunk is one chunk of a container's output as the live fan-out carries it:
// exactly what was written to the file, with its stream label and CRI partial
// tag intact.
type logChunk struct {
	stream  crilog.Stream
	chunk   []byte
	partial bool
}

// logFanout delivers a container's output chunks to live subscribers, and
// RETAINS NOTHING.
//
// Its one consumer is Attach, which is LIVE-ONLY: upstream's CRI attach
// bridges a client to a running container's stdio, and everything the container
// said before the attach is what `kubectl logs` is for — and now genuinely can
// serve, from the file. The retention this type deliberately lacks is the whole
// 256 KiB-per-container ring that used to exist for a GetLogs that no longer
// reads from memory.
//
// Concurrency: mu guards subs. publish is called from BOTH of a container's
// pump goroutines and sends non-blockingly, so a slow or abandoned subscriber
// loses chunks rather than stalling the pump — which, on a full pipe, would
// block the pod's own write(2).
type logFanout struct {
	mu      sync.Mutex
	subs    map[int]chan logChunk
	nextSub int
}

// publish fans one chunk out to every live subscriber. The chunk is copied
// once, here, and then shared: no subscriber may mutate what it receives.
func (f *logFanout) publish(stream crilog.Stream, chunk []byte, partial bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.subs) == 0 {
		return
	}
	ent := logChunk{stream: stream, chunk: append([]byte(nil), chunk...), partial: partial}
	for _, ch := range f.subs {
		select {
		case ch <- ent:
		default: // a slow follower drops chunks; it never stalls the log pump
		}
	}
}

// subscribe registers a follower that receives chunks written after the call,
// returning the channel and a cancel that deregisters it. The channel is
// buffered and is NOT closed by cancel (the consumer exits on its own ctx or
// the container's Done, never on a channel close), so there is no
// sender/receiver close race.
func (f *logFanout) subscribe() (<-chan logChunk, func()) {
	ch := make(chan logChunk, 256)
	f.mu.Lock()
	if f.subs == nil {
		f.subs = make(map[int]chan logChunk)
	}
	id := f.nextSub
	f.nextSub++
	f.subs[id] = ch
	f.mu.Unlock()
	return ch, func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}
}

// containerLogSink is the supervisor.LogSink for one container: it writes the
// chunk to the container's CRI log file and then fans it out to live attach
// subscribers.
//
// The ORDER is load-bearing. The file is the durable record and the fan-out is
// a courtesy, so the write goes first and its error is returned — which stops
// that stream's pump and closes its read end, handing the container an EPIPE
// (see crilog.Writer for why that beats a silent hang). Publishing first would
// let an attached terminal show output that never reached disk.
func containerLogSink(w *crilog.Writer, fan *logFanout) func(crilog.Stream, []byte, bool) error {
	return func(stream crilog.Stream, chunk []byte, partial bool) error {
		if err := w.Write(stream, chunk, partial); err != nil {
			return err
		}
		fan.publish(stream, chunk, partial)
		return nil
	}
}
