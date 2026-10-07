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

package execshim

import (
	"sync"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/crilog"
)

// logChunk is one chunk of output as the log writer saw it.
type logChunk struct {
	stream  crilog.Stream
	chunk   []byte
	partial bool
}

// fanout delivers chunks to live Follow subscribers. It retains nothing: a
// follower sees output from the moment it subscribed, and one that falls behind
// loses chunks rather than stalling the log writer.
type fanout struct {
	mu   sync.Mutex
	subs map[int]chan logChunk
	next int
}

func (f *fanout) publish(stream crilog.Stream, chunk []byte, partial bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.subs) == 0 {
		return
	}
	ent := logChunk{stream: stream, chunk: append([]byte(nil), chunk...), partial: partial}
	for _, ch := range f.subs {
		select {
		case ch <- ent:
		default:
		}
	}
}

func (f *fanout) subscribe() (<-chan logChunk, func()) {
	ch := make(chan logChunk, 256)
	f.mu.Lock()
	if f.subs == nil {
		f.subs = make(map[int]chan logChunk)
	}
	id := f.next
	f.next++
	f.subs[id] = ch
	f.mu.Unlock()
	return ch, func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}
}

// attachChunk renders a chunk for a follower: a chunk that ENDS a line (the CRI
// F tag) gets its newline back, a partial one is forwarded raw.
func attachChunk(ent logChunk) *runtimev1.AttachResponse {
	out := ent.chunk
	if !ent.partial {
		out = append(append(make([]byte, 0, len(ent.chunk)+1), ent.chunk...), '\n')
	}
	if ent.stream == crilog.StreamStderr {
		return &runtimev1.AttachResponse{Stderr: out}
	}
	return &runtimev1.AttachResponse{Stdout: out}
}
