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
	"sync"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// broker fans pod-status events out to WatchPodStatus subscribers. It is the
// event-driven backbone the VK PodNotifier consumes (no polling): publishers
// (CreatePod, the reaper, DeletePod) call publish; each subscriber gets a
// buffered channel and the current snapshot on subscribe.
//
// Concurrency: mu guards subs. publish copies the subscriber list under the lock
// then sends OUTSIDE the lock (a slow/closed subscriber must not block
// publishers or other subscribers); sends are non-blocking (drop on full buffer,
// the subscriber re-reads current state on reconnect).
type broker struct {
	mu   sync.Mutex
	next int
	subs map[int]*subscription
}

type subscription struct {
	// podID filters events; "" means all pods.
	podID string
	ch    chan *runtimev1.PodStatusEvent
}

// newBroker returns an empty broker.
func newBroker() *broker {
	return &broker{subs: make(map[int]*subscription)}
}

// subscribe registers a watcher for podID ("" = all pods) and returns its event
// channel plus a cancel func that unregisters the subscriber. The caller
// (WatchPodStatus) should send any current snapshots after subscribing and
// terminates on its own ctx (not on a channel close — see cancel).
func (b *broker) subscribe(podID string) (<-chan *runtimev1.PodStatusEvent, func()) {
	b.mu.Lock()
	id := b.next
	b.next++
	sub := &subscription{podID: podID, ch: make(chan *runtimev1.PodStatusEvent, 64)}
	b.subs[id] = sub
	b.mu.Unlock()

	// cancel only unregisters; it does NOT close ch. publish is the sender and
	// sends OUTSIDE the lock, so a receiver-side close would race a concurrent
	// send (send-on-closed-channel) — the "sender closes, never the receiver"
	// rule. The unreferenced buffered channel is GC'd once the consumer (which is
	// the sole reader and the caller of cancel) returns on its ctx.
	cancel := func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
	}
	return sub.ch, cancel
}

// publish delivers ev to every matching subscriber without blocking. The send is
// done outside the lock to avoid re-entrancy/deadlock; a full subscriber buffer
// drops the event (the subscriber recovers from the next snapshot).
func (b *broker) publish(ev *runtimev1.PodStatusEvent) {
	b.mu.Lock()
	targets := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		if s.podID == "" || s.podID == ev.GetStatus().GetPodId() {
			targets = append(targets, s)
		}
	}
	b.mu.Unlock()

	for _, s := range targets {
		select {
		case s.ch <- ev:
		default: // buffer full: drop; subscriber re-syncs on reconnect
		}
	}
}
