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
// channel plus a cancel func that unregisters and closes the channel. The caller
// (WatchPodStatus) should send any current snapshots after subscribing.
func (b *broker) subscribe(podID string) (<-chan *runtimev1.PodStatusEvent, func()) {
	b.mu.Lock()
	id := b.next
	b.next++
	sub := &subscription{podID: podID, ch: make(chan *runtimev1.PodStatusEvent, 64)}
	b.subs[id] = sub
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		if s, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(s.ch)
		}
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
