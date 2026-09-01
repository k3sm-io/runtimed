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

package guestagent

import (
	"sync"
	"time"
)

// DefaultEventQueue bounds one ContainerEvents subscriber's backlog. A pod has few
// containers and each produces a handful of transitions, so a backlog this deep
// means the subscriber has stopped reading rather than that it is briefly behind.
const DefaultEventQueue = 64

// ContainerEvent is one container lifecycle transition, in the shape guest/v1's
// ContainerEvent carries. Exactly one of Started or Exited is set — the
// optional-field union the proto uses rather than a oneof.
type ContainerEvent struct {
	// Container is the container name within the pod.
	Container string
	// At is when the guest observed the transition.
	At time.Time
	// Started is set for a spawn.
	Started *ContainerStarted
	// Exited is set for a terminal outcome.
	Exited *ContainerExited
}

// ContainerStarted reports that a container's process was spawned in the guest.
type ContainerStarted struct {
	// PID is the process id inside the guest. It is useful only for guest-side
	// correlation — it means nothing to the host's process table.
	PID int32
}

// ContainerExited reports a container's terminal outcome.
type ContainerExited struct {
	// ExitCode is the process exit status when it exited normally.
	ExitCode int32
	// Signal is the terminating signal number when it was killed, else 0. It is
	// LINUX's numbering, because a Linux kernel produced it.
	Signal int32
	// OOMKilled is true when the guest kernel's cgroup OOM killer ended it.
	//
	// this field is the only source of OOM truth for a vm pod. The kill happens
	// in the guest's cgroup, which the host cannot observe at all: its
	// proc_pid_rusage sampler sees the VM host helper's footprint and nothing
	// inside. A host-derived OOMKilled for a vm pod would be a guess dressed as a
	// kernel fact, and upstream treats OOMKilled as the pod's own fault — it
	// restarts it and counts it against a Job's backoff.
	OOMKilled bool
}

// Events is the ContainerEvents fan-out: the guest's reaper publishes transitions,
// and each ContainerEvents stream subscribes.
//
// DROP-and-MARK, never BLOCK. Publish is called from the guest's reap path — PID
// 1's only reaping loop — so a subscriber that has stopped reading must not be able
// to stall it. A stalled reaper means unreaped zombies, and in a pid namespace
// there is no other process to inherit them. So a full subscriber queue drops the
// event and marks the subscriber lossy; the subscriber is told, and the reaper
// keeps reaping.
//
// The zero value is not usable; construct one with NewEvents.
type Events struct {
	queueSize int

	mu     sync.Mutex
	subs   map[*eventSub]struct{}
	closed bool
}

// eventSub is one subscriber's queue plus its loss flag.
type eventSub struct {
	ch chan ContainerEvent
	// lossy is set once an event was dropped for this subscriber. It is read by
	// Lossy so the stream can end with a stated reason instead of silently
	// omitting a transition — and for a ContainerEvents stream a dropped event
	// can be the pod's only OOMKilled notice.
	lossy bool
}

// NewEvents builds a fan-out with the given per-subscriber queue depth;
// non-positive takes DefaultEventQueue.
func NewEvents(queueSize int) *Events {
	if queueSize <= 0 {
		queueSize = DefaultEventQueue
	}
	return &Events{queueSize: queueSize, subs: map[*eventSub]struct{}{}}
}

// Publish delivers ev to every live subscriber, never blocking. See the type doc.
func (e *Events) Publish(ev ContainerEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	for s := range e.subs {
		select {
		case s.ch <- ev:
		default:
			s.lossy = true
		}
	}
}

// Subscription is one ContainerEvents stream's view of the fan-out.
type Subscription struct {
	events *Events
	sub    *eventSub
	once   sync.Once
}

// C is the subscriber's event channel. It is closed when the fan-out closes.
func (s *Subscription) C() <-chan ContainerEvent { return s.sub.ch }

// Lossy reports whether any event was dropped for this subscriber. A stream that
// ends must say so rather than let a missing OOMKilled look like a clean exit.
func (s *Subscription) Lossy() bool {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	return s.sub.lossy
}

// Close unsubscribes. It is idempotent: a stream can end from the client side or
// because the guest is shutting down, and both paths call it.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.events.mu.Lock()
		delete(s.events.subs, s.sub)
		s.events.mu.Unlock()
	})
}

// Subscribe registers a new subscriber.
func (e *Events) Subscribe() *Subscription {
	sub := &eventSub{ch: make(chan ContainerEvent, e.queueSize)}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		close(sub.ch)
		return &Subscription{events: e, sub: sub}
	}
	e.subs[sub] = struct{}{}
	e.mu.Unlock()
	return &Subscription{events: e, sub: sub}
}

// Close ends every subscription. It is called when the guest is shutting down, so
// a host watching ContainerEvents sees end-of-stream rather than a hang.
func (e *Events) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	for s := range e.subs {
		close(s.ch)
		delete(e.subs, s)
	}
}
