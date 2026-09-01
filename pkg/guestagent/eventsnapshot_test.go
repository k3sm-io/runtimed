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
	"context"
	"sync"
	"testing"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
)

// TestEventsReplaysStateToALateSubscriber is the gate on the defect that left a
// demonstrably running vm pod at Pending with no containerStatuses at all.
//
// The guest starts its containers and only THEN serves the agent, so every
// ContainerStarted was published to an empty subscriber set and lost; the host
// subscribed afterwards and was streamed only what happened next, which for a pod
// that had finished starting was nothing. The same hole re-opened on every
// resubscribe.
func TestEventsReplaysStateToALateSubscriber(t *testing.T) {
	started := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	exited := started.Add(time.Minute)

	cases := []struct {
		name string
		// published is what the guest publishes BEFORE anyone subscribes.
		published []ContainerEvent
		want      []ContainerEvent
	}{
		{
			name:      "nothing-published-yet-replays-nothing",
			published: nil,
			want:      nil,
		},
		{
			name: "a-running-container-replays-with-its-real-pid-and-start-time",
			published: []ContainerEvent{
				{Container: "app", At: started, Started: &ContainerStarted{PID: 93}},
			},
			want: []ContainerEvent{
				{Container: "app", At: started, Started: &ContainerStarted{PID: 93}},
			},
		},
		{
			name: "an-exited-container-replays-its-terminal-event-not-its-start",
			published: []ContainerEvent{
				{Container: "init", At: started, Started: &ContainerStarted{PID: 7}},
				{Container: "init", At: exited, Exited: &ContainerExited{ExitCode: 0}},
			},
			want: []ContainerEvent{
				{Container: "init", At: exited, Exited: &ContainerExited{ExitCode: 0}},
			},
		},
		{
			name: "an-oom-kill-survives-to-the-replay",
			published: []ContainerEvent{
				{Container: "app", At: started, Started: &ContainerStarted{PID: 11}},
				{Container: "app", At: exited, Exited: &ContainerExited{ExitCode: 137, Signal: 9, OOMKilled: true}},
			},
			want: []ContainerEvent{
				{Container: "app", At: exited, Exited: &ContainerExited{ExitCode: 137, Signal: 9, OOMKilled: true}},
			},
		},
		{
			name: "several-containers-replay-in-first-seen-order",
			published: []ContainerEvent{
				{Container: "init", At: started, Started: &ContainerStarted{PID: 7}},
				{Container: "init", At: exited, Exited: &ContainerExited{ExitCode: 0}},
				{Container: "app", At: exited, Started: &ContainerStarted{PID: 93}},
				{Container: "sidecar", At: exited, Started: &ContainerStarted{PID: 94}},
			},
			want: []ContainerEvent{
				{Container: "init", At: exited, Exited: &ContainerExited{ExitCode: 0}},
				{Container: "app", At: exited, Started: &ContainerStarted{PID: 93}},
				{Container: "sidecar", At: exited, Started: &ContainerStarted{PID: 94}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEvents(0)
			for _, ev := range tc.published {
				e.Publish(ev)
			}
			// The subscriber arrives only now — after everything above happened.
			got, sub := e.SubscribeWithSnapshot()
			defer sub.Close()

			if len(got) != len(tc.want) {
				t.Fatalf("replayed %d events, want %d (%+v)", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				assertSameEvent(t, got[i], w)
			}
			// The replay must not also arrive live: a doubled ContainerStarted
			// after a terminal event would resurrect a dead container in the
			// host's fold.
			select {
			case ev := <-sub.C():
				t.Errorf("a replayed event was ALSO delivered live: %+v", ev)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}

	t.Run("a-resubscribe-relearns-the-same-state", func(t *testing.T) {
		// The resubscribe path: the host re-establishes the stream after a
		// transient drop, and without a replay it would never re-learn state it
		// had already been told once.
		e := NewEvents(0)
		e.Publish(ContainerEvent{Container: "app", At: started, Started: &ContainerStarted{PID: 93}})
		first, subA := e.SubscribeWithSnapshot()
		subA.Close()
		second, subB := e.SubscribeWithSnapshot()
		defer subB.Close()
		if len(first) != 1 || len(second) != 1 {
			t.Fatalf("replays = %d and %d, want 1 each", len(first), len(second))
		}
		assertSameEvent(t, second[0], first[0])
	})

	t.Run("live-events-after-the-snapshot-still-arrive", func(t *testing.T) {
		e := NewEvents(0)
		e.Publish(ContainerEvent{Container: "app", At: started, Started: &ContainerStarted{PID: 93}})
		snap, sub := e.SubscribeWithSnapshot()
		defer sub.Close()
		if len(snap) != 1 {
			t.Fatalf("replayed %d events, want 1", len(snap))
		}
		e.Publish(ContainerEvent{Container: "app", At: exited, Exited: &ContainerExited{ExitCode: 3}})
		select {
		case ev := <-sub.C():
			if ev.Exited == nil || ev.Exited.ExitCode != 3 {
				t.Errorf("live event = %+v, want the exit with code 3", ev)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a post-snapshot event never arrived; the snapshot must not replace the live stream")
		}
	})

	t.Run("a-concurrent-publish-is-delivered-exactly-once", func(t *testing.T) {
		// The snapshot/live boundary under contention: whatever the interleaving,
		// every published event reaches the subscriber exactly one way. A miss
		// would leave a container unreported; a double would move a container's
		// StartedAt or resurrect an exited one.
		const n = 200
		e := NewEvents(4 * n)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				e.Publish(ContainerEvent{Container: containerName(i), At: started, Started: &ContainerStarted{PID: int32(i)}})
			}
		}()
		snap, sub := e.SubscribeWithSnapshot()
		defer sub.Close()
		wg.Wait()

		seen := map[string]int{}
		for _, ev := range snap {
			seen[ev.Container]++
		}
		// Drain whatever the live stream carried.
		deadline := time.After(5 * time.Second)
	drain:
		for len(seen) < n {
			select {
			case ev := <-sub.C():
				seen[ev.Container]++
			case <-deadline:
				break drain
			}
		}
		if len(seen) != n {
			t.Errorf("saw %d distinct containers, want %d — an event fell between the snapshot and the live stream", len(seen), n)
		}
		for name, count := range seen {
			if count != 1 {
				t.Errorf("container %s was delivered %d times, want exactly 1", name, count)
			}
		}
	})
}

// containerName gives each publisher iteration a distinct container, so
// last-event-wins retention cannot mask a lost or doubled delivery.
func containerName(i int) string {
	return "c" + string(rune('a'+i%26)) + "-" + time.Duration(i).String()
}

// assertSameEvent compares the fields the host's fold reads.
func assertSameEvent(t *testing.T, got, want ContainerEvent) {
	t.Helper()
	if got.Container != want.Container || !got.At.Equal(want.At) {
		t.Errorf("event = {%s @ %s}, want {%s @ %s}", got.Container, got.At, want.Container, want.At)
	}
	switch {
	case want.Started != nil:
		if got.Started == nil || got.Started.PID != want.Started.PID {
			t.Errorf("started = %+v, want %+v", got.Started, want.Started)
		}
		if got.Exited != nil {
			t.Errorf("event carries both arms of the union: %+v", got)
		}
	case want.Exited != nil:
		if got.Exited == nil || *got.Exited != *want.Exited {
			t.Errorf("exited = %+v, want %+v", got.Exited, want.Exited)
		}
		if got.Started != nil {
			t.Errorf("event carries both arms of the union: %+v", got)
		}
	}
}

// TestContainerEventsStreamOpensWithASnapshot drives the same fact through the
// SHIPPED gRPC handler over a real connection: a client that connects after the
// containers started is told about them.
func TestContainerEventsStreamOpensWithASnapshot(t *testing.T) {
	events := NewEvents(0)
	// Exactly the guest's real ordering: containers start, THEN the agent serves.
	events.Publish(ContainerEvent{Container: "init", At: time.Now(), Exited: &ContainerExited{ExitCode: 0}})
	events.Publish(ContainerEvent{Container: "app", At: time.Now(), Started: &ContainerStarted{PID: 93}})

	client := testAgent(t, "pod-1", Deps{
		Runner: &fakeRunner{names: []string{"init", "app"}},
		Events: events,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.ContainerEvents(ctx, &guestv1.ContainerEventsRequest{PodId: "pod-1"})
	if err != nil {
		t.Fatalf("ContainerEvents: %v", err)
	}

	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("the stream carried no snapshot at all: %v", err)
	}
	if first.GetContainer() != "init" || first.GetExited() == nil {
		t.Errorf("first event = %+v, want init's replayed exit", first)
	}
	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if second.GetContainer() != "app" || second.GetStarted() == nil || second.GetStarted().GetPid() != 93 {
		t.Errorf("second event = %+v, want app's replayed start with pid 93", second)
	}

	// And the live stream still works behind the snapshot.
	events.Publish(ContainerEvent{Container: "app", At: time.Now(), Exited: &ContainerExited{ExitCode: 1}})
	third, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if third.GetContainer() != "app" || third.GetExited().GetExitCode() != 1 {
		t.Errorf("third event = %+v, want app's live exit with code 1", third)
	}
}
