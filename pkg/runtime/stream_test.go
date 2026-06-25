package runtime

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeWatchStream is a grpc.ServerStreamingServer[PodStatusEvent] for tests: Send
// pushes onto a buffered channel recv reads.
type fakeWatchStream struct {
	grpc.ServerStream
	ctx context.Context
	ch  chan *runtimev1.PodStatusEvent
}

func newFakeWatchStream(ctx context.Context) *fakeWatchStream {
	return &fakeWatchStream{ctx: ctx, ch: make(chan *runtimev1.PodStatusEvent, 64)}
}

func (s *fakeWatchStream) Context() context.Context { return s.ctx }
func (s *fakeWatchStream) Send(ev *runtimev1.PodStatusEvent) error {
	select {
	case s.ch <- ev:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *fakeWatchStream) recv(t *testing.T, d time.Duration) *runtimev1.PodStatusEvent {
	t.Helper()
	select {
	case ev := <-s.ch:
		return ev
	case <-time.After(d):
		t.Fatal("timed out waiting for watch event")
		return nil
	}
}

// fakeLogStream is a grpc.ServerStreamingServer[LogEntry] collecting sent entries.
type fakeLogStream struct {
	grpc.ServerStream
	ctx     context.Context
	mu      sync.Mutex
	entries []*runtimev1.LogEntry
}

func newFakeLogStream(ctx context.Context) *fakeLogStream {
	return &fakeLogStream{ctx: ctx}
}

func (s *fakeLogStream) Context() context.Context { return s.ctx }
func (s *fakeLogStream) Send(e *runtimev1.LogEntry) error {
	s.mu.Lock()
	s.entries = append(s.entries, e)
	s.mu.Unlock()
	return nil
}
