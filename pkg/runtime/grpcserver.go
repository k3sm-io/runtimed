package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// DefaultSocketPath is the root unix socket the k3sm-runtimed daemon listens on
// and the k3sm provider dials. It lives under image.DefaultRoot so the runtime
// root and its control socket share one tree. The daemon runs as root; the
// socket is created 0600 inside a 0700 dir so only root can dial it (the
// provider runs as the same uid — they are the same k3sm build, restarted
// together, so there is no cross-uid IPC and no version-negotiation surface).
const DefaultSocketPath = "/var/lib/k3sm/run/runtimed.sock"

// Server hosts a *Runtime behind a gRPC server on a net.Listener. It is the M2
// daemon boundary: the same in-process *Runtime that k3sm imports as a library
// is registered here so the split is a relocation, not a redesign. The seam is
// transport-agnostic (it serves any net.Listener) so it is exercisable over a
// real unix socket on a capable host and over an in-memory pipe in unit tests.
//
// Lifecycle: NewServer registers the runtime; Serve blocks until the listener
// closes or ctx is cancelled (cancellation triggers a GracefulStop); Stop is the
// idempotent explicit shutdown. There is no background goroutine beyond the one
// Serve spawns to watch ctx, which always exits when Serve returns.
type Server struct {
	rt   *Runtime
	grpc *grpc.Server
	log  *slog.Logger
}

// NewServer builds a gRPC Server hosting rt. opts are appended to the k3sm
// defaults, so a caller (or test) can inject credentials or interceptors. The
// runtime is registered immediately so Serve only has to accept connections.
func NewServer(rt *Runtime, opts ...grpc.ServerOption) *Server {
	gs := grpc.NewServer(opts...)
	runtimev1.RegisterRuntimeServer(gs, rt)
	return &Server{rt: rt, grpc: gs, log: rt.log}
}

// Serve accepts connections on lis until lis is closed or ctx is cancelled,
// whichever comes first. On ctx cancellation it triggers a GracefulStop so
// in-flight RPCs drain. It returns the underlying grpc.Serve error, or nil for a
// clean shutdown (a closed listener / cancelled ctx). The caller owns lis and may
// close it to force-stop; Serve never closes lis itself.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	// Watch ctx: on cancellation, GracefulStop unblocks grpc.Serve. The goroutine
	// always exits — either ctx fires (we stop, Serve returns) or Serve returns
	// for another reason and we close stopped to release the goroutine.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.log.Info("runtimed gRPC server stopping (context cancelled)")
			s.grpc.GracefulStop()
		case <-stopped:
		}
	}()

	err := s.grpc.Serve(lis)
	close(stopped) // release the ctx-watcher (sender closes the channel)

	// grpc.Serve returns ErrServerStopped on GracefulStop/Stop — a clean shutdown,
	// not an error to propagate. ctx.Err() distinguishes a cancellation-driven
	// stop from a listener-close stop; both are clean.
	if err == grpc.ErrServerStopped || ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("serve runtime gRPC: %w", err)
	}
	return nil
}

// Stop gracefully stops the server, draining in-flight RPCs. It is idempotent and
// safe to call concurrently with a Serve that is being torn down by ctx.
func (s *Server) Stop() { s.grpc.GracefulStop() }

// Listen creates the root unix-socket listener for the daemon at path, removing a
// stale socket left by an unclean shutdown and tightening permissions so only the
// owning (root) uid can dial: the parent dir is 0700 and the socket node 0600.
// The caller passes the returned listener to Serve and is responsible for closing
// it. On any error the partially-created socket is cleaned up.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		path = DefaultSocketPath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	// Remove a stale socket from a previous (unclean) run; net.Listen fails with
	// EADDRINUSE otherwise. Ignore a not-exist; surface any other removal error.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on unix socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return lis, nil
}
