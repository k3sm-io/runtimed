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
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// DefaultSocketPath is the unix socket the k3sm-runtimed daemon listens on and
// the k3sm provider dials. It lives under image.DefaultRoot so the runtime root
// and its control socket share one tree.
//
// SOCKET POSTURE, accurately. The socket is created 0600 inside a 0700 dir, so
// only the DAEMON'S own UID can dial it. That uid is `_k3sm` in the shipped
// install, not root (the privilege model: k3sm runs unprivileged apart from the
// minimal netd root helper), so "only root can dial" would be false — the
// correct statement is that the dialer must be the daemon's uid. The provider
// runs as that same uid from the same k3sm build, restarted together, so there
// is no cross-uid IPC and no version-negotiation surface. Every service
// registered on this server — Runtime and Images alike — inherits exactly this
// socket and no other.
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
	// one grpc.Server, therefore one listener, therefore one socket posture. The
	// Images service (ListImages / ImageFsInfo / RemoveImage / PruneImages) is
	// registered here, on the identical server the Runtime service is registered
	// on, so it inherits the 0700-dir / 0600-socket permissions documented on
	// DefaultSocketPath and cannot acquire a laxer posture of its own. A separate
	// listener "just for the image commands" is the shape that would silently
	// hand every local uid PruneImages; images.proto records the obligation and
	// this line is the only place it can actually be discharged.
	runtimev1.RegisterImagesServer(gs, &imagesService{rt: rt})
	return &Server{rt: rt, grpc: gs, log: rt.log}
}

// Serve accepts connections on lis until lis is closed or ctx is cancelled,
// whichever comes first. On ctx cancellation it triggers a GracefulStop so
// in-flight RPCs drain. It returns the underlying grpc.Serve error, or nil for a
// clean shutdown (a closed listener / cancelled ctx). The caller owns lis and may
// close it to force-stop; Serve never closes lis itself.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	// Reconcile pod-network startup state before accepting any CreatePod: the
	// real IPAM adapter's in-memory allocator must be re-synced with the durable
	// lo0 aliases a `kickstart -k` restart left behind, or new allocations
	// collide with stale aliases and orphans leak the pool. Runs exactly once
	// per Runtime (sticky), a no-op when the network has no reconciler.
	if err := s.rt.reconcileNetworkStartup(ctx); err != nil {
		return fmt.Errorf("reconcile pod network startup state: %w", err)
	}

	// Reap pod process groups a dead daemon left behind, also before any
	// CreatePod: pods are SETSID session leaders that reparent to launchd on a
	// daemon crash and keep holding ports. Only durably-recorded pgids are
	// considered, each guarded by an exact-instance start-time identity check
	// (podreap.go) — never a name/path heuristic. Unlike the network reconcile
	// this degrades rather than fails closed: reaping a best-effort orphan store
	// is not a scheduling precondition, so ReapOrphanedPods always returns nil
	// (it alerts + skips on an unreadable store) — a store fault must never
	// crash-loop the node out of serving CreatePod. It is exported because the
	// embedded k3sm node path never runs Serve and must call it directly; the
	// sticky once makes the reap happen exactly once either way.
	if err := s.rt.ReapOrphanedPods(); err != nil {
		return fmt.Errorf("reap orphaned pod process groups: %w", err)
	}

	// Start the daemon-side image GC. It is bound to a ctx cancelled when Serve
	// returns (by the defer below), so the goroutine cannot outlive the daemon
	// loop, and it is started after the startup reconciles above so a pass can
	// never race pod-dir reconstruction — a pod dir that has not been rebuilt yet
	// has no reachability record, which the GC correctly reads as "refuse", but
	// there is no reason to make it do that work.
	gcCtx, gcCancel := context.WithCancel(ctx)
	defer gcCancel()
	go s.rt.RunImageGC(gcCtx, 0, image.ReclaimConfig{})

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

// Listen creates the daemon's unix-socket listener at path, removing a stale
// socket left by an unclean shutdown and tightening permissions so only the
// OWNING uid can dial: the parent dir is 0700 and the socket node 0600. The
// owning uid is whatever euid the daemon runs as — `_k3sm` in the shipped
// install, not root; see DefaultSocketPath.
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
