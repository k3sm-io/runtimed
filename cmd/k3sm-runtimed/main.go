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

// Command k3sm-runtimed is the root native-runtime daemon: it hosts the
// in-process *runtime.Runtime (OCI pull → clonefile → ad-hoc-sign → Seatbelt
// confine → posix_spawn/kqueue supervise) behind a gRPC server on a root unix
// socket. The k3sm Virtual Kubelet provider dials that socket.
//
// The daemon and the provider are the same k3sm build, restarted together
// (same-binary, same-node hard cut), so there is no independent-upgrade skew and
// no version-negotiation handshake — GetRuntimeInfo reports the daemon's
// identity/health for diagnostics only.
//
// This is a thin main: flag parsing, signal-driven context, build the Runtime,
// listen, serve. All lifecycle logic lives in k3sm.io/runtimed/pkg/runtime
// (Server/Listen) so the daemon seam is unit-testable without root.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
)

func main() {
	var (
		socketPath = flag.String("socket", runtime.DefaultSocketPath, "unix socket path to listen on")
		root       = flag.String("root", "", "on-disk runtime root (image cache + pod dirs); empty uses the runtimed default")
		version    = flag.String("runtime-version", "dev", "daemon version reported by GetRuntimeInfo")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(*socketPath, *root, *version, log); err != nil {
		log.Error("k3sm-runtimed exited", "err", err)
		os.Exit(1)
	}
}

// run builds the runtime, opens the root unix socket, and serves until SIGINT/
// SIGTERM. It returns the first fatal error (or nil on a clean signal-driven
// shutdown). Kept separate from main so the wiring is exercisable.
func run(socketPath, root, version string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer stop()

	// Ensure the pinned guest boot artifacts before the runtime comes up, the
	// same shape the in-process k3sm node wires: an ensure failure degrades the
	// vm capability (pods fail closed at CreateVM), it never blocks the daemon.
	deps := runtime.Deps{}
	artifactRoot := root
	if artifactRoot == "" {
		artifactRoot = image.DefaultRoot
	}
	if pin, err := guestartifacts.Lookup(guestartifacts.ActiveGuestKernel); err != nil {
		log.Info("guest boot artifacts unavailable: no usable pin; vm pods fail closed", "err", err)
	} else {
		ectx, cancel := context.WithTimeout(ctx, guestartifacts.DefaultFetchTimeout)
		art, aerr := guestartifacts.EnsureGuestArtifacts(ectx,
			filepath.Join(artifactRoot, guestartifacts.GuestArtifactsSubdir), pin, &guestartifacts.HTTPFetcher{})
		cancel()
		if aerr != nil {
			log.Warn("guest boot artifacts could not be ensured; vm capability off", "err", aerr)
		} else {
			// The locator RE-VERIFIES on every boot rather than closing over the
			// ensure's one-time result: this daemon runs for weeks, and a
			// constant closure would assert a digest measured at start for the
			// whole of that uptime. See guestartifacts.Locator.
			deps.VMBackend = sandbox.NewVMBackend(
				sandbox.WithStateRoot(artifactRoot),
				sandbox.WithLogger(log),
				sandbox.WithGuestArtifacts(guestartifacts.Locator(pin, art)))
		}
	}

	rt, err := runtime.New(runtime.Config{
		Root:           root,
		RuntimeVersion: version,
		Logger:         log,
	}, deps)
	if err != nil {
		return err
	}

	lis, err := runtime.Listen(socketPath)
	if err != nil {
		return err
	}
	defer func() { _ = lis.Close() }()

	log.Info("k3sm-runtimed serving", "socket", socketPath, "root", root)
	serveErr := runtime.NewServer(rt).Serve(ctx, lis)

	// Serve has returned, so this process is going away: stop the supervision of
	// every pod still live on the node (reapers, watchContainerExit completions,
	// the ~1 Hz memory samplers) instead of letting the exit collect them. It is
	// the shutdown counterpart of DeletePod's per-pod teardown. The pod PROCESSES
	// are deliberately left running — they outlive the daemon and the startup pod
	// reap reconciles them — and a supervision that misses the bound is reported,
	// never fatal: the daemon is exiting either way, so it must not mask the
	// serve error.
	//
	// It sits here and not in Serve because Serve's contract is a listener loop a
	// caller may end (by closing its listener) while keeping the Runtime; daemon
	// shutdown is this function.
	if err := rt.Close(); err != nil {
		log.Warn("pod supervision did not fully stop at shutdown", "err", err)
	}
	return serveErr
}
