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
// The daemon and the provider are the SAME k3sm build, restarted together
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

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/runtime"
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

	rt, err := runtime.New(runtime.Config{
		Root:           root,
		RuntimeVersion: version,
		Logger:         log,
	}, runtime.Deps{})
	if err != nil {
		return err
	}

	lis, err := runtime.Listen(socketPath)
	if err != nil {
		return err
	}
	defer func() { _ = lis.Close() }()

	log.Info("k3sm-runtimed serving", "socket", socketPath, "root", root)
	return runtime.NewServer(rt).Serve(ctx, lis)
}
