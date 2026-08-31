//go:build darwin && cgo

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

// Command k3sm-vmhost builds and runs ONE vm-backend pod's Linux micro-VM.
//
// IT IS THE ONLY k3sm BINARY CARRYING com.apple.security.virtualization
// (vmhost.entitlements). That is the whole reason it is a separate process: the
//
// # The entitlement set, and why it is exactly one key
//
// vmhost.entitlements grants com.apple.security.virtualization and nothing else.
// That file is deliberately COMMENT-FREE, and the rationale lives here instead:
// codesign parses entitlements with AMFI's XML reader, which is stricter than
// plutil and REJECTS an XML comment. A commented plist lints clean under
// `plutil -lint`, then fails at signing with "AMFIUnserializeXML: syntax error"
// — and `codesign --verify` still reports the binary as validly signed, because
// the signature is fine; it just carries no entitlements. The failure is silent:
// VMBackend.Available() would simply report false on a perfectly capable Mac.
// Keep the plist minimal; document here.
//
// Deliberately NOT granted, each for its own reason:
//
//   - com.apple.security.cs.allow-jit, allow-unsigned-executable-memory,
//     disable-executable-page-protection — the code-running trio. The hypervisor
//     runs the guest; this process does not execute guest code. Granting them
//     would let the one entitled process map writable-executable memory, the most
//     useful primitive an attacker can be handed.
//   - com.apple.vm.networking — restricted (Apple grants it by request) and
//     unnecessary: the guest is NAT-attached, never bridged. A pod does not need a
//     LAN-visible address; the cluster reaches it through the node.
//   - any Rosetta share entitlement — this helper attaches no Rosetta directory
//     share and the node does not advertise the capability, so the entitlement
//     would be authority for nothing.
//
// daemon parses images, serves a gRPC socket and talks to the provider, and none
// of that should sit inside a process holding the authority to create virtual
// machines. The daemon spawns one of these per vm pod and holds no virtualization
// entitlement itself.
//
// It is DUMB BY DESIGN. Every policy decision was made before it started; it reads
// vmhost.spec.json, translates it (pkg/vmhost.FromSpec, which carries all the
// validation), boots the machine, proxies one socket, and stops. It decides
// nothing, and it never parses a byte of the guest/v1 gRPC it relays.
//
// Lifetime: it dies with the daemon that spawned it — no VM outlives the binary
// that booted it — and SIGTERM runs the graceful sequence (guest agent Stop, then
// a hard halt if the grace budget is spent).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/vmhost"
)

// agentSocketMode / agentSocketDirMode keep the relayed agent socket unreachable
// by anything but the daemon.
//
// The socket is the pod's control channel: whoever can connect to it can Exec into
// the guest. It lives under the daemon's private run tree — never the pod dir, so
// no pod's sandbox profile re-allows it — and these modes are the second layer:
// owner-only on both the directory and the socket, so even a same-uid mistake in
// the layout does not hand it out.
const (
	agentSocketMode    os.FileMode = 0o600
	agentSocketDirMode os.FileMode = 0o700
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("vm host failed", "err", err)
		os.Exit(1)
	}
}

// run parses the flags, builds the machine, and drives it until it stops.
func run(log *slog.Logger) error {
	var (
		specPath    = flag.String("spec", "", "path to the vmhost.spec.json this VM is built from (required)")
		agentSocket = flag.String("agent-socket", "", "path of the runtimed-private unix socket proxied to the guest agent (required)")
		consoleLog  = flag.String("console-log", "", "path of the size-capped guest console log; empty discards the console")
		stopGrace   = flag.Duration("stop-grace", 0, "graceful-termination budget for the guest on SIGTERM; 0 uses the package default, and anything above the ceiling is clamped")
	)
	flag.Parse()

	if *specPath == "" || *agentSocket == "" {
		flag.Usage()
		return errors.New("both --spec and --agent-socket are required")
	}

	// PREFLIGHT, BEFORE ANY FRAMEWORK CALL. Constructing a VZVirtualMachine
	// without the entitlement raises an uncaught NSException → SIGABRT, so an
	// unentitled helper would die with a crash report and no explanation. Checking
	// the signature first turns that into one line an operator can act on.
	if !sandbox.ProcessVirtualizationEntitled() {
		return fmt.Errorf("this %s binary does not carry the com.apple.security.virtualization entitlement; "+
			"it must be signed with cmd/k3sm-vmhost/vmhost.entitlements (dev: codesign --entitlements) "+
			"before it can create a virtual machine", sandbox.VMHostName)
	}

	spec, err := vmhost.ReadSpec(*specPath)
	if err != nil {
		return err
	}
	cfg, err := vmhost.FromSpec(spec, defaultOptions(*specPath, *consoleLog))
	if err != nil {
		return err
	}
	log.Info("building the guest",
		"pod", cfg.PodID, "vcpus", cfg.VCPUs, "memory_bytes", cfg.MemoryBytes,
		"shares", len(cfg.Shares), "agent_vsock_port", cfg.Vsock.AgentPort)

	runner, dial, err := vmhost.NewVZMachine(cfg, log)
	if err != nil {
		return err
	}

	lis, err := listenAgentSocket(*agentSocket)
	if err != nil {
		return err
	}
	defer func() {
		_ = lis.Close()
		_ = os.Remove(*agentSocket)
	}()

	// SIGTERM arrives as a context cancellation, so the lifecycle needs no signal
	// handling of its own and there is exactly one shutdown path.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	proxy := vmhost.NewProxy(lis, dial, log)
	proxied := make(chan error, 1)
	go func() { proxied <- proxy.Serve(ctx) }()

	// ONE GRACE BUDGET, ISSUED BY THE DAEMON. The pod's
	// terminationGracePeriodSeconds is a promise made to the workload, and the
	// daemon is the only process that knows it — so it is threaded in here rather
	// than defaulted twice. Without this flag the helper would run its own
	// 20-second default while the daemon's DeletePod escalated on the pod's grace,
	// two independently-clocked timers across a process boundary: whenever the
	// daemon's was the shorter one it SIGKILLed the helper mid-graceful-stop, and
	// a hard stop with a guest still writing is the power cut the grace period
	// exists to prevent. NewLifecycle clamps the value to MaxStopGrace, so an
	// over-long pod grace is bounded here rather than trusted.
	lc := vmhost.NewLifecycle(runner, vmhost.NewAgentStopper(dial), vmhost.LifecycleOptions{
		Grace:  *stopGrace,
		Logger: log,
	})
	runErr := lc.Run(ctx)

	// The proxy is drained BEFORE returning: its Serve returns only once every
	// relay goroutine has finished, so waiting here is what makes "this process is
	// about to exit" also mean "nothing is still holding a connection into the
	// machine that was just halted".
	_ = lis.Close()
	if perr := <-proxied; perr != nil {
		log.Warn("the guest agent proxy ended with an error", "err", perr)
	}
	return runErr
}

// defaultOptions fills the host-derived bounds FromSpec resolves the spec against.
//
// This is the IMPURE EDGE, and it is deliberately the only one: FromSpec takes
// every bound as a value, so all of its validation is table-testable anywhere,
// while the business of asking the host how big a machine may be lives here.
func defaultOptions(specPath, consoleLog string) vmhost.Options {
	return vmhost.Options{
		// The pod dir is the spec file's own directory. The daemon writes
		// vmhost.spec.json INTO the pod dir, so deriving it here rather than
		// taking another flag removes a way for the two to disagree — and the
		// k3sm.spec share is rooted under it.
		PodDir:         filepath.Dir(specPath),
		ConsoleLogPath: consoleLog,

		MinVCPUs:     minVCPUs(),
		MaxVCPUs:     maxVCPUs(),
		DefaultVCPUs: defaultVCPUs(),

		MinMemoryBytes:     minMemoryBytes(),
		MaxMemoryBytes:     maxMemoryBytes(),
		DefaultMemoryBytes: defaultMemoryBytes(),
	}
}

// listenAgentSocket creates the runtimed-private unix socket the daemon dials.
//
// A STALE SOCKET IS REMOVED FIRST. The helper dies with the daemon, and a SIGKILL
// leaves the socket file behind; without the unlink the next pod with the same id
// would fail to bind for a reason that has nothing to do with it.
func listenAgentSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), agentSocketDirMode); err != nil {
		return nil, fmt.Errorf("agent socket dir: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove the stale agent socket %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on the agent socket %s: %w", path, err)
	}
	// Chmod AFTER bind: the socket file does not exist until then, and the umask
	// that applied at bind is not this process's to assume.
	if err := os.Chmod(path, agentSocketMode); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("chmod the agent socket %s: %w", path, err)
	}
	return lis, nil
}
