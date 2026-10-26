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

// Command k3sm-vmhost builds and runs one vm-backend pod's Linux micro-VM.
//
// It is the only k3sm binary carrying com.apple.security.virtualization
// (vmhost.entitlements). That is the whole reason it is a separate process: the
// daemon parses images, serves a gRPC socket and talks to the provider, and none
// of that should sit inside a process holding the authority to create virtual
// machines. The daemon spawns one of these per vm pod and holds no virtualization
// entitlement itself.
//
// # The entitlement set, and why it is exactly one key
//
// vmhost.entitlements grants com.apple.security.virtualization and nothing else.
// That file is deliberately COMMENT-free, and the rationale lives here instead:
// codesign parses entitlements with AMFI's XML reader, which is stricter than
// plutil and REJECTS an XML comment. A commented plist lints clean under
// `plutil -lint`, then fails at signing with "AMFIUnserializeXML: syntax error"
// — and `codesign --verify` still reports the binary as validly signed, because
// the signature is fine; it just carries no entitlements. The failure is silent:
// VMBackend.Available() would simply report false on a perfectly capable Mac.
// Keep the plist minimal; document here.
//
// Deliberately not granted, each for its own reason:
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
// It is DUMB BY DESIGN. Every policy decision was made before it started; it reads
// vmhost.spec.json, translates it (pkg/vmhost.FromSpec, which carries all the
// validation), boots the machine, proxies one socket, and stops. It decides
// nothing, and it never parses a byte of the guest/v1 gRPC it relays.
//
// Lifetime: it OUTLIVES the daemon that spawned it, as a container outlives a
// kubelet restart. It leads its own session, writes its output to a file in its
// run dir (-log-file) rather than to a daemon pipe, and ignores SIGPIPE, so a
// daemon exit takes nothing from it; the next daemon adopts it after checking
// it is this exact helper (its control socket answers VMHostProtocolVersion
// from the recorded pid), or kills it. SIGTERM runs the graceful sequence (guest
// agent Stop, then a hard halt if the grace budget, measured from the SIGTERM,
// is spent), with the agent proxy still serving until the machine is off.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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
	// Defence in depth for the daemon's going away. The output is a file, so
	// no write of the helper's own should ever meet a closed pipe; but a write
	// that did would, under the Go runtime's default, raise SIGPIPE on fd 1 or
	// 2 and kill the helper with its guest. Ignored, such a write returns EPIPE
	// and the helper keeps its machine.
	signal.Ignore(syscall.SIGPIPE)

	var (
		specPath    = flag.String("spec", "", "path to the vmhost.spec.json this VM is built from (required)")
		agentSocket = flag.String("agent-socket", "", "path of the runtimed-private unix socket proxied to the guest agent (required)")
		consoleLog  = flag.String("console-log", "", "path of the size-capped guest console log; empty discards the console")
		stopGrace   = flag.Duration("stop-grace", 0, "graceful-termination budget for the guest on SIGTERM; 0 uses the package default, and anything above the ceiling is clamped")
		logFile     = flag.String("log-file", "", "path of the file the daemon opened as this helper's stdout and stderr; when set the helper rotates it at the size cap")
	)
	flag.Parse()

	var out io.Writer = os.Stderr
	if *logFile != "" {
		out = newHelperLog(*logFile, sandbox.VMHostLogMaxBytes, os.Stderr, []int{1, 2})
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log, *specPath, *agentSocket, *consoleLog, *stopGrace); err != nil {
		log.Error("vm host failed", "err", err)
		os.Exit(1)
	}
}

// run builds the machine and drives it until it stops.
func run(log *slog.Logger, specPath, agentSocket, consoleLog string, stopGrace time.Duration) error {
	if specPath == "" || agentSocket == "" {
		flag.Usage()
		return errors.New("both --spec and --agent-socket are required")
	}

	// PREFLIGHT, before any FRAMEWORK call. Constructing a VZVirtualMachine
	// without the entitlement raises an uncaught NSException → SIGABRT, so an
	// unentitled helper would die with a crash report and no explanation. Checking
	// the signature first turns that into one line an operator can act on.
	if !sandbox.ProcessVirtualizationEntitled() {
		return fmt.Errorf("this %s binary does not carry the com.apple.security.virtualization entitlement; "+
			"it must be signed with cmd/k3sm-vmhost/vmhost.entitlements (dev: codesign --entitlements) "+
			"before it can create a virtual machine", sandbox.VMHostName)
	}

	spec, err := vmhost.ReadSpec(specPath)
	if err != nil {
		return err
	}
	cfg, err := vmhost.FromSpec(spec, defaultOptions(specPath, consoleLog))
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

	lis, err := listenAgentSocket(agentSocket)
	if err != nil {
		return err
	}
	defer func() {
		_ = lis.Close()
		_ = os.Remove(agentSocket)
	}()

	// one GRACE budget, ISSUED BY the DAEMON. The pod's
	// terminationGracePeriodSeconds is a promise made to the workload, and the
	// daemon is the only process that knows it — so it is threaded in here rather
	// than defaulted twice. Without this flag the helper would run its own
	// 20-second default while the daemon's DeletePod escalated on the pod's grace,
	// two independently-clocked timers across a process boundary: whenever the
	// daemon's was the shorter one it SIGKILLed the helper mid-graceful-stop, and
	// a hard stop with a guest still writing is the power cut the grace period
	// exists to prevent. The lifecycle measures the budget from the SIGTERM, the
	// same instant the daemon starts its own wait, and the daemon waits a fixed
	// margin longer, so the helper's hard stop always comes first. NewLifecycle
	// clamps the value to MaxStopGrace, so an over-long pod grace is bounded here
	// rather than trusted.
	lc := vmhost.NewLifecycle(runner, vmhost.NewAgentStopper(dial), vmhost.LifecycleOptions{
		Grace:  stopGrace,
		Logger: log,
	})

	// The control socket, beside the agent socket and as private: one JSON
	// line naming this helper's protocol version and pid per connection. It is
	// how a restarted daemon tells this helper from anything else before it
	// adopts it, and it never relays a byte to the guest. After that line it
	// takes one request, the shorten request: a stopper whose bound is shorter
	// than the pod's grace asks, before its SIGTERM, for the stop to begin with
	// a grace that fits (sandbox.ShortenedStopGrace), and the lifecycle starts
	// it on the same path the SIGTERM takes (Lifecycle.ShortenGrace).
	ctlPath := filepath.Join(filepath.Dir(agentSocket), sandbox.VMHostControlSocketName)
	ctl, err := listenAgentSocket(ctlPath)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer func() {
		_ = ctl.Close()
		_ = os.Remove(ctlPath)
	}()
	go func() {
		if err := sandbox.ServeVMHostControlStop(ctl, sandbox.VMHostControl{
			Version: sandbox.VMHostVersion{Protocol: sandbox.VMHostProtocolVersion, Pid: os.Getpid()},
			Stop:    lc,
			PodID:   cfg.PodID,
			Logger:  log,
		}); err != nil {
			log.Warn("the control socket stopped serving; a restarted daemon will not adopt this helper", "err", err)
		}
	}()

	// SIGTERM arrives as a context cancellation, so the lifecycle needs no signal
	// handling of its own and there is exactly one shutdown path. A shorten
	// request on the control socket takes the same path, through the
	// lifecycle's own cancel.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The proxy outlives the signal: it keeps relaying while the guest stops and
	// is drained only once the machine is off (see RunWithProxy), so the daemon's
	// execs and log follows reach a guest that is still shutting down.
	return vmhost.RunWithProxy(ctx, lc, vmhost.NewProxy(lis, dial, log))
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

// listenAgentSocket creates a runtimed-private unix socket the daemon dials:
// the agent socket, and the control socket beside it.
//
// A stale socket is removed first. A SIGKILLed helper leaves its socket files
// behind; without the unlink the next pod with the same id would fail to bind
// for a reason that has nothing to do with it.
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
	// Chmod after bind: the socket file does not exist until then, and the umask
	// that applied at bind is not this process's to assume.
	if err := os.Chmod(path, agentSocketMode); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("chmod the agent socket %s: %w", path, err)
	}
	return lis, nil
}
