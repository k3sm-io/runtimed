//go:build linux

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

// Command k3sm-guest-init is PID 1 of a k3sm vm-backend pod's micro-VM.
//
// It is the THIN half of the guest init: every decision it makes was already
// made by k3sm.io/runtimed/pkg/guestinit, which is pure and unit-tested on
// darwin. This file walks the plan and calls the kernel — mount, write,
// sethostname, fork/exec, and the reaper's three-method seam — so that the
// only logic reachable exclusively by a cross-compile is syscall plumbing.
//
// It ships inside the pinned initramfs, not in the daemon: the host end and
// this end can be built at different times, which is why guest/v1 is a
// versioned wire contract (see guest.proto).
//
// Boot sequence:
//
//	pseudo-filesystems -> read guest-spec.json -> render /etc -> pod mounts ->
//	hostname -> Rosetta binfmt registration -> per-container rootfs overlays ->
//	init containers sequentially -> main containers -> vsock GuestAgent ->
//	reap loop -> Stop(grace): term -> grace -> KILL -> sync -> poweroff.
//
// The GuestAgent comes up after the containers on purpose: its Health is the
// host's boot-deadline probe, so an agent answering earlier would report a
// guest that is ready for a pod it has not started.
//
// not yet IN this BINARY, and deliberately so — each is its own slice with its
// own gate: pty allocation (so a tty exec is refused rather than run without a
// terminal). A spec requesting an idmapped mount is refused rather than mounted
// without the idmap.
//
// The guest network IS here: lo and eth0 are brought up, eth0 is addressed by a
// minimal in-guest DHCPv4 client against the host's NAT segment, the default
// route is installed over netlink, and the leased address is what
// HealthResponse.guest_ip reports. There is no renewal loop yet — see
// guestStatus.setGuestIP for that ceiling — and /etc/hosts still carries no
// leased address.
//
// Per-container cgroup2 leaves ARE here: the metering controllers are delegated to
// the hierarchy root's children at boot and each container is placed into
// <cgroup2Root>/<name> by the kernel at fork, so the Stats verb finds cpu.stat,
// memory.current and memory.stat where cgroupSampler looks. A container's
// memory.max is NOT set: guest/v1's GuestContainer carries no resource limit, so
// the pod's per-container limit does not reach this binary at all, and the only
// memory ceiling in force is the hypervisor's VZ memorySize for the whole guest.
//
// Per-container log capture IS here: each container is spawned on its own
// stdout/stderr pipes, which are pumped into a bounded per-container ring
// (guestagent.Capture) and, best effort, tee'd to the console so the console
// stays the diagnostic of last resort when the agent is down.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	guestv1 "k3sm.io/apis/guest/v1"
	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
)

// defaultStopGrace is the budget a SIGTERM-driven shutdown gives the pod's
// containers. The host clamps the grace it sends over guest/v1 to fit inside
// the daemon's launchd exit timeout; this value only applies when the guest
// stops on its own signal rather than on the host's Stop RPC.
const defaultStopGrace = 30 * time.Second

// meminfoPath is where the guest's RAM size is read from, to bound each
// container's overlay upper.
const meminfoPath = "/proc/meminfo"

// cmdlinePath is where the guest reads its own kernel command line, which is how
// it learns the pod id it must assert incoming requests against — guest/v1's
// GuestSpec carries no pod_id field. See guestagent.PodIDCmdlineKey.
const cmdlinePath = "/proc/cmdline"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	err := run(context.Background(), log)
	if err != nil {
		// The BACKSTOP, not the mechanism. This line is unreachable on any path
		// that reached the reaper: those return through Reaper.Fail, which puts
		// the reason on the console and then powers the machine off, so run()
		// never returns to here at all. It still covers the paths that fail
		// BEFORE the reaper exists (the pseudo-mounts, the spec read, the plan,
		// /etc, the pod mounts, sethostname, binfmt), which have no shutdown
		// sequence to hang a reason on and reach the poweroff below instead.
		//
		// The contract both layers serve is stated once, on Reaper.Fail: no fatal
		// guest-init path may power off without having written its reason first.
		log.Error("guest init failed", "err", err)
	}
	// PID 1 must never simply exit — the kernel panics when it does, which
	// the host would see as an opaque VM death. Every path ends in a poweroff;
	// the reason is already on the console by the time this one runs.
	if perr := (linuxProc{}).Poweroff(); perr != nil {
		log.Error("poweroff failed", "err", perr)
		os.Exit(1)
	}
}

// run boots the pod described by the spec on the host-supplied share.
func run(ctx context.Context, log *slog.Logger) error {
	proc := linuxProc{}

	if err := applyMounts(log, guestinit.PseudoMounts()); err != nil {
		return err
	}
	if err := applyMounts(log, []guestinit.MountStep{guestinit.SpecMount()}); err != nil {
		return err
	}

	spec, err := readSpec(guestinit.SpecPath)
	if err != nil {
		return err
	}
	meminfo, err := os.ReadFile(meminfoPath)
	if err != nil {
		log.Warn("could not read meminfo; the overlay upper takes its default bound", "err", err)
	}
	plan, err := guestinit.Plan(spec, guestinit.Options{MemTotalBytes: guestinit.ParseMemTotal(string(meminfo))})
	if err != nil {
		return err
	}
	for _, w := range plan.Warnings {
		log.Warn(w)
	}

	if err := writeEtcFiles(plan.Etc); err != nil {
		return err
	}
	if err := applyMounts(log, plan.PodMounts); err != nil {
		return err
	}
	if plan.Hostname != "" {
		if err := unix.Sethostname([]byte(plan.Hostname)); err != nil {
			return fmt.Errorf("sethostname %q: %w", plan.Hostname, err)
		}
	}
	if plan.Binfmt != nil {
		if err := registerBinfmt(log, *plan.Binfmt); err != nil {
			return err
		}
	}

	// The guest's own network, before anything can need it: lo UP, eth0 UP and
	// addressed from the segment's DHCP server, and a default route via the
	// gateway it offered.
	//
	// FAIL CLOSED. A lease failure fails the boot rather than leaving the pod
	// Running-but-unaddressed, and that is the deliberate choice: a Running pod
	// with no address is the silent mode — a Service selecting it gets an
	// EndpointSlice with no addresses, traffic blackholes, and nothing anywhere
	// says why. Kubernetes has no notion of a pod without an address, so a guest
	// that could not get one has not started a pod; refusing makes the provider
	// recreate it, and the reason is on the console because the fatal path goes
	// through the reaper (Reaper.Fail). The DHCP client already absorbs the
	// ordinary case this could over-react to — a lost broadcast — by retrying
	// within its own budget before returning at all.
	//
	// It runs BEFORE the containers because a container may bind a socket as its
	// first act, and before the agent because HealthResponse.guest_ip is fed from
	// what it records.
	netCfg, err := configureNetwork(log)
	if err != nil {
		return err
	}
	log.Info("configured the guest network",
		"link", netCfg.Interface, "address", netCfg.Prefix.String(),
		"gateway", netCfg.Lease.Gateway.String(), "mtu", netCfg.MTU,
		"dns_offered", netCfg.Lease.DNS, "lease", netCfg.Lease.Duration.String())

	// The reaper is started before the first container, so no exit can happen
	// while nothing is reaping.
	sigchld := make(chan struct{}, 1)
	chld := make(chan os.Signal, 1)
	signal.Notify(chld, unix.SIGCHLD)
	go func() {
		for range chld {
			select {
			case sigchld <- struct{}{}:
			default:
			}
		}
	}()

	// The pod's roster, derived once from the plan. It is needed before the
	// reaper because the reaper's exit callback must tell a CONTAINER's exit from
	// an exec's: procExecer tracks each exec under a private "<container>#exec-N"
	// key and the reaper reports both, so publishing every tracked exit would
	// retain a fabricated container per exec on the event bus (which now keeps
	// state — see guestagent.Events) and make the host log a dropped event for an
	// undeclared container on every `kubectl exec`.
	names := make([]string, 0, len(plan.Containers))
	byName := make(map[string]guestinit.ContainerPlan, len(plan.Containers))
	for _, cp := range plan.Containers {
		names = append(names, cp.Name)
		byName[cp.Name] = cp
	}

	// The ContainerEvents fan-out. It is created before the reaper because the
	// reaper's exit callback publishes to it, and before the containers because
	// an exit that happened before the agent was serving still has to reach the
	// bus. It RETAINS each container's last transition, which is what lets the
	// agent — served last, after the containers are already running — replay the
	// pod's state to the host instead of streaming only what happens next.
	events := guestagent.NewEvents(0)
	defer events.Close()

	// The per-container output capture, created before the first spawn because
	// spawn writes into it. Bounded per container; see guestagent.Capture for why
	// an unbounded buffer in a guest whose only storage is RAM is an OOM.
	capture := guestagent.NewCapture(0, 0, 0)
	defer capture.CloseAll()

	// Delegate the metering controllers to the hierarchy root's children BEFORE
	// the first leaf is created: a leaf only gets memory.current / memory.stat if
	// its parent had the memory controller in cgroup.subtree_control when the leaf
	// was made. Without this the sampler found no files, Stats omitted every
	// container, and `kubectl top` reported nothing for a vm pod
	// (/stats/summary answered {"pods":null}).
	//
	// BEST EFFORT, never fatal. A kernel built without a controller costs the pod
	// its metering; refusing to run the workload over it would cost the pod
	// everything. That is the same degradation the sampler already documents —
	// absence rather than zeros — reached one step earlier and said out loud.
	if enabled, err := guestagent.EnableSubtreeControllers(cgroup2Root, guestagent.StatsControllers); err != nil {
		log.Warn("some cgroup2 controllers could not be delegated; those metrics will be absent",
			"root", cgroup2Root, "enabled", enabled, "err", err)
	} else {
		log.Info("delegated cgroup2 controllers", "root", cgroup2Root, "controllers", enabled)
	}

	reaper := guestinit.NewReaper(proc, sigchld, guestinit.ReaperOptions{
		Logger: log,
		OnExit: func(ev guestinit.ExitEvent) {
			if _, declared := byName[ev.Container]; !declared {
				// An exec's child, not a container. The exec route waits on it
				// itself; it is not a pod lifecycle transition.
				log.Debug("reaped a non-container child", "key", ev.Container,
					"exit_code", ev.Status.ExitCode, "signal", ev.Status.Signal)
				return
			}
			log.Info("container exit observed", "container", ev.Container,
				"exit_code", ev.Status.ExitCode, "signal", ev.Status.Signal)
			// The container's log stream ends here so a `kubectl logs -f` reader
			// sees end-of-stream rather than hanging on a process that will never
			// write again. Retained output survives Close and stays readable.
			capture.Close(ev.Container)
			// OOMKilled is deliberately not set here. It is the one fact only
			// the guest can supply, and this init does not yet read the cgroup2
			// memory.events that would prove it — so it is left false rather
			// than guessed, because upstream treats OOMKilled as the pod's own
			// fault and charges a restart against a Job's backoff.
			events.Publish(guestagent.ContainerEvent{
				Container: ev.Container,
				At:        time.Now(),
				Exited: &guestagent.ContainerExited{
					ExitCode: int32(ev.Status.ExitCode),
					Signal:   int32(ev.Status.Signal),
				},
			})
		},
	})
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	go func() {
		if err := reaper.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("reap loop ended", "err", err)
		}
	}()

	if err := startContainers(ctx, log, reaper, events, capture, plan.Containers); err != nil {
		// Anything already running has to be torn down; Stop is the only
		// path that both signals and powers off.
		return reaper.Fail(ctx, defaultStopGrace, err)
	}

	// The agent comes up last, once there is a pod for it to answer about. That
	// ordering is why the event bus retains state: every container has already
	// started by the time anything can subscribe.
	status := &guestStatus{}
	// The leased address becomes HealthResponse.guest_ip, which is what the host
	// polls for a vm pod's live transport address (pkg/runtime's guest-lease
	// watcher). Until this line it was never set and that field was empty for the
	// whole life of every vm pod.
	status.setGuestIP(netCfg.Lease.Address.String())
	rawCmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return reaper.Fail(ctx, defaultStopGrace, fmt.Errorf("read %s: %w", cmdlinePath, err))
	}
	podID, err := guestagent.PodIDFromCmdline(string(rawCmdline))
	if err != nil {
		// fatal, not degraded. An agent that does not know its own pod cannot
		// perform the rejection guest.proto requires of it, and one that accepted
		// every pod_id would answer Exec, Logs and Stats for a pod it is not.
		return reaper.Fail(ctx, defaultStopGrace, err)
	}
	stopAgent, err := serveAgent(podID, spec.GetAgentPort(), guestagent.Deps{
		Runner:  &reaperRunner{names: names, reaper: reaper},
		Sampler: &cgroupSampler{root: cgroup2Root},
		Logs:    capture,
		Execer:  &procExecer{plans: byName, reaper: reaper, log: log},
		Status:  status,
		Events:  events,
		Logger:  log,
	}, log)
	if err != nil {
		// A guest with no agent is a pod the host can never exec into, read logs
		// from, meter, or stop gracefully — so this fails the boot rather than
		// running a pod nothing can observe or shut down.
		return reaper.Fail(ctx, defaultStopGrace, fmt.Errorf("serve the guest agent: %w", err))
	}
	defer stopAgent()
	status.setReady(plan.Binfmt != nil)

	term := make(chan os.Signal, 1)
	signal.Notify(term, unix.SIGTERM, unix.SIGINT)
	sig := <-term
	log.Info("shutting the guest down", "signal", sig)
	return reaper.Stop(ctx, defaultStopGrace)
}

// readSpec reads and decodes the host-written GuestSpec.
//
// Unknown fields are rejected. The file is the proto-JSON encoding of
// GuestSpec and nothing else, so a key this binary does not know means the
// host and the initramfs disagree about the contract — which must fail at boot
// with a legible reason rather than silently drop whatever the host asked for.
func readSpec(path string) (*guestv1.GuestSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read guest spec: %w", err)
	}
	spec := &guestv1.GuestSpec{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, spec); err != nil {
		return nil, fmt.Errorf("decode guest spec: %w", err)
	}
	return spec, nil
}

// applyMounts performs a plan's mount steps in order.
func applyMounts(log *slog.Logger, steps []guestinit.MountStep) error {
	for _, s := range steps {
		if s.IDMap != nil {
			// Refusing beats mounting without the idmap: a PVC written under
			// the wrong owner is damage that outlives the pod.
			return fmt.Errorf("mount %s requests an idmapped mount, which this guest does not yet apply", s.Target)
		}
		for _, dir := range s.MkdirExtra {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dir, err)
			}
		}
		switch {
		case s.TouchTarget:
			if err := os.MkdirAll(path.Dir(s.Target), 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", path.Dir(s.Target), err)
			}
			if err := touch(s.Target); err != nil {
				return err
			}
		case s.MkdirTarget:
			if err := os.MkdirAll(s.Target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", s.Target, err)
			}
		}
		flags, err := guestinit.LinuxMountFlags(s.Options)
		if err != nil {
			return err
		}
		log.Debug("mount", "source", s.Source, "target", s.Target, "type", s.FSType,
			"flags", flags, "data", s.Data, "why", s.Why)
		if err := unix.Mount(s.Source, s.Target, s.FSType, flags, s.Data); err != nil {
			return fmt.Errorf("mount %s at %s (%s): %w", s.Source, s.Target, s.Why, err)
		}
	}
	return nil
}

// touch creates an empty file if it is not there already.
func touch(name string) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}

// writeEtcFiles lays down the pod-level /etc content the per-container bind
// set shadows each image's own copies with.
func writeEtcFiles(etc guestinit.EtcFiles) error {
	if err := os.MkdirAll(guestinit.EtcDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", guestinit.EtcDir, err)
	}
	for name, content := range map[string]string{
		"resolv.conf": etc.ResolvConf,
		"hosts":       etc.Hosts,
		"hostname":    etc.Hostname,
	} {
		p := path.Join(guestinit.EtcDir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	return nil
}

// registerBinfmt mounts the Rosetta share and writes the registration line.
// The mount must precede the write: the F flag makes the kernel open the
// interpreter while it processes the registration.
func registerBinfmt(log *slog.Logger, reg guestinit.BinfmtRegistration) error {
	if err := applyMounts(log, []guestinit.MountStep{reg.ShareMount}); err != nil {
		return err
	}
	f, err := os.OpenFile(reg.RegisterPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", reg.RegisterPath, err)
	}
	defer func() { _ = f.Close() }()
	// One write(2): the kernel parses the registration per write, so a split
	// write is two malformed registrations rather than one good one.
	if _, err := f.WriteString(reg.Line); err != nil {
		return fmt.Errorf("register the %s interpreter: %w", reg.Name, err)
	}
	log.Info("registered a binfmt_misc interpreter", "name", reg.Name, "flags", guestinit.RosettaBinfmtFlags)
	return nil
}

// startContainers realizes the plan's containers in order: an init container
// is waited for and must exit 0, a main container is started and left running.
func startContainers(ctx context.Context, log *slog.Logger, reaper *guestinit.Reaper, events *guestagent.Events, capture *guestagent.Capture, plans []guestinit.ContainerPlan) error {
	for _, cp := range plans {
		if err := applyMounts(log, cp.Mounts); err != nil {
			return fmt.Errorf("container %s: %w", cp.Name, err)
		}
		pid, err := spawn(cp, capture, log)
		if err != nil {
			return fmt.Errorf("start container %s: %w", cp.Name, err)
		}
		reaper.Track(cp.Name, pid)
		events.Publish(guestagent.ContainerEvent{
			Container: cp.Name,
			At:        time.Now(),
			Started:   &guestagent.ContainerStarted{PID: int32(pid)},
		})
		log.Info("started a container", "container", cp.Name, "phase", cp.Phase, "pid", pid)

		if !cp.WaitForExit {
			continue
		}
		status, err := reaper.Wait(ctx, cp.Name)
		if err != nil {
			return fmt.Errorf("wait for init container %s: %w", cp.Name, err)
		}
		if status.ExitCode != 0 || status.Signal != 0 {
			return fmt.Errorf("init container %s failed: exit code %d, signal %d",
				cp.Name, status.ExitCode, status.Signal)
		}
	}
	return nil
}

// spawn resolves one container's program, then forks and execs it inside the
// container's composed rootfs, on its OWN stdout/stderr pipes.
//
// The child is chrooted, credentialed and given its own session before the
// exec; the working directory is applied after the chroot, so it is a path
// inside the container. Nothing here waits on the child: PID 1's reaper is the
// only process that may wait(2), and a second waiter would race it for the
// exit status.
//
// the PIPES are what MAKE `kubectl logs` POSSIBLE. Containers used to inherit
// PID 1's stdio, so every container's output went to the one guest console,
// undemultiplexed and unattributable, and the Logs RPC could only report that
// there was no per-container buffer to serve. Each stream is now pumped into
// capture's bounded ring for that container and tee'd to the console.
//
// stdin stays the console fd. A container's stdin is not plumbed anywhere yet,
// and giving it a pipe nothing writes to would turn a workload that reads stdin
// from a process that blocks into one that gets EOF — a different behaviour,
// chosen by accident.
//
// the CGROUP2 LEAF is JOINED BY the KERNEL, at FORK. The child is placed into
// <cgroup2Root>/<container> by CLONE_INTO_CGROUP (SysProcAttr.UseCgroupFD), so it
// has never executed a single instruction outside its own cgroup — there is no
// window in which its CPU time or its pages are charged to PID 1's cgroup, and
// nothing to race. Go gives no hook between fork and exec, so a post-fork write to
// cgroup.procs would be the only alternative, and it necessarily has that window.
// The post-fork JoinLeaf below is a reconcile for the one case this cannot cover
// (a kernel too old for clone3), not the mechanism.
func spawn(cp guestinit.ContainerPlan, capture *guestagent.Capture, log *slog.Logger) (int, error) {
	groups := make([]uint32, 0, len(cp.Ident.Groups))
	for _, g := range cp.Ident.Groups {
		groups = append(groups, uint32(g))
	}
	dir := cp.WorkingDir
	if dir == "" {
		dir = "/"
	}
	// argv[0] is resolved execvp-style INSIDE the container before the fork.
	// ForkExec is execve: it does no PATH search, so an image whose Entrypoint is
	// a bare name — which is most official images — could not start at all. The
	// resolution has to happen here and not host-side: only the guest has the
	// container's rootfs to stat, and only this container's own env supplies the
	// PATH to search. See guestinit.ResolveProgram.
	//
	// cp.Argv is passed to ForkExec UNCHANGED. execvp replaces only the path it
	// execs, never argv[0] itself, and programs that branch on their own name
	// (busybox, and every `docker-entrypoint.sh` that re-execs) read the argv the
	// image intended.
	prog, err := guestinit.ResolveProgram(cp.Root, cp.WorkingDir, cp.Argv[0], guestinit.PathFromEnv(cp.Env))
	if err != nil {
		return 0, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		closeAll(stdoutR, stdoutW)
		return 0, fmt.Errorf("stderr pipe: %w", err)
	}
	sys := &syscall.SysProcAttr{
		Chroot: cp.Root,
		Credential: &syscall.Credential{
			Uid:    uint32(cp.Ident.UID),
			Gid:    uint32(cp.Ident.GID),
			Groups: groups,
		},
		Setsid: true,
	}
	// The leaf is opened, not just created: CLONE_INTO_CGROUP takes a DIRECTORY
	// FD, and holding it across the fork is what makes the placement atomic.
	// Best effort — a guest that cannot make a leaf still runs its workload, it
	// just cannot meter it (see EnableSubtreeControllers).
	leaf, leafDir := "", (*os.File)(nil)
	if p, cerr := guestagent.CreateLeaf(cgroup2Root, cp.Name); cerr != nil {
		log.Warn("no cgroup2 leaf for a container; it will not be metered",
			"container", cp.Name, "err", cerr)
	} else if fd, oerr := os.Open(p); oerr != nil {
		log.Warn("could not open the cgroup2 leaf; the container will not be metered",
			"container", cp.Name, "leaf", p, "err", oerr)
	} else {
		leaf, leafDir = p, fd
		sys.UseCgroupFD = true
		sys.CgroupFD = int(fd.Fd())
	}
	if leafDir != nil {
		defer func() { _ = leafDir.Close() }()
	}
	attr := &syscall.ProcAttr{
		Dir:   dir,
		Env:   cp.Env,
		Files: []uintptr{0, stdoutW.Fd(), stderrW.Fd()},
		Sys:   sys,
	}
	pid, err := syscall.ForkExec(prog, cp.Argv, attr)
	// This process's copies of the child's write ends go immediately after the
	// fork: holding them open means the readers below never see EOF, so a
	// container's log stream would never end even after the container did.
	closeAll(stdoutW, stderrW)
	if err != nil {
		closeAll(stdoutR, stderrR)
		return 0, err
	}
	if leaf != "" {
		// The reconcile. On every kernel this guest ships against the child is
		// already a member and this write changes nothing; it repairs the
		// clone3-unavailable case. A failure means the container is unmetered, not
		// that it is unhealthy, so it is logged and not returned.
		if jerr := guestagent.JoinLeaf(leaf, pid); jerr != nil {
			log.Warn("could not confirm the container's cgroup2 membership; it may not be metered",
				"container", cp.Name, "leaf", leaf, "pid", pid, "err", jerr)
		}
	}
	go pumpOutput(stdoutR, capture.Writer(cp.Name, guestagent.StreamStdout), os.Stdout)
	go pumpOutput(stderrR, capture.Writer(cp.Name, guestagent.StreamStderr), os.Stderr)
	return pid, nil
}

// pumpOutput drains one of a container's output pipes into its ring, tee'ing to
// the console. It closes both ends at EOF, which flushes a final unterminated
// line into the ring and releases the pipe.
func pumpOutput(src *os.File, sink io.WriteCloser, console io.Writer) {
	defer func() {
		_ = sink.Close()
		_ = src.Close()
	}()
	_, _ = io.Copy(consoleTee{sink: sink, console: console}, src)
}

// consoleTee writes a container's output to its ring and, best effort, to the
// guest console.
//
// The ORDER and the ERROR HANDLING are both deliberate. The ring is written
// first and its result is the one returned, so a console that is full, closed or
// wedged can never stop the capture — an io.MultiWriter would abort the whole
// write on the console's error and silently cost the pod its logs. The console
// copy is kept because it is the only diagnostic left when the agent is down, and
// it costs nothing against the ring's bound: the two sinks are bounded
// independently (the ring here, the console by pkg/vmhost's CappedWriter on the
// host side).
type consoleTee struct {
	sink    io.Writer
	console io.Writer
}

func (t consoleTee) Write(p []byte) (int, error) {
	n, err := t.sink.Write(p)
	if t.console != nil {
		_, _ = t.console.Write(p)
	}
	return n, err
}
