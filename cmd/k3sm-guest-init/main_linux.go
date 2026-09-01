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
// own gate: the eth0 DHCP client (so /etc/hosts carries no leased address yet,
// and HealthResponse.guest_ip is empty), the per-container cgroup2 leaves (so
// Stats omits every container rather than reporting zeros), per-container log
// capture (so Logs reports that the output is on the VM console instead of
// serving an empty stream), and pty allocation (so a tty exec is refused rather
// than run without a terminal). A spec requesting an idmapped mount is refused
// rather than mounted without the idmap.
package main

import (
	"context"
	"errors"
	"fmt"
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
		log.Error("guest init failed", "err", err)
	}
	// PID 1 must never simply exit — the kernel panics when it does, which
	// the host would see as an opaque VM death. Every path ends in a
	// poweroff, so the failure reason above is the last thing on the console.
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

	if err := startContainers(ctx, log, reaper, events, plan.Containers); err != nil {
		// Anything already running has to be torn down; Stop is the only
		// path that both signals and powers off.
		return errors.Join(err, reaper.Stop(ctx, defaultStopGrace))
	}

	// The agent comes up last, once there is a pod for it to answer about. That
	// ordering is why the event bus retains state: every container has already
	// started by the time anything can subscribe.
	status := &guestStatus{}
	rawCmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return errors.Join(fmt.Errorf("read %s: %w", cmdlinePath, err), reaper.Stop(ctx, defaultStopGrace))
	}
	podID, err := guestagent.PodIDFromCmdline(string(rawCmdline))
	if err != nil {
		// fatal, not degraded. An agent that does not know its own pod cannot
		// perform the rejection guest.proto requires of it, and one that accepted
		// every pod_id would answer Exec, Logs and Stats for a pod it is not.
		return errors.Join(err, reaper.Stop(ctx, defaultStopGrace))
	}
	stopAgent, err := serveAgent(podID, spec.GetAgentPort(), guestagent.Deps{
		Runner:  &reaperRunner{names: names, reaper: reaper},
		Sampler: &cgroupSampler{root: cgroup2Root},
		Logs:    &ringLogs{},
		Execer:  &procExecer{plans: byName, reaper: reaper, log: log},
		Status:  status,
		Events:  events,
		Logger:  log,
	}, log)
	if err != nil {
		// A guest with no agent is a pod the host can never exec into, read logs
		// from, meter, or stop gracefully — so this fails the boot rather than
		// running a pod nothing can observe or shut down.
		return errors.Join(fmt.Errorf("serve the guest agent: %w", err), reaper.Stop(ctx, defaultStopGrace))
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
func startContainers(ctx context.Context, log *slog.Logger, reaper *guestinit.Reaper, events *guestagent.Events, plans []guestinit.ContainerPlan) error {
	for _, cp := range plans {
		if err := applyMounts(log, cp.Mounts); err != nil {
			return fmt.Errorf("container %s: %w", cp.Name, err)
		}
		pid, err := spawn(cp)
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

// spawn forks and execs one container's process inside its composed rootfs.
//
// The child is chrooted, credentialed and given its own session before the
// exec; the working directory is applied after the chroot, so it is a path
// inside the container. Nothing here waits on the child: PID 1's reaper is the
// only process that may wait(2), and a second waiter would race it for the
// exit status.
func spawn(cp guestinit.ContainerPlan) (int, error) {
	groups := make([]uint32, 0, len(cp.Ident.Groups))
	for _, g := range cp.Ident.Groups {
		groups = append(groups, uint32(g))
	}
	dir := cp.WorkingDir
	if dir == "" {
		dir = "/"
	}
	attr := &syscall.ProcAttr{
		Dir:   dir,
		Env:   cp.Env,
		Files: []uintptr{0, 1, 2},
		Sys: &syscall.SysProcAttr{
			Chroot: cp.Root,
			Credential: &syscall.Credential{
				Uid:    uint32(cp.Ident.UID),
				Gid:    uint32(cp.Ident.GID),
				Groups: groups,
			},
			Setsid: true,
		},
	}
	return syscall.ForkExec(cp.Argv[0], cp.Argv, attr)
}
