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

package vmhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/Code-Hex/vz/v3"
)

// THIS FILE IS THE ONLY PLACE IN k3sm THAT IMPORTS github.com/Code-Hex/vz.
//
// Everything above it in this package is pure Go with no framework in it, and
// nothing below it exists — realize is one-way, so no framework object ever
// becomes an input to a decision. Keeping the import to a single tagged file is
// what makes the entitlement split auditable: `go list -deps` on the daemon's
// packages must not reach this module, which is asserted by a test rather than
// trusted (TestVZIsNotReachableFromTheDaemon).

// realize turns a validated MachineConfig into a VZVirtualMachineConfiguration.
//
// IT IS A MECHANICAL TRANSLATION AND NOTHING ELSE. Every decision — sizes, paths,
// tags, read-only flags, the MAC, whether Rosetta is attached — was made and
// checked by FromSpec, on a value a test can build anywhere. What is left here is
// field-for-field construction plus the framework's own Validate, so the code that
// needs a Mac to run is also the code with no judgement in it.
//
// The one thing it does decide is device PRESENCE for the fixed devices (console,
// vsock, entropy, balloon), and those are booleans on the config, so even that is
// upstream.
func realize(cfg MachineConfig) (*vz.VirtualMachineConfiguration, error) {
	if cfg.PodID == "" {
		return nil, errors.New("vmhost: realize called on a zero MachineConfig; build one with FromSpec")
	}

	bootOpts := []vz.LinuxBootLoaderOption{}
	if cfg.Boot.InitramfsPath != "" {
		bootOpts = append(bootOpts, vz.WithInitrd(cfg.Boot.InitramfsPath))
	}
	if cfg.Boot.Cmdline != "" {
		bootOpts = append(bootOpts, vz.WithCommandLine(cfg.Boot.Cmdline))
	}
	boot, err := vz.NewLinuxBootLoader(cfg.Boot.KernelPath, bootOpts...)
	if err != nil {
		return nil, fmt.Errorf("boot loader (kernel %s): %w", cfg.Boot.KernelPath, err)
	}

	vmc, err := vz.NewVirtualMachineConfiguration(boot, cfg.VCPUs, cfg.MemoryBytes)
	if err != nil {
		return nil, fmt.Errorf("machine configuration (%d vcpu, %d bytes): %w", cfg.VCPUs, cfg.MemoryBytes, err)
	}

	// Network: NAT only. A bridged attachment needs com.apple.vm.networking, a
	// RESTRICTED entitlement, and a pod does not need a LAN-visible address.
	nat, err := vz.NewNATNetworkDeviceAttachment()
	if err != nil {
		return nil, fmt.Errorf("nat network attachment: %w", err)
	}
	nic, err := vz.NewVirtioNetworkDeviceConfiguration(nat)
	if err != nil {
		return nil, fmt.Errorf("virtio-net device: %w", err)
	}
	hw, err := net.ParseMAC(cfg.Network.MACAddress)
	if err != nil {
		return nil, fmt.Errorf("mac address %q: %w", cfg.Network.MACAddress, err)
	}
	mac, err := vz.NewMACAddress(hw)
	if err != nil {
		return nil, fmt.Errorf("mac address %q: %w", cfg.Network.MACAddress, err)
	}
	nic.SetMACAddress(mac)
	vmc.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{nic})

	// Shares. The read-only flag is applied HERE, at the device, which is the only
	// enforcement point a guest cannot reach (see ShareConfig).
	fsDevices := make([]vz.DirectorySharingDeviceConfiguration, 0, len(cfg.Shares))
	for _, s := range cfg.Shares {
		dev, err := vz.NewVirtioFileSystemDeviceConfiguration(s.Tag)
		if err != nil {
			return nil, fmt.Errorf("virtiofs device %q: %w", s.Tag, err)
		}
		dir, err := vz.NewSharedDirectory(s.Root, s.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("virtiofs share %q (%s): %w", s.Tag, s.Root, err)
		}
		share, err := vz.NewSingleDirectoryShare(dir)
		if err != nil {
			return nil, fmt.Errorf("virtiofs single-directory share %q: %w", s.Tag, err)
		}
		dev.SetDirectoryShare(share)
		fsDevices = append(fsDevices, dev)
	}
	if len(fsDevices) > 0 {
		vmc.SetDirectorySharingDevicesVirtualMachineConfiguration(fsDevices)
	}

	// One vsock device. The agent's port is a guest-side listen, not a device
	// property, so nothing here names it.
	sock, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("virtio-socket device: %w", err)
	}
	vmc.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{sock})

	if cfg.Entropy {
		ent, err := vz.NewVirtioEntropyDeviceConfiguration()
		if err != nil {
			return nil, fmt.Errorf("virtio-rng device: %w", err)
		}
		vmc.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{ent})
	}
	if cfg.Balloon {
		bal, err := vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration()
		if err != nil {
			return nil, fmt.Errorf("memory balloon device: %w", err)
		}
		vmc.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{bal})
	}

	return vmc, nil
}

// vzRunner is the darwin machineRunner: a real VZVirtualMachine plus the console
// plumbing and the run goroutine that owns it.
//
// THE RUN GOROUTINE IS LOCKED TO ITS OS THREAD. Virtualization.framework is
// Objective-C with its own serial dispatch queue per machine, and Code-Hex/vz
// already marshals every call onto that queue — so this is a CONSERVATIVE choice,
// not a proven requirement. It costs one thread for the machine's lifetime, and it
// removes a whole class of "did this framework call happen on the thread it
// expected" question from a code path that can only be exercised on entitled
// hardware. If a hardware spike later shows it unnecessary, dropping it is a
// one-line change with a test that already passes.
type vzRunner struct {
	cfg MachineConfig
	log *slog.Logger

	// console holds the pipe ends and the log file the guest's serial output is
	// pumped through; closed by Stop and by a failed Start.
	console *consolePipes

	mu      sync.Mutex
	vm      *vz.VirtualMachine
	stopped chan struct{}
}

// consolePipes is the guest console plumbing: VZ writes the guest's serial output
// into out.w, a pump copies out.r into the size-capped log file, and in.r is the
// guest's (never written) input side.
//
// The INPUT PIPE EXISTS ONLY BECAUSE THE API DEMANDS IT.
// VZFileHandleSerialPortAttachment takes both handles and dereferences both, so a
// nil read handle is a panic rather than "no input". Nothing ever writes to in.w;
// it is held open so the guest's console read side does not see EOF.
type consolePipes struct {
	inR, inW   *os.File
	outR, outW *os.File
	file       *os.File
	capped     *CappedWriter
	done       chan struct{}
}

func (c *consolePipes) close() {
	if c == nil {
		return
	}
	// Closing the WRITE end first ends the pump's Read with EOF, so the pump exits
	// before anything it writes to is closed underneath it.
	_ = c.outW.Close()
	if c.done != nil {
		<-c.done
	}
	_ = c.outR.Close()
	_ = c.inW.Close()
	_ = c.inR.Close()
	if c.file != nil {
		_ = c.file.Close()
	}
}

// newConsolePipes opens the console plumbing for cfg and starts the pump.
func newConsolePipes(cfg ConsoleConfig, log *slog.Logger) (*consolePipes, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("console input pipe: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, fmt.Errorf("console output pipe: %w", err)
	}

	c := &consolePipes{inR: inR, inW: inW, outR: outR, outW: outW, done: make(chan struct{})}
	if cfg.LogPath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o750); err != nil {
			c.closeFDs()
			return nil, fmt.Errorf("console log dir: %w", err)
		}
		// 0600: the console carries whatever the guest printed, which for a
		// misbehaving workload can include anything it had in memory.
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			c.closeFDs()
			return nil, fmt.Errorf("console log %s: %w", cfg.LogPath, err)
		}
		c.file = f
	}
	var sink io.Writer
	if c.file != nil {
		sink = c.file
	}
	c.capped = NewCappedWriter(sink, cfg.MaxBytes)

	go func() {
		defer close(c.done)
		if _, err := io.Copy(c.capped, c.outR); err != nil {
			log.Debug("the guest console pump ended", "err", err)
		}
		if c.capped.Truncated() {
			log.Warn("the guest console log hit its size cap; later console output was discarded",
				"path", cfg.LogPath, "cap_bytes", cfg.MaxBytes)
		}
	}()
	return c, nil
}

// closeFDs releases the pipe fds on a construction failure, before the pump exists.
func (c *consolePipes) closeFDs() {
	_ = c.inR.Close()
	_ = c.inW.Close()
	_ = c.outR.Close()
	_ = c.outW.Close()
}

// NewVZMachine builds the darwin VZ-backed machine runner for cfg and the vsock
// dialer that reaches its guest agent.
//
// The dialer is returned ALONGSIDE the runner rather than derived from it later
// because a vsock connection can only be made through the machine's own socket
// device: the two are one object, and handing back a dialer that closes over it
// keeps the caller from needing to know that.
func NewVZMachine(cfg MachineConfig, log *slog.Logger) (machineRunner, vsockDialer, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &vzRunner{cfg: cfg, log: log, stopped: make(chan struct{})}
	return r, r.dialAgent, nil
}

// Start builds the machine and boots it, then hands ownership to a thread-locked
// goroutine for the rest of its life. It returns once the machine is running.
func (r *vzRunner) Start(ctx context.Context) error {
	vmc, err := realize(r.cfg)
	if err != nil {
		return err
	}

	console, err := newConsolePipes(r.cfg.Console, r.log)
	if err != nil {
		return err
	}
	attachment, err := vz.NewFileHandleSerialPortAttachment(console.inR, console.outW)
	if err != nil {
		console.close()
		return fmt.Errorf("console attachment: %w", err)
	}
	port, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(attachment)
	if err != nil {
		console.close()
		return fmt.Errorf("console serial port: %w", err)
	}
	vmc.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{port})
	r.console = console

	if ok, err := vmc.Validate(); err != nil || !ok {
		console.close()
		return fmt.Errorf("the machine configuration is not valid: %w", err)
	}

	vm, err := vz.NewVirtualMachine(vmc)
	if err != nil {
		console.close()
		return fmt.Errorf("create the virtual machine: %w", err)
	}
	r.mu.Lock()
	r.vm = vm
	r.mu.Unlock()

	started := make(chan error, 1)
	go func() {
		// See the type doc: conservative, one thread for the machine's lifetime.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		started <- vm.Start()

		// The live run loop. It exists so the machine's owning goroutine — and its
		// locked thread — stay alive for as long as the machine does, rather than
		// the machine being kept alive only by a Go finalizer's whim.
		for state := range vm.StateChangedNotify() {
			r.log.Info("virtual machine state changed", "state", state.String(), "pod", r.cfg.PodID)
			if state == vz.VirtualMachineStateStopped || state == vz.VirtualMachineStateError {
				break
			}
		}
		close(r.stopped)
	}()

	select {
	case err := <-started:
		if err != nil {
			console.close()
			return fmt.Errorf("start the virtual machine: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until the machine has left the running state.
func (r *vzRunner) Wait(ctx context.Context) error {
	select {
	case <-r.stopped:
		r.console.close()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop halts the machine without giving the guest a chance to stop cleanly. It is
// safe on an already-stopped machine: a machine that cannot be stopped is reported
// as stopped, because that is what it is.
func (r *vzRunner) Stop(ctx context.Context) error {
	r.mu.Lock()
	vm := r.vm
	r.mu.Unlock()
	if vm == nil {
		return nil
	}
	if !vm.CanStop() {
		r.console.close()
		return nil
	}
	if err := vm.Stop(); err != nil {
		return fmt.Errorf("halt the virtual machine: %w", err)
	}
	select {
	case <-r.stopped:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.console.close()
	return nil
}

// dialAgent opens one connection to the guest agent's vsock port through the
// machine's socket device.
func (r *vzRunner) dialAgent(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	vm := r.vm
	r.mu.Unlock()
	if vm == nil {
		return nil, errors.New("vmhost: the machine is not running, so its guest agent cannot be reached")
	}
	devices := vm.SocketDevices()
	if len(devices) == 0 {
		return nil, errors.New("vmhost: the machine has no virtio-socket device")
	}
	conn, err := devices[0].Connect(r.cfg.Vsock.AgentPort)
	if err != nil {
		return nil, fmt.Errorf("connect to guest vsock port %d: %w", r.cfg.Vsock.AgentPort, err)
	}
	return conn, nil
}
