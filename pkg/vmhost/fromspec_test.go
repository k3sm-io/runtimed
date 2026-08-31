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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"

	guestv1 "k3sm.io/apis/guest/v1"
)

// --- the fake filesystem the artifact checks go through --------------------

// fakeFileInfo is the minimum fs.FileInfo the artifact validator reads: a name, a
// mode, and nothing else. Using a fake rather than real files is what lets the
// "kernel is a directory" and "kernel is a device node" rows exist at all — the
// second cannot be created in a test tempdir without root.
type fakeFileInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 1 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// statTable is a Stat seam over a fixed path -> mode table; an absent path is
// os.ErrNotExist.
func statTable(modes map[string]fs.FileMode) func(string) (fs.FileInfo, error) {
	return func(name string) (fs.FileInfo, error) {
		mode, ok := modes[name]
		if !ok {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
		}
		return fakeFileInfo{name: filepath.Base(name), mode: mode}, nil
	}
}

const (
	testKernel    = "/var/lib/k3sm/guest/vmlinuz"
	testInitramfs = "/var/lib/k3sm/guest/initramfs.cpio.gz"
	testPodDir    = "/var/lib/k3sm/pods/pod-abc"
)

// baseOptions are the bounds every case starts from: real-shaped, injected, and
// wide enough that a case only sees clamping when it asks for it.
func baseOptions() Options {
	return Options{
		PodDir:             testPodDir,
		ConsoleLogPath:     testPodDir + "/console.log",
		MinVCPUs:           1,
		MaxVCPUs:           8,
		DefaultVCPUs:       2,
		MinMemoryBytes:     128 << 20,
		MaxMemoryBytes:     16 << 30,
		DefaultMemoryBytes: 512 << 20,
		Stat: statTable(map[string]fs.FileMode{
			testKernel:    0,
			testInitramfs: 0,
		}),
	}
}

// baseSpec is a minimal spec every case mutates: valid, and boring.
func baseSpec() *guestv1.VMHostSpec {
	return &guestv1.VMHostSpec{
		PodId:          "pod-abc",
		Vcpus:          2,
		MemoryBytes:    1 << 30,
		KernelPath:     testKernel,
		InitramfsPath:  testInitramfs,
		Cmdline:        "console=hvc0 quiet",
		AgentVsockPort: 1024,
	}
}

func share(tag, path string, ro bool) *guestv1.VMShare {
	return &guestv1.VMShare{Tag: tag, HostPath: path, ReadOnly: ro}
}

// findShare returns the config's share with the given tag.
func findShare(cfg MachineConfig, tag string) (ShareConfig, bool) {
	for _, s := range cfg.Shares {
		if s.Tag == tag {
			return s, true
		}
	}
	return ShareConfig{}, false
}

// TestMachineConfigFromSpec is B227's translator gate. FromSpec carries ALL the
// validation between an untranslated proto and a machine this helper is willing to
// boot, so this is the table that says what "willing" means.
//
// Every subtest is a row of that table, and each is here because the failure it
// forecloses is silent rather than loud: a share that boots writable when it was
// meant read-only, a spec share whose absence kills the guest with an opaque
// message, an ancestor pair that undoes a read-only flag through the parent
// device, a clamp that wraps instead of saturating.
//
// EVERY assertion is a t.Run subtest of this ONE function on purpose: the gate runs
// `go test -run '^TestMachineConfigFromSpec$'`, so a sibling top-level Test* would
// be silently filtered out and never run.
//
// Hermetic: no filesystem (the Stat seam is a table), no Virtualization framework,
// no VM. It runs identically on Linux CI and on an unentitled Mac.
func TestMachineConfigFromSpec(t *testing.T) {
	t.Run("translates-the-happy-path", func(t *testing.T) {
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{
			share(mount.ShareTagRootfs, testPodDir+"/rootfs", true),
			share(mount.ShareTagVols, testPodDir+"/k3sm.vols", false),
		}
		cfg, err := FromSpec(spec, baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		if cfg.PodID != "pod-abc" {
			t.Errorf("PodID = %q, want pod-abc", cfg.PodID)
		}
		if cfg.VCPUs != 2 || cfg.MemoryBytes != 1<<30 {
			t.Errorf("size = %d vcpu / %d bytes, want 2 / %d", cfg.VCPUs, cfg.MemoryBytes, int64(1<<30))
		}
		if cfg.Boot.KernelPath != testKernel || cfg.Boot.InitramfsPath != testInitramfs {
			t.Errorf("boot = %+v, want the spec's artifacts", cfg.Boot)
		}
		// Carried verbatim, PLUS the pod-id parameter FromSpec appends (see the
		// dedicated subtest below for why it has to).
		if want := "console=hvc0 quiet " + guestagent.PodIDCmdlineKey + "=pod-abc"; cfg.Boot.Cmdline != want {
			t.Errorf("cmdline = %q, want %q", cfg.Boot.Cmdline, want)
		}
		if cfg.Vsock.AgentPort != 1024 {
			t.Errorf("agent port = %d, want 1024", cfg.Vsock.AgentPort)
		}
		if !cfg.Entropy {
			t.Error("no entropy device: a fresh micro-VM has almost no entropy of its own")
		}
		if !cfg.Balloon {
			t.Error("no balloon device: it cannot be added to a running machine, so a guest booted without one can never have memory reclaimed")
		}
		if cfg.Console.LogPath != testPodDir+"/console.log" || cfg.Console.MaxBytes != DefaultConsoleMaxBytes {
			t.Errorf("console = %+v, want the option's path and the default cap", cfg.Console)
		}
	})

	// --- the k3sm.spec share: the one nothing else produces -----------------

	t.Run("appends-the-guest-spec-share", func(t *testing.T) {
		// pkg/guestinit mounts guestinit.SpecShareTag as its FIRST act and cannot
		// boot without it, while pkg/mount's ComputeSharePlan emits only
		// rootfs/proj/vols/pvc. If FromSpec did not append it, every guest would
		// die at boot with "cannot find its spec" and nothing would point here.
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{share(mount.ShareTagRootfs, testPodDir+"/rootfs", true)}
		cfg, err := FromSpec(spec, baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		s, ok := findShare(cfg, guestinit.SpecShareTag)
		if !ok {
			t.Fatalf("no %s share; the guest init mounts it first and cannot boot without it. shares = %+v",
				guestinit.SpecShareTag, cfg.Shares)
		}
		if want := filepath.Join(testPodDir, guestinit.SpecShareTag); s.Root != want {
			t.Errorf("%s share root = %q, want %q", guestinit.SpecShareTag, s.Root, want)
		}
		if !s.ReadOnly {
			t.Errorf("%s share is writable; a guest that could rewrite its own boot spec could re-describe itself", guestinit.SpecShareTag)
		}
	})

	t.Run("refuses-a-spec-supplied-spec-share", func(t *testing.T) {
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{share(guestinit.SpecShareTag, testPodDir+"/elsewhere", false)}
		_, err := FromSpec(spec, baseOptions())
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("err = %v, want ErrInvalidSpec: the spec device is appended by the VM host, so a supplied one is a contract disagreement", err)
		}
	})

	t.Run("refuses-without-a-pod-dir", func(t *testing.T) {
		opts := baseOptions()
		opts.PodDir = ""
		if _, err := FromSpec(baseSpec(), opts); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("err = %v, want ErrInvalidSpec: without a pod dir the spec share has no root", err)
		}
	})

	// --- read-only is enforced at the device, not trusted from the producer --

	t.Run("forces-read-only-on-the-protected-tags", func(t *testing.T) {
		for _, tag := range []string{mount.ShareTagRootfs, mount.ShareTagProj} {
			t.Run(tag, func(t *testing.T) {
				spec := baseSpec()
				// The producer says WRITABLE. It must not be believed.
				spec.Shares = []*guestv1.VMShare{share(tag, testPodDir+"/"+tag, false)}
				cfg, err := FromSpec(spec, baseOptions())
				if err != nil {
					t.Fatalf("FromSpec: %v", err)
				}
				s, ok := findShare(cfg, tag)
				if !ok {
					t.Fatalf("share %q missing from %+v", tag, cfg.Shares)
				}
				if !s.ReadOnly {
					t.Errorf("share %q is writable; the VZ device flag is the ONLY enforcement point a guest cannot reach, and %q must never be writable from inside a guest", tag, tag)
				}
			})
		}
	})

	t.Run("leaves-an-unprotected-share-writable", func(t *testing.T) {
		// The converse: forcing read-only must be scoped, not blanket. A writable
		// emptyDir that came back read-only would break every pod that writes.
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{share(mount.ShareTagVols, testPodDir+"/k3sm.vols", false)}
		cfg, err := FromSpec(spec, baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		s, _ := findShare(cfg, mount.ShareTagVols)
		if s.ReadOnly {
			t.Errorf("share %q came back read-only; the forced set must be exactly the protected tags", mount.ShareTagVols)
		}
	})

	// --- share tags ----------------------------------------------------------

	t.Run("rejects-bad-share-tags", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			tag  string
		}{
			{"empty", ""},
			{"over-the-vz-36-byte-limit", strings.Repeat("t", maxShareTagBytes+1)},
			{"path-separator", "k3sm/rootfs"},
			{"control-character", "k3sm\x01rootfs"},
			{"non-ascii", "k3sm.rööt"},
			{"space", "k3sm rootfs"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.Shares = []*guestv1.VMShare{share(tc.tag, testPodDir+"/x", true)}
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("tag %q accepted (err = %v); VZ would reject it at device construction as an opaque framework error", tc.tag, err)
				}
			})
		}
	})

	t.Run("accepts-a-tag-at-exactly-the-limit", func(t *testing.T) {
		// The boundary in the other direction: an off-by-one here would reject a
		// legal tag and fail the pod for no reason.
		tag := strings.Repeat("t", maxShareTagBytes)
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{share(tag, testPodDir+"/x", true)}
		if _, err := FromSpec(spec, baseOptions()); err != nil {
			t.Errorf("a %d-byte tag was rejected: %v", maxShareTagBytes, err)
		}
	})

	t.Run("rejects-a-duplicate-tag", func(t *testing.T) {
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{
			share("k3sm.dup", testPodDir+"/a", true),
			share("k3sm.dup", testPodDir+"/b", true),
		}
		if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("err = %v, want ErrInvalidSpec: a guest mounts by tag, so the second device would be unreachable", err)
		}
	})

	// --- share roots ---------------------------------------------------------

	t.Run("rejects-bad-share-roots", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			root string
		}{
			{"empty", ""},
			{"relative", "pods/pod-abc/rootfs"},
			{"unclean-traversal", "/var/lib/k3sm/pods/pod-abc/../../etc"},
			{"trailing-slash", "/var/lib/k3sm/pods/pod-abc/rootfs/"},
			{"filesystem-root", "/"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.Shares = []*guestv1.VMShare{share("k3sm.x", tc.root, true)}
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("root %q accepted (err = %v)", tc.root, err)
				}
			})
		}
	})

	t.Run("rejects-ancestor-share-roots", func(t *testing.T) {
		// The invariant that makes the read-only flags mean anything: with one
		// root inside another, the guest reaches the inner tree THROUGH the outer
		// device, under the OUTER device's flag — so a writable parent silently
		// hands write access to a read-only child.
		for _, tc := range []struct {
			name string
			a, b string
		}{
			{"parent-then-child", testPodDir, testPodDir + "/rootfs"},
			{"child-then-parent", testPodDir + "/rootfs", testPodDir},
			{"identical", testPodDir + "/rootfs", testPodDir + "/rootfs"},
			{"spec-share-under-a-declared-share", testPodDir, testPodDir + "/other"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.Shares = []*guestv1.VMShare{
					share("k3sm.a", tc.a, false),
					share("k3sm.b", tc.b, true),
				}
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("roots %q and %q accepted (err = %v)", tc.a, tc.b, err)
				}
			})
		}
	})

	t.Run("the-appended-spec-share-is-in-the-disjointness-check", func(t *testing.T) {
		// The appended device is not exempt from the invariant it joins: a
		// declared share rooted AT the pod dir would contain it.
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{share("k3sm.wide", testPodDir, false)}
		if _, gotErr := FromSpec(spec, baseOptions()); !errors.Is(gotErr, ErrInvalidSpec) {
			t.Errorf("err = %v, want ErrInvalidSpec: a share rooted at the pod dir contains the appended %s share", gotErr, guestinit.SpecShareTag)
		}
	})

	t.Run("sibling-prefix-roots-are-not-ancestors", func(t *testing.T) {
		// The string-prefix trap: /a/rootfs-old is NOT under /a/rootfs. Rejecting
		// it would break legitimate plans, so the check is on path components.
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{
			share("k3sm.a", testPodDir+"/rootfs", true),
			share("k3sm.b", testPodDir+"/rootfs-old", true),
		}
		if _, err := FromSpec(spec, baseOptions()); err != nil {
			t.Errorf("sibling roots sharing a string prefix were rejected: %v", err)
		}
	})

	// --- sizing --------------------------------------------------------------

	t.Run("defaults-and-clamps-the-machine-size", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			vcpus      uint32
			memory     int64
			wantVCPUs  uint
			wantMemory uint64
		}{
			{"zero-takes-the-default", 0, 0, 2, 512 << 20},
			{"over-the-max-is-clamped-down", 64, 64 << 30, 8, 16 << 30},
			{"under-the-min-is-clamped-up", 1, 1 << 20, 1, 128 << 20},
			{"in-range-is-carried", 4, 2 << 30, 4, 2 << 30},
			// A negative memory_bytes must mean "unset", not wrap to an enormous
			// unsigned value the clamp would then pin to the host maximum —
			// handing a pod the whole machine because a field was mis-set.
			{"negative-memory-is-unset-not-wrapped", 2, -1, 2, 512 << 20},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.Vcpus, spec.MemoryBytes = tc.vcpus, tc.memory
				cfg, err := FromSpec(spec, baseOptions())
				if err != nil {
					t.Fatalf("FromSpec: %v", err)
				}
				if cfg.VCPUs != tc.wantVCPUs {
					t.Errorf("VCPUs = %d, want %d", cfg.VCPUs, tc.wantVCPUs)
				}
				if cfg.MemoryBytes != tc.wantMemory {
					t.Errorf("MemoryBytes = %d, want %d", cfg.MemoryBytes, tc.wantMemory)
				}
			})
		}
	})

	// --- artifacts -----------------------------------------------------------

	t.Run("rejects-bad-guest-artifacts", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			kernel, initrd   string
			modes            map[string]fs.FileMode
			wantErrSubstring string
		}{
			{
				name: "kernel-missing", kernel: testKernel, initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testInitramfs: 0},
				wantErrSubstring: "kernel_path",
			},
			{
				name: "initramfs-missing", kernel: testKernel, initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testKernel: 0},
				wantErrSubstring: "initramfs_path",
			},
			{
				// The shape a half-finished artifact install leaves behind.
				name: "kernel-is-a-directory", kernel: testKernel, initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testKernel: fs.ModeDir, testInitramfs: 0},
				wantErrSubstring: "directory",
			},
			{
				name: "kernel-is-a-device-node", kernel: testKernel, initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testKernel: fs.ModeDevice, testInitramfs: 0},
				wantErrSubstring: "regular file",
			},
			{
				name: "kernel-relative", kernel: "guest/vmlinuz", initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testInitramfs: 0},
				wantErrSubstring: "absolute",
			},
			{
				name: "kernel-unclean", kernel: "/var/lib/k3sm/guest/../guest/vmlinuz", initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testInitramfs: 0},
				wantErrSubstring: "clean",
			},
			{
				name: "kernel-empty", kernel: "", initrd: testInitramfs,
				modes:            map[string]fs.FileMode{testInitramfs: 0},
				wantErrSubstring: "empty",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.KernelPath, spec.InitramfsPath = tc.kernel, tc.initrd
				opts := baseOptions()
				opts.Stat = statTable(tc.modes)
				_, err := FromSpec(spec, opts)
				if !errors.Is(err, ErrInvalidSpec) {
					t.Fatalf("err = %v, want ErrInvalidSpec", err)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Errorf("err = %v, want it to name %q — VZ's own message for this is unhelpful, which is why the check is here", err, tc.wantErrSubstring)
				}
			})
		}
	})

	// --- MAC -----------------------------------------------------------------

	t.Run("derives-a-stable-mac-when-the-spec-names-none", func(t *testing.T) {
		cfg, err := FromSpec(baseSpec(), baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		if cfg.Network.MACAddress != DeriveMAC("pod-abc") {
			t.Errorf("MAC = %q, want the derivation from the pod id (%q)", cfg.Network.MACAddress, DeriveMAC("pod-abc"))
		}
	})

	t.Run("accepts-a-spec-supplied-locally-administered-mac", func(t *testing.T) {
		spec := baseSpec()
		spec.MacAddress = "02:11:22:33:44:55"
		cfg, err := FromSpec(spec, baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		if cfg.Network.MACAddress != "02:11:22:33:44:55" {
			t.Errorf("MAC = %q, want the spec's", cfg.Network.MACAddress)
		}
	})

	t.Run("rejects-illegal-macs", func(t *testing.T) {
		for _, tc := range []struct{ name, mac string }{
			{"unparseable", "not-a-mac"},
			{"multicast", "03:11:22:33:44:55"},
			{"globally-unique", "00:11:22:33:44:55"},
			{"eui-64", "02:11:22:33:44:55:66:77"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.MacAddress = tc.mac
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("mac %q accepted (err = %v)", tc.mac, err)
				}
			})
		}
	})

	// --- the rest ------------------------------------------------------------

	t.Run("rejects-a-rosetta-request", func(t *testing.T) {
		// B229's other half, at the helper: the node does not advertise
		// guest-Rosetta, and if a spec asks for it anyway the helper refuses rather
		// than booting a guest that silently cannot execute the payloads the share
		// was requested for.
		spec := baseSpec()
		spec.Rosetta = true
		_, err := FromSpec(spec, baseOptions())
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("err = %v, want ErrInvalidSpec while RosettaShareSupported is false", err)
		}
		cfg, err := FromSpec(baseSpec(), baseOptions())
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		if cfg.Rosetta {
			t.Error("MachineConfig.Rosetta is true; this helper attaches no Rosetta share")
		}
	})

	t.Run("carries-the-pod-id-on-the-kernel-command-line", func(t *testing.T) {
		// The guest has NO OTHER WAY to learn its own pod id: guest/v1's GuestSpec
		// carries no pod_id field, yet guest.proto requires the agent to reject a
		// pod_id that is not the pod it booted. Without this the agent could not
		// perform that check at all — it would either accept every id or fail every
		// pod.
		t.Run("appended-when-absent", func(t *testing.T) {
			cfg, err := FromSpec(baseSpec(), baseOptions())
			if err != nil {
				t.Fatalf("FromSpec: %v", err)
			}
			got, err := guestagent.PodIDFromCmdline(cfg.Boot.Cmdline)
			if err != nil {
				t.Fatalf("the cmdline carries no pod id (%q): the guest agent could not assert its own identity", cfg.Boot.Cmdline)
			}
			if got != "pod-abc" {
				t.Errorf("cmdline pod id = %q, want pod-abc", got)
			}
		})

		t.Run("left-alone-when-already-correct", func(t *testing.T) {
			spec := baseSpec()
			spec.Cmdline = "console=hvc0 " + guestagent.PodIDCmdlineKey + "=pod-abc"
			cfg, err := FromSpec(spec, baseOptions())
			if err != nil {
				t.Fatalf("FromSpec: %v", err)
			}
			if cfg.Boot.Cmdline != spec.Cmdline {
				t.Errorf("cmdline = %q, want it untouched (%q)", cfg.Boot.Cmdline, spec.Cmdline)
			}
		})

		t.Run("a-disagreeing-cmdline-is-refused", func(t *testing.T) {
			// The only case that could make a guest answer for the WRONG pod, so
			// it is a rejection rather than an overwrite: silently correcting it
			// would hide a producer bug that is about identity.
			spec := baseSpec()
			spec.Cmdline = guestagent.PodIDCmdlineKey + "=pod-someone-else"
			if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("err = %v, want ErrInvalidSpec", err)
			}
		})

		t.Run("an-empty-cmdline-becomes-just-the-parameter", func(t *testing.T) {
			spec := baseSpec()
			spec.Cmdline = ""
			cfg, err := FromSpec(spec, baseOptions())
			if err != nil {
				t.Fatalf("FromSpec: %v", err)
			}
			if want := guestagent.PodIDCmdlineKey + "=pod-abc"; cfg.Boot.Cmdline != want {
				t.Errorf("cmdline = %q, want %q (no leading space)", cfg.Boot.Cmdline, want)
			}
		})
	})

	t.Run("rejects-a-zero-agent-port", func(t *testing.T) {
		spec := baseSpec()
		spec.AgentVsockPort = 0
		if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("err = %v, want ErrInvalidSpec: with no port the host could never reach the guest agent", err)
		}
	})

	t.Run("rejects-bad-pod-ids", func(t *testing.T) {
		for _, tc := range []struct{ name, id string }{
			{"empty", ""},
			{"path-separator", "ns/pod"},
			{"parent", ".."},
			{"dot", "."},
			{"control-character", "pod\x00abc"},
			{"non-ascii", "pöd"},
			{"over-length", strings.Repeat("p", 254)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.PodId = tc.id
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("pod_id %q accepted (err = %v)", tc.id, err)
				}
			})
		}
	})

	t.Run("rejects-a-cmdline-that-would-silently-truncate", func(t *testing.T) {
		for _, tc := range []struct{ name, cmdline string }{
			{"nul", "console=hvc0\x00root=/dev/vda"},
			{"newline", "console=hvc0\nroot=/dev/vda"},
			{"carriage-return", "console=hvc0\rroot=/dev/vda"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := baseSpec()
				spec.Cmdline = tc.cmdline
				if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
					t.Errorf("cmdline %q accepted (err = %v); the guest would boot with different arguments from the ones the spec named", tc.cmdline, err)
				}
			})
		}
	})

	t.Run("rejects-a-nil-spec-and-a-nil-share", func(t *testing.T) {
		if _, err := FromSpec(nil, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("nil spec err = %v, want ErrInvalidSpec", err)
		}
		spec := baseSpec()
		spec.Shares = []*guestv1.VMShare{nil}
		if _, err := FromSpec(spec, baseOptions()); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("nil share err = %v, want ErrInvalidSpec", err)
		}
	})

	t.Run("uses-os-stat-when-no-seam-is-injected", func(t *testing.T) {
		// The default path has to be exercised too, or a production-only nil-Stat
		// panic would never be caught by this table.
		dir := t.TempDir()
		kernel := filepath.Join(dir, "vmlinuz")
		initrd := filepath.Join(dir, "initramfs")
		for _, p := range []string{kernel, initrd} {
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
		}
		spec := baseSpec()
		spec.KernelPath, spec.InitramfsPath = kernel, initrd
		opts := baseOptions()
		opts.Stat = nil
		opts.PodDir = filepath.Join(dir, "pod")
		if _, err := FromSpec(spec, opts); err != nil {
			t.Errorf("FromSpec with the default Stat: %v", err)
		}
	})
}

// TestRosettaShareCapabilityIsSingleValued binds this helper's own statement about
// the Rosetta share to the one the node ADVERTISES to the cluster.
//
// The two constants cannot be one: pkg/sandbox is imported by the daemon and this
// package imports github.com/Code-Hex/vz, so an import either way would drag the
// Virtualization-linking module into the shipped binary — the exact coupling the
// helper split exists to prevent. A test may import both, so the agreement is
// pinned here instead of by a compiler.
//
// If they ever disagree the failure is not cosmetic: the node advertises
// guest-Rosetta, pkg/image adds linux/amd64 to the pull candidate set for every vm
// pod, and each such image is pulled and then fails to execute in a guest with no
// interpreter registered.
func TestRosettaShareCapabilityIsSingleValued(t *testing.T) {
	if RosettaShareSupported != sandbox.VMHostRosettaShareSupported {
		t.Fatalf("vmhost.RosettaShareSupported = %v but sandbox.VMHostRosettaShareSupported = %v; "+
			"the node would advertise a guest capability the VM host does not build (or withhold one it does)",
			RosettaShareSupported, sandbox.VMHostRosettaShareSupported)
	}
}
