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

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/guestinit"
	"k3sm.io/runtimed/pkg/supervisor"

	guestv1 "k3sm.io/apis/guest/v1"
)

// guestSpecFixture is a FULLY POPULATED vm pod: two containers (one init), a
// read-only pooled projected share, a writable pooled emptyDir share, a claim
// mounted whole, a Memory emptyDir, a structured resolver, an fsGroup, and a
// hostname. Every branch of the composer is reachable from it.
//
// It deliberately mirrors apis/guest/v1/testdata/guest-spec.json's pod — the
// schema's own executable statement of a realistic pod, and the same fixture
// pkg/guestinit's plan tests read — so the producer and the reader are argued
// about with one example rather than two that drift.
func guestSpecFixture() VMSpec {
	return VMSpec{
		PodID:           "pod-abc123",
		PodDir:          "/var/lib/k3sm/pods/pod-abc123",
		AgentSocketPath: "/var/lib/k3sm/run/vm/pod-abc123/agent.sock",
		Hostname:        "web-0",
		FSGroup:         2000,
		Network: GuestNetworkConfig{
			Nameservers: []string{"10.43.0.10"},
			Searches:    []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"},
			Options:     []string{"ndots:5"},
			// The rendered form is present too, and must NOT appear anywhere in
			// the composed spec: see TestBuildGuestSpecReadsOnlyTheStructuredResolver.
			ResolvConf: "nameserver 10.43.0.10\nsearch default.svc.cluster.local\noptions ndots:5\n",
		},
		Containers: []VMContainer{
			{
				Name: "init-db", Init: true, RootfsTag: "k3sm.rootfs.init-db",
				Argv: []string{"/bin/sh", "-c", "initdb /pgdata"},
				Env:  []string{"PGDATA=/pgdata"}, WorkingDir: "/",
				UID: 999, GID: 999,
			},
			{
				Name: "postgres", RootfsTag: "k3sm.rootfs.postgres",
				Argv:       []string{"/usr/local/bin/postgres", "-D", "/pgdata"},
				Env:        []string{"PGDATA=/pgdata", "POSTGRES_DB=stockkitty"},
				WorkingDir: "/var/lib/postgresql", TTY: true,
				UID: 999, GID: 999, SupplementalGIDs: []int64{999, 2000},
			},
		},
		Volumes: VMVolumePlan{
			Shares: []VMShare{
				{Tag: "k3sm.rootfs.init-db", Root: "/var/lib/k3sm/pods/pod-abc123/rootfs/init-db"},
				{Tag: "k3sm.rootfs.postgres", Root: "/var/lib/k3sm/pods/pod-abc123/rootfs/postgres"},
				{Tag: "k3sm.proj", Root: "/var/lib/k3sm/pods/pod-abc123/k3sm.proj"},
				{Tag: "k3sm.vols", Root: "/var/lib/k3sm/pods/pod-abc123/k3sm.vols", Writable: true},
				{Tag: "k3sm.pvc0", Root: "/var/lib/k3sm/storage/pgdata", Writable: true},
			},
			Binds: map[string][]VMBind{
				"init-db": {
					{VolumeName: "sa-token", ShareTag: "k3sm.proj", SourceRel: "sa-token",
						MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
					{VolumeName: "pgdata", ShareTag: "k3sm.pvc0", MountPath: "/pgdata"},
				},
				"postgres": {
					{VolumeName: "sa-token", ShareTag: "k3sm.proj", SourceRel: "sa-token",
						MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
					{VolumeName: "pgdata", ShareTag: "k3sm.pvc0", MountPath: "/pgdata"},
					{VolumeName: "cache", ShareTag: "k3sm.vols", SourceRel: "cache", MountPath: "/cache"},
				},
			},
			Tmpfs: map[string][]VMTmpfs{
				"postgres": {{VolumeName: "shm", MountPath: "/dev/shm", SizeLimit: "64Mi"}},
			},
		},
	}
}

// TestGuestSpecGolden pins the whole composition against a committed
// guest-spec.json. Run with -update to regenerate it.
//
// THE COMPARISON IS OVER THE DECODED MESSAGE, NOT THE BYTES — the same
// discipline TestCreateVMWritesTheMachineDescription and apis/guest/v1's own
// goldens use. protojson deliberately varies its whitespace between runs, so a
// byte comparison would be flaky in a way that says nothing about the contract.
// The golden FILE is still committed and reviewed: it is what a human reads to
// see what the guest is actually told, and a reviewer diffing it sees the
// semantic change even though the test does not compare its bytes.
func TestGuestSpecGolden(t *testing.T) {
	t.Parallel()
	got, err := buildGuestSpec(guestSpecFixture())
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	data, err := marshalGuestSpec(got)
	if err != nil {
		t.Fatalf("marshalGuestSpec: %v", err)
	}
	goldenPath := filepath.Join("testdata", VMGuestSpecFileName)
	if *update {
		// The COMMITTED bytes are re-indented with encoding/json. protojson
		// inserts inconsistent whitespace on purpose (to discourage exactly the
		// byte comparison this test does not do), and the golden's whole value
		// is that a human reads it in a review — so it is normalized for the
		// reader. It stays semantically identical to what writeGuestSpec emits,
		// which is what the decoded comparison below actually checks.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			t.Fatalf("indent golden: %v", err)
		}
		pretty.WriteByte('\n')
		if err := os.WriteFile(goldenPath, pretty.Bytes(), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want guestv1.GuestSpec
	// UNKNOWN FIELDS ARE REJECTED, exactly as the guest init's own reader
	// rejects them: a golden carrying a field guest/v1 no longer has must fail
	// here rather than be silently ignored into a passing test.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode the golden %s: %v", goldenPath, err)
	}
	if !proto.Equal(got, &want) {
		t.Errorf("composed guest spec differs from the golden %s.\n--- got ---\n%s\n--- want ---\n%s",
			goldenPath, data, raw)
	}
}

// TestGuestSpecAgreesWithTheMachineDescription pins the two equalities
// guest.proto REQUIRES between the pair of specs one host writes together: the
// agent port and the Rosetta flag. A disagreement makes the guest unreachable
// (the host would dial a port nothing listens on) or fails the boot outright
// (the helper refuses a Rosetta share it does not attach).
func TestGuestSpecAgreesWithTheMachineDescription(t *testing.T) {
	t.Parallel()
	spec := guestSpecFixture()
	gs, err := buildGuestSpec(spec)
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	hs := buildVMHostSpec(spec, GuestArtifacts{KernelPath: "/k", InitramfsPath: "/i", Cmdline: "console=hvc0"})
	if gs.GetAgentPort() != hs.GetAgentVsockPort() {
		t.Errorf("agent_port %d != agent_vsock_port %d", gs.GetAgentPort(), hs.GetAgentVsockPort())
	}
	if gs.GetAgentPort() != VMAgentVsockPort {
		t.Errorf("agent_port = %d, want the single-homed VMAgentVsockPort %d", gs.GetAgentPort(), VMAgentVsockPort)
	}
	if gs.GetRosetta() != hs.GetRosetta() {
		t.Errorf("GuestSpec.rosetta %v != VMHostSpec.rosetta %v", gs.GetRosetta(), hs.GetRosetta())
	}
	// R26 is in force: this node's helper attaches no Rosetta share, and the
	// composer MIRRORS that constant rather than deciding for itself.
	if gs.GetRosetta() != VMHostRosettaShareSupported {
		t.Errorf("rosetta = %v, want the helper's own VMHostRosettaShareSupported %v",
			gs.GetRosetta(), VMHostRosettaShareSupported)
	}
}

// TestGuestSpecFileNameIsTheGuestsOwnFileName pins the one string the host
// writer and the guest reader share. The guest reads an ABSOLUTE GUEST path
// (guestinit.SpecPath) and the host writes into a host directory, so the
// filename is the whole of their overlap — and a drift in it would present as a
// guest that boots, mounts its share, and finds nothing in it.
func TestGuestSpecFileNameIsTheGuestsOwnFileName(t *testing.T) {
	t.Parallel()
	if got := path.Base(guestinit.SpecPath); got != VMGuestSpecFileName {
		t.Errorf("guestinit.SpecPath basename = %q, want VMGuestSpecFileName %q", got, VMGuestSpecFileName)
	}
	if dir := path.Dir(guestinit.SpecPath); dir != guestinit.SpecMountPoint {
		t.Errorf("guestinit.SpecPath dir = %q, want the spec mount point %q", dir, guestinit.SpecMountPoint)
	}
}

// TestBuildGuestSpecReadsOnlyTheStructuredResolver is the NEGATIVE that proves
// no string-reparsing path exists.
//
// GuestNetworkConfig carries the DNS configuration twice — structured and
// host-rendered — and only the structured triple may cross, because the guest
// renders /etc/resolv.conf musl-safely for its own libc. A composer that read
// the rendered string would be re-parsing its own output to refill the message
// the proto shape exists to keep structured, and the bug would be INVISIBLE in
// the golden (both forms describe the same configuration). So the fixture here
// carries ONLY the rendered string: the honest answer is an absent resolv_conf.
func TestBuildGuestSpecReadsOnlyTheStructuredResolver(t *testing.T) {
	t.Parallel()

	t.Run("rendered-only carries no resolver into the guest", func(t *testing.T) {
		spec := guestSpecFixture()
		spec.Network = GuestNetworkConfig{
			ResolvConf: "nameserver 10.43.0.10\nsearch svc.cluster.local\noptions ndots:5\n",
		}
		gs, err := buildGuestSpec(spec)
		if err != nil {
			t.Fatalf("buildGuestSpec: %v", err)
		}
		if gs.GetResolvConf() != nil {
			t.Fatalf("resolv_conf = %v, want nil: the rendered string must never be re-parsed into the structured message",
				gs.GetResolvConf())
		}
		// And the guest's own renderer, handed that absence, emits a file with
		// no resolver rather than inventing one.
		rendered, _ := guestinit.RenderResolvConf(gs.GetResolvConf())
		if strings.Contains(rendered, "10.43.0.10") {
			t.Errorf("the guest rendered a nameserver from an absent resolv_conf:\n%s", rendered)
		}
	})

	t.Run("no guest network at all is a valid spec with no resolver", func(t *testing.T) {
		spec := guestSpecFixture()
		spec.Network = GuestNetworkConfig{}
		gs, err := buildGuestSpec(spec)
		if err != nil {
			t.Fatalf("buildGuestSpec: %v", err)
		}
		if gs.GetResolvConf() != nil {
			t.Errorf("resolv_conf = %v, want nil for the inert zero-value network", gs.GetResolvConf())
		}
		if _, err := guestinit.Plan(gs, guestinit.Options{MemTotalBytes: 2 << 30}); err != nil {
			t.Errorf("the guest refused a resolver-less spec: %v (a pod with no injected DNS still boots)", err)
		}
	})

	t.Run("the structured triple crosses in order", func(t *testing.T) {
		gs, err := buildGuestSpec(guestSpecFixture())
		if err != nil {
			t.Fatalf("buildGuestSpec: %v", err)
		}
		rc := gs.GetResolvConf()
		if got, want := strings.Join(rc.GetNameservers(), ","), "10.43.0.10"; got != want {
			t.Errorf("nameservers = %q, want %q", got, want)
		}
		if got, want := strings.Join(rc.GetSearches(), " "),
			"default.svc.cluster.local svc.cluster.local cluster.local"; got != want {
			t.Errorf("searches = %q, want %q (order is query order and is preserved)", got, want)
		}
		if got, want := strings.Join(rc.GetOptions(), " "), "ndots:5"; got != want {
			t.Errorf("options = %q, want %q", got, want)
		}
	})
}

// TestBuildGuestSpecFailsClosed is the rejection table: every shape the
// flattening from a per-container plan onto a pod-level mount list cannot
// express, plus every tag the guest could not mount.
func TestBuildGuestSpecFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*VMSpec)
		wantSub string
	}{
		{
			name: "a bind names a share tag the plan does not carry",
			mutate: func(s *VMSpec) {
				s.Volumes.Binds["postgres"][2].ShareTag = "k3sm.ghost"
			},
			wantSub: "the share plan does not carry",
		},
		{
			name: "a container names a rootfs tag the plan does not carry",
			mutate: func(s *VMSpec) {
				s.Containers[1].RootfsTag = "k3sm.rootfs.nope"
			},
			wantSub: "rootfs share tag",
		},
		{
			name: "a container carries no rootfs tag at all",
			mutate: func(s *VMSpec) {
				s.Containers[0].RootfsTag = ""
			},
			wantSub: "carries no rootfs share tag",
		},
		{
			name: "two containers want different sources at one guest path",
			mutate: func(s *VMSpec) {
				s.Volumes.Binds["postgres"][2].MountPath = "/pgdata"
			},
			wantSub: "cannot express both",
		},
		{
			name: "a share tag is declared twice",
			mutate: func(s *VMSpec) {
				s.Volumes.Shares = append(s.Volumes.Shares,
					VMShare{Tag: "k3sm.proj", Root: "/var/lib/k3sm/pods/pod-abc123/other"})
			},
			wantSub: "declared twice",
		},
		{
			name: "an emptyDir size limit is a fractional quantity",
			mutate: func(s *VMSpec) {
				s.Volumes.Tmpfs["postgres"][0].SizeLimit = "1.5Gi"
			},
			wantSub: "not an unsigned integer",
		},
		{
			name: "an emptyDir size limit uses an unsupported suffix",
			mutate: func(s *VMSpec) {
				s.Volumes.Tmpfs["postgres"][0].SizeLimit = "100m"
			},
			wantSub: "unsupported suffix",
		},
		{
			name: "a Memory emptyDir asks for a sub_path",
			mutate: func(s *VMSpec) {
				s.Volumes.Tmpfs["postgres"][0].SubPath = "sub"
			},
			wantSub: "no subdirectory to mount",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := guestSpecFixture()
			tc.mutate(&spec)
			gs, err := buildGuestSpec(spec)
			if err == nil {
				t.Fatalf("buildGuestSpec accepted the spec and produced %v; want a fail-closed rejection", gs)
			}
			if !errors.Is(err, ErrInvalidGuestSpec) {
				t.Errorf("error does not wrap ErrInvalidGuestSpec: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want it to name %q", err, tc.wantSub)
			}
		})
	}
}

// TestBuildGuestSpecMapsTheSharePlan pins the mount mapping itself: which share
// is mounted where, with which read-only bit, and in which order.
func TestBuildGuestSpecMapsTheSharePlan(t *testing.T) {
	t.Parallel()
	gs, err := buildGuestSpec(guestSpecFixture())
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	byTarget := map[string]*guestv1.GuestMount{}
	for _, m := range gs.GetMounts() {
		if prev, dup := byTarget[m.GetTarget()]; dup {
			t.Fatalf("target %q is mounted twice (%v and %v); the flattening must collapse identical requests",
				m.GetTarget(), prev, m)
		}
		byTarget[m.GetTarget()] = m
	}

	t.Run("a claim mounted whole is a virtiofs device at its mount path", func(t *testing.T) {
		m := byTarget["/pgdata"]
		if m.GetKind() != guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS || m.GetTagOrSource() != "k3sm.pvc0" {
			t.Fatalf("/pgdata = %v, want a virtiofs mount of k3sm.pvc0 (no staging: the whole share IS the volume)", m)
		}
		if m.GetReadOnly() {
			t.Error("/pgdata is read-only; the plan marks the claim's share writable")
		}
		if !m.GetIdmap() {
			t.Error("/pgdata carries no idmap; the pod declares fsGroup 2000 and the mount is writable")
		}
	})

	t.Run("a pooled share is staged once and bound out of", func(t *testing.T) {
		stage := byTarget[guestShareStageDir("k3sm.proj")]
		if stage == nil {
			t.Fatalf("k3sm.proj was never staged; mounts = %v", gs.GetMounts())
		}
		if !stage.GetReadOnly() {
			t.Error("the staging mount is writable; a staging mount is always read-only")
		}
		m := byTarget["/var/run/secrets/kubernetes.io/serviceaccount"]
		want := path.Join(guestShareStageDir("k3sm.proj"), "sa-token")
		if m.GetKind() != guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND || m.GetTagOrSource() != want {
			t.Fatalf("serviceaccount mount = %v, want a bind from %q", m, want)
		}
		if !m.GetReadOnly() {
			t.Error("a projected credential bind is writable; the proj share is read-only at the device")
		}
		if m.GetIdmap() {
			t.Error("a read-only bind carries an idmap; there is no ownership a reader can act on")
		}
	})

	t.Run("a Memory emptyDir is guest RAM, bounded, never idmapped", func(t *testing.T) {
		m := byTarget["/dev/shm"]
		if m.GetKind() != guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS {
			t.Fatalf("/dev/shm = %v, want a tmpfs", m)
		}
		if m.GetTagOrSource() != "" {
			t.Errorf("/dev/shm carries source %q; a tmpfs takes none", m.GetTagOrSource())
		}
		if got := m.GetSizeLimitBytes(); got != 64<<20 {
			t.Errorf("/dev/shm size_limit_bytes = %d, want %d (64Mi parsed host-side)", got, 64<<20)
		}
		if m.GetIdmap() {
			t.Error("/dev/shm carries an idmap; a guest tmpfs is created empty, so there is nothing to remap")
		}
	})

	t.Run("every staging mount precedes the bind that sources from it", func(t *testing.T) {
		seen := map[string]bool{}
		for _, m := range gs.GetMounts() {
			if m.GetKind() == guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS &&
				strings.HasPrefix(m.GetTarget(), guestShareStageRoot+"/") {
				seen[m.GetTarget()] = true
				continue
			}
			if m.GetKind() != guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND {
				continue
			}
			src := m.GetTagOrSource()
			if !strings.HasPrefix(src, guestShareStageRoot+"/") {
				continue
			}
			// The staging dir is the first two elements below the stage root.
			rest := strings.TrimPrefix(src, guestShareStageRoot+"/")
			stage := guestShareStageDir(strings.SplitN(rest, "/", 2)[0])
			if !seen[stage] {
				t.Errorf("bind %q at %q is planned before its share is staged at %q; the guest applies mounts in list order",
					src, m.GetTarget(), stage)
			}
		}
	})
}

// TestBuildGuestSpecIsDeterministic pins that the emitted mount order is a
// function of the plan and not of Go's map iteration. Without it the golden
// above would pass or fail at random, and — worse — a boot would occasionally
// plan a bind before the share it sources from.
func TestBuildGuestSpecIsDeterministic(t *testing.T) {
	t.Parallel()
	first, err := buildGuestSpec(guestSpecFixture())
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	for i := 0; i < 32; i++ {
		next, err := buildGuestSpec(guestSpecFixture())
		if err != nil {
			t.Fatalf("buildGuestSpec (run %d): %v", i, err)
		}
		if !proto.Equal(first, next) {
			t.Fatalf("run %d produced a different spec; the composition must not depend on map iteration order", i)
		}
	}
}

// TestGuestSpecRoundTripsThroughGuestInit is where the TWO ENDS OF THE CONTRACT
// MEET IN ONE TEST: what this package composes is fed to the REAL
// pkg/guestinit.Plan — the same entry point the initramfs's PID 1 calls — and
// the plan it produces must mount exactly the tags the share plan declared.
//
// It is the assertion that a golden cannot make. A golden pins the bytes the
// producer emits; only the reader can say whether those bytes describe a
// bootable pod, and the two live in different packages precisely so neither can
// quietly redefine the contract to match itself.
func TestGuestSpecRoundTripsThroughGuestInit(t *testing.T) {
	t.Parallel()
	spec := guestSpecFixture()
	gs, err := buildGuestSpec(spec)
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	plan, err := guestinit.Plan(gs, guestinit.Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("the guest refused the spec this host composed: %v", err)
	}

	declared := map[string]bool{}
	for _, s := range spec.Volumes.Shares {
		declared[s.Tag] = true
	}

	t.Run("every virtiofs source the guest will mount is a declared share tag", func(t *testing.T) {
		var mounted int
		steps := append([]guestinit.MountStep{}, plan.PodMounts...)
		for _, c := range plan.Containers {
			steps = append(steps, c.Mounts...)
		}
		for _, st := range steps {
			if st.FSType != "virtiofs" {
				continue
			}
			mounted++
			if !declared[st.Source] {
				t.Errorf("the guest would mount virtiofs tag %q at %q, which no share device carries",
					st.Source, st.Target)
			}
		}
		if mounted == 0 {
			t.Fatal("the plan mounts no virtiofs share at all; the round trip proves nothing")
		}
	})

	t.Run("each container's rootfs lower is its own declared tag", func(t *testing.T) {
		want := map[string]string{}
		for _, c := range spec.Containers {
			want[c.Name] = c.RootfsTag
		}
		for _, c := range plan.Containers {
			lower, ok := findStep(c.Mounts, guestinit.ContainerLowerDir(c.Name))
			if !ok {
				t.Errorf("container %q has no rootfs lower mount", c.Name)
				continue
			}
			if lower.Source != want[c.Name] {
				t.Errorf("container %q lower = %q, want its declared rootfs tag %q",
					c.Name, lower.Source, want[c.Name])
			}
		}
	})

	t.Run("start order is init containers first", func(t *testing.T) {
		if len(plan.Containers) != 2 {
			t.Fatalf("plan has %d containers, want 2", len(plan.Containers))
		}
		if plan.Containers[0].Name != "init-db" || !plan.Containers[0].WaitForExit {
			t.Errorf("first container = %q (wait=%v), want init-db waited to completion",
				plan.Containers[0].Name, plan.Containers[0].WaitForExit)
		}
		if plan.Containers[1].Name != "postgres" || plan.Containers[1].WaitForExit {
			t.Errorf("second container = %q (wait=%v), want postgres not waited for",
				plan.Containers[1].Name, plan.Containers[1].WaitForExit)
		}
	})

	t.Run("the merged argv survives the crossing intact", func(t *testing.T) {
		got := strings.Join(plan.Containers[1].Argv, " ")
		want := strings.Join(spec.Containers[1].Argv, " ")
		if got != want {
			t.Errorf("postgres argv = %q, want %q", got, want)
		}
	})

	t.Run("the resolver renders with the pod's own search domain first", func(t *testing.T) {
		if !strings.Contains(plan.Etc.ResolvConf, "nameserver 10.43.0.10") {
			t.Errorf("rendered resolv.conf carries no nameserver:\n%s", plan.Etc.ResolvConf)
		}
		if !strings.Contains(plan.Etc.ResolvConf, "search default.svc.cluster.local svc.cluster.local cluster.local") {
			t.Errorf("rendered resolv.conf search list is not the structured list in order:\n%s", plan.Etc.ResolvConf)
		}
	})
}

// findStep returns the first mount step at target.
func findStep(steps []guestinit.MountStep, target string) (guestinit.MountStep, bool) {
	for _, s := range steps {
		if s.Target == target {
			return s, true
		}
	}
	return guestinit.MountStep{}, false
}

// TestParseQuantityBytes is the size-limit table. The accepted forms are the
// ones emptyDir sizeLimits are actually written in; the refused ones are
// refused rather than rounded (see parseQuantityBytes).
func TestParseQuantityBytes(t *testing.T) {
	t.Parallel()
	ok := map[string]int64{
		"":       0,
		"0":      0,
		"512":    512,
		"64Mi":   64 << 20,
		"1Gi":    1 << 30,
		"2Ti":    2 << 40,
		"1k":     1000,
		"5M":     5_000_000,
		"3G":     3_000_000_000,
		"1024Ki": 1 << 20,
	}
	for in, want := range ok {
		got, err := parseQuantityBytes(in)
		if err != nil {
			t.Errorf("parseQuantityBytes(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseQuantityBytes(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"1.5Gi", "100m", "2e3", "-1", "Mi", "64MB", "64 Mi", "9999999999Ei"} {
		if got, err := parseQuantityBytes(in); err == nil {
			t.Errorf("parseQuantityBytes(%q) = %d, want a fail-closed rejection", in, got)
		}
	}
}

// TestCreateVMWritesTheGuestSpec is the WRITER's gate: the boot contract lands
// in the k3sm.spec share root, BEFORE the helper is spawned, sealed read-only,
// and decodes as a guestv1.GuestSpec with unknown fields REJECTED — the same
// strictness the guest init reads it with.
//
// The ORDERING assertion is the load-bearing one. The k3sm.spec share is forced
// read-only at the VZ device, so the only window in which the file is not yet
// protected is the one before any guest exists; asserting that the spawner saw
// the file already committed is what pins that window shut.
func TestCreateVMWritesTheGuestSpec(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	fixture := guestSpecFixture()
	spec.Hostname, spec.FSGroup = fixture.Hostname, fixture.FSGroup
	spec.Network, spec.Containers, spec.Volumes = fixture.Network, fixture.Containers, fixture.Volumes

	specPath := filepath.Join(spec.PodDir, guestinit.SpecShareTag, VMGuestSpecFileName)
	// The observation is taken INSIDE the spawner, which is the exact instant
	// the helper is handed its arguments — the earliest moment a guest could
	// begin to exist. Observing anywhere later (in the health probe, say) would
	// pass even if the write had been moved after the spawn, which is precisely
	// the regression this row exists to catch.
	watcher := &specWatchingSpawner{path: specPath, next: &fakeSpawner{}}
	b, _, _, _ := labBackend(t, root, func(context.Context, string) error { return nil },
		WithVMProcessSeams(watcher, nil, nil, nil, nil, nil))
	if err := b.CreateVM(context.Background(), spec); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	atSpawn := watcher.seen
	if !watcher.spawned {
		t.Fatal("no helper was spawned; the ordering assertion below would be vacuous")
	}
	if atSpawn == nil {
		t.Fatal("the guest spec did not exist at the instant the helper was spawned; it must be committed BEFORE the spawn, because that is the window in which no guest holds the share")
	}
	if mode := atSpawn.Mode().Perm(); mode != 0o444 {
		t.Errorf("guest spec mode = %04o, want 0444 (defence in depth behind the device read-only flag)", mode)
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read the guest spec: %v", err)
	}
	var got guestv1.GuestSpec
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &got); err != nil {
		t.Fatalf("the written guest spec does not decode as a guestv1.GuestSpec with unknown fields rejected: %v\n%s", err, raw)
	}
	want, err := buildGuestSpec(spec)
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	if !proto.Equal(&got, want) {
		t.Errorf("the written spec is not what the composer produced.\n--- written ---\n%s", raw)
	}
	if got.GetHostname() != "web-0" || got.GetAgentPort() != VMAgentVsockPort {
		t.Errorf("hostname/agent_port = %q/%d, want web-0/%d", got.GetHostname(), got.GetAgentPort(), VMAgentVsockPort)
	}
	// No stale temp file survives a committed write.
	if _, err := os.Stat(specPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temp file survived the rename (stat err %v)", err)
	}
}

// TestCreateVMRefusesAnUncomposableSpec pins the fail-closed hook: a share plan
// the composer cannot express fails the boot BEFORE a helper is spawned, rather
// than producing a guest that mounts something nobody planned.
func TestCreateVMRefusesAnUncomposableSpec(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	spec.Volumes = VMVolumePlan{
		Shares: []VMShare{{Tag: "k3sm.rootfs", Root: filepath.Join(spec.PodDir, "rootfs")}},
		Binds: map[string][]VMBind{
			"web": {{VolumeName: "cfg", ShareTag: "k3sm.ghost", SourceRel: "cfg", MountPath: "/etc/cfg"}},
		},
	}
	b, sp, _, _ := labBackend(t, root, func(context.Context, string) error { return nil })
	err := b.CreateVM(context.Background(), spec)
	if err == nil {
		t.Fatal("CreateVM accepted a share plan the guest spec cannot express")
	}
	if !errors.Is(err, ErrInvalidGuestSpec) {
		t.Errorf("error does not wrap ErrInvalidGuestSpec: %v", err)
	}
	if n := sp.count(); n != 0 {
		t.Errorf("spawned %d helpers for a spec that could not be composed; want 0", n)
	}
}

// count reports how many spawns the fake recorded.
func (f *fakeSpawner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.specs)
}

// specWatchingSpawner records whether a path existed at the instant of the
// spawn, then delegates. It is the only seam from which the write-then-spawn
// ORDERING is observable: everything later in CreateVM runs after a guest could
// already exist.
type specWatchingSpawner struct {
	path    string
	next    *fakeSpawner
	seen    os.FileInfo
	spawned bool
}

func (s *specWatchingSpawner) Spawn(ctx context.Context, spec supervisor.SpawnSpec) (int, error) {
	if !s.spawned {
		s.spawned = true
		s.seen, _ = os.Stat(s.path)
	}
	return s.next.Spawn(ctx, spec)
}
