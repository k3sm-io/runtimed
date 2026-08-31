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
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"k3sm.io/runtimed/pkg/guestinit"

	guestv1 "k3sm.io/apis/guest/v1"
)

// THE BOOT CONTRACT'S PRODUCER.
//
// pkg/guestinit has read guest-spec.json since it was written, and until this
// file nothing produced one: CreateVM created the k3sm.spec share root EMPTY and
// left the guest to fail in its own init. The composer below is the other end of
// that contract, and it meets the reader at guest/v1 and nowhere else — exactly
// as buildVMHostSpec meets the k3sm-vmhost helper there (see vmspec.go's header
// for why pkg/vmhost is unreachable from the daemon at all).
//
// The two specs are written by the SAME host in the SAME breath, which is what
// guest.proto's equality requirements between them depend on: GuestSpec.agent_port
// == VMHostSpec.agent_vsock_port (both VMAgentVsockPort) and GuestSpec.rosetta ==
// VMHostSpec.rosetta (both VMHostRosettaShareSupported). Neither value is decided
// here; both are read from the one constant that already decides it.

// VMGuestSpecFileName is the basename of the boot spec written into the pod's
// k3sm.spec share root and read by the guest init as its first act after the
// pseudo-filesystems are up.
//
// It is pinned to guestinit.SpecPath's basename by a test rather than derived
// from it, because the guest-side path is an absolute GUEST path
// (/run/k3sm/spec/guest-spec.json) and the host writes into a host directory —
// the two share only the filename, and that is the part that must not drift.
const VMGuestSpecFileName = "guest-spec.json"

// guestShareStageRoot is the guest directory a POOLED virtiofs share is mounted
// at before its per-volume subdirectories are bound onto their mount paths.
//
// It is derived from guestinit.GuestRoot so the guest-private tree keeps ONE
// root authority; only the subdirectory below it is this composer's convention.
// A staging mount is emitted only when it is unavoidable: a virtiofs device
// mounts a WHOLE share at one target, so a volume that lives in a subdirectory
// of a pooled share (k3sm.proj/<volume>, k3sm.vols/<volume>) cannot be mounted
// at its mount path directly — it has to be mounted once and bound out of.
//
// RESIDUAL, recorded rather than papered over: guestinit re-exposes EVERY
// pod-level mount inside EVERY container's rootfs (containerVisibleMounts), so a
// staged pooled share is visible to every container in the pod, not only to the
// containers that declared a volumeMount from it. That does not widen the VM's
// own boundary — the pooled device is attached to the machine regardless, and
// sandbox.VMBind already records that per-container narrowing is
// GUEST-COOPERATIVE rather than host-enforced — but it does move the pooled
// share from "readable by the guest init" to "readable by the workload".
// Closing it needs a guest-private mount class guest/v1 does not have today.
var guestShareStageRoot = path.Join(guestinit.GuestRoot, "shares")

// guestShareStageDir is where the share tagged tag is staged.
func guestShareStageDir(tag string) string { return path.Join(guestShareStageRoot, tag) }

// ErrInvalidGuestSpec reports a VMSpec that cannot be expressed as a guest/v1
// GuestSpec. Compare with errors.Is.
var ErrInvalidGuestSpec = errors.New("sandbox: invalid guest spec")

// buildGuestSpec composes the pod's boot contract from the VMSpec, its share
// plan and its guest network config.
//
// IT IS PURE AND OS-INDEPENDENT: it touches no disk, so the whole mapping is
// table-testable on any lane, and the one thing that writes (writeGuestSpec) does
// nothing but marshal and rename.
//
// THE DNS CONFIGURATION IS TAKEN FROM THE STRUCTURED TRIPLE ONLY. GuestNetworkConfig
// carries the same configuration twice — Nameservers/Searches/Options and the
// host-rendered ResolvConf string — and only the structured form crosses, because
// the guest renders /etc/resolv.conf musl-safely for its own libc
// (guestinit.RenderResolvConf). Reading the rendered string here would mean
// re-parsing our own output to refill the message the proto shape exists to keep
// structured, so there is deliberately NO code path from ResolvConf into the
// GuestSpec: a config carrying only the rendered string produces no resolv_conf
// at all, and the guest logs a resolver-less boot instead of inheriting a
// silently half-parsed one.
//
// AN EMPTY CONTAINER LIST IS NOT REJECTED HERE. guestinit.Plan refuses a pod with
// no containers, and it is the right refuser: it is PID 1 of a VM that exists to
// run exactly this pod, so its refusal names the pod's own boot. Rejecting here
// as well would only move the same failure one process earlier, and the producer
// (pkg/runtime's container mapper) already refuses every pod-shaped reason a
// container could be missing before it ever composes a spec.
func buildGuestSpec(spec VMSpec) (*guestv1.GuestSpec, error) {
	shares, err := shareIndex(spec.Volumes.Shares)
	if err != nil {
		return nil, err
	}
	containers, err := guestContainers(spec.Containers, shares)
	if err != nil {
		return nil, err
	}
	mounts, err := guestMounts(spec.Volumes, shares, spec.FSGroup)
	if err != nil {
		return nil, err
	}
	return &guestv1.GuestSpec{
		Hostname:   spec.Hostname,
		ResolvConf: guestResolvConf(spec.Network),
		Containers: containers,
		Mounts:     mounts,
		// Both flags are MIRRORED from the constants that already decide them,
		// never decided again: rosetta must equal VMHostSpec.rosetta and
		// agent_port must equal VMHostSpec.agent_vsock_port, and a second
		// decision site is how two specs written together come to disagree.
		Rosetta:   VMHostRosettaShareSupported,
		FsGroup:   spec.FSGroup,
		AgentPort: VMAgentVsockPort,
	}, nil
}

// guestResolvConf maps the STRUCTURED half of the guest network config onto the
// guest/v1 message. It returns nil — not an empty message — when the config
// carries no structured DNS at all, so "no resolver was injected" and "an empty
// resolver was injected" stay distinguishable on the wire.
func guestResolvConf(n GuestNetworkConfig) *guestv1.ResolvConf {
	if len(n.Nameservers) == 0 && len(n.Searches) == 0 && len(n.Options) == 0 {
		return nil
	}
	return &guestv1.ResolvConf{
		Nameservers: append([]string(nil), n.Nameservers...),
		Searches:    append([]string(nil), n.Searches...),
		Options:     append([]string(nil), n.Options...),
	}
}

// shareIndex keys the plan's share devices by tag, rejecting a duplicate.
//
// A duplicate tag is fatal rather than deduplicated because a guest mounts BY
// TAG: the second device would be unreachable, so a plan carrying two is a plan
// whose author believed something false. The helper rejects the same shape on
// its own side (vmhost.resolveShares); this is the producer catching it before a
// spawn is spent.
func shareIndex(shares []VMShare) (map[string]VMShare, error) {
	out := make(map[string]VMShare, len(shares))
	for _, s := range shares {
		if s.Tag == "" {
			return nil, fmt.Errorf("%w: a share device has an empty tag", ErrInvalidGuestSpec)
		}
		if _, dup := out[s.Tag]; dup {
			return nil, fmt.Errorf("%w: share tag %q is declared twice; a guest mounts by tag, so the second device would be unreachable",
				ErrInvalidGuestSpec, s.Tag)
		}
		out[s.Tag] = s
	}
	return out, nil
}

// guestContainers maps the pod's containers onto guest/v1, in the order given.
//
// THE MERGED ARGV RIDES IN command, WITH args EMPTY. guest/v1 defines argv as
// command + args and states that the merge against the image config already
// happened host-side (pkg/image.MergeRunSpec produces ONE merged Argv), so
// re-splitting it into two halves here would invent a boundary the merge had
// already dissolved — and any split reassembles to the same argv, which makes
// the split pure noise a reader has to verify.
//
// The rootfs tag is checked against the share plan: an unknown tag is a mount
// the guest cannot perform, and it must fail here, where the tag and the plan
// are both in hand, rather than as a virtiofs mount failure in a booted guest.
func guestContainers(containers []VMContainer, shares map[string]VMShare) ([]*guestv1.GuestContainer, error) {
	if len(containers) == 0 {
		return nil, nil
	}
	out := make([]*guestv1.GuestContainer, 0, len(containers))
	for i, c := range containers {
		if c.Name == "" {
			return nil, fmt.Errorf("%w: containers[%d] has an empty name", ErrInvalidGuestSpec, i)
		}
		if c.RootfsTag == "" {
			return nil, fmt.Errorf("%w: container %q carries no rootfs share tag", ErrInvalidGuestSpec, c.Name)
		}
		if _, ok := shares[c.RootfsTag]; !ok {
			return nil, fmt.Errorf("%w: container %q names rootfs share tag %q, which the share plan does not carry",
				ErrInvalidGuestSpec, c.Name, c.RootfsTag)
		}
		out = append(out, &guestv1.GuestContainer{
			Name:             c.Name,
			RootfsTag:        c.RootfsTag,
			Command:          append([]string(nil), c.Argv...),
			Env:              append([]string(nil), c.Env...),
			WorkingDir:       c.WorkingDir,
			Tty:              c.TTY,
			Stdin:            c.Stdin,
			Uid:              c.UID,
			Gid:              c.GID,
			SupplementalGids: append([]int64(nil), c.SupplementalGIDs...),
			Init:             c.Init,
		})
	}
	return out, nil
}

// guestMounts expands the share plan into the pod-level mounts the guest
// performs before any container starts.
//
// THE PLAN IS PER-CONTAINER AND guest/v1's MOUNT LIST IS POD-LEVEL, so this is a
// FLATTENING, and the flattening is checked rather than assumed: two containers
// asking for DIFFERENT sources at the SAME target cannot both be honoured by a
// pod-level mount list, so that is a fail-closed rejection here instead of a
// last-writer-wins mount in the guest. Identical requests from several
// containers collapse to one mount, which is what the guest wants anyway — a
// share mounted twice is two independent mounts of one host tree.
//
// Emission order is: every staging mount first (in share-plan order), then the
// per-volume mounts in container-name order. The guest applies the list in
// order, so a bind can only be planned after the share it sources from is
// mounted; putting the staging mounts first is what makes that true by
// construction rather than by the map iteration order of the day.
func guestMounts(plan VMVolumePlan, shares map[string]VMShare, fsGroup int64) ([]*guestv1.GuestMount, error) {
	var staged []*guestv1.GuestMount
	stagedTags := map[string]bool{}
	stage := func(tag string) string {
		if !stagedTags[tag] {
			stagedTags[tag] = true
			staged = append(staged, &guestv1.GuestMount{
				TagOrSource: tag,
				Target:      guestShareStageDir(tag),
				Kind:        guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS,
				// The staging mount is always read-only: it exists only so a
				// subdirectory can be bound out of it, and the bind carries the
				// volume's own writability. A writable staging mount would hand
				// every container the whole pooled share writable.
				ReadOnly: true,
			})
		}
		return guestShareStageDir(tag)
	}

	var mounts []*guestv1.GuestMount
	claimed := map[string]*guestv1.GuestMount{}
	claim := func(m *guestv1.GuestMount) error {
		if prev, ok := claimed[m.GetTarget()]; ok {
			if sameMount(prev, m) {
				return nil
			}
			return fmt.Errorf("%w: two containers want different sources at guest path %q (%s %q vs %s %q); a pod-level mount list cannot express both",
				ErrInvalidGuestSpec, m.GetTarget(),
				kindLabel(prev.GetKind()), prev.GetTagOrSource(),
				kindLabel(m.GetKind()), m.GetTagOrSource())
		}
		claimed[m.GetTarget()] = m
		mounts = append(mounts, m)
		return nil
	}

	for _, name := range sortedKeys(plan.Binds) {
		for _, b := range plan.Binds[name] {
			sh, ok := shares[b.ShareTag]
			if !ok {
				return nil, fmt.Errorf("%w: container %q binds volume %q from share tag %q, which the share plan does not carry",
					ErrInvalidGuestSpec, name, b.VolumeName, b.ShareTag)
			}
			// A share device is read-only at the VZ device unless the plan made
			// it writable, so a bind out of a read-only share is read-only
			// whatever the volumeMount asked for. The guest-side flag mirrors
			// the device flag; it never substitutes for it.
			readOnly := b.ReadOnly || !sh.Writable
			rel := path.Join(b.SourceRel, b.SubPath)
			m := &guestv1.GuestMount{
				Target:   b.MountPath,
				ReadOnly: readOnly,
				Idmap:    idmapWanted(fsGroup, readOnly),
			}
			if rel == "" || rel == "." {
				// The whole share IS the volume (the PVC case): mount the
				// device straight at the mount path, with no staging mount and
				// so no extra exposure.
				m.TagOrSource, m.Kind = b.ShareTag, guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS
			} else {
				m.TagOrSource, m.Kind = path.Join(stage(b.ShareTag), rel), guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND
			}
			if err := claim(m); err != nil {
				return nil, err
			}
		}
	}

	for _, name := range sortedKeys(plan.Tmpfs) {
		for _, t := range plan.Tmpfs[name] {
			size, err := parseQuantityBytes(t.SizeLimit)
			if err != nil {
				return nil, fmt.Errorf("%w: container %q volume %q size limit: %w",
					ErrInvalidGuestSpec, name, t.VolumeName, err)
			}
			// A SubPath under a Memory emptyDir narrows a tmpfs the guest is
			// about to create empty, so there is nothing to narrow TO. It is
			// refused rather than silently ignored: ignoring it would mount the
			// whole volume where a subdirectory was asked for.
			if t.SubPath != "" {
				return nil, fmt.Errorf("%w: container %q volume %q is a Memory emptyDir with sub_path %q; a guest tmpfs is created empty, so there is no subdirectory to mount",
					ErrInvalidGuestSpec, name, t.VolumeName, t.SubPath)
			}
			// NO IDMAP ON A TMPFS, ever. An idmapped mount exists to make
			// HOST-OWNED files appear under the container's ids without a
			// recursive chown; a guest tmpfs is created empty by the guest
			// itself, so its ownership is set at creation and there is nothing
			// to remap. The apis golden fixture shows the same shape.
			m := &guestv1.GuestMount{
				Target:         t.MountPath,
				Kind:           guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS,
				ReadOnly:       t.ReadOnly,
				SizeLimitBytes: size,
			}
			if err := claim(m); err != nil {
				return nil, err
			}
		}
	}
	return append(staged, mounts...), nil
}

// idmapWanted reports whether a HOST-BACKED mount (virtiofs or a bind out of
// one) should carry an idmapped-mount request: the pod declares an fsGroup AND
// the mount is writable.
//
// fsGroup exists so the pod's processes can WRITE the volume as a group they
// hold; an idmap on a read-only mount would remap ownership nobody can act on,
// and guest/v1 documents idmap as the mechanism that avoids a recursive chown,
// not as a general ownership rewrite.
func idmapWanted(fsGroup int64, readOnly bool) bool { return fsGroup != 0 && !readOnly }

// sameMount reports whether two mounts describe the same thing, so a request
// repeated by several containers collapses instead of colliding.
func sameMount(a, b *guestv1.GuestMount) bool {
	return a.GetTagOrSource() == b.GetTagOrSource() &&
		a.GetKind() == b.GetKind() &&
		a.GetReadOnly() == b.GetReadOnly() &&
		a.GetSizeLimitBytes() == b.GetSizeLimitBytes() &&
		a.GetIdmap() == b.GetIdmap()
}

// kindLabel is a mount kind's short name for an error message.
func kindLabel(k guestv1.GuestMountKind) string {
	switch k {
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS:
		return "virtiofs"
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS:
		return "tmpfs"
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND:
		return "bind"
	default:
		return "unspecified"
	}
}

// sortedKeys returns a map's keys in sorted order, so the emitted mount list is
// a function of the plan and not of Go's map iteration.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseQuantityBytes converts a Kubernetes resource.Quantity string to BYTES.
//
// The size limit crosses the boundary as an int64 (GuestMount.size_limit_bytes)
// while the pod spec carries it as a quantity STRING, so the translation has to
// happen somewhere host-side, and here is the only place that holds both ends.
//
// IT IS DELIBERATELY NARROW AND FAIL-CLOSED. Accepted: an unsigned integer with
// an optional binary (Ki/Mi/Gi/Ti/Pi/Ei) or decimal (k/M/G/T/P/E) suffix, which
// is how every emptyDir sizeLimit is written in practice. REFUSED: the
// fractional ("1.5Gi"), exponent ("2e3") and milli ("100m") forms upstream also
// admits — refusing them fails the pod with the quantity quoted, whereas
// rounding one would silently bound a tmpfs somewhere the operator did not ask
// for, and an unbounded fallback would turn a runaway write into a guest OOM
// misattributed to the workload (see guestinit.UpperSizeBytes for the same
// argument on the overlay upper).
func parseQuantityBytes(q string) (int64, error) {
	if q == "" {
		return 0, nil
	}
	digits := strings.TrimRight(q, "KMGTPEikm")
	suffix := q[len(digits):]
	mult, ok := quantitySuffix[suffix]
	if !ok {
		return 0, fmt.Errorf("%w: quantity %q uses an unsupported suffix %q; the accepted forms are an integer with an optional Ki/Mi/Gi/Ti/Pi/Ei or k/M/G/T/P/E suffix",
			ErrInvalidGuestSpec, q, suffix)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: quantity %q is not an unsigned integer with an optional binary or decimal suffix (the fractional, exponent and milli forms are refused rather than rounded)",
			ErrInvalidGuestSpec, q)
	}
	if n != 0 && mult > (1<<63-1)/n {
		return 0, fmt.Errorf("%w: quantity %q overflows an int64 byte count", ErrInvalidGuestSpec, q)
	}
	return n * mult, nil
}

// quantitySuffix is the accepted suffix set and its multiplier.
var quantitySuffix = map[string]int64{
	"":  1,
	"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60,
}

// marshalGuestSpec encodes gs as the proto-JSON the guest init decodes.
//
// UseProtoNames is off for the reason marshalVMHostSpec gives: the wire form is
// lowerCamel, matching the apis goldens (guest/v1/testdata/guest-spec.json),
// which are the schema's only executable statement. Multiline is on because a
// boot failure is diagnosed by reading this file off the share root.
func marshalGuestSpec(gs *guestv1.GuestSpec) ([]byte, error) {
	out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(gs)
	if err != nil {
		return nil, fmt.Errorf("encode the guest spec: %w", err)
	}
	return append(out, '\n'), nil
}

// writeGuestSpec writes the boot contract into the pod's k3sm.spec share root
// and returns its path. The share root itself is created by writeVMHostSpec,
// which runs first in the same boot.
//
// THE FILE IS TAMPER-EVIDENT FROM THE GUEST SIDE, and it is the ORDERING plus
// the DEVICE FLAG that make it so, not the 0444 mode. The k3sm.spec share is
// forced read-only at the VZ device (vmhost.forcedReadOnlyTags names it: "a
// guest that could rewrite it could re-describe itself"), and this write
// completes BEFORE the helper is spawned — so no guest exists while the file is
// being composed, and once one does it holds a read-only device. The 0444 mode
// is defence in depth against a HOST-side accident, never the enforcement point.
//
// The write is atomic (temp + rename) because the guest init reads this file as
// its first act: a half-written spec would be a parse error blamed on the
// contract instead of on the crash that truncated it. The temp file is removed
// first — it is left mode 0444, so a leftover from a previous boot would make
// the retry fail with EACCES on a file this daemon owns.
func writeGuestSpec(podDir string, gs *guestv1.GuestSpec) (string, error) {
	data, err := marshalGuestSpec(gs)
	if err != nil {
		return "", err
	}
	final := filepath.Join(podDir, guestinit.SpecShareTag, VMGuestSpecFileName)
	tmp := final + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("clear the stale guest spec %s: %w", tmp, err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", fmt.Errorf("write the guest spec: %w", err)
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		return "", fmt.Errorf("seal the guest spec %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", fmt.Errorf("commit the guest spec: %w", err)
	}
	return final, nil
}
