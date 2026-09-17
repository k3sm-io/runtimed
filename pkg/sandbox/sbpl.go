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
	"path/filepath"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// DefaultWorkDir is the runtimed on-disk work-dir assumed when a Posture leaves
// WorkDir empty: the legacy root-daemon location. The per-pod pods-root is
// pinned at <WorkDir>/pods and the protected-prefix denies track it. The
// unprivileged user-space posture (the _k3sm daemon) passes an explicit WorkDir
// under the daemon's home instead of relying on this default.
const DefaultWorkDir = "/var/lib/k3sm"

// PodReapSubdir is the daemon-private startup-reap store dir name: a sibling of
// the pods root under the runtime work-dir (<WorkDir>/podreap) holding one
// <podID>/<pgid>.json record per live container process group. It is exported so
// pkg/runtime single-sources the on-disk store name from the same literal the
// SBPL generator defends: resolvePosture pins <WorkDir>/podreap into the
// protected deny-set and Generate emits a matching (deny ...) for it, so a
// confined pod can never forge a reap record (which would drive a root-SIGKILL
// at a process group of its choosing). If the two literals drifted, the deny
// would protect a non-existent sibling while the real store stayed writable.
const PodReapSubdir = "podreap"

// The control-plane and daemon-private work-dir subtrees a confined pod may
// never read or write. They are the first members of DaemonTreeSubdirs, which is
// the one place the whole set is stated — the image-store and guest-artifact
// siblings, whose names are mirrored from their owning packages, live beside it
// in workdirtrees.go.
//
// Like PodReapSubdir they are exported consts so the leaf
// name has exactly one spelling: resolvePosture joins each onto the work-dir,
// pins the result into the protected deny-set, and Generate emits a matching
// (deny ...) for it. A second, drifted literal would leave the deny guarding a
// non-existent sibling while the real tree stayed writable.
//
// Scope — these denies close the caller-supplied extra/PV-path tier. The
// data-volume tier that used to defeat them (validateExtraPaths carves out every
// path under the data volume, and Generate re-allows the data volume after these
// denies, so SBPL's last-match-wins beat them) is closed separately, by the
// ErrDataVolumeUnbounded bound Generate applies to dataVol before either of those
// two consumers runs.
const (
	// ServerSubdir is the control-plane state dir (<WorkDir>/server): the cluster
	// CA private keys, the generated kubeconfigs, and the kine SQLite datastore.
	// It is written by the k3sm control plane rather than by runtimed, and
	// runtimed cannot import k3sm, so the name cannot be single-sourced across
	// the repo boundary today. residual: the control plane takes its state root
	// from a --work-dir flag with a posture-aware default, so on a node started
	// with a different value this deny guards a directory nothing writes.
	ServerSubdir = "server"
	// AgentSubdir is the node-agent state dir (<WorkDir>/agent): the node
	// password and the agent kubeconfig. Same cross-repo residual as ServerSubdir.
	AgentSubdir = "agent"
	// RunSubdir is the daemon socket + key dir (<WorkDir>/run): the runtimed and
	// k3sm-netd control sockets and the wireguard mesh private key under
	// run/keys. The vm backend already refuses to export any slice of this tree
	// (see pkg/mount's share-root guard), so without this deny the Seatbelt
	// fallback was the weaker of the two backends — inverting the invariant that
	// falling back degrades toward stronger isolation.
	RunSubdir = "run"
	// BlobsSubdir is the content-addressed image blob store (<WorkDir>/blobs). A
	// blob path is validated, not verified, and a cache probe treats any regular
	// file at the path as a hit — so a pod able to write here could replace a
	// layer that every subsequent pod materializes without re-verification.
	// pkg/image derives the same dir from its own copy of this literal; the
	// sandbox gate asserts the two still agree.
	BlobsSubdir = "blobs"
)

// DefaultResolverVIP is the cluster DNS Service VIP assumed when a Posture
// leaves ResolverVIP empty. It is PLUMBING-only: the VIP renders NO
// SBPL rule (the macOS 26 Seatbelt grammar cannot express per-IP network
// filters — see the AllowNetwork stanza in Generate), but the field and its
// default are kept as the node-level DNS configuration the env/status plumbing
// reads. Overridable per-node via Posture.
const DefaultResolverVIP = "10.96.0.10"

// systemProtectedPrefixes are the fixed host subtrees a pod may never be granted
// via a caller-supplied extra path, independent of the work-dir: user homes, the
// system secrets/state store, and the dyld cryptex (the system read-only content
// volume). They are absolute literals by definition — anything work-dir-relative
// belongs in resolvePosture instead, which appends the pods-root (sibling pods),
// the daemon-private reap stores (ReapStoreSubdirs) and the control-plane and
// daemon-private trees (DaemonTreeSubdirs) to this set.
// validateExtraPaths rejects any extra read/write path at or under one of these
// (the pod's own data volume is carved out), and Generate emits a matching
// (deny ...) for each after the extra-path allows so an unvalidated path cannot
// override the deny (SBPL is last-match-wins).
var systemProtectedPrefixes = []string{
	"/Users",
	"/private/var/db",
	"/System/Volumes/Preboot/Cryptexes",
	"/System/Cryptexes",
}

// DefaultPodLogsDir is the container-log root a Posture assumes when it names
// none: upstream's /var/log/pods, unchanged, because the whole point of the
// path is that a Kubernetes operator already knows it.
const DefaultPodLogsDir = "/var/log/pods"

// ContainerLogSymlinkDir is the node's container-log SYMLINK tree — upstream's
// /var/log/containers, one link per container pointing into the pod-logs tree.
//
// It is denied alongside PodLogsDir and separately from it, because it is a
// separate hazard: unlink(2) is a write on the PARENT directory, so a pod able
// to write here could delete another container's symlink (breaking every
// host-level log shipper that reads the tree) without ever touching a file the
// pod-logs deny covers. It is a fixed absolute literal rather than a configured
// value because the path is upstream's and the node does not make it settable.
const ContainerLogSymlinkDir = "/var/log/containers"

// ErrMissingDenyDefault reports an SBPL profile that does not start its rule set
// with (deny default) — a profile without it is fail-open and is rejected.
var ErrMissingDenyDefault = errors.New("sbpl: profile missing (deny default)")

// ErrMissingSystemImport reports an SBPL profile that does not (import
// "system.sb"). Without the baseline every binary aborts (SIGABRT) during dyld
// init, so a profile lacking it is rejected.
var ErrMissingSystemImport = errors.New(`sbpl: profile missing (import "system.sb")`)

// ErrNoDataVolume reports a SandboxProfile with no data_volume_path (empty, or a
// path that cleans to "."): there is nowhere the pod may write, so the profile
// cannot be generated. A data_volume_path that is present but too wide — "/"
// included — is ErrDataVolumeUnbounded instead: "the caller sent nothing" and
// "the caller sent the whole filesystem" are different operator signals, and only
// the second is an attempted grant.
var ErrNoDataVolume = errors.New("sbpl: sandbox profile has no data_volume_path")

// ErrProtectedPath reports a caller-supplied extra read/write path that resolves
// at or under a protected prefix (see systemProtectedPrefixes plus the
// work-dir-derived roots resolvePosture adds). Such a path is rejected rather
// than emitted, so a hostPath-style mount can never widen the allow-list into
// /Users, the secrets store, a sibling pod's dir, a control-plane/daemon tree,
// or the dyld cryptex.
var ErrProtectedPath = errors.New("sbpl: extra path is under a protected deny-set")

// ErrDataVolumeUnbounded reports a SandboxProfile.data_volume_path that is not a
// proper descendant of the posture's pods root (<Posture.WorkDir>/pods). The data
// volume is the one tree Generate re-allows read+write after the protected denies
// (SBPL is last-match-wins) and the one carve-out validateExtraPaths grants every
// other caller-supplied path, so an unbounded value overrides the whole deny-set
// in a single emitted line and disarms the extra-path validator with it.
//
// It is a distinct sentinel from ErrProtectedPath, not a reuse, for two reasons:
//
//   - The inputs are different classes. ErrProtectedPath is documented for a
//     caller-supplied extra path that lands inside the deny-set; the values this
//     rejects are mostly ancestors of every protected prefix (`/`, `/var/lib`, the
//     work-dir itself, the pods root itself), which are under none of them. A
//     deny-set membership test would wave all of those through.
//   - ErrProtectedPath is already returned for eight distinct conditions, so a
//     test asserting it could pass because an unrelated fixture path tripped the
//     same sentinel, proving nothing about this bound.
var ErrDataVolumeUnbounded = errors.New("sbpl: data volume is not under the pods root")

// ErrInvalidWorkDir reports a Posture.WorkDir that is not a usable runtime
// work-dir: it must be an absolute, clean path other than the filesystem root.
// A relative, unclean (".."/trailing-slash/double-slash), or "/" work-dir would
// point the per-pod pods-root — and thus a pod's writable data-volume re-allow —
// at an unintended location, so it is rejected (fail closed).
var ErrInvalidWorkDir = errors.New("sbpl: invalid work-dir")

// ErrInvalidPodLogsDir reports a Posture.PodLogsDir that is not a usable
// container-log root: it must be an absolute, clean path other than the
// filesystem root, and it must be SET. It is the sibling of ErrInvalidWorkDir
// and fails closed for a sharper reason: the emitted deny IS the entire
// enforcement, so a malformed or empty value would leave every pod on the node
// able to read — and rewrite — every other pod's log file, silently.
var ErrInvalidPodLogsDir = errors.New("sbpl: invalid pod-logs dir")

// ErrWorkDirEscapesHome reports a Posture.WorkDir that, while well-formed, does
// not reside under the configured Posture.Home. In the unprivileged user-space
// posture the daemon's data area lives under its home; a work-dir outside it
// would let a pod's data-volume re-allow grant write access into another user's
// tree, so it is rejected.
var ErrWorkDirEscapesHome = errors.New("sbpl: work-dir escapes home")

// ErrInvalidDeniedPort reports a SandboxProfile.denied_local_ports entry outside
// the TCP port range 1..65535. The field is a repeated uint32 on the wire, so a 0
// or a 70000 arrives as a well-formed message; only this check can catch it.
//
// It fails closed — the profile is refused rather than generated with the bad
// entry dropped — because a silently-dropped entry is a silently-missing deny:
// the caller believes a loopback listener is unreachable from the pod while the
// emitted profile says nothing about it. A refused profile is one loud error at
// pod creation; a dropped entry is an unnoticed hole.
var ErrInvalidDeniedPort = errors.New("sbpl: denied_local_ports entry is not a TCP port")

// Posture is the NODE-level SBPL configuration: the runtimed work-dir the
// per-pod pods-root and protected-prefix denies are derived from, plus the
// cluster DNS resolver VIP and in-cluster API-server VIP the node advertises.
// Unlike the per-pod GenerateOptions it is the same for every pod on a node, so
// the caller builds it once from the runtime Config and passes it on each
// Generate. The zero value is usable: an empty WorkDir falls back to
// DefaultWorkDir and an empty ResolverVIP to DefaultResolverVIP.
//
// The VIP fields are PLUMBING-only: they render NO SBPL rule
// (per-IP network filters do not compile on macOS 26 — see the AllowNetwork
// stanza in Generate) and are carried for the DNS env/status plumbing.
type Posture struct {
	// WorkDir is the runtimed on-disk work-dir (== runtime Config.Root). The
	// per-pod pods-root is pinned at <WorkDir>/pods and the protected-prefix
	// denies track it. Empty defaults to DefaultWorkDir. A non-empty WorkDir
	// must be absolute and clean (ErrInvalidWorkDir otherwise) and — when Home
	// is set — must reside under Home (ErrWorkDirEscapesHome otherwise).
	WorkDir string
	// Home, when non-empty, is the directory WorkDir must reside under (the
	// _k3sm daemon user's home in the unprivileged user-space posture). It is the
	// containment check that keeps a misconfigured work-dir from pointing a pod's
	// writable re-allow outside the daemon's data area. Empty disables the check
	// (the legacy root posture, where WorkDir is the trusted /var/lib/k3sm).
	Home string
	// ResolverVIP is the cluster DNS Service VIP for this node. Empty defaults to
	// DefaultResolverVIP. PLUMBING-only: it renders NO SBPL rule (the macOS 26
	// Seatbelt grammar rejects per-IP network filters — an earlier VIP-scoped
	// egress allow failed sandbox_apply); it exists for the DNS env/status
	// plumbing that tells a pod where the resolver lives.
	ResolverVIP string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the `kubernetes`
	// ClusterIP, e.g. 10.43.0.1). No default: empty means "not configured".
	// PLUMBING-only: like ResolverVIP it renders NO SBPL rule — an
	// allow_network pod has unfiltered egress (see Generate) — and is carried for
	// the env/status plumbing. The caller (k3sm) sets it from the service CIDR.
	APIServerVIP string
	// PodLogsDir is the node's container-log root (the kubelet's
	// --pod-logs-dir, /var/log/pods by default), threaded from the runtime
	// Config. Unlike the VIP fields it is NOT plumbing: Generate emits a
	// read+write deny for it in the protected tier, and validateExtraPaths
	// refuses any caller-supplied path under it.
	//
	// It has no default and is REQUIRED (ErrInvalidPodLogsDir). A hard-coded
	// literal in systemProtectedPrefixes could not do this job: the value is
	// configurable per node — `k3sm dev` puts it under an instance work dir —
	// and a deny on a path nobody writes protects nothing while looking like it
	// does. Every pod's output, from every namespace, lands under this one
	// tree; a pod that could read it reads the whole node's logs, and one that
	// could write it could forge or erase another pod's.
	PodLogsDir string
}

// GenerateOptions carries the runtimed-internal SBPL inputs that are not part of
// the cross-repo SandboxProfile proto. They are computed during pod setup (by the
// volume materializer in pkg/mount and the persistent-volume binder in pkg/volume,
// and the node-level Posture from the runtime Config), not supplied by the
// provider over the wire.
type GenerateOptions struct {
	// Posture is the node-level configuration (work-dir, home, resolver +
	// API-server VIPs) the pods-root, the protected-prefix denies, and the DNS +
	// API-server egress derive from. The zero value uses the legacy defaults
	// (DefaultWorkDir, DefaultResolverVIP) and emits no API-server egress rule.
	Posture Posture
	// PodIP is the pod IP the network setup assigned. Plumbing-only:
	// it renders NO SBPL rule. An earlier (allow network-bind (local ip
	// "<PodIP>:*")) scoping does not compile on macOS 26 (Seatbelt network
	// filters accept only localhost/* hosts) and failed sandbox_apply for every
	// networked pod; bind-scoping a pod to its own lo0 /32 is not expressible.
	// The field is kept because pod setup computes it and the DNS env/status
	// plumbing consumes it. Not in the proto: it is computed during pod setup,
	// not supplied by the provider.
	PodIP string
	// ReadOnlyPaths get a read-only sub-scope: granted file-read* and explicitly
	// denied file-write*, emitted last so the write-deny wins even when the path
	// lies inside the writable data volume. These are the credential mounts
	// (secrets + the projected ServiceAccount token) a pod must not overwrite.
	ReadOnlyPaths []string
	// WritePaths get a read+write allow: the read-write persistent-volume mount
	// roots. A PVC-backed dir lives outside the pod data volume on the APFS
	// storage root (so it survives pod teardown — ReclaimPolicy Retain), so unlike
	// the pod's own data volume it needs an explicit allow. Validated against the
	// protected deny-set exactly like the extra paths; a read-only PVC uses
	// ReadPaths instead.
	WritePaths []string
	// ReadPaths get a read-only allow (no write): the read_only persistent-volume
	// mount roots. Default-deny then blocks writes to them.
	ReadPaths []string
}

// Generate renders a default-deny SBPL profile for one pod from sp and opts.
//
// The output always begins (version 1) / (deny default) / (import "system.sb"),
// then grants the minimal allow-list: read the OS (/System, /usr, /bin,
// /Library) plus validated extra read paths, read+write the pod's own data
// volume and any read-write persistent-volume mount roots (opts.WritePaths, which
// live outside the data volume on the APFS storage root), read-only
// persistent-volume roots (opts.ReadPaths), and — when sp.AllowNetwork is set —
// unfiltered network-outbound and network-bind (plus the mach-lookup rules the
// DNS resolver path needs). Per-IP scoping (VIP egress, per-pod-IP bind) is not
// expressible in the macOS 26 Seatbelt grammar — see the AllowNetwork stanza.
//
// When sp.AllowGpu is set the allow tier additionally carries the Metal
// user-client opens (metal.go). It is a per-pod widening, never a capability
// claim: a host with no usable Metal device honours the flag by granting access
// that then finds no device, and GetRuntimeInfo's GPUFacts is where a caller
// learns what the host actually has.
//
// The pods-root and the protected-prefix deny-set are derived from opts.Posture
// (the node-level work-dir), so a user-space daemon whose work-dir lives under
// its home pins every per-pod path under that work-dir rather than the legacy
// /var/lib/k3sm. A work-dir that is malformed or escapes the configured home is
// rejected (ErrInvalidWorkDir / ErrWorkDirEscapesHome).
//
// Because the unprivileged posture runs pods at the same uid as the runtime
// client (no per-pod uid isolation), the Seatbelt default-deny is the only
// barrier keeping a pod off the privileged k3sm-netd helper socket: for each
// sp.DeniedUnixSocketPaths entry Generate emits an explicit
// (deny network-outbound (remote unix-socket (literal …))) on top of the
// default-deny, after the network allow so last-match-wins keeps it denied.
// (The path filter is `literal`, an exact-path match — macOS 26 libsandbox
// rejects the non-existent `path-equal` filter with "unbound variable".)
//
// sp.DeniedLocalPorts is that deny's AF_INET sibling, and is threaded as data for
// the same reason: the generator must not know what listens on a given port, only
// that the caller wants it unreachable. For a pod that requested network, each
// entry renders one
// (deny network-outbound (remote ip "localhost:<port>")) after the network
// stanza, so last-match-wins keeps the dial denied while the rest of the grant
// stands; for a pod that did not, nothing is emitted because (deny default)
// already covers it. Entries are deduped, sorted, and range-checked
// (ErrInvalidDeniedPort).
//
// The narrowing is PORT-ONLY, and the ceiling is the grammar's, not a design
// choice: macOS 26 Seatbelt accepts only `localhost` or `*` as the host in a
// network filter (see network.go), so `localhost:<port>` matches that port on
// every address the host owns — loopback, the lo0-aliased pod addresses, the LAN
// address alike. The reach is measured rather than assumed:
// TestLocalPortDenyBlocksLoopbackConnect proves it at 127.0.0.1 and ::1, and the
// integration-tagged TestLocalPortDenyBlocksLANConnect proves it at the host's own
// non-loopback IPv4 address, where a dial to the denied port is refused with
// EPERM while an undenied port on the same address still connects. A Service VIP
// that happens to listen on the same port number is therefore ALSO unreachable
// from a confined pod. This is a same-host defence-in-depth layer over a
// shared-uid process, not per-pod isolation.
//
// Rule order is security-critical because SBPL is last-match-wins. Generate emits
// (in increasing precedence): the OS/extra-path allows + the network allows; then
// the AF_UNIX helper-socket denies and the protected file denies (/Users,
// /private/var/db, the pods root, the podreap store, the control-plane/daemon
// work-dir trees, the dyld cryptex) so a
// caller's extra path can never override them; then the narrow re-allows the
// protected denies would
// otherwise clobber (the dyld closure-cache read, this pod's own data volume,
// which lives under the denied pods root, and the file-read-metadata grant on
// that volume's — and every PV root's — strict ancestors); and last the read-only
// credential sub-scope, whose file-write* deny therefore wins even inside the
// writable data volume.
//
// The ancestor grant belongs to that narrow re-allow tier for the same reason the
// data volume does, and it would be inert anywhere earlier: the nodes it names
// are <podsRoot> and <podsRoot>/<id>, both inside the protected
// (deny file-read* file-write* (subpath <podsRoot>)), so an allow emitted before
// that deny loses to it. It grants file-read-metadata and nothing more — a
// process may stat those directories, which is what a chdir/realpath walk down to
// the data volume needs, and may neither list them nor read anything in them.
//
// The data volume itself IS bounded (see ErrDataVolumeUnbounded): it must be a
// proper descendant of <Posture.WorkDir>/pods. That bound is positive
// containment rather than a protected-prefix membership test because the most
// damaging values are ancestors of every protected prefix and are under none of
// them — `/`, `/var/lib`, or the work-dir itself would pass a deny-list check and
// then clobber pods/podreap/server/agent/run/blobs with the one re-allow below.
// One containment predicate forecloses all of them plus the pods root itself.
// The bound is applied before validateExtraPaths, whose data-volume carve-out
// inherits its entire safety from it: a check placed after would leave a window
// in which the extra-path validator is already disarmed.
//
// It is the value that is constrained, never the emission order: the data-volume
// re-allow must stay after the protected denies, because the pod's own volume
// lives under the denied pods root and would otherwise be unwritable.
//
// Generate returns ErrNoDataVolume if sp has no data volume,
// ErrDataVolumeUnbounded if that volume is not under the posture's pods root,
// ErrProtectedPath if any extra/credential path is under the protected deny-set,
// ErrXcodeToolchainDir if xcode_toolchain_dir is not a usable DEVELOPER_DIR,
// and the work-dir errors above for a bad Posture; otherwise the rendered profile
// is always well-formed and passes Validate.
func Generate(sp *runtimev1.SandboxProfile, opts GenerateOptions) (string, error) {
	if sp == nil {
		return "", ErrNoDataVolume
	}
	dataVol := filepath.Clean(sp.GetDataVolumePath())
	if dataVol == "" || dataVol == "." {
		return "", ErrNoDataVolume
	}

	// Derive the node-level deny-set from the configured work-dir, rejecting a
	// malformed or home-escaping work-dir before emitting anything (fail closed).
	podsRoot, workDirDenyRoots, protectedPrefixes, err := resolvePosture(opts.Posture)
	if err != nil {
		return "", err
	}

	// bound the data volume before anything consumes it — the re-allow below wins
	// over every protected deny (last-match-wins) and validateExtraPaths carves
	// every other path out against it, so an unbounded value defeats both at once.
	// strict containment: the pods root itself is refused, since re-allowing it
	// would hand the pod every sibling pod's materialized secrets.
	if !strictlyUnder(dataVol, podsRoot) {
		return "", fmt.Errorf("%w: %q is not a proper descendant of %q", ErrDataVolumeUnbounded, sp.GetDataVolumePath(), podsRoot)
	}

	// Validate every caller-supplied path before emitting any allow: a path under
	// the protected deny-set is rejected outright (fail closed). The pod's own
	// data volume is carved out (it is re-allowed by design below).
	if err := validateExtraPaths(dataVol, protectedPrefixes, sp.GetExtraReadPaths(), sp.GetExtraWritePaths(), opts.ReadOnlyPaths, opts.WritePaths, opts.ReadPaths); err != nil {
		return "", err
	}

	// The developer-toolchain read grant (xcode_toolchain_dir) is validated here,
	// against the same deny-set, so a bad value fails the whole profile before a
	// line is emitted rather than being silently dropped from it. Empty (the
	// default) yields "" and grants nothing. See xcode.go for the ablation.
	//
	// The same call the exported ValidateXcodeToolchainDir makes, over a
	// protected-prefix set from the same resolvePosture — so a caller that asks
	// before setting the field gets the answer this line will give.
	xcodeDir, err := validateXcodeToolchainDir(sp.GetXcodeToolchainDir(), protectedPrefixes)
	if err != nil {
		return "", err
	}

	// Read scope: the OS baseline + extra read paths + every PV mount root (a
	// read-write PV must be readable too, so its dir joins the read allow).
	readExtra := append([]string{}, sp.GetExtraReadPaths()...)
	readExtra = append(readExtra, opts.ReadPaths...)
	readExtra = append(readExtra, opts.WritePaths...)
	readPaths := dedupeSorted(append([]string{
		"/System",
		"/usr",
		"/bin",
		"/Library",
	}, readExtra...))
	// Write scope: extra write paths + the read-write PV mount roots.
	writePaths := dedupeSorted(append(append([]string{}, sp.GetExtraWritePaths()...), opts.WritePaths...))
	credPaths := dedupeSorted(opts.ReadOnlyPaths)
	deniedSockets := dedupeSorted(sp.GetDeniedUnixSocketPaths())
	// Range-checked before anything is written, and unconditionally — a malformed
	// entry is the caller's bug whether or not this pod asked for network, and
	// reporting it only for networked pods would hide it until the first pod that
	// happens to set the flag.
	deniedPorts, err := dedupeSortedPorts(sp.GetDeniedLocalPorts())
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(";; k3sm per-pod Seatbelt profile — GENERATED, do not edit.\n")
	b.WriteString(";; Default-deny; runs a native pod process at host paths (no chroot).\n")
	b.WriteString(";; Rule order is last-match-wins: OS/extra allows, THEN protected\n")
	b.WriteString(";; denies (so extra paths can't override them), THEN narrow re-allows.\n")
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	// system.sb supplies the dyld shared-cache mapping + mach bootstrap baseline.
	// critical: without it the process aborts (SIGABRT) during dynamic-linker init.
	b.WriteString("(import \"system.sb\")\n")

	b.WriteString("(allow process-exec*)\n")
	b.WriteString("(allow process-fork)\n")

	// --- allows (lowest precedence) ---------------------------------------
	b.WriteString(";; read: OS + frameworks + validated extra read paths.\n")
	b.WriteString("(allow file-read*\n")
	writeFirmlinkSubpaths(&b, readPaths)
	b.WriteString("  (literal \"/dev/null\") (literal \"/dev/zero\")\n")
	b.WriteString("  (literal \"/dev/random\") (literal \"/dev/urandom\"))\n")

	b.WriteString(";; write: validated extra write paths (+ /dev/null); the pod's own\n")
	b.WriteString(";; data volume is re-allowed below, after the protected denies.\n")
	b.WriteString("(allow file-write*\n")
	writeFirmlinkSubpaths(&b, writePaths)
	b.WriteString("  (literal \"/dev/null\"))\n")

	if networkRequested(sp) {
		b.WriteString(networkStanza)
	} else {
		b.WriteString(";; network: default-deny (no allow-network).\n")
	}

	// GPU (allow_gpu): the Metal user-client opens, emitted in the allows tier like
	// every other grant, so the protected denies below still outrank it. See
	// metal.go for what the two class names are and why nothing else is granted.
	if sp.GetAllowGpu() {
		b.WriteString(metalStanza)
	}

	// Developer toolchain (xcode_toolchain_dir): read-only, emitted in the allows
	// tier right after the GPU stanza so the protected denies below still outrank
	// it. See xcode.go for what each path is for and what is deliberately not
	// granted.
	if xcodeDir != "" {
		b.WriteString(xcodeToolchainStanza(xcodeDir))
	}

	// --- AF_UNIX helper-socket denies (higher precedence than network allows) --
	// Pods share the runtime client's uid (the unprivileged _k3sm posture has no
	// per-pod uid isolation), so LOCAL_PEERCRED cannot keep a pod off the
	// privileged k3sm-netd helper socket — the Seatbelt deny is the only barrier.
	// Make it explicit: deny connect() to each helper socket path, after any
	// network allow so last-match-wins keeps it denied even for a networked pod.
	if len(deniedSockets) > 0 {
		b.WriteString(";; AF_UNIX: explicitly deny connect() to the privileged helper\n")
		b.WriteString(";; socket(s) — same-uid pods can't be kept off them any other way.\n")
		b.WriteString("(deny network-outbound\n")
		for _, p := range deniedSockets {
			for _, form := range firmlinkForms(p) {
				b.WriteString(fmt.Sprintf("  (remote unix-socket (literal %q))\n", form))
			}
		}
		b.WriteString("  )\n")
	}

	// --- loopback port denies (higher precedence than the network allows) -----
	// Only meaningful for a pod that was granted network: without the stanza above
	// (deny default) already refuses every dial, and emitting a redundant deny
	// would put a rule in the profile that nothing in it can be read against.
	// Emitted AFTER the stanza so last-match-wins keeps these ports denied while
	// the rest of the grant stands. Port-only by grammar, not by choice — see the
	// ceiling note on Generate and in network.go.
	if networkRequested(sp) && len(deniedPorts) > 0 {
		b.WriteString(";; loopback: deny outbound dials to the local listener port(s)\n")
		b.WriteString(";; the caller named — same-uid pods can't be kept off them\n")
		b.WriteString(";; any other way. `localhost` matches every host-owned address.\n")
		for _, port := range deniedPorts {
			b.WriteString(fmt.Sprintf("(deny network-outbound (remote ip \"localhost:%d\"))\n", port))
		}
	}

	// --- protected denies (higher precedence than the extra-path allows) --
	// Emitted after the allows so a caller's extra path can never override them.
	b.WriteString(";; PROTECTED: deny user homes, the secrets/state store, the shared\n")
	b.WriteString(";; pods root, the daemon-private reap stores and the control-plane\n")
	b.WriteString(";; and daemon-private trees (sibling dirs under the work-dir, named\n")
	b.WriteString(";; below) AND the node's container-log tree (every pod's output plus\n")
	b.WriteString(";; the symlink dir) — read+write, AFTER the allows so a caller's\n")
	b.WriteString(";; extra path (even an ancestor work-dir grant) can't win.\n")
	// Both name lists are RENDERED from the same slices resolvePosture denies
	// (ReapStoreSubdirs/DaemonTreeSubdirs) rather than written out here: a
	// hand-typed header is a second enumeration, and the day it drifts the
	// profile documents a protection it does not carry.
	writeCommentNameList(&b, "reap stores", ReapStoreSubdirs())
	writeCommentNameList(&b, "daemon trees", DaemonTreeSubdirs())
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/Users\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/private/var/db\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	writeFirmlinkSubpaths(&b, workDirDenyRoots)
	b.WriteString("  )\n")
	// The dyld cryptex is denied write only: the dynamic linker must still read
	// the shared cache it holds, so denying read would SIGABRT every pod.
	b.WriteString(";; dyld cryptex: deny WRITE only (read is needed at link time).\n")
	b.WriteString("(deny file-write*\n")
	b.WriteString("  (subpath \"/System/Volumes/Preboot/Cryptexes\")\n")
	b.WriteString("  (subpath \"/System/Cryptexes\"))\n")

	// --- narrow re-allows (higher precedence than the protected denies) ---
	b.WriteString(";; re-allow the dyld closure cache read the /private/var/db deny clobbers.\n")
	b.WriteString("(allow file-read*\n")
	b.WriteString("  (subpath \"/private/var/db/dyld\"))\n")
	b.WriteString(";; re-allow THIS pod's own data volume (under the denied pods root).\n")
	b.WriteString("(allow file-read* file-write*\n")
	writeFirmlinkSubpaths(&b, []string{dataVol})
	b.WriteString("  )\n")

	// The stat-walk grant for every subtree re-allowed above. A tool that
	// canonicalizes its working directory — swift-driver and swift-frontend do,
	// via chdir+realpath — stats each ancestor of the cwd in turn, and under the
	// protected denies those ancestors are <podsRoot> and <podsRoot>/<id>, which
	// sit INSIDE (deny file-read* file-write* (subpath <podsRoot>)). Without this
	// the pod's own volume is readable while nothing can descend to it: a confined
	// swiftc (Swift 6.3.x / Command Line Tools 27.0) aborted with "unable to set
	// working directory: <dataVol>" after a `deny file-read-metadata /private`,
	// and hand-patching exactly these literals into the rendered profile made the
	// same compile succeed (B277).
	//
	// Two things separate it from the xcode stanza's otherwise identical ancestor
	// grant, and both are why it cannot simply be emitted there:
	//
	//   - TIER. The xcode grant sits in the allows, because nothing denies
	//     /Applications. These ancestors are under the protected denies, so the
	//     grant must be emitted AFTER them or last-match-wins erases it.
	//   - FIRMLINK DUAL-FORMING. A developer dir is never under /var,/tmp,/etc, so
	//     the xcode walk has one form per path. A pods root under /var/lib/k3sm has
	//     two, and only the /private one is what libsandbox matches — it is the
	//     form that yields the bare /private literal the denial named.
	//
	// Narrow by construction: file-read-metadata only (stat, never open or
	// readdir), and one (literal …) per node — never a (subpath …), which on
	// <podsRoot> would hand this pod every sibling pod's tree. The guard keeps an
	// empty set from rendering a filterless (allow file-read-metadata), which
	// would grant metadata on the whole filesystem.
	reallowed := append([]string{dataVol}, opts.WritePaths...)
	reallowed = append(reallowed, opts.ReadPaths...)
	if ancestors := ancestorMetadataPaths(reallowed); len(ancestors) > 0 {
		b.WriteString(";; existence only: the strict ancestors of every re-allowed subtree, so a\n")
		b.WriteString(";; stat-walk (chdir/realpath canonicalization — swift-driver, swift-frontend)\n")
		b.WriteString(";; can descend to it. Metadata on directories, one literal per node: never a\n")
		b.WriteString(";; subpath (a subpath on the pods root would reach every sibling pod), never\n")
		b.WriteString(";; file-read-data (no listing).\n")
		b.WriteString("(allow file-read-metadata\n")
		for _, a := range ancestors {
			b.WriteString(fmt.Sprintf("  (literal %q)\n", a))
		}
		b.WriteString("  )\n")
	}

	// --- credential read-only sub-scope (highest precedence) --------------
	// last, so this file-write* deny wins even though the credential lives inside
	// the writable data volume just re-allowed above: a pod can read its mounted
	// secret / SA-token but cannot overwrite it.
	if len(credPaths) > 0 {
		b.WriteString(";; credentials (secrets / SA-token): read-only sub-scope, emitted\n")
		b.WriteString(";; LAST so the write-deny wins inside the writable data volume.\n")
		b.WriteString("(allow file-read*\n")
		writeFirmlinkSubpaths(&b, credPaths)
		b.WriteString("  )\n")
		b.WriteString("(deny file-write*\n")
		writeFirmlinkSubpaths(&b, credPaths)
		b.WriteString("  )\n")
	}

	out := b.String()
	// self-check the network grant against what sp asked for, before the profile
	// escapes: the emitted stanza is the one artifact ValidateNetworkScope pins, so
	// an edit that widens, narrows, or reorders it fails here — at generation, with
	// the pod named — rather than at sandbox_apply, where a non-compiling stanza
	// takes down every networked pod on the node one create at a time.
	if err := ValidateNetworkScope(sp, out); err != nil {
		return "", err
	}
	return out, nil
}

// resolvePosture validates p.WorkDir and p.PodLogsDir and returns the pods root (<WorkDir>/pods —
// the bound Generate holds the data volume to), the work-dir-derived denied
// roots (that pods-root, the daemon-private reap stores named by
// ReapStoreSubdirs, and the control-plane and daemon-private trees named by
// DaemonTreeSubdirs — all read+write denied with firmlink forms by
// Generate) and the ordered protected-prefix
// deny-set (those roots plus the fixed system subtrees). The pods root is
// returned explicitly rather than read back out of the deny-root slice by index,
// so the data-volume bound and the deny it is carved out of cannot drift. An
// empty WorkDir
// falls back to DefaultWorkDir; a non-empty WorkDir must be absolute and clean
// (ErrInvalidWorkDir) and — when p.Home is set — must reside under Home
// (ErrWorkDirEscapesHome). The Posture VIP fields are not consumed here: since
// they render no SBPL (see the AllowNetwork stanza in Generate) and exist
// only for the DNS env/status plumbing.
func resolvePosture(p Posture) (podsRoot string, workDirDenyRoots []string, protectedPrefixes []string, err error) {
	workDir := p.WorkDir
	if workDir == "" {
		workDir = DefaultWorkDir
	} else {
		if !filepath.IsAbs(workDir) {
			return "", nil, nil, fmt.Errorf("%w: %q is not absolute", ErrInvalidWorkDir, workDir)
		}
		if workDir == "/" {
			return "", nil, nil, fmt.Errorf("%w: %q is the filesystem root", ErrInvalidWorkDir, workDir)
		}
		if filepath.Clean(workDir) != workDir {
			return "", nil, nil, fmt.Errorf("%w: %q is not a clean path", ErrInvalidWorkDir, workDir)
		}
	}
	if p.Home != "" {
		home := filepath.Clean(p.Home)
		if !isUnder(workDir, home) {
			return "", nil, nil, fmt.Errorf("%w: %q is not under %q", ErrWorkDirEscapesHome, workDir, home)
		}
	}
	podsRoot = filepath.Join(workDir, "pods")
	// The daemon-private reap stores: a record here drives a root-privileged kill
	// (podreap's kill(-pgid), vmreap's helper SIGKILL + the RemoveAll of the
	// record's run dir), so a confined pod must never be able to write — or read
	// — them. Single-sourced with pkg/runtime and the vm backend via
	// ReapStoreSubdirs.
	workDirDenyRoots = []string{podsRoot}
	for _, sub := range ReapStoreSubdirs() {
		workDirDenyRoots = append(workDirDenyRoots, filepath.Join(workDir, sub))
	}
	// The control-plane and daemon-private siblings. They go in
	// workDirDenyRoots — not in systemProtectedPrefixes — because the fixed list
	// holds absolute literals, so a /var/lib/k3sm entry there would guard nothing
	// on a daemon whose work-dir lives under its home.
	//
	// Be precise about the other list, because the difference decides where a
	// future prefix belongs: systemProtectedPrefixes members are emitted as
	// denies too — but each by a hand-written line in Generate, not by iterating
	// the slice. Only workDirDenyRoots is rendered by iteration
	// (writeFirmlinkSubpaths). So adding a member there gets validation plus an
	// emitted deny for free; adding one to the fixed list gets validation only
	// until you also write its emit line. (RunSubdir is the live example: it is
	// pinned in both forms — see systemProtectedPrefixes.)
	//
	// <WorkDir>/storage is deliberately not among them: it is the parent of every
	// pod's legitimate PVC dir and the denies are emitted after the PV allows, so
	// denying it would clobber every legitimate opts.WritePaths grant. The cost is
	// explicit — a caller-supplied extra path AT <WorkDir>/storage stays reachable,
	// which an emitted deny-list structurally cannot express.
	//
	// ProfileSubdir (<WorkDir>/sbpl) is in the same tier and is the sharpest of
	// them: it holds the per-pod Seatbelt profiles the exec-shim reads BEFORE it
	// applies the sandbox, so write access there is a sandbox-substitution
	// primitive — a pod able to rewrite a staged profile chooses the confinement
	// the next pod runs under. Single-sourced with the staging code and the
	// startup sweep via sandbox.ProfileSubdir.
	//
	// The membership of the set is DaemonTreeSubdirs' to state, not this
	// function's: the same list renders the ";; PROTECTED:" header comment in
	// Generate, so a tree can never be denied without being named or named
	// without being denied.
	for _, sub := range DaemonTreeSubdirs() {
		workDirDenyRoots = append(workDirDenyRoots, filepath.Join(workDir, sub))
	}
	// The socket + key dir also in its absolute form, when the work-dir is not the
	// default. The wireguard mesh private key is written at a hard-coded absolute
	// path (the installer passes a fixed --mesh-key-dir under DefaultWorkDir/run),
	// so unlike everything else here it does not move with runtimed's work-dir: on
	// a daemon whose work-dir lives under its home, the relative form alone would
	// guard an empty sibling while the private key stayed grantable as a
	// caller-supplied extra path. Appending it here rather than to the fixed list
	// is what gets it both the validation and the emitted deny (see the note
	// above); the conditional keeps the default posture from emitting it twice.
	if absRun := DefaultWorkDir + "/" + RunSubdir; filepath.Join(workDir, RunSubdir) != absRun {
		workDirDenyRoots = append(workDirDenyRoots, absRun)
	}
	// The container-log tree, both halves. They join this slice rather than
	// systemProtectedPrefixes for the reason the paragraph above gives: only
	// this slice is RENDERED by iteration, so a member here gets its emitted
	// deny (in both firmlink forms — /var/log/pods resolves to
	// /private/var/log/pods, and a deny written only against the firmlink fails
	// OPEN) as well as its validation. PodLogsDir additionally could not live in
	// the fixed list at all: it is configured per node.
	podLogsDir, err := resolvePodLogsDir(p.PodLogsDir)
	if err != nil {
		return "", nil, nil, err
	}
	workDirDenyRoots = append(workDirDenyRoots, podLogsDir, ContainerLogSymlinkDir)
	// Pin every work-dir root into the protected deny-set so a caller's extra
	// path can never reach a sibling pod, the reap store, or a control-plane
	// tree, then keep the fixed system subtrees.
	protectedPrefixes = append(append([]string{}, workDirDenyRoots...), systemProtectedPrefixes...)
	return podsRoot, workDirDenyRoots, protectedPrefixes, nil
}

// ValidatePodLogsDir reports whether dir is a usable container-log root,
// returning it unchanged when it is. It is exported so the daemon can refuse a
// bad value ONCE at startup rather than once per pod at profile generation: the
// check is the same one Generate applies, asked early.
func ValidatePodLogsDir(dir string) (string, error) { return resolvePodLogsDir(dir) }

// resolvePodLogsDir validates the node's container-log root, defaulting an empty
// value to DefaultPodLogsDir exactly as the work-dir defaults — so the zero
// Posture stays usable, which is what its own doc promises and what every
// generator test relies on. The REQUIREMENT lives one tier up, in the daemon's
// own Config (runtime.New refuses an empty value), where refusing is meaningful:
// there the node knows where its logs are, and inheriting upstream's literal
// would emit a deny for a directory it does not use.
func resolvePodLogsDir(dir string) (string, error) {
	if dir == "" {
		return DefaultPodLogsDir, nil
	}
	switch {
	case !filepath.IsAbs(dir):
		return "", fmt.Errorf("%w: %q is not absolute", ErrInvalidPodLogsDir, dir)
	case dir == "/":
		return "", fmt.Errorf("%w: %q is the filesystem root", ErrInvalidPodLogsDir, dir)
	case filepath.Clean(dir) != dir:
		return "", fmt.Errorf("%w: %q is not a clean path", ErrInvalidPodLogsDir, dir)
	}
	return dir, nil
}

// validateExtraPaths rejects any path in groups that is at or under a protected
// prefix, returning ErrProtectedPath. The pod's own data volume (dataVol) is
// always permitted (it is re-allowed by Generate). Non-absolute paths and "/" are
// rejected — a relative or whole-filesystem grant is never intended.
func validateExtraPaths(dataVol string, protectedPrefixes []string, groups ...[]string) error {
	cleanData := filepath.Clean(dataVol)
	for _, g := range groups {
		for _, raw := range g {
			p := filepath.Clean(raw)
			if p == "" || p == "." {
				continue
			}
			if !filepath.IsAbs(p) {
				return fmt.Errorf("%w: %q is not absolute", ErrProtectedPath, raw)
			}
			if p == "/" {
				return fmt.Errorf("%w: %q grants the entire filesystem", ErrProtectedPath, raw)
			}
			if isUnder(p, cleanData) {
				continue // the pod's own dir is always allowed
			}
			for _, pre := range protectedPrefixes {
				if isUnder(p, pre) {
					return fmt.Errorf("%w: %q is under protected %q; relocate the runtime root off this prefix with the k3sm server --pod-root flag", ErrProtectedPath, raw, pre)
				}
			}
		}
	}
	return nil
}

// isUnder reports whether path is prefix itself or a descendant of it. Both are
// assumed already filepath.Clean'd.
func isUnder(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// strictlyUnder reports whether path is a proper descendant of prefix — the same
// test as isUnder minus the equality case. A relative path never satisfies it
// against an absolute prefix, which is what makes it reject a relative data
// volume.
//
// Unlike isUnder it cleans its own operands rather than documenting the
// precondition. That is deliberate: this is the sink tier, whose stated job is to
// hold when the primary guard is bypassed or when a future caller reaches the
// exported Generate some other way — and a sink whose correctness is inherited
// from the caller it exists to distrust is a primary in disguise. Uncleaned,
// "<prefix>/../../../etc" satisfies a raw prefix test. The live path is already
// safe (Generate cleans first), so this costs nothing and removes the residual.
//
// The one-word difference from isUnder is the whole point, so it is pinned by
// test (TestDataVolumePathRejectsProtectedTree/predicate) rather than asserted
// here: equality-inclusive vs strict is exactly the difference between accepting
// and rejecting the pods root itself as a data volume, and re-allowing the pods
// root read+write after the protected denies would hand one pod every sibling
// pod's materialized secrets and projected SA-token.
//
// It is a third strict variant in this repo, alongside mount.IsStrictlyUnder and
// pkg/supervisor's local one, and that duplication is deliberate rather than
// laziness: pkg/sandbox must not import pkg/mount (the same layering rule that
// makes sandbox.VMVolumePlan plain data — see the mapper note in
// pkg/runtime/pod.go), and the supervisor variant is unexported and deliberately
// stricter (absolute operands only, since a relative base would resolve against
// the process working directory). Importing either would invert layering to save
// one line.
func strictlyUnder(path, prefix string) bool {
	path, prefix = filepath.Clean(path), filepath.Clean(prefix)
	if prefix == string(filepath.Separator) {
		return path != prefix && filepath.IsAbs(path)
	}
	return path != prefix && isUnder(path, prefix)
}

// strictAncestors returns the strict ancestors of p, root-first, excluding "/"
// and p itself: for /Applications/Xcode.app/Contents/Developer it is
// /Applications, /Applications/Xcode.app, /Applications/Xcode.app/Contents; for
// /private/var/lib/k3sm/pods/p1/rootfs it is /private, /private/var, and so on
// down to /private/var/lib/k3sm/pods/p1. These are the directories a stat-walk
// traverses on the way to p, and the metadata-only tier is the whole grant they
// get — a directory a process may stat but neither list nor open.
//
// It lives here rather than beside its first caller (the xcode toolchain stanza)
// because the ancestor walk is not an Xcode fact: Generate uses the same helper
// for every re-allowed subtree, and two copies of a path walk that a grant is
// derived from would be one copy too many.
func strictAncestors(p string) []string {
	var out []string
	for cur := filepath.Dir(p); cur != "/" && cur != "." && cur != p; cur = filepath.Dir(cur) {
		out = append(out, cur)
	}
	// reverse into root-first order, which is how the stat-walk reads.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ancestorMetadataPaths returns every directory a process must be able to stat to
// reach one of roots: for each root, for each of its firmlink forms, that form's
// strict ancestors — deduped, first-seen order (root-first within a form), so the
// rendered stanza is deterministic and carries no duplicate line.
//
// Both forms matter and neither is redundant. libsandbox matches the
// symlink-resolved path, so the /private form is the one a stat of
// /var/lib/k3sm/pods/<id>/rootfs actually tests; the raw form is what a rule
// written against a path the kernel does not rebase (a work-dir already under
// /private, or off the firmlinked trees entirely) needs. Emitting both is how the
// bare /private grant — the first node of the resolved walk, and the denial B277
// observed — comes to exist at all.
func ancestorMetadataPaths(roots []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range roots {
		if r == "" {
			continue
		}
		for _, form := range firmlinkForms(r) {
			for _, anc := range strictAncestors(form) {
				if _, ok := seen[anc]; ok {
					continue
				}
				seen[anc] = struct{}{}
				out = append(out, anc)
			}
		}
	}
	return out
}

// macOSFirmlinks are the synthetic APFS firmlinks the macOS boot volume presents:
// /var, /tmp, /etc resolve to /private/var, /private/tmp, /private/etc.
var macOSFirmlinks = []string{"/var", "/tmp", "/etc"}

// firmlinkForms returns the SBPL literal path form(s) a unix-socket deny must cover
// so it holds regardless of which alias a pod connect()s through. libsandbox matches
// a connect() target against the symlink-resolved path, so a deny filter written
// against a macOS firmlink (e.g. /var/lib/k3sm/run/netd.sock) fails open — the pod's
// resolved target is /private/var/…, which the /var literal never matches (verified
// on macOS 26). This returns the cleaned path plus, when it sits under a firmlink,
// the /private-resolved form. It is deterministic (no filesystem stat), so it works
// at profile-generation time whether or not the socket exists yet.
func firmlinkForms(p string) []string {
	p = filepath.Clean(p)
	forms := []string{p}
	for _, fl := range macOSFirmlinks {
		if isUnder(p, fl) {
			forms = append(forms, "/private"+p)
			break
		}
	}
	return forms
}

// writeFirmlinkSubpaths writes a `(subpath …)` line for every firmlink form of each
// path (firmlinkForms). libsandbox matches a file path against its symlink-resolved
// form, so a rule written only against the /var,/tmp,/etc firmlink silently
// misfires — an allow fails closed (the pod cannot read its own rebased volume
// under /var/lib/k3sm/pods/…, which resolves to /private/var/…), a deny fails open.
// Emitting both forms makes the rule hold regardless of which alias is addressed.
func writeFirmlinkSubpaths(b *strings.Builder, paths []string) {
	for _, p := range paths {
		for _, form := range firmlinkForms(p) {
			b.WriteString(fmt.Sprintf("  (subpath %q)\n", form))
		}
	}
}

// commentWrapCols is the column the generated comment lists wrap at. It is the
// conventional 72 rather than a terminal width: a rendered profile is read in
// diffs and in `sandbox_apply` error output, both of which are line-oriented.
const commentWrapCols = 72

// writeCommentNameList writes names as an SBPL comment block — `;;   <label>:
// a, b, c` — wrapping at commentWrapCols with a continuation indent, so the
// rendered profile carries the deny-set's membership in readable form.
//
// It takes the names as a slice rather than a pre-joined string because its
// whole purpose is that the header is GENERATED from the same lists
// resolvePosture iterates (ReapStoreSubdirs, DaemonTreeSubdirs): a caller that
// had to spell the names to call it would reintroduce the second enumeration
// this exists to remove. An empty list writes nothing rather than an empty
// label, so a future list that legitimately becomes empty leaves no dangling
// line in the golden.
func writeCommentNameList(b *strings.Builder, label string, names []string) {
	if len(names) == 0 {
		return
	}
	const prefix = ";;   "
	const contPrefix = ";;     "
	line := prefix + label + ":"
	for i, n := range names {
		frag := " " + n
		if i < len(names)-1 {
			frag += ","
		}
		if len(line)+len(frag) > commentWrapCols {
			b.WriteString(line + "\n")
			line = contPrefix + strings.TrimPrefix(frag, " ")
			continue
		}
		line += frag
	}
	b.WriteString(line + "\n")
}

// Validate checks that a rendered SBPL profile is fail-closed: it must contain
// (deny default) and (import "system.sb"). It returns ErrMissingDenyDefault or
// ErrMissingSystemImport otherwise. The generator's output always passes; this
// guards a Backend against ever applying a hand-supplied profile that is
// fail-open or that would SIGABRT during dyld init.
func Validate(profile string) error {
	if !containsDirective(profile, "(deny default)") {
		return ErrMissingDenyDefault
	}
	if !containsDirective(profile, `(import "system.sb")`) {
		return ErrMissingSystemImport
	}
	return nil
}

// containsDirective reports whether profile has dir as a directive, ignoring
// comment lines (;; ...) and surrounding whitespace.
func containsDirective(profile, dir string) bool {
	for _, line := range strings.Split(profile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.Contains(line, dir) {
			return true
		}
	}
	return false
}

// dedupeSorted returns the unique, non-empty, lexically sorted elements of in so
// the generated profile is deterministic regardless of input order (golden-test
// stable).
func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// dedupeSortedPorts returns the unique, ascending TCP ports in in, so the
// generated profile is deterministic regardless of input order (golden-test
// stable), and rejects any entry outside 1..65535 with ErrInvalidDeniedPort.
//
// Unlike dedupeSorted, which drops the empty string, this drops nothing: there is
// no "absent" value in the uint32 range that a caller could have meant, so 0 is an
// error rather than a skip. See ErrInvalidDeniedPort for why the whole profile is
// refused instead.
func dedupeSortedPorts(in []uint32) ([]uint32, error) {
	seen := make(map[uint32]struct{}, len(in))
	out := make([]uint32, 0, len(in))
	for _, p := range in {
		if p == 0 || p > 65535 {
			return nil, fmt.Errorf("%w: %d is outside 1..65535", ErrInvalidDeniedPort, p)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
