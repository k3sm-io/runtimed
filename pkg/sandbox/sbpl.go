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
// pkg/runtime single-sources the on-disk store name from the SAME literal the
// SBPL generator defends: resolvePosture pins <WorkDir>/podreap into the
// protected deny-set and Generate emits a matching (deny ...) for it, so a
// confined pod can never forge a reap record (which would drive a root-SIGKILL
// at a process group of its choosing). If the two literals drifted, the deny
// would protect a non-existent sibling while the real store stayed writable.
const PodReapSubdir = "podreap"

// The control-plane and daemon-private work-dir subtrees a confined pod may
// never read or write. Like PodReapSubdir they are exported consts so the leaf
// name has exactly ONE spelling: resolvePosture joins each onto the work-dir,
// pins the result into the protected deny-set, and Generate emits a matching
// (deny ...) for it. A second, drifted literal would leave the deny guarding a
// non-existent sibling while the real tree stayed writable.
//
// SCOPE — these denies close the CALLER-SUPPLIED extra/PV-path tier. The
// data-volume tier that used to defeat them (validateExtraPaths carves out every
// path under the data volume, and Generate re-allows the data volume AFTER these
// denies, so SBPL's last-match-wins beat them) is closed separately, by the
// ErrDataVolumeUnbounded bound Generate applies to dataVol BEFORE either of those
// two consumers runs.
const (
	// ServerSubdir is the control-plane state dir (<WorkDir>/server): the cluster
	// CA private keys, the generated kubeconfigs, and the kine SQLite datastore.
	// It is written by the k3sm control plane rather than by runtimed, and
	// runtimed cannot import k3sm, so the name cannot be single-sourced across
	// the repo boundary today. RESIDUAL: the control plane takes its state root
	// from a --work-dir flag with a posture-aware default, so on a node started
	// with a different value this deny guards a directory nothing writes.
	ServerSubdir = "server"
	// AgentSubdir is the node-agent state dir (<WorkDir>/agent): the node
	// password and the agent kubeconfig. Same cross-repo residual as ServerSubdir.
	AgentSubdir = "agent"
	// RunSubdir is the daemon socket + key dir (<WorkDir>/run): the runtimed and
	// k3sm-netd control sockets and the wireguard mesh PRIVATE KEY under
	// run/keys. The vm backend already refuses to export any slice of this tree
	// (see pkg/mount's share-root guard), so without this deny the Seatbelt
	// fallback was the WEAKER of the two backends — inverting the invariant that
	// falling back degrades toward stronger isolation.
	RunSubdir = "run"
	// BlobsSubdir is the content-addressed image blob store (<WorkDir>/blobs). A
	// blob path is validated, NOT verified, and a cache probe treats any regular
	// file at the path as a hit — so a pod able to write here could replace a
	// layer that every SUBSEQUENT pod materializes without re-verification.
	// pkg/image derives the same dir from its own copy of this literal; the
	// sandbox gate asserts the two still agree.
	BlobsSubdir = "blobs"
)

// DefaultResolverVIP is the cluster DNS Service VIP assumed when a Posture
// leaves ResolverVIP empty. It is PLUMBING-ONLY: since M10.1 the VIP renders NO
// SBPL rule (the macOS 26 Seatbelt grammar cannot express per-IP network
// filters — see the AllowNetwork stanza in Generate), but the field and its
// default are kept as the node-level DNS configuration the env/status plumbing
// reads. Overridable per-node via Posture.
const DefaultResolverVIP = "10.96.0.10"

// systemProtectedPrefixes are the FIXED host subtrees a pod may NEVER be granted
// via a caller-supplied extra path, independent of the work-dir: user homes, the
// system secrets/state store, and the dyld cryptex (the system read-only content
// volume). They are ABSOLUTE LITERALS by definition — anything work-dir-relative
// belongs in resolvePosture instead, which appends the pods-root (sibling pods),
// the daemon-private podreap store, and the control-plane/daemon trees
// (<WorkDir>/{server,agent,run,blobs}) to this set.
// validateExtraPaths rejects any extra read/write path at or under one of these
// (the pod's OWN data volume is carved out), and Generate emits a matching
// (deny ...) for each AFTER the extra-path allows so an unvalidated path cannot
// override the deny (SBPL is last-match-wins).
var systemProtectedPrefixes = []string{
	"/Users",
	"/private/var/db",
	"/System/Volumes/Preboot/Cryptexes",
	"/System/Cryptexes",
}

// ErrMissingDenyDefault reports an SBPL profile that does not start its rule set
// with (deny default) — a profile without it is fail-open and is rejected.
var ErrMissingDenyDefault = errors.New("sbpl: profile missing (deny default)")

// ErrMissingSystemImport reports an SBPL profile that does not (import
// "system.sb"). Without the baseline every binary aborts (SIGABRT) during dyld
// init, so a profile lacking it is rejected.
var ErrMissingSystemImport = errors.New(`sbpl: profile missing (import "system.sb")`)

// ErrNoDataVolume reports a SandboxProfile with no data_volume_path (empty, or a
// path that cleans to "."): there is nowhere the pod may write, so the profile
// cannot be generated. A data_volume_path that is PRESENT but too wide — "/"
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
// PROPER DESCENDANT of the posture's pods root (<Posture.WorkDir>/pods). The data
// volume is the one tree Generate re-allows read+write AFTER the protected denies
// (SBPL is last-match-wins) and the one carve-out validateExtraPaths grants every
// other caller-supplied path, so an unbounded value overrides the whole deny-set
// in a single emitted line and disarms the extra-path validator with it.
//
// It is a DISTINCT sentinel from ErrProtectedPath, not a reuse, for two reasons:
//
//   - The inputs are different classes. ErrProtectedPath is documented for a
//     caller-supplied EXTRA path that lands INSIDE the deny-set; the values this
//     rejects are mostly ANCESTORS of every protected prefix (`/`, `/var/lib`, the
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

// ErrWorkDirEscapesHome reports a Posture.WorkDir that, while well-formed, does
// not reside under the configured Posture.Home. In the unprivileged user-space
// posture the daemon's data area lives under its home; a work-dir outside it
// would let a pod's data-volume re-allow grant write access into another user's
// tree, so it is rejected.
var ErrWorkDirEscapesHome = errors.New("sbpl: work-dir escapes home")

// Posture is the NODE-LEVEL SBPL configuration: the runtimed work-dir the
// per-pod pods-root and protected-prefix denies are derived from, plus the
// cluster DNS resolver VIP and in-cluster API-server VIP the node advertises.
// Unlike the per-pod GenerateOptions it is the same for every pod on a node, so
// the caller builds it once from the runtime Config and passes it on each
// Generate. The zero value is usable: an empty WorkDir falls back to
// DefaultWorkDir and an empty ResolverVIP to DefaultResolverVIP.
//
// The VIP fields are PLUMBING-ONLY since M10.1: they render NO SBPL rule
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
	// DefaultResolverVIP. PLUMBING-ONLY: it renders NO SBPL rule (the macOS 26
	// Seatbelt grammar rejects per-IP network filters — the pre-M10.1 VIP-scoped
	// egress allow failed sandbox_apply); it exists for the DNS env/status
	// plumbing that tells a pod where the resolver lives.
	ResolverVIP string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the `kubernetes`
	// ClusterIP, e.g. 10.43.0.1). No default: empty means "not configured".
	// PLUMBING-ONLY: like ResolverVIP it renders NO SBPL rule since M10.1 — an
	// allow_network pod has unfiltered egress (see Generate) — and is carried for
	// the env/status plumbing. The caller (k3sm) sets it from the service CIDR.
	APIServerVIP string
}

// GenerateOptions carries the runtimed-internal SBPL inputs that are NOT part of
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
	// PodIP is the pod IP the network setup assigned. PLUMBING-ONLY since M10.1:
	// it renders NO SBPL rule. The pre-M10.1 (allow network-bind (local ip
	// "<PodIP>:*")) scoping does not compile on macOS 26 (Seatbelt network
	// filters accept only localhost/* hosts) and failed sandbox_apply for every
	// networked pod; bind-scoping a pod to its own lo0 /32 is NOT expressible.
	// The field is kept because pod setup computes it and the DNS env/status
	// plumbing consumes it. Not in the proto: it is computed during pod setup,
	// not supplied by the provider.
	PodIP string
	// ReadOnlyPaths get a read-only sub-scope: granted file-read* and explicitly
	// denied file-write*, emitted LAST so the write-deny wins even when the path
	// lies inside the writable data volume. These are the credential mounts
	// (secrets + the projected ServiceAccount token) a pod must not overwrite.
	ReadOnlyPaths []string
	// WritePaths get a read+write allow: the read-write PERSISTENT-VOLUME mount
	// roots (M3.1). A PVC-backed dir lives OUTSIDE the pod data volume on the APFS
	// storage root (so it survives pod teardown — ReclaimPolicy Retain), so unlike
	// the pod's own data volume it needs an explicit allow. Validated against the
	// protected deny-set exactly like the extra paths; a read-only PVC uses
	// ReadPaths instead.
	WritePaths []string
	// ReadPaths get a read-only allow (no write): the read_only PERSISTENT-VOLUME
	// mount roots (M3.1). Default-deny then blocks writes to them.
	ReadPaths []string
}

// Generate renders a default-deny SBPL profile for one pod from sp and opts.
//
// The output ALWAYS begins (version 1) / (deny default) / (import "system.sb"),
// then grants the minimal allow-list: read the OS (/System, /usr, /bin,
// /Library) plus validated extra read paths, read+write the pod's own data
// volume and any read-write persistent-volume mount roots (opts.WritePaths, which
// live outside the data volume on the APFS storage root), read-only
// persistent-volume roots (opts.ReadPaths), and — when sp.AllowNetwork is set —
// UNFILTERED network-outbound and network-bind (plus the mach-lookup rules the
// DNS resolver path needs). Per-IP scoping (VIP egress, per-pod-IP bind) is NOT
// expressible in the macOS 26 Seatbelt grammar — see the AllowNetwork stanza.
//
// When sp.AllowGpu is set the allow tier additionally carries the Metal
// user-client opens (metal.go). It is a per-pod WIDENING, never a capability
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
// client (no per-pod uid isolation), the Seatbelt default-deny is the ONLY
// barrier keeping a pod off the privileged k3sm-netd helper socket: for each
// sp.DeniedUnixSocketPaths entry Generate emits an explicit
// (deny network-outbound (remote unix-socket (literal …))) on top of the
// default-deny, AFTER the network allow so last-match-wins keeps it denied.
// (The path filter is `literal`, an exact-path match — macOS 26 libsandbox
// rejects the non-existent `path-equal` filter with "unbound variable".)
//
// Rule ORDER is security-critical because SBPL is last-match-wins. Generate emits
// (in increasing precedence): the OS/extra-path allows + the network allows; THEN
// the AF_UNIX helper-socket denies and the protected file denies (/Users,
// /private/var/db, the pods root, the podreap store, the control-plane/daemon
// work-dir trees, the dyld cryptex) so a
// caller's extra path can never override them; THEN the narrow re-allows the
// protected denies would
// otherwise clobber (the dyld closure-cache read and this pod's own data volume,
// which lives under the denied pods root); and LAST the read-only credential
// sub-scope, whose file-write* deny therefore wins even inside the writable data
// volume.
//
// The DATA VOLUME ITSELF IS BOUNDED (see ErrDataVolumeUnbounded): it must be a
// PROPER DESCENDANT of <Posture.WorkDir>/pods. That bound is POSITIVE
// CONTAINMENT rather than a protected-prefix membership test because the most
// damaging values are ANCESTORS of every protected prefix and are under none of
// them — `/`, `/var/lib`, or the work-dir itself would pass a deny-list check and
// then clobber pods/podreap/server/agent/run/blobs with the one re-allow below.
// One containment predicate forecloses all of them plus the pods root itself.
// The bound is applied BEFORE validateExtraPaths, whose data-volume carve-out
// inherits its entire safety from it: a check placed after would leave a window
// in which the extra-path validator is already disarmed.
//
// It is the VALUE that is constrained, never the emission order: the data-volume
// re-allow MUST stay after the protected denies, because the pod's own volume
// lives under the denied pods root and would otherwise be unwritable.
//
// Generate returns ErrNoDataVolume if sp has no data volume,
// ErrDataVolumeUnbounded if that volume is not under the posture's pods root,
// ErrProtectedPath if any extra/credential path is under the protected deny-set,
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
	// malformed or home-escaping work-dir BEFORE emitting anything (fail closed).
	podsRoot, workDirDenyRoots, protectedPrefixes, err := resolvePosture(opts.Posture)
	if err != nil {
		return "", err
	}

	// BOUND the data volume before anything consumes it — the re-allow below wins
	// over every protected deny (last-match-wins) and validateExtraPaths carves
	// every other path out against it, so an unbounded value defeats both at once.
	// STRICT containment: the pods root ITSELF is refused, since re-allowing it
	// would hand the pod every sibling pod's materialized secrets.
	if !strictlyUnder(dataVol, podsRoot) {
		return "", fmt.Errorf("%w: %q is not a proper descendant of %q", ErrDataVolumeUnbounded, sp.GetDataVolumePath(), podsRoot)
	}

	// Validate every caller-supplied path BEFORE emitting any allow: a path under
	// the protected deny-set is rejected outright (fail closed). The pod's own
	// data volume is carved out (it is re-allowed by design below).
	if err := validateExtraPaths(dataVol, protectedPrefixes, sp.GetExtraReadPaths(), sp.GetExtraWritePaths(), opts.ReadOnlyPaths, opts.WritePaths, opts.ReadPaths); err != nil {
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

	var b strings.Builder
	b.WriteString(";; k3sm per-pod Seatbelt profile — GENERATED, do not edit.\n")
	b.WriteString(";; Default-deny; runs a native pod process at host paths (no chroot).\n")
	b.WriteString(";; Rule order is last-match-wins: OS/extra allows, THEN protected\n")
	b.WriteString(";; denies (so extra paths can't override them), THEN narrow re-allows.\n")
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	// system.sb supplies the dyld shared-cache mapping + mach bootstrap baseline.
	// CRITICAL: without it the process aborts (SIGABRT) during dynamic-linker init.
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

	if sp.GetAllowNetwork() {
		// ============================================================================
		// macOS 26 SBPL GRAMMAR CEILING — per-IP network scoping DOES NOT COMPILE.
		//
		// PROBE-VERIFIED on macOS 26.5.1 through the real k3sm-execshim/libsandbox
		// path: Seatbelt network-address filters accept ONLY `localhost` or `*` as
		// the host. (remote ip "10.43.0.10:53"), (local ip "<PodIP>:*"), and every
		// tcp4/ip4/tcp dialect variant FAIL to compile with "host must be * or
		// localhost in network address" — so the pre-M10.1 VIP-scoped outbound
		// allows and PodIP-scoped bind allow made EVERY AllowNetwork pod fail at
		// sandbox_apply (networked pods could not spawn at all).
		//
		// What the grammar DOES support: per-PORT scoping compiles and enforces
		// precisely ((local ip "*:8899") allowed :8899 and denied :8898), and
		// localhost-host filters compile. Whether `localhost` matches lo0-ALIASED
		// per-pod addresses is UNKNOWN without a root-gated lab probe, so
		// port-scoped and localhost-scoped TIGHTENINGS are a named follow-up —
		// not emitted here.
		//
		// Honest consequence: for an allow_network pod, networking allowed means
		// networking ALLOWED — unfiltered outbound + bind under the profile's
		// (deny default). The isolation story for a networked pod stays fs/exec
		// confinement plus the vm RuntimeClass for untrusted tenancy; NEVER claim
		// network isolation from Seatbelt. Posture.ResolverVIP/APIServerVIP and
		// GenerateOptions.PodIP are plumbing-only (DNS env/status) — they render
		// no SBPL.
		// ============================================================================
		b.WriteString(";; network: ALLOWED — unfiltered outbound+bind+inbound under (deny default).\n")
		b.WriteString(";; macOS 26 Seatbelt accepts only localhost/* hosts in network filters;\n")
		b.WriteString(";; per-IP scoping (VIP egress, per-pod-IP bind) does NOT compile.\n")
		b.WriteString("(allow network-outbound)\n")
		b.WriteString("(allow network-bind)\n")
		// network-inbound authorizes listen()/accept(). A bare (allow network-bind)
		// passes bind() but a TCP server's listen() is gated by the SEPARATE
		// network-inbound operation, so without this EVERY listening pod (a Service
		// target, a readiness/liveness HTTP server) fails listen() with EPERM under
		// (deny default). Regression from M10.1 dropping the PodIP-scoped bind (which
		// implied inbound) for a bare bind; probe-verified through the real
		// execshim/libsandbox path on macOS 26.5.1 (both :8080 and :8081).
		b.WriteString("(allow network-inbound)\n")
		b.WriteString(";; mach-lookup the DNS resolver path (mDNSResponder) needs.\n")
		b.WriteString("(allow mach-lookup\n")
		b.WriteString("  (global-name \"com.apple.dnssd.service\")\n")
		b.WriteString("  (global-name \"com.apple.mDNSResponder\"))\n")
	} else {
		b.WriteString(";; network: default-deny (no allow-network).\n")
	}

	// GPU (allow_gpu): the Metal user-client opens, emitted in the ALLOWS tier like
	// every other grant, so the protected denies below still outrank it. See
	// metal.go for what the two class names are and why nothing else is granted.
	if sp.GetAllowGpu() {
		b.WriteString(metalStanza)
	}

	// --- AF_UNIX helper-socket denies (higher precedence than network allows) --
	// Pods share the runtime client's uid (the unprivileged _k3sm posture has no
	// per-pod uid isolation), so LOCAL_PEERCRED cannot keep a pod off the
	// privileged k3sm-netd helper socket — the Seatbelt deny is the ONLY barrier.
	// Make it explicit: deny connect() to each helper socket path, AFTER any
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

	// --- protected denies (higher precedence than the extra-path allows) --
	// Emitted AFTER the allows so a caller's extra path can never override them.
	b.WriteString(";; PROTECTED: deny user homes, the secrets/state store, the shared\n")
	b.WriteString(";; pods root, the daemon-private podreap store AND the control-plane\n")
	b.WriteString(";; and daemon trees (server, agent, run, blobs — sibling dirs under\n")
	b.WriteString(";; the work-dir) — read+write, AFTER the allows so a caller's extra\n")
	b.WriteString(";; path (even an ancestor work-dir grant) can't win.\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/Users\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/private/var/db\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	writeFirmlinkSubpaths(&b, workDirDenyRoots)
	b.WriteString("  )\n")
	// The dyld cryptex is denied WRITE only: the dynamic linker must still READ
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

	// --- credential read-only sub-scope (highest precedence) --------------
	// LAST, so this file-write* deny wins even though the credential lives inside
	// the writable data volume just re-allowed above: a pod can READ its mounted
	// secret / SA-token but cannot OVERWRITE it.
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

	return b.String(), nil
}

// resolvePosture validates p.WorkDir and returns the pods root (<WorkDir>/pods —
// the bound Generate holds the data volume to), the work-dir-derived denied
// roots (that pods-root, the daemon-private podreap store, and the
// control-plane/daemon trees <WorkDir>/{server,agent,run,blobs} — all read+write
// denied with firmlink forms by Generate) and the ordered protected-prefix
// deny-set (those roots plus the fixed system subtrees). The pods root is
// returned EXPLICITLY rather than read back out of the deny-root slice by index,
// so the data-volume bound and the deny it is carved out of cannot drift. An
// empty WorkDir
// falls back to DefaultWorkDir; a non-empty WorkDir must be absolute and clean
// (ErrInvalidWorkDir) and — when p.Home is set — must reside under Home
// (ErrWorkDirEscapesHome). The Posture VIP fields are NOT consumed here: since
// M10.1 they render no SBPL (see the AllowNetwork stanza in Generate) and exist
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
	// The daemon-private startup-reap store: records here drive a root-privileged
	// kill(-pgid), so a confined pod must never be able to write (or read) them.
	// Single-sourced with pkg/runtime via PodReapSubdir.
	podReapRoot := filepath.Join(workDir, PodReapSubdir)
	workDirDenyRoots = []string{podsRoot, podReapRoot}
	// The control-plane and daemon-private siblings. They go in
	// workDirDenyRoots — NOT in systemProtectedPrefixes — because the fixed list
	// holds ABSOLUTE literals, so a /var/lib/k3sm entry there would guard nothing
	// on a daemon whose work-dir lives under its home.
	//
	// Be precise about the other list, because the difference decides where a
	// FUTURE prefix belongs: systemProtectedPrefixes members ARE emitted as
	// denies too — but each by a hand-written line in Generate, not by iterating
	// the slice. Only workDirDenyRoots is rendered by iteration
	// (writeFirmlinkSubpaths). So adding a member THERE gets validation plus an
	// emitted deny for free; adding one to the fixed list gets validation only
	// until you also write its emit line. (RunSubdir is the live example: it is
	// pinned in BOTH forms — see systemProtectedPrefixes.)
	//
	// <WorkDir>/storage is deliberately NOT among them: it is the parent of every
	// pod's legitimate PVC dir and the denies are emitted AFTER the PV allows, so
	// denying it would clobber every legitimate opts.WritePaths grant. The cost is
	// explicit — a caller-supplied extra path AT <WorkDir>/storage stays reachable,
	// which an emitted deny-list structurally cannot express.
	for _, sub := range []string{ServerSubdir, AgentSubdir, RunSubdir, BlobsSubdir} {
		workDirDenyRoots = append(workDirDenyRoots, filepath.Join(workDir, sub))
	}
	// The socket + key dir ALSO in its absolute form, when the work-dir is not the
	// default. The wireguard mesh PRIVATE KEY is written at a hard-coded absolute
	// path (the installer passes a fixed --mesh-key-dir under DefaultWorkDir/run),
	// so unlike everything else here it does NOT move with runtimed's work-dir: on
	// a daemon whose work-dir lives under its home, the relative form alone would
	// guard an empty sibling while the private key stayed grantable as a
	// caller-supplied extra path. Appending it HERE rather than to the fixed list
	// is what gets it both the validation and the emitted deny (see the note
	// above); the conditional keeps the default posture from emitting it twice.
	if absRun := DefaultWorkDir + "/" + RunSubdir; filepath.Join(workDir, RunSubdir) != absRun {
		workDirDenyRoots = append(workDirDenyRoots, absRun)
	}
	// Pin EVERY work-dir root into the protected deny-set so a caller's extra
	// path can never reach a sibling pod, the reap store, or a control-plane
	// tree, then keep the fixed system subtrees.
	protectedPrefixes = append(append([]string{}, workDirDenyRoots...), systemProtectedPrefixes...)
	return podsRoot, workDirDenyRoots, protectedPrefixes, nil
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

// strictlyUnder reports whether path is a PROPER DESCENDANT of prefix — the same
// test as isUnder MINUS the equality case. A relative path never satisfies it
// against an absolute prefix, which is what makes it reject a relative data
// volume.
//
// Unlike isUnder it CLEANS ITS OWN OPERANDS rather than documenting the
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
// and rejecting the PODS ROOT ITSELF as a data volume, and re-allowing the pods
// root read+write after the protected denies would hand one pod every sibling
// pod's materialized secrets and projected SA-token.
//
// It is a third strict variant in this repo, alongside mount.IsStrictlyUnder and
// pkg/supervisor's local one, and that duplication is deliberate rather than
// laziness: pkg/sandbox must NOT import pkg/mount (the same layering rule that
// makes sandbox.VMVolumePlan plain data — see the mapper note in
// pkg/runtime/pod.go), and the supervisor variant is unexported and DELIBERATELY
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

// macOSFirmlinks are the synthetic APFS firmlinks the macOS boot volume presents:
// /var, /tmp, /etc resolve to /private/var, /private/tmp, /private/etc.
var macOSFirmlinks = []string{"/var", "/tmp", "/etc"}

// firmlinkForms returns the SBPL literal path form(s) a unix-socket deny must cover
// so it holds regardless of which alias a pod connect()s through. libsandbox matches
// a connect() target against the SYMLINK-RESOLVED path, so a deny filter written
// against a macOS firmlink (e.g. /var/lib/k3sm/run/netd.sock) FAILS OPEN — the pod's
// resolved target is /private/var/…, which the /var literal never matches (verified
// on macOS 26). This returns the cleaned path PLUS, when it sits under a firmlink,
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

// writeFirmlinkSubpaths writes a `(subpath …)` line for EVERY firmlink form of each
// path (firmlinkForms). libsandbox matches a file path against its SYMLINK-RESOLVED
// form, so a rule written only against the /var,/tmp,/etc firmlink silently
// misfires — an ALLOW fails closed (the pod cannot read its own rebased volume
// under /var/lib/k3sm/pods/…, which resolves to /private/var/…), a DENY fails OPEN.
// Emitting both forms makes the rule hold regardless of which alias is addressed.
func writeFirmlinkSubpaths(b *strings.Builder, paths []string) {
	for _, p := range paths {
		for _, form := range firmlinkForms(p) {
			b.WriteString(fmt.Sprintf("  (subpath %q)\n", form))
		}
	}
}

// Validate checks that a rendered SBPL profile is fail-closed: it MUST contain
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
