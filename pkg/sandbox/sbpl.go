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
// volume). resolvePosture appends the work-dir-derived pods-root (sibling pods)
// AND the daemon-private podreap store (<WorkDir>/podreap) to this set.
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

// ErrNoDataVolume reports a SandboxProfile with no data_volume_path: there is
// nowhere the pod may write, so the profile cannot be generated.
var ErrNoDataVolume = errors.New("sbpl: sandbox profile has no data_volume_path")

// ErrProtectedPath reports a caller-supplied extra read/write path that resolves
// at or under a protected prefix (see systemProtectedPrefixes + the pods-root).
// Such a path is rejected rather than emitted, so a hostPath-style mount can
// never widen the allow-list into /Users, the secrets store, a sibling pod's
// dir, or the dyld cryptex.
var ErrProtectedPath = errors.New("sbpl: extra path is under a protected deny-set")

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
// /private/var/db, the pods root, the podreap store, the dyld cryptex) so a
// caller's extra path can never override them; THEN the narrow re-allows the
// protected denies would
// otherwise clobber (the dyld closure-cache read and this pod's own data volume,
// which lives under the denied pods root); and LAST the read-only credential
// sub-scope, whose file-write* deny therefore wins even inside the writable data
// volume.
//
// Generate returns ErrNoDataVolume if sp has no data volume, ErrProtectedPath if
// any extra/credential path is under the protected deny-set, and the work-dir
// errors above for a bad Posture; otherwise the rendered profile is always
// well-formed and passes Validate.
func Generate(sp *runtimev1.SandboxProfile, opts GenerateOptions) (string, error) {
	if sp == nil {
		return "", ErrNoDataVolume
	}
	dataVol := filepath.Clean(sp.GetDataVolumePath())
	if dataVol == "" || dataVol == "." || dataVol == "/" {
		return "", ErrNoDataVolume
	}

	// Derive the node-level deny-set from the configured work-dir, rejecting a
	// malformed or home-escaping work-dir BEFORE emitting anything (fail closed).
	workDirDenyRoots, protectedPrefixes, err := resolvePosture(opts.Posture)
	if err != nil {
		return "", err
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
	b.WriteString(";; PROTECTED: deny user homes, the secrets/state store, the\n")
	b.WriteString(";; shared pods root AND the daemon-private podreap store (sibling\n")
	b.WriteString(";; dirs under the work-dir) — read+write, AFTER the allows so a\n")
	b.WriteString(";; caller's extra path (even an ancestor work-dir grant) can't win.\n")
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

// resolvePosture validates p.WorkDir and returns the work-dir-derived denied
// roots (the pods-root AND the daemon-private podreap store, both read+write
// denied with firmlink forms by Generate) and the ordered protected-prefix
// deny-set (those two roots plus the fixed system subtrees). An empty WorkDir
// falls back to DefaultWorkDir; a non-empty WorkDir must be absolute and clean
// (ErrInvalidWorkDir) and — when p.Home is set — must reside under Home
// (ErrWorkDirEscapesHome). The Posture VIP fields are NOT consumed here: since
// M10.1 they render no SBPL (see the AllowNetwork stanza in Generate) and exist
// only for the DNS env/status plumbing.
func resolvePosture(p Posture) (workDirDenyRoots []string, protectedPrefixes []string, err error) {
	workDir := p.WorkDir
	if workDir == "" {
		workDir = DefaultWorkDir
	} else {
		if !filepath.IsAbs(workDir) {
			return nil, nil, fmt.Errorf("%w: %q is not absolute", ErrInvalidWorkDir, workDir)
		}
		if workDir == "/" {
			return nil, nil, fmt.Errorf("%w: %q is the filesystem root", ErrInvalidWorkDir, workDir)
		}
		if filepath.Clean(workDir) != workDir {
			return nil, nil, fmt.Errorf("%w: %q is not a clean path", ErrInvalidWorkDir, workDir)
		}
	}
	if p.Home != "" {
		home := filepath.Clean(p.Home)
		if !isUnder(workDir, home) {
			return nil, nil, fmt.Errorf("%w: %q is not under %q", ErrWorkDirEscapesHome, workDir, home)
		}
	}
	podsRoot := filepath.Join(workDir, "pods")
	// The daemon-private startup-reap store: records here drive a root-privileged
	// kill(-pgid), so a confined pod must never be able to write (or read) them.
	// Single-sourced with pkg/runtime via PodReapSubdir.
	podReapRoot := filepath.Join(workDir, PodReapSubdir)
	workDirDenyRoots = []string{podsRoot, podReapRoot}
	// Pin BOTH work-dir roots into the protected deny-set so a caller's extra
	// path can never reach a sibling pod or the reap store, then keep the fixed
	// system subtrees.
	protectedPrefixes = append(append([]string{}, workDirDenyRoots...), systemProtectedPrefixes...)
	return workDirDenyRoots, protectedPrefixes, nil
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
					return fmt.Errorf("%w: %q is under protected %q", ErrProtectedPath, raw, pre)
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
