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

// DefaultResolverVIP is the cluster DNS Service VIP egress is scoped to when a
// Posture leaves ResolverVIP empty. M1 is single-node and the cluster DNS
// Service is a lo0 alias; allow-network scopes outbound to this address (and the
// mach-lookup the resolver needs) rather than opening all egress. Overridable
// per-node via Posture; broader per-Service egress is an M2 concern.
const DefaultResolverVIP = "10.96.0.10"

// systemProtectedPrefixes are the FIXED host subtrees a pod may NEVER be granted
// via a caller-supplied extra path, independent of the work-dir: user homes, the
// system secrets/state store, and the dyld cryptex (the system read-only content
// volume). resolvePosture appends the work-dir-derived pods-root (sibling pods)
// to this set. validateExtraPaths rejects any extra read/write path at or under
// one of these (the pod's OWN data volume is carved out), and Generate emits a
// matching (deny ...) for each AFTER the extra-path allows so an unvalidated path
// cannot override the deny (SBPL is last-match-wins).
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
// cluster DNS resolver VIP and in-cluster API-server VIP egress is scoped to.
// Unlike the per-pod GenerateOptions it is the same for every pod on a node, so
// the caller builds it once from the runtime Config and passes it on each
// Generate. The zero value is usable: an empty WorkDir falls back to
// DefaultWorkDir and an empty ResolverVIP to DefaultResolverVIP (the legacy
// root-daemon defaults); an empty APIServerVIP emits no API-server egress rule.
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
	// ResolverVIP is the cluster DNS Service VIP outbound is scoped to when a pod
	// sets allow_network. Empty defaults to DefaultResolverVIP.
	ResolverVIP string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the `kubernetes`
	// ClusterIP, e.g. 10.43.0.1) outbound is ADDITIONALLY scoped to when a pod
	// sets allow_network, so an in-pod client-go rest.InClusterConfig() can reach
	// the API server through the datapath VIP. Unlike ResolverVIP it has NO
	// default: empty emits no API-server egress rule, so a zero Posture renders an
	// unchanged profile. The caller (k3sm) sets it from the cluster service CIDR.
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
	// PodIP, when non-empty and sp.AllowNetwork is set, scopes the pod's
	// network-bind allow to (local ip <PodIP>) so a pod cannot bind() a neighbor
	// pod's /32 alias on the shared lo0 loopback. It is the pod IP the network
	// setup assigned; empty leaves bind default-denied. Not in the proto: it is
	// computed during pod setup, not supplied by the provider.
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
// outbound to the cluster DNS VIP (and, when opts.Posture.APIServerVIP is set,
// the in-cluster API-server VIP; plus, when opts.PodIP is known, a network-bind
// scoped to that IP).
//
// The pods-root, the protected-prefix deny-set, and the resolver VIP are derived
// from opts.Posture (the node-level work-dir), so a user-space daemon whose
// work-dir lives under its home pins every per-pod path under that work-dir
// rather than the legacy /var/lib/k3sm. A work-dir that is malformed or escapes
// the configured home is rejected (ErrInvalidWorkDir / ErrWorkDirEscapesHome).
//
// Because the unprivileged posture runs pods at the same uid as the runtime
// client (no per-pod uid isolation), the Seatbelt default-deny is the ONLY
// barrier keeping a pod off the privileged k3sm-netd helper socket: for each
// sp.DeniedUnixSocketPaths entry Generate emits an explicit
// (deny network-outbound (remote unix-socket (path-equal …))) on top of the
// default-deny, AFTER the network allow so last-match-wins keeps it denied.
//
// Rule ORDER is security-critical because SBPL is last-match-wins. Generate emits
// (in increasing precedence): the OS/extra-path allows + the network allows; THEN
// the AF_UNIX helper-socket denies and the protected file denies (/Users,
// /private/var/db, the pods root, the dyld cryptex) so a caller's extra path can
// never override them; THEN the narrow re-allows the protected denies would
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
	podsRoot, protectedPrefixes, resolverVIP, apiServerVIP, err := resolvePosture(opts.Posture)
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
	for _, p := range readPaths {
		b.WriteString(fmt.Sprintf("  (subpath %q)\n", filepath.Clean(p)))
	}
	b.WriteString("  (literal \"/dev/null\") (literal \"/dev/zero\")\n")
	b.WriteString("  (literal \"/dev/random\") (literal \"/dev/urandom\"))\n")

	b.WriteString(";; write: validated extra write paths (+ /dev/null); the pod's own\n")
	b.WriteString(";; data volume is re-allowed below, after the protected denies.\n")
	b.WriteString("(allow file-write*\n")
	for _, p := range writePaths {
		b.WriteString(fmt.Sprintf("  (subpath %q)\n", filepath.Clean(p)))
	}
	b.WriteString("  (literal \"/dev/null\"))\n")

	if sp.GetAllowNetwork() {
		// Scope egress to the cluster DNS resolver VIP + the system DNS resolver
		// the libresolv path consults via mach. This is the minimum a pod needs
		// to resolve Service names; broader egress is an explicit M2 opt-in.
		b.WriteString(";; network: outbound to the cluster DNS resolver VIP only.\n")
		b.WriteString("(allow network-outbound\n")
		b.WriteString(fmt.Sprintf("  (remote ip %q)\n", fmt.Sprintf("%s:53", resolverVIP)))
		b.WriteString(fmt.Sprintf("  (remote ip %q))\n", fmt.Sprintf("%s:0", resolverVIP)))
		if apiServerVIP != "" {
			// Additionally scope egress to the in-cluster API-server VIP (the
			// kubernetes ClusterIP) so an in-pod client-go rest.InClusterConfig()
			// reaches the API server through the datapath VIP. Paired :443/:0 mirrors
			// the DNS-VIP idiom above; emitted ONLY when the node sets APIServerVIP.
			b.WriteString(";; network: outbound to the in-cluster API-server VIP.\n")
			b.WriteString("(allow network-outbound\n")
			b.WriteString(fmt.Sprintf("  (remote ip %q)\n", fmt.Sprintf("%s:443", apiServerVIP)))
			b.WriteString(fmt.Sprintf("  (remote ip %q))\n", fmt.Sprintf("%s:0", apiServerVIP)))
		}
		b.WriteString(";; mach-lookup the DNS resolver path (mDNSResponder) needs.\n")
		b.WriteString("(allow mach-lookup\n")
		b.WriteString("  (global-name \"com.apple.dnssd.service\")\n")
		b.WriteString("  (global-name \"com.apple.mDNSResponder\"))\n")
		if opts.PodIP != "" {
			// network-bind: scope to the pod's OWN lo0 IP so it cannot bind() a
			// neighbor pod's /32 alias on the shared loopback (pods share lo0).
			b.WriteString(";; network-bind: scope to the pod's own lo0 IP (pods share lo0).\n")
			b.WriteString("(allow network-bind\n")
			b.WriteString(fmt.Sprintf("  (local ip %q))\n", fmt.Sprintf("%s:*", opts.PodIP)))
		}
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
			b.WriteString(fmt.Sprintf("  (remote unix-socket (path-equal %q))\n", filepath.Clean(p)))
		}
		b.WriteString("  )\n")
	}

	// --- protected denies (higher precedence than the extra-path allows) --
	// Emitted AFTER the allows so a caller's extra path can never override them.
	b.WriteString(";; PROTECTED: deny user homes, the secrets/state store, and the\n")
	b.WriteString(";; shared pods root (sibling pods) — read+write, AFTER the allows.\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/Users\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/private/var/db\"))\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString(fmt.Sprintf("  (subpath %q))\n", podsRoot))
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
	b.WriteString(fmt.Sprintf("  (subpath %q))\n", dataVol))

	// --- credential read-only sub-scope (highest precedence) --------------
	// LAST, so this file-write* deny wins even though the credential lives inside
	// the writable data volume just re-allowed above: a pod can READ its mounted
	// secret / SA-token but cannot OVERWRITE it.
	if len(credPaths) > 0 {
		b.WriteString(";; credentials (secrets / SA-token): read-only sub-scope, emitted\n")
		b.WriteString(";; LAST so the write-deny wins inside the writable data volume.\n")
		b.WriteString("(allow file-read*\n")
		for _, p := range credPaths {
			b.WriteString(fmt.Sprintf("  (subpath %q)\n", filepath.Clean(p)))
		}
		b.WriteString("  )\n")
		b.WriteString("(deny file-write*\n")
		for _, p := range credPaths {
			b.WriteString(fmt.Sprintf("  (subpath %q)\n", filepath.Clean(p)))
		}
		b.WriteString("  )\n")
	}

	return b.String(), nil
}

// resolvePosture validates p.WorkDir and returns the derived pods-root, the
// ordered protected-prefix deny-set (the fixed system subtrees plus the
// pods-root), the resolver VIP, and the API-server VIP. An empty WorkDir falls
// back to DefaultWorkDir; a non-empty WorkDir must be absolute and clean
// (ErrInvalidWorkDir) and — when p.Home is set — must reside under Home
// (ErrWorkDirEscapesHome). An empty ResolverVIP falls back to DefaultResolverVIP;
// an empty APIServerVIP is returned as-is (no default — no rule is emitted).
func resolvePosture(p Posture) (podsRoot string, protectedPrefixes []string, resolverVIP, apiServerVIP string, err error) {
	workDir := p.WorkDir
	if workDir == "" {
		workDir = DefaultWorkDir
	} else {
		if !filepath.IsAbs(workDir) {
			return "", nil, "", "", fmt.Errorf("%w: %q is not absolute", ErrInvalidWorkDir, workDir)
		}
		if workDir == "/" {
			return "", nil, "", "", fmt.Errorf("%w: %q is the filesystem root", ErrInvalidWorkDir, workDir)
		}
		if filepath.Clean(workDir) != workDir {
			return "", nil, "", "", fmt.Errorf("%w: %q is not a clean path", ErrInvalidWorkDir, workDir)
		}
	}
	if p.Home != "" {
		home := filepath.Clean(p.Home)
		if !isUnder(workDir, home) {
			return "", nil, "", "", fmt.Errorf("%w: %q is not under %q", ErrWorkDirEscapesHome, workDir, home)
		}
	}
	podsRoot = filepath.Join(workDir, "pods")
	// Pin the pods-root into the protected deny-set so a caller's extra path can
	// never reach a sibling pod, then keep the fixed system subtrees.
	protectedPrefixes = append([]string{podsRoot}, systemProtectedPrefixes...)
	resolverVIP = p.ResolverVIP
	if resolverVIP == "" {
		resolverVIP = DefaultResolverVIP
	}
	// APIServerVIP has no default: empty means "emit no API-server egress rule"
	// (back-compatible — a zero Posture renders an unchanged profile).
	apiServerVIP = p.APIServerVIP
	return podsRoot, protectedPrefixes, resolverVIP, apiServerVIP, nil
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
