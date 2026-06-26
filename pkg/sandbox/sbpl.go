package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// podsRoot is the parent of every per-pod rootfs (rootfs_path is
// podsRoot/<id>/rootfs). The generator denies read+write to it broadly so one
// pod cannot reach another pod's dir, then re-allows only this pod's own subpath.
const podsRoot = "/var/lib/k3sm/pods"

// resolverVIP is the CoreDNS Service VIP the pod's resolver path dials. M1 is
// single-node and the cluster DNS Service is a lo0 alias; allow-network scopes
// outbound to this address (and the mach-lookup the resolver needs) rather than
// opening all egress. Overridable per-pod is an M2 concern.
const resolverVIP = "10.96.0.10"

// protectedPrefixes are the host subtrees a pod may NEVER be granted via a
// caller-supplied extra path: user homes, the system secrets/state store, the
// shared pods root (sibling pods), and the dyld cryptex (the system read-only
// content volume). validateExtraPaths rejects any extra read/write path at or
// under one of these (the pod's OWN data volume is carved out), and Generate
// emits a matching (deny ...) for each AFTER the extra-path allows so an
// unvalidated path cannot override the deny (SBPL is last-match-wins).
var protectedPrefixes = []string{
	"/Users",
	"/private/var/db",
	podsRoot,
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
// at or under a protected prefix (see protectedPrefixes). Such a path is rejected
// rather than emitted, so a hostPath-style mount can never widen the allow-list
// into /Users, the secrets store, a sibling pod's dir, or the dyld cryptex.
var ErrProtectedPath = errors.New("sbpl: extra path is under a protected deny-set")

// GenerateOptions carries the runtimed-internal SBPL inputs that are NOT part of
// the cross-repo SandboxProfile proto. They are computed during pod setup (by the
// volume materializer in pkg/mount and the persistent-volume binder in pkg/volume),
// not supplied by the provider over the wire.
type GenerateOptions struct {
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
// outbound to the cluster DNS VIP.
//
// Rule ORDER is security-critical because SBPL is last-match-wins. Generate emits
// (in increasing precedence): the OS/extra-path allows; THEN the protected denies
// (/Users, /private/var/db, the pods root, the dyld cryptex) so a caller's extra
// path can never override them; THEN the narrow re-allows the protected denies
// would otherwise clobber (the dyld closure-cache read and this pod's own data
// volume, which lives under the denied pods root); and LAST the read-only
// credential sub-scope, whose file-write* deny therefore wins even inside the
// writable data volume.
//
// Generate returns ErrNoDataVolume if sp has no data volume and ErrProtectedPath
// if any extra/credential path is under the protected deny-set; otherwise the
// rendered profile is always well-formed and passes Validate.
func Generate(sp *runtimev1.SandboxProfile, opts GenerateOptions) (string, error) {
	if sp == nil {
		return "", ErrNoDataVolume
	}
	dataVol := filepath.Clean(sp.GetDataVolumePath())
	if dataVol == "" || dataVol == "." || dataVol == "/" {
		return "", ErrNoDataVolume
	}

	// Validate every caller-supplied path BEFORE emitting any allow: a path under
	// the protected deny-set is rejected outright (fail closed). The pod's own
	// data volume is carved out (it is re-allowed by design below).
	if err := validateExtraPaths(dataVol, sp.GetExtraReadPaths(), sp.GetExtraWritePaths(), opts.ReadOnlyPaths, opts.WritePaths, opts.ReadPaths); err != nil {
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
		b.WriteString(";; mach-lookup the DNS resolver path (mDNSResponder) needs.\n")
		b.WriteString("(allow mach-lookup\n")
		b.WriteString("  (global-name \"com.apple.dnssd.service\")\n")
		b.WriteString("  (global-name \"com.apple.mDNSResponder\"))\n")
	} else {
		b.WriteString(";; network: default-deny (no allow-network).\n")
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

// validateExtraPaths rejects any path in groups that is at or under a protected
// prefix, returning ErrProtectedPath. The pod's own data volume (dataVol) is
// always permitted (it is re-allowed by Generate). Non-absolute paths and "/" are
// rejected — a relative or whole-filesystem grant is never intended.
func validateExtraPaths(dataVol string, groups ...[]string) error {
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
