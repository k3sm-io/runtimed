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

// Generate renders a default-deny SBPL profile for one pod from sp.
//
// The output ALWAYS begins (version 1) / (deny default) / (import "system.sb"),
// then grants the minimal allow-list: read the OS (/System, /usr, /bin,
// /Library, the dyld cache), read+write the pod's own data volume, and — when
// sp.AllowNetwork is set — outbound to the cluster DNS VIP plus the mach-lookup
// the resolver path needs. It TIGHTENS the validated prototype by denying
// /private/var/db (keeping only the dyld-cache read exception) and denying the
// shared pods root so sibling pod dirs are unreachable.
//
// Generate returns an error only on invalid input (no data volume); the rendered
// profile is otherwise always well-formed and passes Validate.
func Generate(sp *runtimev1.SandboxProfile) (string, error) {
	if sp == nil {
		return "", ErrNoDataVolume
	}
	dataVol := filepath.Clean(sp.GetDataVolumePath())
	if dataVol == "" || dataVol == "." || dataVol == "/" {
		return "", ErrNoDataVolume
	}

	readPaths := dedupeSorted(append([]string{
		"/System",
		"/usr",
		"/bin",
		"/Library",
	}, sp.GetExtraReadPaths()...))
	writePaths := dedupeSorted(append([]string{dataVol}, sp.GetExtraWritePaths()...))

	var b strings.Builder
	b.WriteString(";; k3sm per-pod Seatbelt profile — GENERATED, do not edit.\n")
	b.WriteString(";; Default-deny; runs a native pod process at host paths (no chroot).\n")
	b.WriteString(";; Tightens prototypes/seatbelt-hostpath/pod.sb: denies /private/var/db\n")
	b.WriteString(";; (dyld-cache read excepted) and the shared pods root (sibling pods).\n")
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	// system.sb supplies the dyld shared-cache mapping + mach bootstrap baseline.
	// CRITICAL: without it the process aborts (SIGABRT) during dynamic-linker init.
	b.WriteString("(import \"system.sb\")\n")

	b.WriteString("(allow process-exec*)\n")
	b.WriteString("(allow process-fork)\n")

	// Explicit deny of the secrets/state store. system.sb grants some db reads
	// back; the documented dyld-cache exception below is the only db read this
	// profile intends to permit. (deny ...) here makes the intent auditable and
	// overrides any broad db allow the baseline might carry.
	b.WriteString(";; tighten: deny the system secrets/state store outright ...\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString("  (subpath \"/private/var/db\"))\n")
	// ... except the dyld closure cache, which the dynamic linker reads at init.
	b.WriteString(";; ... except the dyld closure cache the linker reads at init.\n")
	b.WriteString("(allow file-read*\n")
	b.WriteString("  (subpath \"/private/var/db/dyld\"))\n")

	// Deny the whole pods root so a pod cannot read or write a sibling pod's
	// dir; the pod's own data volume is re-allowed by the write/read blocks below.
	b.WriteString(";; tighten: deny the shared pods root (other pods' dirs) ...\n")
	b.WriteString("(deny file-read* file-write*\n")
	b.WriteString(fmt.Sprintf("  (subpath %q))\n", podsRoot))

	b.WriteString(";; read: OS + frameworks + dyld cache + this pod's dir.\n")
	b.WriteString("(allow file-read*\n")
	for _, p := range readPaths {
		b.WriteString(fmt.Sprintf("  (subpath %q)\n", filepath.Clean(p)))
	}
	b.WriteString("  (subpath \"/private/var/db/dyld\")\n")
	b.WriteString("  (literal \"/dev/null\") (literal \"/dev/zero\")\n")
	b.WriteString("  (literal \"/dev/random\") (literal \"/dev/urandom\")\n")
	b.WriteString(fmt.Sprintf("  (subpath %q))\n", dataVol))

	b.WriteString(";; write: ONLY this pod's data volume (+ /dev/null).\n")
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

	return b.String(), nil
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
