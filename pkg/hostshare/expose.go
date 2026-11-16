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

package hostshare

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// exposeKeyword starts an exposure grant line in the node's file.
const exposeKeyword = "expose"

// ExposeSubdir is the directory under the node's data root that holds every
// exposure: <data root>/expose/<namespace>/<pod>/<volume>.
const ExposeSubdir = "expose"

const (
	maxExposeGrants    = 64
	maxGrantNamespaces = 32
	accessRead         = "read"
	accessReadWrite    = "read-write"
	maxExposureVolumes = 16
	maxDNSSubdomain    = 253
)

// dnsLabel is an RFC 1123 label: what Kubernetes allows for a namespace and a
// volume name.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ErrNotExposed reports an exposure volume the node does not admit.
var ErrNotExposed = errors.New("hostshare: exposure is not admitted")

// ExposeGrant lets pods in the named namespaces publish a volume to one host
// account. Root records it once (`sudo k3sm expose allow`); the node admits
// an exposure volume only while a grant names the volume's account by both
// uid and current name, names the pod's namespace, and allows the access the
// volume asks for. It is the exposure half of the delegation model: a scoped
// grant root writes once, re-checked at every create.
type ExposeGrant struct {
	// UID is the account that receives exposures.
	UID uint32
	// User is the account's name when root granted it. A create also requires
	// the uid's current name to equal it, so a renamed or recycled uid
	// inherits nothing.
	User string
	// Namespaces are the namespaces whose pods may expose to the account.
	Namespaces []string
	// ReadWrite allows read-write exposures; otherwise only read.
	ReadWrite bool
}

// String renders g as its line in the node's file.
func (g ExposeGrant) String() string {
	access := accessRead
	if g.ReadWrite {
		access = accessReadWrite
	}
	return fmt.Sprintf("%s uid=%d user=%s namespaces=%s access=%s", exposeKeyword, g.UID, g.User, strings.Join(g.Namespaces, ","), access)
}

// Admits reports whether g lets pods in namespace ns expose to its account.
func (g ExposeGrant) Admits(ns string) bool { return slices.Contains(g.Namespaces, ns) }

// ValidateExposeGrant checks g's shape: a user account uid, a plain account
// name, and one to maxGrantNamespaces distinct namespace names.
func ValidateExposeGrant(g ExposeGrant) error {
	if g.UID < MinDelegateUID || g.UID > 1<<31-1 {
		return fmt.Errorf("%w: exposure grant to uid %d: only a user account (uid %d or above) may receive exposures", ErrInvalidEntry, g.UID, MinDelegateUID)
	}
	if !userName.MatchString(g.User) {
		return fmt.Errorf("%w: exposure grant user name %q is not a plain account name", ErrInvalidEntry, g.User)
	}
	if len(g.Namespaces) == 0 || len(g.Namespaces) > maxGrantNamespaces {
		return fmt.Errorf("%w: exposure grant to %s names %d namespaces (want 1 to %d)", ErrInvalidEntry, g.User, len(g.Namespaces), maxGrantNamespaces)
	}
	seen := map[string]bool{}
	for _, ns := range g.Namespaces {
		if !dnsLabel.MatchString(ns) {
			return fmt.Errorf("%w: exposure grant namespace %q is not a namespace name", ErrInvalidEntry, ns)
		}
		if seen[ns] {
			return fmt.Errorf("%w: exposure grant namespace %q is repeated", ErrInvalidEntry, ns)
		}
		seen[ns] = true
	}
	return nil
}

// ParseNamespaces reads a comma-separated namespace list, keeping order and
// dropping repeats. Each name is checked by ValidateExposeGrant.
func ParseNamespaces(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// ParseAccess reads an access word: "read" or "read-write".
func ParseAccess(s string) (readWrite bool, err error) {
	switch s {
	case accessRead:
		return false, nil
	case accessReadWrite:
		return true, nil
	}
	return false, fmt.Errorf("%w: access %q is not read or read-write", ErrInvalidEntry, s)
}

func parseExposeGrant(fields []string) (ExposeGrant, error) {
	if len(fields) != 5 {
		return ExposeGrant{}, fmt.Errorf("%w: want \"expose uid=<n> user=<name> namespaces=<ns,...> access=read|read-write\"", ErrInvalidEntry)
	}
	kv := func(f, key string) (string, error) {
		v, ok := strings.CutPrefix(f, key+"=")
		if !ok {
			return "", fmt.Errorf("%w: exposure grant field %q: want %s=", ErrInvalidEntry, f, key)
		}
		return v, nil
	}
	us, err := kv(fields[1], "uid")
	if err != nil {
		return ExposeGrant{}, err
	}
	uid, err := strconv.ParseUint(us, 10, 32)
	if err != nil {
		return ExposeGrant{}, fmt.Errorf("%w: exposure grant uid %q", ErrInvalidEntry, us)
	}
	user, err := kv(fields[2], "user")
	if err != nil {
		return ExposeGrant{}, err
	}
	nss, err := kv(fields[3], "namespaces")
	if err != nil {
		return ExposeGrant{}, err
	}
	as, err := kv(fields[4], "access")
	if err != nil {
		return ExposeGrant{}, err
	}
	rw, err := ParseAccess(as)
	if err != nil {
		return ExposeGrant{}, err
	}
	g := ExposeGrant{UID: uint32(uid), User: user, Namespaces: ParseNamespaces(nss), ReadWrite: rw}
	return g, ValidateExposeGrant(g)
}

// ExposeRoot is <dataRoot>/expose.
func ExposeRoot(dataRoot string) string { return filepath.Join(dataRoot, ExposeSubdir) }

// ExposeDir is the node directory of one exposure volume:
// <dataRoot>/expose/<namespace>/<pod>/<volume>. Each component is checked
// here, by the runtime itself, never trusted from the caller: a namespace and
// a volume must be RFC 1123 labels and a pod name an RFC 1123 subdomain, so
// none can be empty, ".", "..", or hold a "/".
func ExposeDir(dataRoot, namespace, pod, volume string) (string, error) {
	if !filepath.IsAbs(dataRoot) || filepath.Clean(dataRoot) != dataRoot {
		return "", fmt.Errorf("%w: data root %q is not absolute and clean", ErrNotExposed, dataRoot)
	}
	if !dnsLabel.MatchString(namespace) {
		return "", fmt.Errorf("%w: namespace %q is not a namespace name", ErrNotExposed, namespace)
	}
	if !validPodName(pod) {
		return "", fmt.Errorf("%w: pod name %q is not a pod name", ErrNotExposed, pod)
	}
	if !dnsLabel.MatchString(volume) {
		return "", fmt.Errorf("%w: volume name %q is not a volume name", ErrNotExposed, volume)
	}
	return filepath.Join(ExposeRoot(dataRoot), namespace, pod, volume), nil
}

// validPodName is an RFC 1123 subdomain: dot-separated labels, 253 bytes at
// most.
func validPodName(s string) bool {
	if s == "" || len(s) > maxDNSSubdomain {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// Exposure is one admitted exposure volume of a pod.
type Exposure struct {
	// Volume is the pod's volume name.
	Volume string
	// Dir is the node directory that holds the volume (ExposeDir).
	Dir string
	// UID and User are the receiving account.
	UID  uint32
	User string
	// ReadWrite is the access the account gets.
	ReadWrite bool
}

// AccountName returns the current account name of a uid on the node.
type AccountName func(uid uint32) (string, error)

// AuthorizeExposures decides every exposure volume a container of box mounts,
// against the node's grants. For each one it requires:
//   - the pod's namespace and name, and the volume name, pass ExposeDir;
//   - every mount of it has no subPath and is not readOnly (the pod writes it);
//   - the volume's uid currently has the name the volume asks for (name), and
//     a grant names that same uid and name and the pod's namespace;
//   - the grant allows read-write when the volume asks for it.
//
// A volume no container mounts is not an exposure and is ignored. Any refusal
// fails the whole pod (ErrNotExposed), before any container starts.
func AuthorizeExposures(grants []ExposeGrant, box *runtimev1.PodBox, dataRoot string, name AccountName) ([]Exposure, error) {
	mounted := map[string]bool{}
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				v := findVolume(box, m.GetName())
				if v == nil || v.GetExpose() == nil {
					continue
				}
				if m.GetSubPath() != "" {
					return nil, notExposed(v.GetName(), "an exposure cannot be mounted with a subPath")
				}
				if m.GetReadOnly() {
					return nil, notExposed(v.GetName(), "an exposure is written by the pod; do not mount it readOnly")
				}
				mounted[v.GetName()] = true
			}
		}
	}
	var out []Exposure
	for _, v := range box.GetVolumes() {
		x := v.GetExpose()
		if x == nil || !mounted[v.GetName()] {
			continue
		}
		if len(out) == maxExposureVolumes {
			return nil, notExposed(v.GetName(), fmt.Sprintf("a pod may have at most %d exposures", maxExposureVolumes))
		}
		dir, err := ExposeDir(dataRoot, box.GetNamespace(), box.GetName(), v.GetName())
		if err != nil {
			return nil, notExposed(v.GetName(), err.Error())
		}
		if x.GetUid() < MinDelegateUID || !userName.MatchString(x.GetUser()) {
			return nil, notExposed(v.GetName(), fmt.Sprintf("account %q (uid %d) is not a user account", x.GetUser(), x.GetUid()))
		}
		cur, err := name(x.GetUid())
		if err != nil || cur != x.GetUser() {
			return nil, notExposed(v.GetName(), fmt.Sprintf("uid %d is not the account %q on this node", x.GetUid(), x.GetUser()))
		}
		g, ok := findGrant(grants, x.GetUid(), x.GetUser(), box.GetNamespace())
		if !ok {
			return nil, notExposed(v.GetName(), fmt.Sprintf("no exposure grant lets namespace %s expose to %s; the node admin adds one with `sudo k3sm expose allow --user %s --namespace %s`", box.GetNamespace(), x.GetUser(), x.GetUser(), box.GetNamespace()))
		}
		if x.GetReadWrite() && !g.ReadWrite {
			return nil, notExposed(v.GetName(), fmt.Sprintf("the grant to %s allows read only; ask for access: read, or the node admin allows read-write", x.GetUser()))
		}
		out = append(out, Exposure{Volume: v.GetName(), Dir: dir, UID: x.GetUid(), User: x.GetUser(), ReadWrite: x.GetReadWrite()})
	}
	return out, nil
}

// findGrant returns the grant that names uid, user and namespace ns. Among
// several, a read-write one wins.
func findGrant(grants []ExposeGrant, uid uint32, user, ns string) (ExposeGrant, bool) {
	var found ExposeGrant
	ok := false
	for _, g := range grants {
		if ValidateExposeGrant(g) != nil || g.UID != uid || g.User != user || !g.Admits(ns) {
			continue
		}
		if !ok || g.ReadWrite {
			found, ok = g, true
		}
	}
	return found, ok
}

func notExposed(volume, why string) error {
	return fmt.Errorf("%w: volume %q: %s", ErrNotExposed, volume, why)
}
