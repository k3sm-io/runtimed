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
	"regexp"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/keystorepaths"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// sbplNode is one parsed SBPL datum: an atom, a string, or a list.
type sbplNode struct {
	atom  string
	str   string
	isStr bool
	list  []sbplNode
	isLst bool
}

// String renders n back as SBPL, for failure messages.
func (n sbplNode) String() string {
	switch {
	case n.isStr:
		return fmt.Sprintf("%q", n.str)
	case n.isLst:
		parts := make([]string, len(n.list))
		for i, c := range n.list {
			parts[i] = c.String()
		}
		return "(" + strings.Join(parts, " ") + ")"
	}
	return n.atom
}

// parseSBPL reads every top-level datum of a rendered profile. It knows the
// subset Generate emits: ";" comments, lists, atoms, "..." strings and #"..."
// regex strings (whose body is kept raw).
func parseSBPL(t *testing.T, src string) []sbplNode {
	t.Helper()
	var stack [][]sbplNode
	var top []sbplNode
	push := func(n sbplNode) {
		if len(stack) == 0 {
			top = append(top, n)
			return
		}
		stack[len(stack)-1] = append(stack[len(stack)-1], n)
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ';':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\n' || c == '\t':
			i++
		case c == '(':
			stack = append(stack, nil)
			i++
		case c == ')':
			if len(stack) == 0 {
				t.Fatalf("unbalanced ) at %d", i)
			}
			l := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			push(sbplNode{list: l, isLst: true})
			i++
		case c == '"' || (c == '#' && i+1 < len(src) && src[i+1] == '"'):
			raw := c == '#'
			if raw {
				i++
			}
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' && !raw {
					i++
				}
				b.WriteByte(src[i])
				i++
			}
			i++
			push(sbplNode{str: b.String(), isStr: true})
		default:
			j := i
			for j < len(src) && !strings.ContainsRune(" \n\t()", rune(src[j])) {
				j++
			}
			push(sbplNode{atom: src[i:j]})
			i = j
		}
	}
	if len(stack) != 0 {
		t.Fatalf("unbalanced profile: %d open lists", len(stack))
	}
	return top
}

// sbplRule is one (allow ...) or (deny ...) directive.
type sbplRule struct {
	allow   bool
	ops     []string
	filters []sbplNode
	text    string
}

func sbplRules(t *testing.T, profile string) []sbplRule {
	t.Helper()
	var rules []sbplRule
	for _, n := range parseSBPL(t, profile) {
		if !n.isLst || len(n.list) == 0 || (n.list[0].atom != "allow" && n.list[0].atom != "deny") {
			continue
		}
		r := sbplRule{allow: n.list[0].atom == "allow", text: n.String()}
		for _, x := range n.list[1:] {
			if x.isLst {
				r.filters = append(r.filters, x)
			} else {
				r.ops = append(r.ops, x.atom)
			}
		}
		rules = append(rules, r)
	}
	return rules
}

// tri is a three-valued match: a filter kind this evaluator does not model is
// "maybe", and a maybe on the way to the verdict fails the test rather than
// guessing.
type tri int

const (
	no tri = iota
	yes
	maybe
)

// sbplQuery is one access: a file operation on a path, or a unix-socket
// connect (network-outbound) or bind (network-bind) at a path.
type sbplQuery struct {
	op     string
	path   string
	target string // for a process operation: self, children, pgrp or others
}

func (q sbplQuery) socket() bool { return strings.HasPrefix(q.op, "network-") }

func opMatches(ruleOp, op string) bool {
	if ruleOp == op || ruleOp == "default" {
		return true
	}
	return strings.HasSuffix(ruleOp, "*") && strings.HasPrefix(op, strings.TrimSuffix(ruleOp, "*"))
}

func pathFilter(t *testing.T, f sbplNode, p string) tri {
	t.Helper()
	if len(f.list) != 2 || !f.list[1].isStr {
		return maybe
	}
	arg := f.list[1].str
	switch f.list[0].atom {
	case "subpath":
		if isUnder(p, arg) {
			return yes
		}
		return no
	case "literal":
		if p == arg {
			return yes
		}
		return no
	case "prefix":
		if strings.HasPrefix(p, arg) {
			return yes
		}
		return no
	case "regex":
		re, err := regexp.Compile(arg)
		if err != nil {
			t.Fatalf("regex %q does not compile: %v", arg, err)
		}
		if re.MatchString(p) {
			return yes
		}
		return no
	}
	return maybe
}

func filterMatches(t *testing.T, f sbplNode, q sbplQuery) tri {
	t.Helper()
	if !f.isLst || len(f.list) == 0 {
		return maybe
	}
	head := f.list[0].atom
	switch head {
	case "require-all", "require-any":
		acc := yes
		if head == "require-any" {
			acc = no
		}
		for _, sub := range f.list[1:] {
			m := filterMatches(t, sub, q)
			switch {
			case head == "require-all" && m == no, head == "require-any" && m == yes:
				return m
			case m == maybe:
				acc = maybe
			}
		}
		return acc
	case "require-not":
		if len(f.list) != 2 {
			return maybe
		}
		switch filterMatches(t, f.list[1], q) {
		case yes:
			return no
		case no:
			return yes
		}
		return maybe
	case "target":
		if q.target == "" || len(f.list) != 2 {
			return no
		}
		switch f.list[1].atom {
		case q.target:
			return yes
		case "self", "children", "pgrp", "others":
			return no
		}
		return maybe
	case "remote", "local":
		if !q.socket() || len(f.list) != 3 {
			return no
		}
		if f.list[1].atom != "unix-socket" {
			return no
		}
		if (head == "remote") != (q.op == "network-outbound") {
			return no
		}
		return pathFilter(t, f.list[2], q.path)
	case "subpath", "literal", "prefix", "regex":
		if q.socket() || q.target != "" {
			return no
		}
		return pathFilter(t, f, q.path)
	}
	return maybe
}

// verdict evaluates q against rules, last match wins, and returns whether it
// is allowed and the deciding rule. A maybe met before a definite match fails.
func verdict(t *testing.T, rules []sbplRule, q sbplQuery) (bool, string) {
	t.Helper()
	for i := len(rules) - 1; i >= 0; i-- {
		r := rules[i]
		applies := false
		for _, op := range r.ops {
			applies = applies || opMatches(op, q.op)
		}
		if !applies {
			continue
		}
		m := yes
		if len(r.filters) > 0 {
			m = no
			for _, f := range r.filters {
				switch filterMatches(t, f, q) {
				case yes:
					m = yes
				case maybe:
					if m == no {
						m = maybe
					}
				}
				if m == yes {
					break
				}
			}
		}
		switch m {
		case yes:
			return r.allow, r.text
		case maybe:
			t.Fatalf("%s %s: rule %s has a filter this evaluator cannot decide", q.op, q.path, r.text)
		}
	}
	return false, "(deny default)"
}

// keystoreOps are the operation classes every keystore path is refused: reads
// (data, metadata, xattrs), the writes (data, create, unlink — a rename is an
// unlink and a create — mode, owner, flags, xattrs, times), a hard link
// (file-link, which file-write* does not cover), a unix-socket connect and a
// unix-socket bind.
var keystoreOps = []string{
	"file-read-data", "file-read-metadata", "file-read-xattr", "file-test-existence",
	"file-write-data", "file-write-create", "file-write-unlink", "file-write-mode",
	"file-write-owner", "file-write-flags", "file-write-xattr", "file-write-times",
	"file-link",
	"network-outbound", "network-bind",
}

// keystoreNames are the data-root-relative keystore paths, every class: the
// files the design names, a name a later change could add, a case variant, the
// run directory, its socket and a path deep inside it.
var keystoreNames = []string{
	"keystore-floor.json",
	"keystore-delivery.json",
	"keystore-user-floor.log",
	"keystore-user-floor.log.new",
	"keystore-audit.log",
	"keystore-audit.log.4",
	"keystore-audit.log.new",
	"keystore-maintenance",
	"keystore-later-addition",
	"KEYSTORE-Floor.json",
	"Keystore-floor.json",
	"keyſtore-run/keys.sock",
	"KEYſTORE-sock/x",
	"keystore-run",
	"keystore-run/keys.sock",
	"keystore-run/sub/deep",
	"keystore-sock",
	"keystore-sock/keys.sock",
	"keystore-sock/sub/deep",
}

// dataRootSpellings returns the spellings a pod can reach root through: as
// written, its /private form under a firmlink, and the data-volume alias.
func dataRootSpellings(root string) []string {
	forms := firmlinkForms(root)
	return append(forms, dataVolumeAlias+forms[len(forms)-1])
}

// TestDataRootDeniesKeystorePathsEveryProfile renders every pod profile variant
// and checks, over the whole rendered profile, that every keystore path class is
// refused for every operation class and through every spelling of the data root,
// whatever allows the variant carries (extra paths at the data root, volumes,
// credentials, exposures, views, host shares; an explicit keystore re-allow is
// refused outright, TestValidateRefusesKeystoreExtraPaths),
// and that a sibling of the data root that is not a keystore name stays
// reachable, so a refusal is the keystore denies and not the default.
func TestDataRootDeniesKeystorePathsEveryProfile(t *testing.T) {
	const (
		varRoot    = "/var/lib/k3sm"
		customPods = "/opt/k3sm-pods"
		optRoot    = "/opt/k3sm-data"
	)
	type variant struct {
		name    string
		root    string // the data root the keystore lives at
		sp      *runtimev1.SandboxProfile
		opts    GenerateOptions
		network bool
		// shimOnly checks the shim profile alone: an exec session runs under
		// the resident shim's profile, which it inherits.
		shimOnly bool
	}
	pod := func(workDir string) *runtimev1.SandboxProfile {
		return &runtimev1.SandboxProfile{
			DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs"),
			AllowNetwork:   true,
		}
	}
	withRootGrant := func(sp *runtimev1.SandboxProfile, root string) *runtimev1.SandboxProfile {
		sp.ExtraReadPaths = append(sp.ExtraReadPaths, root)
		sp.ExtraWritePaths = append(sp.ExtraWritePaths, root)
		return sp
	}
	withBackend := func(sp *runtimev1.SandboxProfile, b runtimev1.SandboxBackend) *runtimev1.SandboxProfile {
		sp.Backend = b
		return sp
	}
	native := func() *runtimev1.SandboxProfile { return withRootGrant(pod(varRoot), varRoot) }
	variants := []variant{
		{name: "native, default posture (data root is the work-dir)", root: varRoot, sp: native(), network: true},
		{name: "native, data root set to the work-dir", root: varRoot, sp: native(),
			opts: GenerateOptions{Posture: Posture{WorkDir: varRoot, DataRoot: varRoot}}, network: true},
		{name: "native, no network", root: varRoot, sp: func() *runtimev1.SandboxProfile {
			sp := native()
			sp.AllowNetwork = false
			return sp
		}()},
		{name: "native, /private spelling of the data root", root: "/private" + varRoot, sp: withRootGrant(pod(varRoot), "/private"+varRoot),
			opts: GenerateOptions{Posture: Posture{WorkDir: varRoot, DataRoot: "/private" + varRoot}}, network: true},
		{name: "custom pod root distinct from the data root", root: varRoot, sp: withRootGrant(pod(customPods), varRoot),
			opts: GenerateOptions{Posture: Posture{WorkDir: customPods, DataRoot: varRoot}}, network: true},
		{name: "custom pod root, data root off the firmlinks", root: optRoot, sp: withRootGrant(pod(customPods), optRoot),
			opts: GenerateOptions{Posture: Posture{WorkDir: customPods, DataRoot: optRoot}}, network: true},
		{name: "pod root under the data root", root: varRoot, sp: withRootGrant(pod(varRoot+"/node"), varRoot),
			opts: GenerateOptions{Posture: Posture{WorkDir: varRoot + "/node", DataRoot: varRoot}}, network: true},
		{name: "pod root a parent of the data root", root: varRoot, sp: withRootGrant(pod("/var/lib"), varRoot),
			opts: GenerateOptions{Posture: Posture{WorkDir: "/var/lib", DataRoot: varRoot}}, network: true},
		{name: "vm backend (rendered: the runtime never renders one, vm.go WrapCommand)", root: varRoot,
			sp: withBackend(native(), runtimev1.SandboxBackend_SANDBOX_BACKEND_VM), network: true},
		{name: "seatbelt in-process backend", root: varRoot,
			sp: withBackend(native(), runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC), network: true},
		{name: "uid-jail backend", root: varRoot,
			sp: withBackend(native(), runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL), network: true},
		{name: "xcode toolchain", root: varRoot, sp: func() *runtimev1.SandboxProfile {
			sp := native()
			sp.XcodeToolchainDir = xcodeDevDir
			return sp
		}(), network: true},
		{name: "gpu", root: varRoot, sp: func() *runtimev1.SandboxProfile {
			sp := native()
			sp.AllowGpu = true
			return sp
		}(), network: true},
		{name: "expose-paths", root: varRoot, sp: native(), opts: GenerateOptions{
			Posture:     Posture{WorkDir: varRoot, DataRoot: varRoot},
			ExposePaths: []string{filepath.Join(varRoot, ExposeSubdir, "ns", "pod", "vol")},
		}, network: true},
		{name: "expose-paths under a data root distinct from the pod root", root: varRoot, sp: withRootGrant(pod(customPods), varRoot), opts: GenerateOptions{
			Posture:     Posture{WorkDir: customPods, DataRoot: varRoot},
			ExposePaths: []string{filepath.Join(varRoot, ExposeSubdir, "ns", "pod", "vol")},
		}, network: true},
		{name: "volumes, credentials, views and host shares", root: varRoot, sp: native(), opts: GenerateOptions{
			Posture:           Posture{WorkDir: varRoot, DataRoot: varRoot},
			WritePaths:        []string{varRoot + "/storage/pvc-rw"},
			ReadPaths:         []string{varRoot + "/storage/pvc-ro"},
			ReadOnlyPaths:     []string{varRoot + "/pods/p1/rootfs/var/run/secrets"},
			ArtifactViewPaths: []string{viewPath(varRoot, viewManifestA)},
			HostShares:        []HostShare{{Path: "/Users/dev/Code/app"}, {Path: "/Users/dev/Code/app/q.sock", Socket: true}},
			PodUID:            "0123abcd-0000-0000-0000-000000000000",
		}, network: true},
		{name: "wasm pod (the k3sm-wasmhost helper: rootfs and volume preopens)", root: varRoot,
			sp: withBackend(native(), runtimev1.SandboxBackend_SANDBOX_BACKEND_WASM), opts: GenerateOptions{
				Posture:    Posture{WorkDir: varRoot, DataRoot: varRoot},
				WritePaths: []string{varRoot + "/storage/pvc-rw"},
				ReadPaths:  []string{varRoot + "/storage/pvc-ro"},
			}},
		{name: "exec session (inherits the resident shim's profile, ShimProfile)", root: varRoot, sp: native(),
			opts: GenerateOptions{Posture: Posture{WorkDir: varRoot, DataRoot: varRoot}}, network: true, shimOnly: true},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			pod, err := Generate(v.sp, v.opts)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			shim, err := ShimProfile(pod, ShimGrant{Dir: filepath.Join(ShimRoot(v.opts.Posture.WorkDir), "0a1b2c3d")})
			if err != nil {
				t.Fatalf("ShimProfile: %v", err)
			}
			profiles := map[string]string{"pod": pod, "shim": shim}
			if v.shimOnly {
				delete(profiles, "pod")
			}
			for which, prof := range profiles {
				t.Run(which, func(t *testing.T) { checkKeystoreVerdicts(t, prof, v.root, v.network) })
			}
		})
	}
}

// checkKeystoreVerdicts runs the keystore verdict loop over one rendered
// profile: every keystore path class refused for every operation class through
// every spelling of root, and a non-keystore sibling reachable.
func checkKeystoreVerdicts(t *testing.T, prof, root string, network bool) {
	t.Helper()
	rules := sbplRules(t, prof)
	for _, spelling := range dataRootSpellings(root) {
		paths := []string{keystorepaths.SocketPath(spelling)}
		for _, n := range keystoreNames {
			paths = append(paths, filepath.Join(spelling, n))
		}
		for _, p := range paths {
			for _, op := range keystoreOps {
				if ok, by := verdict(t, rules, sbplQuery{op: op, path: p}); ok {
					t.Errorf("%s %s is allowed, by %s", op, p, by)
				}
			}
		}
	}
	// The positive control: the variant's own grant at the data root
	// reaches a sibling that is not a keystore name.
	for _, spelling := range firmlinkForms(root) {
		for _, n := range []string{"keystore", "keystore.json", "not-keystore-x", "keystore_floor.json", "xeystore-run", "ke{store-x"} {
			p := filepath.Join(spelling, n)
			ops := []string{"file-read-data", "file-write-create"}
			if network {
				ops = append(ops, "network-outbound", "network-bind")
			}
			for _, op := range ops {
				if ok, by := verdict(t, rules, sbplQuery{op: op, path: p}); !ok {
					t.Errorf("control: %s %s is refused, by %s", op, p, by)
				}
			}
		}
	}
}

// TestShimProfileKeepsTheKeystoreDeniesLast pins that the shim profile, the
// second profile producer, ends with the pod profile's keystore denies after
// its own grant, and refuses a grant dir that names a keystore path.
func TestShimProfileKeepsTheKeystoreDeniesLast(t *testing.T) {
	const root = "/var/lib/k3sm"
	pod, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: root + "/pods/p1/rootfs"},
		GenerateOptions{Posture: Posture{WorkDir: root, DataRoot: root}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	shim, err := ShimProfile(pod, ShimGrant{Dir: root + "/run/shim/0a1b2c3d"})
	if err != nil {
		t.Fatalf("ShimProfile: %v", err)
	}
	stanza := keystoreDenyStanza(keystoreRoots(root, root, ""))
	if !strings.HasSuffix(shim, stanza) {
		t.Errorf("the shim profile does not end with the keystore denies:\n%s", shim[len(pod):])
	}
	if i := strings.LastIndex(shim, "(allow "); i > strings.LastIndex(shim, ";; KEYSTORE:") {
		t.Errorf("an allow follows the shim profile's keystore denies at %d", i)
	}
	for _, dir := range []string{
		root + "/keystore-run", root + "/keystore-sock", root + "/keystore-run/x", root + "/KEYSTORE-Run",
		"/private" + root + "/keystore-sock/x", dataVolumeAlias + "/private" + root + "/keystore-floor.json",
	} {
		if _, err := ShimProfile(pod, ShimGrant{Dir: dir}); !errors.Is(err, ErrInvalidShimGrant) {
			t.Errorf("grant dir %s: err = %v, want ErrInvalidShimGrant", dir, err)
		}
	}
	if _, err := ShimProfile(strings.TrimSuffix(pod, stanza), ShimGrant{Dir: root + "/run/shim/0a1b2c3d"}); !errors.Is(err, ErrInvalidShimGrant) {
		t.Errorf("a pod profile without the keystore denies: err = %v, want ErrInvalidShimGrant", err)
	}
	// A pod profile whose stanza is not its last rule as rendered is refused,
	// not extended: a rule after it, a stanza cut short, or one whose root
	// spelling was edited (in the file denies, where the forms are parsed
	// from, or in a socket deny, which the parse does not read).
	body := strings.TrimSuffix(pod, stanza)
	formLine := `(subpath "/private/var/lib/k3sm/keystore-run")`
	bindLine := `(local unix-socket (subpath "/private/var/lib/k3sm/keystore-sock"))`
	for _, tc := range []struct{ name, edited string }{
		{"a rule appended after the stanza", pod + "(allow file-read* (subpath \"" + root + "/keystore-sock\"))\n"},
		{"a truncated stanza", body + stanza[:len(stanza)/2]},
		{"a stanza missing its last line", body + strings.TrimSuffix(stanza, "  )\n")},
		{"an edited form in the file denies", body + strings.Replace(stanza, formLine, `(subpath "/private/var/lib/k3sm-x/keystore-run")`, 1)},
		{"an edited form in the bind denies", body + strings.Replace(stanza, bindLine, `(local unix-socket (subpath "/private/var/lib/k3sm/keystore-sockx"))`, 1)},
	} {
		if tc.edited == pod {
			t.Fatalf("%s: the edit changed nothing", tc.name)
		}
		if _, err := ShimProfile(tc.edited, ShimGrant{Dir: root + "/run/shim/0a1b2c3d"}); !errors.Is(err, ErrInvalidShimGrant) {
			t.Errorf("%s: err = %v, want ErrInvalidShimGrant", tc.name, err)
		}
	}
}

// TestKeystoreDenyStanzaShape pins the rendered form the gate test reads: the
// regex is anchored on the data root and case-folded, and the stanza is the
// last thing in the profile.
func TestKeystoreDenyStanzaShape(t *testing.T) {
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/opt/k3sm-pods/pods/p1/rootfs"},
		GenerateOptions{Posture: Posture{WorkDir: "/opt/k3sm-pods", DataRoot: "/var/lib/k3sm"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		"(deny file-read* file-read-metadata file-test-existence file-write* file-link\n",
		`(regex #"^/private/var/lib/k3sm/(K|k|K)[Ee][Yy](S|s|ſ)[Tt][Oo][Rr][Ee]-")`,
		`(regex #"^/System/Volumes/Data/private/var/lib/k3sm/(K|k|K)[Ee][Yy](S|s|ſ)[Tt][Oo][Rr][Ee]-")`,
		`(subpath "/private/var/lib/k3sm/keystore-run")`,
		`(subpath "/private/var/lib/k3sm/keystore-sock")`,
		`(local unix-socket (regex #"^/private/var/lib/k3sm/(K|k|K)[Ee][Yy](S|s|ſ)[Tt][Oo][Rr][Ee]-"))`,
		`(remote unix-socket (subpath "/var/lib/k3sm/keystore-run"))`,
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile lacks %s", want)
		}
	}
	if i := strings.LastIndex(prof, "(allow "); i > strings.Index(prof, ";; KEYSTORE:") {
		t.Errorf("an allow follows the keystore denies at %d", i)
	}
	if got, want := keystorepaths.SocketPath("/var/lib/k3sm"), "/var/lib/k3sm/keystore-sock/keys.sock"; got != want {
		t.Errorf("keystorepaths.SocketPath = %q, want %q", got, want)
	}
}

// TestDataRootRefusesPodRootUnderKeystoreName pins that a pods root the
// keystore denies would swallow is refused rather than rendered unusable.
func TestDataRootRefusesPodRootUnderKeystoreName(t *testing.T) {
	for _, workDir := range []string{"/var/lib/k3sm/keystore-pods", "/private/var/lib/k3sm/KEYSTORE-x"} {
		_, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"},
			GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: "/var/lib/k3sm"}})
		if !errors.Is(err, ErrInvalidDataRoot) {
			t.Errorf("work dir %s: err = %v, want ErrInvalidDataRoot", workDir, err)
		}
	}
}

// processInfoOps are the process-info operations a pod could aim at another
// process to read its state (its memory map, descriptors, code signature) or
// steer it.
var processInfoOps = []string{
	"process-info-pidinfo", "process-info-pidfdinfo", "process-info-pidfileportinfo",
	"process-info-setcontrol", "process-info-dirtycontrol", "process-info-rusage",
	"process-info-codesignature", "process-info-listpids",
}

// TestPodProfileDeniesProcessInfoAndSignalToOthers pins that no pod profile
// variant lets a pod inspect or signal a process outside it, the k3sm server
// in particular, which runs as the same uid and holds key material in memory:
// every process-info operation is refused on every target, and a signal is
// refused to any process outside the pod's own children and process group,
// which stay reachable as the control. It reads the profile as rendered today:
// no rule grants process-info, and the only signal grants are podSignal's.
func TestPodProfileDeniesProcessInfoAndSignalToOthers(t *testing.T) {
	const work = "/var/lib/k3sm"
	dataVol := work + "/pods/p1/rootfs"
	for name, in := range map[string]struct {
		sp   *runtimev1.SandboxProfile
		opts GenerateOptions
	}{
		"native":                   {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol}},
		"networked":                {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowNetwork: true}},
		"xcode":                    {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol, XcodeToolchainDir: xcodeDevDir}},
		"gpu":                      {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol, AllowGpu: true}},
		"wasm":                     {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol, Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_WASM}},
		"custom pod root":          {sp: &runtimev1.SandboxProfile{DataVolumePath: "/opt/k3sm-pods/pods/p1/rootfs"}, opts: GenerateOptions{Posture: Posture{WorkDir: "/opt/k3sm-pods", DataRoot: work}}},
		"semaphores and user dirs": {sp: &runtimev1.SandboxProfile{DataVolumePath: dataVol}, opts: GenerateOptions{PodUID: "0123abcd-0000-0000-0000-000000000000"}},
	} {
		t.Run(name, func(t *testing.T) {
			prof, err := Generate(in.sp, in.opts)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			rules := sbplRules(t, prof)
			for _, target := range []string{"others", "self", "children", "pgrp"} {
				for _, op := range processInfoOps {
					if ok, by := verdict(t, rules, sbplQuery{op: op, target: target}); ok {
						t.Errorf("%s on %s is allowed, by %s", op, target, by)
					}
				}
			}
			if ok, by := verdict(t, rules, sbplQuery{op: "signal", target: "others"}); ok {
				t.Errorf("signal to a process outside the pod is allowed, by %s", by)
			}
			for _, target := range []string{"children", "pgrp"} {
				if ok, by := verdict(t, rules, sbplQuery{op: "signal", target: target}); !ok {
					t.Errorf("control: signal to the pod's %s is refused, by %s", target, by)
				}
			}
		})
	}
}

// TestValidateRefusesKeystoreExtraPaths pins that a caller-supplied path naming
// a keystore path is refused before a line is rendered, not only overridden by
// the last-rule deny: extra read and write paths, the volume sources (read,
// write and read-only), host shares, the Xcode toolchain dir, artifact views
// and expose-paths, with ErrProtectedPath, at or under a keystore-*
// name of the data root or the work dir, in every spelling and letter case.
// The data root itself and a non-keystore sibling stay accepted.
func TestValidateRefusesKeystoreExtraPaths(t *testing.T) {
	const (
		work = "/opt/k3sm-pods"
		data = "/var/lib/k3sm"
	)
	posture := Posture{WorkDir: work, DataRoot: data}
	dataVol := work + "/pods/p1/rootfs"
	var bad []string
	for _, root := range []string{data, work} {
		for _, spelling := range dataRootSpellings(root) {
			for _, n := range []string{"keystore-floor.json", "keystore-run", "keystore-sock/keys.sock", "KEYSTORE-Run/x", "Keystore-later",
				"Keystore-run/x", "keyſtore-sock/keys.sock", "KEYſTORE-floor.json"} {
				bad = append(bad, filepath.Join(spelling, n))
			}
		}
		// The data-volume alias in any letter case or fold.
		for _, alias := range []string{"/system/volumes/data", "/SYSTEM/VOLUMES/DATA", "/ſyſtem/Volumeſ/Data"} {
			bad = append(bad, alias+firmlinkForms(root)[len(firmlinkForms(root))-1]+"/keystore-run/x")
		}
	}
	sp := func() *runtimev1.SandboxProfile { return &runtimev1.SandboxProfile{DataVolumePath: dataVol} }
	for _, p := range bad {
		for name, gen := range map[string]func() error{
			"extra read": func() error {
				s := sp()
				s.ExtraReadPaths = []string{p}
				_, err := Generate(s, GenerateOptions{Posture: posture})
				return err
			},
			"extra write": func() error {
				s := sp()
				s.ExtraWritePaths = []string{p}
				_, err := Generate(s, GenerateOptions{Posture: posture})
				return err
			},
			"volume read": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, ReadPaths: []string{p}})
				return err
			},
			"volume write": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, WritePaths: []string{p}})
				return err
			},
			"volume read-only": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, ReadOnlyPaths: []string{p}})
				return err
			},
			"host share": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, HostShares: []HostShare{{Path: p}}})
				return err
			},
			"host socket share": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, HostShares: []HostShare{{Path: p, Socket: true}}})
				return err
			},
			"xcode toolchain dir": func() error {
				s := sp()
				s.XcodeToolchainDir = p
				_, err := Generate(s, GenerateOptions{Posture: posture})
				return err
			},
			"artifact view": func() error {
				_, err := Generate(sp(), GenerateOptions{Posture: posture, ArtifactViewPaths: []string{p}})
				return err
			},
		} {
			if err := gen(); !errors.Is(err, ErrProtectedPath) {
				t.Errorf("%s %s: err = %v, want ErrProtectedPath", name, p, err)
			}
		}
	}
	// An expose-path is held to <root>/expose/<ns>/<pod>/<vol>, so it can never
	// name a keystore path; one that tries is refused by shape.
	for _, p := range []string{data + "/keystore-run/a/b/c", data + "/expose/../keystore-run/a/b"} {
		if _, err := Generate(sp(), GenerateOptions{Posture: posture, ExposePaths: []string{p}}); err == nil {
			t.Errorf("expose-path %s: accepted, want a refusal", p)
		}
	}
	for _, p := range []string{data, data + "/keystore", data + "/not-keystore-x", "/private" + data + "/keystore.json"} {
		s := sp()
		s.ExtraReadPaths = []string{p}
		if _, err := Generate(s, GenerateOptions{Posture: posture}); err != nil {
			t.Errorf("control %s: %v", p, err)
		}
	}
}

// TestEmptyDataRootFailsClosed pins what a profile with no data root does. It
// cannot refuse: the standalone k3sm-runtimed has no data-root setting, and
// the zero Posture is documented usable. So it denies the keystore paths
// under the work dir, where the default node keeps its data root, rather than
// rendering no keystore deny at all; and a set data root the denies cannot be
// written from (relative, unclean, "/", a quote the profile would rewrite)
// refuses the whole profile.
func TestEmptyDataRootFailsClosed(t *testing.T) {
	for _, work := range []string{"", DefaultWorkDir, "/opt/k3sm-pods"} {
		dir := work
		if dir == "" {
			dir = DefaultWorkDir
		}
		prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dir + "/pods/p1/rootfs"}, GenerateOptions{Posture: Posture{WorkDir: work}})
		if err != nil {
			t.Fatalf("work dir %q: Generate: %v", work, err)
		}
		rules := sbplRules(t, prof)
		for _, spelling := range dataRootSpellings(dir) {
			for _, n := range keystoreNames {
				for _, op := range keystoreOps {
					if ok, by := verdict(t, rules, sbplQuery{op: op, path: filepath.Join(spelling, n)}); ok {
						t.Errorf("work dir %q: %s %s allowed by %s", work, op, n, by)
					}
				}
			}
		}
		if !strings.Contains(prof, `(regex #"`+keystorePrefixPattern(firmlinkForms(dir)[len(firmlinkForms(dir))-1])+`")`) {
			t.Errorf("work dir %q: no keystore regex deny under the work dir:\n%s", work, prof)
		}
	}
	for _, bad := range []string{"relative/k3sm", "/var/lib/k3sm/", "/", "/var/lib/k3\"sm"} {
		_, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: DefaultWorkDir + "/pods/p1/rootfs"}, GenerateOptions{Posture: Posture{DataRoot: bad}})
		if !errors.Is(err, ErrInvalidDataRoot) {
			t.Errorf("data root %q: err = %v, want ErrInvalidDataRoot", bad, err)
		}
	}
}

// TestKeystoreStanzaCoversTheDataRootLeaves pins the keystore roots of a node
// that sets Posture.DataRoot and leaves Posture.StateDir unset: its state dir
// is <data root>/server or <data root>/agent, so the stanza names both, in every
// spelling, once each. A state dir that is one of those leaves, in either
// firmlink spelling, renders the same stanza; one with another leaf adds its
// own lines. The paths are literals so a renamed leaf fails here.
func TestKeystoreStanzaCoversTheDataRootLeaves(t *testing.T) {
	const (
		workDir  = "/opt/k3sm-pods"
		dataRoot = "/var/k3sm-data"
	)
	stanza := func(t *testing.T, stateDir string) string {
		t.Helper()
		out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"},
			GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: dataRoot, StateDir: stateDir}})
		if err != nil {
			t.Fatalf("Generate(state dir %q): %v", stateDir, err)
		}
		s, _, err := keystoreStanzaOf(out)
		if err != nil {
			t.Fatalf("keystoreStanzaOf(state dir %q): %v", stateDir, err)
		}
		return s
	}
	unset := stanza(t, "")
	for _, root := range []string{workDir, dataRoot, dataRoot + "/server", dataRoot + "/agent"} {
		for _, form := range keystoreForms(root) {
			line := "(regex #\"" + keystorePrefixPattern(form) + "\")\n"
			if n := strings.Count(unset, "  "+line); n != 1 {
				t.Errorf("file deny for %s appears %d times, want 1:\n%s", form, n, unset)
			}
		}
	}
	for _, sd := range []string{dataRoot + "/server", dataRoot + "/agent", "/private" + dataRoot + "/server"} {
		if got := stanza(t, sd); got != unset {
			t.Errorf("state dir %s changed the stanza:\n--- unset ---\n%s\n--- set ---\n%s", sd, unset, got)
		}
	}
	custom := stanza(t, dataRoot+"/cp")
	if custom == unset || !strings.Contains(custom, "(subpath \""+dataRoot+"/cp/keystore-run\")") {
		t.Errorf("state dir %s/cp added no keystore denies:\n%s", dataRoot, custom)
	}
}
