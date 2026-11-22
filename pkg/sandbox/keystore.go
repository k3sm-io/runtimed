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
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// dataVolumeAlias is the mount point of the macOS data volume. A path under a
// firmlink (/private/var/...) is also reachable through it, so a keystore deny
// is written in that spelling too.
const dataVolumeAlias = "/System/Volumes/Data"

// keystoreRoots returns the directories whose keystore names every pod profile
// denies: the work-dir, the data root when set, the DataRootDenySubdirs leaves
// of the data root (<data root>/server and <data root>/agent; under the
// work-dir when the data root is unset), then the role's state dir
// (Posture.StateDir) when set, each skipped when already listed. The work-dir
// and its leaves stand in for an unset data root for the reason the server and
// agent denies do: on a node whose data root is its work-dir, an unset
// Posture.DataRoot still gets the denies, and the profile is the same as with
// the work-dir named.
//
// The state dir is among them because the role keeps keystore- files there
// too (the delivery state record), and its whole-tree deny is not enough: a
// file-read* deny answers EPERM for a present name but ENOENT for an absent
// one, and does not cover the access(2) F_OK test at all (measured: OK on a
// present name), so a pod could tell which keystore names exist. The stanza's
// file-test-existence and metadata denies answer EPERM either way
// (TestWorkDirKeystoreDenyHidesExistence). The leaves are among them for a
// node that leaves Posture.StateDir unset: its state dir is one of them. They
// come before the state dir so that a state dir naming a leaf, in any firmlink
// spelling, renders the same stanza as an unset one. Only exact repeats are
// skipped here; renderKeystoreStanza drops a spelling already rendered.
func keystoreRoots(workDir, dataRoot, stateDir string) []string {
	roots := []string{workDir}
	add := func(r string) {
		if r != "" && !slices.Contains(roots, r) {
			roots = append(roots, r)
		}
	}
	add(dataRoot)
	leavesOf := dataRoot
	if leavesOf == "" {
		leavesOf = workDir
	}
	for _, sub := range DataRootDenySubdirs() {
		add(filepath.Join(leavesOf, sub))
	}
	add(stateDir)
	return roots
}

// keystoreForms returns every spelling a keystore deny under root is written
// in: the firmlinkForms of root, then the data-volume alias of its resolved
// form (/System/Volumes/Data/private/var/... for /var/...). Seatbelt matches
// the resolved path, so the extra spellings are belt and braces; each costs one
// line.
func keystoreForms(root string) []string {
	forms := firmlinkForms(root)
	resolved := forms[len(forms)-1]
	if !isUnder(resolved, dataVolumeAlias) {
		forms = append(forms, dataVolumeAlias+resolved)
	}
	return forms
}

// keystorePrefixPattern returns the anchored regex that matches every name
// under root beginning keystorepaths.DataRootPrefix, and everything below such a
// name. The prefix is matched in every spelling the data volume folds onto it:
// the volume is case insensitive by default, so KEYSTORE-run names the same
// directory, and APFS folds U+212A (Kelvin sign) to k and U+017F (long s) to
// s, so a pod that could create either spelling would plant the server's
// directory before the server.
//
// A letter with only its two ASCII cases is a class ([Ee]); one with a
// non-ASCII fold is an alternation of the literal UTF-8 spellings ((K|k|K)).
// SBPL's regex takes no \x{...} escape (inside a class it reads the escape as
// the characters x, {, 2, 1, A and }, measured: [Kk\x{212A}]eystore- denied
// xeystore-), and a class holding a multi-byte character may be read as a
// class of its bytes, so the alternation is the one form that means the fold.
func keystorePrefixPattern(root string) string {
	var fold strings.Builder
	for _, r := range keystorepaths.DataRootPrefix {
		spellings := foldSpellings(r)
		switch {
		case len(spellings) == 1:
			fold.WriteString(regexp.QuoteMeta(spellings[0]))
		case len(spellings) == 2:
			fold.WriteString("[" + spellings[0] + spellings[1] + "]")
		default:
			fold.WriteString("(" + strings.Join(spellings, "|") + ")")
		}
	}
	return "^" + regexp.QuoteMeta(root) + "/" + fold.String()
}

// foldSpellings returns every rune that folds onto r (its unicode.SimpleFold
// orbit), upper case ASCII first, then lower, then the rest in orbit order.
func foldSpellings(r rune) []string {
	orbit := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	slices.SortStableFunc(orbit, func(a, b rune) int {
		rank := func(x rune) int {
			switch {
			case x < utf8.RuneSelf && unicode.IsUpper(x):
				return 0
			case x < utf8.RuneSelf:
				return 1
			}
			return 2
		}
		return rank(a) - rank(b)
	})
	out := make([]string, len(orbit))
	for i, x := range orbit {
		out[i] = string(x)
	}
	return out
}

// foldName folds s the way the data volume compares names: each rune to the
// least rune of its unicode.SimpleFold orbit, then to lower case, so K, k and
// U+212A all become k and S, s and U+017F all become s.
func foldName(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return unicode.ToLower(least)
	}, s)
}

// keystoreStanzaHead is the first line of every keystore stanza; keystoreStanzaOf
// finds the stanza in a rendered profile by it.
const keystoreStanzaHead = ";; KEYSTORE: every data-root name beginning " + keystorepaths.DataRootPrefix + " and the whole\n"

// keystoreDenyStanza renders the keystore denies for roots: file reads
// (metadata included), an existence test, every file write (create, unlink
// and rename among them), a hard link (file-link, which file-write* does not
// cover), connect(2) to a unix socket and bind(2) of one, on every name under
// each root that begins keystorepaths.DataRootPrefix and on the whole
// keystorepaths.RunDir tree, in every keystoreForms spelling.
//
// file-test-existence closes one existence oracle, the access(2) F_OK check,
// which file-read* does not cover (measured: access succeeded under a
// file-read* file-read-metadata deny). With it, a read, a stat, an existence
// test and every write of a keystore name answer EPERM whether or not the
// name exists (measured in the state dir,
// TestWorkDirKeystoreDenyHidesExistence).
//
// It hides keystore-named entries only. Every other name in a root it covers
// is outside it: in the state dir the token, tls, db and kubeconfig entries
// meet only the whole-tree deny, which answers EPERM (or OK, for the access(2)
// F_OK test) for a present name and ENOENT for an absent one, so a pod can
// still tell which of those exist. That gap is tracked separately. Nor does
// the stanza hide the names from a listing: a pod that can list a root (a
// data root it holds a read grant on) reads the names there.
//
// Every profile producer emits it as its LAST rule: Generate after the pod
// profile, ShimProfile again after the shim grant (keystoreStanzaOf). Seatbelt is
// last-match-wins, so no allow anywhere in the profile (an extra path, a
// volume, an exposure, a credential, a view, a host share, a shim grant) can
// re-open a keystore path, whatever the validators let through.
func keystoreDenyStanza(roots []string) string {
	var forms []string
	for _, root := range roots {
		forms = append(forms, keystoreForms(root)...)
	}
	return renderKeystoreStanza(forms)
}

// renderKeystoreStanza renders the stanza for forms, the root spellings
// keystoreForms returned, deduplicated in order.
//
// The regex is written raw, not through %q, for the reason writeXcodeHelperCarve
// gives: Go quoting would double its escapes. The roots reaching it passed
// checkDenyDir or are a validated work-dir, so they carry no quote.
func renderKeystoreStanza(forms []string) string {
	forms = dedupeInOrder(forms)
	var filters []string
	for _, form := range forms {
		filters = append(filters,
			"(regex #\""+keystorePrefixPattern(form)+"\")",
			fmt.Sprintf("(subpath %q)", filepath.Join(form, keystorepaths.RunDir)),
			fmt.Sprintf("(subpath %q)", filepath.Join(form, keystorepaths.SockDir)))
	}
	var b strings.Builder
	b.WriteString(keystoreStanzaHead)
	b.WriteString(";; " + keystorepaths.RunDir + " and " + keystorepaths.SockDir + " trees: no read, stat, existence test, write, create,\n")
	b.WriteString(";; unlink, rename, hard link, connect or bind. LAST, so no allow above can re-open them.\n")
	b.WriteString("(deny file-read* file-read-metadata file-test-existence file-write* file-link\n")
	for _, f := range filters {
		b.WriteString("  " + f + "\n")
	}
	b.WriteString("  )\n")
	b.WriteString("(deny network-outbound\n")
	for _, f := range filters {
		b.WriteString("  (remote unix-socket " + f + ")\n")
	}
	b.WriteString("  )\n")
	b.WriteString("(deny network-bind\n")
	for _, f := range filters {
		b.WriteString("  (local unix-socket " + f + ")\n")
	}
	b.WriteString("  )\n")
	return b.String()
}

// dedupeInOrder drops every repeat of an element, keeping first occurrences in
// order.
func dedupeInOrder(in []string) []string {
	seen := make(map[string]bool, len(in))
	return slices.DeleteFunc(slices.Clone(in), func(s string) bool {
		dup := seen[s]
		seen[s] = true
		return dup
	})
}

// keystoreStanzaOf returns the keystore stanza a Generate profile ends with,
// and the root spellings it denies. It fails unless profile ends with exactly
// the stanza renderKeystoreStanza writes for those spellings, so a profile that
// lost, truncated or edited its stanza is refused, not extended.
func keystoreStanzaOf(profile string) (string, []string, error) {
	i := strings.LastIndex(profile, keystoreStanzaHead)
	if i < 0 {
		return "", nil, fmt.Errorf("the profile carries no keystore denies")
	}
	stanza := profile[i:]
	suffix := "/" + keystorepaths.RunDir + "\")"
	var forms []string
	for _, line := range strings.Split(stanza, "\n") {
		line = strings.TrimSpace(line)
		if line == "(deny network-outbound" {
			break
		}
		if !strings.HasPrefix(line, "(subpath ") || !strings.HasSuffix(line, suffix) {
			continue
		}
		p, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "(subpath "), ")"))
		if err != nil {
			return "", nil, fmt.Errorf("the keystore denies do not parse: %w", err)
		}
		forms = append(forms, strings.TrimSuffix(p, "/"+keystorepaths.RunDir))
	}
	if len(forms) == 0 || renderKeystoreStanza(forms) != stanza {
		return "", nil, fmt.Errorf("the keystore denies are not the profile's last rule as rendered")
	}
	return stanza, forms, nil
}

// underKeystoreName reports whether p is at or under a
// keystorepaths.DataRootPrefix name of root, in any firmlink spelling, through
// the data-volume alias (in any letter case), and in any letter case or
// fold of the name (foldName).
func underKeystoreName(p, root string) bool {
	p = filepath.Clean(p)
	// The alias is stripped in any letter case and fold, segment by segment:
	// its spelling as written may not be its byte length (U+017F for s).
	aliasSegs := strings.Count(dataVolumeAlias, "/")
	if segs := strings.Split(p, "/"); underFold(p, dataVolumeAlias) && len(segs) > aliasSegs+1 {
		p = "/" + strings.Join(segs[aliasSegs+1:], "/")
	}
	for _, form := range comparisonForms(p) {
		for _, r := range comparisonForms(root) {
			ps, rs := strings.Split(form, "/"), strings.Split(r, "/")
			if len(ps) > len(rs) && underFold(form, r) && strings.HasPrefix(foldName(ps[len(rs)]), keystorepaths.DataRootPrefix) {
				return true
			}
		}
	}
	return false
}

// validateKeystoreReach refuses, with ErrProtectedPath, any caller-supplied
// path at or under a keystore name of one of roots (underKeystoreName). The
// last-rule deny would override such a grant anyway; refusing it means a pod
// that asks for one fails to start rather than starting with a grant that
// silently does nothing.
func validateKeystoreReach(roots []string, groups ...[]string) error {
	for _, g := range groups {
		for _, p := range g {
			if p == "" {
				continue
			}
			for _, root := range roots {
				if underKeystoreName(p, root) {
					return fmt.Errorf("%w: %q names a keystore path under %q", ErrProtectedPath, p, root)
				}
			}
		}
	}
	return nil
}
