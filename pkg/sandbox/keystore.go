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

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// dataVolumeAlias is the mount point of the macOS data volume. A path under a
// firmlink (/private/var/...) is also reachable through it, so a keystore deny
// is written in that spelling too.
const dataVolumeAlias = "/System/Volumes/Data"

// keystoreRoots returns the directories whose keystore names every pod profile
// denies: the work-dir, then the data root when it is set and differs. The
// work-dir is always among them for the reason the server and agent denies are:
// on a node whose data root is its work-dir, an unset Posture.DataRoot still
// gets the denies.
func keystoreRoots(workDir, dataRoot string) []string {
	roots := []string{workDir}
	if dataRoot != "" && dataRoot != workDir {
		roots = append(roots, dataRoot)
	}
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
// name. The prefix is matched in either letter case: the data volume is case
// insensitive by default, so KEYSTORE-run names the same directory, and a pod
// that could create it would plant the server's directory before the server.
func keystorePrefixPattern(root string) string {
	var fold strings.Builder
	for _, r := range keystorepaths.DataRootPrefix {
		lo, up := strings.ToLower(string(r)), strings.ToUpper(string(r))
		if lo == up {
			fold.WriteString(regexp.QuoteMeta(lo))
			continue
		}
		fold.WriteString("[" + up + lo + "]")
	}
	return "^" + regexp.QuoteMeta(root) + "/" + fold.String()
}

// keystoreStanzaHead is the first line of every keystore stanza; keystoreStanzaOf
// finds the stanza in a rendered profile by it.
const keystoreStanzaHead = ";; KEYSTORE: every data-root name beginning " + keystorepaths.DataRootPrefix + " and the whole\n"

// keystoreDenyStanza renders the keystore denies for roots: file reads
// (metadata included), every file write (create, unlink and rename among them), a
// hard link (file-link, which file-write* does not cover),
// connect(2) to a unix socket and bind(2) of one, on every name under each root
// that begins keystorepaths.DataRootPrefix and on the whole keystorepaths.RunDir tree, in
// every keystoreForms spelling.
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
	b.WriteString(";; " + keystorepaths.RunDir + " and " + keystorepaths.SockDir + " trees: no read, stat, write, create, unlink, rename,\n")
	b.WriteString(";; hard link, connect or bind. LAST, so no allow above can re-open them.\n")
	b.WriteString("(deny file-read* file-read-metadata file-write* file-link\n")
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
// the data-volume alias, and in either letter case.
func underKeystoreName(p, root string) bool {
	p = filepath.Clean(p)
	if isUnder(p, dataVolumeAlias) && p != dataVolumeAlias {
		p = strings.TrimPrefix(p, dataVolumeAlias)
	}
	for _, form := range comparisonForms(p) {
		for _, r := range comparisonForms(root) {
			ps, rs := strings.Split(form, "/"), strings.Split(r, "/")
			if len(ps) > len(rs) && underFold(form, r) && strings.HasPrefix(strings.ToLower(ps[len(rs)]), keystorepaths.DataRootPrefix) {
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
