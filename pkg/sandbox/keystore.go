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

// keystoreDenyStanza renders the keystore denies for roots: file reads
// (metadata included), every file write (create, unlink and rename among them),
// connect(2) to a unix socket and bind(2) of one, on every name under each root
// that begins keystorepaths.DataRootPrefix and on the whole keystorepaths.RunDir tree, in
// every keystoreForms spelling.
//
// Generate emits it as the LAST rule of the profile. Seatbelt is
// last-match-wins, so no allow anywhere in the profile (an extra path, a
// volume, an exposure, a credential, a view, a host share) can re-open a
// keystore path, whatever the validators let through.
//
// The regex is written raw, not through %q, for the reason writeXcodeHelperCarve
// gives: Go quoting would double its escapes. The roots reaching it passed
// checkDenyDir or are a validated work-dir, so they carry no quote.
func keystoreDenyStanza(roots []string) string {
	var filters []string
	for _, root := range roots {
		for _, form := range keystoreForms(root) {
			filters = append(filters,
				"(regex #\""+keystorePrefixPattern(form)+"\")",
				fmt.Sprintf("(subpath %q)", filepath.Join(form, keystorepaths.RunDir)),
				fmt.Sprintf("(subpath %q)", filepath.Join(form, keystorepaths.SockDir)))
		}
	}
	seen := make(map[string]bool, len(filters))
	filters = slices.DeleteFunc(filters, func(f string) bool {
		dup := seen[f]
		seen[f] = true
		return dup
	})
	var b strings.Builder
	b.WriteString(";; KEYSTORE: every data-root name beginning " + keystorepaths.DataRootPrefix + " and the whole\n")
	b.WriteString(";; " + keystorepaths.RunDir + " and " + keystorepaths.SockDir + " trees: no read, stat, write, create, unlink, rename,\n")
	b.WriteString(";; connect or bind. LAST, so no allow above can re-open them.\n")
	b.WriteString("(deny file-read* file-read-metadata file-write*\n")
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
