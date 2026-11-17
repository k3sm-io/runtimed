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
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// namespacesKey is the field that limits a share line, or caps a delegation,
// to named namespaces: namespaces=<n1>,<n2>,...
const namespacesKey = "namespaces"

// namespacePattern is a prefix pattern: the start of an RFC 1123 label
// followed by one trailing '*'. The prefix is never empty, since a bare '*'
// would be a node-wide line spelled another way, and is short enough that a
// label can still follow it.
var namespacePattern = regexp.MustCompile(`^[a-z0-9][-a-z0-9]{0,61}\*$`)

// ValidateNamespaces checks a share line's namespace list, or a delegation's
// cap: at most maxGrantNamespaces names, each an RFC 1123 label (what
// Kubernetes allows for a namespace) or a prefix pattern ending in a single
// '*' (yurei-p-*), with no name repeated. An empty list is valid and means
// node-wide.
func ValidateNamespaces(nss []string) error {
	if len(nss) > maxGrantNamespaces {
		return fmt.Errorf("%w: %d namespaces (at most %d)", ErrInvalidEntry, len(nss), maxGrantNamespaces)
	}
	seen := map[string]bool{}
	for _, ns := range nss {
		if !dnsLabel.MatchString(ns) && !namespacePattern.MatchString(ns) {
			return fmt.Errorf("%w: namespace %q is neither a namespace name nor a prefix pattern ending in one '*'", ErrInvalidEntry, ns)
		}
		if seen[ns] {
			return fmt.Errorf("%w: namespace %q is repeated", ErrInvalidEntry, ns)
		}
		seen[ns] = true
	}
	return nil
}

// ParseNamespaceList reads a comma-separated namespace list strictly: an
// empty list, an empty name, a repeat or an invalid name is an error, never
// a shorter list. It is the parser of the namespaces= field and of the
// share CLI's --namespaces flag.
func ParseNamespaceList(s string) ([]string, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: an empty namespace list (leave the field out for every namespace)", ErrInvalidEntry)
	}
	nss := strings.Split(s, ",")
	if len(nss) > maxGrantNamespaces {
		return nil, fmt.Errorf("%w: %d namespaces (at most %d)", ErrInvalidEntry, len(nss), maxGrantNamespaces)
	}
	if slices.Contains(nss, "") {
		return nil, fmt.Errorf("%w: an empty name in the namespace list %q", ErrInvalidEntry, s)
	}
	return nss, ValidateNamespaces(nss)
}

// parseNamespacesField reads one "namespaces=<list>" field.
func parseNamespacesField(f string) ([]string, error) {
	v, ok := strings.CutPrefix(f, namespacesKey+"=")
	if !ok {
		return nil, fmt.Errorf("%w: field %q: want %s=<namespace,...>", ErrInvalidEntry, f, namespacesKey)
	}
	return ParseNamespaceList(v)
}

// formatNamespaces renders nss as its field, sorted, or "" for none.
func formatNamespaces(nss []string) string {
	if len(nss) == 0 {
		return ""
	}
	s := slices.Clone(nss)
	slices.Sort(s)
	return namespacesKey + "=" + strings.Join(s, ",")
}

// namespaceMatches reports whether namespace ns is named by n, an exact name
// or a prefix pattern. A name that is not a valid namespace matches nothing.
func namespaceMatches(n, ns string) bool {
	if !dnsLabel.MatchString(ns) {
		return false
	}
	if p, ok := strings.CutSuffix(n, "*"); ok {
		return strings.HasPrefix(ns, p)
	}
	return n == ns
}

// admitsNamespace reports whether a list admits namespace ns: an empty list
// admits every namespace, today's node-wide share.
func admitsNamespace(nss []string, ns string) bool {
	if len(nss) == 0 {
		return true
	}
	return slices.ContainsFunc(nss, func(n string) bool { return namespaceMatches(n, ns) })
}

// exactSpecificity ranks an exact namespace name above every pattern, whose
// rank is 1 plus its prefix length (at most 62).
const exactSpecificity = 1 << 16

// namespaceSpecificity ranks how narrowly a list names namespace ns: 0 for a
// node-wide list, 1 plus the prefix length for the longest matching pattern,
// exactSpecificity for an exact name. A list that does not admit ns is never
// asked (match considers only admitting entries).
func namespaceSpecificity(nss []string, ns string) int {
	best := 0
	for _, n := range nss {
		if !namespaceMatches(n, ns) {
			continue
		}
		r := exactSpecificity
		if p, ok := strings.CutSuffix(n, "*"); ok {
			r = 1 + len(p)
		}
		best = max(best, r)
	}
	return best
}

// namespacesWithin reports whether a delegated entry's namespaces stay
// inside its delegation's cap. An uncapped delegation allows any list; an
// entry naming none under a cap inherits the cap (Delegation.Scope). Under a
// cap, an exact name must equal a capped name or start with a capped
// pattern's prefix, and a pattern must be at least as narrow as a capped
// pattern (its prefix starts with that pattern's prefix).
func namespacesWithin(entry, limit []string) error {
	if len(limit) == 0 {
		return nil
	}
	for _, n := range entry {
		p, pattern := strings.CutSuffix(n, "*")
		ok := slices.ContainsFunc(limit, func(c string) bool {
			cp, cpattern := strings.CutSuffix(c, "*")
			switch {
			case cpattern:
				return strings.HasPrefix(p, cp)
			case pattern:
				return false
			}
			return n == c
		})
		if !ok {
			return fmt.Errorf("namespace %s is outside the delegation's namespaces %s", n, strings.Join(limit, ","))
		}
	}
	return nil
}
