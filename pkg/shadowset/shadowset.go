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

package shadowset

// Entry is one re-signed copy and the exec paths it stands in for.
type Entry struct {
	// Copy is the copy's file name in the node's shadow directory.
	Copy string
	// Source is the real file the installer copies from. It is never a
	// symlink (/usr/bin/tar is one, so tar's Source is /usr/bin/bsdtar).
	Source string
	// Hosts are the exec paths swapped for the copy. A binary that
	// dispatches on argv[0] (grep/egrep/zgrep, gunzip/zcat, test/[) lists
	// every name that reaches the same file; the swap keeps argv[0], so the
	// copy dispatches exactly as the host binary would.
	Hosts []string
	// Shell marks the shell entries. The runtime keys its shell-only rules on
	// it (a direct exec of a host-shell script interpreter, and its policy
	// gate); the plain swap applies to every entry.
	Shell bool
}

// entries is the list. /bin/sh maps to the bash copy: /bin/sh is Apple's
// dispatcher, which re-execs /private/var/select/sh, so a copy of it would
// only hand off to the platform shell again; bash run under the basename "sh"
// enters POSIX mode, which is what /bin/sh resolves to by default.
var entries = []Entry{
	// The shells.
	{Copy: "bash", Source: "/bin/bash", Hosts: []string{"/bin/sh", "/bin/bash"}, Shell: true},
	{Copy: "zsh", Source: "/bin/zsh", Hosts: []string{"/bin/zsh"}, Shell: true},
	{Copy: "dash", Source: "/bin/dash", Hosts: []string{"/bin/dash"}, Shell: true},
	{Copy: "env", Source: "/usr/bin/env", Hosts: []string{"/usr/bin/env"}, Shell: true},

	// tar (what kubectl cp runs) and the common coreutils a pod's scripts use.
	{Copy: "tar", Source: "/usr/bin/bsdtar", Hosts: []string{"/usr/bin/tar", "/usr/bin/bsdtar"}},
	{Copy: "cat", Source: "/bin/cat", Hosts: []string{"/bin/cat"}},
	{Copy: "cp", Source: "/bin/cp", Hosts: []string{"/bin/cp"}},
	{Copy: "mv", Source: "/bin/mv", Hosts: []string{"/bin/mv"}},
	{Copy: "ls", Source: "/bin/ls", Hosts: []string{"/bin/ls"}},
	{Copy: "mkdir", Source: "/bin/mkdir", Hosts: []string{"/bin/mkdir"}},
	{Copy: "rmdir", Source: "/bin/rmdir", Hosts: []string{"/bin/rmdir"}},
	{Copy: "rm", Source: "/bin/rm", Hosts: []string{"/bin/rm"}},
	{Copy: "chmod", Source: "/bin/chmod", Hosts: []string{"/bin/chmod"}},
	{Copy: "ln", Source: "/bin/ln", Hosts: []string{"/bin/ln"}},
	{Copy: "echo", Source: "/bin/echo", Hosts: []string{"/bin/echo"}},
	{Copy: "test", Source: "/bin/test", Hosts: []string{"/bin/test", "/bin/["}},
	{Copy: "sleep", Source: "/bin/sleep", Hosts: []string{"/bin/sleep"}},
	{Copy: "date", Source: "/bin/date", Hosts: []string{"/bin/date"}},
	{Copy: "sed", Source: "/usr/bin/sed", Hosts: []string{"/usr/bin/sed"}},
	{Copy: "grep", Source: "/usr/bin/grep", Hosts: []string{"/usr/bin/grep", "/usr/bin/egrep", "/usr/bin/zgrep"}},
	{Copy: "fgrep", Source: "/usr/bin/fgrep", Hosts: []string{"/usr/bin/fgrep"}},
	{Copy: "awk", Source: "/usr/bin/awk", Hosts: []string{"/usr/bin/awk"}},
	{Copy: "tee", Source: "/usr/bin/tee", Hosts: []string{"/usr/bin/tee"}},
	{Copy: "head", Source: "/usr/bin/head", Hosts: []string{"/usr/bin/head"}},
	{Copy: "tail", Source: "/usr/bin/tail", Hosts: []string{"/usr/bin/tail"}},
	{Copy: "wc", Source: "/usr/bin/wc", Hosts: []string{"/usr/bin/wc"}},
	{Copy: "sort", Source: "/usr/bin/sort", Hosts: []string{"/usr/bin/sort"}},
	{Copy: "basename", Source: "/usr/bin/basename", Hosts: []string{"/usr/bin/basename"}},
	{Copy: "dirname", Source: "/usr/bin/dirname", Hosts: []string{"/usr/bin/dirname"}},
	{Copy: "find", Source: "/usr/bin/find", Hosts: []string{"/usr/bin/find"}},
	{Copy: "xargs", Source: "/usr/bin/xargs", Hosts: []string{"/usr/bin/xargs"}},
	{Copy: "cut", Source: "/usr/bin/cut", Hosts: []string{"/usr/bin/cut"}},
	{Copy: "tr", Source: "/usr/bin/tr", Hosts: []string{"/usr/bin/tr"}},
	{Copy: "touch", Source: "/usr/bin/touch", Hosts: []string{"/usr/bin/touch"}},
	// stat and readlink are one binary dispatching on argv[0]; each name gets
	// its own copy, and the swap keeps argv[0].
	{Copy: "stat", Source: "/usr/bin/stat", Hosts: []string{"/usr/bin/stat"}},
	{Copy: "readlink", Source: "/usr/bin/readlink", Hosts: []string{"/usr/bin/readlink"}},
	{Copy: "gzip", Source: "/usr/bin/gzip", Hosts: []string{"/usr/bin/gzip"}},
	{Copy: "gunzip", Source: "/usr/bin/gunzip", Hosts: []string{"/usr/bin/gunzip", "/usr/bin/zcat"}},
	{Copy: "base64", Source: "/usr/bin/base64", Hosts: []string{"/usr/bin/base64"}},
}

// byHost indexes entries by exec path.
var byHost = func() map[string]int {
	m := make(map[string]int)
	for i, e := range entries {
		for _, h := range e.Hosts {
			m[h] = i
		}
	}
	return m
}()

// Entries returns a copy of the list, in declaration order.
func Entries() []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		e.Hosts = append([]string(nil), e.Hosts...)
		out[i] = e
	}
	return out
}

// CopyFor returns the copy name that stands in for the exec path host, and
// whether there is one. host is compared as given (no cleaning, no symlink
// resolution), as the kernel would be handed it.
func CopyFor(host string) (string, bool) {
	i, ok := byHost[host]
	if !ok {
		return "", false
	}
	return entries[i].Copy, true
}

// IsShell reports whether host is an exec path of a shell entry.
func IsShell(host string) bool {
	i, ok := byHost[host]
	return ok && entries[i].Shell
}
