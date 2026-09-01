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

package guestinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// containerRoot builds a temp dir standing in for one container's composed
// rootfs. Each entry is "path[:mode]"; a path ending in "/" is a directory.
//
// It is a temp dir and NOT the test process's own filesystem on purpose: the
// defect this file guards against is resolving argv[0] against the wrong root.
// A host-side os/exec.LookPath would search the machine running the test — where
// /bin/sh genuinely exists — and would pass a naive assertion while failing in
// every real guest. Every case here therefore names a program that exists ONLY in
// this temp tree.
func containerRoot(t *testing.T, entries ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, e := range entries {
		spec, modeStr, hasMode := strings.Cut(e, ":")
		mode := os.FileMode(0o755)
		if hasMode {
			var m uint64
			if _, err := fmtSscan(modeStr, &m); err != nil {
				t.Fatalf("bad mode %q: %v", modeStr, err)
			}
			mode = os.FileMode(m)
		}
		p := filepath.Join(root, filepath.FromSlash(spec))
		if strings.HasSuffix(spec, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fmtSscan parses an octal mode without pulling fmt into the helper's signature.
func fmtSscan(s string, out *uint64) (int, error) {
	v, err := parseOctal(s)
	if err != nil {
		return 0, err
	}
	*out = v
	return 1, nil
}

func parseOctal(s string) (uint64, error) {
	var v uint64
	if s == "" {
		return 0, errors.New("empty mode")
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, errors.New("not octal: " + s)
		}
		v = v*8 + uint64(c-'0')
	}
	return v, nil
}

// TestResolveProgram is the gate on the defect that stopped most real images
// from starting at all. nats:2.10-alpine's merged spec is
//
//	command = ['docker-entrypoint.sh', '-p', '4222', '-m', '8222']
//
// — a BARE NAME the image expects PATH to resolve, living at
// /usr/local/bin/docker-entrypoint.sh. syscall.ForkExec is execve: no PATH search,
// a path required. The host spine deliberately does not resolve argv[0] for a vm
// pod (it does not have the guest's rootfs to stat), and the guest had not taken
// the job up, so neither side did it and nginx, node, postgres and nats all failed
// identically.
func TestResolveProgram(t *testing.T) {
	cases := []struct {
		name       string
		entries    []string
		argv0      string
		workingDir string
		pathEnv    string
		want       string
		wantErr    bool
		// errFragments must all appear in the error, so a refusal actually tells
		// an operator which name failed and where it was looked for.
		errFragments []string
	}{
		{
			name:    "bare-name-found-via-path",
			entries: []string{"usr/local/bin/docker-entrypoint.sh"},
			argv0:   "docker-entrypoint.sh",
			pathEnv: DefaultPath,
			want:    "/usr/local/bin/docker-entrypoint.sh",
		},
		{
			name:    "bare-name-uses-the-posix-default-when-path-is-unset",
			entries: []string{"usr/local/bin/docker-entrypoint.sh"},
			argv0:   "docker-entrypoint.sh",
			pathEnv: "",
			want:    "/usr/local/bin/docker-entrypoint.sh",
		},
		{
			name:    "path-order-decides-which-match-wins",
			entries: []string{"usr/bin/nats-server", "usr/local/bin/nats-server"},
			argv0:   "nats-server",
			pathEnv: "/usr/local/bin:/usr/bin",
			want:    "/usr/local/bin/nats-server",
		},
		{
			name:    "the-other-order-picks-the-other-one",
			entries: []string{"usr/bin/nats-server", "usr/local/bin/nats-server"},
			argv0:   "nats-server",
			pathEnv: "/usr/bin:/usr/local/bin",
			want:    "/usr/bin/nats-server",
		},
		{
			name:         "bare-name-absent-names-argv0-and-the-path",
			entries:      []string{"bin/sh"},
			argv0:        "docker-entrypoint.sh",
			pathEnv:      "/usr/local/bin:/usr/bin",
			wantErr:      true,
			errFragments: []string{"docker-entrypoint.sh", "/usr/local/bin:/usr/bin"},
		},
		{
			name:         "found-but-not-executable-is-refused-and-said-so",
			entries:      []string{"usr/local/bin/docker-entrypoint.sh:644"},
			argv0:        "docker-entrypoint.sh",
			pathEnv:      "/usr/local/bin",
			wantErr:      true,
			errFragments: []string{"docker-entrypoint.sh", "not executable"},
		},
		{
			name:    "a-non-executable-match-does-not-end-the-search",
			entries: []string{"usr/local/bin/nats-server:644", "usr/bin/nats-server"},
			argv0:   "nats-server",
			pathEnv: "/usr/local/bin:/usr/bin",
			want:    "/usr/bin/nats-server",
		},
		{
			name:    "a-directory-where-a-program-should-be-is-skipped",
			entries: []string{"usr/local/bin/nats-server/", "usr/bin/nats-server"},
			argv0:   "nats-server",
			pathEnv: "/usr/local/bin:/usr/bin",
			want:    "/usr/bin/nats-server",
		},
		{
			name:    "a-name-with-a-slash-is-used-as-given",
			entries: []string{"bin/sleep"},
			argv0:   "/bin/sleep",
			pathEnv: DefaultPath,
			want:    "/bin/sleep",
		},
		{
			name:         "a-slash-name-that-does-not-exist-is-refused",
			entries:      []string{"bin/sh"},
			argv0:        "/bin/sleep",
			pathEnv:      DefaultPath,
			wantErr:      true,
			errFragments: []string{"/bin/sleep", "does not exist"},
		},
		{
			name:         "a-slash-name-that-is-not-executable-is-refused",
			entries:      []string{"bin/sleep:644"},
			argv0:        "/bin/sleep",
			pathEnv:      DefaultPath,
			wantErr:      true,
			errFragments: []string{"/bin/sleep", "not executable"},
		},
		{
			name:       "a-relative-slash-name-resolves-against-the-working-dir",
			entries:    []string{"app/run.sh"},
			argv0:      "./run.sh",
			workingDir: "/app",
			pathEnv:    DefaultPath,
			want:       "./run.sh",
		},
		{
			name:       "an-empty-path-element-means-the-working-dir",
			entries:    []string{"app/run.sh"},
			argv0:      "run.sh",
			workingDir: "/app",
			pathEnv:    ":/usr/bin",
			want:       "/app/run.sh",
		},
		{
			// A leading ".." on an absolute element collapses to the root, exactly
			// as it does inside a real chroot — a container cannot climb out of /
			// with "..", and neither can this search.
			name:    "a-traversing-path-element-normalises-inside-the-container",
			entries: []string{"bin/sh"},
			argv0:   "sh",
			pathEnv: "/../../../../../../bin",
			want:    "/bin/sh",
		},
		{
			// The same element, with the container NOT carrying the program: it
			// must not fall through to the host's own /bin/sh, which exists on the
			// machine running this test.
			name:         "a-traversing-path-element-does-not-reach-the-host",
			entries:      []string{"usr/local/bin/only-here"},
			argv0:        "sh",
			pathEnv:      "/../../../../../../bin",
			wantErr:      true,
			errFragments: []string{"sh"},
		},
		{
			name:         "a-relative-traversing-element-also-stays-inside",
			entries:      []string{"usr/local/bin/only-here"},
			argv0:        "sh",
			workingDir:   "/app",
			pathEnv:      "../../../../../../bin",
			wantErr:      true,
			errFragments: []string{"sh"},
		},
		{
			name:         "an-empty-argv0-is-refused",
			entries:      []string{"bin/sh"},
			argv0:        "",
			pathEnv:      DefaultPath,
			wantErr:      true,
			errFragments: []string{"argv[0] is empty"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := containerRoot(t, tc.entries...)
			got, err := ResolveProgram(root, tc.workingDir, tc.argv0, tc.pathEnv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveProgram = %q, want an error", got)
				}
				if !errors.Is(err, ErrProgramNotFound) {
					t.Errorf("err = %v, want ErrProgramNotFound in the chain", err)
				}
				for _, frag := range tc.errFragments {
					if !strings.Contains(err.Error(), frag) {
						t.Errorf("err = %q, want it to mention %q — with the console fix this message is what an operator reads", err, frag)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveProgram: %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveProgram = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveProgramSearchesTheContainerNotTheHost is the regression guard with
// teeth: /bin/sh exists on the machine running this test and does NOT exist in
// the container root, so any implementation that reaches for the host filesystem
// resolves it and fails here.
func TestResolveProgramSearchesTheContainerNotTheHost(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("this host has no /bin/sh, so the guard cannot be exercised")
	}
	root := containerRoot(t, "usr/local/bin/only-here")
	if got, err := ResolveProgram(root, "/", "sh", DefaultPath); err == nil {
		t.Fatalf("ResolveProgram resolved %q; it searched the HOST filesystem, not the container root %s", got, root)
	}
	// And the one that IS in the container resolves, so the negative above is not
	// vacuous.
	if got, err := ResolveProgram(root, "/", "only-here", DefaultPath); err != nil || got != "/usr/local/bin/only-here" {
		t.Fatalf("ResolveProgram = %q, %v; want the container's own program", got, err)
	}
}

// TestPathFromEnv pins the PATH the search uses: the container's own, with the
// POSIX default only as a fallback.
func TestPathFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"unset-falls-back-to-the-posix-default", []string{"HOME=/root"}, DefaultPath},
		{"nil-env-falls-back", nil, DefaultPath},
		{"the-containers-own-path-wins", []string{"HOME=/root", "PATH=/opt/bin"}, "/opt/bin"},
		{"an-empty-assignment-falls-back", []string{"PATH="}, DefaultPath},
		{"the-last-assignment-wins-as-execve-reads-it", []string{"PATH=/first", "PATH=/second"}, "/second"},
		{"a-prefix-lookalike-is-not-path", []string{"PATHEXT=.EXE"}, DefaultPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PathFromEnv(tc.env); got != tc.want {
				t.Errorf("PathFromEnv = %q, want %q", got, tc.want)
			}
		})
	}
}
