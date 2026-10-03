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

package supervisor

import (
	"errors"
	"io/fs"
	"testing"
	"time"
)

// fakeInfo is a minimal fs.FileInfo carrying only a mode.
type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// fakeFS maps a path to a mode, or to an error when errs names it.
type fakeFS struct {
	files map[string]fs.FileMode
	errs  map[string]error
}

func (f fakeFS) stat(p string) (fs.FileInfo, error) {
	if err, ok := f.errs[p]; ok {
		return nil, err
	}
	if m, ok := f.files[p]; ok {
		return fakeInfo{mode: m}, nil
	}
	return nil, fs.ErrNotExist
}

func TestResolveExecPath(t *testing.T) {
	const exe = fs.FileMode(0o755)
	tests := []struct {
		name     string
		cmd      string
		pathEnv  string
		fs       fakeFS
		want     string
		notFound bool
		wantErr  bool
	}{
		{
			name:    "first PATH dir wins over a later one and the default",
			cmd:     "tar",
			pathEnv: "/opt/tools/bin:/usr/bin",
			fs:      fakeFS{files: map[string]fs.FileMode{"/opt/tools/bin/tar": exe, "/usr/bin/tar": exe}},
			want:    "/opt/tools/bin/tar",
		},
		{
			name:    "later PATH dir used when the first lacks the name",
			cmd:     "tar",
			pathEnv: "/opt/tools/bin:/usr/bin",
			fs:      fakeFS{files: map[string]fs.FileMode{"/usr/bin/tar": exe}},
			want:    "/usr/bin/tar",
		},
		{
			name:     "pod PATH replaces the default entirely",
			cmd:      "tar",
			pathEnv:  "/opt/tools/bin",
			fs:       fakeFS{files: map[string]fs.FileMode{"/usr/bin/tar": exe}},
			notFound: true,
		},
		{
			name: "absolute name untouched",
			cmd:  "/usr/bin/true",
			fs:   fakeFS{},
			want: "/usr/bin/true",
		},
		{
			name:    "relative name with a slash untouched",
			cmd:     "bin/app",
			pathEnv: "/usr/bin",
			fs:      fakeFS{files: map[string]fs.FileMode{"/usr/bin/bin/app": exe}},
			want:    "bin/app",
		},
		{
			name: "empty PATH searches the default",
			cmd:  "tar",
			fs:   fakeFS{files: map[string]fs.FileMode{"/bin/tar": exe}},
			want: "/bin/tar",
		},
		{
			name:    "empty and relative elements are skipped",
			cmd:     "app",
			pathEnv: ":.:bin:/usr/bin",
			fs: fakeFS{files: map[string]fs.FileMode{
				"app": exe, "bin/app": exe, "/usr/bin/app": exe,
			}},
			want: "/usr/bin/app",
		},
		{
			name:    "a directory is not a match",
			cmd:     "tool",
			pathEnv: "/a:/b",
			fs:      fakeFS{files: map[string]fs.FileMode{"/a/tool": fs.ModeDir | 0o755, "/b/tool": exe}},
			want:    "/b/tool",
		},
		{
			name:    "a non-executable regular file is skipped",
			cmd:     "tool",
			pathEnv: "/a:/b",
			fs:      fakeFS{files: map[string]fs.FileMode{"/a/tool": 0o644, "/b/tool": 0o700}},
			want:    "/b/tool",
		},
		{
			name:    "a stat error continues to the next dir",
			cmd:     "tool",
			pathEnv: "/denied:/b",
			fs: fakeFS{
				files: map[string]fs.FileMode{"/denied/tool": exe, "/b/tool": exe},
				errs:  map[string]error{"/denied/tool": fs.ErrPermission},
			},
			want: "/b/tool",
		},
		{
			name:     "nothing matches",
			cmd:      "definitely-not-a-binary",
			pathEnv:  "/a:/b",
			fs:       fakeFS{},
			notFound: true,
		},
		{
			name:    "empty name is an error",
			cmd:     "",
			fs:      fakeFS{},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveExecPath(tc.cmd, tc.pathEnv, tc.fs.stat)
			switch {
			case tc.notFound:
				if !errors.Is(err, ErrExecNotFound) {
					t.Fatalf("err = %v, want ErrExecNotFound", err)
				}
				want := `exec: "` + tc.cmd + `": executable not found on the pod's PATH`
				if err.Error() != want {
					t.Errorf("message = %q, want %q", err.Error(), want)
				}
			case tc.wantErr:
				if err == nil {
					t.Fatalf("ResolveExecPath(%q) = %q, want an error", tc.cmd, got)
				}
				if errors.Is(err, ErrExecNotFound) {
					t.Errorf("empty name reported as not-found: %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("ResolveExecPath: %v", err)
				}
				if got != tc.want {
					t.Errorf("ResolveExecPath = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
