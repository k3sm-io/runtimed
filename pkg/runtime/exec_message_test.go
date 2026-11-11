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

package runtime

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestExecFailureMessageHidesHostPaths pins that an exec failure reply names
// only what the tenant sent: the resolved host path, the pod rootfs and the
// cache root stay in the daemon's one Warn line.
func TestExecFailureMessageHidesHostPaths(t *testing.T) {
	cases := []struct {
		name   string
		argv0  string
		code   codes.Code
		want   string
		marker func(p *execArgvPod) string
		wants  func(p *execArgvPod) []string
		setup  func(p *execArgvPod)
	}{
		{
			name:   "image_program_escapes_the_rootfs",
			argv0:  "/../../etc/x",
			code:   codes.InvalidArgument,
			want:   `exec: "/../../etc/x" resolves outside the container image and was refused`,
			marker: func(p *execArgvPod) string { return ErrImageArgvEscapes.Error() },
			wants: func(p *execArgvPod) []string {
				return []string{p.rootfs, filepath.Join(p.rootfs, "../../etc/x"), p.podID, "container=main"}
			},
		},
		{
			name:   "wrap_command_names_a_staging_path",
			argv0:  "echo",
			code:   codes.Internal,
			want:   `exec: "echo" could not be sandboxed; the daemon log has the cause`,
			marker: func(p *execArgvPod) string { return "PLANTED-STAGING-MARKER" },
			wants: func(p *execArgvPod) []string {
				return []string{plantedStaging(p), p.podID, "container=main"}
			},
			setup: func(p *execArgvPod) {
				p.be.mu.Lock()
				defer p.be.mu.Unlock()
				p.be.wrapErr = fmt.Errorf("stage profile %s: PLANTED-STAGING-MARKER", plantedStaging(p))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			p := newExecArgvPodCfg(t, cfg, nil, nil, nil)
			if tc.setup != nil {
				tc.setup(p)
			}
			before := logs.String()
			_, _, err := p.exec(t, tc.argv0)
			if status.Code(err) != tc.code {
				t.Fatalf("Exec error = %v, want %v", err, tc.code)
			}
			msg := status.Convert(err).Message()
			if msg != tc.want {
				t.Errorf("reply = %q, want %q", msg, tc.want)
			}
			for _, leak := range []string{p.rt.cache.Root(), p.rootfs, plantedStaging(p), tc.marker(p)} {
				if strings.Contains(msg, leak) {
					t.Errorf("reply %q names %q", msg, leak)
				}
			}
			assertLoggedOnce(t, strings.TrimPrefix(logs.String(), before), tc.marker(p), tc.wants(p))
		})
	}
}

// plantedStaging is a sandbox staging path under p's cache root, the shape of
// the sbpl staging file a real WrapCommand failure names.
func plantedStaging(p *execArgvPod) string {
	return filepath.Join(p.rt.cache.Root(), "sbpl-staging", "pod.sb")
}
