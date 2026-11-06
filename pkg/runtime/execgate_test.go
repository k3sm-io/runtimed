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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pathErrorSigner fails as the production signer does, with the host path in the
// error, so a message that passes the error on shows the path to the caller.
type pathErrorSigner struct {
	suffix  string
	signErr error
}

func (s pathErrorSigner) Sign(_ context.Context, _, path string) error {
	return fmt.Errorf("copy %s: %w", path, s.signErr)
}

func (s pathErrorSigner) Check(_ context.Context, _ runtimev1.SignaturePolicy, path string) error {
	if strings.HasSuffix(path, s.suffix) {
		return fmt.Errorf("%w: %s is unsigned", image.ErrSignatureRejected, path)
	}
	return nil
}

// TestExecGateRefusalNamesTheContainerPath pins who reads what: the caller of a
// refused exec gets the path it sent, and only the daemon log names the host
// rootfs.
func TestExecGateRefusalNamesTheContainerPath(t *testing.T) {
	tree := map[string]string{"bin/tool": imageScript}
	cases := []struct {
		name   string
		policy runtimev1.SignaturePolicy
	}{
		{name: "a_check_refusal", policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED},
		{name: "a_sign_failure", policy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			signer := pathErrorSigner{suffix: "/bin/tool", signErr: errors.New("no space left")}
			p := newExecArgvPodCfg(t, cfg, tree, signer, func(box *runtimev1.PodBox) {
				box.SignaturePolicy = tc.policy
			})

			got, _, err := p.exec(t, "/bin/tool")
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("Exec error = %v, want FailedPrecondition", err)
			}
			if got != "" {
				t.Errorf("a refused exec reached the confinement seam with argv[0] %q", got)
			}
			msg := status.Convert(err).Message()
			if !strings.Contains(msg, `"/bin/tool"`) {
				t.Errorf("message %q does not name the path the caller sent", msg)
			}
			if strings.Contains(msg, p.rt.cfg.Root) {
				t.Errorf("message %q shows the caller a host path under %q", msg, p.rt.cfg.Root)
			}
			if line := logs.String(); !strings.Contains(line, p.rootfs) {
				t.Errorf("daemon log %q does not name the host rootfs %q", line, p.rootfs)
			}
		})
	}
}
