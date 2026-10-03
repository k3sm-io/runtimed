//go:build integration && darwin

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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodProfileAllowsTheSystemTLSConfig is the canary for the system TLS
// configuration grant: /usr/bin/curl, the stock LibreSSL client, runs as a
// confined pod's main process and completes an HTTPS request to a loopback TLS
// server. Without the /etc/ssl read grant LibreSSL aborts at init ("Auto
// configuration failed ... fopen('/private/etc/ssl/openssl.cnf','rb')
// Operation not permitted") before it dials anything. The paths it opens are
// LibreSSL's per-build compiled-in defaults, not an ABI, so a macOS update that
// moves them turns this red. Loopback only; no external network, no root.
//
// The private-key subdir deny is pinned by TestGenerateSystemTLSConfigRead
// only: /etc/ssl/private does not exist on stock macOS, and a lookup under a
// missing directory fails with ENOENT whether or not the profile denies it, so
// there is no observable denial to assert here without root.
func TestPodProfileAllowsTheSystemTLSConfig(t *testing.T) {
	const curl = "/usr/bin/curl"
	if _, err := os.Stat(curl); err != nil {
		t.Skipf("%s not present: %v", curl, err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	shim := buildExecShim(t)
	posture, dataVol := podVolume(t, "pod-tls")
	profile, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		AllowNetwork:   true,
	}, GenerateOptions{Posture: posture})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	out, err := runUnderShim(t, shim, profile, os.Environ(),
		curl, "-sS", "-k", "-o", "/dev/null", "-w", "%{http_code}", srv.URL)
	if err != nil {
		t.Fatalf("curl under the pod profile failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "200") {
		t.Fatalf("curl under the pod profile: want HTTP 200, got:\n%s", out)
	}
}
