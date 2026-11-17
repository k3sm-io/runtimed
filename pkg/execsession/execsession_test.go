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

package execsession

import (
	"context"
	"io"
	"os/exec"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeStream is a Stream with no client input: Recv reports EOF at once.
type fakeStream struct {
	mu   sync.Mutex
	sent []*runtimev1.ExecResponse
}

func (f *fakeStream) Context() context.Context { return context.Background() }
func (f *fakeStream) Recv() (*runtimev1.ExecRequest, error) {
	return nil, io.EOF
}
func (f *fakeStream) Send(r *runtimev1.ExecResponse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, r)
	return nil
}

// TestRunWithoutTTYLeadsItsOwnSession pins that an exec session, tty or not,
// is a session leader (sid == pgid == pid). A non-tty session that stayed in
// its parent's session would inherit the parent's controlling terminal, and
// the pod profile allows /dev/tty, so a pod process could open the terminal a
// foreground daemon runs in. The check reads the session id, so it holds
// whether or not the test itself has a controlling terminal.
func TestRunWithoutTTYLeadsItsOwnSession(t *testing.T) {
	for _, tty := range []bool{false, true} {
		name := "no tty"
		if tty {
			name = "tty"
		}
		t.Run(name, func(t *testing.T) {
			var sid, pgid, pid int
			var serr, gerr error
			cmd := exec.Command("/bin/sleep", "0.3")
			err := Run(&fakeStream{}, cmd, tty, false, func(p int) {
				pid = p
				sid, serr = unix.Getsid(p)
				pgid, gerr = unix.Getpgid(p)
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if serr != nil || gerr != nil {
				t.Fatalf("getsid/getpgid of %d: %v, %v", pid, serr, gerr)
			}
			if sid != pid || pgid != pid {
				t.Errorf("session %d, group %d, pid %d: want the session to lead its own session and group", sid, pgid, pid)
			}
		})
	}
}
