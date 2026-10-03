//go:build darwin && cgo

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
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSpawnKeepGroup pins SpawnSpec.KeepGroup: the child joins the caller's
// process group instead of leading a new session, and stdin arrives on fd 0.
func TestSpawnKeepGroup(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run("keep="+strconv.FormatBool(keep), func(t *testing.T) {
			inR, inW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			pid, err := PosixSpawner{}.Spawn(context.Background(), SpawnSpec{
				Path: "/bin/sh", Argv: []string{"/bin/sh", "-c", "read x; echo $x; sleep 5"}, Env: []string{},
				StdinFD: inR.Fd(), StdoutFD: outW.Fd(), KeepGroup: keep,
			})
			_, _ = inR.Close(), outW.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = unix.Kill(pid, unix.SIGKILL)
				_, _, _ = KqueueReaper{}.WaitExit(context.Background(), pid)
			})
			_, _ = inW.WriteString("hello\n")
			_ = inW.Close()
			_ = outR.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 16)
			n, _ := outR.Read(buf)
			if got := strings.TrimSpace(string(buf[:n])); got != "hello" {
				t.Fatalf("stdin did not reach the child: read %q", got)
			}
			pgid, err := unix.Getpgid(pid)
			if err != nil {
				t.Fatal(err)
			}
			if keep && pgid != unix.Getpgrp() {
				t.Fatalf("KeepGroup child pgid %d, want the caller's %d", pgid, unix.Getpgrp())
			}
			if !keep && pgid != pid {
				t.Fatalf("default child pgid %d, want its own %d", pgid, pid)
			}
		})
	}
}
