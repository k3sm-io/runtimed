//go:build ignore

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

// Command netd-unix-deny is a MANUAL prototype (not a unit test, not built by
// `go build ./...` — it carries the `ignore` build tag and is run with
// `go run prototypes/netd-unix-deny/main.go`). It is the integration-tier proof
// of the runtimed AF_UNIX barrier (the k3sm-netd-helper change, deliverable #1):
//
//	a pod confined by a generated SBPL profile that denies a helper socket path
//	cannot connect() to that AF_UNIX socket, even though the socket is live and
//	the pod can read/write the socket file's directory.
//
// Why this matters: going user-space, runtimed and the pods it spawns share the
// _k3sm uid (no per-pod uid isolation), so LOCAL_PEERCRED on the k3sm-netd helper
// socket cannot tell a pod apart from the legitimate runtime client. The Seatbelt
// default-deny already blocks the connect(), and sandbox.Generate emits an
// EXPLICIT (deny network-outbound (remote unix-socket (literal …))) on top of
// it as the load-bearing, future-proof barrier. This prototype demonstrates the
// live denial on macOS 26.
//
// It uses /usr/bin/sandbox-exec (deprecated but functional on 26.x, exactly as
// the sibling seatbelt-hostpath prototype does) to apply the SAME SBPL the
// production libsandbox path applies. Run:
//
//	cd runtimed && go run prototypes/netd-unix-deny/main.go
//
// Expected: the unsandboxed control connects (CONNECT-OK); the sandboxed run is
// denied (CONNECT-DENIED errno=1 Operation not permitted).
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// connecterSrc is a tiny C connecter: it connect()s an AF_UNIX socket to argv[1]
// and reports CONNECT-OK or CONNECT-DENIED with errno. errno semantics are the
// clean signal that the Seatbelt deny — not a broken socket — blocked the call.
const connecterSrc = `#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc, char **argv) {
	if (argc < 2) { fprintf(stderr, "usage: connecter <socket-path>\n"); return 2; }
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); return 3; }
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		printf("CONNECT-DENIED errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("CONNECT-OK\n");
	close(fd);
	return 0;
}
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "prototype FAILED:", err)
		os.Exit(1)
	}
}

func run() error {
	// The temp dir stands in for the runtimed work-dir, and the pod data volume
	// sits at its production place underneath (<WorkDir>/pods/<id>/rootfs):
	// sandbox.Generate bounds the data volume to the posture's pods root, so a
	// bare temp dir is refused (sandbox.ErrDataVolumeUnbounded).
	workDir, err := os.MkdirTemp("", "netd-unix-deny-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	work := filepath.Join(workDir, "pods", "pod-proto", "rootfs")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}

	// The "helper" socket: a live AF_UNIX listener the pod must not reach.
	sockPath := filepath.Join(work, "netd.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", sockPath, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Compile the connecter into the work dir (also the pod data volume, so the
	// profile re-allows reading/exec'ing it).
	connecter := filepath.Join(work, "connecter")
	csrc := filepath.Join(work, "connecter.c")
	if err := os.WriteFile(csrc, []byte(connecterSrc), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("clang", "-o", connecter, csrc).CombinedOutput(); err != nil {
		return fmt.Errorf("clang unavailable to build connecter (%v): %s", err, out)
	}

	// Generate the production SBPL: default-deny + the EXPLICIT helper-socket deny.
	profile, err := sandbox.Generate(&runtimev1.SandboxProfile{
		DataVolumePath:        work,
		DeniedUnixSocketPaths: []string{sockPath},
	}, sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: workDir}})
	if err != nil {
		return fmt.Errorf("generate sbpl: %w", err)
	}
	profPath := filepath.Join(work, "pod.sb")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		return err
	}
	fmt.Printf(";; generated profile (%s):\n%s\n", profPath, profile)

	// Control: the connecter WITHOUT a sandbox must connect (proves the socket is
	// live and connectable — so a denial under sandbox is the sandbox's doing).
	fmt.Println("== control: unsandboxed connect ==")
	ctl, _ := exec.Command(connecter, sockPath).CombinedOutput()
	fmt.Print(string(ctl))
	if got := string(ctl); !contains(got, "CONNECT-OK") {
		return fmt.Errorf("control did not connect; socket not live? got: %q", got)
	}

	// Under the sandbox, connect() to the helper socket must be DENIED.
	fmt.Println("== sandboxed connect (expect CONNECT-DENIED) ==")
	sb, _ := exec.Command("/usr/bin/sandbox-exec", "-f", profPath, connecter, sockPath).CombinedOutput()
	fmt.Print(string(sb))
	if got := string(sb); !contains(got, "CONNECT-DENIED") {
		return fmt.Errorf("AF_UNIX deny did NOT block the connect; got: %q", got)
	}

	fmt.Println("\nPASS: the SBPL AF_UNIX deny blocked connect() to the helper socket.")
	return nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
