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

// Command setsidchild is the B1868 fixture. Run as a pod's container with
// arguments <pidfile> <stay|exit|swap:<dir>:<target>>, it re-executes itself as an intermediate in
// a NEW session (setsid, so a new process group too); the intermediate starts
// /bin/sleep, records the sleeper's pid in <pidfile> and exits at once, so the
// sleeper is reparented to launchd outside the container's group and tree (the
// shape of Yureisha's agentd worker). The container then stays, or exits. In
// swap mode it first removes <dir> (its own rootfs) and puts a symlink to
// <target> in its place: the hostile pod that tries to pass another pod's
// processes off as its own.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// fail reports why the fixture stopped (the container log carries stderr).
func fail(code int, what string, err error) {
	fmt.Fprintf(os.Stderr, "setsidchild: %s: %v\n", what, err)
	os.Exit(code)
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "mid" {
		mid(os.Args[2])
		return
	}
	if len(os.Args) < 3 {
		fail(2, "usage: setsidchild <pidfile> <mode>", nil)
	}
	self, err := os.Executable()
	if err != nil {
		fail(3, "executable", err)
	}
	pid, err := syscall.ForkExec(self, []string{"setsidchild", "mid", os.Args[1]}, &syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		fail(4, "start the intermediate", err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil || ws.ExitStatus() != 0 {
		fail(5, "intermediate status "+strconv.Itoa(ws.ExitStatus()), err)
	}
	if os.Args[2] == "exit" {
		return
	}
	if parts := strings.SplitN(os.Args[2], ":", 3); len(parts) == 3 && parts[0] == "swap" {
		// Wait for the test to have read the pid file, which the swap removes.
		for {
			if _, err := os.Stat(parts[1] + "/go"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		// Empty the dir, then rmdir it by name: os.RemoveAll on the dir itself
		// opens its parent, which the pod may not read.
		ents, err := os.ReadDir(parts[1])
		if err != nil {
			fail(9, "list the rootfs", err)
		}
		for _, e := range ents {
			if err := os.RemoveAll(parts[1] + "/" + e.Name()); err != nil {
				fail(9, "empty the rootfs", err)
			}
		}
		if err := syscall.Rmdir(parts[1]); err != nil {
			fail(9, "rmdir the rootfs", err)
		}
		if err := os.Symlink(parts[2], parts[1]); err != nil {
			fail(10, "link the rootfs", err)
		}
	}
	time.Sleep(time.Hour)
}

// mid starts the sleeper, records its pid and returns, orphaning it.
func mid(pidFile string) {
	pid, err := syscall.ForkExec("/bin/sleep", []string{"sleep", "300"}, &syscall.ProcAttr{})
	if err != nil {
		fail(6, "start the sleeper", err)
	}
	tmp := pidFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		fail(7, "write the pid file", err)
	}
	if err := os.Rename(tmp, pidFile); err != nil {
		fail(8, "rename the pid file", err)
	}
}
