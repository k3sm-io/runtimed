/*
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
*/

// Command setsidchild is the B1868 fixture. Run as a pod's container with
// arguments <pidfile> <stay|exit>, it re-executes itself as an intermediate in
// a NEW session (setsid, so a new process group too); the intermediate starts
// /bin/sleep, records the sleeper's pid in <pidfile> and exits at once, so the
// sleeper is reparented to launchd outside the container's group and tree (the
// shape of Yureisha's agentd worker). The container then stays, or exits.
package main

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "mid" {
		mid(os.Args[2])
		return
	}
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		os.Exit(3)
	}
	pid, err := syscall.ForkExec(self, []string{"setsidchild", "mid", os.Args[1]}, &syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		os.Exit(4)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil || ws.ExitStatus() != 0 {
		os.Exit(5)
	}
	if os.Args[2] == "exit" {
		return
	}
	time.Sleep(time.Hour)
}

// mid starts the sleeper, records its pid and returns, orphaning it.
func mid(pidFile string) {
	pid, err := syscall.ForkExec("/bin/sleep", []string{"sleep", "300"}, &syscall.ProcAttr{})
	if err != nil {
		os.Exit(6)
	}
	tmp := pidFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		os.Exit(7)
	}
	if err := os.Rename(tmp, pidFile); err != nil {
		os.Exit(8)
	}
}
