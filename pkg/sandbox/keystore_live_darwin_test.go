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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/keystorepaths"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// keystoreProbeGo tries one operation on a path and prints OK, DENIED:EPERM or
// the error. cdconnect chdirs to its path and connects to the relative name in
// its third argument; link hard-links its path to the third argument.
const keystoreProbeGo = `package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	op, path := os.Args[1], os.Args[2]
	var err error
	switch op {
	case "connect":
		var c net.Conn
		if c, err = net.Dial("unix", path); err == nil {
			c.Close()
		}
	case "cdconnect":
		if err = os.Chdir(path); err == nil {
			var c net.Conn
			if c, err = net.Dial("unix", os.Args[3]); err == nil {
				c.Close()
			}
		}
	case "read":
		_, err = os.ReadFile(path)
	case "link":
		err = os.Link(path, os.Args[3])
	case "stat":
		_, err = os.Lstat(path)
	case "exists":
		err = syscall.Access(path, 0)
	}
	switch {
	case err == nil:
		fmt.Println("OK")
	case errors.Is(err, syscall.EPERM):
		fmt.Println("DENIED:EPERM")
	default:
		fmt.Printf("ERR:%v\n", err)
	}
}
`

// TestKeystoreDeniesUnderSandboxExec applies a real pod profile, and the shim
// profile built on it, to a probe and measures every way a pod could reach the
// keystore under a data root it holds a read-write grant on: connect to the
// socket by absolute path, through a symlink planted in the pod's writable
// rootfs, and by relative path after chdir; read, hard-link, stat and test the
// existence of a keystore file; in every spelling of the data root (as
// created, its /tmp firmlink and the /System/Volumes/Data alias) and of the
// keystore name (as created, upper case, the Kelvin sign and the long s).
// Every keystore attempt must be refused; the same operations on a
// non-keystore sibling are the control and must succeed.
func TestKeystoreDeniesUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the probe")
	}
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "main.go"), []byte(keystoreProbeGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "probe")
	build := exec.Command(goTool, "build", "-o", bin, filepath.Join(binDir, "main.go"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}

	// Short and under /private/tmp: the socket paths must fit sun_path in the
	// longest spelling, and /tmp gives the firmlink spelling.
	base := filepath.Join("/private/tmp", "k3sm-ks-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work, data := filepath.Join(base, "w"), filepath.Join(base, "d")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	listenUnix(t, keystorepaths.SocketPath(data))
	listenUnix(t, filepath.Join(data, "sibling.sock"))
	for _, f := range []string{"keystore-floor.json", "keystore-run/x", "sibling.json"} {
		p := filepath.Join(data, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pod, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:  dataVol,
		AllowNetwork:    true,
		ExtraReadPaths:  []string{binDir, data},
		ExtraWritePaths: []string{data},
	}, GenerateOptions{Posture: Posture{WorkDir: work, DataRoot: data}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	shim, err := ShimProfile(pod, ShimGrant{Dir: filepath.Join(ShimRoot(work), "0a1b2c3d")})
	if err != nil {
		t.Fatalf("ShimProfile: %v", err)
	}

	rootSpellings := map[string]string{
		"as created":           data,
		"/tmp":                 strings.TrimPrefix(data, "/private"),
		"/System/Volumes/Data": dataVolumeAlias + data,
	}
	nameSpellings := map[string]func(string) string{
		"as created":  func(s string) string { return s },
		"upper case":  strings.ToUpper,
		"Kelvin sign": func(s string) string { return strings.Replace(s, "k", "K", 1) },
		"long s":      func(s string) string { return strings.Replace(s, "s", "ſ", 1) },
	}

	for which, prof := range map[string]string{"pod": pod, "shim": shim} {
		t.Run(which, func(t *testing.T) {
			sb := filepath.Join(base, which+".sb")
			if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
				t.Fatal(err)
			}
			n := 0
			run := func(args ...string) string {
				out, _ := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb, bin}, args...)...).CombinedOutput()
				return strings.TrimSpace(string(out))
			}
			fresh := func() string {
				n++
				return filepath.Join(dataVol, which+"-l"+strconv.Itoa(n))
			}
			for rname, root := range rootSpellings {
				for nname, spell := range nameSpellings {
					sockDir := filepath.Join(root, spell(keystorepaths.SockDir))
					sock := filepath.Join(sockDir, keystorepaths.SocketName)
					floor := filepath.Join(root, spell("keystore-floor.json"))
					runX := filepath.Join(root, spell(keystorepaths.RunDir), "x")
					link := fresh()
					if err := os.Symlink(sock, link); err != nil {
						t.Fatal(err)
					}
					attempts := [][]string{
						{"connect", sock},
						{"connect", link},
						{"cdconnect", sockDir, keystorepaths.SocketName},
						{"read", floor},
						{"link", floor, fresh()},
						{"stat", floor},
						{"exists", floor},
						{"read", runX},
						{"stat", runX},
						{"exists", runX},
					}
					for _, a := range attempts {
						got := run(a...)
						t.Logf("%s / root %s / name %s: %s %s: %s", which, rname, nname, a[0], a[1], got)
						if got == "OK" {
							t.Errorf("root %s, name %s: %s %s is allowed", rname, nname, a[0], a[1])
						}
					}
				}
				sib := filepath.Join(root, "sibling.json")
				for _, a := range [][]string{
					{"connect", filepath.Join(root, "sibling.sock")},
					{"cdconnect", root, "sibling.sock"},
					{"read", sib},
					{"link", sib, fresh()},
					{"stat", sib},
					{"exists", sib},
				} {
					if got := run(a...); got != "OK" {
						t.Errorf("control, root %s: %s %s = %s, want OK", rname, a[0], a[1], got)
					}
				}
			}
		})
	}
}
