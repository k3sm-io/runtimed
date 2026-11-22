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
// the error, with its errno name when it has one. cdconnect chdirs to its path
// and connects to the relative name in its third argument; link hard-links its
// path to the third argument and rename renames it onto the third argument;
// create makes a new file (O_CREAT|O_EXCL), mkdir a directory, unlink removes
// a file and bind listens on a unix socket at the path.
const keystoreProbeGo = `package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

var errnoNames = map[syscall.Errno]string{
	syscall.EPERM: "EPERM", syscall.EACCES: "EACCES", syscall.ENOENT: "ENOENT",
	syscall.EEXIST: "EEXIST", syscall.ENOTDIR: "ENOTDIR", syscall.EINVAL: "EINVAL",
	syscall.EADDRINUSE: "EADDRINUSE", syscall.ECONNREFUSED: "ECONNREFUSED",
}

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
	case "create":
		var f *os.File
		if f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
			f.Close()
		}
	case "mkdir":
		err = syscall.Mkdir(path, 0o755)
	case "rename":
		err = syscall.Rename(path, os.Args[3])
	case "unlink":
		err = syscall.Unlink(path)
	case "bind":
		var l net.Listener
		if l, err = net.Listen("unix", path); err == nil {
			l.Close()
		}
	default:
		err = fmt.Errorf("unknown op %q", op)
	}
	var errno syscall.Errno
	switch {
	case err == nil:
		fmt.Println("OK")
	case errors.Is(err, syscall.EPERM):
		fmt.Println("DENIED:EPERM")
	case errors.As(err, &errno):
		fmt.Printf("ERR:%s:%v\n", errnoNames[errno], err)
	default:
		fmt.Printf("ERR:%v\n", err)
	}
}
`

// keystoreDenied is the probe's answer to every keystore attempt: Seatbelt
// refuses each operation the stanza denies with EPERM (measured, for every
// attempt below, under the pod and the shim profile).
const keystoreDenied = "DENIED:EPERM"

// TestKeystoreDeniesUnderSandboxExec applies a real pod profile, and the shim
// profile built on it, to a probe and measures every way a pod could reach the
// keystore under a data root it holds a read-write grant on: connect to the
// socket by absolute path, through a symlink planted in the pod's writable
// rootfs, and by relative path after chdir; read, hard-link, stat, test the
// existence of, unlink and rename a sibling onto a keystore file; bind a
// socket inside the socket directory; and, under a second writable data root
// that holds no keystore yet, plant one: create a keystore file, make the
// socket directory, rename a sibling onto a keystore name and bind a socket
// at one. Each runs in every spelling of the data root (as created, its /tmp
// firmlink and the /System/Volumes/Data alias) and of the keystore name (as
// created, upper case, the Kelvin sign and the long s).
//
// Every keystore attempt must answer exactly DENIED:EPERM, not merely fail:
// an attempt that fails for another reason (ENOENT, EEXIST) has not met the
// deny, and a later change could turn it into a success. Outside the sandbox
// every folded spelling reaches the real file, which shows the data volume
// folds the name and the folded spellings are the real keystore. The same
// operations on a non-keystore sibling are the in-sandbox control and must
// succeed; in the keystore root that includes unlinking, renaming and binding
// a sibling name, so the EPERM on the keystore names is the stanza's and not
// that of a write grant the profile lacks.
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
	// longest spelling, and /tmp gives the firmlink spelling. d is the data
	// root that holds a keystore; e is a writable data root that holds none,
	// where a pod would plant one before the server.
	base := filepath.Join("/private/tmp", "k3sm-ks-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work, data, empty := filepath.Join(base, "w"), filepath.Join(base, "d"), filepath.Join(base, "e")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	for _, dir := range []string{dataVol, empty} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
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

	rootSpellings := map[string]func(string) string{
		"as created":           func(r string) string { return r },
		"/tmp":                 func(r string) string { return strings.TrimPrefix(r, "/private") },
		"/System/Volumes/Data": func(r string) string { return dataVolumeAlias + r },
	}
	nameSpellings := map[string]func(string) string{
		"as created":  func(s string) string { return s },
		"upper case":  strings.ToUpper,
		"Kelvin sign": func(s string) string { return strings.Replace(s, "k", "K", 1) },
		"long s":      func(s string) string { return strings.Replace(s, "s", "ſ", 1) },
	}
	probe := func(sb string, args ...string) string {
		cmd := exec.Command(bin, args...)
		if sb != "" {
			cmd = exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb, bin}, args...)...)
		}
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	// Unsandboxed: every spelling of every root and name reaches the real
	// keystore, so a deny that missed a spelling would leave it open.
	for rname, root := range rootSpellings {
		for nname, spell := range nameSpellings {
			r := root(data)
			for _, a := range [][]string{
				{"connect", filepath.Join(r, spell(keystorepaths.SockDir), keystorepaths.SocketName)},
				{"read", filepath.Join(r, spell("keystore-floor.json"))},
				{"read", filepath.Join(r, spell(keystorepaths.RunDir), "x")},
				{"exists", filepath.Join(r, spell("keystore-floor.json"))},
			} {
				if got := probe("", a...); got != "OK" {
					t.Errorf("unsandboxed, root %s, name %s: %s %s = %s, want OK (the volume does not fold this spelling onto the keystore)", rname, nname, a[0], a[1], got)
				}
			}
		}
	}

	for _, dr := range []struct{ name, root string }{{"keystore root", data}, {"empty root", empty}} {
		pod, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:  dataVol,
			AllowNetwork:    true,
			ExtraReadPaths:  []string{binDir, dr.root},
			ExtraWritePaths: []string{dr.root},
		}, GenerateOptions{Posture: Posture{WorkDir: work, DataRoot: dr.root}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		shim, err := ShimProfile(pod, ShimGrant{Dir: filepath.Join(ShimRoot(work), "0a1b2c3d")})
		if err != nil {
			t.Fatalf("ShimProfile: %v", err)
		}
		for which, prof := range map[string]string{"pod": pod, "shim": shim} {
			t.Run(dr.name+"/"+which, func(t *testing.T) {
				sb := filepath.Join(base, which+".sb")
				if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
					t.Fatal(err)
				}
				n := 0
				fresh := func(dir, stem string) string {
					n++
					return filepath.Join(dir, which+"-"+stem+strconv.Itoa(n))
				}
				// sibling makes a file the pod may rename, outside the sandbox.
				sibling := func(dir string) string {
					p := fresh(dir, "s")
					if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
						t.Fatal(err)
					}
					return p
				}
				for rname, rootOf := range rootSpellings {
					root := rootOf(dr.root)
					for nname, spell := range nameSpellings {
						var attempts [][]string
						if dr.root == data {
							sockDir := filepath.Join(root, spell(keystorepaths.SockDir))
							sock := filepath.Join(sockDir, keystorepaths.SocketName)
							floor := filepath.Join(root, spell("keystore-floor.json"))
							runX := filepath.Join(root, spell(keystorepaths.RunDir), "x")
							link := fresh(dataVol, "l")
							if err := os.Symlink(sock, link); err != nil {
								t.Fatal(err)
							}
							attempts = [][]string{
								{"connect", sock},
								{"connect", link},
								{"cdconnect", sockDir, keystorepaths.SocketName},
								{"read", floor},
								{"link", floor, fresh(dataVol, "h")},
								{"stat", floor},
								{"exists", floor},
								{"read", runX},
								{"stat", runX},
								{"exists", runX},
								{"unlink", floor},
								{"unlink", runX},
								{"rename", sibling(dr.root), floor},
								{"rename", floor, fresh(dr.root, "r")},
								{"bind", filepath.Join(sockDir, which+"-b"+strconv.Itoa(n)+".sock")},
							}
						} else {
							attempts = [][]string{
								{"create", filepath.Join(root, spell("keystore-x"))},
								{"mkdir", filepath.Join(root, spell(keystorepaths.SockDir))},
								{"mkdir", filepath.Join(root, spell(keystorepaths.RunDir))},
								{"rename", sibling(dr.root), filepath.Join(root, spell("keystore-floor.json"))},
								{"bind", filepath.Join(root, spell("keystore-b.sock"))},
							}
						}
						for _, a := range attempts {
							got := probe(sb, a...)
							t.Logf("%s / root %s / name %s: %s %s: %s", which, rname, nname, a[0], a[1], got)
							if got != keystoreDenied {
								t.Errorf("root %s, name %s: %s %s = %s, want %s", rname, nname, a[0], a[1], got, keystoreDenied)
							}
						}
					}
					var controls [][]string
					if dr.root == data {
						sib := filepath.Join(root, "sibling.json")
						controls = [][]string{
							{"connect", filepath.Join(root, "sibling.sock")},
							{"cdconnect", root, "sibling.sock"},
							{"read", sib},
							{"link", sib, fresh(dataVol, "h")},
							{"stat", sib},
							{"exists", sib},
							// The writes the keystore attempts above make, on
							// sibling names in the same root under the same
							// write grant: their EPERM is the stanza's, not a
							// missing grant's.
							{"unlink", sibling(dr.root)},
							{"rename", sibling(dr.root), fresh(root, "r")},
							{"bind", fresh(root, "b") + ".sock"},
						}
					} else {
						controls = [][]string{
							{"create", fresh(root, "c")},
							{"mkdir", fresh(root, "m")},
							{"rename", sibling(dr.root), fresh(root, "r")},
							{"unlink", sibling(dr.root)},
							{"bind", fresh(root, "b") + ".sock"},
						}
					}
					for _, a := range controls {
						if got := probe(sb, a...); got != "OK" {
							t.Errorf("control, root %s: %s %s = %s, want OK", rname, a[0], a[1], got)
						}
					}
				}
			})
		}
	}
	// Nothing a denied attempt aimed at was made or changed.
	for _, p := range []string{"keystore-floor.json", "keystore-run/x"} {
		if b, err := os.ReadFile(filepath.Join(data, p)); err != nil || string(b) != "{}" {
			t.Errorf("%s after the attempts: %q, %v, want it unchanged", p, b, err)
		}
	}
	if ents, err := os.ReadDir(empty); err != nil {
		t.Fatal(err)
	} else {
		for _, e := range ents {
			if strings.HasPrefix(foldName(e.Name()), keystorepaths.DataRootPrefix) {
				t.Errorf("a pod planted %s in the empty data root", e.Name())
			}
		}
	}
}
