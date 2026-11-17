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
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/execsession"
)

// ptyHelperGo is the pod process TestPodProfileAllocatesOnlyItsOwnPTY runs under
// sandbox-exec (one sandbox instance per invocation, as each pod applies its
// own). It uses the libc calls a real program makes (posix_openpt, grantpt,
// unlockpt, ptsname, openpty), not the daemon's in-tree ioctl path. Modes:
//
//	alloc         allocate and exercise a pair; print one "<step> <verdict>"
//	              line per step, then "SLAVE <path>" and "READY"; then read
//	              stdin: "free" closes the pair ("FREED"), "reopen" opens the
//	              slave path again ("REOPEN <verdict>"); EOF exits
//	open <p>...   open each path O_RDWR|O_NOCTTY: "<p> <verdict>"
const ptyHelperGo = `package main

/*
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>

static int k3sm_openpt(int *m, char *name, size_t n) {
	*m = posix_openpt(O_RDWR | O_NOCTTY);
	if (*m < 0) return errno;
	if (grantpt(*m) != 0) return errno;
	if (unlockpt(*m) != 0) return errno;
	char *p = ptsname(*m);
	if (p == NULL) return errno;
	strlcpy(name, p, n);
	return 0;
}
static int k3sm_open(const char *p) {
	int fd = open(p, O_RDWR | O_NOCTTY);
	if (fd < 0) return errno;
	close(fd);
	return 0;
}
static int k3sm_openpty(void) {
	int m, s;
	if (openpty(&m, &s, NULL, NULL, NULL) != 0) return errno;
	close(m); close(s);
	return 0;
}
static int k3sm_winsize(int s, int m) {
	struct winsize ws = { .ws_row = 40, .ws_col = 100 };
	if (ioctl(s, TIOCSWINSZ, &ws) != 0) return errno;
	struct winsize got;
	if (ioctl(m, TIOCGWINSZ, &got) != 0) return errno;
	return (got.ws_row == 40 && got.ws_col == 100) ? 0 : EINVAL;
}
static int k3sm_raw(int s) {
	struct termios t;
	if (tcgetattr(s, &t) != 0) return errno;
	cfmakeraw(&t);
	return tcsetattr(s, TCSANOW, &t) != 0 ? errno : 0;
}
// k3sm_ctty forks a child that makes the slave its controlling terminal and
// writes through /dev/tty; the parent reads the bytes from the master and
// answers, and the child reads the answer through /dev/tty before it exits (a
// session leader's exit hangs the terminal up and flushes what it held).
static int k3sm_ctty(int m, int s) {
	pid_t pid = fork();
	if (pid < 0) return errno;
	if (pid == 0) {
		if (setsid() < 0) _exit(10);
		if (ioctl(s, TIOCSCTTY, 0) != 0) _exit(11);
		int fd = open("/dev/tty", O_RDWR);
		if (fd < 0) _exit(errno == EPERM ? 12 : 13);
		if (write(fd, "CTTY", 4) != 4) _exit(14);
		char c;
		if (read(fd, &c, 1) != 1 || c != 'x') _exit(15);
		_exit(0);
	}
	char buf[8] = {0};
	struct pollfd p = { .fd = m, .events = POLLIN };
	int got = 0;
	while (got < 4 && poll(&p, 1, 10000) == 1) {
		ssize_t n = read(m, buf + got, 4 - got);
		if (n <= 0) break;
		got += n;
	}
	if (got == 4) (void)write(m, "x", 1);
	else kill(pid, SIGKILL);
	int st;
	if (waitpid(pid, &st, 0) < 0) return errno;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return 1000 + WEXITSTATUS(st);
	return (got == 4 && memcmp(buf, "CTTY", 4) == 0) ? 0 : EIO;
}
*/
import "C"

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

func v(rc C.int) string {
	switch {
	case rc == 0:
		return "OK"
	case rc == C.EPERM:
		return "EPERM"
	default:
		return fmt.Sprintf("ERR:%d", int(rc))
	}
}

func open(p string) string {
	cp := C.CString(p)
	defer C.free(unsafe.Pointer(cp))
	return v(C.k3sm_open(cp))
}

func main() {
	switch os.Args[1] {
	case "open":
		for _, p := range os.Args[2:] {
			fmt.Println(p, open(p))
		}
	case "alloc":
		var m C.int
		var name [128]C.char
		if rc := C.k3sm_openpt(&m, &name[0], 128); rc != 0 {
			fmt.Println("posix_openpt", v(rc))
			return
		}
		fmt.Println("posix_openpt OK")
		slave := C.GoString(&name[0])
		s, err := syscall.Open(slave, syscall.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			fmt.Println("open-slave", err)
			return
		}
		fmt.Println("open-slave OK")
		fmt.Println("winsize", v(C.k3sm_winsize(C.int(s), m)))
		fmt.Println("termios", v(C.k3sm_raw(C.int(s))))
		fmt.Println("ctty", v(C.k3sm_ctty(m, C.int(s))))
		fmt.Println("openpty", v(C.k3sm_openpty()))
		out, _ := exec.Command(os.Args[0], "open", slave).Output()
		fmt.Println("exec-child-reopen", string(out[len(slave)+1:len(out)-1]))
		fmt.Println("SLAVE", slave)
		fmt.Println("READY")
		in := bufio.NewScanner(os.Stdin)
		for in.Scan() {
			switch in.Text() {
			case "free":
				syscall.Close(s)
				C.close(m)
				fmt.Println("FREED")
			case "reopen":
				fmt.Println("REOPEN", open(slave))
			}
		}
	}
}
`

// ptyStanzaLines are the directives podPTY must render, exactly.
var ptyStanzaLines = []string{
	`(allow pseudo-tty)`,
	`(literal "/dev/ptmx")`,
	`(literal "/dev/tty"))`,
	`(regex #"^/dev/ttys[0-9][0-9][0-9]+$")`,
	`(extension "com.apple.sandbox.pty")))`,
	`(deny file-ioctl (ioctl-command TIOCSTI) (ioctl-command TIOCCONS))`,
}

// devLiteralsAllowed is every /dev path a pod profile may name: the four read
// literals, the /dev/null write and the pty stanza. A new /dev grant is a red
// here until it is added on purpose.
var devLiteralsAllowed = map[string]bool{
	`(literal "/dev/null") (literal "/dev/zero")`:       true,
	`(literal "/dev/random") (literal "/dev/urandom"))`: true,
	`(literal "/dev/null"))`:                            true,
	`(literal "/dev/ptmx")`:                             true,
	`(literal "/dev/tty"))`:                             true,
	`(regex #"^/dev/ttys[0-9][0-9][0-9]+$")`:            true,
}

// TestPodProfileAllocatesOnlyItsOwnPTY pins the pod profile's terminal reach by
// effect. Pod A, under the generated profile, allocates a pair with
// posix_openpt/grantpt/unlockpt/ptsname, opens the slave, sets the window size
// and raw mode, makes it a child's controlling terminal and writes through
// /dev/tty, allocates a second pair with openpty, and an exec'd child reopens
// the slave by path. Pod B, under identical profile text and the same uid, is
// denied A's live slave, a host terminal, /dev/console and the legacy mode-0666
// BSD slave /dev/ttys0, while it may still clone a pair of its own. The host
// opening its terminal by path is the control: the denials are Seatbelt's, not
// the mode bits'. Finally A frees its pair, the host allocates until it gets
// the same number, and A is denied it: the pty extension does not outlive the
// pair.
func TestPodProfileAllocatesOnlyItsOwnPTY(t *testing.T) {
	workDir, err := os.MkdirTemp("/tmp", "pt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	binDir := filepath.Join(workDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prof, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs"),
		ExtraReadPaths: []string{binDir},
	}, GenerateOptions{Posture: Posture{WorkDir: workDir}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range ptyStanzaLines {
		if !containsDirective(prof, want) {
			t.Errorf("the profile lacks %s", want)
		}
	}
	for _, l := range strings.Split(prof, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, ";") || !strings.Contains(l, "/dev") {
			continue
		}
		if !devLiteralsAllowed[l] {
			t.Errorf("unexpected /dev rule %q: a pod gets only the pty stanza and the four read literals", l)
		}
	}

	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt is darwin-only")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the helper")
	}
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(src, []byte(ptyHelperGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "ptyhelper")
	build := exec.Command(goTool, "build", "-o", bin, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	sb := filepath.Join(workDir, "pod.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}

	// The control first: the base profile without the stanza cannot clone.
	base := strings.Replace(prof, podPTY, "", 1)
	baseSB := filepath.Join(workDir, "base.sb")
	if err := os.WriteFile(baseSB, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("/usr/bin/sandbox-exec", "-f", baseSB, bin, "alloc").Output(); strings.TrimSpace(string(out)) != "posix_openpt EPERM" {
		t.Fatalf("control: without the pty stanza posix_openpt = %q, want EPERM", out)
	}

	// Pod A.
	a := exec.Command("/usr/bin/sandbox-exec", "-f", sb, bin, "alloc")
	stdin, err := a.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := a.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	a.Stderr = os.Stderr
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = a.Process.Kill(); _ = a.Wait() })
	r := bufio.NewReader(stdout)
	// A plain blocking read: the helper is a real process, and a hang is
	// caught by go test's own -timeout rather than a wall-clock wait here.
	readLine := func() string {
		t.Helper()
		s, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("pod A's helper output ended: %v (last %q)", err, s)
		}
		return strings.TrimSpace(s)
	}
	var slave string
	for {
		l := readLine()
		if l == "READY" {
			break
		}
		if p, ok := strings.CutPrefix(l, "SLAVE "); ok {
			slave = p
			continue
		}
		if !strings.HasSuffix(l, " OK") {
			t.Fatalf("pod A, inside its own pty: %q, want OK\n--- profile ---\n%s", l, prof)
		}
	}
	if !strings.HasPrefix(slave, "/dev/ttys") {
		t.Fatalf("pod A's slave = %q, want a /dev/ttysNNN clone", slave)
	}

	// A host terminal, opened outside any sandbox, that no pod inherited.
	hostM, hostS, err := execsession.OpenPTY()
	if err != nil {
		t.Fatalf("host OpenPTY: %v", err)
	}
	defer hostM.Close()
	defer hostS.Close()
	if f, err := os.OpenFile(hostS.Name(), os.O_RDWR|syscall.O_NOCTTY, 0); err != nil {
		t.Fatalf("control: the host could not open its own slave by path: %v", err)
	} else {
		f.Close()
	}

	// Pod B: same profile text, same uid, its own sandbox instance.
	targets := []string{slave, hostS.Name(), "/dev/console"}
	if _, err := os.Stat("/dev/ttys0"); err == nil {
		targets = append(targets, "/dev/ttys0") // legacy BSD slave, mode 0666
	}
	out, err := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb, bin, "open"}, append(targets, "/dev/ptmx")...)...).Output()
	if err != nil {
		t.Fatalf("pod B: %v", err)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p, verdict, ok := strings.Cut(l, " "); ok {
			got[p] = verdict
		}
	}
	for _, p := range targets {
		if got[p] != "EPERM" {
			t.Errorf("pod B opening %s = %q, want EPERM (not its pty)", p, got[p])
		}
	}
	if got["/dev/ptmx"] != "OK" {
		t.Errorf("pod B cloning a pair of its own = %q, want OK", got["/dev/ptmx"])
	}

	// Reuse: A frees its pair; the host takes the same number; A is denied it.
	if _, err := io.WriteString(stdin, "free\n"); err != nil {
		t.Fatal(err)
	}
	if l := readLine(); l != "FREED" {
		t.Fatalf("pod A: %q, want FREED", l)
	}
	var held []*os.File
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	reused := false
	for i := 0; i < 64 && !reused; i++ {
		m, s, err := execsession.OpenPTY()
		if err != nil {
			t.Fatalf("host OpenPTY: %v", err)
		}
		held = append(held, m, s)
		reused = s.Name() == slave
	}
	if !reused {
		t.Skipf("every other leg passed; the reuse leg did not run: the host was not given %s again in 64 allocations (another process took it)", slave)
	}
	if _, err := io.WriteString(stdin, "reopen\n"); err != nil {
		t.Fatal(err)
	}
	if l := readLine(); l != "REOPEN EPERM" {
		t.Errorf("pod A reopening %s after the host took it = %q, want REOPEN EPERM (a stale pty extension)", slave, l)
	}
}
