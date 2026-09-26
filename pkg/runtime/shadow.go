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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// shadowDirEnv is the environment variable that hands Config.ShadowBinDir to
// the path-rebase interposer (shim/pathrebase_shim.c), which applies the same
// rewrite as shadowRewrite to every execve and posix_spawn inside the pod.
const shadowDirEnv = "K3SM_SHADOW_DIR"

// shadowCopies maps each host binary the node keeps a re-signed copy of to the
// copy's file name under Config.ShadowBinDir. It must agree with the
// interposer's k3sm_shadow_map.
//
// /bin/sh maps to bash: /bin/sh is Apple's dispatcher, which re-execs
// /private/var/select/sh, so a copy of it would only hand off to the platform
// shell again. bash run under the basename "sh" enters POSIX mode, which is
// what /bin/sh resolves to by default.
var shadowCopies = map[string]string{
	"/bin/sh":      "bash",
	"/bin/bash":    "bash",
	"/bin/zsh":     "zsh",
	"/bin/dash":    "dash",
	"/usr/bin/env": "env",
}

// shebangMax is how much of a script the kernel reads for its "#!" line
// (XNU's IMG_SHSIZE); a first line longer than that is not one the kernel
// would follow either.
const shebangMax = 512

// shadowExec is the rewritten exec: the file to exec and the argv the program
// sees (argv[0] included, which is NOT the file when bash runs as "sh").
type shadowExec struct {
	path string
	argv []string
	// script reports that path is the interpreter of a script (rule 3), so
	// path is the Mach-O the kernel would have run for it.
	script bool
}

// execRewrite is the inputs of shadowRewrite beyond the exec itself.
type execRewrite struct {
	// dir is Config.ShadowBinDir; empty disables the shadow copies.
	dir string
	// readHead reads up to shebangMax bytes of a regular file.
	readHead func(string) ([]byte, error)
	// rebase maps a path under one of the container's mount prefixes to its
	// materialized copy, exactly as the interposer's k3sm_rebase does; nil is
	// the identity (no mounts, or no path shim).
	rebase func(string) string
	// admit is asked before a copy is used (the ownership check); nil admits.
	// A refused copy falls through to the next rule, as the interposer does.
	admit func(copyPath string) bool
}

// shadowRewrite decides what an exec of path with argv becomes, in the same
// order the interposer's k3sm_plan_exec uses, and returns it (ok=false: exec
// unchanged).
//
// # Why
//
// dyld scrubs DYLD_* from the environment of a restricted process (a platform
// binary, or one carrying CS_RESTRICT), so a pod that starts through /bin/sh
// loses the DNS and path-rebase shims, and with them the per-namespace DNS
// precedence and the bind/connect source discipline, for the shell and every
// descendant. An ad-hoc re-signed copy of the same binary is neither, so the
// variables survive. The copies are made by the node installer, root-owned.
//
// # The rules
//
//  1. The target is rebased (rw.rebase): a path under a mount prefix becomes
//     its materialized copy, as an open() of it would.
//  2. The rebased target is one of the five (shadowCopies) and the copy is
//     admitted: exec the copy with argv unchanged, except that the /bin/sh
//     copy gets argv[0] "sh" unless argv[0] already ends in "sh" as a path
//     component ("/bin/sh" stays "/bin/sh").
//  3. The rebased target is a script (its first two bytes are "#!"): when its
//     interpreter is one of the five and the copy is admitted, exec the copy;
//     else, when the interpreter itself lies under a mount, exec its rebased
//     copy. Either way with the argv the kernel would have built,
//     [interp, arg?, script, argv[1:]...], where arg is everything after the
//     interpreter on the line as ONE argument (XNU's imgact_shell), interp
//     gets the same "sh" treatment, and script is the rebased path. The
//     kernel's own shebang follow happens inside execve, where no interposer
//     can see it, which is why the script is read here.
//  4. Otherwise the rebased target when the rebase moved it, else unchanged.
//
// Recursion is bounded to that one level: the interpreter is exec'd as a
// binary, never followed as a script here.
//
// TOCTOU: the script can change between this read and the exec. The cost is
// the pre-rewrite behaviour for that one exec (the kernel follows whatever
// shebang it then finds), never a wider grant: a rewrite only ever substitutes
// a node-owned copy of a binary the pod could already run, or a file the pod's
// own mount already exposes.
func shadowRewrite(path string, argv []string, rw execRewrite) (shadowExec, bool) {
	if len(argv) == 0 || (rw.dir == "" && rw.rebase == nil) {
		return shadowExec{}, false
	}
	rebase := rw.rebase
	if rebase == nil {
		rebase = func(p string) string { return p }
	}
	admit := func(copyPath string) bool { return rw.admit == nil || rw.admit(copyPath) }
	target := rebase(path)

	if copyName, ok := shadowCopies[target]; ok && rw.dir != "" {
		if cp := filepath.Join(rw.dir, copyName); admit(cp) {
			out := append([]string{}, argv...)
			if target == "/bin/sh" {
				out[0] = asSh(out[0])
			}
			return shadowExec{path: cp, argv: out}, true
		}
	}
	if head, err := rw.readHead(target); err == nil {
		if interp, arg, ok := parseShebang(head); ok {
			script := func(file, name string) (shadowExec, bool) {
				out := []string{name}
				if arg != "" {
					out = append(out, arg)
				}
				out = append(out, target)
				out = append(out, argv[1:]...)
				return shadowExec{path: file, argv: out, script: true}, true
			}
			if copyName, ok := shadowCopies[interp]; ok && rw.dir != "" {
				if cp := filepath.Join(rw.dir, copyName); admit(cp) {
					name := interp
					if interp == "/bin/sh" {
						name = asSh(interp)
					}
					return script(cp, name)
				}
			}
			if ri := rebase(interp); ri != interp {
				return script(ri, interp)
			}
		}
	}
	if target != path {
		return shadowExec{path: target, argv: append([]string{}, argv...)}, true
	}
	return shadowExec{}, false
}

// mountRebaser returns the Go twin of the interposer's k3sm_rebase for one
// container, rule for rule: rootfs and each prefix lose trailing slashes (never
// below one character), a prefix matches a path exactly or '/'-bounded (never
// a sibling like /etcX), the first match wins, and a result that would not fit
// PATH_MAX leaves the path unrewritten. It returns nil when the interposer's
// rebase would be disabled (rootfs not absolute, no absolute prefix).
func mountRebaser(rootfs string, mounts []string) func(string) string {
	if !strings.HasPrefix(rootfs, "/") {
		return nil
	}
	root := trimSlashes(rootfs)
	var prefixes []string
	for _, m := range mounts {
		if strings.HasPrefix(m, "/") {
			prefixes = append(prefixes, trimSlashes(m))
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return func(p string) string {
		if !strings.HasPrefix(p, "/") {
			return p
		}
		for _, m := range prefixes {
			if !strings.HasPrefix(p, m) || (len(p) > len(m) && p[len(m)] != '/') {
				continue
			}
			if len(root)+len(p) >= pathMax {
				return p
			}
			return root + p
		}
		return p
	}
}

// pathMax is the interposer's buffer bound (PATH_MAX on darwin).
const pathMax = 1024

// trimSlashes drops trailing slashes, keeping at least one character.
func trimSlashes(s string) string {
	for len(s) > 1 && strings.HasSuffix(s, "/") {
		s = s[:len(s)-1]
	}
	return s
}

// asSh returns argv0 when its last path component is "sh", else "sh": bash
// decides POSIX mode from exactly that basename.
func asSh(argv0 string) string {
	if filepath.Base(argv0) == "sh" {
		return argv0
	}
	return "sh"
}

// parseShebang parses a "#!interp [arg]" first line the way XNU does:
// optional blanks, the interpreter up to the next blank, then the rest of the
// line with surrounding blanks trimmed as a single argument. A head with no
// complete first line is not a shebang (the kernel would not follow it).
func parseShebang(head []byte) (interp, arg string, ok bool) {
	if len(head) > shebangMax {
		head = head[:shebangMax]
	}
	if !bytes.HasPrefix(head, []byte("#!")) {
		return "", "", false
	}
	line, _, found := bytes.Cut(head[2:], []byte("\n"))
	if !found {
		return "", "", false
	}
	rest := strings.TrimLeft(string(line), " \t")
	interp = rest
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		interp = rest[:i]
		arg = strings.TrimRight(strings.TrimLeft(rest[i:], " \t"), " \t\r")
	}
	if interp == "" {
		return "", "", false
	}
	return interp, arg, true
}

// readShebangHead reads the first shebangMax bytes of path. It opens with
// O_NONBLOCK and reads only a regular file, so a FIFO or a device never blocks
// a container start (the interposer's probe does the same). A short file is
// not an error.
func readShebangHead(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	buf := make([]byte, shebangMax)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return buf[:n], nil
}

// shadowStat is what the trust check needs from an lstat: the owner and the
// raw mode (type and permission bits).
type shadowStat struct {
	uid  uint32
	mode uint32
}

// lstatShadow is the production lstat for the trust check. It never follows a
// symlink, so a link is seen as a link and refused.
func lstatShadow(path string) (shadowStat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return shadowStat{}, err
	}
	return shadowStat{uid: st.Uid, mode: uint32(st.Mode)}, nil
}

// errShadowUntrusted reports a shadow directory or copy that fails the
// ownership/type/mode check.
var errShadowUntrusted = errors.New("shadow copy is not trusted")

// verifyShadow checks the shadow directory and the chosen copy with lstat:
// each must be owned by uid 0, be a directory / a regular file (no symlink),
// and carry no group or other write bit. The error names the path and the
// property that failed.
//
// Why here, at the point of use: this exec is exempt from the signature gate
// (the copy is ad-hoc signed by design), and Seatbelt already lets a pod read
// and exec under /Library, so who may WRITE the directory and the file is the
// whole boundary. A copy some non-root identity could replace would be a code
// path into every pod that starts through a shell. The interposer
// (k3sm_trusted in shim/pathrebase_shim.c) applies the same check.
func verifyShadow(dir, file string, lstat func(string) (shadowStat, error)) error {
	for _, c := range []struct {
		path    string
		wantDir bool
	}{{dir, true}, {file, false}} {
		st, err := lstat(c.path)
		if err != nil {
			return fmt.Errorf("%w: %s: lstat: %v", errShadowUntrusted, c.path, err)
		}
		if st.uid != 0 {
			return fmt.Errorf("%w: %s: owned by uid %d, not root", errShadowUntrusted, c.path, st.uid)
		}
		switch typ := st.mode & unix.S_IFMT; {
		case typ == unix.S_IFLNK:
			return fmt.Errorf("%w: %s: is a symlink", errShadowUntrusted, c.path)
		case c.wantDir && typ != unix.S_IFDIR:
			return fmt.Errorf("%w: %s: not a directory", errShadowUntrusted, c.path)
		case !c.wantDir && typ != unix.S_IFREG:
			return fmt.Errorf("%w: %s: not a regular file", errShadowUntrusted, c.path)
		}
		if st.mode&(unix.S_IWGRP|unix.S_IWOTH) != 0 {
			return fmt.Errorf("%w: %s: group- or world-writable (mode %#o)", errShadowUntrusted, c.path, st.mode&0o7777)
		}
	}
	return nil
}

// shadowExecFor applies shadowRewrite to a host-binary container. A copy is
// admitted only if verifyShadow passes for the directory and the file; a
// refused copy (a missing one on a node whose install predates the shadow set,
// a damaged or tampered one) gets a Warn naming the path and the property, and
// the exec falls through to the next rule, ending at the host binary exactly as
// before this feature: never the unverified copy. The restricted-main-process
// detection then reports the lost shim.
//
// rebase is the container's mount rebase (mountRebaser), or nil.
func (r *Runtime) shadowExecFor(podID, container string, rb resolvedBinary, rebase func(string) string) (shadowExec, bool) {
	lstat := r.shadowLstat
	if lstat == nil {
		lstat = lstatShadow
	}
	return shadowRewrite(rb.path, rb.argv, execRewrite{
		dir:      r.cfg.ShadowBinDir,
		readHead: readShebangHead,
		rebase:   rebase,
		admit: func(copyPath string) bool {
			if err := verifyShadow(r.cfg.ShadowBinDir, copyPath, lstat); err != nil {
				r.log.Warn("shadow shell copy not used; running the host binary (run sudo k3sm install)",
					"pod", podID, "container", container, "path", rb.path, "copy", copyPath, "err", err)
				return false
			}
			return true
		},
	})
}

// hostExecPlan decides, for a host-binary container, the exec argv handed to
// the exec-shim (argv[0] is the file to exec), the argv[0] override the pod
// sees ("" = none), and the path the signature gate answers for.
//
//   - A rewrite of a script (shadowRewrite rule 3) execs its interpreter: the
//     admitted shadow copy, gated on the host interpreter the shebang names
//     (the copy is node infrastructure, never pod code, the same rule as a
//     direct host shell), or an interpreter under a mount, gated as itself.
//   - A script left alone by the rewrite (no shadow set, the copy refused, or
//     an interpreter that is not a host shell, e.g. #!/usr/bin/python3) is
//     gated on its interpreter as the shebang names it; a host-shell
//     interpreter is also exec'd directly with the kernel's argv
//     [interp, arg?, script, args...]. A script is not a Mach-O and cannot
//     carry a signature, so gating the script itself rejected every script
//     entrypoint with "unsigned"; the interpreter is what runs. A
//     non-shell-interpreted script keeps being exec'd as itself (the kernel
//     follows its shebang) and gets the shim-inactive condition when its
//     interpreter is restricted, instead of failing the pod.
//   - A direct host shell rewritten to its copy keeps gating the binary the
//     pod named (the copy is node infrastructure, admitted by verifyShadow);
//     any other host binary gates what is exec'd, which is the path the pod
//     named unless a mount rebase moved it.
//   - A file with no shebang is gated as itself, as before (and an unsigned
//     one is still rejected).
func (r *Runtime) hostExecPlan(podID string, c *runtimev1.Container, rootfs string, rb resolvedBinary) (execArgv []string, argv0, gatePath string) {
	// The interposer rebases a mounted exec target; the spawn does the same so
	// the two agree (only where the interposer is injected).
	var rebase func(string) string
	if paths := containerMountPaths(c); r.cfg.PathShimPath != "" && len(paths) > 0 {
		rebase = mountRebaser(rootfs, paths)
	}
	execArgv, gatePath = rb.argv, rb.path
	if sx, ok := r.shadowExecFor(podID, c.GetName(), rb, rebase); ok {
		execArgv = append([]string{sx.path}, sx.argv[1:]...)
		if sx.argv[0] != sx.path {
			argv0 = sx.argv[0]
		}
		isCopy := r.cfg.ShadowBinDir != "" && filepath.Dir(sx.path) == r.cfg.ShadowBinDir
		switch {
		case sx.script && isCopy:
			// The interpreter as the shebang names it (argv[0] of a script
			// rewrite, one of the shadowCopies keys): the copy is node
			// infrastructure, never pod code, so the policy answers for the
			// host shell exactly as it does for a direct /bin/sh pod.
			return execArgv, argv0, sx.argv[0]
		case sx.script:
			// An interpreter under a mount: the rebased file is what runs.
			return execArgv, argv0, sx.path
		case isCopy:
			return execArgv, argv0, rb.path
		}
		gatePath = sx.path
	}
	// Not rewritten as a script: if what is exec'd is one, gate its
	// interpreter (and exec a host-shell interpreter directly).
	head, err := readShebangHead(execArgv[0])
	if err != nil {
		return execArgv, argv0, gatePath
	}
	interp, arg, ok := parseShebang(head)
	if !ok {
		return execArgv, argv0, gatePath
	}
	if _, shell := shadowCopies[interp]; shell {
		out := []string{interp}
		if arg != "" {
			out = append(out, arg)
		}
		out = append(out, execArgv[0])
		out = append(out, execArgv[1:]...)
		return out, "", interp
	}
	return execArgv, argv0, interp
}
