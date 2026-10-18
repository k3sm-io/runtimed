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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// POSIX named semaphores in a native pod.
//
// macOS keeps POSIX named semaphores in ONE host-wide namespace: there is no
// per-container IPC namespace as on Linux, where a container's semaphores live
// in its own /dev/shm. A bare (allow ipc-posix-sem) would therefore let any pod
// open, post, wait on or unlink any other pod's semaphore by name. So the grant
// is filtered by a per-pod name prefix, and the kernel profile is the whole
// enforcement: the Seatbelt filter judges the name the kernel receives, so a pod
// that names a semaphore outside its prefix gets EPERM however it reached the
// call. The path-rebase shim's sem_open/sem_unlink rewrite (shim/
// pathrebase_shim.c) only moves a cooperative workload's names INTO its prefix;
// a process that skips the shim keeps its own names and gets EPERM, never
// another pod's semaphore.
//
// The SBPL spelling was measured, not assumed (macOS 27.0.1, sandbox_init under
// (deny default) + (import "system.sb")): (ipc-posix-name-prefix "<P>") matches
// the name byte-for-byte INCLUDING the leading '/', so the prefix is rendered
// with it; a prefix without the '/' matches nothing. The combined ipc-posix-sem
// operation and the split create/open/post/wait/unlink operations behave the
// same; the combined one is emitted. Opening or unlinking a semaphore created
// under another prefix is EPERM, and a name that is the prefix minus its
// trailing '.' is EPERM too (the separator is part of the match).
//
// The prefix is "/k3sm.<8 hex>." (PosixSemPrefixLen bytes): fixed length and
// terminated by a separator, so no pod's prefix is a prefix of another's. The
// 8 hex are the first 32 bits of sha256 over the pod UID and nothing else,
// so a pod cannot choose its prefix, and the derivation needs no input a pod
// supplies. Two pods on one node collide only on a 32-bit hash collision of
// their UIDs, which then share a semaphore namespace; that residual is stated
// here rather than hidden.
//
// One residual is the kernel's, and is not changed by the grant: sem_open
// without O_CREAT and sem_unlink look the name up before the sandbox check, so
// a foreign name that does not exist answers ENOENT while one that exists
// answers EPERM. A pod can learn whether a given name exists on the host
// (measured with and without the grant); it cannot open, post, wait on or
// unlink it.
//
// Names are short on this kernel: sem_open refuses a name of PSEMNAMLEN (31)
// bytes or more with ENAMETOOLONG, so a prefixed name has PosixSemNameMax -
// PosixSemPrefixLen = 15 bytes left for the workload's own part. The shim
// shortens a longer part to a hash.
//
// No per-pod cap is promised. kern.posix.sem.max bounds the semaphores of the
// whole host, and every pod draws on that one pool.

// PosixSemPrefixLen is the length of every pod's semaphore prefix
// ("/k3sm." + 8 hex + ".").
const PosixSemPrefixLen = 15

// PosixSemNameMax is the longest semaphore name sem_open accepts on macOS
// (strlen < PSEMNAMLEN, which is 31).
const PosixSemNameMax = 30

// ErrInvalidPodUID reports an empty pod UID, from which no semaphore prefix can
// be derived.
var ErrInvalidPodUID = errors.New("sbpl: pod uid is empty")

// errPosixSemPrefixShape reports a derived prefix that is not exactly
// "/k3sm.<8 lowercase hex>.". The derivation cannot produce one; the check is
// the guard on what is spliced into SBPL, kept independent of the derivation.
var errPosixSemPrefixShape = errors.New("sbpl: posix semaphore prefix has the wrong shape")

// posixSemPrefixRE is the only shape a prefix may have before it is spliced
// into a profile: nothing in it can close the SBPL string literal.
var posixSemPrefixRE = regexp.MustCompile(`^/k3sm\.[0-9a-f]{8}\.$`)

// PosixSemPrefix returns the POSIX semaphore name prefix of the pod with the
// given UID: "/k3sm." + the first 8 hex digits of sha256(podUID) + ".". The
// profile grants exactly that prefix (Generate), and the runtime publishes it to
// the path-rebase shim so a workload's names land inside it.
func PosixSemPrefix(podUID string) (string, error) {
	if podUID == "" {
		return "", ErrInvalidPodUID
	}
	sum := sha256.Sum256([]byte(podUID))
	p := "/k3sm." + hex.EncodeToString(sum[:4]) + "."
	if err := validatePosixSemPrefix(p); err != nil {
		return "", err
	}
	return p, nil
}

// validatePosixSemPrefix checks p against the one allowed shape.
func validatePosixSemPrefix(p string) error {
	if len(p) != PosixSemPrefixLen || !posixSemPrefixRE.MatchString(p) {
		return fmt.Errorf("%w: %q", errPosixSemPrefixShape, p)
	}
	return nil
}

// PosixSemStanza renders the semaphore grant for prefix, or an error when the
// prefix is not the validated shape. It is the one spelling of the rule: Generate
// emits it, the grammar probe compiles it, and the symbol canary compiles it.
func PosixSemStanza(prefix string) (string, error) {
	if err := validatePosixSemPrefix(prefix); err != nil {
		return "", err
	}
	return ";; POSIX semaphores: this pod's own names only (one host-wide namespace;\n" +
		";; the prefix filter is the whole isolation).\n" +
		fmt.Sprintf("(allow ipc-posix-sem (ipc-posix-name-prefix %q))\n", prefix), nil
}

// posixSemProbePrefix is the well-formed prefix the grammar probe compiles.
const posixSemProbePrefix = "/k3sm.00000000."

// posixSemGrammar caches whether this host's libsandbox compiles the stanza.
var (
	posixSemGrammarOnce sync.Once
	posixSemGrammarOK   bool
)

// posixSemGrammarAccepted reports, once per process, whether this host's
// libsandbox compiles the semaphore stanza. Generate emits the grant only when
// it does: a macOS that changed the grammar would otherwise fail sandbox_apply
// for every pod on the node, and with the grant left out a pod's semaphores are
// denied, as they were before the grant existed.
var posixSemGrammarAccepted = func() bool {
	posixSemGrammarOnce.Do(func() {
		stanza, err := PosixSemStanza(posixSemProbePrefix)
		if err != nil {
			return
		}
		posixSemGrammarOK = sbplCompiles("(version 1)\n(deny default)\n(import \"system.sb\")\n" + stanza)
	})
	return posixSemGrammarOK
}
