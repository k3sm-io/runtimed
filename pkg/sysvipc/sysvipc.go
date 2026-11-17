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

// Package sysvipc lists, inspects and removes the host's System V IPC objects
// (shared memory segments, semaphore sets and message queues). It is the OS
// seam of runtimed's SysV sweeper (pkg/runtime/sysvsweep.go) and holds no
// policy: what may be removed is decided there.
//
// Listing runs /usr/bin/ipcs and reads only the kind and id of each row. macOS
// has no public enumeration call (ipcs itself uses a private sysctl
// interface), and the identity fields that matter are read back with
// IPC_STAT, so the parse depends on two columns of a tool whose output format
// has been stable since 4.4BSD. Stat and Remove are the IPC_STAT and IPC_RMID
// control calls, and the kernel's own permission check applies to both: a
// caller that is not root can read and remove only objects whose mode lets it.
package sysvipc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind is the class of a System V IPC object.
type Kind int

// The three System V IPC classes.
const (
	Shm Kind = iota + 1
	Sem
	Msg
)

// String returns the ipcs letter of k.
func (k Kind) String() string {
	switch k {
	case Shm:
		return "shm"
	case Sem:
		return "sem"
	case Msg:
		return "msg"
	}
	return "unknown"
}

// Ref names one object by class and id. An id is reused by the kernel after
// removal, so a Ref alone does not prove identity: compare Key and Ctime of
// two Stats.
type Ref struct {
	Kind Kind
	ID   int
}

// Object is what IPC_STAT reports about one object.
type Object struct {
	Ref
	Key  int64
	UID  uint32 // owner
	CUID uint32 // creator
	// CPID is the creating process (shared memory only; 0 for the others,
	// which record no creator).
	CPID int
	// Nattch is the current attach count (shared memory only).
	Nattch int
	// Used reports whether the object was ever used after creation: a segment
	// attached or detached, a semaphore operated on or holding a nonzero
	// value (SETVAL and SETALL leave no operation time), a queue sent to or
	// read from, or a queue holding messages.
	Used bool
	// Waiters is the number of processes blocked on the object: for a
	// semaphore set, the sum of every semaphore's semncnt and semzcnt, which a
	// blocked semop raises before it completes (and so before Used reads
	// true). 0 for the other kinds, which do not expose one, and for a set
	// already Used or not owned and created by this process's uid, where it
	// decides nothing and is not read.
	Waiters int
	// Ctime is the last change time, which creation sets.
	Ctime time.Time
}

// ErrUnsupported reports a platform with no System V IPC seam.
var ErrUnsupported = errors.New("sysvipc: not supported on this platform")

// ErrGone reports an object that no longer exists (EINVAL or EIDRM from the
// kernel: the id was removed, or never named a live object).
var ErrGone = errors.New("sysvipc: no such object")

// ipcsSections are the section titles `ipcs -m -s -q` prints even when a
// section is empty. Output missing one is a format this parser does not know.
var ipcsSections = []string{"Message Queues:", "Shared Memory:", "Semaphores:"}

// parseIpcs reads the kind and id of every object row of `ipcs -m -s -q`
// output. A row starts with "m", "s" or "q" followed by a numeric id; headers
// and section titles do not. Output without all three section titles is an
// error rather than an empty list, so a changed format stops the sweep loudly
// instead of making it silently find nothing.
func parseIpcs(out []byte) ([]Ref, error) {
	var refs []Ref
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if slices.Contains(ipcsSections, line) {
			seen[line] = true
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var k Kind
		switch f[0] {
		case "m":
			k = Shm
		case "s":
			k = Sem
		case "q":
			k = Msg
		default:
			continue
		}
		id, err := strconv.Atoi(f[1])
		if err != nil || id < 0 {
			return nil, fmt.Errorf("sysvipc: ipcs row %q has no numeric id", sc.Text())
		}
		refs = append(refs, Ref{Kind: k, ID: id})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("sysvipc: read ipcs output: %w", err)
	}
	for _, s := range ipcsSections {
		if !seen[s] {
			return nil, fmt.Errorf("sysvipc: ipcs output has no %q section; unknown format", s)
		}
	}
	return refs, nil
}
