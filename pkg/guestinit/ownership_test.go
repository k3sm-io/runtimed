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

package guestinit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// recordingTarget is an OwnershipTarget that records every call in order and
// fails the calls it is told to.
type recordingTarget struct {
	calls    []string
	failOpen map[string]bool
	failOp   map[string]bool // "chown a", "chmod a", "setxattr a"
	open     int
}

type recordingNode struct {
	t   *recordingTarget
	rel string
}

func (t *recordingTarget) Open(rel string, kind OwnershipKind) (OwnershipNode, error) {
	t.calls = append(t.calls, fmt.Sprintf("open %s %s", rel, kind))
	if t.failOpen[rel] {
		return nil, errors.New("no such node")
	}
	t.open++
	return &recordingNode{t: t, rel: rel}, nil
}

func (n *recordingNode) op(call string) error {
	n.t.calls = append(n.t.calls, call)
	if n.t.failOp[strings.SplitN(call, " ", 2)[0]+" "+n.rel] {
		return errors.New("EPERM")
	}
	return nil
}

func (n *recordingNode) Chown(uid, gid int64) error {
	return n.op(fmt.Sprintf("chown %s %d:%d", n.rel, uid, gid))
}

func (n *recordingNode) Chmod(mode uint32) error {
	return n.op(fmt.Sprintf("chmod %s %o", n.rel, mode))
}

func (n *recordingNode) Setxattr(name string, value []byte) error {
	return n.op(fmt.Sprintf("setxattr %s %s=%s", n.rel, name, value))
}

func (n *recordingNode) Close() error {
	n.t.open--
	return nil
}

func jsonl(t *testing.T, entries ...image.OwnershipEntry) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// TestApplyOwnershipOrderAndTolerance drives the streaming apply over sidecar
// lines ENCODED BY pkg/image's own type — so a field rename on the host side
// fails here rather than as a silently zero uid in a guest.
func TestApplyOwnershipOrderAndTolerance(t *testing.T) {
	t.Parallel()

	t.Run("chown then chmod then setxattr, symlinks chown only", func(t *testing.T) {
		src := jsonl(t,
			image.OwnershipEntry{Path: "tmp", Type: image.OwnershipTypeDir, UID: 0, GID: 0, Mode: 0o1777},
			image.OwnershipEntry{Path: "usr/bin/su", Type: image.OwnershipTypeFile, UID: 0, GID: 0, Mode: 0o4755,
				Xattrs: map[string][]byte{"user.b": []byte("2"), "user.a": []byte("1")}},
			image.OwnershipEntry{Path: "var/run", Type: image.OwnershipTypeSymlink, UID: 5, GID: 6, Mode: 0o777},
		)
		tgt := &recordingTarget{}
		rep, err := ApplyOwnership(context.Background(), strings.NewReader(src), tgt)
		if err != nil {
			t.Fatalf("ApplyOwnership: %v", err)
		}
		want := []string{
			"open tmp dir", "chown tmp 0:0", "chmod tmp 1777",
			"open usr/bin/su file", "chown usr/bin/su 0:0", "chmod usr/bin/su 4755",
			"setxattr usr/bin/su user.a=1", "setxattr usr/bin/su user.b=2",
			"open var/run symlink", "chown var/run 5:6",
		}
		if !reflect.DeepEqual(tgt.calls, want) {
			t.Errorf("calls =\n%q\nwant\n%q", tgt.calls, want)
		}
		if rep.Applied != 3 || rep.Failed != 0 {
			t.Errorf("report = %+v, want 3 applied, 0 failed", rep)
		}
		if tgt.open != 0 {
			t.Errorf("%d nodes left open", tgt.open)
		}
	})

	t.Run("one bad entry never stops the walk", func(t *testing.T) {
		src := jsonl(t, image.OwnershipEntry{Path: "a", Type: image.OwnershipTypeFile, Mode: 0o644}) +
			"{not json\n" +
			jsonl(t,
				image.OwnershipEntry{Path: "../etc/shadow", Type: image.OwnershipTypeFile},
				image.OwnershipEntry{Path: "/abs", Type: image.OwnershipTypeFile},
				image.OwnershipEntry{Path: "dev/x", Type: "chardev"},
				image.OwnershipEntry{Path: "gone", Type: image.OwnershipTypeFile},
				image.OwnershipEntry{Path: "suid", Type: image.OwnershipTypeFile, UID: 1, Mode: 0o4755},
				image.OwnershipEntry{Path: "big", Type: image.OwnershipTypeFile, UID: 1 << 32},
			) +
			"\n" + // a blank line is not an entry
			jsonl(t, image.OwnershipEntry{Path: "z", Type: image.OwnershipTypeDir, Mode: 0o755})
		tgt := &recordingTarget{failOpen: map[string]bool{"gone": true}, failOp: map[string]bool{"chown suid": true}}
		rep, err := ApplyOwnership(context.Background(), strings.NewReader(src), tgt)
		if err != nil {
			t.Fatalf("ApplyOwnership: %v", err)
		}
		if rep.Applied != 2 || rep.Failed != 7 {
			t.Errorf("report = %s, want applied=2 failed=7", rep.Summary())
		}
		for _, c := range tgt.calls {
			if strings.HasPrefix(c, "chmod suid") {
				t.Errorf("a failed chown was followed by %q; setuid must not land on the wrong owner", c)
			}
			if strings.Contains(c, "shadow") || strings.Contains(c, "abs") {
				t.Errorf("an escaping path reached the target: %q", c)
			}
		}
		if last := tgt.calls[len(tgt.calls)-1]; last != "chmod z 755" {
			t.Errorf("last call = %q, want the entry after the failures applied", last)
		}
	})

	t.Run("the error detail is bounded, the count is not", func(t *testing.T) {
		src := strings.Repeat("{bad\n", 100)
		rep, err := ApplyOwnership(context.Background(), strings.NewReader(src), &recordingTarget{})
		if err != nil {
			t.Fatalf("ApplyOwnership: %v", err)
		}
		if rep.Failed != 100 || len(rep.Errors) != MaxOwnershipErrors {
			t.Errorf("failed=%d errors=%d, want 100 and %d", rep.Failed, len(rep.Errors), MaxOwnershipErrors)
		}
	})

	t.Run("an over-long line is one failure, skipped to its newline", func(t *testing.T) {
		src := `{"path":"` + strings.Repeat("x", maxOwnershipLine+10) + "\"}\n" +
			jsonl(t, image.OwnershipEntry{Path: "ok", Type: image.OwnershipTypeDir, Mode: 0o755})
		tgt := &recordingTarget{}
		rep, err := ApplyOwnership(context.Background(), strings.NewReader(src), tgt)
		if err != nil {
			t.Fatalf("ApplyOwnership: %v", err)
		}
		if rep.Applied != 1 || rep.Failed != 1 {
			t.Errorf("report = %s, want applied=1 failed=1", rep.Summary())
		}
	})

	t.Run("a final line without a newline is applied", func(t *testing.T) {
		src := strings.TrimSuffix(jsonl(t, image.OwnershipEntry{Path: "last", Type: image.OwnershipTypeDir, Mode: 0o700}), "\n")
		rep, err := ApplyOwnership(context.Background(), strings.NewReader(src), &recordingTarget{})
		if err != nil || rep.Applied != 1 {
			t.Errorf("rep=%+v err=%v, want the unterminated last entry applied", rep, err)
		}
	})

	t.Run("cancellation stops between entries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ApplyOwnership(ctx, strings.NewReader(jsonl(t, image.OwnershipEntry{Path: "a", Type: image.OwnershipTypeDir})), &recordingTarget{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

// TestOwnershipKindsMatchTheHostSet pins the restated kind constants to the
// host's closed set.
func TestOwnershipKindsMatchTheHostSet(t *testing.T) {
	t.Parallel()
	pairs := map[image.OwnershipEntryType]OwnershipKind{
		image.OwnershipTypeDir:     OwnershipDir,
		image.OwnershipTypeFile:    OwnershipFile,
		image.OwnershipTypeSymlink: OwnershipSymlink,
	}
	for host, guest := range pairs {
		if string(host) != string(guest) {
			t.Errorf("host kind %q != guest kind %q", host, guest)
		}
	}
}
