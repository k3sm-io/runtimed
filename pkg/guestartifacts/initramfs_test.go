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

package guestartifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

// fakeInit is the fixed payload every golden assertion composes from. Its
// length is deliberately not a multiple of four, so the data-padding path is
// exercised rather than skipped.
var fakeInit = []byte("k3sm fake init payload\n")

// goldenSHA256 pins the archive ComposeInitramfs produces from fakeInit.
//
// This is the whole point of the package: the artifact is published by digest,
// so a change in the composed bytes that nobody intended must fail a test
// rather than quietly re-mint a pin. Regenerate it ONLY together with a
// deliberate format or layout change, and say which in the commit message.
const (
	goldenSHA256 = "78c83c75c66feb572d561de5baa1b38f7147eab56bb3926c54e4100903d4c481"
	goldenLen    = 848
)

func TestComposeInitramfs(t *testing.T) {
	tests := []struct {
		name      string
		init      []byte
		wantErr   error
		wantLen   int
		wantSHA   string
		wantNames []string
	}{
		{
			name:    "the golden archive is byte-for-byte what we pin",
			init:    fakeInit,
			wantLen: goldenLen,
			wantSHA: goldenSHA256,
			wantNames: []string{
				"dev", "init", "proc", "run", "run/k3sm", "sys", trailerName,
			},
		},
		{
			name:    "a single-byte init still composes",
			init:    []byte{0x7f},
			wantLen: 848 - len(fakeInit) - padLen(len(fakeInit)) + 1 + padLen(1),
			wantNames: []string{
				"dev", "init", "proc", "run", "run/k3sm", "sys", trailerName,
			},
		},
		{
			name:    "an empty init is refused rather than composed",
			init:    nil,
			wantErr: ErrEmptyInit,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := ComposeInitramfs(&buf, tc.init)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ComposeInitramfs error = %v, want %v", err, tc.wantErr)
				}
				if buf.Len() != 0 {
					t.Errorf("a refused compose wrote %d bytes; it must write none", buf.Len())
				}
				return
			}
			if err != nil {
				t.Fatalf("ComposeInitramfs: %v", err)
			}
			if buf.Len() != tc.wantLen {
				t.Errorf("archive length = %d, want %d", buf.Len(), tc.wantLen)
			}
			if tc.wantSHA != "" {
				sum := sha256.Sum256(buf.Bytes())
				if got := hex.EncodeToString(sum[:]); got != tc.wantSHA {
					t.Errorf("archive sha256 = %s, want %s", got, tc.wantSHA)
				}
			}
			members, err := parseNewc(buf.Bytes())
			if err != nil {
				t.Fatalf("parse composed archive: %v", err)
			}
			var names []string
			for _, m := range members {
				names = append(names, m.name)
			}
			if fmt.Sprint(names) != fmt.Sprint(tc.wantNames) {
				t.Errorf("member names = %v, want %v", names, tc.wantNames)
			}
		})
	}
}

// TestComposeInitramfsIsDeterministic is the assertion the digest pin rests
// on. It composes twice in one process, which catches map-iteration order and
// any other nondeterminism inside the composer; the constant-time inputs
// (mtime, uid, gid, inode) are asserted by TestComposeInitramfsRoundTrip.
func TestComposeInitramfsIsDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := ComposeInitramfs(&a, fakeInit); err != nil {
		t.Fatalf("first compose: %v", err)
	}
	if err := ComposeInitramfs(&b, fakeInit); err != nil {
		t.Fatalf("second compose: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("two composes of the same input differ: %d vs %d bytes", a.Len(), b.Len())
	}
}

func TestComposeInitramfsRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := ComposeInitramfs(&buf, fakeInit); err != nil {
		t.Fatalf("ComposeInitramfs: %v", err)
	}
	members, err := parseNewc(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Every field the host could otherwise leak into the archive is pinned.
	for i, m := range members {
		if m.name == trailerName {
			continue
		}
		if m.uid != 0 || m.gid != 0 {
			t.Errorf("%s: uid/gid = %d/%d, want 0/0", m.name, m.uid, m.gid)
		}
		if m.mtime != 0 {
			t.Errorf("%s: mtime = %d, want 0", m.name, m.mtime)
		}
		if want := uint32(i + 1); m.ino != want {
			t.Errorf("%s: ino = %d, want the sequential %d", m.name, m.ino, want)
		}
	}

	byName := map[string]member{}
	for _, m := range members {
		byName[m.name] = m
	}

	init, ok := byName["init"]
	if !ok {
		t.Fatal("the archive carries no /init")
	}
	if got, want := init.mode, modeTypeFile|initMode; got != want {
		t.Errorf("init mode = %#o, want %#o", got, want)
	}
	if !bytes.Equal(init.data, fakeInit) {
		t.Errorf("init data = %q, want %q", init.data, fakeInit)
	}

	for _, d := range []string{"dev", "proc", "sys", "run", "run/k3sm"} {
		m, ok := byName[d]
		if !ok {
			t.Errorf("the archive carries no %s directory", d)
			continue
		}
		if got, want := m.mode, modeTypeDir|dirMode; got != want {
			t.Errorf("%s mode = %#o, want %#o", d, got, want)
		}
		if len(m.data) != 0 {
			t.Errorf("%s carries %d bytes of data; a directory carries none", d, len(m.data))
		}
	}

	last := members[len(members)-1]
	if last.name != trailerName {
		t.Errorf("last member = %q, want %q", last.name, trailerName)
	}
	if len(last.data) != 0 {
		t.Errorf("the trailer carries %d bytes of data, want 0", len(last.data))
	}
}

// member is one parsed newc entry.
type member struct {
	ino, mode, uid, gid, nlink, mtime uint32
	name                              string
	data                              []byte
}

// parseNewc is an independent reader for the format ComposeInitramfs writes.
// It is deliberately a second implementation rather than a reuse of the
// writer's helpers: a round-trip through shared code proves only that the code
// agrees with itself, which is exactly what a format test must not assume.
func parseNewc(b []byte) ([]member, error) {
	var out []member
	off := 0
	for {
		if off+newcHeaderSize > len(b) {
			return nil, fmt.Errorf("truncated header at offset %d", off)
		}
		if got := string(b[off : off+6]); got != newcMagic {
			return nil, fmt.Errorf("bad magic %q at offset %d", got, off)
		}
		fields := make([]uint32, 13)
		for i := range fields {
			start := off + 6 + i*8
			v, err := strconv.ParseUint(string(b[start:start+8]), 16, 32)
			if err != nil {
				return nil, fmt.Errorf("field %d at offset %d: %w", i, off, err)
			}
			fields[i] = uint32(v)
		}
		filesize, namesize := int(fields[6]), int(fields[11])

		nameStart := off + newcHeaderSize
		if nameStart+namesize > len(b) {
			return nil, fmt.Errorf("truncated name at offset %d", nameStart)
		}
		raw := b[nameStart : nameStart+namesize]
		if raw[len(raw)-1] != 0 {
			return nil, fmt.Errorf("name at offset %d is not NUL-terminated", nameStart)
		}
		m := member{
			ino: fields[0], mode: fields[1], uid: fields[2], gid: fields[3],
			nlink: fields[4], mtime: fields[5],
			name: string(raw[:len(raw)-1]),
		}

		dataStart := nameStart + namesize + padLen(newcHeaderSize+namesize)
		if dataStart+filesize > len(b) {
			return nil, fmt.Errorf("truncated data for %q", m.name)
		}
		m.data = b[dataStart : dataStart+filesize]
		out = append(out, m)

		off = dataStart + filesize + padLen(filesize)
		if m.name == trailerName {
			break
		}
	}
	if off != len(b) {
		return nil, fmt.Errorf("%d trailing bytes after the trailer; the archive must end there", len(b)-off)
	}
	return out, nil
}
