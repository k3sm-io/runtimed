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

package crilog

import (
	"errors"
	"strings"
	"testing"
)

// chunk is one emitted piece, recorded for assertion.
type chunk struct {
	payload string
	partial bool
}

// collect runs the chunker over in and returns what the sink saw.
func collect(t *testing.T, in string) []chunk {
	t.Helper()
	var got []chunk
	if err := Chunk(strings.NewReader(in), func(b []byte, partial bool) error {
		got = append(got, chunk{payload: string(b), partial: partial})
		return nil
	}); err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	return got
}

// TestChunkerLineSemantics pins the line splitting inside the bound: this is
// the behaviour a reader reassembles from, so every shape a container can emit
// — terminated, unterminated, empty, CRLF — is named.
func TestChunkerLineSemantics(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []chunk
	}{
		{"empty-stream", "", nil},
		{"one-terminated-line", "a\n", []chunk{{"a", false}}},
		{"unterminated-line-is-partial", "a", []chunk{{"a", true}}},
		{"blank-lines", "\n\n", []chunk{{"", false}, {"", false}}},
		{"crlf-stripped", "a\r\nb\r\n", []chunk{{"a", false}, {"b", false}}},
		{"trailing-cr-at-eof", "a\r", []chunk{{"a\r", true}}},
		{"terminated-then-unterminated", "a\nb", []chunk{{"a", false}, {"b", true}}},
		{
			"longer-than-the-read-buffer",
			strings.Repeat("z", readBufBytes+10) + "\n",
			[]chunk{{strings.Repeat("z", readBufBytes+10), false}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := collect(t, tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d chunks %s, want %d %s", len(got), summarize(got), len(tc.want), summarize(tc.want))
			}
			for i := range tc.want {
				if got[i].partial != tc.want[i].partial {
					t.Errorf("chunk %d partial = %v, want %v", i, got[i].partial, tc.want[i].partial)
				}
				if got[i].payload != tc.want[i].payload {
					t.Errorf("chunk %d payload = %q, want %q", i, got[i].payload, tc.want[i].payload)
				}
			}
		})
	}
}

// TestWriterChunksAt16KiB is the split gate: a line over the bound is emitted
// as P chunks of exactly MaxLineBytes and a final chunk carrying the rest, so
// nothing is dropped and a reader that concatenates the P run recovers the line
// byte for byte. The 1 MiB truncation the supervisor's old pump applied is
// gone; this is what replaced it.
func TestWriterChunksAt16KiB(t *testing.T) {
	t.Run("40KiB-terminated-line", func(t *testing.T) {
		line := strings.Repeat("abcdefgh", (40<<10)/8)
		if len(line) != 40<<10 {
			t.Fatalf("fixture is %d bytes, want 40 KiB", len(line))
		}
		got := collect(t, line+"\n")
		want := []chunk{
			{line[:MaxLineBytes], true},
			{line[MaxLineBytes : 2*MaxLineBytes], true},
			{line[2*MaxLineBytes:], false},
		}
		if len(got) != 3 {
			t.Fatalf("got %d chunks %s, want 3 (P,P,F)", len(got), summarize(got))
		}
		for i := range want {
			if got[i].partial != want[i].partial {
				t.Errorf("chunk %d partial = %v, want %v", i, got[i].partial, want[i].partial)
			}
			if len(got[i].payload) != len(want[i].payload) {
				t.Errorf("chunk %d is %d bytes, want %d", i, len(got[i].payload), len(want[i].payload))
			}
			if got[i].payload != want[i].payload {
				t.Errorf("chunk %d payload differs from the source slice", i)
			}
		}
		var rejoined strings.Builder
		for _, c := range got {
			rejoined.WriteString(c.payload)
		}
		if rejoined.String() != line {
			t.Error("concatenating the chunks does not reproduce the line; the split lost bytes")
		}
	})

	t.Run("exactly-at-the-bound-is-one-full-chunk", func(t *testing.T) {
		line := strings.Repeat("x", MaxLineBytes)
		got := collect(t, line+"\n")
		if len(got) != 1 || got[0].partial || got[0].payload != line {
			t.Fatalf("got %s, want one F chunk of %d bytes", summarize(got), MaxLineBytes)
		}
	})

	t.Run("oversized-and-unterminated-ends-partial", func(t *testing.T) {
		line := strings.Repeat("y", MaxLineBytes+7)
		got := collect(t, line)
		if len(got) != 2 {
			t.Fatalf("got %d chunks %s, want 2", len(got), summarize(got))
		}
		if !got[0].partial || len(got[0].payload) != MaxLineBytes {
			t.Errorf("first chunk = %d bytes partial=%v, want %d bytes P", len(got[0].payload), got[0].partial, MaxLineBytes)
		}
		// EOF without a newline: the tail is still an INCOMPLETE line, so P.
		if !got[1].partial || len(got[1].payload) != 7 {
			t.Errorf("last chunk = %d bytes partial=%v, want 7 bytes P", len(got[1].payload), got[1].partial)
		}
	})

	t.Run("output-after-an-oversized-line-still-flows", func(t *testing.T) {
		huge := strings.Repeat("h", 3*MaxLineBytes)
		got := collect(t, "before\n"+huge+"\nafter\n")
		if len(got) == 0 {
			t.Fatal("no chunks")
		}
		if got[0].payload != "before" {
			t.Errorf("first chunk = %q, want %q", got[0].payload, "before")
		}
		last := got[len(got)-1]
		if last.payload != "after" || last.partial {
			t.Errorf("last chunk = %q partial=%v, want %q F — an oversized line must not end delivery",
				last.payload, last.partial, "after")
		}
	})
}

// TestChunkerStopsOnSinkError pins the fail-fast half of the write-failure
// policy: a sink error ends the chunker at once and reaches the caller, which
// is what lets the pump close its read end and hand the container an EPIPE.
func TestChunkerStopsOnSinkError(t *testing.T) {
	boom := errors.New("disk full")
	calls := 0
	err := Chunk(strings.NewReader("a\nb\nc\nd\n"), func([]byte, bool) error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Chunk err = %v, want the sink error", err)
	}
	if calls != 2 {
		t.Errorf("sink called %d times, want 2 (the chunker kept going after a failure)", calls)
	}
}

// summarize renders chunks compactly (they can be 16 KiB each).
func summarize(cs []chunk) string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		tag := "F"
		if c.partial {
			tag = "P"
		}
		p := c.payload
		if len(p) > 24 {
			p = p[:24] + "..."
		}
		out = append(out, tag+":"+p)
	}
	return "[" + strings.Join(out, " ") + "]"
}
