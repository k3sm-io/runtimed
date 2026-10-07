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

package execshim

import (
	"io"
	"testing"
	"time"
)

func TestRingDropsOldestAndNeverBlocks(t *testing.T) {
	r := newRing(8)
	done := make(chan struct{})
	go func() {
		// No reader runs: a blocking Write would never return.
		for i := 0; i < 100; i++ {
			_, _ = r.Write([]byte("0123456789"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked with no reader")
	}
	if got, want := r.Dropped(), uint64(100*10-8); got != want {
		t.Fatalf("Dropped = %d, want %d", got, want)
	}
	if got := r.takeDropped(); got != 992 {
		t.Fatalf("takeDropped = %d, want 992", got)
	}
	if got := r.takeDropped(); got != 0 {
		t.Fatalf("second takeDropped = %d, want 0", got)
	}
	r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "23456789" {
		t.Fatalf("kept %q, want the newest 8 bytes", b)
	}
}

func TestRingReadWaitsForData(t *testing.T) {
	r := newRing(64)
	got := make(chan string, 1)
	go func() {
		b := make([]byte, 16)
		n, _ := r.Read(b)
		got <- string(b[:n])
	}()
	time.Sleep(20 * time.Millisecond)
	_, _ = r.Write([]byte("hi"))
	select {
	case s := <-got:
		if s != "hi" {
			t.Fatalf("read %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read never returned")
	}
}

// TestRingWrapsAndKeepsTheNewest drives the ring across many wraps with odd-sized
// writes and reads, checking the reader always sees the newest bytes in order.
func TestRingWrapsAndKeepsTheNewest(t *testing.T) {
	r := newRing(10)
	var want []byte
	next := byte(0)
	for i := 0; i < 200; i++ {
		chunk := make([]byte, i%7+1)
		for j := range chunk {
			chunk[j] = next
			next++
		}
		_, _ = r.Write(chunk)
		want = append(want, chunk...)
		if len(want) > 10 {
			want = want[len(want)-10:]
		}
		if i%3 == 0 {
			b := make([]byte, 3)
			n, _ := r.Read(b)
			if string(b[:n]) != string(want[:n]) {
				t.Fatalf("step %d: read %v, want %v", i, b[:n], want[:n])
			}
			want = want[n:]
		}
	}
	r.Close()
	rest, _ := io.ReadAll(r)
	if string(rest) != string(want) {
		t.Fatalf("drained %v, want %v", rest, want)
	}
}
