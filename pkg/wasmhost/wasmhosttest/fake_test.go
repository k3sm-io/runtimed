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

package wasmhosttest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/wasmhost"
	"k3sm.io/runtimed/pkg/wasmhost/wasmhosttest"
)

// layout builds a pod dir with a rootfs and a module holding body, and returns
// its validated spec.
func layout(t *testing.T, body []byte) (wasmhost.Validated, string) {
	t.Helper()
	pod := filepath.Join(t.TempDir(), "pod")
	module := filepath.Join(pod, "rootfs", "main.wasm")
	if err := os.MkdirAll(filepath.Dir(module), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, body, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := wasmhost.BuildLaunchSpec(wasmhost.Bounds{PodDir: pod}, wasmhost.BuildInput{
		Rootfs:           filepath.Join(pod, "rootfs"),
		Module:           module,
		MemoryLimitBytes: 64 << 20,
		Argv:             []string{"main.wasm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, module
}

var wasmBody = []byte("\x00asm\x01\x00\x00\x00")

func TestFakeEngineReturnsScriptedStatusesInOrder(t *testing.T) {
	v, _ := layout(t, wasmBody)
	script := []wasmhost.ExitStatus{
		{Kind: wasmhost.ExitCode, Code: 7},
		{Kind: wasmhost.ExitTrap, Detail: "wasm trap: unreachable"},
		{Kind: wasmhost.ExitResourceLimit, Detail: "memory limit exceeded"},
	}
	e := wasmhosttest.NewFakeEngine(script...)
	for i, want := range script {
		got, err := e.Run(context.Background(), v)
		if err != nil || got != want {
			t.Fatalf("run %d = %+v, %v; want %+v", i, got, err, want)
		}
	}
	if _, err := e.Run(context.Background(), v); !errors.Is(err, wasmhosttest.ErrNoScriptedStatus) {
		t.Fatalf("run past the script = %v, want ErrNoScriptedStatus", err)
	}
	if n := len(e.Runs()); n != len(script) {
		t.Fatalf("Runs() has %d entries, want %d", n, len(script))
	}
}

func TestFakeEngineRefuses(t *testing.T) {
	cases := []struct {
		name    string
		body    []byte
		zero    bool
		ctxDone bool
		swap    bool
		want    error
	}{
		{name: "the zero Validated", body: wasmBody, zero: true, want: wasmhost.ErrInvalidSpec},
		{name: "a module without the wasm magic", body: []byte("\x7fELF\x02\x01\x01\x00"), want: wasmhosttest.ErrNotWasm},
		{name: "a Mach-O module", body: []byte{0xcf, 0xfa, 0xed, 0xfe}, want: wasmhosttest.ErrNotWasm},
		{name: "a module shorter than the magic", body: []byte("\x00as"), want: wasmhosttest.ErrNotWasm},
		{name: "an empty module", body: []byte{}, want: wasmhosttest.ErrNotWasm},
		{name: "a cancelled context", body: wasmBody, ctxDone: true, want: context.Canceled},
		{name: "a module swapped for a symlink after Validate", body: wasmBody, swap: true, want: wasmhost.ErrInvalidSpec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, module := layout(t, tc.body)
			if tc.zero {
				v = wasmhost.Validated{}
			}
			if tc.swap {
				other := filepath.Join(t.TempDir(), "other.wasm")
				if err := os.WriteFile(other, wasmBody, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(module); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, module); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.ctxDone {
				cancel()
			} else {
				defer cancel()
			}
			e := wasmhosttest.NewFakeEngine(wasmhost.ExitStatus{Kind: wasmhost.ExitCode})
			st, err := e.Run(ctx, v)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Run = %+v, %v; want %v", st, err, tc.want)
			}
			if st != (wasmhost.ExitStatus{}) || len(e.Runs()) != 0 {
				t.Fatalf("a refused run produced a status (%+v) or was recorded", st)
			}
		})
	}
}

func TestFakeEngineIsSafeForConcurrentUse(t *testing.T) {
	v, _ := layout(t, wasmBody)
	const n = 16
	script := make([]wasmhost.ExitStatus, n)
	for i := range script {
		script[i] = wasmhost.ExitStatus{Kind: wasmhost.ExitCode, Code: i}
	}
	e := wasmhosttest.NewFakeEngine(script...)
	var wg sync.WaitGroup
	seen := make(chan int, n)
	for range n {
		wg.Go(func() {
			st, err := e.Run(context.Background(), v)
			if err != nil {
				t.Error(err)
				return
			}
			seen <- st.Code
		})
	}
	wg.Wait()
	close(seen)
	got := map[int]bool{}
	for c := range seen {
		if got[c] {
			t.Fatalf("status %d handed out twice", c)
		}
		got[c] = true
	}
	if len(got) != n {
		t.Fatalf("%d distinct statuses, want %d", len(got), n)
	}
}

func TestExitKindString(t *testing.T) {
	for k, want := range map[wasmhost.ExitKind]string{
		wasmhost.ExitUnknown: "unknown(0)", wasmhost.ExitCode: "exit", wasmhost.ExitTrap: "trap", wasmhost.ExitResourceLimit: "resource-limit",
	} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(k), got, want)
		}
	}
}
