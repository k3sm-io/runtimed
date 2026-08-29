//go:build integration && darwin

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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// machOArch maps a GOARCH to the Mach-O architecture name lipo(1) prints, which
// is the only spelling the arch assert may compare against: "amd64" is a Go
// token and never appears in a Mach-O header.
var machOArch = map[string]string{"amd64": "x86_64", "arm64": "arm64"}

// rosettaPayloadSource is the pod payload under test. It is deliberately tiny and
// stdlib-only (it is built as its own throwaway module, so it can import nothing
// else), and it reports three things on stdout:
//
//   - PAYLOAD-RAN — it reached main(), with its own compiled-in GOARCH and its own
//     sysctl.proc_translated verdict, i.e. whether the KERNEL considers this very
//     process translated. That is the in-sandbox witness that Rosetta engaged; the
//     out-of-sandbox witness is the Mach-O arch assert on the binary itself.
//   - PROBE 0 — a read INSIDE the pod's own data volume, which must succeed. This
//     is the positive control that keeps the deny assert non-vacuous: without it a
//     payload that could open nothing at all would "pass" the deny leg.
//   - PROBE 1 — a read of a path the generated profile DENIES, which must fail with
//     EPERM (errno 1, Seatbelt's denial) rather than EACCES (13, ordinary
//     permissions).
//
// It always exits 0: the verdicts are in the output, so a non-zero exit means the
// payload did not run at all — the failure this gate exists to catch.
const rosettaPayloadSource = `package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

func main() {
	translated := "err"
	if v, err := syscall.SysctlUint32("sysctl.proc_translated"); err == nil {
		translated = fmt.Sprint(v)
	}
	fmt.Printf("PAYLOAD-RAN goarch=%s translated=%s\n", runtime.GOARCH, translated)
	for i, p := range os.Args[1:] {
		f, err := os.Open(p)
		if err == nil {
			f.Close()
			fmt.Printf("PROBE %d %s OK\n", i, p)
			continue
		}
		var errno syscall.Errno
		if errors.As(err, &errno) {
			fmt.Printf("PROBE %d %s errno=%d\n", i, p, int(errno))
			continue
		}
		fmt.Printf("PROBE %d %s err=%v\n", i, p, err)
	}
}
`

// trueHostArch returns the HARDWARE architecture of this host — correct even when
// the caller is itself running translated.
//
// This is not paranoia: the toolchain in this workspace is an amd64 build running
// under Rosetta, so a test binary compiled by it reports runtime.GOARCH == "amd64"
// AND is handed a masked hw.machine == "x86_64" by the kernel, on a Mac that is
// physically arm64. Trusting either would make this gate decide "there is nothing
// to translate here" on precisely the hardware it is meant to run on.
//
// sysctl.proc_translated is the escape: it is per-process, so a 1 means WE are
// translated, and Rosetta 2 translates x86_64 only on Apple Silicon — hence the
// host is arm64. When it is 0 (or absent, as on a real Intel Mac) nothing is
// masked and hw.machine is truthful.
func trueHostArch(t *testing.T) string {
	t.Helper()
	if translated, err := unix.SysctlUint32("sysctl.proc_translated"); err == nil && translated == 1 {
		return "arm64"
	}
	m, err := unix.Sysctl("hw.machine")
	if err != nil {
		t.Fatalf("sysctl hw.machine: %v", err)
	}
	return m
}

// buildRosettaPayload builds rosettaPayloadSource for goarch into bin and ad-hoc
// signs it.
//
// GOARCH/GOOS/CGO_ENABLED are set EXPLICITLY rather than inherited, for the reason
// trueHostArch documents: the ambient toolchain's arch is not the payload's arch,
// and a harness that lets one stand in for the other tests the wrong binary while
// still going green. GOWORK=off keeps the throwaway module out of the workspace's
// go.work, GOPROXY=off proves it needs nothing but the standard library, and
// GOFLAGS is cleared so an ambient flag cannot re-open either.
//
// The ad-hoc signature is plain (no -o options): on arm64 an unsigned Mach-O is
// SIGKILLed by AMFI before the sandbox is ever consulted, which would make this
// gate red for a reason that has nothing to do with Seatbelt.
func buildRosettaPayload(t *testing.T, goarch, bin string) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(rosettaPayloadSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module k3smrosettapayload\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = src
	build.Env = append(os.Environ(),
		"GOOS=darwin", "GOARCH="+goarch, "CGO_ENABLED=0",
		"GOWORK=off", "GOFLAGS=", "GOPROXY=off",
	)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s payload: %v\n%s", goarch, err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", bin).CombinedOutput(); err != nil {
		t.Fatalf("codesign %s payload: %v\n%s", goarch, err, out)
	}
}

// assertMachOArch fails the test LOUDLY unless bin is a thin Mach-O of exactly the
// architecture wantGOARCH names.
//
// It is the harness's own integrity check, and it must run BEFORE the payload is
// used: every claim this gate makes about translation rests on the payload really
// being x86_64 on arm64 hardware. A harness that silently built the native arch
// would exercise the native spine twice and report green — the exact wrong-reason
// pass the explicit GOARCH pinning above exists to prevent. Thin, not fat: a
// universal binary would run natively and prove nothing.
func assertMachOArch(t *testing.T, bin, wantGOARCH string) {
	t.Helper()
	want, ok := machOArch[wantGOARCH]
	if !ok {
		t.Fatalf("no Mach-O arch name known for GOARCH %q", wantGOARCH)
	}
	out, err := exec.Command("lipo", "-archs", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("lipo -archs %s: %v\n%s", bin, err, out)
	}
	got := strings.Fields(string(out))
	if len(got) != 1 || got[0] != want {
		t.Fatalf("payload %s is Mach-O %v, want exactly [%s] — the harness built the wrong architecture, "+
			"so any verdict from it would be about the wrong binary", bin, got, want)
	}
}

// TestHostRosettaSpawnUnderSeatbelt is the B105 regression pin: the generated
// default-deny Seatbelt profile admits a darwin/amd64 pod payload translated by
// host Rosetta 2, on the SAME terms as a native arm64 one.
//
// This pins a measured fact rather than discovering one. The B103 critique pass
// measured that a cold-translated, ad-hoc-signed x86_64 Mach-O spawns and runs
// under the unmodified generated profile, and that every proposed "translation
// surface" grant (an oahd mach-lookup, /var/db/oah, /usr/libexec/rosetta) is
// NOT load-bearing — cold translation is driven by the kernel/AMFI exec path on
// the daemon side, not by a client-side sandbox-checked lookup. Nothing in the
// tree held that fact still. This test does, in both directions:
//
//   - it goes RED if a future profile change starts refusing translated payloads;
//   - it goes RED if a deny stops enforcing for a translated payload, which is the
//     way a "fix" for the first failure would most plausibly be wrong.
//
// It therefore also stands as the review anchor for the rule that no oah/rosetta
// grant may be added to Generate: with this green, such a grant buys nothing and
// only widens every pod profile on the node.
//
// Both legs go through the PRODUCTION path — the real Generate output (never a
// hand-written .sb) applied by the real k3sm-execshim — and both assert the same
// deny, in one table, so "the translated payload is confined identically" is a
// comparison the test actually makes rather than a claim it asserts.
func TestHostRosettaSpawnUnderSeatbelt(t *testing.T) {
	host := trueHostArch(t)
	if host != "arm64" {
		t.Skipf("host hardware is %s: Rosetta 2 translates darwin/amd64 only on Apple Silicon, "+
			"so there is no translated leg to pin here", host)
	}
	// The confiner is pinned to the host arch, not the ambient toolchain's: in
	// production k3sm-execshim is the node's native binary, and it is the payload —
	// not the confiner — that is under translation here.
	shim := buildExecShimForGOARCH(t, host)
	rosetta := ProbeHostRosetta(context.Background())

	for _, tc := range []struct {
		name string
		// goarch is the payload's architecture, pinned explicitly at build time.
		goarch string
		// wantTranslated is the sysctl.proc_translated value the payload must report
		// about ITSELF from inside the sandbox.
		wantTranslated string
	}{
		{name: "native-arm64-control", goarch: "arm64", wantTranslated: "0"},
		{name: "translated-amd64-under-rosetta", goarch: "amd64", wantTranslated: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.goarch != host && !rosetta.Available() {
				t.Skipf("host Rosetta 2 is %s (ProbeHostRosetta): the translated leg cannot run on "+
					"this machine and is owed on Rosetta-capable lab hardware", rosetta)
			}

			posture, work := podVolume(t, "pod-rosetta-"+tc.goarch)
			payload := filepath.Join(work, "payload")
			buildRosettaPayload(t, tc.goarch, payload)
			assertMachOArch(t, payload, tc.goarch)

			// The positive control lives inside the pod's own data volume (re-allowed
			// after the protected denies); the deny probe is /Users, the cheapest of the
			// generated profile's protected denies and the one TestIntegrationConfinement
			// already exercises natively.
			allowed := filepath.Join(work, "allowed.txt")
			if err := os.WriteFile(allowed, []byte("ok\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			const denied = "/Users"

			profile := genProfile(t, posture, work, "/private/tmp", "/private/var/folders", work)
			out, err := runUnderShim(t, shim, profile, os.Environ(), payload, allowed, denied)
			if err != nil {
				t.Fatalf("%s payload did not run to completion under the generated profile: %v\n%s",
					tc.goarch, err, out)
			}

			ran := fmt.Sprintf("PAYLOAD-RAN goarch=%s translated=%s", tc.goarch, tc.wantTranslated)
			if !strings.Contains(out, ran) {
				t.Fatalf("want %q in payload output (did it spawn, and was it translated as expected?):\n%s", ran, out)
			}
			if want := fmt.Sprintf("PROBE 0 %s OK", allowed); !strings.Contains(out, want) {
				t.Errorf("the pod's own data volume was not readable — want %q:\n%s", want, out)
			}
			// EPERM (1) specifically: Seatbelt denies with EPERM, so EACCES here would
			// mean an ordinary permission error stood in for the confinement.
			if want := fmt.Sprintf("PROBE 1 %s errno=%d", denied, int(unix.EPERM)); !strings.Contains(out, want) {
				t.Errorf("the %s deny did not enforce for the %s payload — want %q:\n%s",
					denied, tc.goarch, want, out)
			}
		})
	}
}
