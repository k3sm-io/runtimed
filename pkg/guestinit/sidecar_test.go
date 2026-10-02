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
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
)

// TestStartOrderSidecarDoesNotWaitForExit pins the native-sidecar contract of
// GuestContainer.sidecar on the guest side: a sidecar is an init container the
// boot does not wait for, a sidecar without init is refused, a plain init
// container is still waited for, and at shutdown the mains stop before the
// sidecars, which stop in reverse start order.
//
// It is non-vacuous against the field's absence: before the marker, every init
// container was planned WaitForExit, so the first row would hang a boot on a
// process that never exits; and the shutdown leg below fails against a reaper
// that terminates every container together.
func TestStartOrderSidecarDoesNotWaitForExit(t *testing.T) {
	c := func(name string, init, sidecar bool) *guestv1.GuestContainer {
		return &guestv1.GuestContainer{
			Name: name, Init: init, Sidecar: sidecar,
			RootfsTag: "k3sm.rootfs", Command: []string{"/bin/true"},
		}
	}

	t.Run("init+sidecar starts in its init position and is not waited", func(t *testing.T) {
		steps, err := StartOrder([]*guestv1.GuestContainer{
			c("app", false, false), c("proxy", true, true), c("migrate", true, false),
		})
		if err != nil {
			t.Fatalf("StartOrder: %v", err)
		}
		want := []struct {
			name    string
			phase   Phase
			wait    bool
			sidecar bool
		}{
			{"proxy", PhaseInit, false, true},
			{"migrate", PhaseInit, true, false},
			{"app", PhaseMain, false, false},
		}
		if len(steps) != len(want) {
			t.Fatalf("steps = %d, want %d", len(steps), len(want))
		}
		for i, w := range want {
			got := steps[i]
			if got.Container.GetName() != w.name || got.Phase != w.phase ||
				got.WaitForExit != w.wait || got.Sidecar != w.sidecar {
				t.Errorf("step %d = {%s %s wait=%v sidecar=%v}, want {%s %s wait=%v sidecar=%v}",
					i, got.Container.GetName(), got.Phase, got.WaitForExit, got.Sidecar,
					w.name, w.phase, w.wait, w.sidecar)
			}
		}
	})

	t.Run("sidecar without init is an invalid spec", func(t *testing.T) {
		_, err := StartOrder([]*guestv1.GuestContainer{c("app", false, false), c("proxy", false, true)})
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("StartOrder err = %v, want ErrInvalidSpec", err)
		}
	})

	t.Run("a plain init container still waits", func(t *testing.T) {
		steps, err := StartOrder([]*guestv1.GuestContainer{c("app", false, false), c("migrate", true, false)})
		if err != nil {
			t.Fatalf("StartOrder: %v", err)
		}
		if !steps[0].WaitForExit || steps[0].Sidecar {
			t.Errorf("plain init = wait %v sidecar %v, want wait true sidecar false", steps[0].WaitForExit, steps[0].Sidecar)
		}
	})

	t.Run("the plan carries the marker to the executor", func(t *testing.T) {
		spec := goldenSpec()
		spec.Containers = append(spec.Containers, c("proxy", true, true))
		plan, err := Plan(spec, Options{})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		var proxy *ContainerPlan
		for i := range plan.Containers {
			if plan.Containers[i].Name == "proxy" {
				proxy = &plan.Containers[i]
			}
		}
		if proxy == nil || !proxy.Sidecar || proxy.WaitForExit || proxy.Phase != PhaseInit {
			t.Fatalf("proxy plan = %+v, want an init-phase sidecar that is not waited", proxy)
		}
	})

	t.Run("shutdown order is mains then sidecars in reverse start order", func(t *testing.T) {
		containers := []ContainerPlan{
			{Name: "log-shipper", Sidecar: true},
			{Name: "migrate"},
			{Name: "mesh-proxy", Sidecar: true},
			{Name: "app"},
			{Name: "worker"},
		}
		got := ShutdownOrder(containers)
		want := ShutdownPlan{
			Mains:    []string{"migrate", "app", "worker"},
			Sidecars: []string{"mesh-proxy", "log-shipper"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ShutdownOrder = %+v, want %+v", got, want)
		}
	})

	t.Run("the reaper stops mains, then each sidecar, in that order", func(t *testing.T) {
		f := newFakeProc()
		timerCh := make(chan time.Time)
		r := startReaper(t, f, ReaperOptions{
			Sidecars: []string{"mesh-proxy", "log-shipper"},
			NewTimer: func(time.Duration) (<-chan time.Time, func() bool) { return timerCh, func() bool { return true } },
		})
		// pids deliberately interleaved so a pid-sorted stop would get it wrong.
		for name, pid := range map[string]int{"log-shipper": 10, "app": 11, "mesh-proxy": 12, "worker": 13} {
			f.spawn(pid)
			r.Track(name, pid)
		}
		stopped := make(chan error, 1)
		go func() { stopped <- r.Stop(context.Background(), time.Hour) }()

		// Each container exits as soon as it is asked to; the next group must
		// not be signalled until the previous one is gone.
		for _, want := range []int{11, 13, 12, 10} {
			select {
			case pid := <-f.termed:
				if pid != want {
					t.Fatalf("SIGTERM went to pid %d, want %d", pid, want)
				}
				f.exit(pid, WaitStatus{Signal: int(SignalTerm)})
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out waiting for SIGTERM to pid %d", want)
			}
		}
		if err := <-stopped; err != nil {
			t.Fatalf("Stop: %v", err)
		}
		log := f.snapshotLog()
		want := []string{"term:11", "term:13", "term:12", "term:10", "poweroff"}
		if !reflect.DeepEqual(log, want) {
			t.Fatalf("stop sequence = %v, want %v", log, want)
		}
	})
}
