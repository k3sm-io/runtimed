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
	"context"
	"fmt"
	"log/slog"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// ConditionPressureKillMark is the RuntimeCondition Type reported when pod
// processes are spawned WITHOUT the pressure-kill mark. It is additive and is
// present only in that degraded state: a daemon whose mark is proven (or whose
// spawner was injected) reports the four conditions it always has.
const ConditionPressureKillMark = "PressureKillMark"

// reasonPressureKillUnverified is the condition's Reason token.
const reasonPressureKillUnverified = "MarkUnverified"

// pressureKillProbeTimeout bounds the startup self-check. The probe spawns and
// SIGKILLs one /bin/sleep, so the bound is generous; it exists because New has
// no ctx of its own (see the Rosetta probe note in New).
const pressureKillProbeTimeout = 10 * time.Second

// defaultPodSpawner builds the production pod spawner with the pressure-kill
// mark and proves the mark once on this host. When the proof fails the spawner
// is returned UNMARKED for the daemon's life — a mark that cannot be read back
// is not trusted to do anything, and asking for it on every spawn would only
// repeat the failure — and the error is returned for GetRuntimeInfo to report.
// A nil probe selects supervisor.VerifyPressureKill.
func defaultPodSpawner(log *slog.Logger, probe func(context.Context) error) (supervisor.PosixSpawner, error) {
	if probe == nil {
		probe = supervisor.VerifyPressureKill
	}
	ctx, cancel := context.WithTimeout(context.Background(), pressureKillProbeTimeout)
	defer cancel()
	if err := probe(ctx); err != nil {
		log.Error("pod processes will run without the pressure-kill mark; under memory exhaustion macOS may kill a control-plane process before a pod",
			"err", err)
		return supervisor.PosixSpawner{PressureKill: false}, err
	}
	return supervisor.PosixSpawner{PressureKill: true}, nil
}

// pressureKillCondition renders the degraded-state condition for err, or nil
// when there is nothing to report.
func pressureKillCondition(err error) *runtimev1.RuntimeCondition {
	if err == nil {
		return nil
	}
	return &runtimev1.RuntimeCondition{
		Type:    ConditionPressureKillMark,
		Status:  runtimev1.ConditionStatus_CONDITION_STATUS_FALSE,
		Reason:  reasonPressureKillUnverified,
		Message: fmt.Sprintf("pod processes are spawned without the pcontrol-kill mark (%v); under memory exhaustion a control-plane process may be killed before a pod", err),
	}
}
