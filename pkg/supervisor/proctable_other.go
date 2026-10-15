//go:build !darwin

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

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"
)

// ReadProcTable is unavailable off darwin: it reports ok=false, which the tree
// tracker treats as "nothing learned" and never as an empty table.
func ReadProcTable() ([]ProcEntry, bool) { return nil, false }

// ProcSessionID is unavailable off darwin: it reports no session, which the
// startup reap treats as "not the recorded instance".
func ProcSessionID(pid int) (sid int, ok bool) { return 0, false }

// KillPID is unavailable off darwin.
func KillPID(pid int, sig unix.Signal) error {
	return errors.New("supervisor: KillPID is darwin-only")
}
