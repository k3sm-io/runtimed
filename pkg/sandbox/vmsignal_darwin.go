//go:build darwin

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
	"os"

	"golang.org/x/sys/unix"
)

// vmTermSignal is the vm host helper's graceful-stop first signal and
// vmKillSignal the escalation, typed as supervisor.SignalGroup requires (a
// plain os.Signal whose dynamic type is unix.Signal on darwin).
//
// They are this package's own rather than pkg/runtime's twins because the
// dependency runs the other way — pkg/runtime imports pkg/sandbox — and eight
// lines of platform constants are a smaller cost than an import cycle or a new
// internal package. The values are the same two signals, and must stay so: the
// helper's SIGTERM handler IS its graceful sequence (cmd/k3sm-vmhost's
// signal.NotifyContext), so sending anything else would skip the guest stop.
var (
	vmKillSignal os.Signal = unix.SIGKILL
	vmTermSignal os.Signal = unix.SIGTERM
)
