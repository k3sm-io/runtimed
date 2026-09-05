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

package runtime

import (
	"os"

	"golang.org/x/sys/unix"
)

// killSignal is SIGKILL and termSignal is SIGTERM, as the unix.Signal concrete
// type the supervisor's SignalGroup expects (a plain os.Signal whose dynamic type
// is unix.Signal). termSignal is the graceful-stop first signal; killSignal
// the escalation / immediate kill.
var (
	killSignal os.Signal = unix.SIGKILL
	termSignal os.Signal = unix.SIGTERM
)
