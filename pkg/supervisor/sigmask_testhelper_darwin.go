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

package supervisor

/*
#include <signal.h>

static void k3smBlockSIGTERM(void) {
	sigset_t s;
	sigemptyset(&s);
	sigaddset(&s, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &s, (sigset_t *)0);
}
*/
import "C"

// blockSIGTERMForTest blocks SIGTERM on the CALLING OS thread. It reproduces the
// Go-runtime state (signals blocked on worker threads) that PosixSpawner must
// clear via POSIX_SPAWN_SETSIGMASK, for TestIntegrationSpawnResetsSignalMask. It
// lives in a non-test file because Go forbids cgo in _test.go, and is gated on the
// `integration` build tag so it never compiles into a production binary.
// x/sys/unix ships no Sigset_t / PthreadSigmask on darwin, hence the cgo shim.
func blockSIGTERMForTest() { C.k3smBlockSIGTERM() }
