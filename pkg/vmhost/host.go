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

package vmhost

import "context"

// RunWithProxy drives lc and serves p beside it for the machine's whole life, and
// returns lc's outcome once the proxy has drained.
//
// The proxy is NOT stopped by ctx. ctx is how SIGTERM arrives, and SIGTERM is
// the start of the guest's graceful stop, not its end: during Stopping the
// daemon still needs the agent socket for an exec, a log follow, or the
// container status it records on the way out, and the guest agent is healthy and
// answering. Closing the listener on the signal turned every one of those into an
// Unavailable for the whole grace period. So the proxy runs on a context
// detached from ctx and is cancelled only when Run has returned, which is when
// the machine has left Running (the guest powered off) or been halted.
//
// The drain still holds: Serve returns only after every relay goroutine has
// finished, so "RunWithProxy returned" means nothing is still holding a
// connection into the machine that was just stopped.
func RunWithProxy(ctx context.Context, lc *Lifecycle, p *Proxy) error {
	proxyCtx, stopProxy := context.WithCancel(context.WithoutCancel(ctx))
	defer stopProxy()
	proxied := make(chan error, 1)
	go func() { proxied <- p.Serve(proxyCtx) }()

	runErr := lc.Run(ctx)

	stopProxy()
	if perr := <-proxied; perr != nil {
		p.log.Warn("the guest agent proxy ended with an error", "err", perr)
	}
	return runErr
}
