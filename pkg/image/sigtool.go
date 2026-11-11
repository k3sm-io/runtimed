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

package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// SignatureCheckTimeout bounds ONE signature check: a single codesign --verify,
// codesign -dv or spctl --assess run. The tools consult the system policy daemon,
// and when that daemon is down they block for minutes; a check that has not
// answered in this time is reported as ErrSignatureCheckTimeout, never as a
// verdict.
const SignatureCheckTimeout = 30 * time.Second

// SignatureSignTimeout bounds ONE ad-hoc sign of ONE file. A tree walk applies it
// per file, never to the whole tree, so a large tree is not failed by its size.
const SignatureSignTimeout = 120 * time.Second

// ErrSignatureCheckTimeout reports that a signature tool (codesign or spctl) did
// not finish within its deadline while the caller's context was still live. It
// is NOT a verdict: the binary is neither signed nor unsigned as far as the
// caller knows, so it must not be cached, must not trigger a sign, and must be
// reported as a retryable failure rather than a signature rejection. A
// cancelled caller context is reported as that cancellation, never as this.
var ErrSignatureCheckTimeout = errors.New("image: signature tool timed out")

// checkTimeout and signTimeout are the deadlines the tool calls in this package
// use. They are variables only so tests can shorten them.
var (
	checkTimeout = SignatureCheckTimeout
	signTimeout  = SignatureSignTimeout
)

// toolWaitDelay bounds how long Wait waits, after the child is killed, for the
// child's output pipes to close. A grandchild that inherited the pipe would
// otherwise hold Wait open past the deadline. A variable so tests can shorten it.
var toolWaitDelay = 2 * time.Second

// commandContext is the command seam: production runs exec.CommandContext; tests
// substitute a stub (for example one that sleeps) so the real deadline path is
// exercised without the signature tools.
var commandContext = exec.CommandContext

// WithSignatureDeadline runs fn under a child context that expires after d and
// classifies the outcome. The parent is consulted first:
//
//   - fn succeeded: nil, whatever the contexts did afterwards;
//   - the parent ended: the parent's error (a cancellation stays a cancellation),
//     with fn's error attached;
//   - the parent is live and the child's deadline passed: ErrSignatureCheckTimeout.
//     fn's error is rendered as text only, so an *exec.ExitError from a killed
//     tool is never reachable through the chain and cannot be read as "unsigned";
//   - otherwise fn's error, unchanged.
func WithSignatureDeadline(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	err := fn(cctx)
	if err == nil {
		return nil
	}
	if perr := ctx.Err(); perr != nil {
		return fmt.Errorf("%w: %w", perr, err)
	}
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %s: %v", ErrSignatureCheckTimeout, d, err)
	}
	return err
}

// runTool runs one signature tool invocation under the deadline d. stdout and
// stderr may be nil, or the same writer. On the deadline the child is killed
// (cmd.Cancel) and Wait gives up on its pipes after toolWaitDelay
// (cmd.WaitDelay), so neither the child nor a grandchild holding its output can
// keep the call alive. The result is classified by WithSignatureDeadline.
func runTool(ctx context.Context, d time.Duration, stdout, stderr io.Writer, name string, args ...string) error {
	return WithSignatureDeadline(ctx, d, func(ctx context.Context) error {
		cmd := commandContext(ctx, name, args...)
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.Cancel = func() error { return cmd.Process.Kill() }
		cmd.WaitDelay = toolWaitDelay
		return cmd.Run()
	})
}

// toolAborted reports whether err means the tool was stopped rather than
// answered: its deadline passed, or the caller's context ended. Every verdict
// mapper tests this BEFORE reading an exit status, because a killed tool also
// exits non-zero and that exit must never read as "unsigned".
func toolAborted(err error) bool {
	return errors.Is(err, ErrSignatureCheckTimeout) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}
