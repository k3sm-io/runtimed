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

package mount

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// defaultTokenExpirationSeconds is the lifetime assumed for a ServiceAccount
// token projection that sets no expirationSeconds: the apiserver defaults the
// field to one hour.
const defaultTokenExpirationSeconds = 3600

// TokenIssue records when a projected ServiceAccount token was minted and for
// how long, so Refresh can re-mint it only once it nears expiry. It lives in the
// caller's memory only and is persisted nowhere: a daemon restart forgets it,
// and the first refresh after that re-mints every token.
type TokenIssue struct {
	// IssuedAt is when the token was minted.
	IssuedAt time.Time
	// ExpirationSeconds is the lifetime requested for it (0 = the default).
	ExpirationSeconds int64
}

// due reports whether the token has less than 20% of its lifetime left at now
// (the kubelet token manager's refresh point).
func (t TokenIssue) due(now time.Time) bool {
	life := time.Duration(t.ExpirationSeconds) * time.Second
	if t.ExpirationSeconds <= 0 {
		life = defaultTokenExpirationSeconds * time.Second
	}
	remaining := t.IssuedAt.Add(life).Sub(now)
	return remaining*5 < life
}

// RefreshState is what one render leaves for the next Refresh of the same pod.
type RefreshState struct {
	// Immutable holds, per volume name, whether the volume's every source was an
	// immutable ConfigMap/Secret at its last fetch (such a volume is never
	// re-fetched).
	Immutable map[string]bool
	// Tokens holds, per projected token file (mount dir joined with the
	// projection path), when that token was issued.
	Tokens map[string]TokenIssue
}

// clone returns a deep copy of s with non-nil maps.
func (s RefreshState) clone() RefreshState {
	out := RefreshState{Immutable: maps.Clone(s.Immutable), Tokens: maps.Clone(s.Tokens)}
	if out.Immutable == nil {
		out.Immutable = map[string]bool{}
	}
	if out.Tokens == nil {
		out.Tokens = map[string]TokenIssue{}
	}
	return out
}

// record folds one successful generation render of pm into s.
func (s *RefreshState) record(pm plannedMount, rd *render) {
	s.Immutable[pm.mount.GetName()] = rd.immutable()
	prefix := pm.dest + string(filepath.Separator)
	for k := range s.Tokens {
		if strings.HasPrefix(k, prefix) {
			delete(s.Tokens, k)
		}
	}
	maps.Copy(s.Tokens, rd.tokens)
}

// RefreshOptions parameterizes one Refresh.
type RefreshOptions struct {
	// PodIP is the pod's address, for status.podIP downward-API projections.
	PodIP string
	// State is the previous render's RefreshState (Layout.State after create,
	// then each RefreshResult.State). The zero value refreshes everything and
	// re-mints every token, which is the right answer after a daemon restart.
	State RefreshState
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// RefreshOutcome is what Refresh did to one volume mount.
type RefreshOutcome string

// The RefreshOutcome values.
const (
	// RefreshUpdated: a new generation was rendered and made live.
	RefreshUpdated RefreshOutcome = "Updated"
	// RefreshUnchanged: the rendered content equalled the live generation,
	// which was kept.
	RefreshUnchanged RefreshOutcome = "Unchanged"
	// RefreshSkipped: the mount is not refreshable (see VolumeRefresh.Reason).
	RefreshSkipped RefreshOutcome = "Skipped"
	// RefreshFailed: resolving or rendering failed before the flip; the live
	// generation was left untouched (see VolumeRefresh.Err).
	RefreshFailed RefreshOutcome = "Failed"
	// RefreshUpdatedWithWarnings: the new generation was made live, but the
	// housekeeping after the flip (linking a new key, removing the previous
	// generation, pruning a dropped key) failed; VolumeRefresh.Err names it.
	RefreshUpdatedWithWarnings RefreshOutcome = "UpdatedWithWarnings"
)

// VolumeRefresh is Refresh's outcome for one volume mount.
type VolumeRefresh struct {
	// Name is the volume name.
	Name string
	// Path is the mount dir on the host.
	Path string
	// Outcome is what happened.
	Outcome RefreshOutcome
	// Reason says why a Skipped mount was skipped.
	Reason string
	// Err is the failure of a Failed mount.
	Err error
}

// RefreshResult is the outcome of one Refresh.
type RefreshResult struct {
	// Volumes is one entry per volume mount Materialize materialized, in the
	// same order.
	Volumes []VolumeRefresh
	// State is the state to hand the next Refresh. A failed volume's entries
	// are carried over unchanged.
	State RefreshState
}

// Refresh re-renders the refreshable volume mounts of a running pod — the
// kubelet's periodic projected-volume sync. root is the pod data volume
// Materialize rendered into, box the pod, r the Resolver.
//
// It walks the mounts exactly as Materialize classified them (planMounts) and
// skips subPath mounts (never refreshed, kubelet parity), emptyDir and any other
// non-rendered source, and a volume whose sources were all immutable at the
// last fetch (opts.State.Immutable; not re-fetched). Every other mount —
// configMap, secret, downwardAPI, projected — is rendered as a fresh
// generation and made live with the atomic ..data flip (writeGeneration), or
// discarded if identical to the live one. A projected ServiceAccount token is
// re-minted only when under 20% of its lifetime remains.
//
// A resolver or render error on one volume leaves that volume's live
// generation untouched (RefreshFailed) and does not stop the others; a
// housekeeping error after a successful flip is RefreshUpdatedWithWarnings. The
// returned error joins every such failure, each naming its volume. A plan error
// (the box no longer walks) fails the whole call.
func Refresh(ctx context.Context, root string, box *runtimev1.PodBox, r Resolver, opts RefreshOptions) (RefreshResult, error) {
	root = filepath.Clean(root)
	plans, err := planMounts(box, root)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("plan volume mounts: %w", err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	res := RefreshResult{State: opts.State.clone()}
	var errs []error
	for _, pm := range plans {
		out := VolumeRefresh{Name: pm.mount.GetName(), Path: pm.dest}
		if reason := skipReason(pm, opts.State); reason != "" {
			out.Outcome, out.Reason = RefreshSkipped, reason
			res.Volumes = append(res.Volumes, out)
			continue
		}
		rd := newRender(box, opts.PodIP, r, now, pm.dest, opts.State.Tokens)
		_, flipped, gerr := rd.generation(ctx, pm)
		switch {
		case gerr != nil && flipped:
			// The flip happened; only post-flip housekeeping failed, so the new
			// generation (and its tokens) is what is live.
			out.Outcome, out.Err = RefreshUpdatedWithWarnings, gerr
			errs = append(errs, fmt.Errorf("refresh volume %s: updated, but housekeeping failed: %w", pm.mount.GetName(), gerr))
			res.State.record(pm, rd)
		case gerr != nil:
			out.Outcome, out.Err = RefreshFailed, gerr
			errs = append(errs, fmt.Errorf("refresh volume %s: %w", pm.mount.GetName(), gerr))
		case flipped:
			out.Outcome = RefreshUpdated
			res.State.record(pm, rd)
		default:
			out.Outcome = RefreshUnchanged
			res.State.record(pm, rd)
		}
		res.Volumes = append(res.Volumes, out)
	}
	return res, errors.Join(errs...)
}

// skipReason returns why Refresh leaves pm alone, or "" if it refreshes it.
func skipReason(pm plannedMount, st RefreshState) string {
	switch pm.class {
	case classSubPath:
		return "subPath mounts are never refreshed"
	case classEmptyDir:
		return "emptyDir has no source to refresh"
	case classOther:
		return "source is not refreshable"
	}
	if st.Immutable[pm.mount.GetName()] {
		return "every source is immutable"
	}
	return ""
}
