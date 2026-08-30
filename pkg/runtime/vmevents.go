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

	guestv1 "k3sm.io/apis/guest/v1"
)

// watchGuestContainerEvents subscribes to a vm pod's guest-agent
// ContainerEvents stream and folds each event into that pod's status.
//
// SKELETON (B107 commit 1): the subscription and the fold land in commit 2.
func (r *Runtime) watchGuestContainerEvents(ctx context.Context, p *pod) error {
	_, _ = ctx, p
	return nil
}

// applyGuestContainerEvent folds one guest-agent container event into p.
//
// SKELETON (B107 commit 1): the fold lands in commit 2.
func (r *Runtime) applyGuestContainerEvent(p *pod, ev *guestv1.ContainerEvent) {
	_, _ = p, ev
}
