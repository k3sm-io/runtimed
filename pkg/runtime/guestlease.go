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
	"math/rand/v2"
	"net/netip"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The vm pod's live transport address watcher.
//
// A vm pod has two addresses and they are not interchangeable
// (runtime.proto, PodStatus.guest_transport_address). pod_ip is the pod's
// published IDENTITY — the podCIDR /32 this node allocated, which reaches
// EndpointSlice, DNS and the downward API. The address in this file is the
// other one: what the HOST dials to reach the guest, leased by the guest's own
// DHCP client on the node's NAT segment.
//
// the AGENT IS the only AUTHORITY for IT. guest.proto makes HealthResponse
// guest_ip "the single live-address authority": the host does not re-derive the
// address from the network attachment, so a lease change is observable in that
// field and nowhere else. The advisory GuestNetworkConfig.NATSubnet/PodIP the
// provider stamps onto VMSpec are INTENDED values ("macOS-assigned; an intended
// value runtimed reconciles from the live attachment") and are deliberately not
// used to validate a lease here — checking a live fact against an advisory one
// would fail closed on exactly the divergence the advisory admits to.
//
// So it is polled, not pushed. guest/v1 has no lease-change stream, and adding
// one would put the cadence in the guest's hands: a hostile agent could then
// drive the host's status-publish rate. A host-driven poll bounds that at one
// publish per pod per interval no matter what the guest does.

// defaultGuestLeasePoll is the base cadence of one pod's Health poll.
//
// SECONDS, not MILLISECONDS. A DHCP lease is semi-stable — it changes when a
// guest boots or renews onto a different address, which is a per-pod-lifetime
// event, not a per-second one — so the value being watched barely moves. The
// cost of the poll is the opposite shape: one vsock round trip per pod per
// tick, on a node that may run many pods, forever. Five seconds keeps the
// worst-case staleness of a rebooted guest's address inside a single
// service-dial retry budget while costing a fifth of a wakeup per pod-second.
const defaultGuestLeasePoll = 5 * time.Second

// guestLeasePollMaxBackoff caps the wait after consecutive failed polls. An
// agent that is not up yet (the common case: the watcher is armed before the
// guest has finished booting) must not be hammered, and an agent that is gone
// for good must not cost a wakeup every five seconds for the pod's whole life.
const guestLeasePollMaxBackoff = time.Minute

// guestLeaseHealthTimeout bounds one Health RPC, for the same reason
// guestStatsTimeout bounds one Stats call: a wedged agent must not hold the
// watcher — and with it the pod's transport address — hostage by staying
// silent. It is well above a vsock round trip that reads one cached string.
const guestLeaseHealthTimeout = 2 * time.Second

// maxGuestLeaseBytes caps the guest-supplied address string before it is
// parsed. 45 is the longest textual IPv6 address (an IPv4-mapped form,
// "::ffff:255.255.255.255", plus a zone) — INET6_ADDRSTRLEN - 1. Anything
// longer cannot be an address, so refusing it early means no parser ever sees
// an arbitrarily long guest-chosen string.
const maxGuestLeaseBytes = 45

// The reasons one Health poll can fail to yield a usable lease. They are
// distinct because they are different FACTS about the guest, and an operator
// reading the node log acts differently on each: unreachable means the agent or
// the VM is gone (look at the pod's lifecycle), absent means the guest is up but
// has no lease yet (look at DHCP), and every other reason means the agent
// answered with something no correct agent sends (look at the guest — or at
// whoever is now running in it).
const (
	guestLeaseReasonValid       = "GuestLeaseValid"
	guestLeaseReasonAbsent      = "GuestLeaseAbsent"
	guestLeaseReasonUnreachable = "GuestAgentUnreachable"
	guestLeaseReasonOverlong    = "GuestLeaseOverlong"
	guestLeaseReasonUnparsable  = "GuestLeaseUnparsable"
	guestLeaseReasonZoned       = "GuestLeaseZoned"
	guestLeaseReasonV4MappedV6  = "GuestLeaseV4MappedV6"
	guestLeaseReasonOutOfFamily = "GuestLeaseOutOfFamily"
)

// armGuestLeaseWatcher starts p's guest-lease watcher, if p is a vm pod.
//
// inert for A HOST-PROCESS POD, and inert by the RESOLVED backend (p.isVM),
// never by the requested one: a Seatbelt-confined pod has no guest, no agent
// socket and no lease, so it gets no goroutine, no dial and no field — its
// PodStatus.guest_transport_address stays empty exactly as the contract says.
//
// It is armed after registration, by CreatePod, and it refuses an unregistered
// pod for the reason armMemorySampler does: a goroutine rooted at a pod
// the daemon has already forgotten can neither be found nor stopped by any
// later teardown. It is idempotent — a second call for a pod that already has a
// watcher is a no-op — because the latch is the stopped channel itself, so
// there is no window in which two watchers could exist.
func (r *Runtime) armGuestLeaseWatcher(p *pod) {
	if !p.isVM() {
		return
	}
	podID := p.box.GetPodId()
	if p.supCtx == nil {
		// A pod assembled without a supervision context has no lifetime to root a
		// goroutine at; refusing beats starting one nothing can stop.
		r.log.Warn("refusing to arm a guest-lease watcher for a pod with no supervision context", "pod", podID)
		return
	}
	r.mu.Lock()
	_, registered := r.pods[podID]
	r.mu.Unlock()
	if !registered {
		r.log.Warn("refusing to arm a guest-lease watcher for an unregistered pod", "pod", podID)
		return
	}

	p.mu.Lock()
	if p.guestLeaseStopped != nil {
		p.mu.Unlock()
		return // already armed
	}
	stopped := make(chan struct{})
	p.guestLeaseStopped = stopped
	p.mu.Unlock()

	go func() {
		defer close(stopped)
		r.watchGuestLease(p.supCtx, p)
	}()
}

// watchGuestLease polls p's guest agent for its leased address until ctx ends,
// keeping p's live transport address current.
//
// the field is non-empty iff the most recent poll returned a valid address. A
// failed, empty or rejected poll therefore clears it rather than leaving the
// last good value standing. That is the deliberate choice, and the reason is
// that this is a DHCP lease on a shared NAT segment: an address whose guest we
// can no longer reach may already have been reassigned, so a stale value is not
// a slightly-old address — it is a dial that lands on somebody else's guest.
// Empty is the legible encoding of "no route to this pod right now", and the
// field's own contract tells consumers to re-read rather than cache.
//
// The cost of that choice is churn: a flapping agent alternates the field
// between an address and empty. It is bounded — the publish happens only on
// change, and a change costs one status event per pod per poll interval no
// matter what the guest does — which is the second reason this is a host-driven
// poll rather than a guest-driven stream.
func (r *Runtime) watchGuestLease(ctx context.Context, p *pod) {
	podID := p.box.GetPodId()
	fails := 0
	for {
		addr, reason := r.pollGuestLease(ctx, p)
		if ctx.Err() != nil {
			return // teardown raced the poll; do not publish on the way out
		}
		switch reason {
		case guestLeaseReasonValid, guestLeaseReasonAbsent:
			// A guest that answers "no lease yet" is a HEALTHY guest mid-DHCP, not
			// a failure: it keeps the fast cadence so the first lease is picked up
			// promptly rather than after a backed-off minute.
			fails = 0
		default:
			// The typed reason only — never the guest's bytes. The line rides the
			// backed-off cadence below, so an agent that answers with junk forever
			// costs one log line a minute, not one a tick: the backoff is the log
			// rate limiter as much as it is the wakeup limiter.
			fails++
			r.log.Warn("vm pod guest lease rejected",
				"pod", podID, "reason", reason, "consecutiveFailures", fails)
		}
		r.setGuestLease(p, addr)

		t := time.NewTimer(guestLeaseWait(r.guestLeasePollInterval(), fails))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// guestLeaseWait returns the delay before the next poll after fails consecutive
// failed ones: the base interval doubling to the cap, jittered.
//
// the JITTER IS not DECORATION. Every vm pod on a node arms its watcher at
// pod-create time and then polls on a fixed period; without jitter a node that
// creates ten pods together keeps those ten polls phase-locked for the pods'
// whole lives, so the vsock round trips arrive as one burst per interval
// forever. Spreading each wait over ±20% decorrelates them within a few ticks.
func guestLeaseWait(base time.Duration, fails int) time.Duration {
	d := base
	for i := 0; i < fails && d < guestLeasePollMaxBackoff; i++ {
		d *= 2
	}
	if d > guestLeasePollMaxBackoff {
		d = guestLeasePollMaxBackoff
	}
	// [0.8, 1.2) of d. rand/v2's global source is goroutine-safe, and nothing
	// here is security-sensitive: the jitter spreads wakeups, it does not hide
	// anything from anyone.
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// guestLeasePollInterval is the base Health-poll cadence (Runtime.guestLeasePoll,
// default defaultGuestLeasePoll). It is a field for the same reason drainGrace
// is one: tests shrink it, there being no clock seam in this package.
func (r *Runtime) guestLeasePollInterval() time.Duration {
	if r.guestLeasePoll > 0 {
		return r.guestLeasePoll
	}
	return defaultGuestLeasePoll
}

// pollGuestLease performs one bounded Health RPC against podID's guest agent
// and returns the address to publish (empty unless a lease was both reported
// and accepted) plus the typed reason for what it found.
//
// One connection per call, closed here — the posture dialGuest documents and
// every other guest route takes: no reconnect state machine, nothing to
// invalidate when the pod is deleted, and no way for one pod's dead socket to
// hold resources against another's.
func (r *Runtime) pollGuestLease(ctx context.Context, p *pod) (addr, reason string) {
	podID := p.box.GetPodId()
	conn, err := r.dialGuest(podID)
	if err != nil {
		return "", guestLeaseReasonUnreachable
	}
	defer func() { _ = conn.Close() }()

	cctx, cancel := context.WithTimeout(ctx, guestLeaseHealthTimeout)
	defer cancel()

	resp, err := guestv1.NewGuestAgentClient(conn).Health(cctx, &guestv1.HealthRequest{})
	if err != nil {
		// The error is not quoted onward. It is the one place a guest could put
		// arbitrary text in front of an operator via this route, and the fact worth
		// recording — "the agent did not answer" — is already the reason.
		r.log.Debug("vm pod guest health poll failed", "pod", podID)
		return "", guestLeaseReasonUnreachable
	}
	// The capability set rides the SAME response, and is recorded even when the
	// lease below is rejected: what verbs an agent serves is a fact about the
	// agent, and an address it could not lease says nothing about it. Recording
	// it here also means the fact refreshes on every poll rather than being
	// frozen at boot, which is what a guest restarted onto a different initramfs
	// requires.
	r.setGuestCapabilities(p, resp.GetCapabilities())
	// ready is deliberately not required. guest.proto orders the boot as
	// "filesystems mounted, spec read, network configured" before ready, so a
	// ready=false answer carrying a lease is the narrow window at the end of boot
	// — and the address is no less true for arriving in it.
	return parseGuestLease(resp.GetGuestIp())
}

// parseGuestLease validates one guest-reported address and returns the
// canonical form to publish, or "" plus the reason it was refused.
//
// EVERYTHING here IS untrusted (guest.proto §TRUST): the workload runs in that
// guest as root, so this string is attacker-chosen whenever the workload is.
// The narrowings, in the order they are applied:
//
//   - length FIRST, before any parse, so no parser is ever handed an
//     arbitrarily long guest-chosen string.
//   - exactly one ADDRESS, via netip.ParseAddr — which rejects a port
//     ("10.0.0.1:80"), a CIDR ("10.0.0.0/8"), a list, a hostname, and a
//     leading-zero octet. A zone ("fe80::1%eth0") parses, and is refused
//     separately: a zone names a HOST interface, and a guest does not get to
//     name one.
//   - one SPELLING. An IPv4-mapped IPv6 address is refused rather than
//     unmapped, so the same address has exactly one accepted textual form and
//     no consumer downstream has to canonicalize before comparing — and
//     "::ffff:127.0.0.1" cannot smuggle a loopback past a v4-shaped check.
//   - the VM/NAT FAMILY only. The address must be a PRIVATE UNICAST address
//     (RFC1918 / ULA), which is what a guest on the macOS vmnet NAT segment
//     always leases. That refusal covers the whole public Internet, the
//     documentation and benchmark ranges, loopback, the unspecified address,
//     every multicast scope, and link-local — where link-local matters twice
//     over, because 169.254.0.0/16 is what a guest self-assigns when DHCP
//     failed (so it is the absence of a lease, not one) and it contains the
//     cloud metadata address.
//
// residual, stated PLAINLY: private-unicast does not pin the lease to this
// node's NAT segment, so a hostile agent can still name some other private
// address — a Service VIP, a peer pod's address. Nothing in this repo can close
// that, because the only segment fact runtimed holds (GuestNetworkConfig.
// NATSubnet) is documented ADVISORY and may legitimately differ from what macOS
// assigned. What bounds the residual is on the consuming side and is a contract,
// not a check: this address is HOST-side TRANSPORT only and must never be
// published into EndpointSlice, DNS or status.podIP.
func parseGuestLease(raw string) (addr, reason string) {
	if raw == "" {
		return "", guestLeaseReasonAbsent
	}
	if len(raw) > maxGuestLeaseBytes {
		return "", guestLeaseReasonOverlong
	}
	parsed, err := netip.ParseAddr(raw)
	if err != nil {
		return "", guestLeaseReasonUnparsable
	}
	if parsed.Zone() != "" {
		return "", guestLeaseReasonZoned
	}
	if parsed.Is4In6() {
		return "", guestLeaseReasonV4MappedV6
	}
	if !parsed.IsPrivate() || parsed.IsMulticast() || parsed.IsLoopback() ||
		parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() {
		return "", guestLeaseReasonOutOfFamily
	}
	// The CANONICAL rendering, not the guest's bytes: what the host publishes is
	// this parser's output, so an unusual-but-parsable spelling never reaches a
	// consumer that might compare it as a string.
	return parsed.String(), guestLeaseReasonValid
}

// setGuestLease records addr as p's live transport address and, when it
// CHANGED, republishes the pod's status so WatchPodStatus subscribers observe
// it.
//
// It rides the pod's one status path — podStatus rendered, r.publish fanned out
// — exactly as the guest ContainerEvents fold and the restart path do. There is
// no second channel for this field: a consumer learns the address from the same
// PodStatus stream it learns everything else from, which is what makes the
// field's "only as durable as the status stream that delivered it" contract
// true rather than aspirational.
//
// The publish happens outside p.mu (the house rule for r.publish), and only on
// a real change: a poll that re-reports the same address is silent.
func (r *Runtime) setGuestLease(p *pod, addr string) {
	p.mu.Lock()
	prev := p.guestLease
	p.guestLease = addr
	p.mu.Unlock()
	if prev == addr {
		return
	}
	// Both values here are this package's own canonical parser output (or ""),
	// never the guest's bytes — which is what makes them safe to log.
	r.log.Info("vm pod guest transport address changed",
		"pod", p.box.GetPodId(), "from", prev, "to", addr)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
}
