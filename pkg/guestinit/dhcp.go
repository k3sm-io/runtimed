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

package guestinit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// The DHCPv4 wire constants this client uses (RFC 2131 / RFC 2132). Only the
// options a guest needs to configure one interface are named; an option the
// server sends that is not here is skipped, not rejected — a DHCP server is
// entitled to offer more than its client asked for.
const (
	dhcpOpBootRequest = 1
	dhcpOpBootReply   = 2
	dhcpHTypeEthernet = 1
	dhcpHLenEthernet  = 6

	// dhcpFlagBroadcast asks the server to BROADCAST its reply rather than
	// unicast it to the address being offered.
	//
	// It is load-bearing, not optional. This client runs on an interface with no
	// address yet, so a unicast reply addressed to the offered lease would be
	// dropped by the kernel before any socket saw it — which is why most DHCP
	// clients open a raw AF_PACKET socket and assemble Ethernet/IP/UDP by hand.
	// Setting this flag is what lets a plain UDP socket serve instead, and it
	// removes about a hundred and fifty lines of hand-rolled framing and
	// checksums from a guest that has no way to unit-test them.
	dhcpFlagBroadcast = 0x8000

	// dhcpFixedLen is the fixed header through the magic cookie: 236 bytes of
	// BOOTP header plus the 4-byte cookie. Options begin at this offset.
	dhcpFixedLen = 240
	// dhcpMaxLen bounds a reply this client will parse. A DHCP reply is a single
	// UDP datagram and the protocol's own minimum MTU assumption is 576; 1500
	// covers any real server with room to spare, and bounding it means a
	// malformed length can never make this allocate.
	dhcpMaxLen = 1500

	dhcpOptPad          = 0
	dhcpOptSubnetMask   = 1
	dhcpOptRouter       = 3
	dhcpOptDNS          = 6
	dhcpOptRequestedIP  = 50
	dhcpOptLeaseTime    = 51
	dhcpOptMessageType  = 53
	dhcpOptServerID     = 54
	dhcpOptParamRequest = 55
	dhcpOptClientID     = 61
	dhcpOptEnd          = 255

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
)

// dhcpMagic is the BOOTP vendor-option cookie that marks a DHCP message.
var dhcpMagic = [4]byte{99, 130, 83, 99}

// ErrDHCP reports a DHCP exchange that did not produce a usable lease. Compare
// with errors.Is.
var ErrDHCP = errors.New("guestinit: dhcp")

// Lease is one DHCPv4 lease, as the guest will configure it.
//
// It carries only what configuring an interface needs. Notably it is a LEASE and
// not an identity: guest/v1's HealthResponse.guest_ip — the field Address ends up
// in — documents that a consumer re-reads it and never caches it as a stable
// identifier, and the S5 spike measured stability across restarts only because
// the host stamps a deterministic MAC, which is the host's property to keep, not
// the guest's to assume.
type Lease struct {
	// Address is the leased IPv4 address (DHCP yiaddr).
	Address netip.Addr
	// Mask is the subnet mask (option 1). A server that sends none leaves this
	// unset and Validate rejects the lease: a guest guessing a classful mask
	// would silently mis-route everything off-subnet.
	Mask netip.Addr
	// Gateway is the first router (option 3), the default route's next hop.
	Gateway netip.Addr
	// DNS are the offered resolvers (option 6), in order. k3sm does not use
	// them — the pod's resolv.conf is host-rendered from the cluster's DNS
	// policy — but they are parsed so the console can report what the segment
	// offered when a name does not resolve.
	DNS []netip.Addr
	// ServerID is the DHCP server (option 54), echoed in the REQUEST.
	ServerID netip.Addr
	// Duration is the lease time (option 51); zero when the server sent none.
	Duration time.Duration
}

// PrefixLen returns the lease's prefix length derived from Mask.
func (l Lease) PrefixLen() (int, error) {
	if !l.Mask.Is4() {
		return 0, fmt.Errorf("%w: lease carries no subnet mask", ErrDHCP)
	}
	b := l.Mask.As4()
	ones := 0
	seenZero := false
	for _, octet := range b {
		for bit := 7; bit >= 0; bit-- {
			if octet&(1<<bit) != 0 {
				if seenZero {
					// A non-contiguous mask (255.0.255.0) is not a prefix. Refusing
					// beats picking one of the two readings: every consumer of the
					// result — the address to set, the route to add — assumes CIDR.
					return 0, fmt.Errorf("%w: subnet mask %s is not contiguous", ErrDHCP, l.Mask)
				}
				ones++
				continue
			}
			seenZero = true
		}
	}
	return ones, nil
}

// Prefix returns the lease as an address/prefix pair.
func (l Lease) Prefix() (netip.Prefix, error) {
	n, err := l.PrefixLen()
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(l.Address, n), nil
}

// Validate rejects a lease the guest cannot configure from.
//
// FAIL CLOSED, and specifically: a lease missing any of the address, the mask or
// the gateway is refused rather than partially applied. A guest that brought up
// an address with no route looks Running and reaches nothing — the silent mode
// this whole class of defect keeps producing — and one with no mask cannot even
// decide what is on-link.
func (l Lease) Validate() error {
	switch {
	case !l.Address.Is4() || l.Address.IsUnspecified():
		return fmt.Errorf("%w: no address offered", ErrDHCP)
	case !l.Mask.Is4():
		return fmt.Errorf("%w: no subnet mask offered", ErrDHCP)
	case !l.Gateway.Is4() || l.Gateway.IsUnspecified():
		return fmt.Errorf("%w: no router offered, so the guest would have no default route", ErrDHCP)
	}
	if _, err := l.PrefixLen(); err != nil {
		return err
	}
	return nil
}

// BuildDiscover renders a DHCPDISCOVER for the given transaction id and MAC.
func BuildDiscover(xid uint32, mac []byte) ([]byte, error) {
	return buildDHCP(xid, mac, dhcpDiscover, nil, netip.Addr{}, netip.Addr{})
}

// BuildRequest renders the DHCPREQUEST that accepts offered from serverID. Both
// are echoed as options 50 and 54, which is what tells any OTHER server on the
// segment that its own offer was declined.
func BuildRequest(xid uint32, mac []byte, offered, serverID netip.Addr) ([]byte, error) {
	return buildDHCP(xid, mac, dhcpRequest, nil, offered, serverID)
}

// buildDHCP renders one client message.
func buildDHCP(xid uint32, mac []byte, msgType byte, _ []byte, requested, serverID netip.Addr) ([]byte, error) {
	if len(mac) != dhcpHLenEthernet {
		return nil, fmt.Errorf("%w: hardware address must be %d bytes, got %d", ErrDHCP, dhcpHLenEthernet, len(mac))
	}
	buf := make([]byte, dhcpFixedLen, dhcpFixedLen+64)
	buf[0] = dhcpOpBootRequest
	buf[1] = dhcpHTypeEthernet
	buf[2] = dhcpHLenEthernet
	buf[3] = 0 // hops
	binary.BigEndian.PutUint32(buf[4:8], xid)
	binary.BigEndian.PutUint16(buf[8:10], 0) // secs
	binary.BigEndian.PutUint16(buf[10:12], dhcpFlagBroadcast)
	// ciaddr/yiaddr/siaddr/giaddr stay zero: this client only ever configures
	// from scratch (it has no address to renew from — see the package's lack of
	// a renewal loop, recorded on ConfigureNetwork).
	copy(buf[28:44], mac)
	copy(buf[236:240], dhcpMagic[:])

	buf = appendOption(buf, dhcpOptMessageType, []byte{msgType})
	// Option 61 as the RFC 4361 ethernet form: type 1 followed by the MAC. A
	// server keys its lease table on this, which is what makes the address stable
	// across guest restarts given the host's deterministic MAC (S5 criterion 5).
	buf = appendOption(buf, dhcpOptClientID, append([]byte{dhcpHTypeEthernet}, mac...))
	if requested.Is4() && !requested.IsUnspecified() {
		a := requested.As4()
		buf = appendOption(buf, dhcpOptRequestedIP, a[:])
	}
	if serverID.Is4() && !serverID.IsUnspecified() {
		a := serverID.As4()
		buf = appendOption(buf, dhcpOptServerID, a[:])
	}
	buf = appendOption(buf, dhcpOptParamRequest, []byte{dhcpOptSubnetMask, dhcpOptRouter, dhcpOptDNS, dhcpOptLeaseTime})
	buf = append(buf, dhcpOptEnd)
	return buf, nil
}

// appendOption appends one TLV. A value longer than 255 bytes cannot be encoded
// in one option and this client never builds one, so the length is a plain cast.
func appendOption(buf []byte, code byte, val []byte) []byte {
	buf = append(buf, code, byte(len(val)))
	return append(buf, val...)
}

// ParseReply decodes a server message into its type and lease, checking that it
// is a reply to xid for mac.
//
// EVERY FIELD IS UNTRUSTED. The datagram arrives on a broadcast segment shared
// with whatever else the host's NAT attaches, so the transaction id and the
// client hardware address are checked before anything is believed, every option
// is bounds-checked against the remaining buffer, and a truncated option ends the
// parse rather than reading past it. A message that fails any of these is
// reported as not-for-us so the caller keeps waiting for the real one instead of
// failing the boot on a stray packet.
func ParseReply(buf []byte, xid uint32, mac []byte) (msgType byte, lease Lease, ok bool, err error) {
	if len(buf) < dhcpFixedLen || len(buf) > dhcpMaxLen {
		return 0, Lease{}, false, nil
	}
	if buf[0] != dhcpOpBootReply || buf[1] != dhcpHTypeEthernet {
		return 0, Lease{}, false, nil
	}
	if binary.BigEndian.Uint32(buf[4:8]) != xid {
		return 0, Lease{}, false, nil
	}
	if len(mac) != dhcpHLenEthernet || string(buf[28:34]) != string(mac) {
		return 0, Lease{}, false, nil
	}
	if string(buf[236:240]) != string(dhcpMagic[:]) {
		return 0, Lease{}, false, nil
	}

	lease.Address = netip.AddrFrom4([4]byte(buf[16:20])) // yiaddr
	for i := dhcpFixedLen; i < len(buf); {
		code := buf[i]
		if code == dhcpOptEnd {
			break
		}
		if code == dhcpOptPad {
			i++
			continue
		}
		if i+2 > len(buf) {
			return 0, Lease{}, false, fmt.Errorf("%w: option %d is truncated", ErrDHCP, code)
		}
		n := int(buf[i+1])
		if i+2+n > len(buf) {
			return 0, Lease{}, false, fmt.Errorf("%w: option %d claims %d bytes past the end of the message", ErrDHCP, code, n)
		}
		val := buf[i+2 : i+2+n]
		switch code {
		case dhcpOptMessageType:
			if n == 1 {
				msgType = val[0]
			}
		case dhcpOptSubnetMask:
			if n == 4 {
				lease.Mask = netip.AddrFrom4([4]byte(val))
			}
		case dhcpOptRouter:
			if n >= 4 {
				// Only the FIRST router is taken. The option is a list in
				// preference order and this guest installs one default route; a
				// second gateway would need a metric policy nothing here has.
				lease.Gateway = netip.AddrFrom4([4]byte(val[:4]))
			}
		case dhcpOptDNS:
			for off := 0; off+4 <= n; off += 4 {
				lease.DNS = append(lease.DNS, netip.AddrFrom4([4]byte(val[off:off+4])))
			}
		case dhcpOptServerID:
			if n == 4 {
				lease.ServerID = netip.AddrFrom4([4]byte(val))
			}
		case dhcpOptLeaseTime:
			if n == 4 {
				lease.Duration = time.Duration(binary.BigEndian.Uint32(val)) * time.Second
			}
		}
		i += 2 + n
	}
	if msgType == 0 {
		return 0, Lease{}, false, nil // not a DHCP message, just BOOTP
	}
	return msgType, lease, true, nil
}

// IsOffer / IsAck / IsNak name the reply types the client acts on, so the caller
// reads as the state machine rather than as magic numbers.
func IsOffer(t byte) bool { return t == dhcpOffer }
func IsAck(t byte) bool   { return t == dhcpAck }
func IsNak(t byte) bool   { return t == dhcpNak }
