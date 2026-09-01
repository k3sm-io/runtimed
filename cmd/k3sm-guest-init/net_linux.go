//go:build linux

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

package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/guestinit"
)

// The guest's two interfaces. Both are fixed by the machine the vmhost builds:
// one loopback and one virtio-net attached to the host's NAT segment.
const (
	loopbackName = "lo"
	guestNICName = "eth0"
)

// The DHCP exchange's budget. A DHCP solicitation is a UDP broadcast and is
// entitled to be lost, so a single timeout is not a failure — RFC 2131 says
// retransmit. dhcpAttempts bounded by dhcpAttemptTimeout is the whole budget
// before the boot is failed; it is short because the pod is not up until it
// finishes and the host has its own boot deadline waiting on Health.
const (
	dhcpAttempts       = 4
	dhcpAttemptTimeout = 3 * time.Second
	dhcpClientPort     = 68
	dhcpServerPort     = 67
)

// GuestNetwork is the configuration this guest applied to itself.
type GuestNetwork struct {
	Interface string
	Lease     guestinit.Lease
	Prefix    netip.Prefix
	MTU       int
}

// configureNetwork brings the guest's interfaces up, leases an address for eth0
// and installs the default route, returning what it configured.
//
// the WHOLE POINT, recorded because its absence was invisible: before this, lo
// was DOWN and eth0 was DOWN with no address and no routes. A container binding
// 127.0.0.1 could not, nothing could reach the cluster DNS VIP, and — because
// HealthResponse.guest_ip is fed from what this function records — the host had
// no transport address for the pod at all.
//
// ORDER MATTERS. lo comes up first and unconditionally: it is not part of the
// lease and a guest whose DHCP fails should still have had its loopback, which
// makes the failure legible rather than compounded. eth0 must be UP before the
// DHCP socket can send on it, and the address must be set before the default
// route can be installed (the kernel refuses a gateway that is not on-link).
func configureNetwork(log *slog.Logger) (GuestNetwork, error) {
	if err := linkUp(loopbackName); err != nil {
		return GuestNetwork{}, fmt.Errorf("bring %s up: %w", loopbackName, err)
	}
	log.Info("brought the loopback up", "link", loopbackName)

	if err := linkUp(guestNICName); err != nil {
		return GuestNetwork{}, fmt.Errorf("bring %s up: %w", guestNICName, err)
	}
	mac, err := linkHardwareAddr(guestNICName)
	if err != nil {
		return GuestNetwork{}, err
	}
	lease, err := dhcpLease(log, guestNICName, mac)
	if err != nil {
		return GuestNetwork{}, err
	}
	prefix, err := lease.Prefix()
	if err != nil {
		return GuestNetwork{}, err
	}
	if err := setIPv4(guestNICName, lease.Address, lease.Mask); err != nil {
		return GuestNetwork{}, err
	}
	if err := addDefaultRoute(guestNICName, lease.Gateway); err != nil {
		return GuestNetwork{}, err
	}
	mtu, err := linkMTU(guestNICName)
	if err != nil {
		return GuestNetwork{}, err
	}
	return GuestNetwork{Interface: guestNICName, Lease: lease, Prefix: prefix, MTU: mtu}, nil
}

// ioctlSocket opens the datagram socket every SIOC* ioctl below is issued on.
// The socket is only a handle for the ioctl; nothing is sent on it.
func ioctlSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open an ioctl socket: %w", err)
	}
	return fd, nil
}

// linkUp sets IFF_UP on a link, preserving every other flag.
//
// It READS the flags first and ORs. Writing IFF_UP alone would clear
// IFF_BROADCAST and IFF_MULTICAST, which the DHCP broadcast below depends on.
func linkUp(name string) error {
	fd, err := ioctlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("ifreq %s: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get flags for %s: %w", name, err)
	}
	flags := ifr.Uint16()
	if flags&unix.IFF_UP != 0 {
		return nil
	}
	ifr.SetUint16(flags | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	return nil
}

// linkHardwareAddr reads a link's MAC, which the DHCP client sends as chaddr and
// as its client identifier.
//
// net.InterfaceByName rather than the SIOCGIFHWADDR ioctl: x/sys/unix's Ifreq
// exposes no accessor for the sockaddr union the ioctl fills, so reading it would
// mean reproducing that union's layout by hand — the same by-hand-ABI risk the
// route below uses netlink to avoid, for six bytes the standard library already
// returns correctly.
func linkHardwareAddr(name string) ([]byte, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("look up %s: %w", name, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("%s has a %d-byte hardware address; dhcp needs a 6-byte ethernet one",
			name, len(iface.HardwareAddr))
	}
	return append([]byte(nil), iface.HardwareAddr...), nil
}

// linkMTU reads a link's MTU. The S5 spike measured 1500 on this hardware and
// recorded that the link will not lower it; this reports what the kernel says
// rather than restating that number.
func linkMTU(name string) (int, error) {
	fd, err := ioctlSocket()
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, fmt.Errorf("ifreq %s: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFMTU, ifr); err != nil {
		return 0, fmt.Errorf("get the mtu of %s: %w", name, err)
	}
	return int(ifr.Uint32()), nil
}

// setIPv4 assigns an address and netmask to a link.
func setIPv4(name string, addr, mask netip.Addr) error {
	fd, err := ioctlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, step := range []struct {
		req  uint
		val  netip.Addr
		what string
	}{
		{unix.SIOCSIFADDR, addr, "address"},
		{unix.SIOCSIFNETMASK, mask, "netmask"},
	} {
		ifr, ierr := unix.NewIfreq(name)
		if ierr != nil {
			return fmt.Errorf("ifreq %s: %w", name, ierr)
		}
		if serr := ifr.SetInet4Addr(step.val.AsSlice()); serr != nil {
			return fmt.Errorf("encode the %s %s: %w", step.what, step.val, serr)
		}
		if ierr := unix.IoctlIfreq(fd, step.req, ifr); ierr != nil {
			return fmt.Errorf("set the %s of %s to %s: %w", step.what, name, step.val, ierr)
		}
	}
	return nil
}

// addDefaultRoute installs 0.0.0.0/0 via gw on the named link, over netlink.
//
// NETLINK, not the SIOCADDRT ioctl. That ioctl takes a `struct rtentry` whose
// layout this code would have to reproduce by hand — eleven fields with
// architecture-dependent padding, on a path no darwin test can execute. The
// netlink message is assembled from x/sys/unix's own typed headers, whose sizes
// and alignment come from the platform rather than from a comment, so the one
// class of bug that cannot be caught here is not the one being risked.
func addDefaultRoute(link string, gw netip.Addr) error {
	iface, err := net.InterfaceByName(link)
	if err != nil {
		return fmt.Errorf("look up %s: %w", link, err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open a netlink socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind the netlink socket: %w", err)
	}

	rt := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  0, // 0.0.0.0/0
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_BOOT,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	gw4 := gw.As4()
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(iface.Index))

	body := make([]byte, 0, 64)
	body = append(body, (*(*[unsafe.Sizeof(rt)]byte)(unsafe.Pointer(&rt)))[:]...)
	body = appendRtAttr(body, unix.RTA_GATEWAY, gw4[:])
	body = appendRtAttr(body, unix.RTA_OIF, oif)

	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(body)),
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_REPLACE | unix.NLM_F_ACK,
		Seq:   1,
	}
	msg := make([]byte, 0, int(hdr.Len))
	msg = append(msg, (*(*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr)))[:]...)
	msg = append(msg, body...)

	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("request a default route via %s: %w", gw, err)
	}
	return readNetlinkAck(fd, gw)
}

// appendRtAttr appends one rtattr, padded to NLA alignment. The pad is part of
// the wire format, not an optimization: an unaligned attribute makes the kernel
// misparse every attribute after it.
func appendRtAttr(buf []byte, typ uint16, val []byte) []byte {
	l := unix.SizeofRtAttr + len(val)
	attr := unix.RtAttr{Len: uint16(l), Type: typ}
	buf = append(buf, (*(*[unix.SizeofRtAttr]byte)(unsafe.Pointer(&attr)))[:]...)
	buf = append(buf, val...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// readNetlinkAck reads the kernel's reply to a route request.
//
// The ACK is not optional. NLM_F_ACK asks for one precisely so a rejected route
// is an error here rather than a guest that believes it has a default route and
// silently reaches nothing — the failure mode this whole file exists to end.
func readNetlinkAck(fd int, gw netip.Addr) error {
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("read the netlink reply for the default route via %s: %w", gw, err)
	}
	// The nlmsghdr is walked by hand rather than through a helper: its layout is
	// fixed by the protocol (len, type, flags, seq, pid — 16 bytes) and x/sys
	// gives the size as a constant, so this reads the two fields it needs without
	// depending on a parser the vendored version may or may not export.
	for off := 0; off+unix.NLMSG_HDRLEN <= n; {
		msgLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
		msgType := binary.LittleEndian.Uint16(buf[off+4 : off+6])
		if msgLen < unix.NLMSG_HDRLEN || off+msgLen > n {
			return fmt.Errorf("truncated netlink reply for the default route via %s", gw)
		}
		if msgType == unix.NLMSG_ERROR {
			body := buf[off+unix.NLMSG_HDRLEN : off+msgLen]
			if len(body) < 4 {
				return fmt.Errorf("truncated netlink error for the default route via %s", gw)
			}
			// A zero errno in an NLMSG_ERROR is the ACK; anything else is the
			// kernel refusing the route, and must not be mistaken for success.
			if code := int32(binary.LittleEndian.Uint32(body[:4])); code != 0 {
				return fmt.Errorf("kernel refused the default route via %s: %w", gw, unix.Errno(-code))
			}
			return nil
		}
		off += (msgLen + 3) &^ 3
	}
	return nil
}

// dhcpLease runs the DISCOVER/OFFER/REQUEST/ACK exchange on link and returns the
// validated lease.
//
// A PLAIN UDP SOCKET, not AF_PACKET. The interface has no address yet, so this
// binds 0.0.0.0:68 with SO_BINDTODEVICE (which is what lets the kernel send to
// the limited broadcast with no route in the table) and sets the DHCP BROADCAST
// flag so the server broadcasts its replies rather than unicasting them to an
// address this interface does not have. The alternative — a raw packet socket
// with hand-assembled Ethernet, IP and UDP headers and their checksums — is a
// large body of code that no test on a darwin host could execute; the payload
// encode/decode that remains is pure and is unit-tested (pkg/guestinit/dhcp.go).
func dhcpLease(log *slog.Logger, link string, mac []byte) (guestinit.Lease, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return guestinit.Lease{}, fmt.Errorf("open a dhcp socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		return guestinit.Lease{}, fmt.Errorf("enable broadcast on the dhcp socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return guestinit.Lease{}, fmt.Errorf("set reuseaddr on the dhcp socket: %w", err)
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, link); err != nil {
		return guestinit.Lease{}, fmt.Errorf("bind the dhcp socket to %s: %w", link, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: dhcpClientPort}); err != nil {
		return guestinit.Lease{}, fmt.Errorf("bind the dhcp socket to :%d: %w", dhcpClientPort, err)
	}
	bcast := &unix.SockaddrInet4{Port: dhcpServerPort, Addr: [4]byte{255, 255, 255, 255}}

	var lastErr error
	for attempt := 1; attempt <= dhcpAttempts; attempt++ {
		xid := rand.Uint32()
		lease, err := dhcpRound(fd, bcast, xid, mac)
		if err == nil {
			return lease, nil
		}
		lastErr = err
		log.Warn("dhcp attempt did not produce a lease; retrying",
			"link", link, "attempt", attempt, "of", dhcpAttempts, "err", err)
	}
	return guestinit.Lease{}, fmt.Errorf("%w: no lease on %s after %d attempts: %w",
		guestinit.ErrDHCP, link, dhcpAttempts, lastErr)
}

// dhcpRound is one DISCOVER→OFFER→REQUEST→ACK cycle within the attempt budget.
func dhcpRound(fd int, to *unix.SockaddrInet4, xid uint32, mac []byte) (guestinit.Lease, error) {
	discover, err := guestinit.BuildDiscover(xid, mac)
	if err != nil {
		return guestinit.Lease{}, err
	}
	if err := unix.Sendto(fd, discover, 0, to); err != nil {
		return guestinit.Lease{}, fmt.Errorf("send DHCPDISCOVER: %w", err)
	}
	offer, err := awaitReply(fd, xid, mac, guestinit.IsOffer)
	if err != nil {
		return guestinit.Lease{}, err
	}

	request, err := guestinit.BuildRequest(xid, mac, offer.Address, offer.ServerID)
	if err != nil {
		return guestinit.Lease{}, err
	}
	if err := unix.Sendto(fd, request, 0, to); err != nil {
		return guestinit.Lease{}, fmt.Errorf("send DHCPREQUEST: %w", err)
	}
	ack, err := awaitReply(fd, xid, mac, guestinit.IsAck)
	if err != nil {
		return guestinit.Lease{}, err
	}
	// The ACK is authoritative, but a server may omit an option it already sent
	// in the OFFER; fill only from the offer, never the other way round.
	if !ack.Mask.IsValid() {
		ack.Mask = offer.Mask
	}
	if !ack.Gateway.IsValid() {
		ack.Gateway = offer.Gateway
	}
	if len(ack.DNS) == 0 {
		ack.DNS = offer.DNS
	}
	if err := ack.Validate(); err != nil {
		return guestinit.Lease{}, err
	}
	return ack, nil
}

// awaitReply reads datagrams until one matches want, or the attempt's budget is
// spent. A NAK ends the round immediately: the server has refused, and waiting
// out the timeout would only delay the retry.
func awaitReply(fd int, xid uint32, mac []byte, want func(byte) bool) (guestinit.Lease, error) {
	deadline := time.Now().Add(dhcpAttemptTimeout)
	buf := make([]byte, 1500)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return guestinit.Lease{}, fmt.Errorf("%w: no reply within %s", guestinit.ErrDHCP, dhcpAttemptTimeout)
		}
		tv := unix.NsecToTimeval(int64(remaining))
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return guestinit.Lease{}, fmt.Errorf("set the dhcp receive timeout: %w", err)
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return guestinit.Lease{}, fmt.Errorf("%w: receive: %w", guestinit.ErrDHCP, err)
		}
		msgType, lease, ok, perr := guestinit.ParseReply(buf[:n], xid, mac)
		if perr != nil || !ok {
			continue // not ours, or malformed: keep waiting for the real one
		}
		if guestinit.IsNak(msgType) {
			return guestinit.Lease{}, fmt.Errorf("%w: the server sent DHCPNAK", guestinit.ErrDHCP)
		}
		if want(msgType) {
			return lease, nil
		}
	}
}
