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
	"net/netip"
	"testing"
	"time"
)

var testMAC = []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}

// serverReply builds a DHCP server message the way macOS's bootpd would, so the
// parser is driven against the wire format rather than against its own encoder.
func serverReply(xid uint32, mac []byte, msgType byte, yiaddr string, opts map[byte][]byte) []byte {
	buf := make([]byte, dhcpFixedLen)
	buf[0] = dhcpOpBootReply
	buf[1] = dhcpHTypeEthernet
	buf[2] = dhcpHLenEthernet
	binary.BigEndian.PutUint32(buf[4:8], xid)
	if yiaddr != "" {
		a := netip.MustParseAddr(yiaddr).As4()
		copy(buf[16:20], a[:])
	}
	copy(buf[28:44], mac)
	copy(buf[236:240], dhcpMagic[:])
	buf = appendOption(buf, dhcpOptMessageType, []byte{msgType})
	for code, val := range opts {
		buf = appendOption(buf, code, val)
	}
	return append(buf, dhcpOptEnd)
}

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

// TestDHCPClientMessages pins what the guest puts on the wire. The two facts
// that matter operationally are the BROADCAST flag — without it a server unicasts
// its reply to an address the interface does not have yet, and the guest never
// sees it — and the client identifier, which is what makes the lease stable
// across restarts given the host's deterministic MAC (S5 criterion 5).
func TestDHCPClientMessages(t *testing.T) {
	t.Run("discover-sets-the-broadcast-flag", func(t *testing.T) {
		msg, err := BuildDiscover(0xdeadbeef, testMAC)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(msg[10:12]); got&dhcpFlagBroadcast == 0 {
			t.Errorf("flags = %#04x, want the BROADCAST bit set; without it the reply is unicast to an address this interface does not have", got)
		}
		if msg[0] != dhcpOpBootRequest || msg[1] != dhcpHTypeEthernet || msg[2] != dhcpHLenEthernet {
			t.Errorf("bootp header = %v, want a 6-byte ethernet BOOTREQUEST", msg[:4])
		}
		if string(msg[28:34]) != string(testMAC) {
			t.Errorf("chaddr = %v, want %v", msg[28:34], testMAC)
		}
		if string(msg[236:240]) != string(dhcpMagic[:]) {
			t.Error("the magic cookie is missing; a server reads the message as plain BOOTP without it")
		}
	})

	t.Run("discover-and-request-carry-the-expected-options", func(t *testing.T) {
		offered := netip.MustParseAddr("192.168.66.7")
		server := netip.MustParseAddr("192.168.66.1")
		disc, err := BuildDiscover(1, testMAC)
		if err != nil {
			t.Fatal(err)
		}
		req, err := BuildRequest(1, testMAC, offered, server)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name   string
			msg    []byte
			want   map[byte][]byte
			absent []byte
		}{
			{
				name: "discover",
				msg:  disc,
				want: map[byte][]byte{
					dhcpOptMessageType: {dhcpDiscover},
					dhcpOptClientID:    append([]byte{dhcpHTypeEthernet}, testMAC...),
				},
				// A DISCOVER must not claim a server: it has not heard from one.
				absent: []byte{dhcpOptServerID, dhcpOptRequestedIP},
			},
			{
				name: "request",
				msg:  req,
				want: map[byte][]byte{
					dhcpOptMessageType: {dhcpRequest},
					dhcpOptRequestedIP: ip4("192.168.66.7"),
					// Echoing the server id is what declines any OTHER offer on
					// the segment; omitting it makes a second server hold a lease
					// this guest will never use.
					dhcpOptServerID: ip4("192.168.66.1"),
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := optionsOf(t, tc.msg)
				for code, want := range tc.want {
					if string(got[code]) != string(want) {
						t.Errorf("option %d = %v, want %v", code, got[code], want)
					}
				}
				for _, code := range tc.absent {
					if _, present := got[code]; present {
						t.Errorf("option %d must not be present", code)
					}
				}
				if _, present := got[dhcpOptParamRequest]; !present {
					t.Error("no parameter request list; a server may then send no subnet mask or router at all")
				}
			})
		}
	})

	t.Run("a-bad-hardware-address-is-refused", func(t *testing.T) {
		if _, err := BuildDiscover(1, []byte{1, 2, 3}); !errors.Is(err, ErrDHCP) {
			t.Errorf("err = %v, want ErrDHCP", err)
		}
	})
}

// optionsOf walks a rendered message's option block.
func optionsOf(t *testing.T, msg []byte) map[byte][]byte {
	t.Helper()
	out := map[byte][]byte{}
	for i := dhcpFixedLen; i < len(msg); {
		if msg[i] == dhcpOptEnd {
			break
		}
		if msg[i] == dhcpOptPad {
			i++
			continue
		}
		if i+2 > len(msg) {
			t.Fatalf("truncated option block at %d", i)
		}
		n := int(msg[i+1])
		if i+2+n > len(msg) {
			t.Fatalf("option %d overruns the message", msg[i])
		}
		out[msg[i]] = msg[i+2 : i+2+n]
		i += 2 + n
	}
	return out
}

// TestDHCPParseReply is the untrusted-input half: the datagram arrives on a
// broadcast segment shared with whatever else the host attaches, so a message
// that is not this client's must be ignored rather than acted on or fatal.
func TestDHCPParseReply(t *testing.T) {
	const xid = 0x11223344
	full := map[byte][]byte{
		dhcpOptSubnetMask: ip4("255.255.255.0"),
		dhcpOptRouter:     ip4("192.168.66.1"),
		dhcpOptDNS:        append(ip4("192.168.66.1"), ip4("8.8.8.8")...),
		dhcpOptServerID:   ip4("192.168.66.1"),
		dhcpOptLeaseTime:  {0, 0, 0x0e, 0x10}, // 3600s
	}

	t.Run("an-ack-yields-a-complete-lease", func(t *testing.T) {
		typ, lease, ok, err := ParseReply(serverReply(xid, testMAC, dhcpAck, "192.168.66.7", full), xid, testMAC)
		if err != nil || !ok {
			t.Fatalf("ParseReply: ok=%v err=%v", ok, err)
		}
		if !IsAck(typ) {
			t.Errorf("type = %d, want ACK", typ)
		}
		if lease.Address != netip.MustParseAddr("192.168.66.7") {
			t.Errorf("address = %s", lease.Address)
		}
		if lease.Gateway != netip.MustParseAddr("192.168.66.1") {
			t.Errorf("gateway = %s", lease.Gateway)
		}
		if lease.ServerID != netip.MustParseAddr("192.168.66.1") {
			t.Errorf("server id = %s", lease.ServerID)
		}
		if lease.Duration != time.Hour {
			t.Errorf("duration = %s, want 1h", lease.Duration)
		}
		if len(lease.DNS) != 2 {
			t.Errorf("dns = %v, want two resolvers", lease.DNS)
		}
		if err := lease.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
		p, err := lease.Prefix()
		if err != nil || p.String() != "192.168.66.7/24" {
			t.Errorf("prefix = %v, %v; want 192.168.66.7/24", p, err)
		}
	})

	t.Run("messages-that-are-not-ours-are-ignored-not-fatal", func(t *testing.T) {
		other := []byte{0x52, 0x54, 0x00, 0x99, 0x99, 0x99}
		cases := []struct {
			name string
			msg  []byte
			xid  uint32
			mac  []byte
		}{
			{"another-transaction", serverReply(0x55667788, testMAC, dhcpAck, "192.168.66.7", full), xid, testMAC},
			{"another-client", serverReply(xid, other, dhcpAck, "192.168.66.9", full), xid, testMAC},
			{"too-short", make([]byte, 100), xid, testMAC},
			{"a-request-not-a-reply", func() []byte {
				m := serverReply(xid, testMAC, dhcpAck, "192.168.66.7", full)
				m[0] = dhcpOpBootRequest
				return m
			}(), xid, testMAC},
			{"no-magic-cookie", func() []byte {
				m := serverReply(xid, testMAC, dhcpAck, "192.168.66.7", full)
				copy(m[236:240], []byte{0, 0, 0, 0})
				return m
			}(), xid, testMAC},
			{"plain-bootp-with-no-message-type", func() []byte {
				m := make([]byte, dhcpFixedLen)
				m[0] = dhcpOpBootReply
				m[1] = dhcpHTypeEthernet
				m[2] = dhcpHLenEthernet
				binary.BigEndian.PutUint32(m[4:8], xid)
				copy(m[28:44], testMAC)
				copy(m[236:240], dhcpMagic[:])
				return append(m, dhcpOptEnd)
			}(), xid, testMAC},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, ok, err := ParseReply(tc.msg, tc.xid, tc.mac)
				if ok {
					t.Error("a message that is not this client's was accepted")
				}
				if err != nil {
					t.Errorf("err = %v; a stray packet must not fail the boot", err)
				}
			})
		}
	})

	t.Run("a-truncated-option-is-refused-not-read-past", func(t *testing.T) {
		msg := serverReply(xid, testMAC, dhcpAck, "192.168.66.7", nil)
		// Drop the terminating END and append an option claiming more bytes than
		// remain — the classic over-read.
		msg = append(msg[:len(msg)-1], dhcpOptSubnetMask, 40, 1, 2)
		if _, _, ok, err := ParseReply(msg, xid, testMAC); ok || err == nil {
			t.Errorf("ok=%v err=%v; an option overrunning the message must be refused", ok, err)
		}
	})

	t.Run("a-nak-is-reported-as-a-nak", func(t *testing.T) {
		typ, _, ok, err := ParseReply(serverReply(xid, testMAC, dhcpNak, "", nil), xid, testMAC)
		if err != nil || !ok || !IsNak(typ) {
			t.Errorf("type=%d ok=%v err=%v; want a recognised NAK", typ, ok, err)
		}
	})
}

// TestLeaseValidation is the fail-closed half. A partially applied lease is the
// silent mode this whole change exists to end: an address with no route looks
// configured and reaches nothing.
func TestLeaseValidation(t *testing.T) {
	addr := netip.MustParseAddr("192.168.66.7")
	gw := netip.MustParseAddr("192.168.66.1")
	mask := netip.MustParseAddr("255.255.255.0")

	cases := []struct {
		name    string
		lease   Lease
		wantErr string
	}{
		{"complete", Lease{Address: addr, Mask: mask, Gateway: gw}, ""},
		{"no-address", Lease{Mask: mask, Gateway: gw}, "no address"},
		{"unspecified-address", Lease{Address: netip.MustParseAddr("0.0.0.0"), Mask: mask, Gateway: gw}, "no address"},
		{"no-mask", Lease{Address: addr, Gateway: gw}, "no subnet mask"},
		{"no-gateway", Lease{Address: addr, Mask: mask}, "no router"},
		{"non-contiguous-mask", Lease{Address: addr, Mask: netip.MustParseAddr("255.0.255.0"), Gateway: gw}, "not contiguous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.lease.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate accepted %+v", tc.lease)
			}
			if !errors.Is(err, ErrDHCP) {
				t.Errorf("err = %v, want ErrDHCP in the chain", err)
			}
			if !contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestLeasePrefixLen pins the mask→prefix conversion the address assignment and
// the route both depend on.
func TestLeasePrefixLen(t *testing.T) {
	cases := []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.255.255.252", 30},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.mask, func(t *testing.T) {
			l := Lease{Address: netip.MustParseAddr("10.0.0.1"), Mask: netip.MustParseAddr(tc.mask)}
			got, err := l.PrefixLen()
			if err != nil {
				t.Fatalf("PrefixLen: %v", err)
			}
			if got != tc.want {
				t.Errorf("PrefixLen = %d, want %d", got, tc.want)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
