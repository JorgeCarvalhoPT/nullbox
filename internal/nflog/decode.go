// Package nflog reads nftables egress decisions from nfnetlink_log and turns
// them into console.FlowEvents (the evidence stream). The security-critical,
// attacker-influenced part — packet bytes to a Packet — is a PURE, allocation-
// light, panic-free function fully unit-tested on any OS; only the netlink
// socket is Linux-gated.
package nflog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

var (
	// ErrShort means the copied bytes are shorter than a valid IPv4 header.
	ErrShort = errors.New("nflog: packet shorter than IPv4 header")
	// ErrVersion means the packet is not IPv4 (IPv6 is phase 2).
	ErrVersion = errors.New("nflog: not an IPv4 packet")
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	// NFULA attribute types (nfnetlink_log.h).
	nfulaPayload = 9
	nfulaPrefix  = 10
	nlaTypeMask  = 0x3fff
)

// Packet is the decoded L3/L4 summary of one logged packet.
type Packet struct {
	Proto        string
	Src, Dst     netip.Addr
	SPort, DPort uint16
}

// ParsePacket decodes the IPv4 + TCP/UDP/ICMP bytes NFLOG copied out. It is
// strict, allocation-light, and never panics — every access is bounds-checked
// because these bytes come from traffic the target influences.
func ParsePacket(b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, ErrShort
	}
	if b[0]>>4 != 4 {
		return Packet{}, ErrVersion // IPv6 is phase 2
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, ErrShort
	}
	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])
	p := Packet{Src: src, Dst: dst}
	fragOff := binary.BigEndian.Uint16(b[6:8]) & 0x1fff // only the first fragment carries L4
	switch b[9] {
	case protoTCP:
		p.Proto = "tcp"
		if fragOff == 0 && len(b) >= ihl+4 {
			p.SPort = binary.BigEndian.Uint16(b[ihl : ihl+2])
			p.DPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
		}
	case protoUDP:
		p.Proto = "udp"
		if fragOff == 0 && len(b) >= ihl+4 {
			p.SPort = binary.BigEndian.Uint16(b[ihl : ihl+2])
			p.DPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
		}
	case protoICMP:
		p.Proto = "icmp"
	default:
		p.Proto = "ip-proto-" + strconv.Itoa(int(b[9]))
	}
	return p, nil
}

// ExtractAttrs walks the host-endian nlattr TLV stream of an NFULNL_MSG_PACKET
// (the bytes after the 4-byte nfgenmsg header) and returns the L3 payload and
// the log prefix. Malformed lengths stop the walk without panicking.
func ExtractAttrs(b []byte) (payload []byte, prefix string) {
	for len(b) >= 4 {
		alen := int(binary.NativeEndian.Uint16(b[0:2]))
		atype := binary.NativeEndian.Uint16(b[2:4]) & nlaTypeMask
		if alen < 4 || alen > len(b) {
			break
		}
		val := b[4:alen]
		switch atype {
		case nfulaPayload:
			payload = val
		case nfulaPrefix:
			prefix = strings.TrimRight(string(val), "\x00")
		}
		aligned := (alen + 3) &^ 3 // 4-byte alignment
		if aligned > len(b) {
			break
		}
		b = b[aligned:]
	}
	return payload, prefix
}

// Verdict maps an NFLOG group to a verdict string, given the accept/drop groups
// the policy compiler used.
func Verdict(group, acceptGroup, dropGroup uint16) string {
	switch group {
	case acceptGroup:
		return "accept"
	case dropGroup:
		return "drop"
	default:
		return "unknown"
	}
}

// NoteFromPrefix maps a log prefix to the short human note shown in the console.
func NoteFromPrefix(prefix string) string {
	p := strings.TrimSpace(prefix)
	switch {
	case strings.HasPrefix(p, "nullbox-drop meta"):
		return "metadata"
	case strings.HasPrefix(p, "nullbox-drop deny"):
		return "explicit deny"
	case strings.HasPrefix(p, "nullbox-allow dns"):
		return "dns"
	case strings.HasPrefix(p, "nullbox-drop"):
		return "out of scope"
	case strings.HasPrefix(p, "nullbox-allow"):
		return "in scope"
	default:
		return ""
	}
}
