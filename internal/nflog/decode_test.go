package nflog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4 builds a minimal IPv4 header (ihl words) + payload.
func ipv4(ihlWords, proto int, src, dst string, fragOff uint16, l4 []byte) []byte {
	ihl := ihlWords * 4
	b := make([]byte, ihl+len(l4))
	b[0] = 0x40 | byte(ihlWords) // version 4, IHL
	binary.BigEndian.PutUint16(b[6:8], fragOff&0x1fff)
	b[9] = byte(proto)
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(b[ihl:], l4)
	return b
}

func l4Ports(sp, dp uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], sp)
	binary.BigEndian.PutUint16(b[2:4], dp)
	return b
}

func TestParsePacket(t *testing.T) {
	tcp := ipv4(5, protoTCP, "10.244.0.2", "10.20.5.7", 0, l4Ports(51000, 443))
	p, err := ParsePacket(tcp)
	if err != nil || p.Proto != "tcp" || p.DPort != 443 || p.Dst.String() != "10.20.5.7" {
		t.Fatalf("tcp parse: %+v err %v", p, err)
	}

	udp := ipv4(5, protoUDP, "10.244.0.2", "10.20.5.7", 0, l4Ports(40000, 53))
	if p, _ := ParsePacket(udp); p.Proto != "udp" || p.DPort != 53 {
		t.Errorf("udp parse: %+v", p)
	}

	icmp := ipv4(5, protoICMP, "10.244.0.2", "10.10.9.1", 0, []byte{8, 0})
	if p, _ := ParsePacket(icmp); p.Proto != "icmp" || p.DPort != 0 {
		t.Errorf("icmp parse: %+v", p)
	}

	// IHL > 5 (options) — ports read at the right offset.
	opt := ipv4(6, protoTCP, "10.0.0.1", "10.0.0.2", 0, l4Ports(1, 8443))
	if p, _ := ParsePacket(opt); p.DPort != 8443 {
		t.Errorf("ihl>5 parse dport = %d, want 8443", p.DPort)
	}

	// Non-first fragment — no L4, DPort 0.
	frag := ipv4(5, protoTCP, "10.0.0.1", "10.0.0.2", 24, l4Ports(1, 443))
	if p, _ := ParsePacket(frag); p.DPort != 0 {
		t.Errorf("fragment dport = %d, want 0", p.DPort)
	}

	// Unknown protocol.
	if p, _ := ParsePacket(ipv4(5, 47, "1.1.1.1", "2.2.2.2", 0, nil)); p.Proto != "ip-proto-47" {
		t.Errorf("unknown proto = %q", p.Proto)
	}

	// Errors.
	if _, err := ParsePacket([]byte{0x45, 0, 0}); err != ErrShort {
		t.Errorf("short => %v, want ErrShort", err)
	}
	if _, err := ParsePacket(ipv4(5, protoTCP, "1.1.1.1", "2.2.2.2", 0, l4Ports(1, 2))[:20]); err != nil {
		t.Errorf("20-byte header with no L4 should not error: %v", err)
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if _, err := ParsePacket(v6); err != ErrVersion {
		t.Errorf("ipv6 => %v, want ErrVersion", err)
	}
}

func TestExtractAttrs(t *testing.T) {
	// Build a synthetic nlattr stream: PREFIX then PAYLOAD, host-endian headers.
	attr := func(atype uint16, val []byte) []byte {
		l := 4 + len(val)
		b := make([]byte, (l+3)&^3)
		binary.NativeEndian.PutUint16(b[0:2], uint16(l))
		binary.NativeEndian.PutUint16(b[2:4], atype)
		copy(b[4:], val)
		return b
	}
	pkt := ipv4(5, protoTCP, "10.0.0.1", "10.20.5.7", 0, l4Ports(1, 443))
	stream := append(attr(nfulaPrefix, []byte("nullbox-allow \x00")), attr(nfulaPayload, pkt)...)

	payload, prefix := ExtractAttrs(stream)
	if prefix != "nullbox-allow " {
		t.Errorf("prefix = %q", prefix)
	}
	if p, err := ParsePacket(payload); err != nil || p.DPort != 443 {
		t.Errorf("payload didn't round-trip: %+v err %v", p, err)
	}

	// Malformed (short nla_len) stops without panic.
	bad := []byte{0x02, 0x00, 0x09, 0x00} // alen=2 < 4
	if pl, _ := ExtractAttrs(bad); pl != nil {
		t.Errorf("malformed stream should yield no payload")
	}
}

func TestVerdictAndNote(t *testing.T) {
	if Verdict(331, 331, 332) != "accept" || Verdict(332, 331, 332) != "drop" || Verdict(9, 331, 332) != "unknown" {
		t.Error("Verdict mapping wrong")
	}
	cases := map[string]string{
		"nullbox-drop meta ": "metadata",
		"nullbox-drop deny ": "explicit deny",
		"nullbox-drop ":      "out of scope",
		"nullbox-allow dns ": "dns",
		"nullbox-allow ":     "in scope",
		"other":              "",
	}
	for in, want := range cases {
		if got := NoteFromPrefix(in); got != want {
			t.Errorf("NoteFromPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
