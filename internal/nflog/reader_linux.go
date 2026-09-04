//go:build linux

package nflog

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/JorgeCarvalhoPT/nullbox/internal/console"
)

// nfnetlink_log constants (not all exported by x/sys/unix).
const (
	nfnlSubsysULOG  = 4
	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulaCfgCmd  = 1
	nfulaCfgMode = 2

	nfulnlCfgCmdPFBind = 3
	nfulnlCfgCmdBind   = 1
	nfulnlCopyPacket   = 2

	copyRange = 128
	afINET    = 2
)

// Reader binds NFLOG groups and fans decoded FlowEvents out to subscribers.
type Reader struct {
	fd          int
	engagement  string
	acceptGroup uint16
	dropGroup   uint16

	mu      sync.Mutex
	subs    map[int]chan console.FlowEvent
	nextID  int
	closed  bool
	dropped uint64
}

// NewFeed opens a NETLINK_NETFILTER socket and binds the given NFLOG groups
// (accept group first, drop group second). Needs CAP_NET_ADMIN.
func NewFeed(engagement string, groups ...uint16) (*Reader, error) {
	if len(groups) < 2 {
		return nil, fmt.Errorf("nflog: need accept and drop groups")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nflog socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nflog bind: %w", err)
	}
	// Do not drop us on overflow; grow the receive buffer for scan bursts.
	_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_NO_ENOBUFS, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 1<<21)

	r := &Reader{fd: fd, engagement: engagement, acceptGroup: groups[0], dropGroup: groups[1], subs: map[int]chan console.FlowEvent{}}

	// Bind the AF_INET family once, then each group in copy-packet mode.
	if err := r.sendConfig(0, nfulnlCfgCmdPFBind, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	for _, g := range groups {
		if err := r.sendConfig(g, nfulnlCfgCmdBind, true); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	go r.recvLoop()
	return r, nil
}

// sendConfig sends one NFULNL_MSG_CONFIG for a group: a CMD attr, and (when
// withMode) a MODE attr requesting copy_mode=packet, copy_range=128.
func (r *Reader) sendConfig(group uint16, cmd byte, withMode bool) error {
	var attrs []byte
	attrs = append(attrs, nla(nfulaCfgCmd, []byte{cmd})...)
	if withMode {
		mode := make([]byte, 6)
		binary.BigEndian.PutUint32(mode[0:4], copyRange) // __be32 copy_range
		mode[4] = nfulnlCopyPacket                       // copy_mode
		attrs = append(attrs, nla(nfulaCfgMode, mode)...)
	}
	// nfgenmsg: family, version, res_id(group, big-endian)
	body := make([]byte, 4)
	body[0] = afINET
	body[1] = 0
	binary.BigEndian.PutUint16(body[2:4], group)
	body = append(body, attrs...)

	msg := make([]byte, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))                          // nlmsg_len
	binary.NativeEndian.PutUint16(msg[4:6], uint16(nfnlSubsysULOG<<8|nfulnlMsgConfig)) // nlmsg_type
	binary.NativeEndian.PutUint16(msg[6:8], uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK)) // nlmsg_flags
	copy(msg[unix.NLMSG_HDRLEN:], body)

	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("nflog config group %d: %w", group, err)
	}
	return nil
}

// nla builds a 4-byte-aligned netlink attribute (host-endian header).
func nla(atype uint16, val []byte) []byte {
	l := 4 + len(val)
	b := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], atype)
	copy(b[4:], val)
	return b
}

func (r *Reader) recvLoop() {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			r.mu.Lock()
			done := r.closed
			r.mu.Unlock()
			if done {
				return
			}
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type == unix.NLMSG_ERROR || m.Header.Type == unix.NLMSG_DONE {
				continue
			}
			if int(m.Header.Type>>8) != nfnlSubsysULOG || int(m.Header.Type&0xff) != nfulnlMsgPacket {
				continue
			}
			if len(m.Data) < 4 {
				continue
			}
			group := binary.BigEndian.Uint16(m.Data[2:4]) // nfgenmsg res_id
			payload, prefix := ExtractAttrs(m.Data[4:])
			pkt, perr := ParsePacket(payload)
			if perr != nil {
				continue
			}
			r.broadcast(console.FlowEvent{
				Ts:         time.Now().UTC().Format(time.RFC3339),
				Engagement: r.engagement,
				Proto:      pkt.Proto,
				Src:        pkt.Src.String(),
				Dst:        pkt.Dst.String(),
				DPort:      int(pkt.DPort),
				Verdict:    Verdict(group, r.acceptGroup, r.dropGroup),
				Note:       NoteFromPrefix(prefix),
			})
		}
	}
}

func (r *Reader) broadcast(ev console.FlowEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.subs {
		select {
		case ch <- ev:
		default:
			atomic.AddUint64(&r.dropped, 1) // never block the netlink loop
		}
	}
}

// Subscribe returns a bounded channel of FlowEvents and a cancel func.
func (r *Reader) Subscribe() (<-chan console.FlowEvent, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID
	r.nextID++
	ch := make(chan console.FlowEvent, 256)
	r.subs[id] = ch
	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if c, ok := r.subs[id]; ok {
			delete(r.subs, id)
			close(c)
		}
	}
}

// Close stops the reader and releases the socket.
func (r *Reader) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return unix.Close(r.fd)
}
