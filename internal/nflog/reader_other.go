//go:build !linux

package nflog

import (
	"errors"

	"github.com/JorgeCarvalhoPT/nullbox/internal/console"
)

// ErrUnsupported is returned by NewFeed off Linux.
var ErrUnsupported = errors.New("nflog: egress feed needs a Linux host with nfnetlink_log")

// Reader is a no-op on non-Linux hosts.
type Reader struct{}

// NewFeed is unavailable off Linux; callers fall back to a nil console.Feed.
func NewFeed(engagement string, groups ...uint16) (*Reader, error) { return nil, ErrUnsupported }

// Subscribe satisfies console.Feed with an already-closed channel.
func (r *Reader) Subscribe() (<-chan console.FlowEvent, func()) {
	ch := make(chan console.FlowEvent)
	close(ch)
	return ch, func() {}
}

// Close is a no-op.
func (r *Reader) Close() error { return nil }
