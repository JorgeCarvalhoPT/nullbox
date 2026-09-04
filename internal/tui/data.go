package tui

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

func demoEngagements() []engagement {
	day := func(n int) string { return time.Now().Add(time.Duration(n) * 24 * time.Hour).Format(time.RFC3339) }
	return []engagement{
		{
			name: "acme-internal", client: "ACME Corp", driver: "firecracker", profile: "routed", state: "running",
			authRef: "SOW-2026-0142", windowEnd: day(9), image: "nullbox/guest:full",
			workspace: "/Users/op/engagements/acme/internal", res: "12%/4c · 6.2GB · routed · 8d 21h",
			scope: []scopeEntry{{"10.10.0.0/16", "allow"}, {"10.20.5.0/24:443,8443", "allow"},
				{"portal.acme.example", "allow"}, {"10.10.9.0/24", "deny"}},
			dsts: []string{"10.10.1.14", "10.10.4.9", "10.20.5.7:443", "10.10.22.3", "portal.acme.example:443"},
			outs: []string{"10.10.9.12", "8.8.8.8", "169.254.169.254"}, demo: true,
		},
		{
			name: "acme-web", client: "ACME Corp", driver: "krun", profile: "nat", state: "running",
			authRef: "SOW-2026-0143", windowEnd: day(5), image: "nullbox/guest:thin",
			workspace: "/Users/op/engagements/acme/web", res: "4%/2c · 1.9GB · nat · 4d 06h",
			scope: []scopeEntry{{"app.acme.example", "allow"}, {"*.staging.acme.example", "allow"}},
			dsts:  []string{"app.acme.example:443", "api.staging.acme.example:443"},
			outs:  []string{"cdn.evil.example:443"}, demo: true,
		},
		{
			name: "beta-scan", client: "Beta LLC", driver: "firecracker", profile: "routed", state: "killed",
			authRef: "SOW-2026-0130", windowEnd: day(-1), image: "nullbox/guest:full",
			workspace: "/Users/op/engagements/beta/scan", res: "stopped",
			scope: []scopeEntry{{"198.51.100.0/24", "allow"}},
			dsts:  []string{"198.51.100.4"}, outs: []string{"198.51.100.250"}, demo: true,
		},
	}
}

func fromRecord(r store.Record) engagement {
	e := engagement{
		name: r.Name, client: r.Client, driver: r.Driver, profile: r.Profile, state: r.State,
		authRef: r.AuthRef, windowEnd: r.WindowEnd, image: r.ImageRef, workspace: r.Workspace,
		res: r.Profile, outs: []string{"169.254.169.254"},
	}
	for _, s := range r.Scope {
		e.scope = append(e.scope, scopeEntry{s.Target, s.Kind})
		if s.Kind == "allow" {
			e.dsts = append(e.dsts, s.Target)
		}
	}
	return e
}

func seedFeed(e *engagement) {
	if e.state != "running" {
		return
	}
	for i := 0; i < 9; i++ {
		e.feed = append(e.feed, genEvent(*e, i > 7))
	}
}

func genEvent(e engagement, forceDrop bool) flowEvent {
	drop := forceDrop || rand.Float64() < 0.1
	pool := e.dsts
	if drop {
		pool = e.outs
	}
	if len(pool) == 0 {
		pool = []string{"10.0.0.2"}
	}
	raw := pool[rand.Intn(len(pool))]
	dst, dport := raw, 443
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		dst = raw[:i]
		fmt.Sscanf(raw[i+1:], "%d", &dport)
	} else {
		dport = []int{443, 8443, 80, 22, 53}[rand.Intn(5)]
	}
	proto := "tcp"
	switch {
	case drop:
		proto = []string{"udp", "tcp", "icmp"}[rand.Intn(3)]
	case dport == 53:
		proto = "udp"
	}
	ev := flowEvent{ts: time.Now(), proto: proto, dst: dst, dport: dport, verdict: "accept"}
	if drop {
		ev.verdict = "drop"
		ev.note = "out of scope"
		if dst == "169.254.169.254" {
			ev.note = "metadata"
		}
	}
	return ev
}

type aggRow struct {
	dst, proto, verdict, note string
	dport, hits               int
	ts                        time.Time
}

// aggregate collapses the event feed into one row per destination:port with a
// hit count — the egress "log" view.
func aggregate(e engagement) []aggRow {
	byKey := map[string]*aggRow{}
	var order []string
	for _, ev := range e.feed {
		key := fmt.Sprintf("%s:%d", ev.dst, ev.dport)
		r, ok := byKey[key]
		if !ok {
			r = &aggRow{dst: ev.dst, dport: ev.dport}
			byKey[key] = r
			order = append(order, key)
		}
		r.hits++
		r.proto, r.verdict, r.note, r.ts = ev.proto, ev.verdict, ev.note, ev.ts
	}
	rows := make([]aggRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, *byKey[k])
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ts.After(rows[j].ts) })
	return rows
}

func truncate(s string, n int) string {
	if n < 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
