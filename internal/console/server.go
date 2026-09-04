// Package console is nullbox's operator UI — the sbx-dashboard equivalent, but
// for the containment layer sbx never surfaced: which engagements are live,
// their authorized scope, a running feed of in-scope vs out-of-scope egress,
// the window countdown to auto-expiry, and a per-engagement kill switch.
//
// One HTML file (ui/index.html) is served two ways: embedded here for the live
// console (it calls the /api endpoints below), and published as an Artifact
// where the same page falls back to demo data because the sandbox blocks fetch.
package console

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

//go:embed ui/index.html
var uiFS embed.FS

// FlowEvent is one egress decision on the nft path — the evidence stream.
type FlowEvent struct {
	Ts         string `json:"ts"`
	Engagement string `json:"engagement"`
	Proto      string `json:"proto"`
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	DPort      int    `json:"dport"`
	Verdict    string `json:"verdict"` // "accept" | "drop"
	Note       string `json:"note,omitempty"`
}

// Feed is the source of live flow events. A driver wires one that tails the
// nftables log (`nullbox-drop`) plus accepted-flow accounting; nil means no
// live feed (the console still serves state, and the UI simulates the feed).
type Feed interface {
	// Subscribe returns a channel of events and a cancel func to stop it.
	Subscribe() (<-chan FlowEvent, func())
}

// Server serves the console API and the embedded UI.
type Server struct{ feed Feed }

// New builds a console server. feed may be nil.
func New(feed Feed) *Server { return &Server{feed: feed} }

// Handler returns the HTTP mux (Go 1.22 method+wildcard patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/engagements", s.list)
	mux.HandleFunc("GET /api/engagements/{name}", s.get)
	mux.HandleFunc("POST /api/engagements/{name}/kill", s.kill)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /", s.index)
	return mux
}

func (s *Server) list(w http.ResponseWriter, _ *http.Request) {
	recs, err := store.List()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	if recs == nil {
		recs = []store.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	rec, err := store.Load(r.PathValue("name"))
	if err != nil {
		httpErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) kill(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rec, err := store.Load(name)
	if err != nil {
		httpErr(w, http.StatusNotFound, err)
		return
	}
	d, err := driver.Get(model.Driver(rec.Driver))
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if err := d.Kill(name); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "flushed", "engagement": name})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	if s.feed == nil {
		// No live feed: keep the stream open but silent; the UI simulates.
		w.WriteHeader(http.StatusOK)
		if flusher != nil {
			flusher.Flush()
		}
		<-r.Context().Done()
		return
	}
	ch, cancel := s.feed.Subscribe()
	defer cancel()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	frag, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "console UI missing from build", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The UI file is authored as an Artifact fragment (no <html>/<head>/<body>);
	// wrap it into a standalone document when served directly.
	fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1"></head>`+
		`<body style="margin:0">`)
	w.Write(frag)
	fmt.Fprint(w, "</body></html>")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
