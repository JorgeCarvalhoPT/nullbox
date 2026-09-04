package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

func TestListAndIndex(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	if err := store.Save(store.Record{
		Name: "acme-internal", Driver: "firecracker", Profile: "routed",
		State: "running", CreatedAt: time.Now(),
		Scope: []store.ScopeEntry{{Target: "10.10.0.0/16", Kind: "allow"}},
	}); err != nil {
		t.Fatal(err)
	}
	h := New(nil).Handler()

	// /api/engagements returns the seeded record.
	rec := do(t, h, http.MethodGet, "/api/engagements", 200)
	var recs []store.Record
	if err := json.Unmarshal(rec.Body.Bytes(), &recs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 || recs[0].Name != "acme-internal" {
		t.Fatalf("unexpected engagements: %+v", recs)
	}

	// / serves the wrapped UI document.
	idx := do(t, h, http.MethodGet, "/", 200)
	body := idx.Body.String()
	if !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "nullbox console") {
		t.Errorf("index missing document wrapper or title")
	}
}

func TestGetAndKillRouting(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	_ = store.Save(store.Record{Name: "acme", Driver: "firecracker", Profile: "routed", State: "running", CreatedAt: time.Now()})
	h := New(nil).Handler()

	do(t, h, http.MethodGet, "/api/engagements/acme", 200)
	do(t, h, http.MethodGet, "/api/engagements/ghost", 404)       // unknown name
	do(t, h, http.MethodPost, "/api/engagements/ghost/kill", 404) // kill unknown -> 404 before driver
}

// A feed that emits one event then closes, so the SSE handler writes and returns.
type oneShotFeed struct{}

func (oneShotFeed) Subscribe() (<-chan FlowEvent, func()) {
	ch := make(chan FlowEvent, 1)
	ch <- FlowEvent{Ts: "now", Engagement: "acme", Proto: "tcp", Dst: "10.10.1.5", DPort: 443, Verdict: "accept"}
	close(ch)
	return ch, func() {}
}

func TestEventsSSE(t *testing.T) {
	h := New(oneShotFeed{}).Handler()
	rec := do(t, h, http.MethodGet, "/api/events", 200)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected SSE content-type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"verdict":"accept"`) {
		t.Errorf("expected an accept event in the stream, got: %q", rec.Body.String())
	}
}

func do(t *testing.T, h http.Handler, method, path string, wantCode int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != wantCode {
		t.Fatalf("%s %s: got %d, want %d (body: %s)", method, path, rec.Code, wantCode, rec.Body.String())
	}
	return rec
}
