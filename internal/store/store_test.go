package store

import (
	"testing"
	"time"
)

func TestSaveLoadListDelete(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())

	if got, err := List(); err != nil || len(got) != 0 {
		t.Fatalf("empty store: got %v err %v", got, err)
	}

	a := Record{Name: "acme", Driver: "firecracker", Profile: "routed", State: "running", CreatedAt: time.Now().Add(-time.Hour)}
	b := Record{Name: "beta", Driver: "krun", Profile: "nat", State: "running", CreatedAt: time.Now()}
	for _, r := range []Record{a, b} {
		if err := Save(r); err != nil {
			t.Fatalf("save %s: %v", r.Name, err)
		}
	}

	got, err := Load("acme")
	if err != nil {
		t.Fatalf("load acme: %v", err)
	}
	if got.Driver != "firecracker" || got.Profile != "routed" {
		t.Errorf("load acme mismatch: %+v", got)
	}

	list, err := List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 records, got %d", len(list))
	}
	// Newest first: beta was created later.
	if list[0].Name != "beta" {
		t.Errorf("expected newest-first ordering, got %s first", list[0].Name)
	}

	if err := Delete("acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := Load("acme"); err == nil {
		t.Error("expected load of deleted record to fail")
	}
	// Delete is idempotent.
	if err := Delete("acme"); err != nil {
		t.Errorf("second delete should be nil, got %v", err)
	}
}

func TestRejectsUnsafeNames(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	for _, bad := range []string{"", "../etc/passwd", "a/b", "x..y"} {
		if err := Save(Record{Name: bad}); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
		if _, err := Load(bad); err == nil {
			t.Errorf("expected load(%q) to be rejected", bad)
		}
	}
}
