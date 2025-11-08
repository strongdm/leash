package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestManagerUpsertCreate(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	secret, err := mgr.Upsert("db_password", "", "supersecret")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if secret.ID != "db_password" {
		t.Fatalf("expected id db_password, got %s", secret.ID)
	}
	if secret.Value != "supersecret" {
		t.Fatalf("expected value to round-trip, got %s", secret.Value)
	}
	wantLen := len(secret.Value)
	if wantLen < minPlaceholderLength {
		wantLen = minPlaceholderLength
	}
	if len(secret.Placeholder) != wantLen {
		t.Fatalf("expected placeholder length %d, got %d", wantLen, len(secret.Placeholder))
	}
	if secret.Activations != 0 {
		t.Fatalf("expected zero activations, got %d", secret.Activations)
	}
}

func TestManagerPlaceholderLengthMatchesWhenLongerThanMinimum(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	longValue := strings.Repeat("x", minPlaceholderLength+5)
	secret, err := mgr.Upsert("long", "", longValue)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if len(secret.Placeholder) != len(longValue) {
		t.Fatalf("expected placeholder length %d, got %d", len(longValue), len(secret.Placeholder))
	}
}

func TestManagerUpsertUpdateRegeneratesPlaceholder(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	created, err := mgr.Upsert("api_key", "", "initial")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	updated, err := mgr.Upsert("api_key", "", "rotated")
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if updated.Placeholder == created.Placeholder {
		t.Fatalf("expected placeholder regeneration on value change")
	}
	if updated.Activations != 0 {
		t.Fatalf("expected activations to remain zero, got %d", updated.Activations)
	}

	all := mgr.GetAll()
	if latest, ok := all["api_key"]; !ok || latest.Placeholder != updated.Placeholder {
		t.Fatalf("GetAll missing updated placeholder")
	}
}

func TestManagerRenamePreservesPlaceholderAndActivations(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	created, err := mgr.Upsert("old_id", "", "value")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	deltas := mgr.ReplaceStats(map[string]int{"old_id": 3})
	if deltas["old_id"] != 3 {
		t.Fatalf("expected activations 3, got %#v", deltas)
	}

	renamed, err := mgr.Upsert("old_id", "new_id", "value")
	if err != nil {
		t.Fatalf("rename failed: %v", err)
	}
	if renamed.ID != "new_id" {
		t.Fatalf("expected new id, got %s", renamed.ID)
	}
	if renamed.Placeholder != created.Placeholder {
		t.Fatalf("expected placeholder to remain stable on rename")
	}
	if renamed.Activations != 3 {
		t.Fatalf("expected activations to persist, got %d", renamed.Activations)
	}

	_, _, ok := mgr.LookupByPlaceholder(created.Placeholder)
	if !ok {
		t.Fatalf("expected placeholder lookup to succeed after rename")
	}
}

func TestManagerDeleteRemovesPlaceholder(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	secret, err := mgr.Upsert("temp", "", "value")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, _, ok := mgr.LookupByPlaceholder(secret.Placeholder); !ok {
		t.Fatalf("expected placeholder lookup to succeed")
	}
	if err := mgr.Delete("temp"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, _, ok := mgr.LookupByPlaceholder(secret.Placeholder); ok {
		t.Fatalf("expected placeholder lookup to fail after delete")
	}
}

func TestManagerRenameConflict(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	if _, err := mgr.Upsert("first", "", "one"); err != nil {
		t.Fatalf("create first failed: %v", err)
	}
	if _, err := mgr.Upsert("second", "", "two"); err != nil {
		t.Fatalf("create second failed: %v", err)
	}

	if _, err := mgr.Upsert("first", "second", "one"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestManagerInvalidID(t *testing.T) {
	t.Parallel()
	mgr := NewManager()

	if _, err := mgr.Upsert("invalid id", "", "value"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("expected ErrInvalidID, got %v", err)
	}
	if err := mgr.Delete(""); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("expected ErrInvalidID for delete, got %v", err)
	}
}
