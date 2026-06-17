package admin

import "testing"

func TestDisabledWhenUnset(t *testing.T) {
	a, status := From("")
	if a.Enabled() {
		t.Fatal("admin enabled with empty key")
	}
	if a.Verify("anything") {
		t.Fatal("Verify true while disabled")
	}
	if status == "" {
		t.Fatal("empty status string")
	}
}

func TestDisabledWhenWeak(t *testing.T) {
	a, _ := From("short")
	if a.Enabled() {
		t.Fatal("admin enabled with a too-short key")
	}
	if a.Verify("short") {
		t.Fatal("weak key verified; admin must be disabled")
	}
}

func TestEnabledWithStrongKey(t *testing.T) {
	key := "example-strong-admin-key-0123456789abcd" // 39 chars, not a real key
	a, status := From(key)
	if !a.Enabled() {
		t.Fatalf("admin not enabled with a strong key; status=%q", status)
	}
	if !a.Verify(key) {
		t.Fatal("correct admin key rejected")
	}
	if a.Verify(key + "x") {
		t.Fatal("wrong admin key accepted")
	}
	if a.Verify("") {
		t.Fatal("empty presented key accepted")
	}
}

func TestExactlyMinLength(t *testing.T) {
	key := "01234567890123456789012345678901" // 32 chars
	a, _ := From(key)
	if !a.Enabled() {
		t.Fatal("32-char key should be accepted (>= 32)")
	}
}
