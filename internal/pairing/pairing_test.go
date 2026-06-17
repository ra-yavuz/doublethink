package pairing

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func key(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n
	}
	return b
}

func randKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateAndRedeem(t *testing.T) {
	m := NewManager()
	inv, err := m.Create("chan", "agent", key(1), key(2))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Code == "" {
		t.Fatal("empty pairing code")
	}
	got, sas, err := m.Redeem(inv.Code, key(3), key(4))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if got.Channel != "chan" {
		t.Errorf("channel = %q", got.Channel)
	}
	if sas == "" {
		t.Error("empty SAS")
	}
}

// Single use: a code cannot be redeemed twice. This stops a captured code from
// being replayed to pair an attacker after the legitimate peer used it.
func TestSingleUse(t *testing.T) {
	m := NewManager()
	inv, _ := m.Create("chan", "agent", key(1), key(2))
	if _, _, err := m.Redeem(inv.Code, key(3), key(4)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Redeem(inv.Code, key(5), key(6)); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("second redeem = %v, want ErrNoInvite", err)
	}
}

// Expired invites cannot be redeemed.
func TestExpiry(t *testing.T) {
	m := NewManager()
	base := time.Unix(1_000_000, 0)
	nowFunc = func() time.Time { return base }
	defer func() { nowFunc = time.Now }()

	inv, _ := m.Create("chan", "agent", key(1), key(2))
	// Advance past the TTL.
	nowFunc = func() time.Time { return base.Add(InviteTTL + time.Second) }
	if _, _, err := m.Redeem(inv.Code, key(3), key(4)); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("redeem of expired invite = %v, want ErrNoInvite", err)
	}
}

// Unknown code is a uniform ErrNoInvite (no distinction from expired/used).
func TestUnknownCode(t *testing.T) {
	m := NewManager()
	if _, _, err := m.Redeem("nope", key(3), key(4)); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("unknown code = %v, want ErrNoInvite", err)
	}
}

// Rate limit: a channel cannot have unbounded outstanding invites.
func TestRateLimit(t *testing.T) {
	m := NewManager()
	for i := 0; i < maxInvitesPerChannel; i++ {
		if _, err := m.Create("chan", "agent", key(byte(i)), key(byte(i+100))); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := m.Create("chan", "agent", key(99), key(199)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("over-limit create = %v, want ErrRateLimited", err)
	}
	// A different channel is unaffected.
	if _, err := m.Create("other", "agent", key(1), key(2)); err != nil {
		t.Fatalf("other channel create: %v", err)
	}
}

// The SAS is identical whether computed from inviter's or joiner's vantage point
// (keys sorted), so both humans see the same string to compare.
func TestSASSymmetric(t *testing.T) {
	idA, ecdhA := randKey(t), randKey(t)
	idB, ecdhB := randKey(t), randKey(t)
	s1 := ComputeSAS("chan", "agent", idA, ecdhA, idB, ecdhB, "code")
	s2 := ComputeSAS("chan", "agent", idB, ecdhB, idA, ecdhA, "code")
	if s1 != s2 {
		t.Fatalf("SAS not symmetric: %q vs %q", s1, s2)
	}
}

// The MITM-detection guarantee: substituting either peer's key changes the SAS,
// so a man-in-the-middle that swapped a key cannot make both sides see the same
// string. This is the property that lets out-of-band SAS comparison catch a MITM.
func TestSASChangesOnKeySubstitution(t *testing.T) {
	idA, ecdhA := randKey(t), randKey(t)
	idB, ecdhB := randKey(t), randKey(t)
	honest := ComputeSAS("chan", "agent", idA, ecdhA, idB, ecdhB, "code")

	// Attacker substitutes B's identity key with its own.
	evilID := randKey(t)
	substituted := ComputeSAS("chan", "agent", idA, ecdhA, evilID, ecdhB, "code")
	if honest == substituted {
		t.Fatal("SAS unchanged after identity-key substitution; MITM would go undetected")
	}

	// And substituting the ECDH key also changes it.
	evilECDH := randKey(t)
	substituted2 := ComputeSAS("chan", "agent", idA, ecdhA, idB, evilECDH, "code")
	if honest == substituted2 {
		t.Fatal("SAS unchanged after ECDH-key substitution; MITM would go undetected")
	}
}

// The SAS also binds the channel and code, so the same keys on a different channel
// or under a different code yield a different SAS (anti cross-binding).
func TestSASBindsContext(t *testing.T) {
	idA, ecdhA := randKey(t), randKey(t)
	idB, ecdhB := randKey(t), randKey(t)
	base := ComputeSAS("chan1", "agent", idA, ecdhA, idB, ecdhB, "code1")
	if base == ComputeSAS("chan2", "agent", idA, ecdhA, idB, ecdhB, "code1") {
		t.Error("SAS did not change with channel")
	}
	if base == ComputeSAS("chan1", "agent", idA, ecdhA, idB, ecdhB, "code2") {
		t.Error("SAS did not change with code")
	}
}

// SAS format is the human-comparable XXXX-XXXX shape.
func TestSASFormat(t *testing.T) {
	s := ComputeSAS("c", "r", key(1), key(2), key(3), key(4), "code")
	if len(s) != 9 || s[4] != '-' {
		t.Errorf("SAS format = %q, want XXXX-XXXX", s)
	}
}
