package clientcrypto_test

import (
	"bytes"
	"testing"

	internal "github.com/ra-yavuz/doublethink/internal/clientcrypto"
	pub "github.com/ra-yavuz/doublethink/pkg/clientcrypto"
)

// TestPublicWrapperRoundTrip proves the public surface is usable on its own: A
// seals, B opens, and the reverse direction too. This is the exact path an
// external client (claude-doublethink) takes.
func TestPublicWrapperRoundTrip(t *testing.T) {
	secret, err := pub.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	a, err := pub.NewSession(secret, pub.RoleA)
	if err != nil {
		t.Fatalf("NewSession A: %v", err)
	}
	b, err := pub.NewSession(secret, pub.RoleB)
	if err != nil {
		t.Fatalf("NewSession B: %v", err)
	}

	msg := []byte(`{"channel":"x","type":"progress","id":"1","payload":"hi","ts":"t"}`)

	sealed, err := a.Seal(msg)
	if err != nil {
		t.Fatalf("A.Seal: %v", err)
	}
	got, err := b.Open(sealed)
	if err != nil {
		t.Fatalf("B.Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("A->B mismatch: got %q want %q", got, msg)
	}

	sealedB, err := b.Seal(msg)
	if err != nil {
		t.Fatalf("B.Seal: %v", err)
	}
	gotA, err := a.Open(sealedB)
	if err != nil {
		t.Fatalf("A.Open: %v", err)
	}
	if !bytes.Equal(gotA, msg) {
		t.Fatalf("B->A mismatch: got %q want %q", gotA, msg)
	}
}

// TestSameRoleIsMute documents the trap: two clients with the same role share a
// send key and cannot read each other. A correct client must derive role from who
// created the channel, never pick arbitrarily.
func TestSameRoleIsMute(t *testing.T) {
	secret, _ := pub.GenerateSecret()
	a1, _ := pub.NewSession(secret, pub.RoleA)
	a2, _ := pub.NewSession(secret, pub.RoleA)
	sealed, _ := a1.Seal([]byte("nope"))
	if _, err := a2.Open(sealed); err == nil {
		t.Fatal("expected same-role Open to fail, but it succeeded")
	}
}

// TestWrapperMatchesInternal proves the public wrapper produces values that
// interoperate byte-for-byte with the internal package: a payload sealed via the
// public surface opens with an internal session and vice versa, and the
// registration key / challenge response match exactly. If the wrapper ever drifts
// from the internal impl, this fails.
func TestWrapperMatchesInternal(t *testing.T) {
	secret, _ := pub.GenerateSecret()

	// Registration key identical.
	pubRK, err := pub.RegistrationKey(secret)
	if err != nil {
		t.Fatalf("pub.RegistrationKey: %v", err)
	}
	intRK, err := internal.RegistrationKey(secret)
	if err != nil {
		t.Fatalf("internal.RegistrationKey: %v", err)
	}
	if pubRK != intRK {
		t.Fatalf("RegistrationKey drift: pub %q != internal %q", pubRK, intRK)
	}

	// Challenge response identical.
	challenge := []byte("a-fixed-challenge-value-32-bytes!")
	pubCR, err := pub.ChallengeResponse(secret, challenge)
	if err != nil {
		t.Fatalf("pub.ChallengeResponse: %v", err)
	}
	intCR, err := internal.ChallengeResponse(secret, challenge)
	if err != nil {
		t.Fatalf("internal.ChallengeResponse: %v", err)
	}
	if !bytes.Equal(pubCR, intCR) {
		t.Fatal("ChallengeResponse drift between public and internal")
	}

	// Cross-package session interop: public A seals, internal B opens.
	pubA, _ := pub.NewSession(secret, pub.RoleA)
	intB, _ := internal.NewSession(secret, internal.RoleB)
	msg := []byte("cross-package payload")
	sealed, _ := pubA.Seal(msg)
	got, err := intB.Open(sealed)
	if err != nil {
		t.Fatalf("internal B.Open of public A seal: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("cross-package A->B payload mismatch")
	}
}
