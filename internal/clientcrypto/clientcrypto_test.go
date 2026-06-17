package clientcrypto

import (
	"bytes"
	"testing"
)

// pairedSessions sets up two device identities, exchanges public keys, and derives
// each peer's session for a channel, exactly as pairing then connecting would.
func pairedSessions(t *testing.T, channel string) (a, b *Session, idA, idB *Identity) {
	t.Helper()
	idA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a, err = idA.Derive(idB.ECDHPublic(), channel)
	if err != nil {
		t.Fatalf("peer A derive: %v", err)
	}
	b, err = idB.Derive(idA.ECDHPublic(), channel)
	if err != nil {
		t.Fatalf("peer B derive: %v", err)
	}
	return a, b, idA, idB
}

// The core round trip: what peer A seals, peer B opens, and vice versa. This is
// the bidirectional confidentiality both directions of CodeSpeak's channel need.
func TestSealOpenBothDirections(t *testing.T) {
	a, b, _, _ := pairedSessions(t, "codespeak/xyz")

	msgAtoB := []byte(`{"step":"ran tests","detail":"42 passed"}`)
	blob, err := a.Seal(msgAtoB)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(blob)
	if err != nil {
		t.Fatalf("B could not open A's message: %v", err)
	}
	if !bytes.Equal(got, msgAtoB) {
		t.Errorf("A->B plaintext mismatch:\n got %s\nwant %s", got, msgAtoB)
	}

	msgBtoA := []byte(`{"control":"barge-in"}`)
	blob2, err := b.Seal(msgBtoA)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := a.Open(blob2)
	if err != nil {
		t.Fatalf("A could not open B's message: %v", err)
	}
	if !bytes.Equal(got2, msgBtoA) {
		t.Errorf("B->A plaintext mismatch:\n got %s\nwant %s", got2, msgBtoA)
	}
}

// Test 3, the differentiator (SECURITY.md req 3): the broker, holding only the
// sealed blob and NO key, cannot recover the plaintext. We simulate the broker by
// having a third identity (or no key at all) try to open the blob.
func TestBrokerCannotReadSealedPayload(t *testing.T) {
	a, _, _, _ := pairedSessions(t, "private")
	secret := []byte("code context and a shell command the operator must not see")
	blob, err := a.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}

	// The plaintext must not appear anywhere in the blob that crosses the broker.
	if bytes.Contains(blob, secret) {
		t.Fatal("plaintext is present in the sealed blob the broker sees")
	}

	// A third party (the broker, or any eavesdropper) with its OWN freshly derived
	// session cannot open it: it never had either peer's private key.
	eve, _, _, _ := pairedSessions(t, "private")
	if _, err := eve.Open(blob); err == nil {
		t.Fatal("an unrelated session opened the sealed payload; confidentiality broken")
	}
}

// A key bound to a DIFFERENT channel id derives a different secret, so a blob
// sealed for one channel cannot be opened with another channel's session even by
// the same two peers. This ties the crypto to the channel (anti-confusion).
func TestChannelBindingSeparatesKeys(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()

	aChan1, _ := idA.Derive(idB.ECDHPublic(), "channel-1")
	bChan2, _ := idB.Derive(idA.ECDHPublic(), "channel-2")

	blob, err := aChan1.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bChan2.Open(blob); err == nil {
		t.Fatal("a blob sealed for channel-1 opened under channel-2's session")
	}
}

// Tampering with the ciphertext is detected (Poly1305 authentication).
func TestTamperingDetected(t *testing.T) {
	a, b, _, _ := pairedSessions(t, "c")
	blob, err := a.Seal([]byte("intact"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the ciphertext region (after the 24-byte nonce).
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := b.Open(tampered); err == nil {
		t.Fatal("tampered ciphertext opened successfully; integrity broken")
	}
}

// Each Seal uses a fresh nonce, so encrypting the same plaintext twice yields
// different blobs (no deterministic leakage).
func TestNonceFreshness(t *testing.T) {
	a, _, _, _ := pairedSessions(t, "c")
	p := []byte("same plaintext")
	b1, _ := a.Seal(p)
	b2, _ := a.Seal(p)
	if bytes.Equal(b1, b2) {
		t.Fatal("two seals of the same plaintext produced identical blobs (nonce reuse?)")
	}
}

// Per-sender keys: peer A's send key differs from peer B's send key, so the two
// peers do not share a key or a nonce domain (the CODEX-flagged footgun is fixed).
func TestPerSenderKeysDiffer(t *testing.T) {
	a, b, _, _ := pairedSessions(t, "c")
	if a.send == b.send {
		t.Fatal("both peers share one send key; per-direction separation missing")
	}
	// A's send must equal B's recv, and vice versa, or the round trip would fail.
	if a.send != b.recv || b.send != a.recv {
		t.Fatal("direction keys are not mirrored between peers")
	}
}
