package clientcrypto

import (
	"bytes"
	"testing"
)

// Two parties holding the SAME shared secret S derive mirrored sessions and can
// exchange messages both ways. This is the core ntfy-easy property: share one
// secret, both can talk.
func TestSealOpenBothDirections(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewSession(secret, RoleA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSession(secret, RoleB)
	if err != nil {
		t.Fatal(err)
	}

	msgAB := []byte(`{"step":"ran tests"}`)
	blob, _ := a.Seal(msgAB)
	got, err := b.Open(blob)
	if err != nil {
		t.Fatalf("B could not open A's message: %v", err)
	}
	if !bytes.Equal(got, msgAB) {
		t.Errorf("A->B mismatch: %s vs %s", got, msgAB)
	}

	msgBA := []byte(`{"control":"barge-in"}`)
	blob2, _ := b.Seal(msgBA)
	got2, err := a.Open(blob2)
	if err != nil {
		t.Fatalf("A could not open B's message: %v", err)
	}
	if !bytes.Equal(got2, msgBA) {
		t.Errorf("B->A mismatch: %s vs %s", got2, msgBA)
	}
}

// The differentiator (SECURITY.md req 3): the broker holds only the channel id and
// K_auth, never S, so it cannot derive K_enc and cannot read the payload. We model
// that: a party with a DIFFERENT secret cannot open the blob, and the plaintext is
// absent from the ciphertext.
func TestBrokerCannotReadPayload(t *testing.T) {
	secret, _ := GenerateSecret()
	a, _ := NewSession(secret, RoleA)
	plaintext := []byte("code context and a shell command the operator must not see")
	blob, _ := a.Seal(plaintext)

	if bytes.Contains(blob, plaintext) {
		t.Fatal("plaintext present in the sealed blob the broker forwards")
	}
	// A different secret = different K_enc; cannot open.
	other, _ := GenerateSecret()
	eve, _ := NewSession(other, RoleB)
	if _, err := eve.Open(blob); err == nil {
		t.Fatal("a session from a different secret opened the payload; confidentiality broken")
	}
}

// K_auth (what the broker stores) does not let anyone derive K_enc: a holder of
// only K_auth (the broker) cannot construct a session that opens the payload. We
// check this structurally: K_auth and the encryption keys come from different HKDF
// labels, so the registration key must differ from anything used for encryption.
func TestAuthKeyIndependentOfEncryption(t *testing.T) {
	secret, _ := GenerateSecret()
	ka, _ := AuthKey(secret)
	a, _ := NewSession(secret, RoleA)
	if ka == a.send || ka == a.recv {
		t.Fatal("K_auth equals an encryption key; broker holding K_auth could read payloads")
	}
}

// A wrong secret produces a different K_auth, so the broker's challenge-response
// rejects it (verified here by the response differing for different secrets).
func TestResponseDiffersBySecret(t *testing.T) {
	s1, _ := GenerateSecret()
	s2, _ := GenerateSecret()
	challenge := []byte("0123456789abcdef0123456789abcdef")
	r1, _ := ChallengeResponse(s1, challenge)
	r2, _ := ChallengeResponse(s2, challenge)
	if bytes.Equal(r1, r2) {
		t.Fatal("two different secrets produced the same challenge response")
	}
	// And the broker, recomputing from the registered K_auth, matches the holder.
	ka, _ := AuthKey(s1)
	if !bytes.Equal(ChallengeResponse1(ka, challenge), r1) {
		t.Fatal("broker recomputation does not match the client response")
	}
}

// helper mirroring the broker-side recomputation, for the test above.
func ChallengeResponse1(ka [keySize]byte, challenge []byte) []byte {
	return ResponseFromAuthKey(ka, challenge)
}

// Per-direction keys differ, so the two parties never share a nonce domain.
func TestPerDirectionKeysDiffer(t *testing.T) {
	secret, _ := GenerateSecret()
	a, _ := NewSession(secret, RoleA)
	b, _ := NewSession(secret, RoleB)
	if a.send == b.send {
		t.Fatal("both roles share one send key; per-direction separation missing")
	}
	if a.send != b.recv || b.send != a.recv {
		t.Fatal("direction keys are not mirrored between the two roles")
	}
}

// Tampering is detected (Poly1305).
func TestTamperingDetected(t *testing.T) {
	secret, _ := GenerateSecret()
	a, _ := NewSession(secret, RoleA)
	b, _ := NewSession(secret, RoleB)
	blob, _ := a.Seal([]byte("intact"))
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := b.Open(tampered); err == nil {
		t.Fatal("tampered ciphertext opened; integrity broken")
	}
}

// Fresh nonce per seal: same plaintext twice yields different blobs.
func TestNonceFreshness(t *testing.T) {
	secret, _ := GenerateSecret()
	a, _ := NewSession(secret, RoleA)
	b1, _ := a.Seal([]byte("same"))
	b2, _ := a.Seal([]byte("same"))
	if bytes.Equal(b1, b2) {
		t.Fatal("two seals of the same plaintext are identical (nonce reuse?)")
	}
}

// Round-trip of the registration key (broker persistence path).
func TestAuthKeyEncodeDecode(t *testing.T) {
	secret, _ := GenerateSecret()
	enc, _ := RegistrationKey(secret)
	k, err := DecodeAuthKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	ka, _ := AuthKey(secret)
	if k != ka {
		t.Fatal("decoded registration key does not match K_auth")
	}
	reEnc, _ := RegistrationKeyFromBytes(k)
	if reEnc != enc {
		t.Fatal("re-encode mismatch")
	}
}

func TestInvalidSecretRejected(t *testing.T) {
	if _, err := NewSession("!!!notbase32!!!", RoleA); err == nil {
		t.Error("NewSession accepted a malformed secret")
	}
	if _, err := AuthKey("short"); err == nil {
		t.Error("AuthKey accepted a too-short secret")
	}
}
