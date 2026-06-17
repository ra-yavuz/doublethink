package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A correctly-signed challenge by an authorized key on the right channel passes.
func TestVerifyAuthorizedKeySucceeds(t *testing.T) {
	r := NewRegistry()
	pub, priv := newKey(t)
	if err := r.Register("chan-x", pub); err != nil {
		t.Fatal(err)
	}
	ch, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, ch)
	if err := r.Verify("chan-x", pub, ch, sig); err != nil {
		t.Fatalf("authorized signed challenge rejected: %v", err)
	}
}

// Test 1 (SECURITY.md req 1): an unauthenticated peer is rejected. Here the peer
// presents a key with a bogus/zero signature; it must be refused.
func TestUnauthenticatedRejected(t *testing.T) {
	r := NewRegistry()
	pub, _ := newKey(t)
	if err := r.Register("chan-x", pub); err != nil {
		t.Fatal(err)
	}
	ch, _ := NewChallenge()
	badSig := make([]byte, ed25519.SignatureSize) // all zeros, not a real signature
	if err := r.Verify("chan-x", pub, ch, badSig); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad signature accepted or wrong error: %v", err)
	}
}

// Test 2 (SECURITY.md req 2): another authenticated party cannot attach to a
// channel it is not authorized for. The intruder holds a perfectly valid key and
// signs correctly, but is registered on a DIFFERENT channel.
func TestOtherAuthenticatedPartyRejected(t *testing.T) {
	r := NewRegistry()
	ownerPub, _ := newKey(t)
	intruderPub, intruderPriv := newKey(t)

	if err := r.Register("private-A", ownerPub); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("private-B", intruderPub); err != nil {
		t.Fatal(err)
	}

	// The intruder authenticates flawlessly for its OWN channel...
	ch, _ := NewChallenge()
	sig := ed25519.Sign(intruderPriv, ch)
	if err := r.Verify("private-B", intruderPub, ch, sig); err != nil {
		t.Fatalf("intruder rejected on its own channel: %v", err)
	}
	// ...but the same valid signature must NOT grant access to channel A.
	ch2, _ := NewChallenge()
	sig2 := ed25519.Sign(intruderPriv, ch2)
	if err := r.Verify("private-A", intruderPub, ch2, sig2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("authenticated-but-unauthorized party reached channel A: %v", err)
	}
}

// Test 4 (SECURITY.md req 5): denial is uniform. An unknown channel and an
// unauthorized key on a known channel must return the SAME error, so the broker
// does not leak whether a private channel exists.
func TestUniformDenialNoExistenceLeak(t *testing.T) {
	r := NewRegistry()
	ownerPub, _ := newKey(t)
	strangerPub, strangerPriv := newKey(t)
	if err := r.Register("known", ownerPub); err != nil {
		t.Fatal(err)
	}

	ch, _ := NewChallenge()
	sig := ed25519.Sign(strangerPriv, ch)

	errUnknownChannel := r.Verify("does-not-exist", strangerPub, ch, sig)
	errUnauthorizedKey := r.Verify("known", strangerPub, ch, sig)

	if !errors.Is(errUnknownChannel, ErrUnauthorized) {
		t.Errorf("unknown channel error = %v, want ErrUnauthorized", errUnknownChannel)
	}
	if !errors.Is(errUnauthorizedKey, ErrUnauthorized) {
		t.Errorf("unauthorized key error = %v, want ErrUnauthorized", errUnauthorizedKey)
	}
	if errUnknownChannel.Error() != errUnauthorizedKey.Error() {
		t.Errorf("denials differ and leak existence:\n  unknown channel: %q\n  unauthorized key: %q",
			errUnknownChannel.Error(), errUnauthorizedKey.Error())
	}
}

// Revocation (DESIGN-M1.md decision 4): after Revoke, a previously-authorized key
// can no longer authenticate. This is M1's revoke-by-re-pair primitive.
func TestRevoke(t *testing.T) {
	r := NewRegistry()
	pub, priv := newKey(t)
	if err := r.Register("c", pub); err != nil {
		t.Fatal(err)
	}
	ch, _ := NewChallenge()
	sig := ed25519.Sign(priv, ch)
	if err := r.Verify("c", pub, ch, sig); err != nil {
		t.Fatalf("authorized before revoke should pass: %v", err)
	}

	r.Revoke("c", pub)
	r.Revoke("c", pub) // idempotent

	ch2, _ := NewChallenge()
	sig2 := ed25519.Sign(priv, ch2)
	if err := r.Verify("c", pub, ch2, sig2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key still authenticates: %v", err)
	}
}

// Authorize adds a second peer to a channel (the two-peer pairing case).
func TestAuthorizeSecondPeer(t *testing.T) {
	r := NewRegistry()
	a, aPriv := newKey(t)
	b, bPriv := newKey(t)
	if err := r.Register("pair", a); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize("pair", b); err != nil {
		t.Fatal(err)
	}
	for name, priv := range map[string]ed25519.PrivateKey{"peer-a": aPriv, "peer-b": bPriv} {
		var pub ed25519.PublicKey
		if name == "peer-a" {
			pub = a
		} else {
			pub = b
		}
		ch, _ := NewChallenge()
		sig := ed25519.Sign(priv, ch)
		if err := r.Verify("pair", pub, ch, sig); err != nil {
			t.Errorf("%s rejected after pairing: %v", name, err)
		}
	}
}

// Authorizing on an unknown channel is a uniform denial, not a silent create.
func TestAuthorizeUnknownChannelDenied(t *testing.T) {
	r := NewRegistry()
	pub, _ := newKey(t)
	if err := r.Authorize("nope", pub); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("Authorize on unknown channel = %v, want ErrUnauthorized", err)
	}
}

// A replayed signature for a DIFFERENT challenge fails: the signature is over the
// issued challenge, and a fresh challenge each handshake means a captured
// (challenge, sig) pair does not authenticate the next handshake.
func TestReplayedSignatureFailsOnNewChallenge(t *testing.T) {
	r := NewRegistry()
	pub, priv := newKey(t)
	if err := r.Register("c", pub); err != nil {
		t.Fatal(err)
	}
	ch1, _ := NewChallenge()
	sig1 := ed25519.Sign(priv, ch1)
	if err := r.Verify("c", pub, ch1, sig1); err != nil {
		t.Fatal(err)
	}
	// New handshake issues a new challenge; replaying the old signature must fail.
	ch2, _ := NewChallenge()
	if err := r.Verify("c", pub, ch2, sig1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed signature accepted against a fresh challenge: %v", err)
	}
}
