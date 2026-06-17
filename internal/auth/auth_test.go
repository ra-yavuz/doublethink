package auth

import (
	"errors"
	"testing"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// register a channel from a fresh secret, returning the secret so the test can
// compute the matching challenge response (as a real client would).
func registerChannel(t *testing.T, r *Registry, channel string) string {
	t.Helper()
	secret, err := clientcrypto.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	ka, err := clientcrypto.AuthKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Register(channel, ka); err != nil {
		t.Fatal(err)
	}
	return secret
}

func respond(t *testing.T, secret string, challenge []byte) []byte {
	t.Helper()
	resp, err := clientcrypto.ChallengeResponse(secret, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// A holder of the secret answers the challenge correctly and is admitted.
func TestVerifyHolderSucceeds(t *testing.T) {
	r := NewRegistry()
	secret := registerChannel(t, r, "chan-x")
	ch, _ := NewChallenge()
	if err := r.Verify("chan-x", ch, respond(t, secret, ch)); err != nil {
		t.Fatalf("holder of the secret rejected: %v", err)
	}
}

// Test 1 (SECURITY.md req 1): a client that does not hold the secret is rejected.
func TestNonHolderRejected(t *testing.T) {
	r := NewRegistry()
	registerChannel(t, r, "chan-x")
	ch, _ := NewChallenge()
	wrongSecret, _ := clientcrypto.GenerateSecret()
	if err := r.Verify("chan-x", ch, respond(t, wrongSecret, ch)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-holder admitted or wrong error: %v", err)
	}
}

// Test 2 (SECURITY.md req 2): a holder of channel A's secret cannot attach to
// channel B. Knowing one channel's secret grants nothing on another.
func TestSecretBoundToOwnChannel(t *testing.T) {
	r := NewRegistry()
	secretA := registerChannel(t, r, "A")
	registerChannel(t, r, "B")
	ch, _ := NewChallenge()
	// A correct response for A's secret, presented against channel B, must fail.
	if err := r.Verify("B", ch, respond(t, secretA, ch)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("A's secret reached channel B: %v", err)
	}
}

// Test 4 (SECURITY.md req 5): unknown channel and wrong response return the SAME
// error, so the broker does not leak whether a private channel exists.
func TestUniformDenial(t *testing.T) {
	r := NewRegistry()
	registerChannel(t, r, "known")
	ch, _ := NewChallenge()
	stranger, _ := clientcrypto.GenerateSecret()
	errUnknown := r.Verify("does-not-exist", ch, respond(t, stranger, ch))
	errWrong := r.Verify("known", ch, respond(t, stranger, ch))
	if !errors.Is(errUnknown, ErrUnauthorized) || !errors.Is(errWrong, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized both: %v / %v", errUnknown, errWrong)
	}
	if errUnknown.Error() != errWrong.Error() {
		t.Errorf("denials differ and leak existence: %q vs %q", errUnknown, errWrong)
	}
}

// Replay: a response captured for one challenge does not authenticate the next
// (fresh) challenge.
func TestReplayedResponseFails(t *testing.T) {
	r := NewRegistry()
	secret := registerChannel(t, r, "c")
	ch1, _ := NewChallenge()
	resp1 := respond(t, secret, ch1)
	if err := r.Verify("c", ch1, resp1); err != nil {
		t.Fatal(err)
	}
	ch2, _ := NewChallenge()
	if err := r.Verify("c", ch2, resp1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed response accepted against a fresh challenge: %v", err)
	}
}

// Register is single-shot: a second Register for the same channel errors.
func TestRegisterTwiceErrors(t *testing.T) {
	r := NewRegistry()
	registerChannel(t, r, "c")
	var k [clientcrypto.KeySize]byte
	if err := r.Register("c", k); !errors.Is(err, ErrChannelExists) {
		t.Fatalf("re-register = %v, want ErrChannelExists", err)
	}
}

// Remove deletes a channel; afterward its holder can no longer attach.
func TestRemove(t *testing.T) {
	r := NewRegistry()
	secret := registerChannel(t, r, "c")
	r.Remove("c")
	r.Remove("c") // idempotent
	ch, _ := NewChallenge()
	if err := r.Verify("c", ch, respond(t, secret, ch)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("removed channel still admits: %v", err)
	}
}

// Snapshot/Load round-trips the registry (persistence).
func TestSnapshotLoad(t *testing.T) {
	r := NewRegistry()
	secret := registerChannel(t, r, "c")
	snap := r.Snapshot()

	r2 := NewRegistry()
	r2.Load(snap)
	ch, _ := NewChallenge()
	if err := r2.Verify("c", ch, respond(t, secret, ch)); err != nil {
		t.Fatalf("reloaded registry rejected the holder: %v", err)
	}
}
