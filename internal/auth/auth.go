// Package auth is doublethink's broker-side admission control for private channels
// (docs/DESIGN-M1.md). A private channel is gated by a shared secret S that the two
// parties hold; the broker never sees S. At channel creation the client registers
// K_auth = HKDF(S, "doublethink-auth-v1") (see package clientcrypto); the broker
// stores K_auth and admits a connecting client by a challenge-response that proves
// the client can compute the same PRF over a fresh nonce.
//
// The gate is possession of the secret, not name-secrecy: knowing a channel id
// grants nothing without a valid response (SECURITY.md). Denials are uniform, an
// unknown channel and a wrong response return the same error, so the broker does
// not leak whether a private channel exists (SECURITY.md req 5).
//
// Broker-blindness: K_auth is derived from S by a different HKDF label than the
// encryption key K_enc, so a broker holding K_auth still cannot derive K_enc and
// cannot read payloads.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// ChallengeSize is the byte length of the random nonce a client must respond to.
const ChallengeSize = 32

// ErrUnauthorized is the single, uniform denial. It does not distinguish "no such
// channel" from "wrong response", so the broker leaks no information about
// private-channel existence (SECURITY.md req 5).
var ErrUnauthorized = errors.New("not authorized")

// ErrChannelExists is returned by Register when a channel id is already registered.
var ErrChannelExists = errors.New("channel already registered")

// Registry maps each private channel id to its registered K_auth.
type Registry struct {
	mu       sync.RWMutex
	channels map[string][clientcrypto.KeySize]byte // channel id -> K_auth
	onChange func()
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{channels: make(map[string][clientcrypto.KeySize]byte)}
}

// OnChange registers a callback invoked after each mutation, for persistence.
func (r *Registry) OnChange(fn func()) {
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

func (r *Registry) notify() {
	r.mu.RLock()
	fn := r.onChange
	r.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// Register creates a private channel bound to the given K_auth. Errors if the
// channel already exists, so re-registration is deliberate (rotate by recreating
// with a fresh secret), not an accidental overwrite.
func (r *Registry) Register(channel string, authKey [clientcrypto.KeySize]byte) error {
	if channel == "" {
		return errors.New("empty channel id")
	}
	r.mu.Lock()
	if _, ok := r.channels[channel]; ok {
		r.mu.Unlock()
		return ErrChannelExists
	}
	r.channels[channel] = authKey
	r.mu.Unlock()
	r.notify()
	return nil
}

// Remove deletes a channel (e.g. rotation by delete-then-recreate). Idempotent.
func (r *Registry) Remove(channel string) {
	r.mu.Lock()
	_, existed := r.channels[channel]
	delete(r.channels, channel)
	r.mu.Unlock()
	if existed {
		r.notify()
	}
}

// NewChallenge returns a fresh random challenge for a client to respond to. It is
// single-use by construction (the caller discards it after one Verify), which
// defeats replay of a captured response.
func NewChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify checks that `response` is the correct challenge-response for `channel`:
// the broker recomputes the expected response from the stored K_auth and compares
// in constant time. Unknown channel or wrong response both yield ErrUnauthorized
// (uniform). The comparison runs even on an unknown channel so timing does not
// distinguish the two cases.
func (r *Registry) Verify(channel string, challenge, response []byte) error {
	r.mu.RLock()
	authKey, ok := r.channels[channel]
	r.mu.RUnlock()

	// Recompute against a real key when known, or a throwaway when not, so both
	// branches do the same work.
	var expected []byte
	if ok {
		expected = clientcrypto.ResponseFromAuthKey(authKey, challenge)
	} else {
		var dummy [clientcrypto.KeySize]byte
		expected = clientcrypto.ResponseFromAuthKey(dummy, challenge)
	}
	match := subtle.ConstantTimeCompare(expected, response) == 1
	if !ok || !match {
		return ErrUnauthorized
	}
	return nil
}

// HasChannel reports whether a channel is registered. For transport-layer routing
// only; must NOT be exposed to clients (would leak existence, SECURITY.md req 5).
func (r *Registry) HasChannel(channel string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.channels[channel]
	return ok
}

// Snapshot returns channel id -> base32 K_auth, for persistence. A copy.
func (r *Registry) Snapshot() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.channels))
	for ch, k := range r.channels {
		out[ch] = encodeKey(k)
	}
	return out
}

// Load replaces the registry from a snapshot map (base32 K_auth). Malformed
// entries are skipped.
func (r *Registry) Load(snap map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels = make(map[string][clientcrypto.KeySize]byte, len(snap))
	for ch, enc := range snap {
		if k, err := clientcrypto.DecodeAuthKey(enc); err == nil {
			r.channels[ch] = k
		}
	}
}

func encodeKey(k [clientcrypto.KeySize]byte) string {
	enc, _ := clientcrypto.RegistrationKeyFromBytes(k)
	return enc
}
