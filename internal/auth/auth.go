// Package auth is doublethink's broker-side authentication and authorization for
// private channels (docs/DESIGN-M1.md decision 4b). It is separate from the
// end-to-end encryption of payloads: this layer decides WHO may attach to a
// channel; the E2E layer (client-side) decides who can READ the payload.
//
// The gate is authentication PLUS authorization, never name-secrecy:
//   - Authentication: a peer proves it holds the private half of an Ed25519
//     identity key by signing a server-issued random challenge.
//   - Authorization: that Ed25519 public key must be in the target channel's
//     registered authorized set. Being able to authenticate for one channel grants
//     nothing on another (SECURITY.md req 2).
//
// A peer that cannot produce a valid signature for an authorized key is rejected
// outright (SECURITY.md req 1). Denials are uniform: "not authorized" is returned
// identically whether the channel is unknown or the key is simply not on it, so
// the broker never leaks whether a private channel exists (SECURITY.md req 5).
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
)

// ChallengeSize is the byte length of the random nonce a peer must sign. 32 bytes
// of CSPRNG output makes the challenge unpredictable and non-repeating in practice.
const ChallengeSize = 32

// ErrUnauthorized is the single, uniform denial. It deliberately does not
// distinguish "no such channel" from "key not authorized" so the broker leaks no
// information about private-channel existence (SECURITY.md req 5).
var ErrUnauthorized = errors.New("not authorized")

// ErrChannelExists is returned by Register when a channel id is already registered.
var ErrChannelExists = errors.New("channel already registered")

// Registry holds, per private channel, the set of Ed25519 public keys authorized
// to attach. Public channels are not registered here at all: they have no auth
// gate by definition, and the transport layer routes them without consulting auth.
type Registry struct {
	mu       sync.RWMutex
	channels map[string]map[string]struct{} // channel id -> set of base64(ed25519 pubkey)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{channels: make(map[string]map[string]struct{})}
}

func keyString(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// Register creates a private channel with an initial authorized key set. It errors
// if the channel already exists, so re-registration is a deliberate act (rotate via
// Authorize/Revoke or a fresh channel id), not an accidental overwrite.
func (r *Registry) Register(channel string, authorized ...ed25519.PublicKey) error {
	if channel == "" {
		return errors.New("empty channel id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.channels[channel]; ok {
		return ErrChannelExists
	}
	set := make(map[string]struct{}, len(authorized))
	for _, k := range authorized {
		if len(k) == ed25519.PublicKeySize {
			set[keyString(k)] = struct{}{}
		}
	}
	r.channels[channel] = set
	return nil
}

// Authorize adds a public key to an existing channel's authorized set (pairing a
// second peer, or rotating in a re-paired key). Errors if the channel is unknown.
func (r *Registry) Authorize(channel string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("bad public key length")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.channels[channel]
	if !ok {
		return ErrUnauthorized
	}
	set[keyString(pub)] = struct{}{}
	return nil
}

// Revoke removes a public key from a channel's authorized set. This is M1's
// revocation primitive (DESIGN-M1.md decision 4: revocation = re-pair / rotate).
// After Revoke the key can no longer authenticate to the channel. Idempotent.
func (r *Registry) Revoke(channel string, pub ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set, ok := r.channels[channel]; ok {
		delete(set, keyString(pub))
	}
}

// isAuthorized reports whether pub is in channel's authorized set. Unknown channel
// and unauthorized key both yield false, so callers cannot tell them apart.
func (r *Registry) isAuthorized(channel string, pub ed25519.PublicKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.channels[channel]
	if !ok {
		return false
	}
	_, ok = set[keyString(pub)]
	return ok
}

// NewChallenge returns a fresh random challenge for a peer to sign. The caller
// holds the returned bytes for the lifetime of one handshake and passes them back
// to Verify; a challenge is single-use by construction (the caller discards it
// after one Verify), which is what defeats replay of a captured signature.
func NewChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify checks that `sig` is a valid Ed25519 signature over `challenge` by `pub`,
// AND that `pub` is authorized for `channel`. Both must hold. It returns
// ErrUnauthorized (uniform) on any failure: bad signature, unknown channel, or
// unauthorized key. The two checks are independent: a valid signature for a key
// that is not on this channel still fails (authorization, not just authentication).
func (r *Registry) Verify(channel string, pub ed25519.PublicKey, challenge, sig []byte) error {
	// Authorization first is fine; both must pass and we reveal nothing either way.
	authorized := r.isAuthorized(channel, pub)
	// Always run the signature check (even when unauthorized) so timing does not
	// distinguish "unknown channel" from "bad signature".
	sigOK := len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, challenge, sig)
	if !authorized || !sigOK {
		return ErrUnauthorized
	}
	return nil
}

// HasChannel reports whether a channel is a registered private channel. For
// transport-layer routing decisions only; it must NOT be exposed to clients,
// since that would leak private-channel existence (SECURITY.md req 5).
func (r *Registry) HasChannel(channel string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.channels[channel]
	return ok
}

// ConstantTimeChallengeEqual compares two challenges in constant time. Exposed for
// callers that must confirm a returned challenge matches the issued one without a
// timing side channel.
func ConstantTimeChallengeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
