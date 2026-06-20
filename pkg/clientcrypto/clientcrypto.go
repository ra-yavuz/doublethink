// Package clientcrypto is the public, stable client-side crypto surface for
// doublethink private channels. It is a thin re-export of the internal
// implementation so that external programs (for example the claude-doublethink
// coordination MCP) can speak a private channel using the EXACT same crypto the
// broker and the official clients use, with no second implementation to drift.
//
// There is deliberately ONE implementation: this package aliases the internal
// types and forwards the internal functions. A change to the crypto happens in
// exactly one place (internal/clientcrypto) and is reflected here automatically.
//
// Only the CLIENT surface is exported here. Broker-side helpers
// (DecodeAuthKey, ResponseFromAuthKey, RegistrationKeyFromBytes) stay internal:
// an external client never needs to verify a challenge or persist a key the way
// the broker does.
//
// Model (unchanged from the internal package): a private channel is gated by one
// high-entropy shared secret S, generated client-side and shared out of band. S is
// NEVER sent to the broker; only the channel id and a K_auth verifier are. The two
// parties are RoleA (channel creator) and RoleB (joiner); the role only orients
// which per-direction key is send vs recv. Honest limits: symmetric (no per-sender
// non-repudiation, no single-party revoke without rotating S), no forward secrecy.
package clientcrypto

import internal "github.com/ra-yavuz/doublethink/internal/clientcrypto"

// Role labels which side of a two-party channel a client is. The channel creator
// is RoleA, the joiner is RoleB. Both parties derive the identical key pair from S;
// the role only selects which per-direction key is send vs recv. Two clients that
// pick the SAME role cannot read each other (they would share a send key), so a
// correct client derives its role from who created the channel.
type Role = internal.Role

// RoleA is the channel creator; RoleB is the joiner.
const (
	RoleA = internal.RoleA
	RoleB = internal.RoleB
)

// Session holds a client's per-direction payload keys for a channel.
type Session = internal.Session

// KeySize is the byte length of K_auth.
const KeySize = internal.KeySize

// GenerateSecret returns a fresh 256-bit channel secret S, base32-encoded (no
// padding, lowercase-friendly) so it is copy-pasteable. This is the ONE value
// shared out of band between the two parties; treat it like a password.
func GenerateSecret() (string, error) { return internal.GenerateSecret() }

// RegistrationKey is what the client sends the broker ONCE at channel creation:
// K_auth (a verifier derived from S by a different HKDF label than the encryption
// key), base32-encoded. A broker holding it still cannot read payloads, and S
// itself is never sent.
func RegistrationKey(secret string) (string, error) { return internal.RegistrationKey(secret) }

// AuthKey derives K_auth from the shared secret S. Used to answer the broker's
// admission challenge.
func AuthKey(secret string) ([KeySize]byte, error) { return internal.AuthKey(secret) }

// ChallengeResponse computes the proof a client returns for a broker-issued random
// challenge: a PRF over the challenge keyed by K_auth. A fresh challenge per attach
// makes a captured response useless for the next attach.
func ChallengeResponse(secret string, challenge []byte) ([]byte, error) {
	return internal.ChallengeResponse(secret, challenge)
}

// NewSession derives the per-direction encryption keys from S for the given role.
// RoleA sends on a->b and receives on b->a; RoleB is mirrored. Seal/Open on the
// returned *Session encrypt/decrypt payloads that cross the broker opaquely.
func NewSession(secret string, role Role) (*Session, error) {
	return internal.NewSession(secret, role)
}
