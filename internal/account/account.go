// Package account is doublethink's lightweight identity layer (docs/DESIGN-M2.md
// decision 1): accounts and API keys. An account is the unit that owns retained
// channels and that quotas are attributed to. It is deliberately minimal: no
// passwords, no email, no sessions. An API key is a capability that attributes
// usage and enables revocation.
//
// The broker stores only a HASH of the API key, never the key itself. The key is
// shown to the creator once, at POST /account. This is orthogonal to a channel's
// shared secret S (which gates channel contents and is never seen by the broker);
// the API key gates channel creation and ownership.
package account

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

const (
	// idBytes / keyBytes are the entropy of an account id and an API key.
	idBytes  = 12 // 96-bit account id
	keyBytes = 32 // 256-bit API key
	// keyPrefix marks a doublethink API key so it is recognisable and greppable.
	keyPrefix = "dtk_"
)

// ErrBadKey is returned when an API key is malformed.
var ErrBadKey = errors.New("malformed api key")

// NewID returns a fresh random account id (base64url, no padding).
func NewID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewKey returns a fresh API key (prefixed, base64url). The plaintext is returned
// to the creator once; only HashKey(key) is stored.
func NewKey() (string, error) {
	b := make([]byte, keyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashKey returns the hex SHA-256 of an API key, the value the broker persists.
// A hash (not the key) at rest means a leaked database cannot present keys.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyKey reports whether `key` hashes to `storedHash`, in constant time.
func VerifyKey(key, storedHash string) bool {
	got := HashKey(key)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// LooksLikeKey is a cheap shape check before hashing (rejects obviously-bad input
// without revealing anything via timing on the hash path).
func LooksLikeKey(key string) bool {
	if len(key) < len(keyPrefix)+20 || key[:len(keyPrefix)] != keyPrefix {
		return false
	}
	return true
}
