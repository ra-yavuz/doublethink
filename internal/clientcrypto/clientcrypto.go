// Package clientcrypto is the CLIENT-side crypto for doublethink private channels.
// The broker never imports it to read payloads: it only ever sees ciphertext.
//
// Model (ntfy-easy shared secret; crypto cross-checked against CODEX):
//
// A private channel is gated by ONE high-entropy shared secret S, generated
// client-side and shared between the two parties out of band (like sharing an ntfy
// topic, except S is the real gate, not the channel name, and is unguessable).
// Everything derives from S by HKDF with domain separation:
//
//   - K_auth = HKDF(S, "doublethink-auth-v1"). The broker stores K_auth (registered
//     once at channel creation) and admits a client by a challenge-response that
//     proves the client holds K_auth, so K_auth is not re-sent on every attach.
//     K_auth is derived from S by a DIFFERENT HKDF label than the encryption key,
//     so a broker holding K_auth still cannot derive K_enc and cannot read payloads.
//   - K_enc  = HKDF(S, "doublethink-enc-v1"), then per-direction keys
//     HKDF(K_enc, "enc a->b") / HKDF(K_enc, "enc b->a"), so the two parties do not
//     share a nonce domain. Payloads are sealed with NaCl secretbox
//     (XSalsa20-Poly1305) under the sender's per-direction key.
//
// CRITICAL invariant for broker-blindness: S is NEVER sent to the broker. The
// broker receives only the channel id and the K_auth verifier (both computed
// client-side). If S ever reached the broker, the honest claim would weaken to "we
// do not store it" rather than "the operator cannot read it".
//
// Honest limits (documented, not hidden): the model is symmetric, both parties
// who hold S can encrypt and decrypt, so there is no per-sender non-repudiation and
// no way to revoke one party without rotating S. There is no forward secrecy (S is
// static). This is the right trade for "two parties who share a secret trust each
// other"; stronger properties are a deliberate future step, not an accident.
package clientcrypto

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize      = 32
	nonceSize    = 24
	secretBytes  = 32 // 256-bit channel secret S
	authTag      = "doublethink-auth-v1"
	encTag       = "doublethink-enc-v1"
	challengeTag = "doublethink-challenge-v1"
)

// Role labels which side of a two-party channel a client is. The creator is RoleA,
// the joiner is RoleB. It only selects which per-direction key is "send" vs "recv";
// both parties derive the same two keys from S.
type Role string

const (
	RoleA Role = "a"
	RoleB Role = "b"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleA || r == RoleB }

// GenerateSecret returns a fresh 256-bit channel secret S, base32-encoded (no
// padding, lowercase) so it is copy-pasteable. This is the ONE value shared out of
// band between the two parties. Treat it like a password: anyone who has it can
// join the channel and read its traffic.
func GenerateSecret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generating channel secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func decodeSecret(s string) ([]byte, error) {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(b) < 16 {
		return nil, errors.New("invalid channel secret")
	}
	return b, nil
}

func blake2bNew() hash.Hash { h, _ := blake2b.New256(nil); return h }

func derive(ikm []byte, info string) [keySize]byte {
	out := make([]byte, keySize)
	r := hkdf.New(blake2bNew, ikm, nil, []byte(info))
	_, _ = io.ReadFull(r, out)
	var k [keySize]byte
	copy(k[:], out)
	return k
}

// AuthKey derives K_auth from the shared secret S. The client uses it to answer the
// broker's admission challenge; the broker never sees it directly (only a verifier
// derived from it, see Verifier).
func AuthKey(secret string) ([keySize]byte, error) {
	s, err := decodeSecret(secret)
	if err != nil {
		return [keySize]byte{}, err
	}
	return derive(s, authTag), nil
}

// RegistrationKey is what the client sends the broker ONCE at channel creation:
// K_auth, base32-encoded. The broker stores it to verify future admission
// challenges. It is NOT the encryption key (that is a different HKDF label off the
// same S), so a broker holding it still cannot read payloads. S itself is never
// sent to the broker.
func RegistrationKey(secret string) (string, error) {
	ka, err := AuthKey(secret)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ka[:]), nil
}

// ChallengeResponse computes the proof a client returns for a broker-issued random
// challenge: a PRF (HKDF) over the challenge keyed by K_auth. The broker, which
// holds K_auth, recomputes the same value and compares (see auth.VerifyResponse).
// Because a fresh challenge is used per attach, a captured response does not
// authenticate the next attach.
func ChallengeResponse(secret string, challenge []byte) ([]byte, error) {
	ka, err := AuthKey(secret)
	if err != nil {
		return nil, err
	}
	return ResponseFromAuthKey(ka, challenge), nil
}

// ResponseFromAuthKey is the shared challenge-response construction, used by the
// client (via ChallengeResponse) and by the broker (which holds K_auth and
// recomputes the expected response). Both sides MUST use this exact function.
func ResponseFromAuthKey(ka [keySize]byte, challenge []byte) []byte {
	r := hkdf.New(blake2bNew, ka[:], challenge, []byte(challengeTag))
	out := make([]byte, keySize)
	_, _ = io.ReadFull(r, out)
	return out
}

// KeySize is the byte length of K_auth, exported so the broker can validate a
// registered key's length.
const KeySize = keySize

// DecodeAuthKey parses a base32 RegistrationKey back into K_auth bytes (broker side).
func DecodeAuthKey(encoded string) ([keySize]byte, error) {
	var k [keySize]byte
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil || len(b) != keySize {
		return k, errors.New("invalid auth key")
	}
	copy(k[:], b)
	return k, nil
}

// RegistrationKeyFromBytes encodes a raw K_auth back to base32 (broker side, for
// persistence). Inverse of DecodeAuthKey.
func RegistrationKeyFromBytes(k [keySize]byte) (string, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k[:]), nil
}

// Session holds a client's per-direction payload keys for a channel.
type Session struct {
	send [keySize]byte
	recv [keySize]byte
}

// NewSession derives the per-direction encryption keys from S for the given role.
// RoleA sends on a->b and receives on b->a; RoleB is mirrored. Both parties derive
// the identical pair of keys; role only orients send vs recv.
func NewSession(secret string, role Role) (*Session, error) {
	if !role.Valid() {
		return nil, errors.New("invalid role")
	}
	s, err := decodeSecret(secret)
	if err != nil {
		return nil, err
	}
	kenc := derive(s, encTag)
	aToB := derive(kenc[:], "enc a->b")
	bToA := derive(kenc[:], "enc b->a")
	sess := &Session{}
	if role == RoleA {
		sess.send, sess.recv = aToB, bToA
	} else {
		sess.send, sess.recv = bToA, aToB
	}
	return sess, nil
}

// Seal encrypts plaintext under this client's send key with a fresh random nonce.
// Returns nonce||ciphertext, which crosses the broker as the opaque payload.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return secretbox.Seal(nonce[:], plaintext, &nonce, &s.send), nil
}

// Open decrypts a nonce||ciphertext blob produced by the other party.
func (s *Session) Open(blob []byte) ([]byte, error) {
	if len(blob) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	var nonce [nonceSize]byte
	copy(nonce[:], blob[:nonceSize])
	out, ok := secretbox.Open(nil, blob[nonceSize:], &nonce, &s.recv)
	if !ok {
		return nil, errors.New("decryption failed (wrong secret or tampered)")
	}
	return out, nil
}

// --- Sealed boxes (anonymous public-key encryption) ---
//
// The shared-secret model above is for two parties who already hold S. A sealed
// box (NaCl crypto_box_seal: Curve25519 + XSalsa20-Poly1305) covers the OTHER
// case: anyone can encrypt TO a published public key, and only the keyholder can
// read it. This is what lets a public web page (which can only ever hold a public
// key) send a message that the operator AND the public cannot read, while only the
// recipient's device, holding the private key, can open it.
//
// The construction generates a fresh ephemeral keypair per message and discards
// the ephemeral private key, so even the sender cannot decrypt afterward. The
// nonce is BLAKE2b(ephemeral_pub || recipient_pub) with output length 24, and the
// output layout is ephemeral_pub(32) || box, byte-identical to libsodium's
// crypto_box_seal and to a tweetnacl hand-build (see the JS client).
//
// Honest limits: sealed boxes are ANONYMOUS. There is no sender authenticity (no
// signature, no identity); anyone can seal to the public key, so an open inbox is
// spam-able and the recipient cannot verify who sent a message. There is no
// forward secrecy beyond the per-message ephemeral key. Losing the private key
// makes every message sealed to it permanently unreadable.

// BoxPublicKeySize and BoxPrivateKeySize are the Curve25519 key lengths.
const (
	BoxPublicKeySize  = 32
	BoxPrivateKeySize = 32
)

// BoxKeypair is a Curve25519 keypair for sealed-box (anonymous) encryption. The
// public key is safe to publish; the private key must stay on the recipient's
// device.
type BoxKeypair struct {
	Public  [BoxPublicKeySize]byte
	Private [BoxPrivateKeySize]byte
}

// GenerateBoxKeypair returns a fresh Curve25519 keypair for sealed boxes.
func GenerateBoxKeypair() (BoxKeypair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return BoxKeypair{}, fmt.Errorf("generating box keypair: %w", err)
	}
	return BoxKeypair{Public: *pub, Private: *priv}, nil
}

// SealTo anonymously encrypts msg to recipientPub. It uses a fresh ephemeral
// keypair that is discarded, so the sender cannot decrypt the result. Output is
// ephemeral_pub(32) || box, byte-compatible with libsodium crypto_box_seal.
func SealTo(recipientPub [BoxPublicKeySize]byte, msg []byte) ([]byte, error) {
	sealed, err := box.SealAnonymous(nil, msg, &recipientPub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sealing: %w", err)
	}
	return sealed, nil
}

// OpenSealed decrypts a sealed blob with the recipient keypair. Returns false on
// any failure (wrong key, tampered, or truncated).
func OpenSealed(kp BoxKeypair, blob []byte) ([]byte, bool) {
	return box.OpenAnonymous(nil, blob, &kp.Public, &kp.Private)
}
