// Package clientcrypto is the CLIENT-side end-to-end encryption for doublethink
// private channels (docs/DESIGN-M1.md decision 4). The broker never imports this
// package to encrypt or decrypt anything: by design it only ever sees ciphertext.
// This code lives here so the reference CLI client and the tests that prove the
// broker cannot read a private payload can share one correct implementation.
//
// Design, with the corrections from the CODEX crypto review folded in:
//   - A device pairs as an identity bundle: an Ed25519 keypair (for broker-attach
//     auth, see package auth) and an X25519 keypair (for ECDH only). The two are
//     kept separate; an X25519 key is never used to sign.
//   - The channel secret is HKDF over the X25519 ECDH shared secret, salted by the
//     channel id and bound to BOTH peers' X25519 public keys (sorted, so direction
//     does not matter) plus a version label. This prevents identity-misbinding and
//     gives domain separation.
//   - Each DIRECTION gets its OWN payload key derived from the channel secret, so
//     the two peers never share a key (and thus never a nonce domain). secretbox
//     (XSalsa20-Poly1305) seals payloads under the sender's per-direction key with
//     a random 192-bit nonce.
//
// M1 limitation (documented, not hidden): the channel secret is static for the
// life of a pairing, so there is no forward secrecy. Compromise of a peer's
// X25519 private key exposes past captured ciphertext. Revocation is by re-pairing
// (fresh keys, fresh secret). A ratchet is a named post-M1 follow-up.
package clientcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32
	nonceSize = 24
	// versionLabel is the domain-separation tag mixed into key derivation. Bump it
	// if the derivation scheme ever changes, so keys from different schemes differ.
	versionLabel = "doublethink-channel-v1"
)

// Identity is a device's key bundle. Sign uses the Ed25519 half (broker auth);
// the X25519 half is for channel-key agreement only.
type Identity struct {
	SignPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey

	ecdhPub  [keySize]byte
	ecdhPriv [keySize]byte
}

// GenerateIdentity creates a fresh device identity bundle.
func GenerateIdentity() (*Identity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	id := &Identity{SignPub: signPub, signPriv: signPriv}
	if _, err := io.ReadFull(rand.Reader, id.ecdhPriv[:]); err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	pub, err := curve25519.X25519(id.ecdhPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 public: %w", err)
	}
	copy(id.ecdhPub[:], pub)
	return id, nil
}

// ECDHPublic returns the device's X25519 public key (shared with the peer at
// pairing). SignPublic (the Ed25519 half) is the exported field SignPub.
func (id *Identity) ECDHPublic() [keySize]byte { return id.ecdhPub }

// Sign signs a broker challenge with the Ed25519 identity key (used by package auth).
func (id *Identity) Sign(challenge []byte) []byte { return ed25519.Sign(id.signPriv, challenge) }

// PersistedIdentity is the serialisable form of an Identity. It contains PRIVATE
// keys and must be stored only on the owning peer's machine, never sent to the
// broker. All fields are base64.
type PersistedIdentity struct {
	SignPriv string `json:"sign_priv"` // Ed25519 private key (seed+pub, 64 bytes)
	SignPub  string `json:"sign_pub"`  // Ed25519 public key
	ECDHPriv string `json:"ecdh_priv"` // X25519 private scalar
	ECDHPub  string `json:"ecdh_pub"`  // X25519 public key
}

// Export serialises an Identity for storage on the owning peer's machine.
func (id *Identity) Export() PersistedIdentity {
	return PersistedIdentity{
		SignPriv: base64.StdEncoding.EncodeToString(id.signPriv),
		SignPub:  base64.StdEncoding.EncodeToString(id.SignPub),
		ECDHPriv: base64.StdEncoding.EncodeToString(id.ecdhPriv[:]),
		ECDHPub:  base64.StdEncoding.EncodeToString(id.ecdhPub[:]),
	}
}

// ImportIdentity reconstructs an Identity from its persisted form.
func ImportIdentity(p PersistedIdentity) (*Identity, error) {
	signPriv, err := base64.StdEncoding.DecodeString(p.SignPriv)
	if err != nil || len(signPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("bad sign_priv")
	}
	signPub, err := base64.StdEncoding.DecodeString(p.SignPub)
	if err != nil || len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("bad sign_pub")
	}
	ecdhPriv, err := base64.StdEncoding.DecodeString(p.ECDHPriv)
	if err != nil || len(ecdhPriv) != keySize {
		return nil, errors.New("bad ecdh_priv")
	}
	ecdhPub, err := base64.StdEncoding.DecodeString(p.ECDHPub)
	if err != nil || len(ecdhPub) != keySize {
		return nil, errors.New("bad ecdh_pub")
	}
	id := &Identity{SignPub: ed25519.PublicKey(signPub), signPriv: ed25519.PrivateKey(signPriv)}
	copy(id.ecdhPriv[:], ecdhPriv)
	copy(id.ecdhPub[:], ecdhPub)
	return id, nil
}

// Session is the derived per-channel crypto state for one peer: its two
// per-direction keys. send is the key this peer encrypts with; recv is the key it
// decrypts the other peer's messages with.
type Session struct {
	send [keySize]byte
	recv [keySize]byte
}

// Derive computes the channel secret and this peer's per-direction keys.
//
//	myECDHPriv/myECDHPub: this peer's X25519 keypair.
//	peerECDHPub:          the other peer's X25519 public key (learned at pairing).
//	channelID:            the channel's id (HKDF salt; ties keys to this channel).
//
// Both peers calling Derive with mirrored inputs land on the same channel secret
// and the same two direction keys, but each gets `send`/`recv` oriented for itself.
func (id *Identity) Derive(peerECDHPub [keySize]byte, channelID string) (*Session, error) {
	shared, err := curve25519.X25519(id.ecdhPriv[:], peerECDHPub[:])
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	// All-zero shared secret means a low-order/invalid peer key. Reject it.
	var zero [keySize]byte
	if bytes.Equal(shared, zero[:]) {
		return nil, errors.New("invalid peer public key (zero shared secret)")
	}

	// Bind both public keys, sorted, into the derivation so direction does not
	// matter and neither peer can be misbound to a different identity.
	lo, hi := id.ecdhPub, peerECDHPub
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	info := bytes.NewBuffer(nil)
	info.WriteString(versionLabel)
	info.Write(lo[:])
	info.Write(hi[:])

	channelSecret := make([]byte, keySize)
	r := hkdf.New(blake2bNew, shared, []byte(channelID), info.Bytes())
	if _, err := io.ReadFull(r, channelSecret); err != nil {
		return nil, fmt.Errorf("hkdf channel secret: %w", err)
	}

	// Per-direction keys. "lo->hi" is the direction from the lexicographically
	// smaller public key to the larger; each peer knows which side it is on.
	keyLoToHi := deriveDirKey(channelSecret, "payload lo->hi", lo, hi)
	keyHiToLo := deriveDirKey(channelSecret, "payload hi->lo", lo, hi)

	s := &Session{}
	if id.ecdhPub == lo {
		s.send, s.recv = keyLoToHi, keyHiToLo
	} else {
		s.send, s.recv = keyHiToLo, keyLoToHi
	}
	return s, nil
}

func deriveDirKey(channelSecret []byte, dir string, lo, hi [keySize]byte) [keySize]byte {
	info := bytes.NewBuffer(nil)
	info.WriteString(versionLabel)
	info.WriteString(dir)
	info.Write(lo[:])
	info.Write(hi[:])
	out := make([]byte, keySize)
	r := hkdf.New(blake2bNew, channelSecret, nil, info.Bytes())
	_, _ = io.ReadFull(r, out)
	var k [keySize]byte
	copy(k[:], out)
	return k
}

// blake2bNew adapts blake2b to the hash.Hash constructor hkdf expects.
func blake2bNew() hash.Hash {
	h, _ := blake2b.New256(nil)
	return h
}

// Seal encrypts plaintext under this peer's send key with a fresh random nonce.
// The returned bytes are nonce||ciphertext, which is what crosses the broker as
// the opaque payload. The broker cannot open it: it has neither key.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return secretbox.Seal(nonce[:], plaintext, &nonce, &s.send), nil
}

// Open decrypts a nonce||ciphertext blob produced by the peer (under the peer's
// send key, which is this peer's recv key). It fails if the blob was not sealed
// by the legitimate peer for this direction, or was tampered with.
func (s *Session) Open(blob []byte) ([]byte, error) {
	if len(blob) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	var nonce [nonceSize]byte
	copy(nonce[:], blob[:nonceSize])
	out, ok := secretbox.Open(nil, blob[nonceSize:], &nonce, &s.recv)
	if !ok {
		return nil, errors.New("decryption failed (wrong key or tampered)")
	}
	return out, nil
}
