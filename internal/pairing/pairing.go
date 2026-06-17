// Package pairing manages doublethink's MITM-resistant channel pairing. It is the
// security-critical step the prior-art survey (SimpleX) and the CODEX review both
// flagged as the real weak point: a broker that simply records whatever public key
// a peer presents could silently substitute its own and man-in-the-middle the
// channel. This package closes that hole for M1 with two cheap, standard measures:
//
//  1. Invites are single-use, short-lived, high-entropy, and rate-limited. A
//     pairing code authorises RENDEZVOUS only (it lets a peer present a key), not
//     final trust.
//  2. A Short Authentication String (SAS) is derived from a transcript binding the
//     channel, both peers' Ed25519 identity keys and X25519 ECDH keys, the role,
//     and the invite id. Both peers see the same SAS only if no key was substituted
//     in transit. The broker does NOT admit the joining peer's key to the channel's
//     authorized set until the SAS is confirmed out-of-band.
//
// Deliberately NOT in M1 (over-engineering for now): X3DH/double-ratchet, WebAuthn,
// PKI, multi-device identity graphs. The SAS + single-use TTL is the minimum that
// makes a silent broker MITM impossible without disturbing the keypair auth core.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// InviteTTL is how long a pairing invite is valid. Short enough to bound the
// window for code interception, long enough for a human to pair a second device.
const InviteTTL = 10 * time.Minute

// maxInvitesPerChannel rate-limits outstanding invites per channel, so an attacker
// cannot grind invite codes.
const maxInvitesPerChannel = 8

// codeBytes is the entropy of a pairing code (128 bits).
const codeBytes = 16

var (
	// ErrNoInvite is returned (uniformly) when a code is unknown, expired, or used.
	ErrNoInvite = errors.New("invalid or expired pairing code")
	// ErrRateLimited is returned when a channel has too many outstanding invites.
	ErrRateLimited = errors.New("too many outstanding invites for this channel")
)

// nowFunc is overridable in tests so TTL behaviour is deterministic. Production
// uses time.Now; the doctrine forbids real wall-clock in some contexts but this is
// a server runtime, not a workflow script.
var nowFunc = time.Now

// Invite is a pending pairing: a single-use code bound to a channel, with the
// inviter's keys recorded so the SAS transcript can bind both sides.
type Invite struct {
	Code      string
	Channel   string
	Role      string
	expiresAt time.Time
	used      bool

	// inviter key material, captured when the invite is created.
	inviterID   []byte // Ed25519 public key
	inviterECDH []byte // X25519 public key
}

// InviterIDKey returns the inviter's Ed25519 public key captured at Create.
func (i *Invite) InviterIDKey() []byte { return i.inviterID }

// InviterECDHKey returns the inviter's X25519 public key captured at Create.
func (i *Invite) InviterECDHKey() []byte { return i.inviterECDH }

// Manager holds outstanding invites. Safe for concurrent use.
type Manager struct {
	mu      sync.Mutex
	invites map[string]*Invite // code -> invite
	perChan map[string]int     // channel -> outstanding invite count
}

// NewManager returns an empty pairing manager.
func NewManager() *Manager {
	return &Manager{invites: make(map[string]*Invite), perChan: make(map[string]int)}
}

// Create issues a single-use pairing code for a channel, binding the inviter's
// Ed25519 and X25519 public keys. The code authorises a second peer to present its
// own keys; it does not by itself grant trust (the SAS does).
func (m *Manager) Create(channel, role string, inviterID, inviterECDH []byte) (*Invite, error) {
	code, err := newCode()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked()
	if m.perChan[channel] >= maxInvitesPerChannel {
		return nil, ErrRateLimited
	}
	inv := &Invite{
		Code:        code,
		Channel:     channel,
		Role:        role,
		expiresAt:   nowFunc().Add(InviteTTL),
		inviterID:   append([]byte(nil), inviterID...),
		inviterECDH: append([]byte(nil), inviterECDH...),
	}
	m.invites[code] = inv
	m.perChan[channel]++
	return inv, nil
}

// Redeem consumes a pairing code (single use). On success it returns the invite
// and the SAS computed over the full transcript binding both peers' keys. The
// caller must NOT admit the joiner's key until the SAS is confirmed out-of-band.
func (m *Manager) Redeem(code string, joinerID, joinerECDH []byte) (*Invite, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked()
	inv, ok := m.invites[code]
	if !ok || inv.used || nowFunc().After(inv.expiresAt) {
		return nil, "", ErrNoInvite
	}
	inv.used = true
	delete(m.invites, code)
	if m.perChan[inv.Channel] > 0 {
		m.perChan[inv.Channel]--
	}
	sas := ComputeSAS(inv.Channel, inv.Role, inv.inviterID, inv.inviterECDH, joinerID, joinerECDH, code)
	return inv, sas, nil
}

// gcLocked drops expired invites. Caller holds the lock.
func (m *Manager) gcLocked() {
	now := nowFunc()
	for code, inv := range m.invites {
		if now.After(inv.expiresAt) {
			delete(m.invites, code)
			if m.perChan[inv.Channel] > 0 {
				m.perChan[inv.Channel]--
			}
		}
	}
}

// ComputeSAS derives a short authentication string from a transcript that binds
// the channel, role, both peers' Ed25519 identity keys, both peers' X25519 keys,
// and the invite code. The keys are sorted so both sides compute the same value
// regardless of who is inviter vs joiner. A substituted key on either side changes
// the SAS, so a mismatch reveals a man-in-the-middle. The output is a short,
// human-comparable string (two groups of base32), enough entropy that an attacker
// cannot cheaply produce a colliding substituted key.
func ComputeSAS(channel, role string, idA, ecdhA, idB, ecdhB []byte, code string) string {
	h := sha256.New()
	writeField(h, []byte("doublethink-sas-v1"))
	writeField(h, []byte(channel))
	writeField(h, []byte(role))
	writeField(h, []byte(code))
	// Sort the two (id, ecdh) pairs so direction does not matter.
	pairA := append(append([]byte(nil), idA...), ecdhA...)
	pairB := append(append([]byte(nil), idB...), ecdhB...)
	lo, hi := pairA, pairB
	if string(lo) > string(hi) {
		lo, hi = hi, lo
	}
	writeField(h, lo)
	writeField(h, hi)
	sum := h.Sum(nil)
	// Take the first 40 bits and render as two 4-char base32 groups, e.g. "AB12-CD34".
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:5])
	return enc[:4] + "-" + enc[4:8]
}

// writeField writes a length-prefixed field so concatenation is unambiguous (no
// field-boundary confusion between, say, channel and role).
func writeField(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func newCode() (string, error) {
	raw := make([]byte, codeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}
