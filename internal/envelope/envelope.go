// Package envelope defines doublethink's wire message: the fixed JSON envelope
// from docs/CODESPEAK-REQUIREMENTS.md. The broker routes on channel/type/id/ts
// and transports payload opaquely, byte for byte. payload is NEVER re-marshalled
// by the broker: for a private channel it is end-to-end-encrypted ciphertext the
// broker cannot read, and even for a plaintext topic the broker has no business
// reshaping a sender's bytes.
package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Type is the closed set of envelope message types CodeSpeak uses. Keeping it a
// closed enum lets the broker reject malformed traffic with an honest error
// rather than silently forwarding garbage (SECURITY.md req 5).
type Type string

const (
	TypeRequest  Type = "request"
	TypeProgress Type = "progress"
	TypeResult   Type = "result"
	TypeSummary  Type = "summary"
	TypeControl  Type = "control"
	TypeError    Type = "error"
)

// validTypes is the membership set for Type.Valid. Listed explicitly rather than
// derived so adding a type is a deliberate edit, not an accident.
var validTypes = map[Type]struct{}{
	TypeRequest:  {},
	TypeProgress: {},
	TypeResult:   {},
	TypeSummary:  {},
	TypeControl:  {},
	TypeError:    {},
}

// Valid reports whether t is one of the defined envelope types.
func (t Type) Valid() bool {
	_, ok := validTypes[t]
	return ok
}

// Envelope is the fixed message shape. Field order and names mirror the contract
// exactly so a CodeSpeak client cannot tell doublethink from its mock.
//
// Payload is json.RawMessage so the broker neither parses nor re-encodes it. The
// bytes a sender published are the bytes a subscriber receives.
type Envelope struct {
	Channel string          `json:"channel"`
	Type    Type            `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
	TS      string          `json:"ts"`
}

// ErrInvalid is returned by Validate (wrapped) when an envelope is malformed.
var ErrInvalid = errors.New("invalid envelope")

// Validate checks the routing-relevant fields the broker depends on. It does NOT
// inspect Payload: payload is opaque by contract. ts is required to be present
// (the contract carries it) but its format is the sender's concern, not the
// broker's, so we do not parse it here.
func (e *Envelope) Validate() error {
	if e.Channel == "" {
		return fmt.Errorf("%w: empty channel", ErrInvalid)
	}
	if !e.Type.Valid() {
		return fmt.Errorf("%w: unknown type %q", ErrInvalid, e.Type)
	}
	if e.ID == "" {
		return fmt.Errorf("%w: empty id", ErrInvalid)
	}
	if e.TS == "" {
		return fmt.Errorf("%w: empty ts", ErrInvalid)
	}
	// A null/absent payload is allowed (e.g. a bare control with no body); an
	// explicitly malformed payload would have failed JSON decoding already.
	return nil
}

// Decode parses bytes into an Envelope and validates routing fields. It rejects
// unknown top-level fields so a client drifting from the contract is caught here
// rather than silently tolerated (contract-drift is a defect, not a feature).
func Decode(b []byte) (*Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// Encode serialises an Envelope back to bytes. Payload passes through unchanged
// because it is already json.RawMessage.
func (e *Envelope) Encode() ([]byte, error) {
	return json.Marshal(e)
}
