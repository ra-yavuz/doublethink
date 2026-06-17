package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// the exact envelope shape CodeSpeak's mock emits, from CODESPEAK-REQUIREMENTS.md.
const codespeakSample = `{"channel":"codespeak/abc123","type":"progress","id":"task-7","payload":{"step":"ran tests","pct":40},"ts":"2026-06-17T20:00:00Z"}`

func TestDecodeValidEnvelope(t *testing.T) {
	e, err := Decode([]byte(codespeakSample))
	if err != nil {
		t.Fatalf("Decode failed on a valid contract envelope: %v", err)
	}
	if e.Channel != "codespeak/abc123" {
		t.Errorf("channel = %q, want codespeak/abc123", e.Channel)
	}
	if e.Type != TypeProgress {
		t.Errorf("type = %q, want progress", e.Type)
	}
	if e.ID != "task-7" {
		t.Errorf("id = %q, want task-7", e.ID)
	}
	if e.TS != "2026-06-17T20:00:00Z" {
		t.Errorf("ts = %q, want 2026-06-17T20:00:00Z", e.TS)
	}
}

// The broker must transport payload byte-for-byte. This proves the bytes a
// sender published are exactly the bytes that round-trip out, with no reshaping.
// For a private channel that payload is opaque ciphertext, so any reshaping would
// corrupt it; this test is the guard for that guarantee.
func TestPayloadIsOpaqueAndIntact(t *testing.T) {
	// A payload with deliberately unusual key ordering and whitespace-sensitive
	// content. If the broker parsed and re-emitted it, ordering could change.
	raw := `{"z":1,"a":2,"nested":{"k":"v with spaces"}}`
	src := `{"channel":"c","type":"control","id":"i","payload":` + raw + `,"ts":"t"}`

	e, err := Decode([]byte(src))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(e.Payload, []byte(raw)) {
		t.Errorf("payload bytes changed on decode:\n got %s\nwant %s", e.Payload, raw)
	}

	out, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Re-decode the encoded form and confirm payload survived the full round trip.
	e2, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode round trip: %v", err)
	}
	if !bytes.Equal(e2.Payload, []byte(raw)) {
		t.Errorf("payload bytes changed across round trip:\n got %s\nwant %s", e2.Payload, raw)
	}
}

func TestRejectUnknownType(t *testing.T) {
	src := `{"channel":"c","type":"bogus","id":"i","payload":{},"ts":"t"}`
	_, err := Decode([]byte(src))
	if err == nil {
		t.Fatal("Decode accepted an unknown type; should reject")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error = %v, want wrapped ErrInvalid", err)
	}
}

func TestRejectMissingFields(t *testing.T) {
	cases := map[string]string{
		"empty channel": `{"channel":"","type":"request","id":"i","payload":{},"ts":"t"}`,
		"empty id":      `{"channel":"c","type":"request","id":"","payload":{},"ts":"t"}`,
		"empty ts":      `{"channel":"c","type":"request","id":"i","payload":{},"ts":""}`,
		"missing type":  `{"channel":"c","id":"i","payload":{},"ts":"t"}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(src)); err == nil {
				t.Errorf("Decode accepted invalid envelope (%s)", name)
			}
		})
	}
}

// Contract-drift guard: a client adding an undocumented field is caught here, not
// silently tolerated. Tightening the contract is deliberate; silent drift is not.
func TestRejectUnknownField(t *testing.T) {
	src := `{"channel":"c","type":"request","id":"i","payload":{},"ts":"t","extra":"nope"}`
	if _, err := Decode([]byte(src)); err == nil {
		t.Error("Decode accepted an envelope with an unknown top-level field")
	}
}

// A null payload is allowed (a bare control message need carry no body).
func TestNullPayloadAllowed(t *testing.T) {
	src := `{"channel":"c","type":"control","id":"i","payload":null,"ts":"t"}`
	e, err := Decode([]byte(src))
	if err != nil {
		t.Fatalf("Decode rejected null payload: %v", err)
	}
	if len(e.Payload) != 0 && string(e.Payload) != "null" {
		t.Errorf("unexpected payload for null: %s", e.Payload)
	}
}

// Sanity: the type set matches the contract string exactly.
func TestTypeSetMatchesContract(t *testing.T) {
	want := []Type{TypeRequest, TypeProgress, TypeResult, TypeSummary, TypeControl, TypeError}
	for _, ty := range want {
		if !ty.Valid() {
			t.Errorf("%q should be a valid type", ty)
		}
	}
	var asJSON struct {
		T Type `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":"request"}`), &asJSON); err != nil {
		t.Fatal(err)
	}
	if asJSON.T != TypeRequest {
		t.Errorf("json type decode = %q, want request", asJSON.T)
	}
}
