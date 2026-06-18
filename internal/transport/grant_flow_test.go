package transport_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/envelope"
)

// The headline M3 flow: an admin issues a grant for a PERMANENT topic; a user
// redeems it creating the channel with their OWN secret (admin never sees it); the
// channel is permanent (ttl 0) and E2E works.
func TestAdminGrantPermanentTopicFlow(t *testing.T) {
	httpURL, wsURL, st, _ := retentionServer(t)

	// 1. Admin issues a grant (permanent, uncapped) bound to a channel id. Admin key only.
	const channel = "perm/team-debug"
	grantBody, _ := json.Marshal(map[string]any{
		"channel_match": channel, "ttl_sec": 0, "max_bytes": 0, "max_msgs": 0, "expiry_sec": 600,
	})
	greq, _ := http.NewRequest("POST", httpURL+"/admin/grant", bytes.NewReader(grantBody))
	greq.Header.Set("Authorization", "Bearer "+adminKey)
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	if gresp.StatusCode != 200 {
		t.Fatalf("grant status %d", gresp.StatusCode)
	}
	var gout struct {
		Ticket string `json:"ticket"`
	}
	json.NewDecoder(gresp.Body).Decode(&gout)
	gresp.Body.Close()
	if gout.Ticket == "" {
		t.Fatal("no ticket issued")
	}

	// 2. A non-admin cannot issue a grant.
	bad, _ := http.NewRequest("POST", httpURL+"/admin/grant", bytes.NewReader(grantBody))
	bad.Header.Set("Authorization", "Bearer wrong")
	bresp, _ := http.DefaultClient.Do(bad)
	if bresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin grant = %d, want 401", bresp.StatusCode)
	}
	bresp.Body.Close()

	// 3. User creates the channel WITH THE TICKET and their OWN secret (admin never saw it).
	secret, _ := clientcrypto.GenerateSecret()
	ka, _ := clientcrypto.RegistrationKey(secret)
	cbody, _ := json.Marshal(map[string]any{"channel": channel, "auth_key": ka, "ticket": gout.Ticket})
	cresp, err := http.Post(httpURL+"/channel", "application/json", bytes.NewReader(cbody))
	if err != nil {
		t.Fatal(err)
	}
	if cresp.StatusCode != 200 {
		t.Fatalf("ticketed create status %d", cresp.StatusCode)
	}
	cresp.Body.Close()

	// 4. The channel exists, is retained, and is PERMANENT (ttl 0, uncapped) from the ticket.
	ch, err := st.GetChannel(channel)
	if err != nil || !ch.Retained || ch.TTLSeconds != 0 || ch.MaxMsgs != 0 {
		t.Fatalf("granted channel policy = %+v %v (want retained, ttl0, uncapped)", ch, err)
	}

	// 5. End-to-end works on it: A publishes (retained), B catches up and decrypts.
	sa, _ := clientcrypto.NewSession(secret, clientcrypto.RoleA)
	sb, _ := clientcrypto.NewSession(secret, clientcrypto.RoleB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := attach(t, ctx, wsURL, channel, secret, 0)
	defer a.CloseNow()
	sealed, _ := sa.Seal([]byte("permanent debug line"))
	env := &envelope.Envelope{Channel: channel, Type: envelope.TypeProgress, ID: "1",
		Payload: mustJSON(base64.StdEncoding.EncodeToString(sealed)), TS: time.Now().UTC().Format(time.RFC3339)}
	raw, _ := env.Encode()
	a.Write(ctx, websocket.MessageText, raw)
	time.Sleep(200 * time.Millisecond)

	b := attach(t, ctx, wsURL, channel, secret, 0)
	defer b.CloseNow()
	_, data, err := b.Read(ctx)
	if err != nil {
		t.Fatalf("B catch-up read: %v", err)
	}
	ge, _ := envelope.Decode(data)
	var s string
	json.Unmarshal(ge.Payload, &s)
	blob, _ := base64.StdEncoding.DecodeString(s)
	pt, err := sb.Open(blob)
	if err != nil || string(pt) != "permanent debug line" {
		t.Fatalf("B decrypt = %q %v", pt, err)
	}
}

// Public /stats serves aggregate counters and never leaks channel ids or secrets.
func TestPublicStats(t *testing.T) {
	httpURL, _, _, _ := retentionServer(t)
	resp, err := http.Get(httpURL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stats status %d", resp.StatusCode)
	}
	body := new(bytes.Buffer)
	body.ReadFrom(resp.Body)
	var st map[string]any
	if err := json.Unmarshal(body.Bytes(), &st); err != nil {
		t.Fatalf("stats not json: %v", err)
	}
	if _, ok := st["channels"]; !ok {
		t.Fatal("stats missing channels counter")
	}
	// must not leak a channel id or any obvious secret field
	if strings.Contains(body.String(), "k_auth") || strings.Contains(body.String(), "secret") {
		t.Fatalf("stats leaked sensitive field: %s", body.String())
	}
}

// admin channels listing is admin-gated and returns metadata only (no k_auth).
func TestAdminChannelsListing(t *testing.T) {
	httpURL, _, _, _ := retentionServer(t)
	// no key -> 404 (no admin surface advertised) ... actually requireAdmin returns 404 only
	// when admin disabled; here admin IS enabled, so a missing/bad key is 401.
	noauth, _ := http.Get(httpURL + "/admin/channels")
	if noauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth admin/channels = %d, want 401", noauth.StatusCode)
	}
	noauth.Body.Close()

	req, _ := http.NewRequest("GET", httpURL+"/admin/channels", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("admin/channels = %d, want 200", resp.StatusCode)
	}
	b := new(bytes.Buffer)
	b.ReadFrom(resp.Body)
	resp.Body.Close()
	if strings.Contains(b.String(), "k_auth") {
		t.Fatalf("admin listing leaked k_auth: %s", b.String())
	}
}
