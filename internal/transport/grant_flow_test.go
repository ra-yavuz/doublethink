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

// A grant lets the USER choose plaintext: a keyless ticketed create makes a
// PERMANENT plaintext topic reachable on the open /publish + /subscribe path, with
// retention (a later subscriber catches up on the backlog). No E2E, by the user's
// choice; the broker stores readable text.
func TestGrantPlaintextRetainedTopicFlow(t *testing.T) {
	httpURL, _, st, _ := retentionServer(t)

	const topic = "ring/guestbook-1"
	// 1. admin grants the (encryption-agnostic) permanent capped slot.
	grantBody, _ := json.Marshal(map[string]any{
		"channel_match": topic, "ttl_sec": 0, "max_bytes": 0, "max_msgs": 0, "expiry_sec": 600,
	})
	greq, _ := http.NewRequest("POST", httpURL+"/admin/grant", bytes.NewReader(grantBody))
	greq.Header.Set("Authorization", "Bearer "+adminKey)
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil || gresp.StatusCode != 200 {
		t.Fatalf("grant: %v status %v", err, gresp.StatusCode)
	}
	var gout struct {
		Ticket string `json:"ticket"`
	}
	json.NewDecoder(gresp.Body).Decode(&gout)
	gresp.Body.Close()

	// 2. user redeems WITHOUT an auth_key -> plaintext topic (user's choice).
	cbody, _ := json.Marshal(map[string]any{"channel": topic, "ticket": gout.Ticket}) // no auth_key
	cresp, err := http.Post(httpURL+"/channel", "application/json", bytes.NewReader(cbody))
	if err != nil || cresp.StatusCode != 200 {
		b, _ := io_ReadAll(cresp)
		t.Fatalf("plaintext ticketed create: %v status %v body %s", err, cresp.StatusCode, b)
	}
	var cout struct {
		Encrypted bool `json:"encrypted"`
		Retained  bool `json:"retained"`
	}
	json.NewDecoder(cresp.Body).Decode(&cout)
	cresp.Body.Close()
	if cout.Encrypted || !cout.Retained {
		t.Fatalf("plaintext create response = %+v, want encrypted=false retained=true", cout)
	}

	// stored channel has empty k_auth and is retained + permanent.
	ch, err := st.GetChannel(topic)
	if err != nil || ch.KAuth != "" || !ch.Retained || ch.TTLSeconds != 0 {
		t.Fatalf("plaintext channel = %+v %v (want empty k_auth, retained, ttl0)", ch, err)
	}

	// 3. publish two entries on the OPEN path (no key, ntfy-style). They persist.
	for _, msg := range []string{"first guest", "second guest"} {
		pr, perr := http.Post(httpURL+"/publish/"+topic, "text/plain", strings.NewReader(msg))
		if perr != nil || pr.StatusCode != 200 {
			t.Fatalf("publish %q: %v status %v", msg, perr, pr.StatusCode)
		}
		var pout struct {
			Retained bool `json:"retained"`
		}
		json.NewDecoder(pr.Body).Decode(&pout)
		pr.Body.Close()
		if !pout.Retained {
			t.Fatalf("publish of %q reported retained=false on a retained topic", msg)
		}
	}

	// 4. a FRESH subscriber catches up on both entries from the backlog (proves
	// retention + open-path reachability). Read the SSE stream briefly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sreq, _ := http.NewRequestWithContext(ctx, "GET", httpURL+"/subscribe/"+topic, nil)
	sresp, err := http.DefaultClient.Do(sreq)
	if err != nil || sresp.StatusCode != 200 {
		t.Fatalf("subscribe: %v status %v", err, sresp.StatusCode)
	}
	defer sresp.Body.Close()
	// Read the stream on a goroutine; ctx (5s) closes the body to unblock us.
	gotCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		acc := ""
		for {
			n, rerr := sresp.Body.Read(buf)
			acc += string(buf[:n])
			if strings.Contains(acc, "first guest") && strings.Contains(acc, "second guest") {
				gotCh <- acc
				return
			}
			if rerr != nil {
				gotCh <- acc
				return
			}
		}
	}()
	var got string
	select {
	case got = <-gotCh:
	case <-ctx.Done():
		got = "<timeout>"
	}
	if !strings.Contains(got, "first guest") || !strings.Contains(got, "second guest") {
		t.Fatalf("catch-up did not replay both entries; got:\n%s", got)
	}
}

// A keyless create WITHOUT a ticket is rejected: only an admin grant authorizes a
// plaintext topic, so the open retention path cannot be opened without one.
func TestKeylessCreateWithoutTicketRejected(t *testing.T) {
	httpURL, _, _, _ := retentionServer(t)
	body, _ := json.Marshal(map[string]any{"channel": "ring/sneaky", "retain": true}) // no auth_key, no ticket
	resp, err := http.Post(httpURL+"/channel", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("keyless no-ticket create = %d, want 400", resp.StatusCode)
	}
}

// The root path (and any unrouted path) serves a rotating human brush-off, and
// the message varies across requests. Real API routes are unaffected.
func TestRootBrushoff(t *testing.T) {
	httpURL, _, _, _ := retentionServer(t)

	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		resp, err := http.Get(httpURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		b := new(bytes.Buffer)
		b.ReadFrom(resp.Body)
		resp.Body.Close()
		body := strings.TrimSpace(b.String())
		if body == "ok" || body == "404 page not found" {
			t.Fatalf("root served the bare default %q, want a brush-off message", body)
		}
		if body == "" {
			t.Fatal("root served an empty body")
		}
		seen[body] = true
	}
	// Over several hits we should see more than one distinct message (it rotates).
	if len(seen) < 2 {
		t.Fatalf("root message did not vary across requests; saw only %d distinct", len(seen))
	}

	// An arbitrary unrouted path also gets a brush-off, not a bare 404.
	r2, _ := http.Get(httpURL + "/favicon.ico")
	b2 := new(bytes.Buffer)
	b2.ReadFrom(r2.Body)
	r2.Body.Close()
	if strings.TrimSpace(b2.String()) == "404 page not found" {
		t.Fatal("unrouted path served the bare default 404")
	}

	// /healthz is untouched: still plain "ok" with 200.
	h, _ := http.Get(httpURL + "/healthz")
	hb := new(bytes.Buffer)
	hb.ReadFrom(h.Body)
	h.Body.Close()
	if h.StatusCode != 200 || strings.TrimSpace(hb.String()) != "ok" {
		t.Fatalf("/healthz = %d %q, want 200 \"ok\" (must stay a clean health probe)", h.StatusCode, hb.String())
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
