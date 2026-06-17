package transport_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/envelope"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

// testServer spins up the real transport over httptest and returns a ws:// URL.
func testServer(t *testing.T) (*broker.Broker, *auth.Registry, string, func()) {
	t.Helper()
	b := broker.New()
	reg := auth.NewRegistry()
	srv := httptest.NewServer(transport.New(b, reg).Handler())
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	return b, reg, wsURL, srv.Close
}

// connectAuthed performs the full handshake (handshake -> challenge -> sign ->
// result) as a real client would, using an Ed25519 identity. Returns the open
// connection on success, or an error.
func connectAuthed(ctx context.Context, wsURL, channel string, signPub ed25519.PublicKey, sign func([]byte) []byte) (*websocket.Conn, error) {
	c, _, err := websocket.Dial(ctx, wsURL+"/ws", nil)
	if err != nil {
		return nil, err
	}
	// handshake
	hs, _ := json.Marshal(map[string]string{
		"channel": channel,
		"pubkey":  base64.StdEncoding.EncodeToString(signPub),
	})
	if err := c.Write(ctx, websocket.MessageText, hs); err != nil {
		c.CloseNow()
		return nil, err
	}
	// challenge
	_, chData, err := c.Read(ctx)
	if err != nil {
		c.CloseNow()
		return nil, err
	}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(chData, &ch); err != nil {
		c.CloseNow()
		return nil, err
	}
	challenge, _ := base64.StdEncoding.DecodeString(ch.Challenge)
	// sign
	sig := sign(challenge)
	authMsg, _ := json.Marshal(map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
	if err := c.Write(ctx, websocket.MessageText, authMsg); err != nil {
		c.CloseNow()
		return nil, err
	}
	// result
	_, resData, err := c.Read(ctx)
	if err != nil {
		c.CloseNow()
		return nil, err
	}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(resData, &res)
	if !res.OK {
		c.CloseNow()
		return nil, &authError{res.Error}
	}
	return c, nil
}

type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

// The headline end-to-end test: two paired peers stand up against the real
// server, exchange an end-to-end-encrypted message over a private channel, and
// the broker only ever holds ciphertext. This is the "someone can stand it up and
// exchange messages with confidence nobody else can read it" bar.
func TestPrivateChannelE2ERoundTrip(t *testing.T) {
	_, reg, wsURL, closeSrv := testServer(t)
	defer closeSrv()

	// Pairing (out of band, here done directly): two identities, register both
	// Ed25519 keys on the channel, exchange X25519 keys, derive sessions.
	idA, _ := clientcrypto.GenerateIdentity()
	idB, _ := clientcrypto.GenerateIdentity()
	const channel = "codespeak/secret-paired-id"
	if err := reg.Register(channel, idA.SignPub); err != nil {
		t.Fatal(err)
	}
	if err := reg.Authorize(channel, idB.SignPub); err != nil {
		t.Fatal(err)
	}
	sessA, _ := idA.Derive(idB.ECDHPublic(), channel)
	sessB, _ := idB.Derive(idA.ECDHPublic(), channel)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connA, err := connectAuthed(ctx, wsURL, channel, idA.SignPub, idA.Sign)
	if err != nil {
		t.Fatalf("peer A connect: %v", err)
	}
	defer connA.CloseNow()
	connB, err := connectAuthed(ctx, wsURL, channel, idB.SignPub, idB.Sign)
	if err != nil {
		t.Fatalf("peer B connect: %v", err)
	}
	defer connB.CloseNow()

	// Give B's subscription a moment to register before A publishes.
	time.Sleep(100 * time.Millisecond)

	// Peer A seals a secret payload and publishes the envelope.
	secret := []byte(`{"cmd":"deploy prod","token":"do-not-leak"}`)
	sealed, _ := sessA.Seal(secret)
	out := &envelope.Envelope{
		Channel: channel,
		Type:    envelope.TypeRequest,
		ID:      "task-1",
		Payload: mustJSON(base64.StdEncoding.EncodeToString(sealed)),
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := out.Encode()
	if err := connA.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}

	// Peer B receives, decodes the envelope, and decrypts the payload.
	_, got, err := connB.Read(ctx)
	if err != nil {
		t.Fatalf("peer B read: %v", err)
	}
	gotEnv, err := envelope.Decode(got)
	if err != nil {
		t.Fatalf("peer B decode: %v", err)
	}
	if gotEnv.ID != "task-1" {
		t.Errorf("id = %q, want task-1", gotEnv.ID)
	}
	var b64 string
	if err := json.Unmarshal(gotEnv.Payload, &b64); err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(b64)
	plain, err := sessB.Open(blob)
	if err != nil {
		t.Fatalf("peer B could not decrypt: %v", err)
	}
	if string(plain) != string(secret) {
		t.Errorf("decrypted = %s, want %s", plain, secret)
	}

	// The broker only ever saw the (base64 of the) sealed blob, never the secret.
	if strings.Contains(string(got), "do-not-leak") {
		t.Fatal("secret token appeared in the bytes the broker forwarded")
	}
}

// An unauthenticated / unauthorized peer cannot attach to a private channel.
func TestUnauthorizedWSRejected(t *testing.T) {
	_, reg, wsURL, closeSrv := testServer(t)
	defer closeSrv()

	owner, _ := clientcrypto.GenerateIdentity()
	const channel = "private"
	if err := reg.Register(channel, owner.SignPub); err != nil {
		t.Fatal(err)
	}

	// A stranger with a perfectly valid key NOT on the channel tries to attach.
	stranger, _ := clientcrypto.GenerateIdentity()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := connectAuthed(ctx, wsURL, channel, stranger.SignPub, stranger.Sign)
	if err == nil {
		t.Fatal("stranger authenticated to a private channel it is not authorized for")
	}
}

// The plaintext public path refuses to serve a name that is a private channel,
// so a private channel cannot be reached through the open path.
func TestPublicPathRefusesPrivateChannel(t *testing.T) {
	_, reg, wsURL, closeSrv := testServer(t)
	defer closeSrv()
	httpURL := "http" + strings.TrimPrefix(wsURL, "ws")

	owner, _ := clientcrypto.GenerateIdentity()
	if err := reg.Register("locked", owner.SignPub); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(httpURL + "/subscribe/locked")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("public subscribe to a private channel returned %d, want 403", resp.StatusCode)
	}
}

// A public plaintext topic works ntfy-style: POST publishes, SSE subscribers
// receive it incrementally.
func TestPublicTopicPubSub(t *testing.T) {
	_, _, wsURL, closeSrv := testServer(t)
	defer closeSrv()
	httpURL := "http" + strings.TrimPrefix(wsURL, "ws")

	// Start an SSE subscriber.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, httpURL+"/subscribe/news", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscribe status = %d", resp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond) // let the subscriber register

	// Publish to the topic.
	pubResp, err := http.Post(httpURL+"/publish/news", "text/plain", strings.NewReader("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	pubResp.Body.Close()

	// Read SSE lines and confirm the payload made it through.
	got := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				select {
				case got <- line:
				default:
				}
				return
			}
		}
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, "hello world") {
			t.Fatalf("SSE event missing payload: %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not receive published message over SSE")
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
