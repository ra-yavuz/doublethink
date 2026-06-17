package transport_test

import (
	"bufio"
	"bytes"
	"context"
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

func testServer(t *testing.T) (*broker.Broker, *auth.Registry, string, string, func()) {
	t.Helper()
	b := broker.New()
	reg := auth.NewRegistry()
	srv := httptest.NewServer(transport.New(b, reg).Handler())
	httpURL := srv.URL
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	return b, reg, wsURL, httpURL, srv.Close
}

// createChannel does the self-service POST /channel a client would do: it mints a
// secret, registers K_auth, and returns the channel id + secret.
func createChannel(t *testing.T, httpURL, channel, secret string) {
	t.Helper()
	authKey, err := clientcrypto.RegistrationKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"channel": channel, "auth_key": authKey})
	resp, err := http.Post(httpURL+"/channel", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create channel returned %d", resp.StatusCode)
	}
}

// connectWithSecret performs the WS attach: handshake (channel) -> challenge ->
// response (computed from the secret) -> result.
func connectWithSecret(ctx context.Context, wsURL, channel, secret string) (*websocket.Conn, error) {
	c, _, err := websocket.Dial(ctx, wsURL+"/ws", nil)
	if err != nil {
		return nil, err
	}
	hs, _ := json.Marshal(map[string]string{"channel": channel})
	if err := c.Write(ctx, websocket.MessageText, hs); err != nil {
		c.CloseNow()
		return nil, err
	}
	_, chData, err := c.Read(ctx)
	if err != nil {
		c.CloseNow()
		return nil, err
	}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(chData, &ch)
	challenge, _ := base64.StdEncoding.DecodeString(ch.Challenge)
	response, err := clientcrypto.ChallengeResponse(secret, challenge)
	if err != nil {
		c.CloseNow()
		return nil, err
	}
	authMsg, _ := json.Marshal(map[string]string{"response": base64.StdEncoding.EncodeToString(response)})
	if err := c.Write(ctx, websocket.MessageText, authMsg); err != nil {
		c.CloseNow()
		return nil, err
	}
	_, resData, err := c.Read(ctx)
	if err != nil {
		c.CloseNow()
		return nil, err
	}
	var res struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal(resData, &res)
	if !res.OK {
		c.CloseNow()
		return nil, errNotOK
	}
	return c, nil
}

var errNotOK = &dtErr{"not authorized"}

type dtErr struct{ m string }

func (e *dtErr) Error() string { return e.m }

// Headline: two parties sharing one secret create a channel, both attach, and
// exchange an end-to-end-encrypted message the broker only sees as ciphertext.
func TestSharedSecretE2ERoundTrip(t *testing.T) {
	_, _, wsURL, httpURL, closeSrv := testServer(t)
	defer closeSrv()

	const channel = "codespeak/secret-paired-id"
	secret, _ := clientcrypto.GenerateSecret()
	createChannel(t, httpURL, channel, secret)

	sessA, _ := clientcrypto.NewSession(secret, clientcrypto.RoleA)
	sessB, _ := clientcrypto.NewSession(secret, clientcrypto.RoleB)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connA, err := connectWithSecret(ctx, wsURL, channel, secret)
	if err != nil {
		t.Fatalf("party A connect: %v", err)
	}
	defer connA.CloseNow()
	connB, err := connectWithSecret(ctx, wsURL, channel, secret)
	if err != nil {
		t.Fatalf("party B connect: %v", err)
	}
	defer connB.CloseNow()

	time.Sleep(100 * time.Millisecond) // let B's subscription register

	secretMsg := []byte(`{"cmd":"deploy prod","token":"do-not-leak"}`)
	sealed, _ := sessA.Seal(secretMsg)
	out := &envelope.Envelope{
		Channel: channel, Type: envelope.TypeRequest, ID: "task-1",
		Payload: mustJSON(base64.StdEncoding.EncodeToString(sealed)),
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := out.Encode()
	if err := connA.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}

	_, got, err := connB.Read(ctx)
	if err != nil {
		t.Fatalf("party B read: %v", err)
	}
	gotEnv, _ := envelope.Decode(got)
	var b64 string
	_ = json.Unmarshal(gotEnv.Payload, &b64)
	blob, _ := base64.StdEncoding.DecodeString(b64)
	plain, err := sessB.Open(blob)
	if err != nil {
		t.Fatalf("party B could not decrypt: %v", err)
	}
	if string(plain) != string(secretMsg) {
		t.Errorf("decrypted = %s, want %s", plain, secretMsg)
	}
	if strings.Contains(string(got), "do-not-leak") {
		t.Fatal("secret appeared in the bytes the broker forwarded")
	}
}

// A client without the secret cannot attach.
func TestWrongSecretRejected(t *testing.T) {
	_, _, wsURL, httpURL, closeSrv := testServer(t)
	defer closeSrv()
	const channel = "private"
	secret, _ := clientcrypto.GenerateSecret()
	createChannel(t, httpURL, channel, secret)

	wrong, _ := clientcrypto.GenerateSecret()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := connectWithSecret(ctx, wsURL, channel, wrong); err == nil {
		t.Fatal("a client with the wrong secret attached to a private channel")
	}
}

// The plaintext public path refuses a name registered as a private channel.
func TestPublicPathRefusesPrivateChannel(t *testing.T) {
	_, _, wsURL, httpURL, closeSrv := testServer(t)
	defer closeSrv()
	_ = wsURL
	const channel = "locked"
	secret, _ := clientcrypto.GenerateSecret()
	createChannel(t, httpURL, channel, secret)

	resp, err := http.Get(httpURL + "/subscribe/locked")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("public subscribe to a private channel returned %d, want 403", resp.StatusCode)
	}
}

// Public plaintext topic works ntfy-style.
func TestPublicTopicPubSub(t *testing.T) {
	_, _, wsURL, httpURL, closeSrv := testServer(t)
	defer closeSrv()
	_ = wsURL

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
	time.Sleep(100 * time.Millisecond)

	pubResp, err := http.Post(httpURL+"/publish/news", "text/plain", strings.NewReader("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	pubResp.Body.Close()

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
	b, _ := json.Marshal(v)
	return b
}
