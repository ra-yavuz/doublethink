package transport_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ra-yavuz/doublethink/internal/admin"
	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/envelope"
	"github.com/ra-yavuz/doublethink/internal/limits"
	"github.com/ra-yavuz/doublethink/internal/store"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

const adminKey = "test-admin-key-with-enough-entropy-xxxxx"

// startTestRedis boots a throwaway redis-server on a unix socket and returns a
// connected store. Skips if redis-server is absent.
func startTestRedis(t *testing.T) *store.Store {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not on PATH; skipping Redis-backed transport tests")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "r.sock")
	cmd := exec.Command(bin, "--port", "0", "--unixsocket", sock, "--save", "", "--appendonly", "no", "--dir", dir)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	var st *store.Store
	for i := 0; i < 100; i++ {
		st, err = store.Open("unix://" + sock)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st == nil {
		t.Fatalf("connect redis: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func retentionServer(t *testing.T) (httpURL, wsURL string, st *store.Store, closeFn func()) {
	t.Helper()
	st = startTestRedis(t)
	ad, _ := admin.From(adminKey)
	srv := httptest.NewServer(transport.NewWithConfig(transport.Config{
		Broker: broker.New(), Reg: auth.NewRegistry(), Store: st, Admin: ad, Limits: limits.DefaultLimits(),
	}).Handler())
	t.Cleanup(func() { srv.Close() })
	return srv.URL, "ws" + strings.TrimPrefix(srv.URL, "http"), st, srv.Close
}

func makeAccount(t *testing.T, httpURL string) (id, key string) {
	t.Helper()
	resp, err := http.Post(httpURL+"/account", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("account create status %d", resp.StatusCode)
	}
	var m map[string]string
	json.NewDecoder(resp.Body).Decode(&m)
	return m["account"], m["api_key"]
}

func createRetained(t *testing.T, httpURL, channel, secret, acctID, key string) {
	t.Helper()
	ka, _ := clientcrypto.RegistrationKey(secret)
	body, _ := json.Marshal(map[string]any{"channel": channel, "auth_key": ka, "retain": true})
	req, _ := http.NewRequest("POST", httpURL+"/channel", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Doublethink-Account", acctID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io_ReadAll(resp)
		t.Fatalf("create retained status %d: %s", resp.StatusCode, b)
	}
}

func io_ReadAll(resp *http.Response) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// attach connects, completes the secret challenge with an optional catch-up cursor,
// and returns the open conn.
func attach(t *testing.T, ctx context.Context, wsURL, channel, secret string, afterSeq int64) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, wsURL+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := json.Marshal(map[string]any{"channel": channel, "after_seq": afterSeq})
	c.Write(ctx, websocket.MessageText, hs)
	_, chData, _ := c.Read(ctx)
	var ch struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(chData, &ch)
	nonce, _ := base64.StdEncoding.DecodeString(ch.Challenge)
	resp, _ := clientcrypto.ChallengeResponse(secret, nonce)
	am, _ := json.Marshal(map[string]string{"response": base64.StdEncoding.EncodeToString(resp)})
	c.Write(ctx, websocket.MessageText, am)
	_, res, _ := c.Read(ctx)
	var rr struct {
		OK bool `json:"ok"`
	}
	json.Unmarshal(res, &rr)
	if !rr.OK {
		c.CloseNow()
		t.Fatal("attach not authorized")
	}
	return c
}

// Retained channel: a party publishes while the peer is offline; the peer
// reconnects with a catch-up cursor and receives exactly what it missed.
func TestRetainedCatchUp(t *testing.T) {
	httpURL, wsURL, _, _ := retentionServer(t)
	acctID, key := makeAccount(t, httpURL)
	const channel = "codespeak/retained-1"
	secret, _ := clientcrypto.GenerateSecret()
	createRetained(t, httpURL, channel, secret, acctID, key)

	sa, _ := clientcrypto.NewSession(secret, clientcrypto.RoleA)
	sb, _ := clientcrypto.NewSession(secret, clientcrypto.RoleB)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Party A connects and publishes 3 messages while B is OFFLINE.
	a := attach(t, ctx, wsURL, channel, secret, 0)
	for i := 0; i < 3; i++ {
		sealed, _ := sa.Seal([]byte("msg" + string(rune('0'+i))))
		env := &envelope.Envelope{Channel: channel, Type: envelope.TypeProgress, ID: "x",
			Payload: mustJSON(base64.StdEncoding.EncodeToString(sealed)), TS: time.Now().UTC().Format(time.RFC3339)}
		raw, _ := env.Encode()
		a.Write(ctx, websocket.MessageText, raw)
	}
	time.Sleep(300 * time.Millisecond) // let persistence settle
	a.CloseNow()

	// Party B connects fresh (after_seq 0) and must receive the 3 retained messages.
	b := attach(t, ctx, wsURL, channel, secret, 0)
	defer b.CloseNow()
	got := 0
	for got < 3 {
		rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
		_, data, err := b.Read(rctx)
		rcancel()
		if err != nil {
			t.Fatalf("catch-up read %d failed: %v", got, err)
		}
		ge, err := envelope.Decode(data)
		if err != nil {
			continue
		}
		var b64 string
		json.Unmarshal(ge.Payload, &b64)
		blob, _ := base64.StdEncoding.DecodeString(b64)
		if _, err := sb.Open(blob); err != nil {
			t.Fatalf("B could not decrypt caught-up msg %d: %v", got, err)
		}
		got++
	}
}

// Anonymous (no account) cannot create a retained channel.
func TestAnonymousCannotRetain(t *testing.T) {
	httpURL, _, _, _ := retentionServer(t)
	secret, _ := clientcrypto.GenerateSecret()
	ka, _ := clientcrypto.RegistrationKey(secret)
	body, _ := json.Marshal(map[string]any{"channel": "x", "auth_key": ka, "retain": true})
	resp, err := http.Post(httpURL+"/channel", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous retained create = %d, want 401", resp.StatusCode)
	}
}

// Admin can override a channel's limits; a non-admin cannot.
func TestAdminLimitOverride(t *testing.T) {
	httpURL, _, st, _ := retentionServer(t)
	acctID, key := makeAccount(t, httpURL)
	const channel = "codespeak/adminc"
	secret, _ := clientcrypto.GenerateSecret()
	createRetained(t, httpURL, channel, secret, acctID, key)

	// Non-admin (wrong key) is rejected.
	body, _ := json.Marshal(map[string]any{"channel": channel, "ttl_sec": 999999, "max_bytes": -1, "max_msgs": 50})
	req, _ := http.NewRequest("POST", httpURL+"/admin/limit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-key")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin override = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Admin succeeds and the override lands in the store.
	req2, _ := http.NewRequest("POST", httpURL+"/admin/limit", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+adminKey)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != 200 {
		t.Fatalf("admin override = %d, want 200", resp2.StatusCode)
	}
	resp2.Body.Close()
	ch, _ := st.GetChannel(channel)
	if ch.MaxMsgs != 50 {
		t.Fatalf("override max_msgs = %d, want 50", ch.MaxMsgs)
	}
}

// With no store (legacy server), retained create returns not-implemented and admin
// endpoint is 404 (no admin surface).
func TestLegacyServerNoRetention(t *testing.T) {
	srv := httptest.NewServer(transport.New(broker.New(), auth.NewRegistry()).Handler())
	defer srv.Close()
	secret, _ := clientcrypto.GenerateSecret()
	ka, _ := clientcrypto.RegistrationKey(secret)
	body, _ := json.Marshal(map[string]any{"channel": "x", "auth_key": ka, "retain": true})
	resp, _ := http.Post(srv.URL+"/channel", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("retained create on legacy server = %d, want 501", resp.StatusCode)
	}
	resp.Body.Close()
	r2, _ := http.Post(srv.URL+"/admin/limit", "application/json", strings.NewReader("{}"))
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("admin endpoint on legacy server = %d, want 404", r2.StatusCode)
	}
	r2.Body.Close()
}
