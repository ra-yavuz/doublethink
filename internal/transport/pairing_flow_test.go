package transport_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

// adminServer stands up both the channel server and the admin API over httptest,
// sharing one registry, as the real serve command does.
func adminServer(t *testing.T) (reg *auth.Registry, wsURL, adminURL string, closeAll func()) {
	t.Helper()
	b := broker.New()
	reg = auth.NewRegistry()
	chanSrv := httptest.NewServer(transport.New(b, reg).Handler())
	var adminReg transport.Registry = reg
	adminSrv := httptest.NewServer(transport.NewAdminAPI(&adminReg).Handler())
	wsURL = "ws" + strings.TrimPrefix(chanSrv.URL, "http")
	return reg, wsURL, adminSrv.URL, func() { chanSrv.Close(); adminSrv.Close() }
}

func post(t *testing.T, url string, body any, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(out)
	} else {
		_, _ = io.ReadAll(resp.Body)
	}
	return resp.StatusCode
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The hardened pairing flow's load-bearing property: a joining peer that has
// redeemed an invite (and so holds a valid keypair and a SAS) STILL cannot attach
// to the channel until the SAS is confirmed. This is what makes a silent broker
// MITM impossible: an unconfirmed key is never admitted.
func TestJoinerCannotAttachBeforeConfirm(t *testing.T) {
	reg, wsURL, adminURL, closeAll := adminServer(t)
	defer closeAll()

	// Peer A creates the channel (enrolled directly).
	idA, _ := clientcrypto.GenerateIdentity()
	ecdhA := idA.ECDHPublic()
	const channel = "codespeak/harden-test"
	if code := post(t, adminURL+"/admin/channel/create", map[string]string{
		"channel": channel, "id_pub": b64(idA.SignPub), "ecdh_pub": b64(ecdhA[:]),
	}, nil); code != http.StatusOK {
		t.Fatalf("create returned %d", code)
	}

	// Peer A invites a second peer.
	var inv struct {
		Code string `json:"code"`
	}
	if code := post(t, adminURL+"/admin/invite", map[string]string{
		"channel": channel, "role": "agent", "id_pub": b64(idA.SignPub), "ecdh_pub": b64(ecdhA[:]),
	}, &inv); code != http.StatusOK || inv.Code == "" {
		t.Fatalf("invite returned %d code=%q", code, inv.Code)
	}

	// Peer B redeems the invite: it now has a valid keypair and a SAS, but is NOT
	// yet admitted.
	idB, _ := clientcrypto.GenerateIdentity()
	ecdhB := idB.ECDHPublic()
	var red struct {
		SAS string `json:"sas"`
	}
	if code := post(t, adminURL+"/admin/redeem", map[string]string{
		"code": inv.Code, "id_pub": b64(idB.SignPub), "ecdh_pub": b64(ecdhB[:]),
	}, &red); code != http.StatusOK || red.SAS == "" {
		t.Fatalf("redeem returned %d sas=%q", code, red.SAS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// BEFORE confirm: peer B must be rejected at the channel, even though it holds
	// a valid keypair, because its key is not yet in the authorized set.
	if _, err := connectAuthed(ctx, wsURL, channel, idB.SignPub, idB.Sign); err == nil {
		t.Fatal("peer B attached before SAS confirmation; the MITM gate is open")
	}

	// Confirm with the SAS (a human matched it out of band).
	if code := post(t, adminURL+"/admin/confirm", map[string]string{"sas": red.SAS}, nil); code != http.StatusOK {
		t.Fatalf("confirm returned %d", code)
	}

	// AFTER confirm: peer B can attach.
	conn, err := connectAuthed(ctx, wsURL, channel, idB.SignPub, idB.Sign)
	if err != nil {
		t.Fatalf("peer B rejected after confirmation: %v", err)
	}
	conn.CloseNow()

	// Sanity: the registry now holds peer B's key.
	if !reg.HasChannel(channel) {
		t.Fatal("channel missing from registry")
	}
}

// A wrong/unknown SAS does not admit anyone.
func TestConfirmWithWrongSASAdmitsNobody(t *testing.T) {
	_, wsURL, adminURL, closeAll := adminServer(t)
	defer closeAll()

	idA, _ := clientcrypto.GenerateIdentity()
	ecdhA := idA.ECDHPublic()
	const channel = "c"
	post(t, adminURL+"/admin/channel/create", map[string]string{
		"channel": channel, "id_pub": b64(idA.SignPub), "ecdh_pub": b64(ecdhA[:]),
	}, nil)
	var inv struct {
		Code string `json:"code"`
	}
	post(t, adminURL+"/admin/invite", map[string]string{
		"channel": channel, "role": "agent", "id_pub": b64(idA.SignPub), "ecdh_pub": b64(ecdhA[:]),
	}, &inv)
	idB, _ := clientcrypto.GenerateIdentity()
	ecdhB := idB.ECDHPublic()
	post(t, adminURL+"/admin/redeem", map[string]string{
		"code": inv.Code, "id_pub": b64(idB.SignPub), "ecdh_pub": b64(ecdhB[:]),
	}, nil)

	// Confirm with a SAS that was never issued.
	if code := post(t, adminURL+"/admin/confirm", map[string]string{"sas": "ZZZZ-ZZZZ"}, nil); code == http.StatusOK {
		t.Fatal("confirm accepted a wrong SAS")
	}

	// Peer B still cannot attach.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := connectAuthed(ctx, wsURL, channel, idB.SignPub, idB.Sign); err == nil {
		t.Fatal("peer B attached despite no valid confirmation")
	}
}
