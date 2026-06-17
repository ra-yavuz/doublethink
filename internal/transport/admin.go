package transport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/ra-yavuz/doublethink/internal/pairing"
)

// AdminAPI is the loopback-only control surface the doublethink CLI uses to create
// channels and pair peers against a running server. It is bound to localhost by
// the serve command and carries no auth of its own: the trust model is "whoever
// can reach localhost on the admin port already controls this host." It MUST NOT
// be exposed off-host; the serve command documents this.
//
// Pairing is MITM-resistant (internal/pairing): an invite authorises a peer to
// PRESENT a key (rendezvous), not to be trusted. A joining peer's key is admitted
// to the channel's authorized set only after both peers confirm a matching SAS
// out-of-band, so the broker cannot silently substitute a key it controls.
type AdminAPI struct {
	reg     *Registry
	pm      *pairing.Manager
	mu      sync.Mutex
	ecdhDir map[string]map[string]string // channel -> (base64 ed25519 id -> base64 x25519 pub)
	pending map[string]pendingJoin       // SAS -> joiner awaiting confirmation
}

// Registry is the subset of *auth.Registry the admin API needs. Declared as an
// interface so the admin handler does not import auth directly in a cycle.
type Registry interface {
	Register(channel string, authorized ...ed25519.PublicKey) error
	Authorize(channel string, pub ed25519.PublicKey) error
	HasChannel(channel string) bool
}

// NewAdminAPI builds the admin handler over a registry.
func NewAdminAPI(reg *Registry) *AdminAPI {
	return &AdminAPI{reg: reg, pm: pairing.NewManager(), ecdhDir: make(map[string]map[string]string)}
}

// Handler returns the admin mux. Serve it on a loopback-only listener.
func (a *AdminAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/channel/create", a.handleCreate)
	mux.HandleFunc("/admin/invite", a.handleInvite)
	mux.HandleFunc("/admin/redeem", a.handleRedeem)
	mux.HandleFunc("/admin/confirm", a.handleConfirm)
	return mux
}

type createReq struct {
	Channel string `json:"channel"`
	// The creating (first) peer's public keys. The creator is admitted directly:
	// it is the party that owns the channel from the start, so there is no second
	// party to MITM yet. The SAS protects the SECOND peer's enrolment.
	IDPub   string `json:"id_pub"`
	ECDHPub string `json:"ecdh_pub"`
}

func (a *AdminAPI) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Channel == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	idPub, err1 := base64.StdEncoding.DecodeString(req.IDPub)
	_, err2 := base64.StdEncoding.DecodeString(req.ECDHPub)
	if err1 != nil || err2 != nil || len(idPub) != ed25519.PublicKeySize {
		http.Error(w, "bad keys", http.StatusBadRequest)
		return
	}
	if err := (*a.reg).Register(req.Channel, ed25519.PublicKey(idPub)); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.recordECDH(req.Channel, req.IDPub, req.ECDHPub)
	writeJSONResp(w, map[string]any{"channel": req.Channel, "created": true})
}

type inviteReq struct {
	Channel string `json:"channel"`
	Role    string `json:"role"`
	IDPub   string `json:"id_pub"`   // inviter's Ed25519 public key (already on the channel)
	ECDHPub string `json:"ecdh_pub"` // inviter's X25519 public key
}

// handleInvite issues a single-use, short-TTL pairing code for a second peer to
// join. The inviter must already be on the channel. The code authorises rendezvous
// only; trust is conferred later via SAS confirmation.
func (a *AdminAPI) handleInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req inviteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	idPub, err1 := base64.StdEncoding.DecodeString(req.IDPub)
	ecdhPub, err2 := base64.StdEncoding.DecodeString(req.ECDHPub)
	if req.Channel == "" || err1 != nil || err2 != nil || len(idPub) != ed25519.PublicKeySize {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !(*a.reg).HasChannel(req.Channel) {
		http.Error(w, "no such channel", http.StatusNotFound)
		return
	}
	inv, err := a.pm.Create(req.Channel, req.Role, idPub, ecdhPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	writeJSONResp(w, map[string]any{"code": inv.Code, "channel": req.Channel, "ttl_seconds": int(pairing.InviteTTL.Seconds())})
}

type redeemReq struct {
	Code    string `json:"code"`
	IDPub   string `json:"id_pub"`   // joiner's Ed25519 public key
	ECDHPub string `json:"ecdh_pub"` // joiner's X25519 public key
}

// handleRedeem consumes a pairing code and returns the SAS the joiner must compare
// with the inviter out-of-band. It does NOT yet admit the joiner's key: that waits
// for /admin/confirm after a human matches the SAS. It does return the inviter's
// X25519 public key so the joiner can derive the channel key.
func (a *AdminAPI) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req redeemReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	idPub, err1 := base64.StdEncoding.DecodeString(req.IDPub)
	ecdhPub, err2 := base64.StdEncoding.DecodeString(req.ECDHPub)
	if err1 != nil || err2 != nil || len(idPub) != ed25519.PublicKeySize {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	inv, sas, err := a.pm.Redeem(req.Code, idPub, ecdhPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Stash the joiner's keys as pending under the SAS so confirm can admit them.
	a.stashPending(sas, inv.Channel, req.IDPub, req.ECDHPub)
	// Return the inviter's ECDH key so the joiner can derive the shared key.
	a.recordECDH(inv.Channel, req.IDPub, req.ECDHPub)
	writeJSONResp(w, map[string]any{
		"channel":        inv.Channel,
		"sas":            sas,
		"inviter_ecdh":   base64.StdEncoding.EncodeToString(inv.InviterECDHKey()),
		"inviter_id_pub": base64.StdEncoding.EncodeToString(inv.InviterIDKey()),
	})
}

type confirmReq struct {
	SAS string `json:"sas"`
}

// handleConfirm admits the pending joiner's Ed25519 key to the channel's authorized
// set, but only when called with the SAS that the human confirmed matched on both
// sides. Until this is called, the joiner cannot authenticate to the channel.
func (a *AdminAPI) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req confirmReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SAS == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	channel, idPubB64, ok := a.takePending(req.SAS)
	if !ok {
		http.Error(w, "no pending pairing for that SAS", http.StatusNotFound)
		return
	}
	idPub, err := base64.StdEncoding.DecodeString(idPubB64)
	if err != nil || len(idPub) != ed25519.PublicKeySize {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := (*a.reg).Authorize(channel, ed25519.PublicKey(idPub)); err != nil {
		http.Error(w, "authorize failed", http.StatusInternalServerError)
		return
	}
	writeJSONResp(w, map[string]any{"channel": channel, "admitted": true})
}

// --- pending-joiner and ECDH directory bookkeeping ---

type pendingJoin struct {
	channel string
	idPub   string
	ecdhPub string
}

func (a *AdminAPI) stashPending(sas, channel, idPub, ecdhPub string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		a.pending = make(map[string]pendingJoin)
	}
	a.pending[sas] = pendingJoin{channel: channel, idPub: idPub, ecdhPub: ecdhPub}
}

func (a *AdminAPI) takePending(sas string) (channel, idPub string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, present := a.pending[sas]
	if !present {
		return "", "", false
	}
	delete(a.pending, sas)
	return p.channel, p.idPub, true
}

func (a *AdminAPI) recordECDH(channel, idPub, ecdhPub string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ecdhDir[channel] == nil {
		a.ecdhDir[channel] = make(map[string]string)
	}
	a.ecdhDir[channel][idPub] = ecdhPub
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
