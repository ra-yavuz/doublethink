package transport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
)

// AdminAPI is the loopback-only control surface the doublethink CLI uses to
// create channels and pair peers against a running server. It is bound to
// localhost by the serve command and carries no auth of its own: the trust model
// is "whoever can reach localhost on the admin port already controls this host."
// This is the same pragmatic model ntfy's CLI uses against its local server, and
// it is documented as such. It MUST NOT be exposed off-host.
//
// The admin API also acts as the pairing rendezvous: it relays peers' X25519
// public keys (which are public by definition) so a second peer can derive the
// shared channel key. Private keys never reach the server.
type AdminAPI struct {
	reg *Registry
	mu  sync.Mutex
	// ecdhDir maps channel id -> (base64 ed25519 id key -> base64 x25519 pub key),
	// the pairing directory of peers' public ECDH keys for rendezvous.
	ecdhDir map[string]map[string]string
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
	return &AdminAPI{reg: reg, ecdhDir: make(map[string]map[string]string)}
}

// Handler returns the admin mux. Serve it on a loopback-only listener.
func (a *AdminAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/channel/create", a.handleCreate)
	mux.HandleFunc("/admin/pair", a.handlePair)
	return mux
}

type createReq struct {
	Channel string `json:"channel"`
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
	if err := (*a.reg).Register(req.Channel); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSONResp(w, map[string]any{"channel": req.Channel, "created": true})
}

type pairReq struct {
	Channel    string `json:"channel"`
	IDPub      string `json:"id_pub"`   // base64 Ed25519 identity public key
	ECDHPub    string `json:"ecdh_pub"` // base64 X25519 public key
}

type pairResp struct {
	Channel string            `json:"channel"`
	Peers   map[string]string `json:"peers"` // id_pub -> ecdh_pub of all paired peers
}

// handlePair authorizes a peer's Ed25519 key on the channel, records its X25519
// public key in the rendezvous directory, and returns the directory so the peer
// learns the other peer's X25519 key. Creating the channel must happen first.
func (a *AdminAPI) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pairReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	idPub, err1 := base64.StdEncoding.DecodeString(req.IDPub)
	_, err2 := base64.StdEncoding.DecodeString(req.ECDHPub)
	if req.Channel == "" || err1 != nil || err2 != nil || len(idPub) != ed25519.PublicKeySize {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !(*a.reg).HasChannel(req.Channel) {
		http.Error(w, "no such channel", http.StatusNotFound)
		return
	}
	if err := (*a.reg).Authorize(req.Channel, ed25519.PublicKey(idPub)); err != nil {
		http.Error(w, "authorize failed", http.StatusInternalServerError)
		return
	}

	a.mu.Lock()
	if a.ecdhDir[req.Channel] == nil {
		a.ecdhDir[req.Channel] = make(map[string]string)
	}
	a.ecdhDir[req.Channel][req.IDPub] = req.ECDHPub
	peers := make(map[string]string, len(a.ecdhDir[req.Channel]))
	for k, v := range a.ecdhDir[req.Channel] {
		peers[k] = v
	}
	a.mu.Unlock()

	writeJSONResp(w, pairResp{Channel: req.Channel, Peers: peers})
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
