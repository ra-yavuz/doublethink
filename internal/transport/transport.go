// Package transport exposes the broker over the network. Everything is on ONE
// public surface (no separate admin port); a private channel is gated by a shared
// secret, not by who can reach an endpoint:
//
//   - Create a private channel: POST /channel with the channel id and K_auth (the
//     client derived both from the shared secret S; S itself is never sent). This
//     is self-service and needs no operator. Anyone can create a channel, exactly
//     like picking an ntfy topic, but a private channel is useless to anyone who
//     does not hold S.
//   - Use a private channel over WebSocket (/ws): the client names the channel and
//     answers a challenge with a response only a holder of S can compute. Payloads
//     are end-to-end encrypted client-side; the broker only ever sees ciphertext.
//   - Public plaintext topics, ntfy-style: POST /publish/<topic>, GET
//     /subscribe/<topic> (SSE). Opt-in, no secret, fully open like ntfy.
//
// The easy path is the secure path: creating a private channel takes one request
// and yields a secret that is the real gate; the public plaintext endpoints refuse
// any name that is a registered private channel, so a private channel can never be
// reached through the open path.
package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/ra-yavuz/doublethink/internal/account"
	"github.com/ra-yavuz/doublethink/internal/admin"
	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/envelope"
	"github.com/ra-yavuz/doublethink/internal/limits"
	"github.com/ra-yavuz/doublethink/internal/store"
)

// Server ties the broker, the in-memory auth registry, the persistent store, the
// rate limiters, and the admin layer to HTTP handlers.
type Server struct {
	broker  *broker.Broker
	reg     *auth.Registry
	store   *store.Store // may be nil in the legacy/test constructor (no retention)
	admin   *admin.Admin
	lim     limits.Defaults
	allowed []string // CORS / WS allow-list of browser origins (never "*")
	mux     *http.ServeMux

	createLim *limits.RateLimiter // channel creation per IP
	pubChan   *limits.RateLimiter // publish per channel
	conns     *limits.ConnCounter // concurrent WS connections per IP
}

// Config wires the M2 dependencies. store/admin may be nil (then retention and
// admin are simply unavailable; the broker still serves ephemeral + public).
type Config struct {
	Broker *broker.Broker
	Reg    *auth.Registry
	Store  *store.Store
	Admin  *admin.Admin
	Limits limits.Defaults
	// AllowedOrigins RESTRICTS cross-origin access to this explicit list (CORS +
	// WebSocket). EMPTY means OPEN: any origin may call the API and open a WS. Open
	// is the default because doublethink is meant to be used cross-origin and has
	// no cookies or ambient session for a malicious origin to ride; auth is always
	// an explicit Bearer key or the in-band secret challenge. Set this only to lock
	// a private deployment to known origins.
	AllowedOrigins []string
}

// NewWithConfig builds a fully-wired Server.
func NewWithConfig(cfg Config) *Server {
	ad := cfg.Admin
	if ad == nil {
		ad, _ = admin.From("") // disabled
	}
	s := &Server{
		broker:    cfg.Broker,
		reg:       cfg.Reg,
		store:     cfg.Store,
		admin:     ad,
		lim:       cfg.Limits,
		allowed:   cfg.AllowedOrigins,
		mux:       http.NewServeMux(),
		createLim: limits.NewPerHour(cfg.Limits.CreatePerIPPerHour, 15),
		pubChan:   limits.NewPerMinute(cfg.Limits.PublishPerChanPerMin, 20),
		conns:     limits.NewConnCounter(cfg.Limits.ConnectionsPerIP),
	}
	s.mux.HandleFunc("/account", s.handleCreateAccount)
	s.mux.HandleFunc("/channel", s.handleCreateChannel)
	s.mux.HandleFunc("/ws", s.handleWS)
	s.mux.HandleFunc("/publish/", s.handlePublicPublish)
	s.mux.HandleFunc("/subscribe/", s.handlePublicSubscribe)
	s.mux.HandleFunc("/stats", s.handleStats)
	s.mux.HandleFunc("/admin/limit", s.handleAdminLimit)
	s.mux.HandleFunc("/admin/grant", s.handleAdminGrant)
	s.mux.HandleFunc("/admin/channels", s.handleAdminChannels)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return s
}

// requireAdmin checks the admin Bearer key; writes 404 (no admin surface) when
// admin is disabled, 401 on a bad key. Returns true if the caller may proceed.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.admin.Enabled() || s.store == nil {
		http.NotFound(w, r)
		return false
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !s.admin.Verify(strings.TrimSpace(key)) {
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// New is the legacy constructor (broker + in-memory auth only, no store/admin).
// Retained channels and accounts are unavailable; ephemeral private channels and
// public topics work. Kept for tests and minimal deployments.
func New(b *broker.Broker, reg *auth.Registry) *Server {
	return NewWithConfig(Config{Broker: b, Reg: reg, Limits: limits.DefaultLimits()})
}

// Handler returns the HTTP handler for serving (so the caller owns the
// http.Server, TLS config, and listen address). It wraps the mux with CORS so a
// browser on an allowed origin (the Pages demo) can call the API; with no allowed
// origins the wrapper is a passthrough (same-origin only).
func (s *Server) Handler() http.Handler {
	open := len(s.allowed) == 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			h := w.Header()
			if open {
				// Open CORS: reflect any origin. Never combined with credentials
				// (doublethink has no cookies/session), so this is safe.
				h.Set("Access-Control-Allow-Origin", "*")
			} else if s.originAllowed(origin) {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
			}
			if open || s.originAllowed(origin) {
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Doublethink-Account")
				h.Set("Access-Control-Max-Age", "600")
			}
		}
		// Preflight: answer OPTIONS here without hitting the routes.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

// originAllowed reports whether a browser Origin is on the explicit allow-list.
// Exact match only.
func (s *Server) originAllowed(origin string) bool {
	for _, a := range s.allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// wsAcceptOptions returns the WebSocket Accept options. OPEN (no allow-list) skips
// the cross-origin check entirely (InsecureSkipVerify); a restricted deployment
// pins OriginPatterns to the configured hosts.
func (s *Server) wsAcceptOptions() *websocket.AcceptOptions {
	if len(s.allowed) == 0 {
		return &websocket.AcceptOptions{InsecureSkipVerify: true} // open: any origin
	}
	hosts := make([]string, 0, len(s.allowed))
	for _, a := range s.allowed {
		if u, err := url.Parse(a); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	return &websocket.AcceptOptions{OriginPatterns: hosts}
}

const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	maxCatchUp       = 1000
)

// clientIP extracts a rate-limit key from the request: the X-Forwarded-For first
// hop if present (we sit behind primergy's nginx), else the remote address. This
// is best-effort; a determined abuser can spoof XFF, but combined with global caps
// it bounds casual abuse, which is the M2 intent.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- accounts ---

// handleCreateAccount issues a new account + API key. The key is returned ONCE; the
// broker stores only its hash. Rate-limited per IP (reuses the create limiter) to
// bound anonymous account farming.
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		http.Error(w, "accounts not available on this instance", http.StatusNotImplemented)
		return
	}
	if !s.createLim.Allow("acct:" + clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	id, err := account.NewID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	key, err := account.NewKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateAccount(id, account.HashKey(key)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// The key is shown once; the broker keeps only its hash.
	_ = json.NewEncoder(w).Encode(map[string]any{"account": id, "api_key": key})
}

// authedAccount returns the account id if the request carries a valid Bearer API
// key, or "" if none/invalid. The hash check is constant-time inside account.
func (s *Server) authedAccount(r *http.Request) string {
	if s.store == nil {
		return ""
	}
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	key := strings.TrimSpace(h[len(p):])
	if !account.LooksLikeKey(key) {
		return ""
	}
	id := r.Header.Get("X-Doublethink-Account")
	if id == "" {
		return ""
	}
	stored, err := s.store.AccountKeyHash(id)
	if err != nil {
		return ""
	}
	if !account.VerifyKey(key, stored) {
		return ""
	}
	return id
}

// --- self-service private-channel creation ---

type createChannelReq struct {
	Channel string `json:"channel"`  // the channel id (client-chosen, ideally high-entropy)
	AuthKey string `json:"auth_key"` // base32 K_auth, derived client-side from S
	Retain  bool   `json:"retain"`   // request retention (requires an account)
	TTLSec  int64  `json:"ttl_sec"`  // optional retention TTL override (capped)
	Ticket  string `json:"ticket"`   // optional admin grant ticket -> permanent/over-default channel
}

// handleCreateChannel registers a private channel. The client sends the channel id
// and K_auth (NOT the secret S, NOT the encryption key). EPHEMERAL channels are
// self-service and anonymous (rate-limited per IP). RETAINED channels require a
// valid account API key and count against that account's quota.
func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.createLim.Allow("chan:" + clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	var req createChannelReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Channel == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	authKey, err := clientcrypto.DecodeAuthKey(req.AuthKey)
	if err != nil {
		http.Error(w, "bad auth key", http.StatusBadRequest)
		return
	}

	// Grant ticket: an admin pre-authorized this channel with a policy (possibly
	// permanent / uncapped). The user brings their own secret; the policy comes
	// from the ticket, not from this request. The admin never saw the secret.
	if req.Ticket != "" {
		if s.store == nil {
			http.Error(w, "retention not available on this instance", http.StatusNotImplemented)
			return
		}
		// A ticket may belong to an account holder or be anonymous; attribute to the
		// account if one is presented, else leave unowned.
		owner := s.authedAccount(r)
		if err := s.store.CreateChannelWithTicket(req.Ticket, req.Channel, req.AuthKey, owner); err != nil {
			switch {
			case errors.Is(err, store.ErrExists):
				http.Error(w, "channel already exists", http.StatusConflict)
			case errors.Is(err, store.ErrBadTicket):
				http.Error(w, "invalid, expired, or unauthorized ticket", http.StatusForbidden)
			default:
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}
		_ = s.reg.Register(req.Channel, authKey)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"channel": req.Channel, "created": true, "retained": true, "granted": true})
		return
	}

	// Retained channels require the store AND an authenticated account. Anonymous
	// retained channels are refused (they would be an unbounded-storage hole).
	if req.Retain {
		if s.store == nil {
			http.Error(w, "retention not available on this instance", http.StatusNotImplemented)
			return
		}
		owner := s.authedAccount(r)
		if owner == "" {
			http.Error(w, "retained channels require an account (POST /account, then Authorization: Bearer + X-Doublethink-Account)", http.StatusUnauthorized)
			return
		}
		ttl := s.lim.RetentionTTL
		if req.TTLSec > 0 {
			ttl = time.Duration(req.TTLSec) * time.Second
			if ttl > s.lim.RetentionTTLMax {
				ttl = s.lim.RetentionTTLMax
			}
		}
		ch := store.Channel{
			ID: req.Channel, OwnerID: owner, KAuth: req.AuthKey, Retained: true,
			TTLSeconds: int64(ttl.Seconds()), MaxBytes: s.lim.BytesPerChannel, MaxMsgs: int64(s.lim.RetainedMsgsPerChan),
		}
		if err := s.store.CreateChannel(ch, s.lim.ChannelsPerAccount); err != nil {
			switch {
			case errors.Is(err, store.ErrExists):
				http.Error(w, "channel already exists", http.StatusConflict)
			case errors.Is(err, store.ErrTooManyChan):
				http.Error(w, "account channel limit reached", http.StatusTooManyRequests)
			default:
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}
		// Mirror into the in-memory auth registry for fast admission.
		_ = s.reg.Register(req.Channel, authKey)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"channel": req.Channel, "created": true, "retained": true})
		return
	}

	// Ephemeral channel: in-memory only, anonymous-friendly.
	if s.store != nil {
		if err := s.store.CreateChannel(store.Channel{ID: req.Channel, KAuth: req.AuthKey, Retained: false}, 1<<30); err != nil && !errors.Is(err, store.ErrExists) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if err := s.reg.Register(req.Channel, authKey); err != nil {
		http.Error(w, "channel already exists", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"channel": req.Channel, "created": true, "retained": false})
}

// --- admin: raise limits for a preferred channel ---

type adminLimitReq struct {
	Channel  string `json:"channel"`
	TTLSec   int64  `json:"ttl_sec"`   // -1 = leave unchanged
	MaxBytes int64  `json:"max_bytes"` // -1 = leave unchanged
	MaxMsgs  int64  `json:"max_msgs"`  // -1 = leave unchanged
}

// handleAdminLimit overrides a channel's retention limits. Requires the admin key.
// Disabled (404) when no admin key is configured, so there is no admin surface
// without an operator key.
func (s *Server) handleAdminLimit(w http.ResponseWriter, r *http.Request) {
	if !s.admin.Enabled() || s.store == nil {
		http.NotFound(w, r) // do not advertise an admin surface that is not configured
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !s.admin.Verify(strings.TrimSpace(key)) {
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}
	var req adminLimitReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Channel == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.SetChannelLimits(req.Channel, req.TTLSec, req.MaxBytes, req.MaxMsgs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no such channel", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"channel": req.Channel, "updated": true})
}

// --- admin: issue a grant ticket for a permanent / over-default-limit topic ---

type adminGrantReq struct {
	ChannelMatch string `json:"channel_match"` // exact id, or "prefix/*" namespace
	TTLSec       int64  `json:"ttl_sec"`       // 0 = never expires (permanent)
	MaxBytes     int64  `json:"max_bytes"`     // 0 = uncapped
	MaxMsgs      int64  `json:"max_msgs"`      // 0 = uncapped
	ExpirySec    int64  `json:"expiry_sec"`    // ticket lifetime; how long the user has to redeem it
}

// handleAdminGrant issues a single-use grant ticket. The admin specifies the POLICY
// (which channel id/prefix, what TTL/caps, including permanent/uncapped). The user
// later redeems the ticket when creating their own channel with their own secret,
// so the admin never sees the secret. Admin-key authenticated.
func (s *Server) handleAdminGrant(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req adminGrantReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.ChannelMatch == "" {
		http.Error(w, "bad request (channel_match required)", http.StatusBadRequest)
		return
	}
	expiry := req.ExpirySec
	if expiry <= 0 {
		expiry = 3600 // default: ticket valid 1 hour to be redeemed
	}
	ticket, err := s.store.IssueGrant(store.Grant{
		ChannelMatch: req.ChannelMatch, Retained: true,
		TTLSeconds: req.TTLSec, MaxBytes: req.MaxBytes, MaxMsgs: req.MaxMsgs,
	}, expiry)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ticket": ticket, "channel_match": req.ChannelMatch, "expiry_sec": expiry,
		"note": "give this ticket to the user; they create the channel with it and their own secret. Single use; expires.",
	})
}

// handleAdminChannels lists channel METADATA (never secrets or payloads). Admin-key.
func (s *Server) handleAdminChannels(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	list, err := s.store.ListChannels()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"channels": list})
}

// handleStats serves PUBLIC aggregate counters: no IPs, no per-user data, no
// channel ids. Safe for a public usage page.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "stats not available", http.StatusNotImplemented)
		return
	}
	st, err := s.store.Stats()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// --- WebSocket: private channels ---

// wsHandshake is the first frame a client sends: the channel it wants to attach to,
// and (for retained channels) the last seq it has already seen, so the broker can
// replay only what it missed. The broker replies with a random challenge; the
// client returns wsAuth with the response only a holder of the channel secret can
// compute. Pub/sub begins only after a successful verify.
type wsHandshake struct {
	Channel  string `json:"channel"`
	AfterSeq int64  `json:"after_seq,omitempty"` // catch-up cursor; 0 = from the start
}

type wsChallenge struct {
	Challenge string `json:"challenge"` // base64 random nonce
}

type wsAuth struct {
	Response string `json:"response"` // base64 challenge response derived from K_auth
}

type wsResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// Connection cap per IP (bounds concurrent WS connections from one source).
	ip := clientIP(r)
	if !s.conns.Acquire(ip) {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer s.conns.Release(ip)

	c, err := websocket.Accept(w, r, s.wsAcceptOptions())
	if err != nil {
		return // Accept already wrote an error
	}
	// Default to an abnormal-closure status; replaced on clean exit.
	defer c.CloseNow()

	ctx := r.Context()

	hs, err := s.authenticateWS(ctx, c)
	if err != nil {
		// Honest, uniform failure. We do not say whether the channel exists.
		writeJSON(ctx, c, wsResult{OK: false, Error: "not authorized"})
		c.Close(websocket.StatusPolicyViolation, "not authorized")
		return
	}
	if err := writeJSON(ctx, c, wsResult{OK: true}); err != nil {
		return
	}

	s.pumpWS(ctx, c, hs.Channel, hs.AfterSeq)
}

// authenticateWS runs the shared-secret challenge/response. Returns the validated
// handshake (channel + catch-up cursor) on success, or a uniform error on failure.
func (s *Server) authenticateWS(ctx context.Context, c *websocket.Conn) (wsHandshake, error) {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	var hs wsHandshake
	if err := readJSON(hctx, c, &hs); err != nil {
		return hs, err
	}

	challenge, err := auth.NewChallenge()
	if err != nil {
		return hs, err
	}
	if err := writeJSON(hctx, c, wsChallenge{Challenge: base64.StdEncoding.EncodeToString(challenge)}); err != nil {
		return hs, err
	}

	var a wsAuth
	if err := readJSON(hctx, c, &a); err != nil {
		return hs, err
	}
	response, err := base64.StdEncoding.DecodeString(a.Response)
	if err != nil {
		return hs, auth.ErrUnauthorized
	}
	if err := s.reg.Verify(hs.Channel, challenge, response); err != nil {
		return hs, err
	}
	return hs, nil
}

// retained reports whether a channel is a retained channel in the store.
func (s *Server) retained(channel string) bool {
	if s.store == nil {
		return false
	}
	ch, err := s.store.GetChannel(channel)
	return err == nil && ch.Retained
}

// pumpWS runs the bidirectional loop once authenticated. For a retained channel it
// first replays missed messages (seq > afterSeq) as catch-up, then streams live;
// inbound publishes on a retained channel are persisted as they pass through. Read
// and write run on separate goroutines so a long inbound stream never blocks an
// outbound control delivery.
func (s *Server) pumpWS(ctx context.Context, c *websocket.Conn, channel string, afterSeq int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	isRetained := s.retained(channel)

	sub := s.broker.Subscribe(channel)
	defer s.broker.Unsubscribe(sub)

	// Catch-up: replay what this subscriber missed, in order, before live frames.
	// Done before the live writer starts so ordering is catch-up-then-live.
	if isRetained {
		msgs, err := s.store.CatchUp(channel, afterSeq, maxCatchUp)
		if err == nil {
			for _, m := range msgs {
				wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
				werr := c.Write(wctx, websocket.MessageText, m.Ciphertext)
				wcancel()
				if werr != nil {
					return
				}
			}
		}
	}

	// Writer: broker deliveries -> socket.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sub.Closed:
				c.Close(websocket.StatusInternalError, "subscription dropped")
				cancel()
				return
			case e := <-sub.C:
				b, err := e.Encode()
				if err != nil {
					continue
				}
				wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
				err = c.Write(wctx, websocket.MessageText, b)
				wcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Reader: socket -> broker. Runs in this goroutine.
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			cancel()
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		e, err := envelope.Decode(data)
		if err != nil {
			// Reject malformed traffic honestly rather than forwarding garbage.
			s.sendError(ctx, c, "invalid envelope")
			continue
		}
		// A peer may only publish to the channel it authenticated for. This stops
		// an authenticated peer from injecting into a channel it does not own by
		// putting a different channel in the envelope.
		if e.Channel != channel {
			s.sendError(ctx, c, "channel mismatch")
			continue
		}
		// Enforce max message size and per-channel publish rate.
		if s.lim.MaxMessageBytes > 0 && int64(len(data)) > s.lim.MaxMessageBytes {
			s.sendError(ctx, c, "message too large")
			continue
		}
		if !s.pubChan.Allow(channel) {
			s.sendError(ctx, c, "rate limited")
			continue
		}
		// Persist the FULL envelope bytes for a retained channel, so a reconnecting
		// subscriber's catch-up replays the exact message (the broker stores opaque
		// ciphertext: it never reads the payload). A quota rejection drops this
		// message from retention but does not kill the live connection.
		if isRetained {
			if _, err := s.store.Append(channel, e.ID, string(e.Type), e.TS, data, s.lim.BytesPerAccount); err != nil {
				if errors.Is(err, store.ErrQuotaAcct) {
					s.sendError(ctx, c, "storage quota exceeded")
					// still deliver live below; just not retained
				}
			}
		}
		s.broker.Publish(e)
	}
}

func (s *Server) sendError(ctx context.Context, c *websocket.Conn, msg string) {
	e := &envelope.Envelope{
		Channel: "",
		Type:    envelope.TypeError,
		ID:      "",
		Payload: json.RawMessage(fmt.Sprintf("%q", msg)),
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	// Error envelopes carry a channel for routing; here we cannot, so this is a
	// best-effort direct write. Encode manually since Validate requires fields.
	b, _ := json.Marshal(e)
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	_ = c.Write(wctx, websocket.MessageText, b)
}

// --- HTTP: public plaintext topics (ntfy-style) ---

func (s *Server) handlePublicPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	topic := strings.TrimPrefix(r.URL.Path, "/publish/")
	if !s.guardPublicTopic(w, topic) {
		return
	}
	body := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
		if len(body) > 1<<20 { // 1 MiB cap on a plaintext publish
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	payload, _ := json.Marshal(string(body))
	e := &envelope.Envelope{
		Channel: topic,
		Type:    envelope.TypeRequest,
		ID:      time.Now().UTC().Format("20060102T150405.000000000"),
		Payload: payload,
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	n := s.broker.Publish(e)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"delivered": n})
}

func (s *Server) handlePublicSubscribe(w http.ResponseWriter, r *http.Request) {
	topic := strings.TrimPrefix(r.URL.Path, "/subscribe/")
	if !s.guardPublicTopic(w, topic) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sub := s.broker.Subscribe(topic)
	defer s.broker.Unsubscribe(sub)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.Closed:
			return
		case e := <-sub.C:
			b, err := e.Encode()
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// guardPublicTopic rejects empty names and, critically, refuses to serve the
// plaintext path for any name registered as a PRIVATE channel. This is the
// invariant that a private channel can never be reached through the open path.
func (s *Server) guardPublicTopic(w http.ResponseWriter, topic string) bool {
	if topic == "" {
		http.Error(w, "missing topic", http.StatusBadRequest)
		return false
	}
	if s.reg.HasChannel(topic) {
		// Uniform refusal: do not confirm the private channel exists. To the
		// plaintext caller this name is simply not available on this path.
		http.Error(w, "not authorized", http.StatusForbidden)
		return false
	}
	return true
}

// --- small JSON-over-WS helpers ---

func readJSON(ctx context.Context, c *websocket.Conn, v any) error {
	typ, data, err := c.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("expected text frame")
	}
	return json.Unmarshal(data, v)
}

func writeJSON(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, b)
}
