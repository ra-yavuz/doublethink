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
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
	"github.com/ra-yavuz/doublethink/internal/envelope"
)

// Server ties the broker and the auth registry to HTTP handlers.
type Server struct {
	broker *broker.Broker
	reg    *auth.Registry
	mux    *http.ServeMux
}

// New builds a Server with its routes registered.
func New(b *broker.Broker, reg *auth.Registry) *Server {
	s := &Server{broker: b, reg: reg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/channel", s.handleCreateChannel)
	s.mux.HandleFunc("/ws", s.handleWS)
	s.mux.HandleFunc("/publish/", s.handlePublicPublish)
	s.mux.HandleFunc("/subscribe/", s.handlePublicSubscribe)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return s
}

// Handler returns the HTTP handler for serving (so the caller owns the
// http.Server, TLS config, and listen address).
func (s *Server) Handler() http.Handler { return s.mux }

const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
)

// --- self-service private-channel creation ---

type createChannelReq struct {
	Channel string `json:"channel"`  // the channel id (client-chosen, ideally high-entropy)
	AuthKey string `json:"auth_key"` // base32 K_auth, derived client-side from S
}

// handleCreateChannel registers a private channel. The client sends the channel id
// and K_auth (NOT the secret S, NOT the encryption key). No operator, no pairing
// ceremony: one request and the channel exists, locked to holders of S.
func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	if err := s.reg.Register(req.Channel, authKey); err != nil {
		// Channel already exists: do not reveal it as a distinct, probeable state
		// beyond the conflict status the creator needs.
		http.Error(w, "channel already exists", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"channel": req.Channel, "created": true})
}

// --- WebSocket: private channels ---

// wsHandshake is the first frame a client sends: the channel it wants to attach to.
// The broker replies with a random challenge; the client returns wsAuth with the
// response only a holder of the channel secret can compute. Pub/sub begins only
// after a successful verify.
type wsHandshake struct {
	Channel string `json:"channel"`
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
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept already wrote an error
	}
	// Default to an abnormal-closure status; replaced on clean exit.
	defer c.CloseNow()

	ctx := r.Context()

	channel, err := s.authenticateWS(ctx, c)
	if err != nil {
		// Honest, uniform failure. We do not say whether the channel exists.
		writeJSON(ctx, c, wsResult{OK: false, Error: "not authorized"})
		c.Close(websocket.StatusPolicyViolation, "not authorized")
		return
	}
	if err := writeJSON(ctx, c, wsResult{OK: true}); err != nil {
		return
	}

	s.pumpWS(ctx, c, channel)
}

// authenticateWS runs the shared-secret challenge/response. Returns the authorized
// channel on success, or a uniform error on any failure.
func (s *Server) authenticateWS(ctx context.Context, c *websocket.Conn) (string, error) {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	var hs wsHandshake
	if err := readJSON(hctx, c, &hs); err != nil {
		return "", err
	}

	challenge, err := auth.NewChallenge()
	if err != nil {
		return "", err
	}
	if err := writeJSON(hctx, c, wsChallenge{Challenge: base64.StdEncoding.EncodeToString(challenge)}); err != nil {
		return "", err
	}

	var a wsAuth
	if err := readJSON(hctx, c, &a); err != nil {
		return "", err
	}
	response, err := base64.StdEncoding.DecodeString(a.Response)
	if err != nil {
		return "", auth.ErrUnauthorized
	}
	if err := s.reg.Verify(hs.Channel, challenge, response); err != nil {
		return "", err
	}
	return hs.Channel, nil
}

// pumpWS runs the bidirectional loop once authenticated: it subscribes the peer to
// the channel and forwards broker deliveries to the socket, while reading the
// peer's published envelopes and fanning them out. Read and write run on separate
// goroutines so a long inbound stream never blocks an outbound control delivery.
func (s *Server) pumpWS(ctx context.Context, c *websocket.Conn, channel string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sub := s.broker.Subscribe(channel)
	defer s.broker.Unsubscribe(sub)

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
