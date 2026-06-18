package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// A Grant is an admin-issued capability that lets a user create ONE channel with a
// policy beyond the public defaults (e.g. permanent / uncapped). The admin issues
// it; the user redeems it when creating their channel. The admin never sees the
// channel secret: the grant authorizes POLICY, the user brings the secret.
//
// The grant is bound tightly (CODEX: the risk is overbroad authorization): a
// channel-id or a narrow prefix it applies to, the exact policy, a single-use
// ticket id (nonce), an expiry (Redis key TTL), and the issuing context. It is
// consumed in the same Lua script that creates the channel, so it cannot be
// replayed and cannot create more than one channel.
type Grant struct {
	TicketID     string // the opaque single-use ticket the user presents
	ChannelMatch string // exact channel id, or "prefix/*" for a namespace
	Retained     bool
	TTLSeconds   int64 // 0 = never expires (permanent)
	MaxBytes     int64 // 0 = uncapped
	MaxMsgs      int64 // 0 = uncapped
}

// ErrBadTicket is the uniform failure when a ticket is missing, expired, used, or
// does not authorize the requested channel.
var ErrBadTicket = errors.New("invalid, expired, or unauthorized ticket")

func ticketKey(id string) string { return "dt:ticket:" + id }

// IssueGrant stores a grant under a fresh ticket id with a Redis TTL = expirySec
// (after which it is gone, the ticket expires). Returns the ticket id.
func (s *Store) IssueGrant(g Grant, expirySec int64) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	retained := "0"
	if g.Retained {
		retained = "1"
	}
	key := ticketKey(ticket)
	if err := s.rdb.HSet(s.ctx, key,
		"match", g.ChannelMatch, "retained", retained,
		"ttl_sec", g.TTLSeconds, "max_bytes", g.MaxBytes, "max_msgs", g.MaxMsgs,
	).Err(); err != nil {
		return "", err
	}
	if expirySec > 0 {
		s.rdb.Expire(s.ctx, key, time.Duration(expirySec)*time.Second)
	}
	return ticket, nil
}

// createWithTicketLua validates+consumes a ticket and creates the channel, atomically.
// KEYS: [ticketKey, chKey, chUsageKey, chansSet]
// ARGV: [channelId, k_auth, owner]
// The channel's policy comes from the TICKET, not from the client (anti-overbroad).
// Returns: "OK", "BADTICKET", "MISMATCH", or "EXISTS".
var createWithTicketLua = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then return "BADTICKET" end
local match = redis.call("HGET", KEYS[1], "match")
local id = ARGV[1]
-- match is either an exact id or a "prefix/*" namespace
local ok = false
if match == id then ok = true
elseif string.sub(match, -2) == "/*" then
  local prefix = string.sub(match, 1, #match - 1) -- keep trailing slash
  if string.sub(id, 1, #prefix) == prefix then ok = true end
end
if not ok then return "MISMATCH" end
if redis.call("EXISTS", KEYS[2]) == 1 then return "EXISTS" end
local retained = redis.call("HGET", KEYS[1], "retained")
local ttl = redis.call("HGET", KEYS[1], "ttl_sec")
local mb = redis.call("HGET", KEYS[1], "max_bytes")
local mm = redis.call("HGET", KEYS[1], "max_msgs")
redis.call("HSET", KEYS[2],
  "owner", ARGV[3], "k_auth", ARGV[2], "retained", retained,
  "ttl_sec", ttl, "max_bytes", mb, "max_msgs", mm, "created", "0")
redis.call("HSET", KEYS[3], "bytes", 0, "msgs", 0, "next_seq", 1)
redis.call("SADD", KEYS[4], id)
redis.call("DEL", KEYS[1])  -- consume the single-use ticket
return "OK"
`)

// CreateChannelWithTicket creates a channel using a grant ticket: the channel's
// policy (retained, ttl, caps) is taken from the ticket, NOT from client input, so
// a client cannot self-assert "permanent/uncapped". The ticket is consumed
// atomically; replay is rejected. owner may be empty (the grant can be for an
// anonymous holder). Returns ErrBadTicket on any validation failure.
func (s *Store) CreateChannelWithTicket(ticket, channelID, kAuth, owner string) error {
	if ticket == "" || channelID == "" {
		return ErrBadTicket
	}
	res, err := createWithTicketLua.Run(s.ctx, s.rdb,
		[]string{ticketKey(ticket), chKey(channelID), chUsageKey(channelID), chansSet},
		channelID, kAuth, owner,
	).Result()
	if err != nil {
		return err
	}
	switch res {
	case "OK":
		return nil
	case "EXISTS":
		return ErrExists
	default: // BADTICKET, MISMATCH
		return ErrBadTicket
	}
}

// channelMatches mirrors the Lua match logic (exact id or "prefix/*" namespace),
// for tests.
func channelMatches(match, id string) bool {
	if match == id {
		return true
	}
	if strings.HasSuffix(match, "/*") {
		return strings.HasPrefix(id, match[:len(match)-1])
	}
	return false
}
