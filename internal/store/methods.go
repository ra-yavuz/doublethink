package store

import (
	"errors"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// --- accounts ---

// CreateAccount inserts an account with the given id and api-key hash.
func (s *Store) CreateAccount(id, keyHash string) error {
	ok, err := s.rdb.HSetNX(s.ctx, acctKey(id), "api_key_hash", keyHash).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrExists
	}
	s.rdb.HSet(s.ctx, acctKey(id), "created", nowUnix())
	s.rdb.HSetNX(s.ctx, acctUsageKey(id), "bytes", 0)
	s.rdb.HSetNX(s.ctx, acctUsageKey(id), "channels", 0)
	return nil
}

// AccountKeyHash returns the stored api-key hash for an account, or ErrNotFound.
func (s *Store) AccountKeyHash(id string) (string, error) {
	h, err := s.rdb.HGet(s.ctx, acctKey(id), "api_key_hash").Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	return h, err
}

// --- channels ---

// createChannelLua creates a channel atomically, enforcing the per-account channel
// cap. KEYS: [chKey, chUsageKey, acctUsageKey, chansSet]
// ARGV: [id, owner, k_auth, retained, ttl_sec, max_bytes, max_msgs, created, chanCap]
// Returns: "OK", "EXISTS", or "TOOMANY".
var createChannelLua = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then return "EXISTS" end
local owner = ARGV[2]
if owner ~= "" then
  local n = tonumber(redis.call("HGET", KEYS[3], "channels") or "0")
  if n >= tonumber(ARGV[9]) then return "TOOMANY" end
end
redis.call("HSET", KEYS[1],
  "owner", owner, "k_auth", ARGV[3], "retained", ARGV[4],
  "ttl_sec", ARGV[5], "max_bytes", ARGV[6], "max_msgs", ARGV[7], "created", ARGV[8])
redis.call("HSET", KEYS[2], "bytes", 0, "msgs", 0, "next_seq", 1)
redis.call("SADD", KEYS[4], ARGV[1])
if owner ~= "" then redis.call("HINCRBY", KEYS[3], "channels", 1) end
return "OK"
`)

// CreateChannel inserts a channel, enforcing the per-account channel cap
// transactionally. chanCap <= 0 disables the cap (used for anonymous/ephemeral).
func (s *Store) CreateChannel(c Channel, channelsPerAccountCap int) error {
	if channelsPerAccountCap <= 0 {
		channelsPerAccountCap = 1 << 30
	}
	retained := "0"
	if c.Retained {
		retained = "1"
	}
	res, err := createChannelLua.Run(s.ctx, s.rdb,
		[]string{chKey(c.ID), chUsageKey(c.ID), acctUsageKey(c.OwnerID), chansSet},
		c.ID, c.OwnerID, c.KAuth, retained,
		c.TTLSeconds, c.MaxBytes, c.MaxMsgs, nowUnix(), channelsPerAccountCap,
	).Result()
	if err != nil {
		return err
	}
	switch res {
	case "EXISTS":
		return ErrExists
	case "TOOMANY":
		return ErrTooManyChan
	}
	return nil
}

// GetChannel returns a channel's config, or ErrNotFound.
func (s *Store) GetChannel(id string) (Channel, error) {
	m, err := s.rdb.HGetAll(s.ctx, chKey(id)).Result()
	if err != nil {
		return Channel{}, err
	}
	if len(m) == 0 {
		return Channel{}, ErrNotFound
	}
	atoi := func(k string) int64 { n, _ := strconv.ParseInt(m[k], 10, 64); return n }
	return Channel{
		ID:         id,
		OwnerID:    m["owner"],
		KAuth:      m["k_auth"],
		Retained:   m["retained"] == "1",
		TTLSeconds: atoi("ttl_sec"),
		MaxBytes:   atoi("max_bytes"),
		MaxMsgs:    atoi("max_msgs"),
	}, nil
}

// HasChannel reports whether a channel id is registered.
func (s *Store) HasChannel(id string) bool {
	n, _ := s.rdb.Exists(s.ctx, chKey(id)).Result()
	return n > 0
}

// SetChannelLimits overrides a channel's retention limits (admin path). Pass -1 to
// leave a field unchanged; 0 means "no TTL" / "uncapped".
func (s *Store) SetChannelLimits(id string, ttlSec, maxBytes, maxMsgs int64) error {
	if !s.HasChannel(id) {
		return ErrNotFound
	}
	fields := []any{}
	if ttlSec >= 0 {
		fields = append(fields, "ttl_sec", ttlSec)
	}
	if maxBytes >= 0 {
		fields = append(fields, "max_bytes", maxBytes)
	}
	if maxMsgs >= 0 {
		fields = append(fields, "max_msgs", maxMsgs)
	}
	if len(fields) == 0 {
		return nil
	}
	return s.rdb.HSet(s.ctx, chKey(id), fields...).Err()
}

// AllChannelKAuth returns every channel id -> K_auth, for loading the in-memory
// auth registry at boot.
func (s *Store) AllChannelKAuth() (map[string]string, error) {
	ids, err := s.rdb.SMembers(s.ctx, chansSet).Result()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		ka, err := s.rdb.HGet(s.ctx, chKey(id), "k_auth").Result()
		if err == nil {
			out[id] = ka
		}
	}
	return out, nil
}

// ChannelUsage returns the current (bytes, msgs) for a channel.
func (s *Store) ChannelUsage(channelID string) (bytes, msgs int64, err error) {
	m, err := s.rdb.HMGet(s.ctx, chUsageKey(channelID), "bytes", "msgs").Result()
	if err != nil {
		return 0, 0, err
	}
	if m[0] == nil {
		return 0, 0, ErrNotFound
	}
	parse := func(v any) int64 {
		if s, ok := v.(string); ok {
			n, _ := strconv.ParseInt(s, 10, 64)
			return n
		}
		return 0
	}
	return parse(m[0]), parse(m[1]), nil
}
