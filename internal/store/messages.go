package store

import (
	"errors"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// appendLua appends one message atomically and enforces quotas/caps.
// KEYS: [chUsageKey, chMsgsKey, acctUsageKey]
// ARGV: [blob, size, ttl_sec, max_bytes, max_msgs, acctBytesCap, now, hasOwner]
// Returns: the assigned seq (number) on success, or "QUOTA_ACCT".
//
// Steps, all atomic:
//  1. account byte cap (if owned and cap>0): reject if it would exceed.
//  2. assign seq = next_seq; compute expires_at (0 ttl => 0 = never).
//  3. XADD the entry with explicit id "<seq>-1" so the stream id IS the seq.
//  4. bump channel usage (bytes, msgs, next_seq) and account bytes.
//  5. evict oldest entries while over max_msgs or max_bytes (each >0), decrementing
//     usage (and account bytes). Eviction reads each victim's stored size.
var appendLua = redis.NewScript(`
local size = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local maxBytes = tonumber(ARGV[4])
local maxMsgs = tonumber(ARGV[5])
local acctCap = tonumber(ARGV[6])
local now = tonumber(ARGV[7])
local hasOwner = ARGV[8] == "1"

if hasOwner and acctCap > 0 then
  local ab = tonumber(redis.call("HGET", KEYS[3], "bytes") or "0")
  if ab + size > acctCap then return "QUOTA_ACCT" end
end

local seq = tonumber(redis.call("HGET", KEYS[1], "next_seq") or "1")
local expires = 0
if ttl > 0 then expires = now + ttl end
redis.call("XADD", KEYS[2], seq .. "-1", "blob", ARGV[1], "exp", expires, "size", size)
redis.call("HINCRBY", KEYS[1], "bytes", size)
redis.call("HINCRBY", KEYS[1], "msgs", 1)
redis.call("HINCRBY", KEYS[1], "next_seq", 1)
if hasOwner then redis.call("HINCRBY", KEYS[3], "bytes", size) end

-- evict oldest while over caps
while true do
  local b = tonumber(redis.call("HGET", KEYS[1], "bytes") or "0")
  local m = tonumber(redis.call("HGET", KEYS[1], "msgs") or "0")
  local over = (maxMsgs > 0 and m > maxMsgs) or (maxBytes > 0 and b > maxBytes)
  if not over then break end
  local oldest = redis.call("XRANGE", KEYS[2], "-", "+", "COUNT", 1)
  if #oldest == 0 then break end
  local oid = oldest[1][1]
  local fields = oldest[1][2]
  local osize = 0
  for i = 1, #fields, 2 do if fields[i] == "size" then osize = tonumber(fields[i+1]) end end
  redis.call("XDEL", KEYS[2], oid)
  redis.call("HINCRBY", KEYS[1], "bytes", -osize)
  redis.call("HINCRBY", KEYS[1], "msgs", -1)
  if hasOwner then redis.call("HINCRBY", KEYS[3], "bytes", -osize) end
end
return seq
`)

// Append stores one message on a retained channel atomically (assign seq, enforce
// account byte cap, append, ring-buffer-evict oldest past caps). Returns the seq.
func (s *Store) Append(channelID, msgID, msgType, ts string, blob []byte, acctBytesCap int64) (int64, error) {
	c, err := s.GetChannel(channelID)
	if err != nil {
		return 0, err
	}
	if !c.Retained {
		return 0, errors.New("channel is not retained")
	}
	hasOwner := "0"
	if c.OwnerID != "" {
		hasOwner = "1"
	}
	res, err := appendLua.Run(s.ctx, s.rdb,
		[]string{chUsageKey(channelID), chMsgsKey(channelID), acctUsageKey(c.OwnerID)},
		blob, len(blob), c.TTLSeconds, c.MaxBytes, c.MaxMsgs, acctBytesCap, nowUnix(), hasOwner,
	).Result()
	if err != nil {
		return 0, err
	}
	if res == "QUOTA_ACCT" {
		return 0, ErrQuotaAcct
	}
	seq, _ := toInt64(res)
	return seq, nil
}

// CatchUp returns retained messages with seq strictly greater than afterSeq, in
// order, up to limit, skipping any past their TTL. The stream entry id is "<seq>-1",
// so we range from "(afterSeq-exclusive" upward.
func (s *Store) CatchUp(channelID string, afterSeq int64, limit int) ([]StoredMessage, error) {
	start := "(" + strconv.FormatInt(afterSeq, 10) + "-1" // exclusive of afterSeq's entry
	entries, err := s.rdb.XRangeN(s.ctx, chMsgsKey(channelID), start, "+", int64(limit)).Result()
	if err != nil {
		return nil, err
	}
	now := nowUnix()
	out := make([]StoredMessage, 0, len(entries))
	for _, e := range entries {
		exp, _ := strconv.ParseInt(asString(e.Values["exp"]), 10, 64)
		if exp > 0 && exp <= now {
			continue // expired but not yet swept
		}
		seq, _ := strconv.ParseInt(strings.SplitN(e.ID, "-", 2)[0], 10, 64)
		out = append(out, StoredMessage{Seq: seq, Ciphertext: []byte(asString(e.Values["blob"]))})
	}
	return out, nil
}

// PruneExpired deletes messages past their TTL across all channels and fixes usage
// counters. Returns the number pruned. Never-expire entries (exp == 0) are skipped.
func (s *Store) PruneExpired() (int, error) {
	ids, err := s.rdb.SMembers(s.ctx, chansSet).Result()
	if err != nil {
		return 0, err
	}
	now := nowUnix()
	pruned := 0
	for _, id := range ids {
		entries, err := s.rdb.XRange(s.ctx, chMsgsKey(id), "-", "+").Result()
		if err != nil {
			continue
		}
		for _, e := range entries {
			exp, _ := strconv.ParseInt(asString(e.Values["exp"]), 10, 64)
			if exp == 0 || exp > now {
				continue
			}
			size, _ := strconv.ParseInt(asString(e.Values["size"]), 10, 64)
			n, _ := s.rdb.XDel(s.ctx, chMsgsKey(id), e.ID).Result()
			if n == 0 {
				continue
			}
			s.rdb.HIncrBy(s.ctx, chUsageKey(id), "bytes", -size)
			s.rdb.HIncrBy(s.ctx, chUsageKey(id), "msgs", -1)
			if owner, _ := s.rdb.HGet(s.ctx, chKey(id), "owner").Result(); owner != "" {
				s.rdb.HIncrBy(s.ctx, acctUsageKey(owner), "bytes", -size)
			}
			pruned++
		}
	}
	return pruned, nil
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
