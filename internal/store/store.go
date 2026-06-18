// Package store is doublethink's persistent state, backed by Redis. It holds
// accounts, channels (with retention policy), retained messages, and the admin
// grant tickets. It never holds a channel's shared secret S or the encryption key,
// only ciphertext blobs and the K_auth admission key.
//
// Layout in Redis:
//   - dt:ch:{id}                  hash: channel config (owner, k_auth, retained,
//                                 ttl_sec, max_bytes, max_msgs, created)
//   - dt:ch:{id}:msgs             stream: retained messages (entry id = seq)
//   - dt:ch:{id}:usage            hash: {bytes, msgs}
//   - dt:acct:{id}                hash: {api_key_hash, created}
//   - dt:acct:{id}:usage          hash: {bytes, channels}
//   - dt:chans                    set: all channel ids (for AllChannelKAuth at boot)
//   - dt:ticket:{id}              hash: a grant (see grant.go), with a Redis TTL
//
// Atomicity: the message append (assign seq, enforce account byte cap, append,
// evict oldest past msg/byte caps, update counters) runs as ONE Lua script so the
// multi-key read-modify-write is atomic. Channel-create-with-ticket likewise runs
// as one script so the ticket is consumed iff the channel is created.
//
// Never-expire / uncapped (no sentinels): ttl_sec == 0 means never expires;
// max_bytes == 0 / max_msgs == 0 mean uncapped (no eviction on that dimension).
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Errors surfaced to callers (shared by any backend).
var (
	ErrNotFound    = errors.New("not found")
	ErrExists      = errors.New("already exists")
	ErrQuotaAcct   = errors.New("account storage quota exceeded")
	ErrTooManyChan = errors.New("account channel limit reached")
)

// Channel is the stored config of a channel. TTLSeconds/MaxBytes/MaxMsgs == 0 mean
// "no TTL" / "uncapped" respectively (explicit, no sentinels).
type Channel struct {
	ID         string
	OwnerID    string // empty for anonymous-owned channels
	KAuth      string
	Retained   bool
	TTLSeconds int64
	MaxBytes   int64
	MaxMsgs    int64
}

// StoredMessage is a retained message as returned by catch-up. Seq is the stream
// sequence (monotonic per channel).
type StoredMessage struct {
	Seq        int64
	Ciphertext []byte
}

// Store is the Redis-backed store.
type Store struct {
	rdb *redis.Client
	ctx context.Context
}

// nowUnix is the clock (seconds), injectable for tests.
var nowUnix = func() int64 { return time.Now().Unix() }

// Open connects to Redis at addr and verifies the link. addr may be a TCP
// "host:port" or a "unix:///path/to.sock" unix-socket URL (used in tests).
func Open(addr string) (*Store, error) {
	opt := &redis.Options{Addr: addr}
	if strings.HasPrefix(addr, "unix://") {
		opt = &redis.Options{Network: "unix", Addr: strings.TrimPrefix(addr, "unix://")}
	}
	rdb := redis.NewClient(opt)
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, err
	}
	return &Store{rdb: rdb, ctx: ctx}, nil
}

// Close closes the Redis client.
func (s *Store) Close() error { return s.rdb.Close() }

func chKey(id string) string      { return "dt:ch:" + id }
func chMsgsKey(id string) string  { return "dt:ch:" + id + ":msgs" }
func chUsageKey(id string) string { return "dt:ch:" + id + ":usage" }
func acctKey(id string) string    { return "dt:acct:" + id }
func acctUsageKey(id string) string { return "dt:acct:" + id + ":usage" }

const chansSet = "dt:chans"
