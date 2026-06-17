// Package store is doublethink's persistent state for M2 (docs/DESIGN-M2.md
// decision 2): a SQLite database (pure-Go modernc driver, no cgo, single binary)
// holding accounts, channels, retained messages, and usage counters.
//
// What it persists and what it does NOT:
//   - accounts: id + a HASH of the API key (never the key).
//   - channels: id, owner, K_auth (admission key, NOT the encryption key),
//     retention config, and optional per-channel limit overrides.
//   - messages (retained channels only): per-channel monotonic seq for catch-up,
//     expiry, size, and the CIPHERTEXT blob (the broker cannot read it).
//   - usage counters per channel and per account for quota enforcement.
//
// It never holds a channel's shared secret S or the encryption key. Retained
// ciphertext is user data: it expires (TTL), can be deleted, and counts to quota.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// nowUnix is the clock (seconds), injectable for tests.
var nowUnix = func() int64 { return time.Now().Unix() }

// Errors surfaced to callers.
var (
	ErrNotFound    = errors.New("not found")
	ErrExists      = errors.New("already exists")
	ErrQuotaChan   = errors.New("channel storage quota exceeded")
	ErrQuotaAcct   = errors.New("account storage quota exceeded")
	ErrTooManyChan = errors.New("account channel limit reached")
)

// Open opens (and migrates the schema of) the SQLite database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	// SQLite + a single connection avoids "database is locked" under the WAL
	// concurrency we have (one broker process). Keep it simple and correct.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id            TEXT PRIMARY KEY,
  api_key_hash  TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
  id                 TEXT PRIMARY KEY,
  owner_account_id   TEXT,
  k_auth             TEXT NOT NULL,
  retained           INTEGER NOT NULL DEFAULT 0,
  retention_ttl_sec  INTEGER NOT NULL DEFAULT 0,
  max_bytes          INTEGER NOT NULL DEFAULT 0,
  max_msgs           INTEGER NOT NULL DEFAULT 0,
  created_at         INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  channel_id      TEXT NOT NULL,
  seq             INTEGER NOT NULL,
  msg_id          TEXT,
  type            TEXT,
  ts              TEXT,
  expires_at      INTEGER NOT NULL,
  size_bytes      INTEGER NOT NULL,
  ciphertext_blob BLOB NOT NULL,
  PRIMARY KEY (channel_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(expires_at);
CREATE TABLE IF NOT EXISTS channel_usage (
  channel_id TEXT PRIMARY KEY,
  bytes      INTEGER NOT NULL DEFAULT 0,
  msgs       INTEGER NOT NULL DEFAULT 0,
  next_seq   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS account_usage (
  account_id TEXT PRIMARY KEY,
  bytes      INTEGER NOT NULL DEFAULT 0,
  channels   INTEGER NOT NULL DEFAULT 0
);
`
	_, err := s.db.Exec(schema)
	return err
}

// --- accounts ---

// CreateAccount inserts an account with the given id and api-key hash.
func (s *Store) CreateAccount(id, keyHash string) error {
	_, err := s.db.Exec(`INSERT INTO accounts(id, api_key_hash, created_at) VALUES(?,?,?)`,
		id, keyHash, nowUnix())
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO account_usage(account_id) VALUES(?)`, id)
	return nil
}

// AccountKeyHash returns the stored api-key hash for an account, or ErrNotFound.
func (s *Store) AccountKeyHash(id string) (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT api_key_hash FROM accounts WHERE id=?`, id).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// Channel is the stored config of a channel.
type Channel struct {
	ID         string
	OwnerID    string // empty for grandfathered legacy channels
	KAuth      string
	Retained   bool
	TTLSeconds int64
	MaxBytes   int64
	MaxMsgs    int64
}

// CreateChannel inserts a channel. For a retained channel with an owner, it
// enforces the per-account channel-count cap transactionally. Returns ErrExists if
// the id is taken, ErrTooManyChan if the owner is at its channel cap.
func (s *Store) CreateChannel(c Channel, channelsPerAccountCap int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var dummy string
	err = tx.QueryRow(`SELECT id FROM channels WHERE id=?`, c.ID).Scan(&dummy)
	if err == nil {
		return ErrExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if c.OwnerID != "" {
		var n int
		_ = tx.QueryRow(`SELECT channels FROM account_usage WHERE account_id=?`, c.OwnerID).Scan(&n)
		if n >= channelsPerAccountCap {
			return ErrTooManyChan
		}
	}

	retained := 0
	if c.Retained {
		retained = 1
	}
	_, err = tx.Exec(`INSERT INTO channels(id, owner_account_id, k_auth, retained, retention_ttl_sec, max_bytes, max_msgs, created_at)
	                  VALUES(?,?,?,?,?,?,?,?)`,
		c.ID, nullIfEmpty(c.OwnerID), c.KAuth, retained, c.TTLSeconds, c.MaxBytes, c.MaxMsgs, nowUnix())
	if err != nil {
		return fmt.Errorf("insert channel: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO channel_usage(channel_id) VALUES(?)`, c.ID); err != nil {
		return err
	}
	if c.OwnerID != "" {
		if _, err := tx.Exec(`UPDATE account_usage SET channels = channels + 1 WHERE account_id=?`, c.OwnerID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetChannel returns a channel's config, or ErrNotFound.
func (s *Store) GetChannel(id string) (Channel, error) {
	var c Channel
	var owner sql.NullString
	var retained int
	err := s.db.QueryRow(`SELECT id, owner_account_id, k_auth, retained, retention_ttl_sec, max_bytes, max_msgs
	                      FROM channels WHERE id=?`, id).
		Scan(&c.ID, &owner, &c.KAuth, &retained, &c.TTLSeconds, &c.MaxBytes, &c.MaxMsgs)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.OwnerID = owner.String
	c.Retained = retained == 1
	return c, nil
}

// HasChannel reports whether a channel id is registered.
func (s *Store) HasChannel(id string) bool {
	var x string
	err := s.db.QueryRow(`SELECT id FROM channels WHERE id=?`, id).Scan(&x)
	return err == nil
}

// SetChannelLimits overrides a channel's retention limits (admin path). Only
// non-negative values are applied; pass -1 to leave a field unchanged.
func (s *Store) SetChannelLimits(id string, ttlSec, maxBytes, maxMsgs int64) error {
	c, err := s.GetChannel(id)
	if err != nil {
		return err
	}
	if ttlSec >= 0 {
		c.TTLSeconds = ttlSec
	}
	if maxBytes >= 0 {
		c.MaxBytes = maxBytes
	}
	if maxMsgs >= 0 {
		c.MaxMsgs = maxMsgs
	}
	_, err = s.db.Exec(`UPDATE channels SET retention_ttl_sec=?, max_bytes=?, max_msgs=? WHERE id=?`,
		c.TTLSeconds, c.MaxBytes, c.MaxMsgs, id)
	return err
}

// --- messages / retention ---

// StoredMessage is a retained message as returned by catch-up.
type StoredMessage struct {
	Seq        int64
	Ciphertext []byte
}

// Append stores one message on a retained channel and enforces quota
// transactionally: it assigns the next per-channel seq, inserts the blob, updates
// usage, evicts oldest messages past the channel's max_msgs / max_bytes (ring
// buffer), and rejects if the account storage cap would be exceeded.
// blob is the opaque ciphertext payload. Returns the assigned seq.
func (s *Store) Append(channelID string, msgID, msgType, ts string, blob []byte, acctBytesCap int64) (int64, error) {
	c, err := s.GetChannel(channelID)
	if err != nil {
		return 0, err
	}
	if !c.Retained {
		return 0, errors.New("channel is not retained")
	}
	size := int64(len(blob))

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Account storage cap (only meaningful for owned channels).
	if c.OwnerID != "" && acctBytesCap > 0 {
		var acctBytes int64
		_ = tx.QueryRow(`SELECT bytes FROM account_usage WHERE account_id=?`, c.OwnerID).Scan(&acctBytes)
		if acctBytes+size > acctBytesCap {
			return 0, ErrQuotaAcct
		}
	}

	// Assign seq.
	var seq int64
	if err := tx.QueryRow(`SELECT next_seq FROM channel_usage WHERE channel_id=?`, channelID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("next_seq: %w", err)
	}
	expires := int64(0)
	if c.TTLSeconds > 0 {
		expires = nowUnix() + c.TTLSeconds
	} else {
		expires = nowUnix() + 1<<31 // effectively no TTL
	}
	if _, err := tx.Exec(`INSERT INTO messages(channel_id, seq, msg_id, type, ts, expires_at, size_bytes, ciphertext_blob)
	                      VALUES(?,?,?,?,?,?,?,?)`,
		channelID, seq, msgID, msgType, ts, expires, size, blob); err != nil {
		return 0, fmt.Errorf("insert message: %w", err)
	}
	if _, err := tx.Exec(`UPDATE channel_usage SET bytes=bytes+?, msgs=msgs+1, next_seq=next_seq+1 WHERE channel_id=?`,
		size, channelID); err != nil {
		return 0, err
	}
	if c.OwnerID != "" {
		if _, err := tx.Exec(`UPDATE account_usage SET bytes=bytes+? WHERE account_id=?`, size, c.OwnerID); err != nil {
			return 0, err
		}
	}

	// Evict oldest past the ring-buffer caps (max_msgs, max_bytes).
	if err := evictLocked(tx, channelID, c.OwnerID, c.MaxMsgs, c.MaxBytes); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

// evictLocked drops oldest messages until the channel is within max_msgs and
// max_bytes, decrementing usage. Runs inside the Append transaction.
func evictLocked(tx *sql.Tx, channelID, ownerID string, maxMsgs, maxBytes int64) error {
	for {
		var bytes, msgs int64
		if err := tx.QueryRow(`SELECT bytes, msgs FROM channel_usage WHERE channel_id=?`, channelID).Scan(&bytes, &msgs); err != nil {
			return err
		}
		over := (maxMsgs > 0 && msgs > maxMsgs) || (maxBytes > 0 && bytes > maxBytes)
		if !over {
			return nil
		}
		// Find the oldest message (lowest seq).
		var seq, size int64
		err := tx.QueryRow(`SELECT seq, size_bytes FROM messages WHERE channel_id=? ORDER BY seq ASC LIMIT 1`, channelID).Scan(&seq, &size)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // nothing left to evict
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM messages WHERE channel_id=? AND seq=?`, channelID, seq); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE channel_usage SET bytes=bytes-?, msgs=msgs-1 WHERE channel_id=?`, size, channelID); err != nil {
			return err
		}
		if ownerID != "" {
			if _, err := tx.Exec(`UPDATE account_usage SET bytes=bytes-? WHERE account_id=?`, size, ownerID); err != nil {
				return err
			}
		}
	}
}

// CatchUp returns retained messages on a channel with seq strictly greater than
// `afterSeq`, in order, up to `limit`. This is how a reconnecting subscriber
// replays what it missed; it tracks the last seq it has seen.
func (s *Store) CatchUp(channelID string, afterSeq int64, limit int) ([]StoredMessage, error) {
	rows, err := s.db.Query(`SELECT seq, ciphertext_blob FROM messages
	                         WHERE channel_id=? AND seq>? AND expires_at>?
	                         ORDER BY seq ASC LIMIT ?`,
		channelID, afterSeq, nowUnix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredMessage
	for rows.Next() {
		var m StoredMessage
		if err := rows.Scan(&m.Seq, &m.Ciphertext); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PruneExpired deletes all messages past their TTL across all channels and fixes
// usage counters. Called by the background sweeper and opportunistically. Returns
// the number of messages pruned.
func (s *Store) PruneExpired() (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT channel_id, seq, size_bytes FROM messages WHERE expires_at<=?`, nowUnix())
	if err != nil {
		return 0, err
	}
	type victim struct {
		ch   string
		seq  int64
		size int64
	}
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.ch, &v.seq, &v.size); err != nil {
			rows.Close()
			return 0, err
		}
		victims = append(victims, v)
	}
	rows.Close()

	for _, v := range victims {
		if _, err := tx.Exec(`DELETE FROM messages WHERE channel_id=? AND seq=?`, v.ch, v.seq); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`UPDATE channel_usage SET bytes=bytes-?, msgs=msgs-1 WHERE channel_id=?`, v.size, v.ch); err != nil {
			return 0, err
		}
		// Decrement the owning account's bytes too.
		var owner sql.NullString
		_ = tx.QueryRow(`SELECT owner_account_id FROM channels WHERE id=?`, v.ch).Scan(&owner)
		if owner.Valid && owner.String != "" {
			if _, err := tx.Exec(`UPDATE account_usage SET bytes=bytes-? WHERE account_id=?`, v.size, owner.String); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(victims), nil
}

// ChannelUsage returns the current (bytes, msgs) for a channel.
func (s *Store) ChannelUsage(channelID string) (bytes, msgs int64, err error) {
	err = s.db.QueryRow(`SELECT bytes, msgs FROM channel_usage WHERE channel_id=?`, channelID).Scan(&bytes, &msgs)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	return
}

// AllChannelKAuth returns every channel id -> K_auth, for loading the in-memory
// auth registry at boot (so admission does not hit SQLite on every attach).
func (s *Store) AllChannelKAuth() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT id, k_auth FROM channels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, k string
		if err := rows.Scan(&id, &k); err != nil {
			return nil, err
		}
		out[id] = k
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
