# doublethink: M2 Design (accounts, retention, aging, quotas, abuse control)

**Status: proposed (2026-06-17).** M2 takes doublethink from a stateless,
online-only broker to one that can retain messages for offline peers, with the
limits a public instance needs. It is downstream of [`../GOAL.md`](../GOAL.md),
[`SECURITY.md`](SECURITY.md), and [`DESIGN-M1.md`](DESIGN-M1.md) (the live M1
shared-secret model). Grounded against a second model (CODEX) on the store choice,
the identity model, the default limits, and the sequencing.

## Why M2 exists

M1 is live at `api.caleidoscode.io` and is meant to go public (CodeSpeak first,
then webrings and the general web). Two gaps make that unsafe as-is:

1. **Nothing bounds resource use.** Channel creation is anonymous and unlimited;
   there are no connection, message-size, or rate limits. A public instance like
   that is an open relay anyone can bloat.
2. **There is no retention.** M1 is at-most-once, online-only: a peer that was
   offline misses messages. Real use (a phone that backgrounds the PWA, an agent
   that reconnects) needs catch-up.

M2 adds retention, ages it out (TTL), bounds it (quotas), and gates it (abuse
controls + a lightweight account layer). The user asked for all four together.

## The contract change M2 makes (read this before building)

Retention is **not** "just storing the encrypted blobs." It changes the product
contract, and that must be stated to users:

- doublethink now owns **replay semantics, per-channel ordering, expiry
  correctness, deletion, and storage-DoS surface.** These did not exist in M1.
- End-to-end encryption hides **payloads, not traffic shape.** A retained channel
  exposes to the operator: ciphertext blob sizes, message timestamps, message
  counts, channel activity, and catch-up behaviour. The broker still cannot read
  the payloads, but it now stores user data and must treat it as such (deletion,
  expiry, abuse policy) from day one.
- Retained ciphertext is **user data.** It expires, it can be deleted, it counts
  against quota, and (if a hosted instance ever backs up) backups carry it.

This is recorded in SECURITY.md as part of M2.

---

## Decisions

### 0. Three tiers of identity

M2 has three privilege tiers, each a key the holder presents:

- **Anonymous** (no key): ephemeral non-retained channels and public plaintext
  topics only, under tight per-IP limits.
- **Account API key** (`POST /account`): create and own retained channels; usage
  and quotas attributed to the account; default limits apply.
- **Admin API key** (operator-set, see decision 6): override limits/quotas for
  preferred channels or accounts, and read operational state. Not obtainable
  through the public API; set in the broker's environment by whoever runs it.

### 1. Identity: a lightweight account + API-key layer

Per-user quotas need someone to attribute usage to, but M1 channel creation is
anonymous. M2 adds the minimum honest identity for a public broker:

- `POST /account` issues an **API key** (returned once; the broker stores only a
  hash of it).
- Creating a **retained** channel requires `Authorization: Bearer <api_key>`. The
  channel row records `owner_account_id`. Quotas key off the account; per-channel
  caps nest under the owner.
- **Anonymous use survives only for ephemeral, non-retained channels** and public
  plaintext topics, under tight per-IP limits. There are **no anonymous retained
  channels** (that would reopen the unbounded-storage hole).

This is deliberately minimal: no passwords, no email, no sessions. An API key is a
capability that attributes usage and enables revocation. It is orthogonal to the
channel secret S (which still gates channel *contents* and is never seen by the
broker); the API key gates channel *creation and ownership*.

### 2. Store: SQLite (pure-Go), replacing the JSON state file

SQLite (`modernc.org/sqlite`, pure-Go, no cgo, keeps the single-binary ntfy-ease)
over an embedded KV: it gives transactional quota enforcement, indexed TTL
pruning, aggregate usage accounting, and migrations in one file. The M1 JSON state
file is migrated into it on first boot (existing channels grandfathered with a
synthetic legacy owner).

Schema (shape; column types refined in code):

```
accounts(
  id            TEXT PRIMARY KEY,   -- random account id
  api_key_hash  TEXT NOT NULL,      -- hash of the issued key (never the key)
  created_at    INTEGER
)

channels(
  id                 TEXT PRIMARY KEY,
  owner_account_id   TEXT,          -- NULL only for grandfathered legacy channels
  k_auth             TEXT NOT NULL, -- base32 K_auth (admission; not the enc key)
  retained           INTEGER,       -- 0 = ephemeral (no storage), 1 = retained
  retention_ttl_sec  INTEGER,
  max_bytes          INTEGER,
  max_msgs           INTEGER,
  created_at         INTEGER
)

messages(
  channel_id      TEXT,
  seq             INTEGER,          -- monotonic per channel; catch-up cursor
  id              TEXT,             -- envelope id
  type            TEXT,
  ts              TEXT,
  expires_at      INTEGER,          -- created + ttl; indexed for pruning
  size_bytes      INTEGER,
  ciphertext_blob BLOB,             -- the opaque payload; broker cannot read it
  PRIMARY KEY (channel_id, seq)
)

channel_usage(channel_id TEXT PRIMARY KEY, bytes INTEGER, msgs INTEGER)
account_usage(account_id TEXT PRIMARY KEY, bytes INTEGER, channels INTEGER)
```

Catch-up for a reconnecting subscriber: `SELECT ... WHERE channel_id = ? AND
seq > ? ORDER BY seq LIMIT ?`. The subscriber tracks the last `seq` it saw.
Pruning happens **on write, on subscribe, and via a periodic background sweep**;
caps are enforced **transactionally** (a write that would exceed `max_bytes` /
`max_msgs` evicts oldest-first or is rejected, decided in code, evict-oldest for a
ring buffer feel).

### 3. Retention model

- A channel is created **ephemeral by default** (M1 behaviour: online-only, no
  storage) or **retained** (opt-in, requires an account). Ephemeral keeps the
  zero-storage, anonymous-friendly path; retained adds the catch-up store.
- A retained channel is a bounded **ring buffer**: newest messages kept up to
  `max_msgs` and `max_bytes`, oldest evicted past either, and anything past
  `retention_ttl_sec` aged out by the sweeper regardless of room.
- On subscribe to a retained channel, the broker first replays `seq > cursor`
  (the catch-up), then streams live. Ordering is per-channel by `seq`.
- The broker stores **ciphertext only**; retention does not weaken E2E.

### 4. Abuse control (the part shippable with no schema change)

Enforced in the transport layer, independent of the store:

- **Max message size** (reject oversize publishes).
- **Connection cap per IP** (bound concurrent WS connections).
- **Channel-creation rate limit per IP** (token bucket).
- **Publish rate limit** per channel and per account (token bucket).

These protect the live instance immediately and do not depend on accounts or
SQLite; they are built first.

### 5. Default limits (public instance; all tunable via flags/config)

Conservative starting points (CODEX-suggested, expect to tune down under real
abuse):

| Limit | Default |
|---|---|
| Max message size | 256 KiB |
| Retained messages per channel | 1000 |
| Retention TTL | 24h default, 7d max |
| Storage per channel | 32 MiB |
| Storage per account | 256 MiB |
| Channels per account | 100 |
| Channel creation per IP | 10/hour, burst 3/min |
| Connections per IP | 20 |
| Publish per channel | 60/min, burst 20 |
| Publish per account | 600/min |

These are the DEFAULTS. The operator can raise them for specific channels or
accounts via the admin API (decision 6); the per-channel/per-account override is
stored alongside the channel/account row and takes precedence over the default.

### 6. Admin API key (operator privilege, set via environment)

The operator gets a privileged key, read from the environment
(`DOUBLETHINK_ADMIN_KEY`), never issued through the public API. It enables a small
set of admin-only endpoints, authenticated by `Authorization: Bearer <admin_key>`:

- **Raise/override limits for a preferred channel or account**: set a custom
  `max_bytes`, `max_msgs`, `retention_ttl_sec`, publish rate, or channel-count cap
  on a named channel or account. Stored as an override on that row; takes
  precedence over the table of defaults. This is the "preferred channels get
  higher limits" capability.
- **Operational reads**: list accounts/channels and their usage (metadata only;
  the admin key does NOT grant payload access, that still requires the channel
  secret S, which the broker never holds).
- (Room to grow: revoke an account key, delete a channel, but those are additive
  later, not required for the first M2.)

Fail-safe rules (load-bearing):
- If `DOUBLETHINK_ADMIN_KEY` is **unset or empty, the admin endpoints are
  DISABLED** (return 404/501), not open. No admin key = no admin surface.
- The key is compared in **constant time**; the broker stores/uses it only from
  the environment, never logs it, never returns it.
- A minimum-length/entropy check on startup; refuse to enable admin with a weak
  key (e.g. shorter than 32 chars) so a trivial key cannot be brute-forced.
- The admin key is distinct from any account key; it is operator-only.

Deployment consequence: the exone stack gains a `DOUBLETHINK_ADMIN_KEY`
environment variable (a high-entropy value, kept out of git, set in the Portainer
stack env), which requires a stack redeploy. The value is generated once and held
by the operator.

---

## Module layout (additions to M1)

```
internal/account/     account ids, API-key issue/hash/verify, per-account quota counters
internal/store/        SQLite: channels, messages (seq), usage, per-row limit overrides; catch-up query; TTL prune; JSON->sqlite migration
internal/limits/       token-bucket rate limiters + connection/size caps (transport-side); resolves effective limit = override or default
internal/admin/        admin-key verify (from env, constant-time, fail-safe-disabled); override-setting logic
internal/broker/       retained channels replay seq>cursor on subscribe; ephemeral path unchanged
internal/transport/    POST /account; auth on retained create; catch-up cursor on WS attach; limit middleware; admin endpoints (gated on admin key)
cmd/doublethink/       account create; channel create --retain [--ttl --max-msgs --max-bytes]; admin set-limit (uses admin key)
```

## Build order (one milestone, deploy once)

1. `internal/limits` + wire abuse controls into transport (size, conns/IP, create
   + publish rate). Tests.
2. `internal/account` (key issue/hash/verify, quota counters). Tests.
3. `internal/store` (SQLite schema, channel + message CRUD with monotonic seq,
   usage accounting, catch-up query, TTL prune, transactional caps, JSON
   migration). Tests (quota transactional, prune correctness, ordering).
4. Wire retention into the broker: retained-channel subscribe replays `seq >
   cursor` then goes live; ephemeral path unchanged. Tests (replay + order + no
   replay for ephemeral).
5. TTL background sweeper. Test (expired pruned).
6. Quota enforcement on publish + create (reject/evict per policy). Tests.
7. `internal/admin` + admin endpoints + CLI: admin-key verify (env, constant-time,
   disabled when unset), per-channel/per-account limit overrides, operational
   reads. `limits` resolves effective = override-or-default. Tests (admin disabled
   without key; weak key refused; override raises the effective limit; admin key
   does NOT grant payload access).
8. Transport endpoints + CLI (`account create`, `channel create --retain`,
   `admin set-limit`). Tests.
9. Docs: SECURITY.md (retention + metadata + deletion + the three identity tiers),
   README, index.html. CI.
10. Deploy: migrate exone stack (SQLite in the `/data` volume), set
    `DOUBLETHINK_ADMIN_KEY` in the stack env, grandfather existing channels, tag
    v0.3.0, re-push source, restart, verify live.

## Testing (the security/correctness rules, not just happy path)

- Anonymous client CANNOT create a retained channel (only ephemeral).
- API key required + verified for retained create; bad/missing key rejected.
- Quota: a publish exceeding per-channel `max_bytes`/`max_msgs` evicts oldest (or
  rejects) transactionally; per-account storage + channel-count caps enforced.
- TTL: messages past `expires_at` are gone after a sweep and not replayed.
- Catch-up: a subscriber reconnecting with cursor N receives exactly `seq > N` in
  order, then live; an ephemeral channel replays nothing.
- Rate limits: creation/publish past the bucket are rejected; connection cap per
  IP holds.
- Retention does not weaken E2E: stored blobs are ciphertext; the broker cannot
  read them (the M1 differentiator test still passes).

## Self-critique (attack before a reviewer does)

- **Biggest trap (CODEX):** treating retained ciphertext as "just blobs." It is
  user data with deletion/expiry/abuse obligations and visible traffic-shape
  metadata. The docs must say this plainly; the code must actually delete on TTL
  and on channel removal.
- **API key is a bearer secret.** Leaked key = create/own channels as that
  account (NOT read its channels, that still needs the channel secret). Store only
  a hash; support revocation; rate-limit account creation per IP too.
- **Metadata leak grows with retention.** Stored timestamps/sizes/counts are a
  richer side channel than M1's transient ones. Stated, not hidden.
- **Migration risk:** the JSON->SQLite migration runs on a live instance. It must
  be idempotent and must not drop existing channels; grandfather them and verify
  before flipping retention on.
- **Eviction policy choice** (reject newest vs evict oldest) is a real product
  decision; ring-buffer evict-oldest matches "catch up on recent" better than
  rejecting, but means a flood can push out a peer's unread backlog. Documented.
