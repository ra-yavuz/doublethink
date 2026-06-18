# doublethink: Operator and admin reference

This document is for whoever **runs** a doublethink broker. It covers the
admin API (every call), the grant/ticket flow for permanent channels, the
storage backend, and the durability guarantee (how much data a crash can lose).

Everyday client usage (creating channels, publishing, subscribing) is in the
[README](../README.md). The security model is in [`SECURITY.md`](SECURITY.md).
The legal terms a public instance should publish are in [`LEGAL.md`](LEGAL.md).

## Running the broker

doublethink is one binary plus a Redis instance:

```
doublethink serve \
    --addr 0.0.0.0:8080 \
    --redis-addr 127.0.0.1:6379
```

| Flag / env | Default | Meaning |
|---|---|---|
| `--addr` | `:8080` | listen address |
| `--redis-addr` / `DOUBLETHINK_REDIS_ADDR` | `127.0.0.1:6379` | Redis `host:port`, or `unix:///path/to.sock` |
| `DOUBLETHINK_ADMIN_KEY` | unset | admin key. **Unset = admin API fully disabled** (fail-safe) |
| `--allowed-origins` | `*` (open) | CORS allow-list. Open by default because the API is meant to be called cross-origin and uses no cookies/session; restrict if you want |

The admin key is read from the environment only, never a flag, so it does not
land in shell history or `ps`. It is never logged and is compared in constant
time. When it is unset, every `/admin/*` route returns `404` (the surface is not
advertised at all) and `requireAdmin` fails closed.

## Storage backend (Redis) and durability

Channels, retained messages, accounts, usage counters, and grant tickets live in
Redis. Messages are stored as Redis Streams (one per channel); a reconnecting
peer catches up by sequence number via `XRANGE`. There is no SQLite and no other
database; Redis is the single source of truth.

**Durability disclaimer (read this before you offer permanent channels).**
Redis is configured for high throughput with periodic persistence, not
synchronous-on-every-write durability:

- **AOF append, fsync every second** (`appendfsync everysec`). Every write is
  appended to the append-only file; the OS is told to flush it to disk about
  once a second.
- **RDB snapshot** as a backstop (e.g. `save 60 1000`: snapshot if >=1000 keys
  changed in 60s).

The practical consequence: on a *clean* shutdown nothing is lost. On a **hard
crash or power loss**, you can lose **up to roughly the last one second** of
writes (whatever had not yet been fsynced). This applies equally to permanent
(TTL 0) channels and to time-limited (TTL N days) ones: "permanent" means *the
data does not age out*, not *the data survives a power cut to the millisecond*.

This is a deliberate trade. doublethink's assumption is high message throughput
with modest durably-stored volume; `everysec` keeps the hardware comfortable
while bounding worst-case loss to about a second. If your use needs
zero-loss-on-crash, run Redis with `appendfsync always` (slower, heavier on the
disk) or front it with a replicated/clustered setup; doublethink does not require
those and does not promise them.

State this ~1s worst-case window to anyone you give a permanent channel to. It is
also in the public-facing terms ([`LEGAL.md`](LEGAL.md)).

## The three identity tiers

| Tier | How | Can create | Notes |
|---|---|---|---|
| **Anonymous** | no credentials | ephemeral private channels, public plaintext topics | per-IP rate/connection limits; no retention |
| **Account** | `POST /account` -> API key | retained channels | quota-attributed; broker stores only a hash of the key |
| **Admin** | `DOUBLETHINK_ADMIN_KEY` | grants, limit overrides; reads metadata | metadata/limit control only, **never** payload access |

The admin key never grants the ability to read any channel's payloads. End-to-end
encryption is keyed off the per-channel secret, which the broker never holds; no
operator capability changes that. The admin can see and shape *metadata and
limits*, and can authorize permanent channels, but cannot read what flows through
them.

## Admin API

All admin calls authenticate with the admin key as a bearer token:

```
Authorization: Bearer $DOUBLETHINK_ADMIN_KEY
```

Without a valid key these routes return `401`; with the admin key unset entirely
they return `404`. The CLI wraps all of them under `doublethink admin ...` and
reads the key from `$DOUBLETHINK_ADMIN_KEY` by default (override with
`--admin-key`).

### `POST /admin/grant` - issue a single-use ticket for a permanent / over-default channel

This is the headline M3 capability. An admin **pre-authorizes** a channel with a
chosen policy (e.g. never expires, uncapped) and hands the user a **single-use
ticket**. The user redeems it while creating the channel **with their own secret**,
so the admin authorizes the channel **without ever learning the secret** and
without being able to read it.

Request body:

| Field | Type | Meaning |
|---|---|---|
| `channel_match` | string | the channel id the ticket authorizes; either an exact id (`perm/team-debug`) or a namespace (`perm/*`) |
| `ttl_sec` | int | retention TTL of the granted channel in seconds. **`0` = never expires (permanent).** |
| `max_bytes` | int | per-channel byte cap. `0` = uncapped |
| `max_msgs` | int | per-channel message cap. `0` = uncapped |
| `expiry_sec` | int | how long the **ticket** is valid to redeem. `0` = server default (1 hour) |

Note the two different lifetimes: `ttl_sec` is how long the *channel's data*
lives once created (0 = forever); `expiry_sec` is how long the *ticket* is valid
to be redeemed (a short window; the admin sets it). A ticket that is never
redeemed simply expires and disappears.

Response:

```json
{
  "ticket": "<single-use token>",
  "channel_match": "perm/team-debug",
  "expiry_sec": 3600,
  "note": "give this ticket to the user; they create the channel with it and their own secret. Single use; expires."
}
```

CLI:

```
doublethink admin grant --channel perm/team-debug --ttl-sec 0
# grant ticket (single use, valid 60 minutes to redeem):
#   <ticket>
```

`--ttl-sec 0` (the default) makes a permanent channel; pass e.g.
`--ttl-sec 2592000` for 30 days. `--expiry-sec` sets the ticket's redeem window.

**Why a ticket and not "admin creates the channel directly":** the design
requirement is that the admin authorizes a durable channel **without seeing the
user's secret**. If the admin created the channel they would have to know or
choose the secret. The ticket inverts that: the admin authorizes the *policy*,
the user supplies the *secret*. The channel's policy comes from the ticket, never
from the redeeming client's input, so a leaked or guessed ticket cannot be used
to grant itself a broader policy than the admin chose. The ticket is consumed
atomically in the same operation that creates the channel, so it cannot be
replayed.

### Redeeming a grant (client side, no admin key)

The user redeems the ticket on channel creation. No admin key is involved; the
ticket is the authorization:

```
doublethink channel create --channel perm/team-debug --ticket <ticket>
#   channel: perm/team-debug
#   secret:  <high-entropy secret>   <- the user keeps this; the admin never sees it
```

Or over HTTP directly:

```
POST /channel
{ "channel": "perm/team-debug", "auth_key": "<HKDF(secret,auth)>", "ticket": "<ticket>" }
```

If `channel_match` was a namespace (`perm/*`), the user picks any id under it
(`perm/anything`). The resulting channel is retained with exactly the TTL and
caps the admin set in the grant. Optionally the user can also pass an account
key, which attributes ownership of the channel to that account.

### Full grant flow

```
admin                          broker (Redis)                  user
  |  POST /admin/grant            |                              |
  |  (channel_match, ttl_sec=0,   |                              |
  |   expiry_sec=3600)            |                              |
  |------------------------------>| store ticket, TTL=expiry     |
  |  { ticket }                   |                              |
  |<------------------------------|                              |
  |                               |                              |
  |  hand ticket to user (out of band; admin never sees secret)  |
  |------------------------------------------------------------->|
  |                               |  POST /channel               |
  |                               |  (channel, auth_key, ticket) |
  |                               |<-----------------------------|
  |                               | validate ticket matches      |
  |                               | channel; create channel with |
  |                               | TICKET's policy; DEL ticket   |
  |                               | (consume) -- all atomic       |
  |                               |   channel created (permanent) |
  |                               |----------------------------->|
```

### `POST /admin/limit` - raise an existing channel's retention limits

Adjust an already-created channel's TTL and caps (e.g. promote a channel to
permanent after the fact, or raise its caps).

| Field | Type | Meaning |
|---|---|---|
| `channel` | string | channel id (required) |
| `ttl_sec` | int | new TTL seconds. `-1` = leave unchanged, `0` = never expire |
| `max_bytes` | int | new byte cap. `-1` = unchanged, `0` = uncapped |
| `max_msgs` | int | new message cap. `-1` = unchanged, `0` = uncapped |

```
doublethink admin set-limit --channel codespeak/abc --ttl-sec 0 --max-msgs 0
```

Returns `404` if the channel does not exist.

### `GET /admin/channels` - list channel metadata

Returns per-channel **metadata only**: id, owner (if any), retained flag, TTL,
caps, and current byte/message counts. **Never** the secret, the stored auth key,
or any payload.

```
doublethink admin channels
```

```json
{ "channels": [
  { "id": "perm/team-debug", "retained": true, "ttl_sec": 0,
    "max_bytes": 0, "max_msgs": 0, "bytes": 4096, "msgs": 12 }
] }
```

Use this to find a channel id for a takedown (see [`LEGAL.md`](LEGAL.md)) or to
audit what is retained.

### `GET /stats` - public aggregate counters (no admin key)

`/stats` is **public** and intentionally GDPR-safe: it returns only aggregate
counts, never IPs, never channel ids, never per-user data, never anything that
identifies a person or a deployment using the broker.

```json
{ "channels": 42, "retained_channels": 7, "accounts": 5,
  "retained_messages": 1280, "retained_bytes": 4194304 }
```

This lets a community see that the instance is alive and roughly how loaded it is
without exposing who uses it or for what. A per-domain usage list is deliberately
**not** served by default; see the GDPR note in [`LEGAL.md`](LEGAL.md).

## Operational notes

- **Dropping all state.** Because everything is in Redis, flushing the broker is
  `redis-cli FLUSHDB` (or dropping the volume). There is no migration path and no
  other store to clear; doublethink is greenfield on Redis.
- **TTL aging.** A background sweeper prunes expired retained messages
  periodically. Channels with `ttl_sec = 0` are skipped (permanent).
- **Taking a channel down.** Delete its keys in Redis by id (the id is visible in
  `GET /admin/channels`). This removes the (encrypted) data and the channel
  registration without needing, or being able, to read the payloads.
