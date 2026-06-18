# doublethink

**A secure publish/subscribe message broker that is as easy to stand up as
[ntfy](https://ntfy.sh), but with real authentication and genuinely private
channels.** ntfy is everywhere because it is trivial to use; its topics are also
effectively public. doublethink keeps the minutes-to-set-up ergonomics and adds
the thing ntfy deliberately omits: identity, authentication, and private
channels you can trust with real traffic.

Create a private channel with one request and you get back a high-entropy secret.
Whoever holds the secret can join the channel; nobody else can. Messages are
end-to-end encrypted between the parties who share it, so the broker relays them
but cannot read them. Opt-in message retention lets a peer that was offline catch
up on reconnect. Plaintext public topics are available too, ntfy-style. It is
cross-platform: run it in Docker or as a single native binary.

## Quickstart

Stand it up. Pick one:

```
# Docker, serve from this checkout (no image build):
docker compose up

# Docker, prebuilt self-contained image (distroless):
docker compose -f docker-compose.build.yml up --build

# Or a single Go binary (toolchain stays in the dev container under .claude-dev/):
go build -o doublethink ./cmd/doublethink
./doublethink serve
```

The broker listens on `:8080`.

Create a private channel. This is self-service, one request, no operator:

```
./doublethink channel create --prefix codespeak
#   channel: codespeak/<random-id>
#   secret:  <high-entropy shared secret>
```

The **secret is the gate.** Share it with the other party over a trusted channel
(it is like an ntfy topic, except the secret, not the name, is what grants access,
and it is unguessable). Both parties then connect to the channel using that secret;
anyone who holds it can join, and no one else can. The broker **never sees the
secret**: it stores only a derived authentication key, so it can check who may join
but cannot read your messages. Messages are end-to-end encrypted between the two
parties who hold the secret.

Plaintext public topics work ntfy-style for those who want them, no secret, fully
open:

```
curl -d "hello" http://localhost:8080/publish/mytopic
curl -sN http://localhost:8080/subscribe/mytopic   # Server-Sent Events stream
```

The public path refuses any name registered as a private channel, so a private
channel can never be reached through the open path. The security model is in
[`docs/SECURITY.md`](docs/SECURITY.md).

### Retained channels (catch up after being offline)

A channel created as above is **ephemeral**: messages are delivered to whoever is
connected and then gone (online-only, anonymous, ntfy-easy). For a peer that may be
offline at publish time (a backgrounded app, a reconnecting agent), create a
**retained** channel instead: the broker stores its messages so a reconnecting peer
can catch up. Retained channels require an account:

```
# 1. Get an account API key (shown once; the broker stores only a hash of it).
./doublethink account create
#   account: <id>
#   api key: <key>

# 2. Create a retained channel with that key.
./doublethink channel create --prefix codespeak --retain \
    --account <id> --api-key <key>
```

On reconnect, a subscriber sends the last sequence number it saw and receives only
the messages it missed, in order, then resumes live. Stored messages are still
end-to-end encrypted ciphertext: the broker keeps them but cannot read them. The
shared-secret model is otherwise unchanged.

Anonymous clients can still create ephemeral channels and use public topics, but
**not** retained ones (that path needs an account so storage can be attributed and
bounded).

### Permanent and admin-provisioned channels

A retained channel ages out by a TTL by default. For a channel that should
**persist indefinitely** (or for any TTL up to infinity) the operator
pre-authorizes it with a **single-use grant ticket**, and the user redeems the
ticket while creating the channel **with their own secret**. The admin authorizes
the durable channel **without ever learning the secret** and cannot read it:

```
# Operator (holds the admin key) issues a grant for a permanent channel:
doublethink admin grant --channel perm/team-debug --ttl-sec 0
#   grant ticket (single use, valid 60 minutes to redeem): <ticket>

# User redeems it with their OWN secret (no admin key needed):
doublethink channel create --channel perm/team-debug --ticket <ticket>
#   channel: perm/team-debug
#   secret:  <high-entropy secret>   <- the user keeps this; the admin never sees it
```

`--ttl-sec 0` means never expire. The channel's policy comes from the ticket, not
from the client, so the grant cannot be used to authorize more than the operator
chose; the ticket is single-use and expires if not redeemed. The full admin API,
the grant flow, and the storage durability guarantee are in
[`docs/ADMIN.md`](docs/ADMIN.md).

### Storage and durability

doublethink stores channels, retained messages, and accounts in **Redis** (one
binary plus a Redis instance; there is no other database). Redis is run for high
throughput with periodic persistence: writes are appended and flushed to disk
about once a second. A clean shutdown loses nothing; a **hard crash or power loss
can lose up to roughly the last one second** of writes. "Permanent" channels mean
the data does not age out, not that it survives a power cut to the millisecond.
If you need zero-loss-on-crash, configure Redis accordingly (see
[`docs/ADMIN.md`](docs/ADMIN.md)).

### Limits and accounts

A public instance bounds resource use. Retention is capped per channel (a message
count and a byte size, oldest evicted past either) and aged out by a TTL (default
24h, max 7d). Each account has a storage quota (256 MiB) and a channel cap (100).
Messages are size-capped (256 KiB), and channel creation, publishing, and
connections are rate-limited per source. An operator can raise the limits for a
preferred channel with `doublethink admin set-limit`, pre-authorize permanent
channels with `doublethink admin grant`, and list channel metadata with
`doublethink admin channels` (all authenticated by the `DOUBLETHINK_ADMIN_KEY`
the broker runs with, and disabled entirely when it is unset). The admin key
controls limits, grants, and reads usage metadata only; it never grants access to
any channel's payloads. The aggregate, non-identifying counters are public at
`GET /stats`. The full admin reference is in [`docs/ADMIN.md`](docs/ADMIN.md).

**What retention costs you to know:** stored messages are user data. They expire,
can be evicted to stay within caps, and count against quota. End-to-end encryption
still hides payloads, but a retained channel exposes more to the operator than an
ephemeral one: stored message sizes, timestamps, and counts are visible (the broker
still cannot read the payloads). The model is also symmetric, both holders of a
secret can publish and read, so there is no per-sender attribution and no way to
remove one party without rotating the secret, and there is no forward secrecy yet.

## Security is the point, not a feature

doublethink exists because "ntfy, but I can trust it with private data" is a real
need. That makes security a primary, non-negotiable design goal, held on equal
footing with ease of use, never traded against it:

- Private channels admit only authenticated, authorised parties. Unauthenticated
  access is rejected.
- Private-channel contents are confidential to the authorised parties; other
  parties on the broker cannot read or write them.
- Private-channel payloads are end-to-end encrypted between the parties who hold
  the channel secret. The broker derives, from that secret, only a key that lets
  it check who may join; it never holds the encryption key and cannot read your
  messages.

The full security model, threat model, and honest limits are in
[`docs/SECURITY.md`](docs/SECURITY.md).

## Disclaimer / no warranty

doublethink is a message broker that, by design, carries other parties' private
traffic and enforces access to it. It is provided **as is, without warranty of
any kind**, express or implied, including but not limited to merchantability,
fitness for a particular purpose, and noninfringement.

By installing or running this software you accept that:

- You alone are responsible for how you deploy and secure it, for the data that
  flows through it, and for the consequences of any misconfiguration.
- The author and contributors are **not liable** for any harm, data loss, data
  exposure, security incident, or other damages, however caused.
- No security mechanism is perfect. doublethink aims for a strong, honestly
  documented security posture, but you are responsible for evaluating whether it
  meets your own requirements before trusting it with sensitive traffic.

If you do not accept these terms, do not install or run this software.

End-to-end encryption is a feature of the software, and using it is lawful;
doublethink is a general-purpose dual-use communications tool.

### The public instance at `api.caleidoscode.io`

The author runs a free public instance for the demo and for trying doublethink
out. It is **free, best-effort, with no SLA and no guarantees**, and **may be
rate-limited, wiped, or shut down at any time without notice**. Do not depend on
it; if you need guarantees, **self-host** (that is what the single-binary design
is for). Use of the public instance is subject to an acceptable-use policy (no
illegal use), an abuse/takedown process keyed on channel id, and a GDPR-safe
stats posture. All of that is in [`docs/LEGAL.md`](docs/LEGAL.md); the abuse
contact is `yavuzramazan1994@gmail.com`.

Full legal license: see [`LICENSE`](LICENSE) (MIT).

## Author

[Ramazan Yavuz](https://ramazan-yavuz.tr). Part of a set of independent,
open-source tools published at [ra-yavuz.github.io](https://ra-yavuz.github.io/).
