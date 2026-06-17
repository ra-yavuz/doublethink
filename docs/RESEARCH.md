# doublethink: Prior-Art Research

**Status: done (2026-06-17).** This document was the open prior-art gate named in
[`../GOAL.md`](../GOAL.md) and [`SECURITY.md`](SECURITY.md). It is now answered.
Nothing below should be built on without reading the verdict and its limits.

The question this survey had to answer honestly: **does something already fill
doublethink's exact gap, a broker that is *both* ntfy-easy *and* genuinely
private/authenticated?** The bar is the *combination*. Many secure brokers exist;
the test is whether any clears ntfy's "stand it up in minutes, point things at it
with almost no ceremony" friction bar *while* giving real private channels. If one
did, doublethink would duplicate it rather than build.

## How this was produced

A multi-source web survey (fan-out search, source fetch, adversarial 3-vote
verification of each claim, then synthesis): 21 sources fetched, 25 load-bearing
claims verified, 25 confirmed (3-0), 0 refuted. Findings were then cross-checked
against a second independent model (CODEX), which surfaced one material miss
(SimpleX, added below), one framing correction (the "thin layer" wording), and the
single biggest risk (metadata and key lifecycle, not byte-encryption). The managed
services and SimpleX were verified by direct first-party reads after that
cross-check. Sources are linked inline.

Given the subject (auth and crypto), this is a survey, not a security proof. The
implementation it points to must itself be reviewed before release, per
[`SECURITY.md`](SECURITY.md).

---

## Verdict

**Build doublethink: a thin broker core, a thick trust layer. Do not build a new
broker transport from scratch; do not abandon.**

No surveyed self-hostable tool occupies all four cells at once:

> **self-hostable + ntfy-easy setup + real per-channel authz + broker-blind
> end-to-end encryption.**

That empty cell is doublethink's defensible niche. The two halves of the bar trade
off directly in every existing tool: the tools that are ntfy-easy are open by
default (name-secrecy only, broker reads plaintext); the tools with real privacy
cost materially more setup than vanilla ntfy; and the only tools that ship true
broker-blind E2E are either closed managed services (not self-hostable) or
substrates whose setup is nowhere near ntfy-easy.

**Closest competitors, and exactly where each falls short:**

- **NATS** is closest on *conventional broker + authz*: real Ed25519 nkey/JWT
  identity, server-enforced per-subject authorization, accounts isolated by
  default. It falls short on (a) ntfy-grade setup friction (operator/account/user
  JWT chain via `nsc`) and (b) confidentiality: it is TLS-in-transit only, the
  broker sees plaintext.
- **SimpleX / SimpleXMQ (SMP)** is closest on *broker-blind privacy*: a
  self-hostable relay where the server only ever sees encrypted blobs and cannot
  read content or identify users, with per-queue asymmetric keys and
  MITM-resistant addressing. It falls short on the ntfy-ease + familiar-pub/sub
  side: it is not named-topic pub/sub, its address model is cryptographic-
  fingerprint-based rather than human-named topics, and the SMP agent is its own
  protocol, not a drop-in broker API.

So the niche is real, but **only when framed precisely**: *ntfy-like, self-hosted,
named-topic pub/sub with first-class per-channel authz and broker-blind payloads.*
Drop any one of those qualifiers and an existing tool already wins.

### "Thin layer" is the wrong word; say "thin core, thick trust layer"

It is tempting to call doublethink "a thin trustworthy layer on NATS." That is
self-deception. A mature transport (NATS, or similar) gives you accounts, subject
permissions, isolation, routing, and optional retention (JetStream). It does **not**
give you the actual product: device pairing, identity, key exchange, membership
changes and revocation, replay/ordering rules, offline-peer delivery semantics,
client SDKs, and an ntfy-easy setup UX. That layer is not thin. doublethink's real
work is the trust layer, whichever transport sits under it.

### The decision this forces in SECURITY.md

[`SECURITY.md`](SECURITY.md) currently lists "end-to-end vs in-transit" as an open
decision. **This research effectively answers it.** If doublethink chooses
TLS-in-transit-only (broker reads plaintext), it has no differentiation: NATS,
EMQX, and RabbitMQ already do that, better and more maturely. doublethink's only
defensible reason to exist is **broker-blind end-to-end encryption** (the operator
cannot read a private channel). This should be confirmed deliberately with the
user and then written into SECURITY.md as a decided position, not left open.

### The biggest risk, stated up front

The hard part is **not encrypting bytes; it is metadata and key lifecycle.**
"The operator cannot read it" is only *payload* confidentiality. A serious design
must also reason about what the broker still sees (channel names/subjects, message
timing, sizes, sender/receiver patterns, channel existence, retention) and about
the genuinely hard crypto: key revocation, forward secrecy, multi-device recovery,
and making pairing MITM-resistant *without* making setup painful. Even the best
commercial E2E (Ably) encrypts only the payload and leaves event names, client IDs,
and presence metadata visible to the operator. doublethink must decide its
metadata posture on purpose and state it plainly to users.

---

## Comparison across the five axes

Axes: **(1)** setup friction vs ntfy, **(2)** real per-channel authz (not
name-secrecy), **(3)** auth/identity model, **(4)** confidentiality (in-transit vs
broker-blind E2E), **(5)** bidirectional async + streaming.

| Tool | 1. Setup vs ntfy | 2. Real per-channel authz | 3. Identity model | 4. Confidentiality | 5. Async + streaming | Self-hostable |
|---|---|---|---|---|---|---|
| **ntfy (vanilla)** | ✅ trivial (the bar) | ❌ name is the only gate | none / anonymous | TLS-in-transit; broker caches plaintext | ✅ pub/sub + SSE stream | ✅ |
| **ntfy (auth + deny-all)** | ⚠️ heavier: auth DB, `deny-all`, restart, per-user ACLs | ✅ per-topic ACLs; unlisted users denied | user/pass + tokens | TLS-in-transit; broker reads plaintext (issue #69 open) | ✅ | ✅ |
| **NATS (+ nkeys/JWT)** | ❌ operator/account/user JWT chain via `nsc` | ✅ server-enforced per-subject; accounts isolated by default | Ed25519 nkeys, signed JWTs, challenge-response | TLS-in-transit; broker reads plaintext | ✅ core + JetStream | ✅ |
| **EMQX 6.0** | ❌ heavier than ntfy | ✅ per-topic/identity; **deny-by-default from 6.0** | clientid/user, TLS, etc. | TLS-in-transit; broker reads plaintext | ✅ MQTT | ✅ |
| **RabbitMQ** | ❌ heavier than ntfy | ✅ configure/write/read regex per vhost per user | user/pass, x.509 mTLS, LDAP, OAuth2/JWT | TLS-in-transit; broker reads plaintext | ✅ | ✅ |
| **Matrix / Synapse** | ❌ enterprise: domain, DNS delegation, reverse proxy, PostgreSQL, web client | ✅ room membership | per-user accounts, device keys | ✅ **E2E (Olm/Megolm)** | ✅ rooms (chat-shaped) | ✅ |
| **SimpleX / SMP** | ❌ not ntfy-easy; fingerprint-addressed, own protocol | ✅ per-queue asymmetric keys | per-queue keypairs; cert-fingerprint address (anti-MITM) | ✅ **broker-blind** (server sees only encrypted blobs) | ✅ simplex/duplex queues | ✅ |
| **Pusher Channels** | ✅ easy (managed) | ✅ private/presence channels | server-auth'd channel grants | ✅ **E2E (NaCl SecretBox)**; key never touches Pusher | ✅ | ❌ managed-only |
| **Ably** | ✅ easy (managed) | ✅ private channels (adapter) | token/key | ✅ **client-side E2E**; keys never reach Ably, **but payload only** (names/clientId/presence visible) | ✅ | ❌ managed-only |
| **PubNub** | ✅ easy (managed) | ✅ access manager | keys/grants | ✅ **client-side AES-256** | ✅ | ❌ managed-only |

Legend: ✅ meets, ⚠️ partial / added friction, ❌ does not meet.

### The pattern the table shows

1. **ntfy-ease and real privacy are anti-correlated** in every self-hostable tool.
   ntfy is light *only when left open*. Turning on real authz makes it heavier;
   the brokers that are private-by-config are all heavier than ntfy to begin with.
2. **Broker-blind E2E is the rarest property** and the real gap. Among
   self-hostable tools only Matrix and SimpleX have it, and both pay for it with
   setup friction far above ntfy. Among ntfy-easy tools, only the *managed,
   closed* services (Pusher/Ably/PubNub) have it.
3. **The empty cell is the intersection of all four**: self-hostable AND
   ntfy-easy AND real authz AND broker-blind E2E. Nothing surveyed sits there.

---

## Per-tool findings (verified)

### ntfy

- **Vanilla ntfy is frictionless precisely because the topic name is the only
  gate.** By default anyone who knows or guesses a topic can read and write it;
  no sign-up, no ACLs. ntfy's own docs call the topic "essentially a password."
  This is the exact failure mode doublethink must not reproduce.
  ([faq](https://docs.ntfy.sh/faq/),
  [config](https://docs.ntfy.sh/config/),
  [config.md](https://github.com/binwiederhier/ntfy/blob/main/docs/config.md))
- **ntfy *can* enforce real per-topic authz** via an auth DB (SQLite/PostgreSQL)
  plus per-user ACLs (`ntfy access USER TOPIC PERMISSION`); with
  `auth-default-access: deny-all`, unmatched requests, including authenticated
  users with no matching ACL and the anonymous `everyone`/`*` user, are rejected.
  Confirmed by [issue #1474](https://github.com/binwiederhier/ntfy/issues/1474)
  (no all-authenticated shortcut exists). So it is real authz, not name-secrecy,
  *when configured*. ([config](https://docs.ntfy.sh/config/))
- **But enabling that costs the ntfy-ease.** A private instance needs `server.yml`
  edits (`auth-file` + `deny-all`), a restart, and per-user/per-topic
  provisioning. "Technically possible with config," not "frictionless like ntfy."
  ([config](https://docs.ntfy.sh/config/))
- **Even fully authenticated ntfy is TLS-in-transit only.** The server sees and
  caches message plaintext (12h default); the operator can read private content.
  The native-E2E request,
  [issue #69](https://github.com/binwiederhier/ntfy/issues/69), is still open;
  the project's own answer is "run your own server." Third-party encrypt-before-
  send wrappers exist precisely because ntfy has no native E2E.
  ([privacy](https://docs.ntfy.sh/privacy),
  [deepwiki security page](https://deepwiki.com/binwiederhier/ntfy/6.2-security-and-privacy))

### NATS (closest on broker + authz)

- **Accounts isolate the subject space by default**: messages in account A are not
  visible to account B; cross-account flow needs explicit export/import. Per-
  subject authz is server-enforced at the JWT level, so knowing a subject name in
  another account grants nothing. Real per-channel authz, not name-secrecy.
  ([accounts](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/accounts),
  [authorization](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization))
- **Identity maps cleanly onto a per-party keypair-pairing model** (relevant to
  CodeSpeak's Device ID / keypair pairing): each party gets an Ed25519 nkey plus a
  signed JWT in an Operator -> Account -> User chain (`nsc`); auth is
  challenge-response (sign a server nonce), and the server never sees private keys.
  ([jwt](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt),
  [nkey_auth](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/nkey_auth),
  [nsc](https://github.com/nats-io/nsc))
- **Cost:** the operator/account/user JWT chain is meaningfully heavier than
  ntfy's zero-config start, and NATS is TLS-in-transit only (broker reads
  plaintext). Pin to a patched release: CVE-2025-30215 (fixed 2.10.27 / 2.11.1)
  was a JetStream admin-plane cross-account bypass (no data disclosure reported).

### SimpleX / SimpleXMQ / SMP (closest on broker-blind privacy)

- **A self-hostable relay where the server only ever sees encrypted blobs** and
  cannot read content or identify users. Access to each queue is controlled by
  per-queue asymmetric keypairs (separate sender/recipient). The offline
  certificate fingerprint is part of the server address, protecting the
  client/server connection against MITM. Initialized with `smp-server init`.
  ([simplexmq README](https://github.com/simplex-chat/simplexmq/blob/stable/README.md),
  [SMP protocol](https://github.com/simplex-chat/simplexmq/blob/master/protocol/simplex-messaging.md),
  [smp-server image](https://hub.docker.com/r/simplexchat/smp-server))
- **Why it does not close the gap:** it is not named-topic pub/sub; addressing is
  cryptographic-fingerprint-based rather than human-named topics, and the SMP agent
  is its own protocol, not a drop-in broker API. It is also not ntfy-easy in the
  point-and-publish sense. It is, however, the strongest existing evidence that
  self-hosted broker-blind delivery is achievable, and a primary reference design.

### EMQX (MQTT)

- Real per-topic, per-identity authz; **deny-by-default from EMQX 6.0** (was
  allow-by-default in 5.x). TLS-in-transit only; heavier to operate than ntfy.
  ([authz](https://docs.emqx.com/en/emqx/latest/access-control/authz/authz.html),
  [authz file](https://docs.emqx.com/en/emqx/latest/access-control/authz/file.html))

### RabbitMQ

- Genuine per-resource, per-user authz (configure/write/read regex per vhost);
  many auth backends (user/pass, x.509 mTLS, LDAP, OAuth2/JWT). Confidentiality is
  TLS-in-transit only; as a store-and-forward broker it necessarily decrypts and
  re-encrypts, so it sees plaintext; app-level encryption is the documented
  recommendation. ([access-control](https://www.rabbitmq.com/docs/access-control))

### Matrix / Synapse (self-hostable E2E, but heavy)

- The one self-hostable substrate that genuinely ships E2E (Olm/Megolm). But
  self-hosting is enterprise-grade: dedicated domain, multiple DNS records,
  `.well-known` federation delegation, a reverse proxy, PostgreSQL, and a separate
  web client, "not a simple containerized application." Far above ntfy-ease, and
  room/chat-shaped rather than pub/sub-shaped.
  ([E2E](https://matrix.org/docs/matrix-concepts/end-to-end-encryption/),
  [self-host guide](https://oneuptime.com/blog/post/2026-02-08-how-to-run-matrix-synapse-in-docker-for-chat/view))

### Managed services (E2E, but not self-hostable)

- **Pusher Channels:** end-to-end encryption out of beta, NaCl SecretBox; the key
  is never passed through Pusher infrastructure; managed-only.
  ([E2E announcement](https://pusher.com/blog/end-to-end-encryption-for-pusher-channels-is-out-of-beta/))
- **Ably:** client-side encryption; payloads opaque to Ably, keys never reach
  Ably, **but only the payload is encrypted**, event `name`, `clientId`, and
  presence metadata remain visible to Ably; managed-only.
  ([encryption](https://ably.com/docs/channels/options/encryption))
- **PubNub:** client-side AES-256; payloads not decrypted on the network;
  managed-only.
- These prove the ntfy-easy + E2E combination is *commercially* viable, but they
  are closed and hosted-only, so they do not serve the self-hoster who wants
  privacy, which is doublethink's user.

### Also surveyed, briefly

- **Centrifugo:** self-hosted pub/sub (WebSocket/SSE/etc.), JWT auth, `$`-prefixed
  private channels gated by per-subscription tokens from your backend. No native
  broker-blind E2E documented. ([github](https://github.com/centrifugal/centrifugo),
  [private channels](https://centrifugal.dev/docs/3/server/private_channels))
- **Mercure, Mosquitto** noted in the survey; same pattern (real authz possible,
  no broker-blind E2E, friction above vanilla ntfy).

---

## Honest limitations of this survey

- **"Frictionless like ntfy" is qualitative.** The setup-friction rankings are
  honest relative orderings, not a measured benchmark. They are defensible but not
  numeric.
- **Version-gated facts.** Current for 2025-2026 lines (ntfy v2.x, NATS 2.x,
  EMQX 6.0, RabbitMQ 3.13.x). EMQX deny-by-default is 6.0-specific; 5.x can grant
  on no-match. Pin NATS to a CVE-2025-30215-patched release.
- **A couple of conclusions rest on architectural inference**, flagged but not
  refuted: RabbitMQ "broker sees plaintext" is inferred from its store-and-forward
  design (the access-control docs are silent on E2E), and ntfy's per-user deny
  under `deny-all` is confirmed via issue #1474 rather than a dedicated docs line.
- **SimpleX was found in cross-check, not the first sweep.** It is now verified
  against first-party docs, but it deserves a deeper read before it is used as a
  reference design, especially its queue model, retention, and how (or whether) a
  named-topic pub/sub shape could sit on top of SMP.
- **Not deeply evaluated:** AWS IoT Core and Google Cloud Pub/Sub on the
  self-hoster-privacy axis (managed, so largely off-target for doublethink's user);
  Gotify (noted by cross-check as ntfy-adjacent, token-auth, no E2E).

## Open questions carried into design

These are now design-phase questions, not research gaps:

1. **Transport decision:** build doublethink's broker core on NATS (mature authz +
   isolation, but adds the JWT-chain friction we must hide), study SimpleX/SMP as
   the broker-blind reference, or write a minimal purpose-built core. The
   "thin-core / thick-trust-layer" framing applies whichever way this goes.
2. **Metadata posture:** exactly what the broker is allowed to see (channel names,
   timing, sizes, existence, retention) and what is hidden. State it to users.
3. **Key lifecycle:** revocation, forward secrecy, multi-device recovery, and
   MITM-resistant pairing that stays ntfy-easy. This is the hardest part.
4. **Pairing mapping:** how doublethink's pairing maps onto CodeSpeak's Device ID /
   Session Token / keypair model (see
   [`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md)), and whether any
   surveyed pairing flow can be reused or doublethink needs its own handshake.
5. **Confirm the E2E decision in [`SECURITY.md`](SECURITY.md)** as decided, not
   open, per the verdict above.
