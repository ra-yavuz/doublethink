# doublethink: M1 Design

**Status: M1 implemented, shared-secret model (2026-06-17).** This is the
architecture for doublethink's first implementation milestone. It is downstream of
[`../GOAL.md`](../GOAL.md), [`SECURITY.md`](SECURITY.md),
[`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md), and the verified verdict
in [`RESEARCH.md`](RESEARCH.md). The broker-blind E2E posture (decision 4) is
confirmed and recorded as decided in SECURITY.md.

## How a private channel works, and the design path that got here

A private channel is gated by **one high-entropy shared secret S** that the two
parties hold. You create a channel with a single request, get back S, and share S
with the other party out of band (like sharing an ntfy topic, except S, not the
channel name, is the real gate, and S is unguessable). Whoever holds S can join and
read the channel; no one else can; the broker never sees S and so cannot read the
traffic. This is **self-service and ntfy-easy**: no operator, no per-channel
ceremony.

This is deliberately simpler than where the design started. An earlier attempt
authenticated channel admission with an Ed25519 keypair challenge plus an
admin-issued single-use invite code and an out-of-band short authentication string
(SAS) that both parties had to compare and confirm. That was **dropped as
over-engineered**: it required a manual operator ceremony for every authenticated
channel, which directly contradicts the ntfy-ease that is doublethink's reason to
exist. The shared-secret model keeps the property that matters (the broker cannot
read private payloads) while making channel creation a one-request, no-operator
act. The earlier design's stronger MITM-resistance and per-sender identity are
noted as future options under "deferred", not requirements for M1.

The message envelope is unchanged and still satisfies
[`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md); only how a client gains
access to a channel changed. The consumer (CodeSpeak) adapts its thin channel
client to the published broker's shared-secret credential.

## M1 acceptance bar

A real doublethink that someone can stand up and use for authenticated, private,
end-to-end-encrypted, bidirectional, streaming channels, satisfying the
*capabilities* in [`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md). The
envelope is fixed and transported with `payload` opaque:

```json
{ "channel": "codespeak/<paired-id>", "type": "request|progress|result|summary|control|error",
  "id": "correlation-id", "payload": { }, "ts": "ISO-8601" }
```

Everything not needed for that bar is deferred (see the last section).

---

## Decisions

### 1. Language and dependencies: Go, near-stdlib

**Go, compiled to a single static binary.** Rationale: one static binary is the
literal shape of ntfy-ease (download, run, done); it is cross-platform and runs
either in Docker or natively on bare metal with no runtime to install;
`net/http` gives the HTTP + WebSocket server with almost no dependencies;
`golang.org/x/crypto/{hkdf,blake2b,nacl/secretbox}` give the exact HKDF +
XSalsa20-Poly1305 primitives the shared-secret model needs, from a maintained,
audited library; the attack surface stays small.

Dependency budget for M1, deliberately tiny:
- `net/http`, `crypto/*`, `encoding/json` from the stdlib.
- one WebSocket library (`nhooyr.io/websocket`, now `coder/websocket`: context-aware,
  small, modern) for the browser-facing socket.
- `golang.org/x/crypto/{nacl/secretbox,hkdf,blake2b}` for crypto.
- `modernc.org/sqlite` (pure-Go, no cgo) only if M1 needs persistence; M1 starts
  in-memory (see delivery semantics), so this may not land until retention does.

**Trade-off:** vs Rust, Go gives up some compile-time memory-safety strictness and
has GC pauses (irrelevant at this scale). It buys faster correct delivery and the
easiest single-binary, run-in-Docker-or-natively story. The repo's other projects
are shell/Python; nothing constrains the language, so a network daemon picks the
best fit, which is Go.

### 2. Transport: one WebSocket per peer, HTTP for publish-once

The PWA is a **browser**, so the client transport must be browser-native. That
rules out raw MQTT-over-TCP and NATS's native protocol. Choice:

- **Primary: a single WebSocket per connected peer**, carrying both directions.
  This is full-duplex by construction, supports streaming (many frames over time),
  and is the simplest thing a browser and a Go agent can both speak. The peer
  authenticates during the WS handshake (see decision 4), then publishes and
  receives envelopes as WS messages on the same socket.
- **Secondary: HTTP `POST /publish` and `GET /subscribe` (SSE)** for ntfy-shaped
  one-shot or curl-friendly use, especially for public/plaintext topics. This is
  what makes "point things at it like ntfy" literally true for simple senders.

**Head-of-line / barge-in:** a `control` message (barge-in cancel) from the PWA and
a long `progress` stream from the agent travel in **opposite directions on two
separate sockets**, so the stream never blocks the control message. Within one
sender's own socket, ordering is preserved (that is wanted); control is not queued
behind that sender's own stream because control comes from the *other* peer. This
satisfies CONVERSATION-MODEL.md barge-in without a separate control channel.

### 3. Broker core: purpose-built for M1, not NATS

The research named NATS as the closest competitor. But the browser constraint means
NATS could not face the PWA directly; it would need a WebSocket gateway in front
*plus* the entire pairing/E2E/authz/envelope layer written on top. At M1 scale (one
paired channel, modest throughput, no clustering, no durable retention yet), running
and bending NATS is *more* total moving parts than a small purpose-built core, and it
threatens the single-binary promise.

**Decision: build a small purpose-built broker core for M1.** It is structured so the
in-memory routing/store is behind an interface that could later be backed by NATS
JetStream or similar if scale (clustering, large fan-out, durable streams) ever
demands it. That is a deferred concern, not an M1 abstraction built speculatively.

**Trade-off (named honestly):** we own broker correctness (fan-out, ordering,
backpressure) instead of inheriting NATS's hardened core. Mitigation: M1's delivery
guarantee is deliberately minimal (see 6) and the security/delivery rules are covered
by tests (see Testing). This is the single biggest "build-it-ourselves" risk and is
called out again in Self-critique.

### 4. Shared-secret channels: admission and E2E from one secret

Per [`RESEARCH.md`](RESEARCH.md), TLS-only has no differentiation; the defensible
posture is **broker-blind end-to-end encryption** for private channels (decided in
SECURITY.md). doublethink delivers both broker-blindness and ntfy-ease from a
single shared secret. Crypto cross-checked against CODEX; the construction is in
`internal/clientcrypto`.

A channel is gated by a **256-bit shared secret S**, generated client-side
(`GenerateSecret`), shared out of band, and **never sent to the broker.** Two keys
are derived from S by HKDF with domain separation (different `info` labels):

- `K_auth = HKDF(S, "doublethink-auth-v1")`. This is the admission key (see below).
- `K_enc  = HKDF(S, "doublethink-enc-v1")`, then **per-direction payload keys**
  `HKDF(K_enc, "enc a->b")` and `HKDF(K_enc, "enc b->a")`. The two parties take
  opposite directions as send/recv via a `Role` (RoleA = creator, RoleB = joiner),
  so they never share a nonce domain. Message `payload` is sealed with **NaCl
  secretbox (XSalsa20-Poly1305)** under the sender's per-direction key with a random
  192-bit nonce. Only the sealed ciphertext crosses the broker.

**Admission (challenge-response on K_auth).** At creation the client sends the broker
the channel id and `K_auth` (base32), never S and never `K_enc`. To attach, the
client names the channel; the broker replies with a random challenge; the client
returns `ResponseFromAuthKey(K_auth, challenge)` (an HKDF PRF over the challenge
keyed by K_auth); the broker recomputes the same value from the stored K_auth and
**constant-time compares**. A fresh challenge per attach makes a captured response
useless for the next attach (replay-resistant), and K_auth itself is not re-sent on
each attach.

**Why broker-blindness holds.** K_auth and K_enc come from the **same S but
different HKDF labels**, so the broker, which holds only K_auth, cannot derive
K_enc (that would require inverting HKDF). The broker can verify who may attach yet
cannot read any payload. The load-bearing invariant: **S is never sent to the
broker.** If it were, the honest claim would weaken to "we do not store it" rather
than "the operator cannot read it" (logs, crash dumps, tracing, a malicious build
all see whatever crosses the wire). CODEX flagged the matching footgun in the
design phase: a broker that stored only a hash of S could not verify a response
keyed by S, hence the broker stores K_auth and recomputes the response.

**What the broker can see** (metadata posture, stated plainly to users):
- the channel id, the envelope `type`, `id`, and `ts` (it routes and correlates on
  these; they are deliberately *outside* `payload`),
- ciphertext bytes, their size, and message timing.

**What the broker cannot see:** the `payload` plaintext, the shared secret S, or the
encryption key K_enc.

**Honest limits of the symmetric model** (documented, not hidden):
- **Symmetric, so no per-sender non-repudiation.** Both parties hold the same S and
  can derive every key, so the protocol cannot prove which of the two sent a given
  message. This is the right trade for "two parties who share a secret trust each
  other"; it is not a group-chat or signed-message protocol.
- **Revocation = rotate S.** There is no way to revoke one party while keeping the
  other on the same channel; you recreate the channel with a fresh secret (a fresh
  `channel create`) and re-share it. M1 supports delete-then-recreate, not in-band
  rekey.
- **No forward secrecy.** The channel key is static for the life of S, so disclosure
  of S exposes past captured ciphertext. A ratchet is a named follow-up, not an M1
  deliverable; cutting it is what keeps M1 shippable.
- **MITM on the out-of-band share.** If S is intercepted while being shared, the
  interceptor can join. This is inherent to "share a secret out of band" (the same
  as leaking an ntfy topic, but with real entropy). The earlier keypair + SAS design
  addressed this with a human-verified fingerprint; it was dropped for ntfy-ease and
  remains a future option for a high-assurance mode.

### 5. Channel naming and anti-enumeration

- Public/plaintext topics: ntfy-style human names, openly readable/writable (opt-in).
- Private channels: the channel id is a high-entropy random id (128-bit, base32,
  optionally a human prefix like `codespeak/`), not a guessable human string. The id
  is **not** the security boundary, the shared secret is; the random id only removes
  enumeration as a cheap probe. The broker returns identical "not authorized"
  responses for "wrong response" and "no such channel" so it does not leak channel
  existence (req 5), and the public plaintext path refuses any name that is a
  registered private channel.

### 6. Delivery semantics for M1 (minimal and honest)

- **At-most-once, online delivery.** The broker fans out a published envelope to the
  currently-connected authorized subscribers. A peer that is offline at publish time
  **misses** that message in M1.
- **Ordering:** per-channel, per-sender order is preserved (single WS, sequential
  fan-out). No global ordering across senders is promised.
- **Retention:** none in M1 (in-memory). Documented limitation.
- **Why this is acceptable for the M1 bar:** CodeSpeak's PWA and agent are both online
  during a live session; streaming progress to a connected subscriber is exactly the
  online case. Durable retention + at-least-once replay for a briefly-offline peer is a
  **named follow-up** (the first thing to add after M1), backed by the store interface
  from decision 3. Calling M1 "at-most-once, online" is the honest guarantee; promising
  more without building it would be the defect.

This is a deliberate minimum, flagged to the user, not an accident.

### 7. The ntfy-easy setup flow (concretely)

Stand it up:
```
docker run -p 8080:8080 doublethink            # or: ./doublethink serve
```
Secure defaults out of the box (SECURITY.md req 6): a private channel is gated by
its secret; there is no wide-open admin surface to lock down; TLS is via a reverse
proxy, and the quickstart documents the secure path first.

Create a private channel (self-service, one request, no operator):
```
doublethink channel create --prefix codespeak
#   channel: codespeak/<random-id>
#   secret:  <high-entropy shared secret>
```
The client mints the secret, derives K_auth from it, and registers only the channel
id + K_auth with the broker (never the secret). Share the secret with the other
party over a trusted channel. Both parties then connect with the secret: each does a
WS connect, answers the broker's challenge from K_auth, and publishes/receives
envelopes on that socket, encrypting payloads with the key derived from the same
secret. Anyone who holds the secret can join; no one else can; the broker cannot
read the traffic.

Public/plaintext topic (ntfy parity), opt-in:
```
curl -d "hello" http://localhost:8080/publish/mytopic
curl -s http://localhost:8080/subscribe/mytopic     # SSE stream
```

### 8. Explicitly deferred past M1

So M1 scope stays small and honest:
- Hosted/multi-tenant offering and billing.
- Durable retention + at-least-once replay for offline peers (first follow-up).
- Forward secrecy / message-key ratchet.
- Multi-device per party.
- Clustering / horizontal scale / NATS-backed store.
- Web dashboard / admin UI.
- Federation.

---

## Repo and module layout (as built)

doublethink is cross-platform: it runs in Docker or as a single native binary.
There is deliberately **no Debian/.deb packaging and no systemd unit** (decided
2026-06-17): the project does not need them, and shipping them would be scope and
surface for no benefit at this stage.

```
doublethink/
  cmd/doublethink/             CLI: serve, channel create (flag-based)
  internal/broker/             core: channels, fan-out, subscriptions, delivery
  internal/transport/          WebSocket + HTTP/SSE handlers; one public surface
  internal/auth/               K_auth challenge/response, per-channel admission, state persistence
  internal/clientcrypto/       shared-secret HKDF + secretbox helpers for the CLIENT side + tests
  internal/envelope/           the fixed envelope type + (de)serialization
  Dockerfile                   multi-stage build -> distroless static image
  docker-compose.yml           serve from mounted source (default dev path)
  docker-compose.build.yml     run the built image
  scripts/smoke.sh             end-to-end smoke test of the real binary
  docs/index.html              project Pages site (+ disclaimer), robots.txt, sitemap.xml
  docs/DESIGN-M1.md            this file
  .github/workflows/ci.yml     go vet + go test + docker build + Release on tag
```

There is no separate admin or pairing surface: the keypair + invite-code + SAS
design was dropped (see the top of this doc), so `internal/pairing` and the
loopback admin API no longer exist. Channel creation is one self-service request
on the public surface.

Note: the broker does not need `internal/clientcrypto` to encrypt (it never sees plaintext);
that package exists for the **client/CLI** side and for tests that prove the broker
cannot read sealed payloads. Three similar lines beat a premature abstraction; the
store-behind-an-interface seam (decision 3) is the only forward-looking seam, and it
earns its place because retention is the very next milestone.

## Testing (exercises the security rules, not just happy path)

1. **Non-holder rejected:** a WS attach with a response computed from the wrong
   secret (or no valid response) to a private channel is refused (req 1).
2. **Secret bound to its own channel:** a correct response for channel X's secret,
   presented against channel Y, is refused (req 2).
3. **Broker-cannot-read-private-payload:** drive a real seal on the client side,
   assert the plaintext is absent from the forwarded blob and that a session from a
   different secret cannot open it; and that K_auth (what the broker holds) is not an
   encryption key (req 3, the differentiator).
4. **Honest failure / no existence leak:** an unknown channel and a wrong response
   return identical refusals (req 5).
5. **Streaming:** many `progress` messages arrive incrementally to a connected
   subscriber, not batched.
6. **Control bypasses HOL:** while one subscriber's queue is full, a `control`
   delivery to a healthy subscriber is not blocked.
7. **Contract conformance:** the fixed envelope round-trips intact and in order.
8. **Public topic parity:** ntfy-style POST/SSE works for an opt-in plaintext topic.
9. **Replay:** a captured challenge response does not authenticate a fresh challenge.

## Self-critique (attack the design before a reviewer does)

- **Biggest weakness: we own broker correctness.** A purpose-built core means fan-out,
  ordering, and backpressure bugs are ours. Mitigation: minimal M1 guarantee + the test
  matrix above; the store seam lets us swap to a hardened core later. If M1 throughput
  or durability needs grow, revisit the NATS decision honestly.
- **Metadata leak is real.** The broker sees channel id, `type`, `id`, `ts`, sizes, and
  timing. A hostile reviewer will say "broker-blind" overstates it: it is
  **payload-blind**, not metadata-blind. The docs say exactly that.
- **Symmetric secret: no sender authenticity, no single-party revoke.** Either holder
  of S can produce any message and derive any key, so the protocol cannot attribute a
  message to one of the two parties, and you cannot drop one party without rotating S
  (recreate the channel). Stated plainly; acceptable for "two parties who share a
  secret trust each other", wrong for a group or signed-message setting.
- **No forward secrecy.** Disclosure of S exposes past captured ciphertext. A ratchet
  is a named follow-up; cutting it is a deliberate scope call, not an oversight.
- **MITM on the out-of-band share.** Whoever intercepts S in transit can join. This is
  inherent to sharing a secret out of band (the same risk as leaking an ntfy topic,
  but S has real entropy). A high-assurance mode with a verified fingerprint (the
  dropped SAS idea) is a future option, not an M1 requirement.

## Build sequence for M1 (as built)

1. Lock the **broker-blind E2E** posture; record it as decided in SECURITY.md.
2. `internal/envelope`: the fixed envelope type + JSON round-trip + tests.
3. `internal/broker`: in-memory channels, subscriptions, fan-out, per-sender ordering;
   the store interface seam. Tests 5, 6, 7.
4. `internal/clientcrypto`: shared-secret derivation (`GenerateSecret`, K_auth, K_enc,
   per-direction keys, challenge response, seal/open). Test 3, 9.
5. `internal/auth`: store K_auth per channel; challenge/response admission with
   constant-time compare; uniform denial; persistence. Tests 1, 2, 4.
6. `internal/transport`: self-service `POST /channel` + WebSocket attach + HTTP/SSE
   public path on one surface. Test 8.
7. `cmd/doublethink`: `serve` and `channel create` (mints the secret, registers
   K_auth); the setup flow from decision 7.
8. Distribution: `Dockerfile` (multi-stage to distroless), `docker-compose.yml`
   (serve from mounted source) and `docker-compose.build.yml` (run the image); the
   native single-binary path is just `go build`. No Debian/.deb, no systemd.
9. Publish: `docs/index.html` with the disclaimer on every required surface; CI
   (vet + test + docker build + Release on tag); GitHub repo + Pages + hub / profile /
   website cards. (CodeSpeak adopts the published broker and adapts its client to the
   shared-secret credential.)
