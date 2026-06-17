# doublethink: M1 Design

**Status: proposed (2026-06-17).** This is the architecture for doublethink's
first implementation milestone. It is downstream of [`../GOAL.md`](../GOAL.md),
[`SECURITY.md`](SECURITY.md), [`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md),
and the verified verdict in [`RESEARCH.md`](RESEARCH.md). One decision in here
(committing to broker-blind E2E) is reserved for the user per SECURITY.md and is
marked **PROPOSED** below; everything else follows from it.

## M1 acceptance bar (fixed)

A real doublethink that **replaces CodeSpeak's mock with zero CodeSpeak code
change.** The envelope is fixed and transported with `payload` opaque:

```json
{ "channel": "codespeak/<paired-id>", "type": "request|progress|result|summary|control|error",
  "id": "correlation-id", "payload": { }, "ts": "ISO-8601" }
```

If M1 satisfies the contract in [`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md),
it is done. Everything not needed for that bar is deferred (see the last section).

---

## Decisions

### 1. Language and dependencies: Go, near-stdlib

**Go, compiled to a single static binary.** Rationale: one static binary is the
literal shape of ntfy-ease (download, run, done); Go cross-compiles trivially for
the .deb this repo ships; `net/http` gives the HTTP + WebSocket server with almost
no dependencies; `golang.org/x/crypto/nacl/box` and `nacl/secretbox` give the exact
X25519 + XSalsa20-Poly1305 primitives the E2E model needs, from a maintained,
audited library; the attack surface stays small.

Dependency budget for M1, deliberately tiny:
- `net/http`, `crypto/*`, `encoding/json` from the stdlib.
- one WebSocket library (`nhooyr.io/websocket`, now `coder/websocket`: context-aware,
  small, modern) for the browser-facing socket.
- `golang.org/x/crypto/{nacl/box,nacl/secretbox,hkdf,blake2b}` for crypto.
- `modernc.org/sqlite` (pure-Go, no cgo) only if M1 needs persistence; M1 starts
  in-memory (see delivery semantics), so this may not land until retention does.

**Trade-off:** vs Rust, Go gives up some compile-time memory-safety strictness and
has GC pauses (irrelevant at this scale). It buys faster correct delivery and the
easiest single-binary + .deb story. The repo's other projects are shell/Python;
nothing constrains the language, so a network daemon picks the best fit, which is Go.

### 2. Transport: one WebSocket per peer, HTTP for publish-once

The PWA is a **browser**, so the client transport must be browser-native. That
rules out raw MQTT-over-TCP and NATS's native protocol. Choice:

- **Primary: a single WebSocket per connected peer**, carrying both directions.
  This is full-duplex by construction, supports streaming (many frames over time),
  and is the simplest thing a browser and a Go agent can both speak. The peer
  authenticates during the WS handshake (see 4b), then publishes and receives
  envelopes as WS messages on the same socket.
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

### 4. E2E crypto for private channels  **(PROPOSED, user-reserved decision)**

Per [`RESEARCH.md`](RESEARCH.md), TLS-only has no differentiation; the defensible
posture is **broker-blind end-to-end encryption** for private channels. This is the
one decision SECURITY.md reserves for the user; it is proposed here, not locked.

Model (crypto cross-checked against CODEX; corrections folded in):
- The two peers pair **out of band** (CodeSpeak's existing Device ID / Session Token /
  keypair pairing). During pairing each peer generates a **device identity bundle**:
  an **Ed25519** keypair (for signing / broker-attach auth, layer 4b) and an **X25519**
  keypair (for ECDH only). Peers exchange both **public** keys out of band. The broker
  never sees any private key. Keeping signing and ECDH keys separate avoids the footgun
  of treating an X25519 key as a signing key (it is not one).
- Each peer computes the X25519 ECDH shared secret of (my x25519 private, their x25519
  public), then derives a **channel secret** via **HKDF** with identity binding:
  `HKDF(ikm = ECDH, salt = channel_id, info = "doublethink-channel-v1" || sorted(x25519_pubA, x25519_pubB))`.
  Sorting the two public keys removes direction ambiguity; the version string and bound
  identities give domain separation and prevent identity-misbinding.
- **Per-sender payload keys**, not one shared key both peers encrypt under (a real
  footgun, no sender/nonce-domain separation):
  `K_{A->B} = HKDF(channel_secret, info = "payload A->B" || pubA || pubB)` and
  `K_{B->A} = HKDF(channel_secret, info = "payload B->A" || pubA || pubB)`.
  Each direction encrypts under its own key.
- Message `payload` is sealed with **NaCl secretbox (XSalsa20-Poly1305)** under the
  sender's per-direction key, with a per-message random 192-bit nonce (collision
  negligible; per-sender keys mean the two peers never share a nonce domain). Only the
  sealed ciphertext crosses the broker.
- **Note on what auth proves:** broker-attach auth (4b) proves "this device may attach
  to this channel," NOT "this ciphertext came from peer X." Per-sender keys give the
  receiver that sender-origin assurance at the payload layer (only the holder of
  `K_{A->B}` could have produced a message that opens under it). Do not conflate the two
  layers.

**What the broker can see** (metadata posture, stated plainly to users):
- the channel id, the envelope `type`, `id`, and `ts` (it routes and correlates on
  these; they are deliberately *outside* `payload`),
- ciphertext bytes, their size, and message timing.

**What the broker cannot see:** the `payload` plaintext, the channel key, or either
peer's private key.

**Key lifecycle for M1** (the part CODEX flagged as the real hardness):
- **Revocation = re-pair.** Re-running pairing produces fresh keypairs and a fresh
  channel key; the old key is dead. M1 supports this; it does not support silent
  in-band rekey.
- **Forward secrecy: DEFERRED and documented.** M1 uses a static channel key, so
  compromise of a peer's long-term key exposes past captured ciphertext. This is a
  known, written limitation, not a silent gap. A ratchet (Double Ratchet / X3DH-style)
  is a named follow-up, not an M1 deliverable. Cutting it is what keeps M1 shippable;
  shipping it half-built would be worse.
- **Multi-device: DEFERRED.** The contract is one PWA to one agent. Multi-device key
  distribution is out of M1 scope and documented as such.

### 4b. Broker-layer authentication and authorization (separate from E2E)

E2E protects contents; it does **not** decide who may attach to a channel. SECURITY.md
requires that knowing a channel name grants nothing. So, independent of E2E:

- At pairing, the broker registers, as the channel's authorized set, each peer's
  **Ed25519 identity public key** (from the device bundle in decision 4). A per-channel
  high-entropy token may additionally gate the initial attach, but the token alone is
  never sufficient (bearer-token leakage must not equal channel access).
- To connect, a peer opens the WebSocket and completes a **signed challenge**: the
  broker sends a random nonce; the peer signs it with its **Ed25519 identity private
  key** (the dedicated signing key, never the X25519 ECDH key). The broker verifies the
  signature against an Ed25519 public key in that channel's authorized set. A connection
  that cannot produce a valid signature for an authorized key is **rejected outright**
  (SECURITY.md req 1, honest failure req 5).
- **Authorization is per-channel** (req 2): being able to authenticate says nothing
  about *which* channel; the signed-public-key must be on that channel's authorized set.
  Another authenticated party cannot attach to a channel it is not registered on.

This makes the gate **authentication + authorization**, never name-secrecy.

### 5. Channel naming and anti-enumeration

- Public/plaintext topics: ntfy-style human names, openly readable/writable (opt-in).
- Private channels: the **routing id** the broker stores is a high-entropy random id
  (for example 128-bit, base32), not a guessable human string. CodeSpeak's
  `codespeak/<paired-id>` maps to such an id at pairing time; `<paired-id>` is the
  random id, not a user-chosen name. Even so, the id is **not** the security boundary,
  authz (4b) is; the random id only removes enumeration as a cheap attack. The broker
  returns identical "denied" responses for "wrong channel" and "no such channel" so it
  does not leak channel existence (req 5).

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
Secure defaults out of the box (SECURITY.md req 6): private channels require auth;
there is no wide-open admin; TLS is via `--tls` or a reverse proxy, and the quickstart
documents the secure path first.

Create a private channel + pair two peers:
```
doublethink channel create --private            # prints channel id + a pairing code
# peer A (e.g. the agent):  doublethink pair <pairing-code>   -> generates keypair, registers pubkey
# peer B (e.g. the PWA):    enters the same pairing code      -> generates keypair, registers pubkey
```
Each peer now holds its own private key and the channel id; the broker holds both
public keys and the channel's authorized set. Neither the pairing code nor the channel
key is stored by the broker after pairing. Publishing is then a WS connect + signed
challenge + send envelope; subscribing is the same connection receiving envelopes.

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

## Repo and module layout (matches this tree's conventions)

```
doublethink/
  bin/doublethink              thin launcher / or installed Go binary entrypoint
  cmd/doublethink/main.go      CLI: serve, channel, pair  (cobra-free, flag-based)
  internal/broker/             core: channels, fan-out, subscriptions, delivery
  internal/transport/          WebSocket + HTTP/SSE handlers
  internal/auth/               challenge/response, per-channel authz, channel tokens
  internal/crypto/             X25519/HKDF/secretbox helpers for the CLIENT side + tests
  internal/envelope/           the fixed envelope type + (de)serialization
  systemd/doublethink.service  daemon unit (startup log carries the disclaimer)
  debian/                      control/changelog/postinst/postrm/source/format/compat/rules
  scripts/build-deb.sh         portable .deb build (template from inhibit-charge)
  docs/index.html              project Pages site (+ disclaimer), robots.txt, sitemap.xml
  docs/DESIGN-M1.md            this file
  .github/workflows/ci.yml     go vet + go test + build .deb + Release on tag
```

Note: the broker does not need `internal/crypto` to encrypt (it never sees plaintext);
that package exists for the **client/CLI** side and for tests that prove the broker
cannot read sealed payloads. Three similar lines beat a premature abstraction; the
store-behind-an-interface seam (decision 3) is the only forward-looking seam, and it
earns its place because retention is the very next milestone.

## Testing (exercises the security rules, not just happy path)

1. **Unauthenticated rejected:** a WS connect with no/invalid signature to a private
   channel is refused (req 1).
2. **Other-authenticated-party rejected:** a peer authorized for channel X cannot
   attach to channel Y (req 2).
3. **Broker-cannot-read-private-payload:** drive a real seal on the client side, assert
   the broker only ever holds ciphertext, and that a decrypt with the wrong key fails
   (req 3, the differentiator).
4. **Honest failure / no existence leak:** "wrong channel" and "no such channel" return
   identical refusals (req 5).
5. **Streaming:** many `progress` messages arrive incrementally to a connected
   subscriber, not batched.
6. **Control bypasses HOL:** while peer A streams `progress`, a `control` from peer B is
   delivered promptly.
7. **Contract conformance:** the exact CodeSpeak envelope round-trips intact and in
   order, proving the mock-replacement bar.
8. **Public topic parity:** ntfy-style POST/SSE works for an opt-in plaintext topic.

## Self-critique (attack the design before a reviewer does)

- **Biggest weakness: we own broker correctness.** A purpose-built core means fan-out,
  ordering, and backpressure bugs are ours. Mitigation: minimal M1 guarantee + the test
  matrix above; the store seam lets us swap to a hardened core later. If M1 throughput
  or durability needs grow, revisit the NATS decision honestly.
- **Metadata leak is real.** The broker sees channel id, `type`, `id`, `ts`, sizes, and
  timing. A hostile reviewer will say "broker-blind" overstates it: it is
  **payload-blind**, not metadata-blind. The docs must say exactly that. Hiding `type`
  from the broker is hard because CodeSpeak may rely on the broker routing by it; if it
  does not, moving `type`/`id` inside the sealed payload is a tightening worth
  evaluating before locking the contract.
- **No forward secrecy in M1.** Long-term key compromise exposes past captured
  ciphertext. Stated as a written limitation; a reviewer who needs FS must wait for the
  ratchet follow-up. Cutting it is a deliberate scope call, not an oversight.
- **Pairing-code MITM.** If the out-of-band pairing code is intercepted before both
  peers register, an attacker could register its own key. Mitigation: short-lived,
  single-use pairing codes and (like SimpleX) binding the channel/connection to a
  cert/key fingerprint the peers verify. This is the sharpest practical attack and must
  be designed carefully, not hand-waved.
- **Assumption to verify against CodeSpeak:** that the broker is allowed to read
  `type`/`id`/`ts` for routing. If CodeSpeak wants those hidden too, decision 4's
  metadata posture changes. This is a contract question to confirm, not to assume.

## Build sequence for M1

1. Lock the **broker-blind E2E** posture with the user; update SECURITY.md from "open"
   to "decided". Confirm the broker-reads-`type`/`id`/`ts` assumption with CodeSpeak.
2. `internal/envelope`: the fixed envelope type + JSON round-trip + tests.
3. `internal/broker`: in-memory channels, subscriptions, fan-out, per-sender ordering;
   the store interface seam. Tests 5, 6, 7.
4. `internal/auth`: channel tokens, challenge/response, per-channel authz. Tests 1, 2, 4.
5. `internal/transport`: WebSocket peer connection + HTTP/SSE public path. Test 8.
6. `internal/crypto` (client side) + a reference CLI client that seals/opens, proving
   test 3 (broker holds only ciphertext).
7. `cmd/doublethink`: `serve`, `channel create`, `pair`; the setup flow from decision 7.
8. Point CodeSpeak's client at it in place of the mock; prove zero-change replacement.
9. Packaging: `scripts/build-deb.sh`, `debian/`, `systemd/`, `docs/index.html` with the
   disclaimer on every required surface; CI; then the publish pipeline.
