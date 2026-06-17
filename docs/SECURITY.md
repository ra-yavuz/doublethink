# doublethink: Security Expectations

Security is doublethink's reason to exist. ntfy is easy but its topics are
effectively public; doublethink's whole value is being ntfy-easy **and**
trustworthy with private traffic. This document states the security posture the
project commits to: its requirements, the mechanism it uses, and its honest
limits.

Security here is a primary goal, held on equal footing with ease of use. Where
the two appear to conflict, the resolution is a design problem to solve, not a
licence to weaken security for convenience.

## Security requirements

1. **Authentication is mandatory for private channels.** A private channel
   admits only authenticated, authorised parties to publish or subscribe.
   Unauthenticated requests are rejected outright, not downgraded to read-only or
   silently ignored.
2. **Authorisation is per-channel.** Being authenticated is not being authorised.
   A party authenticated to the broker still only reaches the channels it is
   authorised for. CodeSpeak's pairing maps one PWA + one agent to their channel
   and nothing else.
3. **Confidentiality of private channels.** Contents of a private channel are
   readable only by its authorised parties. Other parties on the same broker, and
   passive observers of the network, cannot read them.
4. **Integrity in transit.** A message delivered on a channel is the message that
   was sent: not altered, not injected by an unauthorised party, not replayable
   in a way that causes a duplicated effect where ordering/correlation matters.
5. **Honest failure.** When access is denied or authentication fails, the broker
   refuses clearly. It does not silently drop, silently succeed, or leak via
   error messages whether a private channel exists.
6. **No weak default.** Setup must be ntfy-easy, but the easy path must not be the
   insecure path. A user who follows the simplest setup must still get
   authenticated, confidential private channels, not a wide-open broker they are
   expected to lock down later.

## How the security works

The load-bearing mechanisms behind the requirements above:

- **Authentication: shared-secret challenge-response.** A private channel is gated
  by one high-entropy shared secret S that the two parties hold. The broker stores
  `K_auth = HKDF(S, "auth")` (a different HKDF label than the encryption key) and
  admits a client by a challenge-response proving possession of `K_auth`; S itself
  is never sent to the broker. Creating a channel is a single self-service request,
  no operator, no pairing ceremony.
- **End-to-end encryption (broker-blind).** Private-channel payloads are encrypted
  under `K_enc = HKDF(S, "enc")` (then per-direction NaCl secretbox keys). Because
  S is never sent to the broker and `K_enc` is a different HKDF label than the
  `K_auth` the broker stores, the broker can authenticate holders of S but cannot
  derive `K_enc`. It relays ciphertext it cannot read. Honest scope: the broker is
  **payload-blind, not metadata-blind**. It still sees the channel id, the
  envelope's `type`/`id`/`ts`, and ciphertext sizes and timing.
- **Channel naming.** A private channel id is high-entropy and unguessable, so it
  resists enumeration, but the id is never the security boundary; the secret is.
  Knowing a channel name grants nothing.
- **Replay and ordering.** Ephemeral channels are at-most-once and online-only (a
  peer offline at publish time misses the message). Retained channels (opt-in)
  store messages with a per-channel monotonic sequence number; a reconnecting peer
  replays exactly the messages with a higher sequence than the last it saw, in
  order, then resumes live. Retention is bounded by a TTL and per-channel and
  per-account caps (oldest evicted).
- **Operator trust model, stated plainly.** The operator (and anyone with database
  access) can see, per channel: its id, each message's `type`/`id`/`ts`, ciphertext
  sizes, counts, and timing; and for retained channels, the stored ciphertext
  blobs. The operator CANNOT read any private-channel payload, that requires the
  shared secret, which the broker never holds. Retention widens the visible
  metadata; that is disclosed here, not defaulted away.

## Threat model (what the security posture must withstand)

- **A stranger who knows a channel name.** Knowing a private channel's name must
  not grant read or write access. Access is gated by authentication and
  authorisation, never by name-secrecy alone. (This is the specific failure mode
  of ntfy that doublethink must not reproduce.)
- **Another authenticated party on the broker.** A party authenticated for its
  own channels must not be able to read or write a private channel it is not
  authorised for.
- **A passive network observer.** Must not be able to read private-channel
  contents in transit.
- **A misconfiguring operator.** The easy setup path must not leave a broker
  unintentionally open. Insecurity must require a deliberate, informed choice,
  not be the default outcome of following the quickstart.

## Identity tiers and retention (M2)

doublethink M2 adds three tiers of identity and an opt-in retention store. The
security-relevant points:

- **Three tiers.** Anonymous (ephemeral private channels and public plaintext
  topics only, under per-IP rate/connection limits); an **account API key**
  (`POST /account`; required to create a *retained* channel; quotas attributed to
  it; the broker stores only a hash of the key, never the key); and an **operator
  admin key** (set in the broker's environment as `DOUBLETHINK_ADMIN_KEY`; raises
  limits for preferred channels and reads usage metadata). The admin key grants
  metadata/limit control ONLY, never payload access. It is fail-safe disabled when
  unset, never logged, and compared in constant time.
- **No anonymous retained channels.** Retention consumes storage, so it requires
  an account that quotas can be charged against. Anonymous use stays unbounded only
  in the ephemeral/no-storage sense, under tight per-IP limits.
- **Retained ciphertext is user data.** It expires (TTL), can be evicted (ring
  buffer) or deleted, and counts to quota. It is stored as ciphertext the broker
  cannot read. Treat it, and the metadata around it, accordingly.

## Out of scope (stated so it is not mistaken for covered)

- doublethink does not promise to defend against a fully compromised endpoint: if
  an authorised party's own device/keys are stolen, that party's channels are
  compromised. Endpoint security is the user's responsibility.
- doublethink does not vouch for message *content*; it transports payloads. What
  CodeSpeak or any other consumer puts in a payload is that consumer's concern.
- **No per-sender non-repudiation and no forward secrecy (yet).** The shared-secret
  model is symmetric: any holder of S can both send and read, so a message does not
  prove which party sent it, one party cannot be evicted without rotating S, and a
  leaked S exposes past retained ciphertext. These are deliberate, documented
  limits, not oversights; stronger properties are a future step.

This is the security baseline any doublethink implementation must meet or exceed.
Given the subject matter (auth and crypto), the implementation of these
requirements should be reviewed and cross-checked before release, not shipped on
a single author's say-so.
