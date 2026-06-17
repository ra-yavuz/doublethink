# doublethink: Project Goal

This is the canonical statement of what doublethink is for. It is the source of
truth for the project; the README, the requirements, and any future
implementation are downstream of it.

## One sentence

**doublethink is a secure publish/subscribe message broker that is as easy to
stand up and use as ntfy, but with real authentication and genuinely private
channels.**

## The gap it fills

[ntfy](https://ntfy.sh) is wonderful because it is trivial: pick a topic, POST to
it, subscribe to it, done. That simplicity is exactly why it is everywhere. But
ntfy topics are effectively public: anyone who knows (or guesses) a topic name
can read and write it. There is no real notion of "this channel belongs to these
two parties and no one else."

doublethink keeps ntfy's setup-in-minutes simplicity and adds the thing ntfy
deliberately does not have: **identity and private channels.** A channel can be
private, scoped to authenticated parties, with unauthenticated access rejected.
You get the ergonomics of ntfy and the trust model of something you would
actually put real traffic through.

The bet: there is a real niche for "ntfy, but I can trust it with private data,"
and serving that niche well could grow into a hosted offering with income
potential over time. That commercial possibility is a reason to make doublethink
its own standalone project rather than a buried component of one app.

> **Research note (open, not yet done).** Before committing to build,
> doublethink's design phase must check whether something already occupies this
> exact gap: a broker that is *both* ntfy-easy *and* genuinely
> private/authenticated. Candidates to evaluate include ntfy itself (with its
> access-control features), MQTT brokers (Mosquitto, EMQX) with auth, NATS with
> accounts/nkeys, and managed pub/sub services. The question is not "does a
> secure broker exist" (many do) but "does a secure broker exist that is as
> frictionless to set up and use as ntfy." If one does, doublethink's value
> proposition must be reconsidered honestly. See
> [`docs/RESEARCH.md`](docs/RESEARCH.md).

## What doublethink must be

1. **A pub/sub broker.** Named channels (topics). Parties subscribe to channels
   and publish messages to them.
2. **Secure by design.** Channels can be private. A private channel admits only
   authenticated, authorised parties to publish or subscribe; unauthenticated
   access is rejected. Public channels may also exist for ntfy-style open use.
3. **As easy as ntfy.** Self-hostable and pointable-at with minimal ceremony.
   Setup friction is the enemy; ease of use is a primary design goal, on par
   with security, not traded against it.
4. **Bidirectional and asynchronous.** Either party can send at any time; the
   channel is not request/response-locked. Suited to real-time, two-way,
   long-lived conversations between peers.
5. **Streaming-friendly.** A sender can emit many messages over time and a
   subscriber receives them incrementally, not batched.
6. **Confidential in transit.** Private-channel contents are confidential to the
   authorised parties; other parties on the broker cannot read them. (Whether the
   broker operator can ever see plaintext, or whether payloads are end-to-end
   encrypted between peers, is a core design decision, see open questions.)

## Why it exists right now: CodeSpeak needs it

The immediate, concrete driver is **CodeSpeak**
(`~/github-ra-yavuz/codespeak/`), a voice-first coding companion whose PWA and
local agent must talk over a secure channel. CodeSpeak does not want to ship its
own broker, and it needs more than ntfy can safely give: private, authenticated,
bidirectional, streaming channels between a paired app and agent.

doublethink's **first job** is to satisfy CodeSpeak's contract. That contract is
mirrored on doublethink's side in
[`docs/CODESPEAK-REQUIREMENTS.md`](docs/CODESPEAK-REQUIREMENTS.md), and on
CodeSpeak's side in `~/github-ra-yavuz/codespeak/docs/DOUBLETHINK-CONTRACT.md`.
The two must stay consistent.

Important sequencing: **CodeSpeak is being built first, against a mock of
doublethink that implements this contract.** doublethink is built in parallel.
When doublethink is ready and meets the contract, CodeSpeak swaps the mock for
the real broker with no other change. If CodeSpeak discovers it needs something
beyond the current contract, that requirement is brought back into doublethink
deliberately, not bolted onto CodeSpeak's mock.

CodeSpeak is the first consumer, not the only intended one. doublethink is meant
to be generally useful to anyone who wants ntfy's ease with real privacy.

## What doublethink is NOT

- **Not** a CodeSpeak-internal module. It is a standalone, independently useful
  project with its own repo, releases, and project page. CodeSpeak is its first
  customer, not its owner.
- **Not** a reimplementation of ntfy. It borrows ntfy's ease-of-use bar and adds
  what ntfy intentionally omits. If the research phase finds an existing tool
  already at this exact intersection, doublethink reconsiders rather than
  duplicates.
- **Not** finished thinking. This document fixes the goal; the mechanism
  (transport, auth scheme, crypto model, hosting) is deliberately still open and
  is the subject of the design and research phase.

## Endgoal, stated plainly

A person should be able to: stand up doublethink about as fast as they would
stand up ntfy; create a private channel bound to specific authenticated parties;
have those parties exchange messages bidirectionally, asynchronously, and
streamed, with confidence that no one else on the broker can read or write that
channel; and, if they want, do all of this against a hosted doublethink they pay
for instead of self-hosting. CodeSpeak proves the first real use of that
capability; the niche of "ntfy you can trust with private traffic" is the
broader prize.

## Open design questions (to be answered in the design phase, not guessed)

- Transport: WebSocket, MQTT, NATS, plain HTTP long-poll/SSE, or a custom one.
- Authentication and key exchange for private channels.
- Whether payloads are end-to-end encrypted between peers, or only TLS-in-transit
  with the broker able to see plaintext.
- Channel naming/namespacing and how party-identity maps onto channel access.
- Delivery guarantees: at-least-once vs at-most-once, ordering, retention, and
  behaviour for a party that was briefly offline.
- Self-hosted-only vs also-hosted-service, and what the hosted/commercial shape
  is if pursued.
- Where doublethink sits relative to ntfy/MQTT/NATS after the research phase:
  build fresh, or build a thin trustworthy layer on top of one of them.
