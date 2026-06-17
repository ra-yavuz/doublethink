# What CodeSpeak requires from doublethink

This is doublethink's view of its first consumer's needs. It mirrors
`~/github-ra-yavuz/codespeak/docs/DOUBLETHINK-CONTRACT.md`. The two must stay
consistent; if they drift, that is a defect to fix, not tolerate.

CodeSpeak is being built against a **mock** that implements exactly the contract
below. doublethink's first acceptance bar is: a real doublethink that satisfies
this contract can replace CodeSpeak's mock with no CodeSpeak code change.

## The minimum CodeSpeak needs

1. **Named-channel pub/sub.** Parties subscribe to named channels and publish
   messages to them.
2. **Private channels with authentication.** A private channel admits only an
   authenticated, authorised party to publish or subscribe; unauthenticated
   access is rejected. CodeSpeak uses private channels exclusively. This is the
   capability ntfy does not safely provide and the reason CodeSpeak needs
   doublethink rather than ntfy.
3. **Bidirectional, asynchronous delivery.** Either party can send at any time;
   not request/response-locked. This is what lets CodeSpeak support barge-in,
   overlapping requests, and a background task queue.
4. **Streaming / incremental delivery.** A long-running task emits many messages
   over time; the subscriber receives them as they arrive, not batched at the
   end.
5. **Confidentiality of private channels.** Contents of a private channel are
   confidential to its authorised parties; other parties on the broker cannot
   read them. CodeSpeak carries code context, findings, and commands here.
6. **Pairing-friendly identity.** doublethink must let CodeSpeak bind one PWA
   instance to one local-agent installation (CodeSpeak's Device ID / Session
   Token / key-pair pairing) and enforce that only that pair uses their channel.
7. **ntfy-easy setup.** Standing up doublethink and pointing CodeSpeak at it must
   be about as easy as ntfy. Setup friction here is CodeSpeak onboarding friction.

## The message envelope CodeSpeak assumes

CodeSpeak sends and receives a small JSON envelope on a channel. Field names are
**provisional**; doublethink confirming or revising them is a deliberate contract
change, communicated back to CodeSpeak, not a silent edit on either side.

```json
{
  "channel": "codespeak/<paired-id>",
  "type": "request | progress | result | summary | control | error",
  "id": "correlation-id-for-a-task",
  "payload": { "...": "type-specific" },
  "ts": "ISO-8601 timestamp"
}
```

doublethink's obligations toward the envelope: deliver it intact, in order per
channel where feasible, to the right authenticated subscribers, and keep
private-channel payloads confidential. doublethink transports `payload` opaquely;
it does not need to understand or validate it.

## Change protocol

CodeSpeak assumes doublethink will exist and meet this contract. If CodeSpeak
development reveals a need beyond it, the CodeSpeak side stops and raises it with
the user so the requirement is integrated here deliberately. Tightening or
extending this contract is fine when done on purpose; either side silently
diverging is not.

See also [`SECURITY.md`](SECURITY.md), which is the security backing for
requirements 2, 5, and 6 above.
