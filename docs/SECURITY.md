# doublethink: Security Expectations

Security is doublethink's reason to exist. ntfy is easy but its topics are
effectively public; doublethink's whole value is being ntfy-easy **and**
trustworthy with private traffic. This document states the security posture the
project commits to. It defines requirements and a threat model; it does not pick
the cryptographic mechanism, that is a design-phase decision (see
[`../GOAL.md`](../GOAL.md) open questions) to be made deliberately and, given the
stakes, cross-checked rather than guessed.

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

## Decisions that must be made on purpose (not defaulted)

These are the load-bearing security decisions. Each must be chosen deliberately
in the design phase and documented; none may be settled by accident or by
copying a snippet:

- **End-to-end vs in-transit.** Are private-channel payloads end-to-end
  encrypted between the authorised peers (broker never sees plaintext), or
  TLS-protected in transit with the broker able to read plaintext? CodeSpeak
  carries code context and shell commands over this channel, so this choice has
  real consequences and must be stated explicitly to users.
- **Authentication and key exchange mechanism.** How a party proves identity and
  how channel keys are established. Must interoperate with CodeSpeak's Device ID
  / Session Token / public-private key-pair pairing (see
  [`CODESPEAK-REQUIREMENTS.md`](CODESPEAK-REQUIREMENTS.md)).
- **Channel namespacing and access mapping.** How channel names map to authorised
  parties, and how name guessing or enumeration is prevented for private
  channels.
- **Replay and ordering guarantees.** What is promised about duplicate delivery,
  ordering per channel, and a peer that was briefly offline.
- **Operator trust model.** For a hosted doublethink, what the operator can and
  cannot see, stated plainly to the user. (If end-to-end encryption is chosen,
  this is bounded by design; if not, it must be disclosed.)

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

## Out of scope (stated so it is not mistaken for covered)

- doublethink does not promise to defend against a fully compromised endpoint: if
  an authorised party's own device/keys are stolen, that party's channels are
  compromised. Endpoint security is the user's responsibility.
- doublethink does not vouch for message *content*; it transports payloads. What
  CodeSpeak or any other consumer puts in a payload is that consumer's concern.

This is the security baseline any doublethink implementation must meet or exceed.
Given the subject matter (auth and crypto), the implementation of these
requirements should be reviewed and cross-checked before release, not shipped on
a single author's say-so.
