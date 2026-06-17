# doublethink

**A secure publish/subscribe message broker that is as easy to stand up as
[ntfy](https://ntfy.sh), but with real authentication and genuinely private
channels.** ntfy is everywhere because it is trivial to use; its topics are also
effectively public. doublethink keeps the minutes-to-set-up ergonomics and adds
the thing ntfy deliberately omits: identity, authentication, and private
channels you can trust with real traffic.

> **Status: specification.** This repository currently contains the project
> definition, not an implementation. Start with [`GOAL.md`](GOAL.md), the
> canonical endgoal. The mechanism (transport, auth scheme, crypto model,
> hosting) is deliberately still open and is the subject of the design and
> research phase.

## Security is the point, not a feature

doublethink exists because "ntfy, but I can trust it with private data" is a real
need. That makes security a primary, non-negotiable design goal, held on equal
footing with ease of use, never traded against it:

- Private channels admit only authenticated, authorised parties. Unauthenticated
  access is rejected.
- Private-channel contents are confidential to the authorised parties; other
  parties on the broker cannot read or write them.
- Whether the broker operator can ever see plaintext, or whether payloads are
  end-to-end encrypted between peers, is a core design decision being made
  deliberately (see [`GOAL.md`](GOAL.md) open questions), not defaulted away.

The full security expectations are in [`docs/SECURITY.md`](docs/SECURITY.md).

## Why it exists right now: CodeSpeak

The immediate driver is [CodeSpeak](https://github.com/ra-yavuz/codespeak), a
voice-first coding companion whose PWA and local agent must talk over a secure,
private, bidirectional, streaming channel, more than ntfy can safely provide.
doublethink's first job is to satisfy CodeSpeak's contract, mirrored here in
[`docs/CODESPEAK-REQUIREMENTS.md`](docs/CODESPEAK-REQUIREMENTS.md). CodeSpeak is
being built first against a **mock** of doublethink that implements that
contract; doublethink is built in parallel and swapped in when ready. CodeSpeak
is the first consumer, not the only intended one: doublethink is meant to be
generally useful to anyone who wants ntfy's ease with real privacy.

## Documents

| Document | What it pins down |
|---|---|
| [`GOAL.md`](GOAL.md) | The canonical endgoal of doublethink. |
| [`docs/SECURITY.md`](docs/SECURITY.md) | The security expectations and threat model. |
| [`docs/CODESPEAK-REQUIREMENTS.md`](docs/CODESPEAK-REQUIREMENTS.md) | The minimum CodeSpeak needs from doublethink, and the message envelope it assumes. |
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | The open question of whether an existing tool already fills this exact gap. |

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

Full legal license: see [`LICENSE`](LICENSE) (MIT) once published.

## Author

[Ramazan Yavuz](https://ramazan-yavuz.tr). Part of a set of independent,
open-source tools published at [ra-yavuz.github.io](https://ra-yavuz.github.io/).
