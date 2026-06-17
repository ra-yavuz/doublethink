# doublethink

**A secure publish/subscribe message broker that is as easy to stand up as
[ntfy](https://ntfy.sh), but with real authentication and genuinely private
channels.** ntfy is everywhere because it is trivial to use; its topics are also
effectively public. doublethink keeps the minutes-to-set-up ergonomics and adds
the thing ntfy deliberately omits: identity, authentication, and private
channels you can trust with real traffic.

> **Status: M1 working, pre-release.** The prior-art research is done
> ([`docs/RESEARCH.md`](docs/RESEARCH.md)) and the first milestone is implemented
> and tested: a runnable broker you can stand up, create a private channel on with
> one request, and have two parties who share its secret exchange
> end-to-end-encrypted streamed messages the broker cannot read, plus opt-in
> plaintext topics. The design is in
> [`docs/DESIGN-M1.md`](docs/DESIGN-M1.md). It is cross-platform: run it in Docker
> or as a single native binary. No hosted offering yet. Start with
> [`GOAL.md`](GOAL.md) for the canonical endgoal.

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
channel can never be reached through the open path. See
[`docs/DESIGN-M1.md`](docs/DESIGN-M1.md) for the crypto and threat model.

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
