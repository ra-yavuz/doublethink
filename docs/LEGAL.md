# doublethink: terms, acceptable use, and the public instance

This document covers two different things, kept separate on purpose:

1. **The software** (this repository): what you may do with the code, and the
   no-warranty terms under which it is provided.
2. **The public instance** at `api.caleidoscode.io`: a free, best-effort service
   the author runs. It can be changed or shut off at any time. If you depend on
   it, self-host instead - that is exactly what the software is for.

If you only self-host doublethink, sections about the public instance do not
apply to you; you are the operator and the terms are between you and your users.

## The software (license and warranty)

doublethink is released under the [MIT License](../LICENSE). In particular it is
provided **as is, without warranty of any kind**, express or implied, including
but not limited to merchantability, fitness for a particular purpose, and
noninfringement.

By installing or running this software you accept that:

- You alone are responsible for how you deploy and secure it, for the data that
  flows through it, and for the consequences of any misconfiguration.
- The author and contributors are **not liable** for any harm, data loss, data
  exposure, security incident, or other damages, however caused.
- No security mechanism is perfect. doublethink aims for a strong, honestly
  documented security posture (see [`SECURITY.md`](SECURITY.md)), but evaluating
  whether it meets *your* requirements before trusting it with sensitive traffic
  is your responsibility, not the author's.

End-to-end encryption is a feature of the software, and using it is lawful. The
software is a general-purpose, dual-use communications tool, like TLS or any
messenger. Providing it does not make the author responsible for what others
choose to send through their own deployments.

## The public instance at `api.caleidoscode.io`

The author runs a public doublethink instance at `https://api.caleidoscode.io`
as a convenience (for the demo, for CodeSpeak, and for anyone who wants to try
it). The following terms apply to **that hosted instance only**.

### Free service, no SLA, no guarantees

- The public instance is provided **free of charge, with no service-level
  agreement and no guarantees** of availability, durability, performance, or
  data retention.
- It may be **slow, rate-limited, wiped, or unavailable** at any time, without
  notice. Retained data may be evicted by caps or TTL, and the entire store may
  be flushed. On a hard crash, up to roughly the last second of writes can be
  lost (see the durability note in [`ADMIN.md`](ADMIN.md)).
- **The author may modify, rate-limit, restrict, or shut down the public
  instance at any time, for any reason, without notice or liability.** Do not
  build anything you cannot afford to lose on top of it.
- If you want guarantees, **self-host**. doublethink is a single binary plus
  Redis and is designed to be stood up in minutes; the README shows how. Running
  your own instance puts you in full control of availability, retention, and
  policy.

### Acceptable use (public instance)

When you use the public instance, you agree **not** to use it to:

- do anything unlawful under applicable law, or to facilitate, plan, or carry out
  illegal activity;
- distribute malware, run command-and-control for malicious software, or
  coordinate attacks, intrusion, or other abuse of third-party systems;
- transmit child sexual abuse material or other content that is illegal to
  possess or distribute;
- harass, threaten, defraud, or infringe the rights of others;
- attempt to overwhelm, degrade, or circumvent the limits of the service, or to
  attack the service or its infrastructure.

Because private channels are end-to-end encrypted, the operator **cannot read
payloads** and does not monitor content. That is the point of the design, not a
loophole: it does not authorize illegal use, and it does not shift responsibility
for content away from the parties who send it. Operating an encrypted relay is
lawful; the parties who choose what to put through it remain responsible for it.

### Abuse and takedown

The operator acts as a **mere conduit / intermediary** for traffic on the public
instance and does not select or modify the content carried over private channels.

If you believe the public instance is being used for illegal activity or in
violation of the acceptable-use terms above, report it:

> **Abuse contact:** abuse@caleidoscode.io

Because payloads are end-to-end encrypted, the operator cannot read message
content and therefore acts on **channel identifiers and metadata**, not on
content review. A report should identify the **channel id** involved (and any
relevant timing). The operator can then disable or delete that channel by id (the
id is visible to the operator via the admin API; the payload is not). On a valid
report, or on a competent authority's lawful request, the operator will take down
the identified channel.

This abuse process and the intermediary posture are how a free encrypted relay
stays on the right side of intermediary-liability rules (mere-conduit safe
harbour, and the EU Digital Services Act's notice-and-action expectations) while
preserving end-to-end encryption: the operator cannot police content it cannot
read, but it can and will act on identified channels.

### Privacy and statistics (GDPR)

The public instance is operated in line with the GDPR. Concretely:

- **No payload access.** Private-channel payloads are end-to-end encrypted; the
  operator cannot read them.
- **Minimal metadata.** The broker necessarily processes channel ids, message
  sizes/timing, and (for retained channels) encrypted blobs, plus transport-level
  data (e.g. source IP) for rate-limiting and abuse handling. This is the minimum
  needed to run and protect the service.
- **Aggregate, anonymous statistics only.** The public `GET /stats` endpoint
  exposes only aggregate counts (number of channels, retained messages, bytes,
  etc.). It **does not** expose IP addresses, channel ids, referrer URLs, or any
  data that identifies a person or a site using the broker. There is **no
  per-domain or per-IP usage list** published by default; such a list is not
  served because it would be hard to reconcile with data-minimisation and would
  risk identifying users. If a domain-usage signal is ever added, it would be
  **opt-in** and limited to a coarse registrable domain, never IPs or full
  referrers.

For privacy questions about the public instance, use the abuse contact above.

---

These terms govern the hosted convenience instance and the no-warranty provision
of the software. They are not legal advice; an operator self-hosting doublethink
for others should publish their own terms appropriate to their jurisdiction and
users.
