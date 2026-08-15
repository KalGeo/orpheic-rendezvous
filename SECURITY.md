# Security policy

The Orpheic rendezvous is an **introducer**: it helps devices find each other and holds
nothing of value — no keys, no user data, no media, and nothing on disk. The end-to-end
security of Orpheic Remote (pinned TLS, Ed25519 identities) does **not** depend on this
server being trustworthy; it is treated as untrusted by design. So the realistic concern
here is **availability** (denial of service) and logic bugs in the abuse defences — not
disclosure or takeover.

That said, we take reports seriously and welcome them.

## Reporting a vulnerability

Please email **hello@orpheic.com** with the details. **Do not open a public issue** for a
security problem.

Helpful to include:

- what the flaw is and where (file / line if you can),
- how to reproduce it, and
- what an attacker could actually achieve.

## What to expect

- We aim to acknowledge your report within a few days.
- We'll work with you on a fix and coordinate timing before any public disclosure.
- Credit is offered gladly, if you'd like it.

## Scope

**In scope** — `rendezvous.py` and its shipped configuration: crashes, resource exhaustion
that bypasses the built-in per-IP limits, ways to make the server carry or reveal something
it should not, or reflection / amplification.

**Out of scope** — that the server learns connection metadata (which keys are online, from
which address, when): that is inherent to any introducer, and is exactly why you can run
your own. "A large enough botnet could DoS it" without a specific amplification or bypass is
also generally out of scope; that is what the per-IP limits, an upstream provider's baseline
DDoS protection, and self-hosting are for.

## Fixes

Fixes land in this repository. If you run the official rendezvous or your own, pull and
restart to pick them up.
