# Security Policy

`PGPonyCore` is the cryptographic core of PGPony. Security reports are taken seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not via public issues.

- **Email:** NorseHorse@norsehor.se
- Use the subject line `PGPonyCore security` so it's routed correctly.
- If you wish to encrypt your report, request the current public key at that address.

Please include: affected file(s)/function(s), a description of the issue, and — if
possible — a minimal reproduction or test vector. Do **not** include real private keys
or other secrets in your report.

## What to expect

This is maintained by a solo developer, so responses are best-effort rather than on a
fixed SLA. You can expect an acknowledgement, an assessment, and — for confirmed issues
— a fix and a credit (if you'd like one) in the release notes.

## Scope

In scope: the cryptographic and protocol code in this package (packet handling,
primitives, key generation, the OpenPGP card command layer, symmetric encryption, the
`pass` parser, the keyserver/WKD clients).

Out of scope here: the PGPony apps themselves (closed-source) and their UI, storage, and
account handling — though if a core issue is reachable through an app, say so.
