# Contributing to PGPonyCore

Thanks for looking. This package is published primarily for **auditability** — so the
most valuable contributions are careful reading, and reports of anything that looks
wrong in the cryptography or protocol handling.

## Good contributions

- **Security findings** — please follow [SECURITY.md](SECURITY.md) (report privately).
- **Correctness issues** — spec deviations (RFC 9580 / OpenPGP), interop failures with
  GnuPG or other implementations, edge cases in packet parsing. A failing test vector
  is the gold standard.
- **Test vectors** — fixture-free, secrets-free tests that exercise the core against
  known-good values.
- **Documentation** — clarifying the public API surface as it's defined.

## Ground rules

- **Never commit secrets.** No private keys, no real PINs, no tokens, no personal data —
  not in code, tests, fixtures, or commit messages.
- Keep contributions to the **crypto/protocol core**; app behavior lives in the
  (closed) apps and isn't changed here.
- By submitting a contribution you agree it is licensed under
  [Apache-2.0](LICENSE), consistent with this project.

## Building

See the README. The package is iOS-platform (CoreNFC), so build/test against an iOS
destination with `xcodebuild`.
