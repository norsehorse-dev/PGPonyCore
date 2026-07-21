# PGPonyCore

The auditable crypto core of **[PGPony](https://pgpony.app)** — a hardware-key-first
OpenPGP app for iOS (and the rest of the NorseHorse portfolio).

This package exists for one reason: **so you can read and verify the cryptography.**
The apps are closed-source, but the part that matters for trust — the OpenPGP packet
handling, the primitives, the hardware-card protocol — is open here. No marketing, no
app code, just the core.

> **Two cores, one story.** This is the **Swift / Apple** core. A sibling **Android /
> Kotlin** core (`PGPonyCore-Kotlin`) is planned under the same owner — same idea, same
> license, separate code (Android uses Bouncy Castle, so the implementations can't be
> shared, only the transparency goal).

## What's in here

This tree is the **PGPony 8.0.0** core.

A self-contained OpenPGP implementation with **no third-party Swift dependencies** —
system frameworks only (Foundation, CryptoKit, CommonCrypto, Security, CoreNFC, zlib)
plus one pinned, vendored C library: [liboqs](https://github.com/open-quantum-safe/liboqs)
(ML-KEM only), shipped as `Vendor/liboqs.xcframework` so the package builds out of the
box and auditors see the exact binary the app links.

| Area | Files |
|---|---|
| **Packet** | OpenPGP packet builder + parser (RFC 9580 / v6, partial body lengths, SEIPD v1/v2) |
| **Primitives** | AEAD/OCB, AES key-wrap (RFC 3394), Argon2 + classic S2K, Cv25519 ECDH, Ed25519 keygen, Keccak/KMAC |
| **PQC** | ML-KEM via the vendored liboqs + composite-KEM packet handling (OpenPGP PQC draft) |
| **LibrePGP** | LibrePGP (v5) encrypt / decrypt / combiner for GnuPG interop |
| **KeyGen** | v6 key generation (RFC 9580) |
| **KeyOps** | software key-expiration editing — fresh self-certs/bindings, gpg-verifiable |
| **Card** | OpenPGP smartcard protocol — APDU command layer, PSO:CDS/DECIPHER, PIN, on-card GEN (CoreNFC transport) |
| **Symmetric** | passphrase-only (`gpg -c`) encrypt/decrypt |
| **Backup** | backup-code generation (the passphrase behind the encrypted keyring backup) |
| **MIME** | PGP/MIME message parser + builder |
| **Pass** | pure parser for `pass` (password-store) entries |
| **Network** | keyserver + WKD clients (+ proxy-aware session factory) |
| **Diagnostics** | v6 interop self-diagnostic |

## What's deliberately *not* here

The app, not the core: SwiftUI views, SwiftData models, `AppState`, key storage,
contacts, notifications, and the ObjectivePGP-backed orchestration layer. Those stay
closed because they're application logic, not cryptography worth auditing. The boundary
is "pure bytes-in / bytes-out crypto and protocol" — everything here meets that bar.

## Build

```sh
# This package is iOS-only (the card transport uses CoreNFC), so build for an
# iOS destination rather than the host:
xcodebuild build -scheme PGPonyCore -destination 'generic/platform=iOS'

# Run the tests on a simulator (adjust the device to one your Xcode has installed):
xcodebuild test -scheme PGPonyCore -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest'
```

`swift build` on macOS will fail on `import CoreNFC` — that's expected; this is an
iOS-platform package. See the roadmap below for the macOS path.

## Using it

Add the package and `import PGPonyCore`. **Note:** the initial extraction keeps the
lifted files at their original `internal` access level, so the public API surface is
still being defined — making the consumed symbols `public` (and documenting them, since
*that documented surface is the audit surface*) is the next step. Read the source
directly in the meantime; that's what it's here for.

## Roadmap

- **Public API surface** — promote the consumed symbols to `public` and document them.
- **Transport seam** — introduce an `OpenPGPCardTransport` protocol so the card command
  layer is platform-independent (NFC on iOS; PC/SC via CryptoTokenKit on macOS). This is
  what would make the package build on macOS and back a future macOS app.
- **Kotlin sibling** — `PGPonyCore-Kotlin`, the Android core.

## Security

See [SECURITY.md](SECURITY.md). Disclosure contact: **NorseHorse@norsehor.se**.

## License

[Apache-2.0](LICENSE). Copyright 2026 NorseHorse. The apps that build on this core remain
closed-source; this license governs `PGPonyCore` only.
