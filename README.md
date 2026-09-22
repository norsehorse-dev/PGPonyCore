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

This tree is the **PGPony 8.3.0** core.

A self-contained OpenPGP implementation with **no third-party Swift dependencies** —
system frameworks only (Foundation, CryptoKit, CommonCrypto, Security, CoreNFC, zlib)
plus one pinned, vendored C library: [liboqs](https://github.com/open-quantum-safe/liboqs)
(ML-KEM only), shipped as `Vendor/liboqs.xcframework` so the package builds out of the
box and auditors see the exact binary the app links.

Added in 8.3.0: ML-DSA (for composite signatures) comes from CryptoKit's `MLDSA65`,
which exists on iOS 26 and later only. Building needs the iOS 26 SDK (Xcode 26); on an
older OS every ML-DSA path reports "not available" at run time, and the rest of the
package is unaffected. The deployment floor stays 17.6.

One qualifier, added in 8.1.0: the USB-C smart card transport is written against
[YubiKit](https://github.com/Yubico/yubikit-ios), because that is the only way iOS
exposes a wired smart card. The whole of that path sits behind
`#if canImport(YubiKit)`, so this package builds and tests with nothing added and simply
reports USB as unavailable. The app links YubiKit; the core does not require it. NFC has
no such caveat and needs only CoreNFC.

| Area | Files |
|---|---|
| **Packet** | OpenPGP packet builder + parser (RFC 9580 / v6, partial body lengths, SEIPD v1/v2), multi-recipient envelopes across classical, composite and LibrePGP recipients, streaming binary signing, a from-scratch BZip2 decoder for compression algorithm 3, input size limits, and armor extraction from surrounding text |
| **Primitives** | AEAD/OCB, AES key-wrap (RFC 3394), Argon2 + classic S2K, Cv25519 ECDH, NIST P-256/384/521 ECDH and ECDSA (RFC 6637), X448 (RFC 7748), Ed25519 keygen, Keccak/KMAC/SHA3-256/SHA3-512 |
| **PQC** | ML-KEM via the vendored liboqs + composite-KEM packet handling (RFC 9980): ML-KEM-768 with X25519 (algorithm 35, on v6 and v4 keys) and ML-KEM-1024 with X448 (algorithm 36); composite ML-DSA-65 with Ed25519 signatures (algorithm 30: sign and verify, iOS 26) |
| **LibrePGP** | LibrePGP (v5) encrypt / decrypt / combiner for GnuPG interop |
| **KeyGen** | v6 key generation (RFC 9580), post-quantum and authentication subkeys on existing v6 keys |
| **KeyOps** | software key-expiration editing: fresh self-certs/bindings, gpg-verifiable, revoked identities and subkeys left alone |
| **Card** | OpenPGP smartcard protocol — APDU command layer, PSO:CDS/DECIPHER, PIN, KDF-DO (00F9) derived PINs, on-card GEN, over a transport seam with NFC and USB-C implementations |
| **Symmetric** | passphrase-only (`gpg -c`) encrypt/decrypt |
| **Backup** | backup-code generation (the passphrase behind the encrypted keyring backup) |
| **MIME** | PGP/MIME message parser + builder |
| **Pass** | pure parser for `pass` (password-store) entries |
| **Network** | keyserver + WKD clients (+ proxy-aware session factory) |

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
- **Transport seam** — done in 8.1.0. `CardTransport` now sits under the card command
  layer, with NFC and USB-C smart card implementations behind it. What remains for macOS
  is a PC/SC implementation over CryptoTokenKit, plus dropping the `import CoreNFC` that
  still makes this an iOS-platform package.
- **Kotlin sibling** — `PGPonyCore-Kotlin`, the Android core.

## Security

See [SECURITY.md](SECURITY.md). Disclosure contact: **NorseHorse@norsehor.se**.

## License

[Apache-2.0](LICENSE). Copyright 2026 NorseHorse. The apps that build on this core remain
closed-source; this license governs `PGPonyCore` only.
