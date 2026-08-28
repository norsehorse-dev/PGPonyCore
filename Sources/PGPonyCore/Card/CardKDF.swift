// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardKDF.swift
// PGPony
//
// v8.1.0 — §4b: OpenPGP card KDF data object (DO 00F9) support.
//
// WHY THIS EXISTS
// A card provisioned through GnuPG/Kleopatra with `gpg --card-edit` -> `kdf-setup`
// stores a KDF-DO and from then on expects the *derived* form of the PIN in
// VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER — never the PIN itself.
// PGPony sent `Array(pin.utf8)` unconditionally, so on such a card every correct
// PIN was rejected with 63Cx and burned one PW1 attempt. Three of those and the
// user's card is blocked. That is the Jul 30 field report.
//
// THE DERIVATION IS **NOT** PBKDF2.
// The 8.1.0 planning note names PBKDF2-HMAC-SHA256. That is incorrect and would
// fail identically to sending the raw PIN. The OpenPGP Smart Card Application
// spec §4.3.2 defines exactly one KDF: KDF_ITERSALTED_S2K (algorithm byte 0x03),
// which is RFC 4880 §3.7.1.3 iterated-and-salted S2K. GnuPG derives it with
// gcry_kdf_derive(GCRY_KDF_ITERSALTED_S2K, ...). Do not "modernise" this to
// PBKDF2 — the card compares against a stored digest and any other function
// produces a wrong value that costs the user a retry.
//
// ITERATION COUNT IS AN OCTET COUNT, ALREADY EXPANDED.
// DO 83 is a 4-byte big-endian value (GnuPG's default is 0x000186A0 = 100000).
// It is the total number of octets of (salt || PIN) to feed the hash — the same
// quantity RFC 4880 encodes into a single coded byte elsewhere in OpenPGP, but
// here it is stored raw and must NOT be run through the coded-count expansion
// in PGPService.s2kDeriveKey. That is why this file has its own loop rather
// than calling that method: same algorithm, different count encoding, plus
// SHA-512 which the existing helper does not implement.
//
// Pure and dependency-free by design so the parse and the derivation are unit
// testable without a card. See CardKDFTests.

import Foundation
import CryptoKit

/// Parsed contents of the OpenPGP card KDF data object (DO 00F9).
///
/// Layout per OpenPGP Smart Card Application §4.3.2:
///
///     81 01 <kdf algorithm>    00 = none, 03 = KDF_ITERSALTED_S2K
///     82 01 <hash algorithm>   08 = SHA-256, 0A = SHA-512
///     83 04 <iteration count>  big-endian octet count
///     84 xx <salt PW1>
///     85 xx <salt reset code>
///     86 xx <salt PW3>
///     87 xx <initial hash PW1>
///     88 xx <initial hash PW3>
///
/// Tags 87/88 are the card's stored digests of the factory-default PINs; PGPony
/// never needs them to verify and they are parsed only so the DO round-trips.
struct CardKDF: Equatable {

    enum Algorithm: UInt8, Equatable {
        case none          = 0x00
        case iterSaltedS2K = 0x03
    }

    enum HashAlgorithm: UInt8, Equatable {
        case sha256 = 0x08
        case sha512 = 0x0A

        /// Digest length in bytes — also the length of the derived PIN value.
        var digestLength: Int {
            switch self {
            case .sha256: return 32
            case .sha512: return 64
            }
        }

        var displayName: String {
            switch self {
            case .sha256: return "SHA-256"
            case .sha512: return "SHA-512"
            }
        }
    }

    /// Which stored salt applies. PW1 in either mode (0x81 signing / 0x82
    /// confidentiality) uses the same PW1 salt — the modes select what the
    /// verification authorises, not which secret it is.
    enum PINReference: Equatable {
        case pw1
        case resetCode
        case pw3
    }

    let algorithm: Algorithm
    let hashAlgorithm: HashAlgorithm
    let iterationCount: Int
    let saltPW1: [UInt8]
    let saltResetCode: [UInt8]
    let saltPW3: [UInt8]
    let initialHashPW1: [UInt8]
    let initialHashPW3: [UInt8]

    /// True when the card actually expects derived PINs. A card can carry a
    /// KDF-DO whose algorithm byte is 0x00, which means "configured off" and
    /// must take the raw path exactly as if no DO were present.
    var isEnabled: Bool { algorithm == .iterSaltedS2K }

    /// Short description for the card-status screen, so a KDF card is
    /// diagnosable in the field instead of presenting as "wrong PIN".
    var displayDescription: String {
        guard isEnabled else { return String(localized: "Off") }
        return "\(hashAlgorithm.displayName), \(iterationCount) iterations"
    }

    // MARK: - Parsing

    /// Parse the value of DO 00F9. Returns nil if the DO is malformed or names
    /// an algorithm/hash this build cannot derive — callers treat nil as "no
    /// KDF" only when the DO is genuinely absent; a present-but-unparseable DO
    /// is an error worth surfacing, because falling back to the raw path there
    /// would silently burn the user's attempts.
    static func parse(_ bytes: [UInt8]) -> CardKDF? {
        guard !bytes.isEmpty else { return nil }

        var fields: [UInt8: [UInt8]] = [:]
        var i = 0
        while i < bytes.count {
            let tag = bytes[i]
            i += 1
            guard i < bytes.count else { return nil }
            let length = Int(bytes[i])
            // Every field in this DO is short-form; a long-form length here means
            // we are misreading the structure, so bail rather than guess.
            guard length < 0x80 else { return nil }
            i += 1
            guard i + length <= bytes.count else { return nil }
            fields[tag] = Array(bytes[i..<(i + length)])
            i += length
        }

        guard let algoBytes = fields[0x81], let algoRaw = algoBytes.first,
              let algorithm = Algorithm(rawValue: algoRaw) else { return nil }

        // Algorithm "none" is a complete, valid answer: the card is telling us to
        // use raw PINs. Fill the rest with empties rather than failing the parse.
        guard algorithm == .iterSaltedS2K else {
            return CardKDF(
                algorithm: .none, hashAlgorithm: .sha256, iterationCount: 0,
                saltPW1: [], saltResetCode: [], saltPW3: [],
                initialHashPW1: [], initialHashPW3: []
            )
        }

        guard let hashBytes = fields[0x82], let hashRaw = hashBytes.first,
              let hash = HashAlgorithm(rawValue: hashRaw) else { return nil }

        guard let countBytes = fields[0x83], countBytes.count == 4 else { return nil }
        var count = 0
        for b in countBytes { count = (count << 8) | Int(b) }
        guard count > 0 else { return nil }

        // PW1 salt is the only one required to verify a user PIN. The reset-code
        // and PW3 salts are optional here so a card that omits them still works
        // for the common path.
        guard let saltPW1 = fields[0x84], !saltPW1.isEmpty else { return nil }

        return CardKDF(
            algorithm: algorithm,
            hashAlgorithm: hash,
            iterationCount: count,
            saltPW1: saltPW1,
            saltResetCode: fields[0x85] ?? [],
            saltPW3: fields[0x86] ?? [],
            initialHashPW1: fields[0x87] ?? [],
            initialHashPW3: fields[0x88] ?? []
        )
    }

    // MARK: - Derivation

    /// The salt for a given PIN reference.
    ///
    /// `kdf-setup single` (GnuPG's 90-byte layout) writes only tag 84 and reuses
    /// that one salt for PW1, the reset code and PW3 alike; the three-salt
    /// 110-byte layout comes from `kdf-setup all`. Falling back to the PW1 salt
    /// when a specific one is absent matches GnuPG's own salt_index selection.
    /// Without this, admin operations — PIN change, unblock, factory reset, and
    /// on-card key generation — all fail on a single-salt card while sign and
    /// decrypt keep working, which presents as "the admin PIN stopped working".
    func salt(for reference: PINReference) -> [UInt8] {
        switch reference {
        case .pw1:       return saltPW1
        case .resetCode: return saltResetCode.isEmpty ? saltPW1 : saltResetCode
        case .pw3:       return saltPW3.isEmpty ? saltPW1 : saltPW3
        }
    }

    /// Derive the value to send in place of `pin`. Returns nil when KDF is off
    /// (caller sends the PIN raw) or when the required salt is missing.
    func derive(pin: String, reference: PINReference) -> [UInt8]? {
        guard isEnabled else { return nil }
        let salt = salt(for: reference)
        guard !salt.isEmpty else { return nil }
        return Self.iteratedSaltedS2K(
            passphrase: Array(pin.utf8),
            salt: salt,
            iterationCount: iterationCount,
            hash: hashAlgorithm
        )
    }

    /// RFC 4880 §3.7.1.3 iterated-and-salted S2K, with the octet count supplied
    /// directly rather than as a coded byte.
    ///
    /// The hash is fed (salt || passphrase) repeatedly until `iterationCount`
    /// octets have been consumed, truncating the final repetition mid-way if the
    /// count is not a whole multiple. A count smaller than one repetition still
    /// hashes at least the whole of (salt || passphrase) once — RFC 4880 requires
    /// the full value be hashed even when the count would cut it short, and
    /// GnuPG's gcry_kdf_derive behaves this way.
    ///
    /// Output is exactly one digest; the KDF-DO derived PIN is never longer than
    /// the hash, so the multi-pass zero-prefix extension of general S2K is not
    /// reachable here.
    static func iteratedSaltedS2K(
        passphrase: [UInt8],
        salt: [UInt8],
        iterationCount: Int,
        hash: HashAlgorithm
    ) -> [UInt8] {
        let saltedPass = salt + passphrase
        guard !saltedPass.isEmpty else { return [] }

        // RFC 4880 requires the whole of (salt || passphrase) be hashed even when
        // the count is smaller than it, so the count is a floor, not a cap. This
        // matches libgcrypt's openpgp_s2k: `if (count < len2) count = len2;`.
        let total = Swift.max(iterationCount, saltedPass.count)

        // Fed incrementally rather than materialised. The count on a real card is
        // whatever GnuPG's calibration produced — tens of millions of octets is
        // ordinary, and the DO field can hold up to 0xFFFFFFFF. Building the
        // repeated buffer would mean a multi-megabyte (worst case 4 GB)
        // allocation, which on iOS is a jetsam kill, and PGPonyAction runs under
        // a share-extension memory budget tighter still.
        switch hash {
        case .sha256:
            var h = SHA256()
            absorb(saltedPass, total) { h.update(data: $0) }
            return Array(h.finalize())
        case .sha512:
            var h = SHA512()
            absorb(saltedPass, total) { h.update(data: $0) }
            return Array(h.finalize())
        }
    }

    /// Push `total` octets of the repeating `block` into a hash, truncating the
    /// final repetition when the count isn't a whole multiple. Constant memory.
    private static func absorb(
        _ block: [UInt8],
        _ total: Int,
        _ update: ([UInt8]) -> Void
    ) {
        var remaining = total
        while remaining > 0 {
            let n = Swift.min(block.count, remaining)
            update(n == block.count ? block : Array(block[0..<n]))
            remaining -= n
        }
    }
}
