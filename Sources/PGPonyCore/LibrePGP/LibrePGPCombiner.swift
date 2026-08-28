// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPCombiner.swift
// PGPony — Phase F (PQC), LibrePGP / GnuPG interop.
//
// GnuPG's composite KEM combiner (common/kem.c gnupg_kem_combiner). LibrePGP's
// PQC (algorithm 8, "Kyber": ML-KEM + ECDH) is a different standard from RFC 9980
// — it derives the key-encryption key with KMAC256 (see Keccak) rather than
// SHA3-256, uses a leading counter, ECC-first ordering, and binds a fixedInfo of
// (session-key algorithm ‖ v5 fingerprint). The KEK is always 32 octets
// (AES-256 key wrap is mandatory in GnuPG's implementation).
//
// Validated in LibrePGPCombinerTests against an independent KMAC256, and
// end-to-end by GnuPG decrypting messages PGPony builds with it.

import Foundation

/// The LibrePGP (algorithm 8) composite parameter sets, v8.2.0 §1 (K2a).
///
/// Unlike the IETF side, algo 8 is a SINGLE code point for both levels: a v5
/// algo-8 key is 768-vs-1024 only by its curve OID and lengths. gpg pairs
/// exactly these two (`ky768_cv25519`, `ky1024_cv448`); there is no
/// ML-KEM-1024 + X25519. The KMAC256 KEK combiner is level-independent, but
/// gpg's ECC key-share KDF (gnupg_ecc_kem_simple_kdf) scales its hash with
/// the curve: SHA3-256 for X25519, SHA3-512 for X448. Using 256 for X448
/// derives a different KEK and fails the unwrap ("checksum failed"), a trap
/// the Android 4.2.0 port hit live against gpg.
enum LibrePGPSuite {
    case ky768_cv25519
    case ky1024_cv448

    /// Curve length: scalars, public points, ephemerals, all this many octets.
    var eccKeyBytes: Int {
        switch self {
        case .ky768_cv25519: return 32
        case .ky1024_cv448:  return 56
        }
    }

    var mlkemLevel: MLKEMService.Level {
        switch self {
        case .ky768_cv25519: return .mlkem768
        case .ky1024_cv448:  return .mlkem1024
        }
    }

    /// DER OID body as it appears (1-octet-length-prefixed) in the v5 key
    /// packet: X25519 = 1.3.101.110, X448 = 1.3.101.111.
    var oidTail: [UInt8] {
        switch self {
        case .ky768_cv25519: return [0x2b, 0x65, 0x6e]
        case .ky1024_cv448:  return [0x2b, 0x65, 0x6f]
        }
    }

    var mlkemPublicBytes: Int { mlkemLevel.publicKeyBytes }
    var mlkemCiphertextBytes: Int { mlkemLevel.ciphertextBytes }

    /// Raw composite secret material: ECC scalar ‖ 64-octet ML-KEM seed.
    var secretBytes: Int { eccKeyBytes + 64 }

    /// Match a v5 key packet's OID body (without the length octet).
    static func fromOidTail(_ bytes: [UInt8]) -> LibrePGPSuite? {
        if bytes == [0x2b, 0x65, 0x6e] { return .ky768_cv25519 }
        if bytes == [0x2b, 0x65, 0x6f] { return .ky1024_cv448 }
        return nil
    }

    /// Adjust a raw ECC point value to exactly `eccKeyBytes` octets. LibrePGP
    /// stores points as variable-length MPIs/SOSes, but the KEM (agreement,
    /// KDF, combiner) needs the fixed curve length: trim to the LOW
    /// `eccKeyBytes` if longer (drops a 0x40 native-point prefix or high zero
    /// octets), left-pad with zeros if shorter (gpg emits minimal MPIs).
    /// Feeding the raw MPI bytes instead makes the KDF disagree with gpg and
    /// the session-key unwrap fail with "checksum failed".
    func normalizePoint(_ b: [UInt8]) -> [UInt8] {
        if b.count == eccKeyBytes { return b }
        if b.count > eccKeyBytes { return Array(b.suffix(eccKeyBytes)) }
        return [UInt8](repeating: 0, count: eccKeyBytes - b.count) + b
    }

    /// gpg's ECC key-share KDF (gnupg_ecc_kem_simple_kdf):
    ///   ecc_ss = SHA3( rawECDH ‖ ecc_ct ‖ ecc_pk )
    /// with SHA3-256 for X25519 and SHA3-512 for X448 (the hash scales with
    /// the curve per the Kyber spec gpg follows).
    func eccKemKdf(rawECDH: [UInt8], eccCipherText: [UInt8], eccPublic: [UInt8]) -> [UInt8] {
        let input = rawECDH + eccCipherText + eccPublic
        switch self {
        case .ky768_cv25519: return Keccak.sha3_256(input)
        case .ky1024_cv448:  return Keccak.sha3_512(input)
        }
    }
}

enum LibrePGPCombiner {

    /// GnuPG OpenPGP public-key algorithm ID for the Kyber/ML-KEM composite.
    static let algIdKyber: UInt8 = 8

    private static let kmacKey = Array("OpenPGPCompositeKeyDerivationFunction".utf8)
    private static let kmacCustom = Array("KDF".utf8)

    /// Derive the 32-octet KEK.
    ///
    ///   KEK = KMAC256( key="OpenPGPCompositeKeyDerivationFunction", custom="KDF",
    ///                  data = 00000001 ‖ eccShared ‖ eccCipherText
    ///                         ‖ mlkemShared ‖ mlkemCipherText
    ///                         ‖ sessionKeyAlgo(1) ‖ v5Fingerprint(32),
    ///                  L = 256 bits )
    static func deriveKEK(eccShared: [UInt8],
                          eccCipherText: [UInt8],
                          mlkemShared: [UInt8],
                          mlkemCipherText: [UInt8],
                          sessionKeyAlgo: UInt8,
                          v5Fingerprint: [UInt8]) -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(4 + eccShared.count + eccCipherText.count
                             + mlkemShared.count + mlkemCipherText.count + 1 + v5Fingerprint.count)
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])   // counter
        data.append(contentsOf: eccShared)
        data.append(contentsOf: eccCipherText)
        data.append(contentsOf: mlkemShared)
        data.append(contentsOf: mlkemCipherText)
        data.append(sessionKeyAlgo)                         // fixedInfo[0]
        data.append(contentsOf: v5Fingerprint)              // fixedInfo[1...]
        return Keccak.kmac256(key: kmacKey, data: data, outLen: 32, customization: kmacCustom)
    }
}
