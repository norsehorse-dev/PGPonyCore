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
//
// 8.4.0 build 7 wave 2 (plan K3, Android 4.6.0 item 13 and issue #2): gpg
// also pairs ML-KEM with the brainpool curves, `ky768_bp256` (ML-KEM-768 +
// brainpoolP256r1, which PGPony now generates) and `ky1024_bp384` (ML-KEM-1024
// + brainpoolP384r1, imported from Kleopatra users). Those are Weierstrass
// curves: a 32 or 48 octet scalar, an uncompressed 0x04 || X || Y point (65 or
// 97 octets) as the public key and as the ephemeral, the WHOLE shared point as
// the raw ECDH input to the KDF, and the KDF hash by curve size (SHA3-256 for
// brainpoolP256r1, SHA3-512 for brainpoolP384r1), as gpg's common/kem.c
// ecc_table and Android's CompositeKemLibrePGP have them.
enum LibrePGPSuite {
    case ky768_cv25519
    case ky1024_cv448
    case ky768_bp256
    case ky1024_bp384

    /// Scalar length, and for the Montgomery curves also the length of a
    /// public point or ephemeral. The composite secret is this many octets of
    /// ECC scalar followed by the 64-octet ML-KEM seed.
    var eccKeyBytes: Int {
        switch self {
        case .ky768_cv25519: return 32
        case .ky1024_cv448:  return 56
        case .ky768_bp256:   return 32
        case .ky1024_bp384:  return 48
        }
    }

    /// Length of a public point or ephemeral on the wire: the native point
    /// for X25519 / X448, the uncompressed SEC 1 point for brainpool.
    var eccPointBytes: Int {
        switch self {
        case .ky768_cv25519, .ky1024_cv448: return eccKeyBytes
        case .ky768_bp256:  return 65
        case .ky1024_bp384: return 97
        }
    }

    /// The brainpool curve of a Weierstrass suite; nil for X25519 / X448.
    var brainpoolCurve: BrainpoolCurve? {
        switch self {
        case .ky768_cv25519, .ky1024_cv448: return nil
        case .ky768_bp256:  return .p256r1
        case .ky1024_bp384: return .p384r1
        }
    }

    var mlkemLevel: MLKEMService.Level {
        switch self {
        case .ky768_cv25519, .ky768_bp256: return .mlkem768
        case .ky1024_cv448, .ky1024_bp384: return .mlkem1024
        }
    }

    /// DER OID body as it appears (1-octet-length-prefixed) in the v5 key
    /// packet: X25519 = 1.3.101.110, X448 = 1.3.101.111, brainpoolP256r1 =
    /// 1.3.36.3.3.2.8.1.1.7, brainpoolP384r1 = 1.3.36.3.3.2.8.1.1.11.
    var oidTail: [UInt8] {
        switch self {
        case .ky768_cv25519: return [0x2b, 0x65, 0x6e]
        case .ky1024_cv448:  return [0x2b, 0x65, 0x6f]
        case .ky768_bp256:   return BrainpoolCurve.p256r1.oid
        case .ky1024_bp384:  return BrainpoolCurve.p384r1.oid
        }
    }

    var mlkemPublicBytes: Int { mlkemLevel.publicKeyBytes }
    var mlkemCiphertextBytes: Int { mlkemLevel.ciphertextBytes }

    /// Raw composite secret material: ECC scalar ‖ 64-octet ML-KEM seed.
    var secretBytes: Int { eccKeyBytes + 64 }

    /// Match a v5 key packet's OID body (without the length octet).
    static func fromOidTail(_ bytes: [UInt8]) -> LibrePGPSuite? {
        for suite in [LibrePGPSuite.ky768_cv25519, .ky1024_cv448, .ky768_bp256, .ky1024_bp384]
            where suite.oidTail == bytes {
            return suite
        }
        return nil
    }

    /// Adjust a raw ECC point value to the length the KEM needs. LibrePGP
    /// stores points as variable-length MPIs/SOSes, but the KEM (agreement,
    /// KDF, combiner) needs the fixed curve length: trim to the LOW
    /// `eccKeyBytes` if longer (drops a 0x40 native-point prefix or high zero
    /// octets), left-pad with zeros if shorter (gpg emits minimal MPIs).
    /// Feeding the raw MPI bytes instead makes the KDF disagree with gpg and
    /// the session-key unwrap fail with "checksum failed". A brainpool point
    /// is used as written (its 0x04 lead octet is never stripped); callers
    /// check it lies on the curve.
    func normalizePoint(_ b: [UInt8]) -> [UInt8] {
        if brainpoolCurve != nil { return b }
        if b.count == eccKeyBytes { return b }
        if b.count > eccKeyBytes { return Array(b.suffix(eccKeyBytes)) }
        return [UInt8](repeating: 0, count: eccKeyBytes - b.count) + b
    }

    /// gpg's ECC key-share KDF (gnupg_ecc_kem_simple_kdf):
    ///   ecc_ss = SHA3( rawECDH ‖ ecc_ct ‖ ecc_pk )
    /// with SHA3-256 for X25519 and brainpoolP256r1, SHA3-512 for X448 and
    /// brainpoolP384r1 (the hash scales with the curve per the Kyber spec gpg
    /// follows).
    func eccKemKdf(rawECDH: [UInt8], eccCipherText: [UInt8], eccPublic: [UInt8]) -> [UInt8] {
        let input = rawECDH + eccCipherText + eccPublic
        switch self {
        case .ky768_cv25519, .ky768_bp256: return Keccak.sha3_256(input)
        case .ky1024_cv448, .ky1024_bp384: return Keccak.sha3_512(input)
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
