// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeSuite.swift
// PGPony
//
// v8.2.0 §1 (ML-KEM-1024 + X448). The shared parameter model for the two
// IETF composite KEM code points, ported from the Android 4.2.0 design
// (CompositeSuite.kt): the security-critical combiner and packet code read
// their curve, ML-KEM level, byte lengths and algorithm id from a suite
// instead of hardcoded 768/X25519 constants, so the 1024 parameter set is
// a data entry here, not a second copy of the crypto.
//
//   algo 35  ML-KEM-768  + X25519   (v6 subkey)   [shipped 8.0.0, Phase F]
//   algo 36  ML-KEM-1024 + X448    (v6 subkey)   [new, §1]
//
// RFC 9980 registers exactly these two KEM code points and gpg pairs the
// same way, so the two cases are the whole space: there is no
// ML-KEM-1024 + X25519. The LibrePGP v5 pathway (algo 8, Kyber) is a
// separate code base on iOS (LibrePGPEncrypt/DecryptService) and stays
// 768-only this cycle per the K2 resolution, so it does not appear here.
//
// The construction is identical for both suites: only the ECDH curve, the
// ML-KEM parameter set, the byte lengths, and the algorithm-id octet fed
// into the KDF differ. The KEK is SHA3-256 and 32 octets for BOTH suites
// (it wraps an AES-256 session key either way); the hash does not grow
// with the parameter set.

import Foundation

enum CompositeSuite: CaseIterable {

    /// RFC 9980 algorithm 35: ML-KEM-768 + X25519 (mandatory to implement).
    case ietf768

    /// RFC 9980 algorithm 36: ML-KEM-1024 + X448.
    case ietf1024

    /// The OpenPGP public-key algorithm id octet, as it appears in key
    /// packets, PKESKs, and the KDF input.
    var algId: UInt8 {
        switch self {
        case .ietf768:  return 35
        case .ietf1024: return 36
        }
    }

    /// Which ML-KEM parameter set the suite pairs.
    var mlkemLevel: MLKEMService.Level {
        switch self {
        case .ietf768:  return .mlkem768
        case .ietf1024: return .mlkem1024
        }
    }

    /// ECDH curve length: scalars, public keys, ephemerals and shares are
    /// all this many octets (32 for X25519, 56 for X448).
    var eccKeyBytes: Int {
        switch self {
        case .ietf768:  return 32
        case .ietf1024: return 56
        }
    }

    var mlkemPublicBytes: Int { mlkemLevel.publicKeyBytes }
    var mlkemCiphertextBytes: Int { mlkemLevel.ciphertextBytes }

    /// Composite public key material: ECC public ‖ ML-KEM public.
    /// 1216 for 768/X25519, 1624 for 1024/X448.
    var compositePublicBytes: Int { eccKeyBytes + mlkemPublicBytes }

    /// Composite secret material: ECC secret ‖ ML-KEM seed (d‖z, 64 for
    /// every parameter set, which is why the secret barely grows: only the
    /// ECC half does, 32 to 56).
    var compositeSecretBytes: Int { eccKeyBytes + MLKEMService.seedBytes }

    /// Match an OpenPGP algorithm id octet to a suite.
    static func from(algId: UInt8) -> CompositeSuite? {
        allCases.first { $0.algId == algId }
    }
}
