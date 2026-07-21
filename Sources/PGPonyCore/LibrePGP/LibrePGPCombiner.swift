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
