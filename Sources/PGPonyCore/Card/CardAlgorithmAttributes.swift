// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardAlgorithmAttributes.swift
// PGPony
//
// v6.0 — Phase 10b: parse an OpenPGP card algorithm-attributes data object
// (C1 = signature, C2 = decryption, C3 = authentication) into a friendly
// display name. Swift port of the Android CardAlgorithmAttributes.
//
// Layout (OpenPGP card spec §4.4.3.x):
//   RSA:  01 | modulus-bit-length(2) | exponent-bit-length(2) | format(1)
//   ECC:  {12|13|16} | curve-OID-bytes(var) | [optional format byte]
//
// The trailing ECC format byte is ambiguous against the OID, so curve OIDs are
// matched by prefix against a known table rather than by exact length.

import Foundation

struct CardAlgorithmAttributes {
    let rawAlgoID: UInt8
    let displayName: String
    let modulusBits: Int?
    let curveName: String?

    // OID *body* bytes (no leading 0x06 tag/length), as they appear in the
    // card attribute DO.
    private static let oidEd25519: [UInt8]      = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
    private static let oidCv25519: [UInt8]      = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
    private static let oidNistP256: [UInt8]     = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    private static let oidNistP384: [UInt8]     = [0x2B, 0x81, 0x04, 0x00, 0x22]
    private static let oidNistP521: [UInt8]     = [0x2B, 0x81, 0x04, 0x00, 0x23]
    private static let oidSecp256k1: [UInt8]    = [0x2B, 0x81, 0x04, 0x00, 0x0A]
    private static let oidBrainpoolP256: [UInt8] = [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
    private static let oidBrainpoolP384: [UInt8] = [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B]
    private static let oidBrainpoolP512: [UInt8] = [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D]

    private static let algoRSA: UInt8   = 0x01
    private static let algoECDH: UInt8  = 0x12  // 18
    private static let algoECDSA: UInt8 = 0x13  // 19
    private static let algoEdDSA: UInt8 = 0x16  // 22

    /// Parse the raw attribute bytes; nil if empty.
    static func parse(_ attr: [UInt8]) -> CardAlgorithmAttributes? {
        guard let algoID = attr.first else { return nil }
        let rest = Array(attr.dropFirst())

        switch algoID {
        case algoRSA:
            guard rest.count >= 4 else {
                return CardAlgorithmAttributes(rawAlgoID: algoID, displayName: "RSA", modulusBits: nil, curveName: nil)
            }
            let modBits = (Int(rest[0]) << 8) | Int(rest[1])
            return CardAlgorithmAttributes(rawAlgoID: algoID, displayName: "RSA-\(modBits)", modulusBits: modBits, curveName: nil)
        case algoECDH, algoECDSA, algoEdDSA:
            let curve = identifyCurve(rest)
            return CardAlgorithmAttributes(rawAlgoID: algoID, displayName: curve, modulusBits: nil, curveName: curve)
        default:
            return CardAlgorithmAttributes(
                rawAlgoID: algoID,
                displayName: String(format: "Algorithm 0x%02X", algoID),
                modulusBits: nil,
                curveName: nil
            )
        }
    }

    private static func identifyCurve(_ oidPlusMaybeFormat: [UInt8]) -> String {
        func startsWith(_ prefix: [UInt8]) -> Bool {
            guard oidPlusMaybeFormat.count >= prefix.count else { return false }
            return Array(oidPlusMaybeFormat.prefix(prefix.count)) == prefix
        }
        if startsWith(oidEd25519)      { return "Ed25519" }
        if startsWith(oidCv25519)      { return "Cv25519" }
        if startsWith(oidNistP256)     { return "NIST P-256" }
        if startsWith(oidNistP384)     { return "NIST P-384" }
        if startsWith(oidNistP521)     { return "NIST P-521" }
        if startsWith(oidSecp256k1)    { return "secp256k1" }
        if startsWith(oidBrainpoolP256) { return "brainpoolP256r1" }
        if startsWith(oidBrainpoolP384) { return "brainpoolP384r1" }
        if startsWith(oidBrainpoolP512) { return "brainpoolP512r1" }
        return "EC (unrecognized curve)"
    }
}
