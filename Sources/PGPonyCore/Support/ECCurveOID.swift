// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ECCurveOID.swift
// PGPony — elliptic-curve OID recognition for key import (issue #2).
//
// GnuPG and GPG4WIN routinely produce keys on curves PGPony does not generate
// itself: the brainpool family (common in German and enterprise setups) and
// the NIST prime curves. Before this, iOS import read only the public-key
// algorithm byte (18 ECDH, 19 ECDSA, 22 EdDSA) and never the curve OID, so an
// algo-18 brainpool subkey was mislabeled as Curve25519 and an algo-19 ECDSA
// key was not recognized at all and fell back to "RSA 4096". This maps the OID
// so an imported key is identified and labeled correctly.
//
// Recognition only: PGPony does not sign, verify, or encrypt with these curves.
// The point is that a key that carries one imports and displays with the right
// name instead of being dropped or mislabeled.
//
// OID bodies are the DER content octets exactly as they appear in a v4 EC
// public-key packet (a 1-octet length followed by these bytes). Verified
// byte-for-byte against the DER encodings and against the brainpool OIDs
// already used in CardAlgorithmAttributes.

import Foundation

enum ECCurve: Equatable {
    case nistP256, nistP384, nistP521
    case brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
    case ed25519Legacy, cv25519           // the OIDs PGPony already generates
    case ed25519, x25519, ed448, x448     // RFC 9580 / native OIDs

    /// A short, stable human name for the curve (crypto identifier, not
    /// localized). Used to build an import label.
    var displayName: String {
        switch self {
        case .nistP256:        return "NIST P-256"
        case .nistP384:        return "NIST P-384"
        case .nistP521:        return "NIST P-521"
        case .brainpoolP256r1: return "brainpoolP256r1"
        case .brainpoolP384r1: return "brainpoolP384r1"
        case .brainpoolP512r1: return "brainpoolP512r1"
        case .ed25519Legacy:   return "Ed25519"
        case .cv25519:         return "Cv25519"
        case .ed25519:         return "Ed25519"
        case .x25519:          return "X25519"
        case .ed448:           return "Ed448"
        case .x448:            return "X448"
        }
    }

    /// True for the curves PGPony can only recognize, not operate on: the
    /// brainpool family (CryptoKit has no brainpool). The Curve25519/448
    /// OIDs are the ones PGPony generates, and since 8.3.0 (NIST A to E) the
    /// three NIST prime curves decrypt, encrypt, verify and sign on CryptoKit.
    var isRecognitionOnly: Bool {
        switch self {
        case .ed25519Legacy, .cv25519, .ed25519, .x25519, .ed448, .x448,
             .nistP256, .nistP384, .nistP521:
            return false
        default:
            return true
        }
    }

    /// 8.3.0: the NIST curve this is, when it is one.
    var nistCurve: NISTCurve? { NISTCurve(self) }

    private static let table: [(oid: [UInt8], curve: ECCurve)] = [
        ([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], .nistP256),
        ([0x2B, 0x81, 0x04, 0x00, 0x22],                   .nistP384),
        ([0x2B, 0x81, 0x04, 0x00, 0x23],                   .nistP521),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], .brainpoolP256r1),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], .brainpoolP384r1),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], .brainpoolP512r1),
        ([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01], .ed25519Legacy),
        ([0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01], .cv25519),
        ([0x2B, 0x65, 0x70], .ed25519),
        ([0x2B, 0x65, 0x6E], .x25519),
        ([0x2B, 0x65, 0x71], .ed448),
        ([0x2B, 0x65, 0x6F], .x448),
    ]

    /// Identify a curve from its OID body (the bytes after the 1-octet length).
    static func from(oid: [UInt8]) -> ECCurve? {
        return table.first(where: { $0.oid == oid })?.curve
    }

    /// Read the curve OID out of a v4 public-key or secret-key packet body and
    /// identify it. The body is `version(1) | created(4) | algo(1) | oidLen(1)
    /// | oid | ...`, so the OID begins at offset 7 for an EC algorithm (18
    /// ECDH, 19 ECDSA, 22 EdDSA). Returns nil for non-EC algorithms or a
    /// truncated/unknown OID.
    static func fromKeyPacketBody(_ body: [UInt8]) -> ECCurve? {
        guard body.count > 7 else { return nil }
        let algo = body[5]
        guard algo == 18 || algo == 19 || algo == 22 else { return nil }
        let oidLen = Int(body[6])
        guard oidLen > 0, 7 + oidLen <= body.count else { return nil }
        return from(oid: Array(body[7..<(7 + oidLen)]))
    }
}
