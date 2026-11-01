// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SubkeyCapabilitySet.swift
// PGPonyCore
//
// CORE SEAM: in the app this option set lives in PGPSubkeyModel.swift beside
// the SwiftData subkey model; the core lifts it out on its own, the way
// KeyAlgorithm.swift is lifted, so nothing here depends on SwiftData.

import Foundation

/// Capability flags for a subkey, mirroring RFC 4880 §5.2.3.21 (Key Flags subpacket).
///
/// Most v4.1-era PGPony keys follow the standard layout:
///   - Primary key: .certify (often + .sign for Ed25519)
///   - Single subkey: .encrypt (Cv25519 / RSA encryption subkey)
/// RSA primary keys (especially older v4.1 generations) typically carry C + S + E
/// on the primary with no subkey at all.
struct SubkeyCapabilitySet: OptionSet, Codable, Hashable, Sendable {
    let rawValue: Int

    static let certify       = SubkeyCapabilitySet(rawValue: 1 << 0)   // C — certify other keys
    static let sign          = SubkeyCapabilitySet(rawValue: 1 << 1)   // S — sign data
    static let encrypt       = SubkeyCapabilitySet(rawValue: 1 << 2)   // E — encrypt data
    static let authenticate  = SubkeyCapabilitySet(rawValue: 1 << 3)   // A — authentication

    /// Compact letter badge for KeyDetailView, matching standard PGP UX (e.g. "scESC").
    var badge: String {
        var out = ""
        if contains(.sign) { out += "S" }
        if contains(.certify) { out += "C" }
        if contains(.encrypt) { out += "E" }
        if contains(.authenticate) { out += "A" }
        return out.isEmpty ? "-" : out
    }

    var displayDescription: String {
        var parts: [String] = []
        if contains(.sign)         { parts.append(String(localized: "Sign")) }
        if contains(.certify)      { parts.append(String(localized: "Certify")) }
        if contains(.encrypt)      { parts.append(String(localized: "Encrypt")) }
        if contains(.authenticate) { parts.append(String(localized: "Authenticate")) }
        return parts.isEmpty ? String(localized: "None") : parts.joined(separator: " · ")
    }

    // MARK: - Heuristics

    /// Best-guess capabilities for a parsed subkey when we don't have the self-signature
    /// key-flags subpacket parsed yet. Conservative defaults that match how PGPony has
    /// historically generated keys, and how the vast majority of imported keys are laid out.
    ///
    /// - Parameters:
    ///   - algorithm: the PGPony KeyAlgorithm of this subkey
    ///   - isPrimary: true if this is the primary key, false for subkeys
    static func heuristic(for algorithm: KeyAlgorithm, isPrimary: Bool) -> SubkeyCapabilitySet {
        switch algorithm {
        case .rsa2048, .rsa3072, .rsa4096, .rsa8192:
            // RSA can do everything. Primary in old PGPony layouts has C+S+E (no subkey).
            return isPrimary ? [.certify, .sign, .encrypt] : [.encrypt]

        case .ed25519, .v6Ed25519, .v6Ed448, .v6MLDSA65, .v6MLDSA87, .librePGPEd448:
            // Pure signing algorithms (the composite ML-DSA + EdDSA suites too).
            return isPrimary ? [.certify, .sign] : [.sign]

        case .v6X25519, .v6X448, .librePGPX448:
            // Pure encryption algorithms (only valid as subkeys).
            return [.encrypt]

        case .v6MLKEM768, .v6MLKEM1024, .librePGPKyber, .librePGPKyber1024, .librePGPKyberBP256, .librePGPKyberBP384,
             .v4MLKEM768:
            return isPrimary ? [.certify, .sign, .encrypt] : [.encrypt]
        case .nistP256, .nistP384, .nistP521:
            // ECDSA primary certifies and signs; an ECDH subkey encrypts.
            return isPrimary ? [.certify, .sign] : [.encrypt]
        case .otherEC:
            // Recognized EC key; capabilities not tracked, conservative guess.
            return isPrimary ? [.certify, .sign] : [.encrypt]
        }
    }
}
