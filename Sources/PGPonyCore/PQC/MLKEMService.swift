// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// MLKEMService.swift
// PGPony — Phase F (PQC).
//
// Thin, safe Swift wrapper over liboqs ML-KEM (FIPS-203). This is the
// crypto-primitive layer: raw key encapsulation only. The RFC 9980 composite
// KEM combiner (ML-KEM + ECDH) and the OpenPGP v6 packet framing are
// built ON TOP of this in later Phase-F chunks (F2 = combiner, F3 = packets).
//
// ML-KEM-768 is RFC 9980's mandatory-to-implement KEM (the PQC half of
// composite algorithm 35). Sizes below are fixed by FIPS-203 and are asserted
// against liboqs at call time, so a library/version mismatch fails loudly
// rather than silently corrupting key material.
//
// v8.2.0 §1: generalized to carry ML-KEM-1024 (the PQC half of composite
// algorithm 36, paired with X448) beside 768. Every entry point takes a
// `level` and defaults to `.mlkem768`, so every Phase-F caller and the KAT
// suite exercises the exact prior behavior with zero call-site churn.
// ML-KEM-1024 needs the xcframework built with KEM_ml_kem_1024 in OQS_ALGS
// (build-liboqs-ios.sh does this as of 8.2.0); against an older 768-only
// framework the availability check throws `.unavailable` instead of
// misbehaving.

import Foundation
import COQS

enum MLKEMService {

    // MARK: - FIPS-203 parameter sets

    /// Which ML-KEM parameter set to run. Sizes are fixed by FIPS-203. The
    /// seed (d‖z) is 64 octets and the shared secret 32 octets for EVERY
    /// set; only keys and ciphertexts grow between 768 and 1024.
    enum Level {
        case mlkem768
        case mlkem1024

        var publicKeyBytes: Int {
            switch self {
            case .mlkem768:  return 1184
            case .mlkem1024: return 1568
            }
        }
        var secretKeyBytes: Int {
            switch self {
            case .mlkem768:  return 2400
            case .mlkem1024: return 3168
            }
        }
        var ciphertextBytes: Int {
            switch self {
            case .mlkem768:  return 1088
            case .mlkem1024: return 1568
            }
        }
        /// The liboqs algorithm name for this set.
        var oqsAlgorithm: String {
            switch self {
            case .mlkem768:  return OQS_KEM_alg_ml_kem_768
            case .mlkem1024: return OQS_KEM_alg_ml_kem_1024
            }
        }
    }

    // MARK: - FIPS-203 ML-KEM-768 constants
    //
    // Kept as named statics because the Phase-F packet layer and the KAT
    // tests reference them; they equal Level.mlkem768's values.

    static let publicKeyBytes    = 1184
    static let secretKeyBytes    = 2400
    static let ciphertextBytes   = 1088
    static let sharedSecretBytes = 32
    /// Derandomized keypair seed = d(32) ‖ z(32). Confirmed against the liboqs
    /// source: coins[0..32) is the IND-CPA seed d, coins[32..64) is the
    /// implicit-rejection value z (matches the FIPS-203 / ACVP d,z ordering).
    /// Same length for every FIPS-203 parameter set.
    static let seedBytes         = 64

    // MARK: - Errors

    enum Failure: Error, LocalizedError {
        case unavailable
        case badInputSize(field: String, expected: Int, got: Int)
        case operationFailed(String)

        var errorDescription: String? {
            switch self {
            case .unavailable:
                return "This ML-KEM parameter set is not available in this build of liboqs."
            case let .badInputSize(field, expected, got):
                return "ML-KEM \(field) has wrong size: expected \(expected) bytes, got \(got)."
            case let .operationFailed(op):
                return "ML-KEM \(op) failed."
            }
        }
    }

    // MARK: - Handle lifecycle

    /// Runs `body` with a live OQS_KEM handle for `level`, freeing it
    /// afterwards. Also asserts liboqs's advertised sizes match the level's
    /// constants, so a mismatched library can never feed the packet layer
    /// wrong-sized buffers.
    private static func withKEM<T>(_ level: Level,
                                   _ body: (UnsafeMutablePointer<OQS_KEM>) throws -> T) throws -> T {
        guard OQS_KEM_alg_is_enabled(level.oqsAlgorithm) == 1,
              let kem = OQS_KEM_new(level.oqsAlgorithm) else {
            throw Failure.unavailable
        }
        defer { OQS_KEM_free(kem) }
        let k = kem.pointee
        guard k.length_public_key == level.publicKeyBytes,
              k.length_secret_key == level.secretKeyBytes,
              k.length_ciphertext == level.ciphertextBytes,
              k.length_shared_secret == sharedSecretBytes else {
            throw Failure.unavailable
        }
        return try body(kem)
    }

    // MARK: - Key generation

    /// Random ML-KEM keypair for `level`. Returns (publicKey, secretKey) at
    /// the level's sizes (1184/2400 for 768, 1568/3168 for 1024).
    static func generateKeyPair(level: Level = .mlkem768) throws -> (publicKey: Data, secretKey: Data) {
        try withKEM(level) { kem in
            var pk = [UInt8](repeating: 0, count: level.publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: level.secretKeyBytes)
            let rc = OQS_KEM_keypair(kem, &pk, &sk)
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("keypair") }
            return (Data(pk), Data(sk))
        }
    }

    /// Derandomized keypair from a 64-byte seed (d‖z). Used for known-answer
    /// tests and for seed-based key storage. Returns (pk, sk).
    static func generateKeyPair(seed: Data, level: Level = .mlkem768) throws -> (publicKey: Data, secretKey: Data) {
        guard seed.count == seedBytes else {
            throw Failure.badInputSize(field: "seed", expected: seedBytes, got: seed.count)
        }
        return try withKEM(level) { kem in
            var pk = [UInt8](repeating: 0, count: level.publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: level.secretKeyBytes)
            let rc = seed.withUnsafeBytes { s in
                OQS_KEM_keypair_derand(kem, &pk, &sk,
                                       s.bindMemory(to: UInt8.self).baseAddress)
            }
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("keypair_derand") }
            return (Data(pk), Data(sk))
        }
    }

    // MARK: - Encapsulation / decapsulation

    /// Encapsulate to a recipient public key. Returns (ciphertext,
    /// sharedSecret 32) at `level`'s sizes. The shared secret is the KEM
    /// output that the RFC 9980 combiner will mix with the ECDH share; it
    /// is never used as a session key directly.
    static func encapsulate(publicKey: Data, level: Level = .mlkem768) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard publicKey.count == level.publicKeyBytes else {
            throw Failure.badInputSize(field: "publicKey", expected: level.publicKeyBytes, got: publicKey.count)
        }
        return try withKEM(level) { kem in
            var ct = [UInt8](repeating: 0, count: level.ciphertextBytes)
            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            let rc = publicKey.withUnsafeBytes { p in
                OQS_KEM_encaps(kem, &ct, &ss,
                               p.bindMemory(to: UInt8.self).baseAddress)
            }
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("encaps") }
            return (Data(ct), Data(ss))
        }
    }

    /// Decapsulate a ciphertext with the secret key. Returns sharedSecret (32).
    /// ML-KEM's implicit rejection means a malformed ciphertext yields a
    /// pseudo-random secret rather than an error — the mismatch surfaces later
    /// when the combined session key fails to unwrap, exactly as intended.
    static func decapsulate(ciphertext: Data, secretKey: Data, level: Level = .mlkem768) throws -> Data {
        guard ciphertext.count == level.ciphertextBytes else {
            throw Failure.badInputSize(field: "ciphertext", expected: level.ciphertextBytes, got: ciphertext.count)
        }
        guard secretKey.count == level.secretKeyBytes else {
            throw Failure.badInputSize(field: "secretKey", expected: level.secretKeyBytes, got: secretKey.count)
        }
        return try withKEM(level) { kem in
            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            let rc = ciphertext.withUnsafeBytes { c in
                secretKey.withUnsafeBytes { sk in
                    OQS_KEM_decaps(kem, &ss,
                                   c.bindMemory(to: UInt8.self).baseAddress,
                                   sk.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("decaps") }
            return Data(ss)
        }
    }
}
