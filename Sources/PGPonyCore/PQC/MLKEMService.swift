// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// MLKEMService.swift
// PGPony — Phase F (PQC).
//
// Thin, safe Swift wrapper over liboqs ML-KEM-768 (FIPS-203). This is the
// crypto-primitive layer: raw key encapsulation only. The RFC 9980 composite
// KEM combiner (ML-KEM-768 + X25519) and the OpenPGP v6 packet framing are
// built ON TOP of this in later Phase-F chunks (F2 = combiner, F3 = packets).
//
// ML-KEM-768 is RFC 9980's mandatory-to-implement KEM (the PQC half of
// composite algorithm 35). Sizes below are fixed by FIPS-203 and are asserted
// against liboqs at call time, so a library/version mismatch fails loudly
// rather than silently corrupting key material.

import Foundation
import COQS

enum MLKEMService {

    // MARK: - FIPS-203 ML-KEM-768 constants

    static let publicKeyBytes    = 1184
    static let secretKeyBytes    = 2400
    static let ciphertextBytes   = 1088
    static let sharedSecretBytes = 32
    /// Derandomized keypair seed = d(32) ‖ z(32). Confirmed against the liboqs
    /// source: coins[0..32) is the IND-CPA seed d, coins[32..64) is the
    /// implicit-rejection value z (matches the FIPS-203 / ACVP d,z ordering).
    static let seedBytes         = 64

    // MARK: - Errors

    enum Failure: Error, LocalizedError {
        case unavailable
        case badInputSize(field: String, expected: Int, got: Int)
        case operationFailed(String)

        var errorDescription: String? {
            switch self {
            case .unavailable:
                return "ML-KEM-768 is not available in this build of liboqs."
            case let .badInputSize(field, expected, got):
                return "ML-KEM \(field) has wrong size: expected \(expected) bytes, got \(got)."
            case let .operationFailed(op):
                return "ML-KEM \(op) failed."
            }
        }
    }

    // MARK: - Handle lifecycle

    /// Runs `body` with a live OQS_KEM handle, freeing it afterwards. Also
    /// asserts liboqs's advertised sizes match our constants, so a mismatched
    /// library can never feed the packet layer wrong-sized buffers.
    private static func withKEM<T>(_ body: (UnsafeMutablePointer<OQS_KEM>) throws -> T) throws -> T {
        guard OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_768) == 1,
              let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768) else {
            throw Failure.unavailable
        }
        defer { OQS_KEM_free(kem) }
        let k = kem.pointee
        guard k.length_public_key == publicKeyBytes,
              k.length_secret_key == secretKeyBytes,
              k.length_ciphertext == ciphertextBytes,
              k.length_shared_secret == sharedSecretBytes else {
            throw Failure.unavailable
        }
        return try body(kem)
    }

    // MARK: - Key generation

    /// Random ML-KEM-768 keypair. Returns (publicKey 1184, secretKey 2400).
    static func generateKeyPair() throws -> (publicKey: Data, secretKey: Data) {
        try withKEM { kem in
            var pk = [UInt8](repeating: 0, count: publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: secretKeyBytes)
            let rc = OQS_KEM_keypair(kem, &pk, &sk)
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("keypair") }
            return (Data(pk), Data(sk))
        }
    }

    /// Derandomized keypair from a 64-byte seed (d‖z). Used for known-answer
    /// tests and for any future seed-based key storage. Returns (pk, sk).
    static func generateKeyPair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        guard seed.count == seedBytes else {
            throw Failure.badInputSize(field: "seed", expected: seedBytes, got: seed.count)
        }
        return try withKEM { kem in
            var pk = [UInt8](repeating: 0, count: publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: secretKeyBytes)
            let rc = seed.withUnsafeBytes { s in
                OQS_KEM_keypair_derand(kem, &pk, &sk,
                                       s.bindMemory(to: UInt8.self).baseAddress)
            }
            guard rc == OQS_SUCCESS else { throw Failure.operationFailed("keypair_derand") }
            return (Data(pk), Data(sk))
        }
    }

    // MARK: - Encapsulation / decapsulation

    /// Encapsulate to a recipient public key. Returns (ciphertext 1088,
    /// sharedSecret 32). The shared secret is the KEM output that the RFC 9980
    /// combiner will mix with the X25519 share — never used as a session key
    /// directly.
    static func encapsulate(publicKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard publicKey.count == publicKeyBytes else {
            throw Failure.badInputSize(field: "publicKey", expected: publicKeyBytes, got: publicKey.count)
        }
        return try withKEM { kem in
            var ct = [UInt8](repeating: 0, count: ciphertextBytes)
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
    static func decapsulate(ciphertext: Data, secretKey: Data) throws -> Data {
        guard ciphertext.count == ciphertextBytes else {
            throw Failure.badInputSize(field: "ciphertext", expected: ciphertextBytes, got: ciphertext.count)
        }
        guard secretKey.count == secretKeyBytes else {
            throw Failure.badInputSize(field: "secretKey", expected: secretKeyBytes, got: secretKey.count)
        }
        return try withKEM { kem in
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
