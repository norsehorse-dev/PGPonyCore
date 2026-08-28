// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeKEMService.swift
// PGPony — Phase F (PQC).
//
// RFC 9980 §4 composite KEM: ML-KEM-768 + X25519 (algorithm ID 35). This layer
// combines the two KEM halves into a single Key-Encryption Key (KEK) using the
// RFC 9980 §4.2.1 key combiner. The KEK then wraps the OpenPGP session key with
// AES-256 Key Wrap (RFC 3394, see AESKeyWrap) in the PKESK — that framing lives
// in the packet layer (Phase F3/F4); this file is the algorithm itself.
//
// Every constant here (the SHA3-256 combiner, the 21-octet "OpenPGPCompositeKDFv1"
// domain separator, algorithm ID 0x23, the ecdhCipherText/ecdhPublicKey ordering)
// is validated byte-for-byte against RFC 9980's own test vector in
// CompositeKEMKATTests — do not change one without re-running that KAT.
//
// v8.2.0 §1: generalized over CompositeSuite so the same audited combiner
// also carries algorithm 36 (ML-KEM-1024 + X448, hand-rolled curve in
// X448.swift). The construction is IDENTICAL for both suites: only the
// curve, the ML-KEM parameter set, the byte lengths, and the algorithm-id
// octet in the KDF input differ, and the KEK stays SHA3-256/32 octets for
// both (it wraps an AES-256 session key either way). Every entry point
// defaults to the 768 suite, so all Phase-F callers and the KAT run the
// exact prior code path. This mirrors the Android 4.2.0 CompositeKem
// design, which is gpg-2.5.x interop-validated for both suites.

import Foundation
import CryptoKit
import COQS

enum CompositeKEMService {

    /// RFC 9980 §4.2.1 domain separator: UTF-8 "OpenPGPCompositeKDFv1", 21 octets.
    static let domainSeparator: [UInt8] = Array("OpenPGPCompositeKDFv1".utf8)

    /// RFC 9980 algorithm ID for ML-KEM-768 + X25519 (mandatory to implement).
    static let algIdMLKEM768X25519: UInt8 = 35

    enum Failure: Error, LocalizedError {
        case badKeySize(field: String, expected: Int, got: Int)
        case ecdh(String)

        var errorDescription: String? {
            switch self {
            case let .badKeySize(field, expected, got):
                return "Composite KEM \(field) has wrong size: expected \(expected), got \(got)."
            case let .ecdh(m):
                return "Composite KEM ECDH error: \(m)."
            }
        }
    }

    // MARK: - SHA3-256 (from liboqs)

    private static func sha3_256(_ input: [UInt8]) -> Data {
        var out = [UInt8](repeating: 0, count: 32)
        OQS_SHA3_sha3_256(&out, input, input.count)
        return Data(out)
    }

    // MARK: - Key combiner (RFC 9980 §4.2.1)

    /// multiKeyCombine: derive the 32-byte KEK from the two KEM key shares plus
    /// the ECDH ciphertext and recipient ECDH public key.
    ///
    ///     KEK = SHA3-256( mlkemKeyShare ‖ ecdhKeyShare ‖ ecdhCipherText
    ///                     ‖ ecdhPublicKey ‖ algId ‖ domSep ‖ len(domSep) )
    ///
    /// All key shares / keys are 32-octet strings for the ML-KEM-768+X25519 set.
    static func deriveKEK(mlkemKeyShare: Data,
                          ecdhKeyShare: Data,
                          ecdhCipherText: Data,
                          ecdhPublicKey: Data,
                          algId: UInt8 = algIdMLKEM768X25519) -> Data {
        var buf = [UInt8]()
        buf.reserveCapacity(32 * 4 + 1 + domainSeparator.count + 1)
        buf.append(contentsOf: mlkemKeyShare)
        buf.append(contentsOf: ecdhKeyShare)
        buf.append(contentsOf: ecdhCipherText)
        buf.append(contentsOf: ecdhPublicKey)
        buf.append(algId)
        buf.append(contentsOf: domainSeparator)
        buf.append(UInt8(domainSeparator.count))   // len(domSep) = 21 = 0x15
        return sha3_256(buf)
    }

    // MARK: - ECDH halves

    /// Fresh ephemeral keypair on the suite's curve: (secret, public).
    private static func generateEphemeral(_ suite: CompositeSuite) throws -> (secret: Data, publicKey: Data) {
        switch suite {
        case .ietf768:
            let priv = Curve25519.KeyAgreement.PrivateKey()
            return (priv.rawRepresentation, priv.publicKey.rawRepresentation)
        case .ietf1024:
            let priv = try X448.generatePrivateKey()
            return (priv, try X448.publicKey(for: priv))
        }
    }

    /// ECDH agreement on the suite's curve: the raw shared u-coordinate.
    /// Both curves reject a degenerate (all-zero) share: CryptoKit throws on
    /// low-order X25519 inputs, and X448.sharedSecret carries the RFC 7748
    /// §6.2 zero check. A poisoned ephemeral therefore fails the decrypt
    /// instead of deriving a predictable KEK.
    private static func agree(_ suite: CompositeSuite, secret: Data, peerPublic: Data) throws -> Data {
        switch suite {
        case .ietf768:
            let priv: Curve25519.KeyAgreement.PrivateKey
            do { priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret) }
            catch { throw Failure.ecdh("invalid secret key") }
            let peer: Curve25519.KeyAgreement.PublicKey
            do { peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic) }
            catch { throw Failure.ecdh("invalid public key") }
            do {
                let ss = try priv.sharedSecretFromKeyAgreement(with: peer)
                return ss.withUnsafeBytes { Data($0) }               // raw X25519 output
            } catch { throw Failure.ecdh("key agreement failed") }
        case .ietf1024:
            do { return try X448.sharedSecret(privateKey: secret, publicKey: peerPublic) }
            catch { throw Failure.ecdh("X448 agreement failed: \(error.localizedDescription)") }
        }
    }

    // MARK: - Encapsulation / decapsulation

    struct Encapsulation {
        let mlkemCipherText: Data   // 1088 (768) or 1568 (1024)
        let ecdhCipherText: Data    // ephemeral ECDH public "V": 32 (X25519) or 56 (X448)
        let kek: Data               // 32 for both suites
    }

    /// Composite encapsulation to a recipient's ML-KEM and ECDH public keys.
    /// The two public keys are taken separately here; the packet layer splits
    /// them out of the concatenated key material.
    static func encapsulate(mlkemPublicKey: Data,
                            ecdhPublicKey: Data,
                            suite: CompositeSuite = .ietf768) throws -> Encapsulation {
        guard ecdhPublicKey.count == suite.eccKeyBytes else {
            throw Failure.badKeySize(field: "ecdhPublicKey", expected: suite.eccKeyBytes, got: ecdhPublicKey.count)
        }
        // ML-KEM half.
        let (mlkemCT, kMlkem) = try MLKEMService.encapsulate(publicKey: mlkemPublicKey,
                                                             level: suite.mlkemLevel)
        // ECDH half: fresh ephemeral {v, V}, shared coordinate X = ECDH(v, R).
        let (ephSecret, V) = try generateEphemeral(suite)
        let X = try agree(suite, secret: ephSecret, peerPublic: ecdhPublicKey)

        let kek = deriveKEK(mlkemKeyShare: kMlkem,
                            ecdhKeyShare: X,
                            ecdhCipherText: V,
                            ecdhPublicKey: ecdhPublicKey,
                            algId: suite.algId)
        return Encapsulation(mlkemCipherText: mlkemCT, ecdhCipherText: V, kek: kek)
    }

    /// Composite decapsulation. Recomputes the KEK from the two ciphertexts and
    /// the recipient's secret keys. `mlkemSecretKey` is the expanded liboqs
    /// secret key (2400 octets for 768, 3168 for 1024); the packet layer
    /// derives it from the stored 64-octet ML-KEM seed via
    /// MLKEMService.generateKeyPair(seed:level:). The suite is selected by
    /// `algId`, exactly as it arrives in the PKESK.
    static func decapsulate(mlkemCipherText: Data,
                            ecdhCipherText: Data,
                            mlkemSecretKey: Data,
                            ecdhSecretKey: Data,
                            ecdhPublicKey: Data,
                            algId: UInt8 = algIdMLKEM768X25519) throws -> Data {
        guard let suite = CompositeSuite.from(algId: algId) else {
            throw Failure.ecdh("unknown composite algorithm id \(algId)")
        }
        guard ecdhCipherText.count == suite.eccKeyBytes else {
            throw Failure.badKeySize(field: "ecdhCipherText", expected: suite.eccKeyBytes, got: ecdhCipherText.count)
        }
        guard ecdhSecretKey.count == suite.eccKeyBytes else {
            throw Failure.badKeySize(field: "ecdhSecretKey", expected: suite.eccKeyBytes, got: ecdhSecretKey.count)
        }
        // ML-KEM half.
        let kMlkem = try MLKEMService.decapsulate(ciphertext: mlkemCipherText,
                                                  secretKey: mlkemSecretKey,
                                                  level: suite.mlkemLevel)
        // ECDH half: X = ECDH(r, V).
        let X = try agree(suite, secret: ecdhSecretKey, peerPublic: ecdhCipherText)

        return deriveKEK(mlkemKeyShare: kMlkem,
                         ecdhKeyShare: X,
                         ecdhCipherText: ecdhCipherText,
                         ecdhPublicKey: ecdhPublicKey,
                         algId: algId)
    }
}
