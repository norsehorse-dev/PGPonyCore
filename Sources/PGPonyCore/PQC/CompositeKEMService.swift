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
                return "Composite KEM X25519 error: \(m)."
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

    // MARK: - Encapsulation / decapsulation

    struct Encapsulation {
        let mlkemCipherText: Data   // 1088
        let ecdhCipherText: Data    // 32  (ephemeral X25519 public key, "V")
        let kek: Data               // 32
    }

    /// Composite encapsulation to a recipient's ML-KEM and X25519 public keys.
    /// The two public keys are taken separately here; the packet layer splits
    /// them out of the concatenated key material.
    static func encapsulate(mlkemPublicKey: Data,
                            ecdhPublicKey: Data) throws -> Encapsulation {
        guard ecdhPublicKey.count == 32 else {
            throw Failure.badKeySize(field: "ecdhPublicKey", expected: 32, got: ecdhPublicKey.count)
        }
        // ML-KEM half.
        let (mlkemCT, kMlkem) = try MLKEMService.encapsulate(publicKey: mlkemPublicKey)

        // X25519 half: fresh ephemeral {v, V}, shared coordinate X = X25519(v, R).
        let recipient: Curve25519.KeyAgreement.PublicKey
        do { recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ecdhPublicKey) }
        catch { throw Failure.ecdh("invalid recipient public key") }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let V = ephemeral.publicKey.rawRepresentation                 // ecdhCipherText
        let X: Data
        do {
            let ss = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
            X = ss.withUnsafeBytes { Data($0) }                       // raw X25519 output
        } catch { throw Failure.ecdh("key agreement failed") }

        let kek = deriveKEK(mlkemKeyShare: kMlkem,
                            ecdhKeyShare: X,
                            ecdhCipherText: V,
                            ecdhPublicKey: ecdhPublicKey)
        return Encapsulation(mlkemCipherText: mlkemCT, ecdhCipherText: V, kek: kek)
    }

    /// Composite decapsulation. Recomputes the KEK from the two ciphertexts and
    /// the recipient's secret keys. `mlkemSecretKey` is the expanded 2400-octet
    /// liboqs secret key — the packet layer derives it from the stored 64-octet
    /// ML-KEM seed via MLKEMService.generateKeyPair(seed:).
    static func decapsulate(mlkemCipherText: Data,
                            ecdhCipherText: Data,
                            mlkemSecretKey: Data,
                            ecdhSecretKey: Data,
                            ecdhPublicKey: Data,
                            algId: UInt8 = algIdMLKEM768X25519) throws -> Data {
        guard ecdhCipherText.count == 32 else {
            throw Failure.badKeySize(field: "ecdhCipherText", expected: 32, got: ecdhCipherText.count)
        }
        guard ecdhSecretKey.count == 32 else {
            throw Failure.badKeySize(field: "ecdhSecretKey", expected: 32, got: ecdhSecretKey.count)
        }
        // ML-KEM half.
        let kMlkem = try MLKEMService.decapsulate(ciphertext: mlkemCipherText,
                                                  secretKey: mlkemSecretKey)
        // X25519 half: X = X25519(r, V).
        let priv: Curve25519.KeyAgreement.PrivateKey
        do { priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ecdhSecretKey) }
        catch { throw Failure.ecdh("invalid secret key") }
        let ephemeral: Curve25519.KeyAgreement.PublicKey
        do { ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ecdhCipherText) }
        catch { throw Failure.ecdh("invalid ephemeral (ciphertext) public key") }
        let X: Data
        do {
            let ss = try priv.sharedSecretFromKeyAgreement(with: ephemeral)
            X = ss.withUnsafeBytes { Data($0) }
        } catch { throw Failure.ecdh("key agreement failed") }

        return deriveKEK(mlkemKeyShare: kMlkem,
                         ecdhKeyShare: X,
                         ecdhCipherText: ecdhCipherText,
                         ecdhPublicKey: ecdhPublicKey,
                         algId: algId)
    }
}
