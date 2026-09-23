// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeKEMPacket.swift
// PGPony — Phase F (PQC) F3.
//
// OpenPGP v6 packet glue for the composite ML-KEM + ECDH KEMs (algorithms
// 35 and 36, RFC 9980). This turns parsed packets into a session key: it
// reads the composite secret-subkey material and decapsulates a composite
// PKESK (parsed by OpenPGPPacketParser) using CompositeKEMService +
// AESKeyWrap.
//
// Scope of this chunk: the DECRYPT core, validated end-to-end against RFC 9980's
// own sample message in CompositePacketKATTests. S2K-protected secret keys, the
// public-key-material import path, and the packet BUILDER (encrypt side) are
// separate later-F3 work.
//
// v8.2.0 §1: generalized over CompositeSuite. The v6 packet layout is
// identical for algorithm 36 (ML-KEM-1024 + X448); only the algorithm-id
// octet and the material lengths change, so parsing derives the suite from
// the algo octet and reads the suite's lengths. The 768 statics stay for
// the callers and tests that reference them.

import Foundation
import CryptoKit

enum CompositeKEMPacket {

    /// RFC 9980 algorithm ID for ML-KEM-768 + X25519.
    static let algId: UInt8 = 35

    /// Fixed sizes for the ML-KEM-768 + X25519 composite (RFC 9980). The
    /// algorithm-36 equivalents come from CompositeSuite.ietf1024; these
    /// stay as named statics for the 768 call sites and KATs.
    static let x25519PublicBytes  = 32
    static let x25519SecretBytes  = 32
    static let mlkemPublicBytes   = 1184
    static let mlkemSeedBytes     = 64      // d‖z, same for every parameter set
    static let publicMaterialBytes = 32 + 1184   // X25519 pub ‖ ML-KEM pub

    struct SecretMaterial {
        let ecdhSecret: [UInt8]   // ECC secret scalar: 32 (X25519) or 56 (X448)
        let ecdhPublic: [UInt8]   // ECC public key, from the packet: 32 or 56
        let mlkemSeed: [UInt8]    // 64 (d‖z; expands to the liboqs secret key)
        /// Which composite this material belongs to. Defaults to the 768
        /// suite so every pre-8.2.0 construction site compiles and behaves
        /// exactly as before.
        let suite: CompositeSuite

        init(ecdhSecret: [UInt8], ecdhPublic: [UInt8], mlkemSeed: [UInt8],
             suite: CompositeSuite = .ietf768) {
            self.ecdhSecret = ecdhSecret
            self.ecdhPublic = ecdhPublic
            self.mlkemSeed = mlkemSeed
            self.suite = suite
        }
    }

    enum Failure: Error, LocalizedError {
        case notComposite
        case protectedKeyUnsupported
        case malformed(String)

        var errorDescription: String? {
            switch self {
            case .notComposite:
                return "Not a composite ML-KEM (algorithm 35/36) packet."
            case .protectedKeyUnsupported:
                return "This composite secret key is passphrase-protected; unlock is handled elsewhere."
            case let .malformed(m):
                return "Malformed composite key packet: \(m)."
            }
        }
    }

    // MARK: - Secret-key material

    /// Parse the secret material of an UNPROTECTED (S2K usage 0) v6
    /// composite secret (sub)key packet body (tag 5 or 7), algorithm 35
    /// or 36.
    ///
    /// Layout (RFC 9580 v6 secret key + RFC 9980 §5.2 key material):
    ///   version(1)=6 | created(4) | algo(1)=35/36 | pubMatLen(4)
    ///   | pubMat( ECCpub ‖ mlkemPub )        [1216 octets @35, 1624 @36]
    ///   | s2kUsage(1)=0
    ///   | ECCsecret ‖ mlkemSeed(64)          [no count, no checksum]
    static func parseUnprotectedSecretMaterial(secretBody body: [UInt8]) throws -> SecretMaterial {
        guard body.count >= 10 else { throw Failure.malformed("secret key packet too short") }
        guard body[0] == 6 else { throw Failure.malformed("not a v6 key packet") }
        guard let suite = CompositeSuite.from(algId: body[5]) else { throw Failure.notComposite }

        let pubMatLen = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
        guard pubMatLen == suite.compositePublicBytes else {
            throw Failure.malformed("unexpected public material length \(pubMatLen)")
        }
        var off = 10
        guard off + pubMatLen <= body.count else {
            throw Failure.malformed("public material truncated")
        }
        let ecdhPublic = Array(body[off..<(off + suite.eccKeyBytes)])   // R
        off += pubMatLen                                                // skip full pubMat

        guard off < body.count else { throw Failure.malformed("missing S2K usage octet") }
        let usage = body[off]; off += 1
        guard usage == 0 else { throw Failure.protectedKeyUnsupported }

        let secretLen = suite.compositeSecretBytes                      // 96 @35, 120 @36
        guard off + secretLen <= body.count else {
            throw Failure.malformed("secret material truncated")
        }
        let ecdhSecret = Array(body[off..<(off + suite.eccKeyBytes)]); off += suite.eccKeyBytes
        let mlkemSeed  = Array(body[off..<(off + mlkemSeedBytes)])

        return SecretMaterial(ecdhSecret: ecdhSecret, ecdhPublic: ecdhPublic,
                              mlkemSeed: mlkemSeed, suite: suite)
    }

    // MARK: - Session-key decapsulation

    /// Decapsulate a composite PKESK (algorithm 35 or 36, parsed by
    /// OpenPGPPacketParser.parsePKESK) to the OpenPGP session key. The ML-KEM
    /// secret key is expanded on the fly from the stored 64-octet seed. The
    /// PKESK's algorithm must match the key material's suite: a 1024 key
    /// cannot open a 768 PKESK or vice versa, and pretending otherwise would
    /// just fail later in the key unwrap with a less precise error.
    static func decryptSessionKey(pkesk: ParsedPKESK, secret: SecretMaterial) throws -> [UInt8] {
        let suite = secret.suite
        guard pkesk.algorithm == suite.algId else { throw Failure.notComposite }
        guard pkesk.ephemeralPublicKey.count == suite.eccKeyBytes else {
            throw Failure.malformed("ecdhCipherText (V) must be \(suite.eccKeyBytes) bytes")
        }
        guard pkesk.mlkemCipherText.count == suite.mlkemCiphertextBytes else {
            throw Failure.malformed("ML-KEM ciphertext must be \(suite.mlkemCiphertextBytes) bytes")
        }
        guard secret.ecdhSecret.count == suite.eccKeyBytes,
              secret.mlkemSeed.count == 64,
              secret.ecdhPublic.count == suite.eccKeyBytes else {
            throw Failure.malformed("bad secret material sizes")
        }

        // Expand the 64-octet ML-KEM seed to the liboqs expanded secret key.
        let (_, mlkemSK) = try MLKEMService.generateKeyPair(seed: Data(secret.mlkemSeed),
                                                           level: suite.mlkemLevel)

        let kek = try CompositeKEMService.decapsulate(
            mlkemCipherText: Data(pkesk.mlkemCipherText),
            ecdhCipherText: Data(pkesk.ephemeralPublicKey),
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: Data(secret.ecdhSecret),
            ecdhPublicKey: Data(secret.ecdhPublic),
            algId: suite.algId)

        // v6 composite PKESK: the AES-unwrapped plaintext IS the session key
        // (no leading symmetric-algorithm octet, no trailing checksum).
        return try AESKeyWrap.unwrap(ciphertext: pkesk.wrappedSessionKey, kek: [UInt8](kek))
    }

    // MARK: - Decrypt-path glue

    /// A stored composite secret key made available to the message-decrypt path.
    struct DecryptionKey {
        let subkeyID: [UInt8]            // first 8 octets of the v6 subkey fingerprint
        let subkeyFingerprint: [UInt8]   // 32-octet v6 subkey fingerprint
        let secret: SecretMaterial
    }

    /// Try each composite key against a parsed v6 composite PKESK (algorithm
    /// 35 or 36) and return the session key from the first that unwraps. AES
    /// Key Wrap carries an integrity check, so a wrong key (whose ML-KEM
    /// implicit rejection yields a bogus KEK) makes `decryptSessionKey`
    /// throw, and we simply move on. Keys whose fingerprint doesn't match the PKESK
    /// are skipped first; an anonymous recipient (empty PKESK fingerprint)
    /// falls through to try every key. A suite-mismatched key (768 key
    /// against a 36 PKESK) fails decryptSessionKey's algorithm guard and is
    /// skipped the same way.
    static func trySessionKey(pkesk: ParsedPKESK, keys: [DecryptionKey]) -> [UInt8]? {
        guard CompositeSuite.from(algId: pkesk.algorithm) != nil else { return nil }
        for key in keys {
            let targeted = pkesk.keyFingerprint == key.subkeyFingerprint
                || (!pkesk.keyID.isEmpty && pkesk.keyID == key.subkeyID)
            let anonymous = pkesk.keyFingerprint.isEmpty && pkesk.keyID.allSatisfy { $0 == 0 }
            guard targeted || anonymous else { continue }
            if let sk = try? decryptSessionKey(pkesk: pkesk, secret: key.secret) {
                return sk
            }
        }
        return nil
    }
}
