// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeKEMPacket.swift
// PGPony — Phase F (PQC) F3.
//
// OpenPGP v6 packet glue for the composite ML-KEM-768 + X25519 KEM (algorithm
// 35, RFC 9980). This turns parsed packets into a session key: it reads the
// composite secret-subkey material and decapsulates a composite PKESK (parsed
// by OpenPGPPacketParser) using CompositeKEMService + AESKeyWrap.
//
// Scope of this chunk: the DECRYPT core, validated end-to-end against RFC 9980's
// own sample message in CompositePacketKATTests. S2K-protected secret keys, the
// public-key-material import path, and the packet BUILDER (encrypt side) are
// separate later-F3 work.

import Foundation
import CryptoKit

enum CompositeKEMPacket {

    /// RFC 9980 algorithm ID for ML-KEM-768 + X25519.
    static let algId: UInt8 = 35

    /// Fixed sizes for the ML-KEM-768 + X25519 composite (RFC 9980).
    static let x25519PublicBytes  = 32
    static let x25519SecretBytes  = 32
    static let mlkemPublicBytes   = 1184
    static let mlkemSeedBytes     = 64      // d‖z
    static let publicMaterialBytes = 32 + 1184   // X25519 pub ‖ ML-KEM pub

    struct SecretMaterial {
        let ecdhSecret: [UInt8]   // 32  (X25519 secret scalar)
        let ecdhPublic: [UInt8]   // 32  (X25519 public key, from the packet)
        let mlkemSeed: [UInt8]    // 64  (d‖z; expands to the liboqs secret key)
    }

    enum Failure: Error, LocalizedError {
        case notComposite
        case protectedKeyUnsupported
        case malformed(String)

        var errorDescription: String? {
            switch self {
            case .notComposite:
                return "Not an ML-KEM-768+X25519 (algorithm 35) packet."
            case .protectedKeyUnsupported:
                return "This composite secret key is passphrase-protected; unlock is handled elsewhere."
            case let .malformed(m):
                return "Malformed composite key packet: \(m)."
            }
        }
    }

    // MARK: - Secret-key material

    /// Parse the secret material of an UNPROTECTED (S2K usage 0) v6
    /// ML-KEM-768+X25519 secret (sub)key packet body (tag 5 or 7).
    ///
    /// Layout (RFC 9580 v6 secret key + RFC 9980 §5.2 key material):
    ///   version(1)=6 | created(4) | algo(1)=35 | pubMatLen(4)
    ///   | pubMat( X25519pub(32) ‖ mlkemPub(1184) )       [= 1216 octets]
    ///   | s2kUsage(1)=0
    ///   | X25519secret(32) ‖ mlkemSeed(64)               [no count, no checksum]
    static func parseUnprotectedSecretMaterial(secretBody body: [UInt8]) throws -> SecretMaterial {
        guard body.count >= 10 else { throw Failure.malformed("secret key packet too short") }
        guard body[0] == 6 else { throw Failure.malformed("not a v6 key packet") }
        guard body[5] == algId else { throw Failure.notComposite }

        let pubMatLen = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
        guard pubMatLen == publicMaterialBytes else {
            throw Failure.malformed("unexpected public material length \(pubMatLen)")
        }
        var off = 10
        let ecdhPublic = Array(body[off..<(off + x25519PublicBytes)])   // R
        off += pubMatLen                                                // skip full pubMat

        guard off < body.count else { throw Failure.malformed("missing S2K usage octet") }
        let usage = body[off]; off += 1
        guard usage == 0 else { throw Failure.protectedKeyUnsupported }

        let secretLen = x25519SecretBytes + mlkemSeedBytes              // 96
        guard off + secretLen <= body.count else {
            throw Failure.malformed("secret material truncated")
        }
        let ecdhSecret = Array(body[off..<(off + x25519SecretBytes)]); off += x25519SecretBytes
        let mlkemSeed  = Array(body[off..<(off + mlkemSeedBytes)])

        return SecretMaterial(ecdhSecret: ecdhSecret, ecdhPublic: ecdhPublic, mlkemSeed: mlkemSeed)
    }

    // MARK: - Session-key decapsulation

    /// Decapsulate a composite PKESK (algorithm 35, parsed by
    /// OpenPGPPacketParser.parsePKESK) to the OpenPGP session key. The ML-KEM
    /// secret key is expanded on the fly from the stored 64-octet seed.
    static func decryptSessionKey(pkesk: ParsedPKESK, secret: SecretMaterial) throws -> [UInt8] {
        guard pkesk.algorithm == algId else { throw Failure.notComposite }
        guard pkesk.ephemeralPublicKey.count == 32 else {
            throw Failure.malformed("ecdhCipherText (V) must be 32 bytes")
        }
        guard pkesk.mlkemCipherText.count == 1088 else {
            throw Failure.malformed("ML-KEM ciphertext must be 1088 bytes")
        }
        guard secret.ecdhSecret.count == 32,
              secret.mlkemSeed.count == 64,
              secret.ecdhPublic.count == 32 else {
            throw Failure.malformed("bad secret material sizes")
        }

        // Expand the 64-octet ML-KEM seed to the liboqs 2400-octet secret key.
        let (_, mlkemSK) = try MLKEMService.generateKeyPair(seed: Data(secret.mlkemSeed))

        let kek = try CompositeKEMService.decapsulate(
            mlkemCipherText: Data(pkesk.mlkemCipherText),
            ecdhCipherText: Data(pkesk.ephemeralPublicKey),
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: Data(secret.ecdhSecret),
            ecdhPublicKey: Data(secret.ecdhPublic),
            algId: algId)

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

    /// Try each composite key against a parsed v6 algorithm-35 PKESK and return
    /// the session key from the first that unwraps. AES Key Wrap carries an
    /// integrity check, so a wrong key (whose ML-KEM implicit rejection yields a
    /// bogus KEK) makes `decryptSessionKey` throw — we simply move on. Keys whose
    /// fingerprint doesn't match the PKESK are skipped first; an anonymous
    /// recipient (empty PKESK fingerprint) falls through to try every key.
    static func trySessionKey(pkesk: ParsedPKESK, keys: [DecryptionKey]) -> [UInt8]? {
        guard pkesk.algorithm == algId else { return nil }
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
