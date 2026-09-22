// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SymmetricEncryption.swift
// PGPony
//
// Passphrase-only ("gpg -c") OpenPGP encryption.
//
// To be openable by any real-world GnuPG (including 2.2 / 2.4, which do not
// understand RFC 9580 v6 packets), PGPony EMITS the classic gpg -c format:
//   SKESK v4 (iterated-salted S2K, mode 3) || SEIPDv1 (CFB + SHA-1 MDC).
// The S2K-derived key is used directly as the session key (there is no
// encrypted-session-key field), exactly as `gpg --symmetric` produces.
//
// On DECRYPT, PGPony reads all three:
//   - v4 SKESK (S2K modes 0 / 1 / 3)  -> SEIPDv1 (CFB + MDC)
//   - v5 SKESK (LibrePGP, S2K + AEAD) -> tag 20 AEAD Encrypted Data (OCB)
//   - v6 SKESK (Argon2id)             -> SEIPDv2 (AES-OCB)
// so it can open classic gpg -c output, the `gpg -c --force-aead` output of
// GnuPG 2.2.8 through 2.5.x (8.3.0, field report against a 2.5.22 file), and
// any v6 messages produced by earlier builds.
//
// New code here is confined to the v4 SKESK build/parse. The S2K derivation,
// the SEIPD bodies, packet parsing, and armoring are all reused from existing,
// GnuPG-verified code (S2K.deriveKey, OpenPGPPacketBuilder, and
// OpenPGPPacketParser).

import Foundation
import Security

enum SymmetricEncryptionError: LocalizedError {
    case randomGenerationFailed
    case noSKESK
    case noSEIPD
    case unsupportedSKESKVersion(UInt8)
    case unsupportedSEIPDVersion(UInt8)
    case unsupportedCipher(UInt8)
    case malformedSKESK(String)
    case wrongPassphrase

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            return "Failed to generate secure random bytes."
        case .noSKESK:
            return "This message is not passphrase-encrypted (no SKESK packet found)."
        case .noSEIPD:
            return "No encrypted data packet (SEIPD) was found in the message."
        case .unsupportedSKESKVersion(let v):
            return "Unsupported passphrase-packet version \(v)."
        case .unsupportedSEIPDVersion(let v):
            return "Unsupported encrypted-data version \(v)."
        case .unsupportedCipher(let c):
            return "Unsupported cipher algorithm \(c)."
        case .malformedSKESK(let m):
            return "Malformed passphrase packet: \(m)."
        case .wrongPassphrase:
            return "Incorrect passphrase."
        }
    }
}

enum SymmetricEncryption {

    // Emit parameters (classic gpg -c, AES-256).
    static let cipherAES256: UInt8 = 9
    static let hashSHA256: UInt8 = 8
    static let s2kIteratedSalted: UInt8 = 3
    // Coded iteration count. 0xFF decodes to 65,011,712 bytes, matching gpg's
    // default. Decode: (16 + (c & 15)) << ((c >> 4) + 6).
    static let s2kCodedCount: UInt8 = 0xFF
    static let s2kSaltSize = 8

    // MARK: - Detection

    static func isSymmetric(message: [UInt8]) -> Bool {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: message) else { return false }
        return packets.contains { $0.tag == 3 } && !packets.contains { $0.tag == 1 }
    }

    static func isSymmetric(armored: String) -> Bool {
        guard let data = try? OpenPGPPacketParser.dearmor(armored) else { return false }
        return isSymmetric(message: Array(data))
    }

    // MARK: - Encrypt (classic gpg -c)

    static func encrypt(plaintext: [UInt8], passphrase: String, filename: String? = nil) throws -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: s2kSaltSize)
        guard SecRandomCopyBytes(kSecRandomDefault, s2kSaltSize, &salt) == errSecSuccess else {
            throw SymmetricEncryptionError.randomGenerationFailed
        }

        let keySize = try cipherKeySize(cipherAES256)
        // The iterated-salted S2K output is used directly as the session key.
        let sessionKey = S2K.deriveKey(
            passphrase: passphrase,
            salt: salt,
            s2kType: s2kIteratedSalted,
            hashAlgo: hashSHA256,
            codedCount: s2kCodedCount,
            keySize: keySize
        )

        let skesk = buildV4SKESK(
            salt: salt,
            cipherAlgo: cipherAES256,
            hashAlgo: hashSHA256,
            codedCount: s2kCodedCount
        )

        let seipd = try OpenPGPPacketBuilder.buildSEIPDPacket(
            plaintext: plaintext,
            sessionKey: sessionKey,
            sessionAlgorithmID: cipherAES256,
            filename: filename
        )

        return skesk + Array(seipd)
    }

    static func encryptArmored(plaintext: [UInt8], passphrase: String, filename: String? = nil) throws -> String {
        let raw = try encrypt(plaintext: plaintext, passphrase: passphrase, filename: filename)
        return OpenPGPPacketBuilder.armorMessage(Data(raw))
    }

    // MARK: - Decrypt (reads classic v4 and legacy v6)

    static func decrypt(message: [UInt8], passphrase: String) throws -> [UInt8] {
        let packets = try OpenPGPPacketParser.parsePackets(data: message)

        guard let skesk = packets.first(where: { $0.tag == 3 }) else {
            throw SymmetricEncryptionError.noSKESK
        }
        let opened = try openSKESK(body: skesk.body, passphrase: passphrase)

        let inner: [UInt8]
        if let aeadPacket = packets.first(where: { $0.tag == 20 }) {
            // `gpg -c --force-aead` (GnuPG 2.2.8 through 2.5.x) pairs a v5
            // SKESK with a LibrePGP AEAD Encrypted Data packet (tag 20), the
            // same body the PKESK paths already decrypt for AEAD messages
            // addressed to a key. The v5 unwrap above is authenticated, so a
            // wrong passphrase has already been reported there; a failure here
            // is a damaged body or an AEAD mode this build lacks (EAX), and
            // its own message is the useful one.
            inner = try OpenPGPPacketParser.decryptAEADEncryptedData(
                body: aeadPacket.body,
                sessionKey: opened.sessionKey
            )
        } else {
            guard let seipdPacket = packets.first(where: { $0.tag == 18 }) else {
                throw SymmetricEncryptionError.noSEIPD
            }
            let seipd = try OpenPGPPacketParser.parseSEIPD(body: seipdPacket.body)

            do {
                switch seipd.version {
                case 1:
                    inner = try OpenPGPPacketParser.decryptSEIPD(
                        encryptedData: seipd.encryptedData,
                        sessionKey: opened.sessionKey,
                        algorithmID: opened.cipherAlgo
                    )
                case 2:
                    inner = try OpenPGPPacketParser.decryptSEIPDv2(
                        seipd: seipd,
                        sessionKey: opened.sessionKey
                    )
                default:
                    throw SymmetricEncryptionError.unsupportedSEIPDVersion(seipd.version)
                }
            } catch let e as SymmetricEncryptionError {
                throw e
            } catch {
                // A v4 SKESK is not authenticated, so a wrong passphrase surfaces as
                // an MDC / decryption failure at this step rather than earlier.
                throw SymmetricEncryptionError.wrongPassphrase
            }
        }

        let innerPackets = try OpenPGPPacketParser.parsePackets(data: inner)
        if let literal = try OpenPGPPacketParser.extractLiteralData(from: innerPackets) {
            return Array(literal)
        }
        return inner
    }

    static func decryptArmored(armored: String, passphrase: String) throws -> [UInt8] {
        let data = try OpenPGPPacketParser.dearmor(armored)
        return try decrypt(message: Array(data), passphrase: passphrase)
    }

    // MARK: - SKESK build / open

    private static func buildV4SKESK(salt: [UInt8], cipherAlgo: UInt8,
                                     hashAlgo: UInt8, codedCount: UInt8) -> [UInt8] {
        // body: version(4) | cipher | S2K(type 3 | hash | salt(8) | count)
        // No encrypted session key: the S2K output is the session key.
        var body: [UInt8] = [0x04, cipherAlgo, s2kIteratedSalted, hashAlgo]
        body += salt
        body.append(codedCount)
        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 3, body: body)
    }

    private static func openSKESK(body: [UInt8], passphrase: String) throws
        -> (sessionKey: [UInt8], cipherAlgo: UInt8) {
        guard let version = body.first else {
            throw SymmetricEncryptionError.malformedSKESK("empty")
        }
        switch version {
        case 4:
            return try openV4SKESK(body: body, passphrase: passphrase)
        case 5:
            return try openV5SKESK(body: body, passphrase: passphrase)
        case 6:
            let key = try openV6SKESK(body: body, passphrase: passphrase)
            // v6 pairs with SEIPDv2, which carries its own cipher; this value is
            // unused on that path but returned for a consistent signature.
            let cipher = body.count > 2 ? body[2] : cipherAES256
            return (key, cipher)
        default:
            throw SymmetricEncryptionError.unsupportedSKESKVersion(version)
        }
    }

    private static func openV4SKESK(body: [UInt8], passphrase: String) throws
        -> (sessionKey: [UInt8], cipherAlgo: UInt8) {
        var off = 0
        func need(_ n: Int) throws {
            guard off + n <= body.count else {
                throw SymmetricEncryptionError.malformedSKESK("truncated")
            }
        }

        try need(3)
        off += 1                                  // version (4)
        let cipherAlgo = body[off]; off += 1
        let s2kType = body[off]; off += 1

        var hashAlgo: UInt8 = hashSHA256
        var salt: [UInt8] = []
        var codedCount: UInt8 = 0
        switch s2kType {
        case 0:                                    // Simple
            try need(1)
            hashAlgo = body[off]; off += 1
        case 1:                                    // Salted
            try need(9)
            hashAlgo = body[off]; off += 1
            salt = Array(body[off..<off + 8]); off += 8
        case 3:                                    // Iterated + salted (gpg -c default)
            try need(10)
            hashAlgo = body[off]; off += 1
            salt = Array(body[off..<off + 8]); off += 8
            codedCount = body[off]; off += 1
        default:
            throw SymmetricEncryptionError.malformedSKESK("unsupported S2K type \(s2kType)")
        }

        // Classic gpg -c carries no encrypted session key; the S2K output is it.
        guard off == body.count else {
            throw SymmetricEncryptionError.malformedSKESK("v4 SKESK with an encrypted session key is not supported")
        }

        let keySize = try cipherKeySize(cipherAlgo)
        let sessionKey = S2K.deriveKey(
            passphrase: passphrase,
            salt: salt,
            s2kType: s2kType,
            hashAlgo: hashAlgo,
            codedCount: codedCount,
            keySize: keySize
        )
        return (sessionKey, cipherAlgo)
    }

    // Reads a LibrePGP v5 SKESK, the packet GnuPG writes for `gpg -c
    // --force-aead` (2.2.8 through 2.5.x). Layout, per LibrePGP section 5.3:
    //   version(5) | cipher | aead | S2K specifier | nonce (15 for OCB, 16 for
    //   EAX) | encrypted session key (cipher key length) | auth tag (16)
    // The S2K output is the key-encryption key as it is (no HKDF step, which
    // is the v6 difference), and the associated data is the four header
    // octets 0xC3 | 0x05 | cipher | aead. The packet after it is a tag 20
    // AEAD Encrypted Data packet, which decrypt() hands to the parser's
    // existing tag 20 routine. Verified against a gpg 2.5.22 file (AES-256,
    // OCB, S2K type 3 with SHA-256); see SymmetricAEADv5Tests.
    private static func openV5SKESK(body: [UInt8], passphrase: String) throws
        -> (sessionKey: [UInt8], cipherAlgo: UInt8) {
        var off = 0
        func need(_ n: Int, _ what: String) throws {
            guard off + n <= body.count else {
                throw SymmetricEncryptionError.malformedSKESK("truncated \(what)")
            }
        }

        try need(4, "header")
        off += 1                                  // version (5)
        let cipherAlgo = body[off]; off += 1
        let aeadAlgo = body[off]; off += 1
        let s2kType = body[off]; off += 1
        let keySize = try cipherKeySize(cipherAlgo)

        let kek: [UInt8]
        switch s2kType {
        case 0, 1, 3:                              // Simple / Salted / Iterated+salted
            try need(1, "S2K hash")
            let hashAlgo = body[off]; off += 1
            var salt: [UInt8] = []
            var codedCount: UInt8 = 0
            if s2kType != 0 {
                try need(8, "S2K salt")
                salt = Array(body[off..<off + 8]); off += 8
            }
            if s2kType == 3 {
                try need(1, "S2K count")
                codedCount = body[off]; off += 1
            }
            // CORE SEAM: the app calls PGPService.s2kDeriveKey; S2K.deriveKey is the same loop.
            kek = S2K.deriveKey(
                passphrase: passphrase,
                salt: salt,
                s2kType: s2kType,
                hashAlgo: hashAlgo,
                codedCount: codedCount,
                keySize: keySize
            )
        case 4:                                    // Argon2: salt(16) | t | p | m
            try need(19, "Argon2 S2K")
            let salt = Array(body[off..<off + 16]); off += 16
            let t = Int(body[off]); off += 1
            let p = Int(body[off]); off += 1
            let m = Int(body[off]); off += 1
            kek = try Argon2Service.deriveKey(
                passphrase: passphrase,
                salt: salt,
                iterations: t,
                parallelism: p,
                memoryExponent: m,
                hashLength: keySize
            )
        default:
            throw SymmetricEncryptionError.malformedSKESK("unsupported S2K type \(s2kType) in a v5 SKESK")
        }

        let nonceLen = AEADService.nonceSize(for: aeadAlgo)
        guard nonceLen > 0 else {
            throw SymmetricEncryptionError.malformedSKESK("unknown AEAD algorithm \(aeadAlgo)")
        }
        try need(nonceLen, "nonce")
        let nonce = Array(body[off..<off + nonceLen]); off += nonceLen

        try need(keySize + AEADService.tagSize, "encrypted session key")
        let encKey = Array(body[off..<off + keySize]); off += keySize
        let tag = Array(body[off..<off + AEADService.tagSize]); off += AEADService.tagSize

        let aad: [UInt8] = [0xC3, 0x05, cipherAlgo, aeadAlgo]
        do {
            let sessionKey = try AEADService.decrypt(
                ciphertext: encKey,
                tag: tag,
                key: kek,
                nonce: nonce,
                aeadAlgo: aeadAlgo,
                associatedData: aad
            )
            return (sessionKey, cipherAlgo)
        } catch AEADError.unsupportedAlgorithm(let a) {
            // An AEAD mode this build cannot do (EAX) is a capability gap, not
            // a wrong passphrase; say so instead of asking for it again.
            throw AEADError.unsupportedAlgorithm(a)
        } catch {
            throw SymmetricEncryptionError.wrongPassphrase
        }
    }

    // Reads a legacy v6 SKESK (Argon2id) that earlier PGPony builds produced.
    private static func openV6SKESK(body: [UInt8], passphrase: String) throws -> [UInt8] {
        var off = 0
        func need(_ n: Int, _ what: String) throws {
            guard off + n <= body.count else {
                throw SymmetricEncryptionError.malformedSKESK("truncated \(what)")
            }
        }

        try need(2, "header")
        off += 1                                  // version (6)
        off += 1                                  // length of the 4 following fields
        try need(3, "algorithms")
        let cipherAlgo = body[off]; off += 1
        let aeadAlgo = body[off]; off += 1
        let s2kLen = Int(body[off]); off += 1

        try need(s2kLen, "S2K")
        let s2k = Array(body[off..<off + s2kLen]); off += s2kLen
        guard s2k.count == 20, s2k[0] == 4 else {
            throw SymmetricEncryptionError.malformedSKESK("expected a 20-byte Argon2 S2K")
        }
        let salt = Array(s2k[1..<17])
        let t = Int(s2k[17])
        let p = Int(s2k[18])
        let m = Int(s2k[19])

        let nonceLen = AEADService.nonceSize(for: aeadAlgo)
        try need(nonceLen, "nonce")
        let nonce = Array(body[off..<off + nonceLen]); off += nonceLen

        let remaining = Array(body[off...])
        guard remaining.count > AEADService.tagSize else {
            throw SymmetricEncryptionError.malformedSKESK("missing encrypted session key")
        }
        let split = remaining.count - AEADService.tagSize
        let encKey = Array(remaining[0..<split])
        let tag = Array(remaining[split...])

        let kek = try Argon2Service.deriveKey(
            passphrase: passphrase,
            salt: salt,
            iterations: t,
            parallelism: p,
            memoryExponent: m,
            hashLength: 32
        )
        let aad: [UInt8] = [0xC3, 0x06, cipherAlgo, aeadAlgo]
        do {
            return try AEADService.decrypt(
                ciphertext: encKey,
                tag: tag,
                key: kek,
                nonce: nonce,
                aeadAlgo: aeadAlgo,
                associatedData: aad
            )
        } catch {
            throw SymmetricEncryptionError.wrongPassphrase
        }
    }

    // MARK: - Helpers

    private static func cipherKeySize(_ cipherID: UInt8) throws -> Int {
        switch cipherID {
        case 7: return 16   // AES-128
        case 8: return 24   // AES-192
        case 9: return 32   // AES-256
        default: throw SymmetricEncryptionError.unsupportedCipher(cipherID)
        }
    }
}
