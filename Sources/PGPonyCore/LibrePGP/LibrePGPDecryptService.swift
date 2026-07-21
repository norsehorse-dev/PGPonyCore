// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPDecryptService.swift
// PGPony — Phase F (PQC), LibrePGP / GnuPG interop (decrypt side).
//
// Inverse of LibrePGPEncryptService: decrypts a GnuPG LibrePGP PQC message
// (v3 PKESK for a v5 Kyber subkey, algorithm 8) using a stored composite secret
// subkey. Recovers the session key via the SHA3-256(rawECDH‖ct‖pk) + KMAC256
// combiner and AES-256 key-unwrap, then hands it to the shared SEIPD/AEAD
// pipeline (GnuPG wraps these in SEIPDv1 when the recipient key does not
// advertise AEAD, so compression + MDC are handled downstream).
//
// Validated end to end: gpg encrypts to a PGPony-generated LibrePGP key and this
// path recovers the plaintext.

import Foundation
import CryptoKit
import CommonCrypto

enum LibrePGPDecryptService {

    enum Failure: Error, LocalizedError {
        case noCompositeSubkey
        case noPKESK
        case malformed(String)
        case passphraseRequired
        case invalidPassphrase
        case foreignSecretFormat

        var errorDescription: String? {
            switch self {
            case .noCompositeSubkey: return "No LibrePGP ML-KEM+X25519 secret subkey found"
            case .noPKESK:           return "No LibrePGP (algorithm 8) PKESK in the message"
            case .malformed(let m):  return "Malformed LibrePGP data: \(m)"
            case .passphraseRequired: return "This LibrePGP key is passphrase-protected"
            case .invalidPassphrase:  return "Incorrect passphrase for this LibrePGP key"
            case .foreignSecretFormat:
                return String(localized: "This key's private material was exported by GnuPG in its internal format, which PGPony can't use to decrypt. Use a LibrePGP key generated in PGPony.")
            }
        }
    }

    /// Decryption material extracted from a v5 Kyber (algorithm 8) secret subkey.
    struct DecryptionKey {
        let keyID: [UInt8]          // leading 8 octets of the v5 fingerprint
        let v5Fingerprint: [UInt8]  // 32 octets
        let eccPublic: [UInt8]      // recipient X25519 public (R)
        let eccSecret: [UInt8]      // raw 32-octet X25519 scalar
        let mlkemSeed: [UInt8]      // 64-octet ML-KEM seed (d‖z)
    }

    // MARK: - Public API

    /// Decrypt a LibrePGP PQC message using a transferable secret key that
    /// contains a v5 Kyber subkey. Returns the literal plaintext.
    static func decrypt(messageData: [UInt8], secretKeyData: [UInt8], passphrase: String? = nil) throws -> Data {
        try decryptContents(messageData: messageData, secretKeyData: secretKeyData, passphrase: passphrase).literalData
    }

    /// Same as `decrypt`, but returns the full decrypted contents (literal data
    /// plus the inner packet stream) so the caller can find and verify an inline
    /// OnePassSignature/Signature that a signing sender embedded.
    static func decryptContents(messageData: [UInt8], secretKeyData: [UInt8], passphrase: String? = nil) throws -> OpenPGPPacketParser.DecryptedMessageContents {
        // Parse the PKESK FIRST so we know which recipient key ID the message
        // targets, then unlock ONLY the matching key. Otherwise a keyring with
        // several LibrePGP keys tries the wrong key's passphrase and loops the
        // decrypt prompt forever.
        let packets = try OpenPGPPacketParser.parsePackets(data: messageData)
        guard let pkeskPacket = packets.first(where: { $0.tag == 1 }) else { throw Failure.noPKESK }
        let pkesk = try parsePKESK(pkeskPacket.body)

        guard let key = try extractDecryptionKey(privateKeyData: secretKeyData, passphrase: passphrase, matchKeyID: pkesk.keyID) else {
            throw Failure.noCompositeSubkey
        }
        let sessionKey = try recoverSessionKey(pkesk: pkesk, key: key)
        return try OpenPGPPacketParser.decryptMessageWithSessionKey(
            messageData: Data(messageData),
            sessionKey: sessionKey,
            cipherAlgorithmID: pkesk.sessionKeyAlgo)
    }

    // MARK: - Key extraction

    static func extractDecryptionKey(privateKeyData: [UInt8], passphrase: String? = nil, matchKeyID: [UInt8]? = nil) throws -> DecryptionKey? {
        let packets = try OpenPGPPacketParser.parsePackets(data: privateKeyData)
        for packet in packets where packet.tag == 7 || packet.tag == 5 {
            if let key = try parseKyberSecretSubkey(body: packet.body, passphrase: passphrase, matchKeyID: matchKeyID) { return key }
        }
        return nil
    }

    /// Parse a v5 unprotected Kyber secret-subkey body (the inverse of
    /// Ed25519KeyGenerator.buildKyberSecretKeyBody).
    private static func parseKyberSecretSubkey(body: [UInt8], passphrase: String? = nil, matchKeyID: [UInt8]? = nil) throws -> DecryptionKey? {
        guard body.count > 10, body[0] == 5 else { return nil }
        var o = 1 + 4                                   // version + creation time
        let algo = body[o]; o += 1
        guard algo == 8 else { return nil }

        guard o + 4 <= body.count else { return nil }
        let keyMatLen = Int(body[o]) << 24 | Int(body[o+1]) << 16 | Int(body[o+2]) << 8 | Int(body[o+3])
        o += 4
        let matStart = o
        guard matStart + keyMatLen <= body.count else { return nil }

        var p = matStart
        let oidLen = Int(body[p]); p += 1 + oidLen      // skip curve OID
        guard p + 2 <= matStart + keyMatLen else { return nil }
        let ptBits = Int(body[p]) << 8 | Int(body[p+1]); p += 2
        let ptBytes = (ptBits + 7) / 8
        guard p + ptBytes <= matStart + keyMatLen else { return nil }
        var eccPoint = Array(body[p..<(p + ptBytes)])
        if eccPoint.first == 0x40 { eccPoint.removeFirst() }
        guard eccPoint.count == 32 else { return nil }

        o = matStart + keyMatLen
        let publicBody = Array(body[0..<o])
        let v5fp = LibrePGPEncryptService.computeV5Fingerprint(packetBody: publicBody)

        // Only attempt the subkey the message was actually encrypted to. This is
        // computed from PUBLIC material (no passphrase needed), so a non-matching
        // key is skipped WITHOUT prompting for or rejecting a passphrase — which
        // is what otherwise loops the decrypt prompt across a multi-key keyring.
        if let want = matchKeyID, Array(v5fp.prefix(8)) != want { return nil }

        guard o < body.count else { return nil }
        let usage = body[o]; o += 1

        let secret: [UInt8]
        if usage == 0 {
            guard o + 4 <= body.count else { return nil }
            let count = Int(body[o]) << 24 | Int(body[o+1]) << 16 | Int(body[o+2]) << 8 | Int(body[o+3])
            o += 4
            guard count == 96, o + count <= body.count else { return nil }
            secret = Array(body[o..<(o + count)])
        } else if usage == 254 || usage == 255 {
            guard let pass = passphrase, !pass.isEmpty else { throw Failure.passphraseRequired }
            // v5 keys prepend a 1-octet protection-material length before the
            // cipher (GnuPG requires it; PGPony 8.0.0 now writes it). Keys from
            // earlier builds omitted it, so detect and skip: a valid cipher octet
            // (7/8/9) here means the legacy layout; anything else is the v5 length
            // octet, which we step over so both round-trip.
            guard o < body.count else { return nil }
            if !(body[o] == 7 || body[o] == 8 || body[o] == 9) { o += 1 }
            guard o + 1 + 1 + 1 + 8 + 1 + 16 + 4 <= body.count else { return nil }
            // PGPony writes AES-128 / iterated-salted(3) / SHA-256. Anything else
            // on an algorithm-8 key is GnuPG's internal s-expression export (which
            // uses a "GNU" S2K extension), not something we can unlock — surface a
            // clear, non-retryable error instead of looping the passphrase prompt.
            let cipher = body[o]; o += 1
            guard cipher == 7 else { throw Failure.foreignSecretFormat }
            let s2kType = body[o]; o += 1
            guard s2kType == 3 else { throw Failure.foreignSecretFormat }
            let hashAlgo = body[o]; o += 1
            guard hashAlgo == 8 else { throw Failure.foreignSecretFormat }
            let salt = Array(body[o..<(o + 8)]); o += 8
            let codedCount = body[o]; o += 1
            let iv = Array(body[o..<(o + 16)]); o += 16
            let count = Int(body[o]) << 24 | Int(body[o+1]) << 16 | Int(body[o+2]) << 8 | Int(body[o+3])
            o += 4
            guard count > 0, o + count <= body.count else { return nil }
            let encrypted = Array(body[o..<(o + count)])
            let key = s2kDeriveKeySHA256(passphrase: pass, salt: salt, codedCount: codedCount, keySize: 16)
            let decrypted = aesCFBDecrypt(ciphertext: encrypted, key: key, iv: iv)
            if usage == 254 {
                guard decrypted.count == 96 + 20 else { throw Failure.invalidPassphrase }
                let material = Array(decrypted[0..<96])
                var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                CC_SHA1(material, CC_LONG(material.count), &sha1)
                guard Array(decrypted[96..<116]) == sha1 else { throw Failure.invalidPassphrase }
                secret = material
            } else {
                guard decrypted.count == 96 + 2 else { throw Failure.invalidPassphrase }
                let material = Array(decrypted[0..<96])
                let sum = material.reduce(UInt16(0)) { $0 &+ UInt16($1) }
                let stored = UInt16(decrypted[96]) << 8 | UInt16(decrypted[97])
                guard sum == stored else { throw Failure.invalidPassphrase }
                secret = material
            }
        } else {
            throw Failure.malformed("unsupported S2K usage \(usage)")
        }

        return DecryptionKey(
            keyID: Array(v5fp.prefix(8)),
            v5Fingerprint: v5fp,
            eccPublic: eccPoint,
            eccSecret: Array(secret[0..<32]),
            mlkemSeed: Array(secret[32..<96]))
    }

    // MARK: - PKESK parsing + KEM decapsulation

    private struct PKESK {
        let keyID: [UInt8]
        let eccCipherText: [UInt8]    // 32-octet X25519 ephemeral public (V)
        let mlkemCipherText: [UInt8]  // 1088 octets
        let sessionKeyAlgo: UInt8
        let wrappedKey: [UInt8]       // 40-octet AES-256 key wrap
    }

    /// Parse a v3 PKESK for the Kyber composite (algorithm 8):
    ///   ver(3) ‖ keyID(8) ‖ algo(8)
    ///     ‖ eccCT (bit-length SOS) ‖ mlkemCT (4-octet length)
    ///     ‖ sessionKeyAlgo(1) ‖ wrappedKeyLen(1) ‖ wrappedKey.
    private static func parsePKESK(_ b: [UInt8]) throws -> PKESK {
        var o = 0
        guard b.count > 11, b[o] == 3 else { throw Failure.malformed("expected v3 PKESK") }
        o += 1
        let keyID = Array(b[o..<(o + 8)]); o += 8
        guard b[o] == 8 else { throw Failure.malformed("PKESK is not algorithm 8") }
        o += 1

        guard o + 2 <= b.count else { throw Failure.malformed("truncated ecc length") }
        let bits = Int(b[o]) << 8 | Int(b[o+1]); o += 2
        let nBytes = (bits + 7) / 8
        guard o + nBytes <= b.count else { throw Failure.malformed("truncated ecc ciphertext") }
        let eccCT = Array(b[o..<(o + nBytes)]); o += nBytes

        guard o + 4 <= b.count else { throw Failure.malformed("truncated ML-KEM length") }
        let mLen = Int(b[o]) << 24 | Int(b[o+1]) << 16 | Int(b[o+2]) << 8 | Int(b[o+3]); o += 4
        guard o + mLen <= b.count else { throw Failure.malformed("truncated ML-KEM ciphertext") }
        let mlkemCT = Array(b[o..<(o + mLen)]); o += mLen

        guard o + 2 <= b.count else { throw Failure.malformed("truncated wrapped key header") }
        let symAlgo = b[o]; o += 1
        let wLen = Int(b[o]); o += 1
        guard o + wLen <= b.count else { throw Failure.malformed("truncated wrapped key") }
        let wrapped = Array(b[o..<(o + wLen)])

        return PKESK(keyID: keyID, eccCipherText: eccCT, mlkemCipherText: mlkemCT,
                     sessionKeyAlgo: symAlgo, wrappedKey: wrapped)
    }

    private static func recoverSessionKey(pkesk: PKESK, key: DecryptionKey) throws -> [UInt8] {
        // X25519: raw shared secret X = X25519(r, V).
        let priv: Curve25519.KeyAgreement.PrivateKey
        do { priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(key.eccSecret)) }
        catch { throw Failure.malformed("invalid X25519 secret") }
        let ephemeral: Curve25519.KeyAgreement.PublicKey
        do { ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(pkesk.eccCipherText)) }
        catch { throw Failure.malformed("invalid X25519 ephemeral public") }
        let rawECDH = try priv.sharedSecretFromKeyAgreement(with: ephemeral).withUnsafeBytes { Array($0) }

        // ML-KEM decapsulation using the seed-derived secret key.
        let (_, mlkemSecret) = try MLKEMService.generateKeyPair(seed: Data(key.mlkemSeed))
        let mlkemSS = try MLKEMService.decapsulate(
            ciphertext: Data(pkesk.mlkemCipherText), secretKey: mlkemSecret)

        // Same combiner as the encrypt path.
        let kek = LibrePGPEncryptService.compositeKEK(
            rawECDH: rawECDH,
            eccCipherText: pkesk.eccCipherText,
            eccPublic: key.eccPublic,
            mlkemShared: [UInt8](mlkemSS),
            mlkemCipherText: pkesk.mlkemCipherText,
            sessionKeyAlgo: pkesk.sessionKeyAlgo,
            v5Fingerprint: key.v5Fingerprint)

        return try AESKeyWrap.unwrap(ciphertext: pkesk.wrappedKey, kek: kek)
    }

    private static func s2kDeriveKeySHA256(passphrase: String, salt: [UInt8],
                                           codedCount: UInt8, keySize: Int) -> [UInt8] {
        let expbias: UInt32 = 6
        let c = UInt32(codedCount)
        let count = Int((16 + (c & 15)) << ((c >> 4) + expbias))
        let saltedPass = salt + Array(passphrase.utf8)
        var keyMaterial: [UInt8] = []
        var prefixCount = 0
        while keyMaterial.count < keySize {
            var ctx = CC_SHA256_CTX()
            CC_SHA256_Init(&ctx)
            if prefixCount > 0 {
                let prefix = [UInt8](repeating: 0, count: prefixCount)
                CC_SHA256_Update(&ctx, prefix, CC_LONG(prefix.count))
            }
            var bytesHashed = 0
            while bytesHashed < count {
                let chunk = min(saltedPass.count, count - bytesHashed)
                CC_SHA256_Update(&ctx, Array(saltedPass[0..<chunk]), CC_LONG(chunk))
                bytesHashed += chunk
            }
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256_Final(&hash, &ctx)
            keyMaterial.append(contentsOf: hash)
            prefixCount += 1
        }
        return Array(keyMaterial.prefix(keySize))
    }

    private static func aesCFBDecrypt(ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        let blockSize = 16
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
        var feedback = iv
        var offset = 0
        while offset < ciphertext.count {
            var keystream = [UInt8](repeating: 0, count: blockSize)
            var outLen = 0
            var cryptorRef: CCCryptorRef?
            CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode), key, key.count, nil, &cryptorRef)
            if let cryptor = cryptorRef {
                CCCryptorUpdate(cryptor, feedback, blockSize, &keystream, blockSize, &outLen)
                CCCryptorRelease(cryptor)
            }
            let blockEnd = min(offset + blockSize, ciphertext.count)
            for i in offset..<blockEnd {
                plaintext[i] = ciphertext[i] ^ keystream[i - offset]
            }
            if blockEnd - offset == blockSize {
                feedback = Array(ciphertext[offset..<blockEnd])
            }
            offset += blockSize
        }
        return plaintext
    }
}
