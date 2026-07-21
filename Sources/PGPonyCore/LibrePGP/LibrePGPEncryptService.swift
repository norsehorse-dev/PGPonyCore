// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPEncryptService.swift
// PGPony — Phase F (PQC), LibrePGP / GnuPG interop (encrypt side).
//
// Produces a LibrePGP (GnuPG 2.5.x) PQC message that `gpg` can decrypt: a v3
// PKESK (tag 1) for a v5 Kyber subkey (public-key algorithm 8 = ML-KEM-768 +
// X25519) followed by an OCB Encrypted Data packet (tag 20). This is the
// LibrePGP counterpart to the RFC 9980 (algorithm 35) encrypt path — a DIFFERENT
// standard: KMAC256 combiner (see LibrePGPCombiner), ECC-first ordering,
// fixedInfo = sessionKeyAlgo ‖ v5 fingerprint, and the older tag-20 AEAD packet
// (session key used directly, no HKDF, chunk index folded into the AAD).
//
// Wire formats reverse-engineered from, and validated against, a real GnuPG
// 2.5.x message + public key: the v5 fingerprint (SHA-256, 0x9A prefix) matches
// the PKESK key ID, and gpg decrypts PGPony's output end to end.

import Foundation
import CryptoKit

enum LibrePGPEncryptService {

    enum Failure: Error, LocalizedError {
        case notAKyberSubkey
        case malformedKey(String)
        case rng
        case internalError(String)

        var errorDescription: String? {
            switch self {
            case .notAKyberSubkey:      return "Not a LibrePGP ML-KEM+X25519 (algorithm 8) subkey"
            case .malformedKey(let m):  return "Malformed LibrePGP key: \(m)"
            case .rng:                  return "Secure random generation failed"
            case .internalError(let m): return "LibrePGP encrypt error: \(m)"
            }
        }
    }

    /// GnuPG public-key algorithm ID for the Kyber/ML-KEM composite.
    static let algIdKyber: UInt8 = 8
    /// AES-256 — the session-key symmetric algorithm we emit (matches GnuPG).
    static let sessionKeyAlgoAES256: UInt8 = 9
    /// OCB AEAD algorithm ID.
    static let aeadOCB: UInt8 = 2
    /// tag-20 chunk-size octet: chunk = 2^(byte + 6). 0x0C ⇒ 256 KiB.
    static let chunkSizeByte: UInt8 = 0x0C

    private static let x25519PublicBytes = 32
    private static let mlkemPublicBytes  = 1184
    private static let mlkemCipherBytes  = 1088
    private static let ocbNonceBytes     = 15
    private static let ocbTagBytes        = 16

    // MARK: - Recipient (parsed v5 Kyber subkey)

    struct Recipient {
        let keyID: [UInt8]          // 8 bytes — leading octets of the v5 fingerprint
        let v5Fingerprint: [UInt8]  // 32 bytes
        let eccPublic: [UInt8]      // 32-byte X25519 public (0x40 prefix stripped)
        let mlkemPublic: [UInt8]    // 1184-byte ML-KEM-768 public
    }

    // MARK: - Public API

    /// Encrypt `plaintext` to the given transferable public key (armored/binary
    /// packet stream). Finds the first v5 Kyber (algorithm 8) encryption subkey.
    static func encrypt(plaintext: [UInt8],
                        publicKeyData: [UInt8],
                        filename: String? = nil,
                        signingInfo: Ed25519SigningInfo? = nil) throws -> [UInt8] {
        let packets = try OpenPGPPacketParser.parsePackets(data: publicKeyData)
        // Scan key + subkey packets (public tag 14/6 and, defensively, secret
        // tag 7) for the v5 Kyber (algorithm 8) subkey. Capture the first parse
        // failure so a mismatch surfaces WHY rather than a bare "not a subkey".
        var lastReason: String? = nil
        var summary: [String] = []
        for packet in packets where packet.tag == 14 || packet.tag == 6 || packet.tag == 7 {
            let ver = packet.body.first.map { Int($0) } ?? -1
            let algo = packet.body.count > 5 ? Int(packet.body[5]) : -1
            summary.append("t\(packet.tag)v\(ver)a\(algo)l\(packet.body.count)")
            do {
                let recipient = try parseV5KyberSubkey(packetBody: packet.body)
                return try encrypt(plaintext: plaintext, recipient: recipient, filename: filename, signingInfo: signingInfo)
            } catch {
                lastReason = (error as? Failure)?.errorDescription ?? "\(error)"
            }
        }
        pgpDebugLog("LibrePGP encrypt: no Kyber subkey. packets=[\(summary.joined(separator: " "))] lastReason=\(lastReason ?? "none")")
        throw Failure.malformedKey("no algorithm-8 subkey found. Saw packets: \(summary.joined(separator: ", ")). Last parse error: \(lastReason ?? "none")")
    }

    /// Encrypt to an already-parsed recipient. Produces `PKESK(tag1) ‖ OCB-Data(tag20)`.
    static func encrypt(plaintext: [UInt8],
                        recipient: Recipient,
                        filename: String? = nil,
                        signingInfo: Ed25519SigningInfo? = nil) throws -> [UInt8] {
        // 1. Random AES-256 session key.
        let sessionKey = try randomBytes(32)

        // 2. Composite KEM to the recipient's subkey → KEK (32 octets).
        //    ML-KEM encaps + fresh X25519 ephemeral; combine via GnuPG's KMAC256.
        let (mlkemCT, mlkemSS) = try MLKEMService.encapsulate(publicKey: Data(recipient.mlkemPublic))

        let recipientPub: Curve25519.KeyAgreement.PublicKey
        do { recipientPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(recipient.eccPublic)) }
        catch { throw Failure.malformedKey("recipient X25519 public key invalid") }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let eccCT = [UInt8](ephemeral.publicKey.rawRepresentation)          // V — 32-byte ephemeral public
        let rawECDH: [UInt8]
        do {
            let ss = try ephemeral.sharedSecretFromKeyAgreement(with: recipientPub)
            rawECDH = ss.withUnsafeBytes { Array($0) }                      // raw X25519 output
        } catch { throw Failure.internalError("X25519 key agreement failed") }
        let kek = compositeKEK(
            rawECDH: rawECDH,
            eccCipherText: eccCT,
            eccPublic: recipient.eccPublic,
            mlkemShared: [UInt8](mlkemSS),
            mlkemCipherText: [UInt8](mlkemCT),
            sessionKeyAlgo: sessionKeyAlgoAES256,
            v5Fingerprint: recipient.v5Fingerprint)

        // 3. AES-256 key-wrap (RFC 3394) the session key with the KEK.
        let wrapped = try AESKeyWrap.wrap(plaintext: sessionKey, kek: kek)   // 40 octets

        // 4. Assemble the two packets.
        let pkesk = buildV3PKESK(keyID: recipient.keyID,
                                 eccCipherText: eccCT,
                                 mlkemCipherText: [UInt8](mlkemCT),
                                 sessionKeyAlgo: sessionKeyAlgoAES256,
                                 wrappedKey: wrapped)
        let ocb = try buildTag20OCB(plaintext: plaintext,
                                    sessionKey: sessionKey,
                                    filename: filename,
                                    signingInfo: signingInfo)
        return pkesk + ocb
    }

    /// Derive the 32-octet composite KEK the way GnuPG's encrypt path does.
    ///
    /// The ECC contribution is NOT the raw X25519 output: GnuPG's
    /// `gnupg_ecc_kem_simple_kdf` binds it to both public keys as
    ///   ecc_ss = SHA3-256( rawECDH ‖ ecc_ct ‖ ecc_pk )
    /// before the KMAC256 combiner mixes it with the ML-KEM shared secret and the
    /// fixedInfo (sessionKeyAlgo ‖ v5 fingerprint). Factored out so it can be
    /// pinned by a known-answer test independent of the random ephemeral.
    static func compositeKEK(rawECDH: [UInt8],
                             eccCipherText: [UInt8],
                             eccPublic: [UInt8],
                             mlkemShared: [UInt8],
                             mlkemCipherText: [UInt8],
                             sessionKeyAlgo: UInt8,
                             v5Fingerprint: [UInt8]) -> [UInt8] {
        let eccSS = Keccak.sha3_256(rawECDH + eccCipherText + eccPublic)
        return LibrePGPCombiner.deriveKEK(
            eccShared: eccSS,
            eccCipherText: eccCipherText,
            mlkemShared: mlkemShared,
            mlkemCipherText: mlkemCipherText,
            sessionKeyAlgo: sessionKeyAlgo,
            v5Fingerprint: v5Fingerprint)
    }

    // MARK: - v5 Kyber subkey parsing

    /// Parse a v5 public (sub)key packet body for algorithm 8 (ML-KEM-768 +
    /// X25519). Layout: ver(1)=5 | ctime(4) | algo(1)=8 | keyMatLen(4) |
    ///   OID(len(1)=3 ‖ 2b 65 6e) | ecc SOS(bit-len(2) ‖ 0x40 ‖ 32) |
    ///   mlkemLen(4) | mlkemPub(1184).
    static func parseV5KyberSubkey(packetBody body: [UInt8]) throws -> Recipient {
        guard body.count > 10, body[0] == 5 else { throw Failure.notAKyberSubkey }
        var o = 1 + 4                                  // version + creation time
        let algo = body[o]; o += 1
        guard algo == algIdKyber else { throw Failure.notAKyberSubkey }

        guard o + 4 <= body.count else { throw Failure.malformedKey("truncated key-material length") }
        let keyMatLen = Int(body[o]) << 24 | Int(body[o+1]) << 16 | Int(body[o+2]) << 8 | Int(body[o+3])
        o += 4
        guard o + keyMatLen <= body.count else { throw Failure.malformedKey("key material overruns packet") }
        var p = o
        let matEnd = o + keyMatLen

        // Curve OID (expect X25519: 1.3.101.110 = 2b 65 6e).
        guard p < matEnd else { throw Failure.malformedKey("missing OID") }
        let oidLen = Int(body[p]); p += 1
        guard p + oidLen <= matEnd else { throw Failure.malformedKey("OID overruns") }
        p += oidLen

        // ECC point as a bit-length SOS; strip the 0x40 native-point prefix.
        guard p + 2 <= matEnd else { throw Failure.malformedKey("missing ECC point length") }
        let ptBits = Int(body[p]) << 8 | Int(body[p+1]); p += 2
        let ptBytes = (ptBits + 7) / 8
        guard p + ptBytes <= matEnd, ptBytes >= 1 else { throw Failure.malformedKey("ECC point overruns") }
        var eccPoint = Array(body[p..<(p + ptBytes)]); p += ptBytes
        if eccPoint.first == 0x40 { eccPoint.removeFirst() }
        guard eccPoint.count == x25519PublicBytes else {
            throw Failure.malformedKey("X25519 public key must be 32 octets, got \(eccPoint.count)")
        }

        // ML-KEM public key: 4-octet length prefix then 1184 octets.
        guard p + 4 <= matEnd else { throw Failure.malformedKey("missing ML-KEM length") }
        let mlkemLen = Int(body[p]) << 24 | Int(body[p+1]) << 16 | Int(body[p+2]) << 8 | Int(body[p+3])
        p += 4
        guard mlkemLen == mlkemPublicBytes, p + mlkemLen <= matEnd else {
            throw Failure.malformedKey("ML-KEM public key must be 1184 octets, got \(mlkemLen)")
        }
        let mlkemPub = Array(body[p..<(p + mlkemLen)])

        let fpr = computeV5Fingerprint(packetBody: body)
        return Recipient(keyID: Array(fpr.prefix(8)),
                         v5Fingerprint: fpr,
                         eccPublic: eccPoint,
                         mlkemPublic: mlkemPub)
    }

    /// LibrePGP v5 fingerprint: SHA-256( 0x9A ‖ 4-octet big-endian body length ‖ body ).
    static func computeV5Fingerprint(packetBody body: [UInt8]) -> [UInt8] {
        var pre: [UInt8] = [0x9A]
        let n = body.count
        pre.append(contentsOf: [UInt8(truncatingIfNeeded: n >> 24),
                                UInt8(truncatingIfNeeded: n >> 16),
                                UInt8(truncatingIfNeeded: n >> 8),
                                UInt8(truncatingIfNeeded: n)])
        pre.append(contentsOf: body)
        return Array(SHA256.hash(data: Data(pre)))
    }

    // MARK: - Packet builders

    /// v3 PKESK (tag 1) for a Kyber recipient. Body:
    ///   ver(3) ‖ keyID(8) ‖ algo(8)
    ///   ‖ eccCT  : bit-length SOS  (0x01 0x00 ‖ 32 octets)
    ///   ‖ mlkemCT: 4-octet length  (00 00 04 40 ‖ 1088 octets)
    ///   ‖ sessionKeyAlgo(1) ‖ wrappedKeyLen(1) ‖ wrappedKey.
    static func buildV3PKESK(keyID: [UInt8],
                             eccCipherText: [UInt8],
                             mlkemCipherText: [UInt8],
                             sessionKeyAlgo: UInt8,
                             wrappedKey: [UInt8]) -> [UInt8] {
        var body: [UInt8] = [3]
        body.append(contentsOf: keyID)
        body.append(algIdKyber)

        // eccCT — fixed-length 256-bit SOS (GnuPG stores the X25519 KEM ciphertext
        // as a plain 32-octet value, no 0x40 prefix).
        let bits = eccCipherText.count * 8
        body.append(UInt8(truncatingIfNeeded: bits >> 8))
        body.append(UInt8(truncatingIfNeeded: bits))
        body.append(contentsOf: eccCipherText)

        // mlkemCT — 4-octet big-endian length prefix.
        let n = mlkemCipherText.count
        body.append(contentsOf: [UInt8(truncatingIfNeeded: n >> 24),
                                 UInt8(truncatingIfNeeded: n >> 16),
                                 UInt8(truncatingIfNeeded: n >> 8),
                                 UInt8(truncatingIfNeeded: n)])
        body.append(contentsOf: mlkemCipherText)

        // Wrapped session key: symAlgo(1) ‖ len(1) ‖ C.
        body.append(sessionKeyAlgo)
        body.append(UInt8(truncatingIfNeeded: wrappedKey.count))
        body.append(contentsOf: wrappedKey)

        return newFormatPacket(tag: 1, body: body)
    }

    /// OCB Encrypted Data packet (tag 20, version 1) — the LibrePGP AEAD packet.
    /// The session key is used directly as the AEAD key (no HKDF); a random IV is
    /// stored; per-chunk the last 8 nonce octets are XORed with the chunk index,
    /// which is ALSO appended to the associated data.
    static func buildTag20OCB(plaintext: [UInt8],
                              sessionKey: [UInt8],
                              filename: String?,
                              signingInfo: Ed25519SigningInfo? = nil) throws -> [UInt8] {
        let cipher = sessionKeyAlgoAES256
        let aead = aeadOCB
        let chunkByte = chunkSizeByte
        // Inner packet stream. With a signer, wrap OnePassSignature | Literal |
        // v4 Ed25519 Signature (encrypt-then-sign layout gpg verifies); otherwise
        // just the literal. The signature is over the raw literal body (sig type
        // 0x00, binary document) — the same v4 builders the SEIPD path uses.
        let inner: [UInt8]
        if let signer = signingInfo {
            let ops = OpenPGPPacketBuilder.buildOnePassSignaturePacket(keyID: signer.keyID)
            let literal = literalDataPacket(data: plaintext, filename: filename)
            let sig = try OpenPGPPacketBuilder.buildBinarySignaturePacket(
                signingKey: signer.privateKey,
                keyID: signer.keyID,
                fingerprint: signer.fingerprint,
                literalBody: plaintext)
            inner = ops + literal + sig
        } else {
            inner = literalDataPacket(data: plaintext, filename: filename)
        }

        var iv = try randomBytes(ocbNonceBytes)

        func nonce(forChunk index: UInt64) -> [UInt8] {
            var n = iv
            let ib = withUnsafeBytes(of: index.bigEndian) { Array($0) }
            let len = n.count
            for i in 0..<8 { n[len - 8 + i] ^= ib[i] }
            return n
        }
        // Per-chunk AAD: header(5) ‖ chunk index(8, BE).
        func chunkAAD(index: UInt64) -> [UInt8] {
            var a: [UInt8] = [0xD4, 0x01, cipher, aead, chunkByte]
            a.append(contentsOf: withUnsafeBytes(of: index.bigEndian) { Array($0) })
            return a
        }

        let chunkSize = 1 << (Int(chunkByte) + 6)
        var encrypted = [UInt8]()
        var chunkIndex: UInt64 = 0
        var total: UInt64 = 0
        var offset = 0
        // Emit at least one (possibly empty) chunk so tiny messages still carry a tag.
        repeat {
            let end = min(offset + chunkSize, inner.count)
            let chunk = Array(inner[offset..<end])
            let sealed = try AEADService.encryptWithAppendedTag(
                plaintext: chunk,
                key: sessionKey,
                nonce: nonce(forChunk: chunkIndex),
                aeadAlgo: aead,
                associatedData: chunkAAD(index: chunkIndex))
            encrypted.append(contentsOf: sealed)
            total += UInt64(chunk.count)
            offset = end
            chunkIndex += 1
        } while offset < inner.count

        // Final authentication tag over the empty string. AAD = header(5) ‖
        // chunk index(8) ‖ total length(8); nonce advances to the final index.
        var finalAAD: [UInt8] = [0xD4, 0x01, cipher, aead, chunkByte]
        finalAAD.append(contentsOf: withUnsafeBytes(of: chunkIndex.bigEndian) { Array($0) })
        finalAAD.append(contentsOf: withUnsafeBytes(of: total.bigEndian) { Array($0) })
        let finalTag = try AEADService.encryptWithAppendedTag(
            plaintext: [],
            key: sessionKey,
            nonce: nonce(forChunk: chunkIndex),
            aeadAlgo: aead,
            associatedData: finalAAD)
        encrypted.append(contentsOf: finalTag)

        var body: [UInt8] = [1, cipher, aead, chunkByte]
        body.append(contentsOf: iv)
        body.append(contentsOf: encrypted)
        iv.removeAll()
        return newFormatPacket(tag: 20, body: body)
    }

    // MARK: - Small helpers

    /// Literal data packet (tag 11): format('b') ‖ nameLen ‖ name ‖ date(4) ‖ data.
    private static func literalDataPacket(data: [UInt8], filename: String?) -> [UInt8] {
        var body: [UInt8] = [0x62]                     // 'b' — binary
        if let name = filename, !name.isEmpty {
            let nameBytes = Array(Array(name.utf8).prefix(255))
            body.append(UInt8(nameBytes.count))
            body.append(contentsOf: nameBytes)
        } else {
            body.append(0)
        }
        body.append(contentsOf: [0, 0, 0, 0])          // date = 0 (unspecified)
        body.append(contentsOf: data)
        return newFormatPacket(tag: 11, body: body)
    }

    /// New-format packet framing with a one-, two-, or five-octet length.
    private static func newFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0xC0 | tag]
        let n = body.count
        if n < 192 {
            out.append(UInt8(n))
        } else if n < 8384 {
            let v = n - 192
            out.append(UInt8(192 + (v >> 8)))
            out.append(UInt8(v & 0xFF))
        } else {
            out.append(0xFF)
            out.append(contentsOf: [UInt8(truncatingIfNeeded: n >> 24),
                                    UInt8(truncatingIfNeeded: n >> 16),
                                    UInt8(truncatingIfNeeded: n >> 8),
                                    UInt8(truncatingIfNeeded: n)])
        }
        out.append(contentsOf: body)
        return out
    }

    private static func randomBytes(_ count: Int) throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &b) == errSecSuccess else { throw Failure.rng }
        return b
    }
}
