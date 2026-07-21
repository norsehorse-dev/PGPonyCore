// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// OpenPGPPacketBuilder.swift
// PGPony
//
// Constructs OpenPGP encrypted messages for Cv25519 ECDH recipients.
// Builds PKESK (tag 1) + SEIPD (tag 18) packets with MDC.
// This is the encrypt side of the native ECDH path.

import Foundation
import CommonCrypto
import CryptoKit
import Security

// MARK: - Customizable armor "Comment:" header (iOS port of the Android feature)
//
// User setting for the "Comment:" header embedded in ASCII-armored PGP output
// (encrypt / sign / encrypt-and-sign). The user can keep the default, write
// their own, or remove it entirely.
//
// This type lives in OpenPGPPacketBuilder.swift on purpose: that file is
// compiled into BOTH the PGPony app target and the PGPonyAction share
// extension target, so the same armorer + setting is available everywhere
// armor is produced without any project membership surgery.
//
// Persistence is via the App Group UserDefaults suite (KeychainService
// .sharedDefaults → group.com.pgpony.shared), so the toggle + custom string
// survive an app restart AND are shared with the share extension. The
// SwiftUI Settings screen binds @AppStorage to the same suite + keys.
//
// SCOPE: this affects message-style armored output only (encrypt, sign,
// encrypt-and-sign). Exported public/secret keys are produced by
// ObjectivePGP's Armor and are deliberately NOT routed through here, so they
// never pick up the comment setting — matching the Android export behavior.
enum ArmorComment {

    /// Default comment text. Matches Android and the canonical domain.
    /// Embedded as: "Comment: PGPony - PGPony.app".
    static let defaultComment = "PGPony - PGPony.app"

    /// Hard cap on the embedded comment length, in characters.
    static let maxLength = 80

    /// App Group UserDefaults keys (shared with the extension + @AppStorage).
    static let includeKey = "armor_comment_include"
    static let textKey = "armor_comment_text"

    /// Sanitize a raw user string so it can NEVER produce a malformed armor
    /// header line. Mirrors the Android ArmorCommentValidator exactly:
    ///   1. Force a single line — drop every CR and LF.
    ///   2. Drop every other control character.
    ///   3. Strip leading ':' characters (and surrounding leading whitespace).
    ///   4. Trim leading/trailing whitespace.
    ///   5. Cap at maxLength, without splitting a Unicode grapheme/scalar pair,
    ///      then trim any trailing space left by the cut.
    /// The result may be empty — callers treat empty as "no header".
    static func sanitize(_ raw: String) -> String {
        // 1 + 2: keep only non-ISO-control scalars (this also removes CR/LF).
        // Matches Java's Character.isISOControl: U+0000–U+001F and U+007F–U+009F.
        var s = String(String.UnicodeScalarView(
            raw.unicodeScalars.filter { scalar in
                let v = scalar.value
                let isISOControl = v <= 0x1F || (v >= 0x7F && v <= 0x9F)
                return !isISOControl
            }
        ))

        // 3: strip leading colons and the whitespace around them.
        s = String(s.drop(while: { $0 == " " || $0 == "\t" }))
        while s.hasPrefix(":") {
            s.removeFirst()
            s = String(s.drop(while: { $0 == " " || $0 == "\t" }))
        }

        // 4: trim both ends.
        s = s.trimmingCharacters(in: .whitespaces)

        // 5: cap by Character count (never splits a grapheme cluster).
        if s.count > maxLength {
            s = String(s.prefix(maxLength))
            s = String(s.reversed().drop(while: { $0 == " " || $0 == "\t" }).reversed())
        }

        return s
    }

    /// Resolve the (toggle, text) pair into the final Comment value, or nil
    /// when no Comment header should be written.
    ///   - toggle OFF                          -> nil (no header)
    ///   - toggle ON but empty after sanitize  -> nil (no header)
    ///   - toggle ON with content              -> the sanitized value
    static func validate(include: Bool, raw: String) -> String? {
        guard include else { return nil }
        let s = sanitize(raw)
        return s.isEmpty ? nil : s
    }

    /// Injectable hook for the host app to supply the user's Comment-header
    /// preference (toggle + text). The core keeps no app storage of its own, so
    /// a host that wants a persisted/@AppStorage-backed toggle assigns this once
    /// at launch, e.g. from its App Group defaults suite. The default reproduces
    /// PGPony's first-launch behavior: comment ON with `defaultComment`.
    /// Returning (false, _) writes no header.
    static var settingsProvider: () -> (include: Bool, raw: String) = {
        (true, defaultComment)
    }

    /// The validated Comment value to embed. nil means "write no Comment header".
    static var current: String? {
        let (include, raw) = settingsProvider()
        return validate(include: include, raw: raw)
    }

    /// The header line(s) to splice in directly after the BEGIN line: either
    /// "Comment: <value>\n" or "" (no header). The RFC-required blank-line
    /// separator is added by the armorers themselves, so an empty result
    /// still yields valid, GnuPG-clean armor.
    static func headerBlock() -> String {
        if let c = current, !c.isEmpty { return "Comment: \(c)\n" }
        return ""
    }

    /// v7.1.x — SEPARATE toggle for embedding the Comment in EXPORTED PUBLIC KEYS
    /// (copy / share / save-as-file). Independent of the message toggle above;
    /// reuses the same comment text. Default ON.
    static let pubkeyIncludeKey = "armor_comment_pubkey_include"

    /// Injectable hook for the host app's public-key-export Comment preference
    /// (separate toggle, shared text). Default mirrors first launch: ON with
    /// `defaultComment`.
    static var pubkeySettingsProvider: () -> (include: Bool, raw: String) = {
        (true, defaultComment)
    }

    /// The Comment value for public-key exports, or nil for none. Honors the
    /// separate pubkey toggle (default ON) and the shared comment text.
    static func pubkeyComment() -> String? {
        let (include, raw) = pubkeySettingsProvider()
        guard include else { return nil }
        let s = sanitize(raw)
        return s.isEmpty ? nil : s
    }

    /// Splice a "Comment: <value>" line into an armored PUBLIC KEY's header, right
    /// after the BEGIN line, when the pubkey toggle is on. ONLY the armor header
    /// is touched — the base64 key body (UID + key material) is never modified,
    /// so this cannot corrupt the key and stays GnuPG-clean. Returns the input
    /// unchanged when no comment should be written or the BEGIN line isn't found.
    static func withPublicKeyComment(_ armored: String) -> String {
        guard let comment = pubkeyComment() else { return armored }
        let begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        guard let beginRange = armored.range(of: begin),
              let newline = armored[beginRange.upperBound...].firstIndex(of: "\n") else {
            return armored
        }
        let insertAt = armored.index(after: newline)
        var result = armored
        result.insert(contentsOf: "Comment: \(comment)\n", at: insertAt)
        return result
    }
}

enum PacketBuilderError: LocalizedError {
    case noRecipients
    case encryptionFailed(String)
    case invalidKeyData(String)
    case sessionKeyGenerationFailed
    case signingFailed(String)

    var errorDescription: String? {
        switch self {
        case .noRecipients: return "No recipients specified"
        case .encryptionFailed(let msg): return "Packet encryption failed: \(msg)"
        case .invalidKeyData(let msg): return "Invalid key data: \(msg)"
        case .sessionKeyGenerationFailed: return "Failed to generate random session key"
        case .signingFailed(let msg): return String(localized: "Signing failed: \(msg)")
        }
    }
}

// MARK: - Recipient Info

/// Parsed Cv25519 recipient key info needed for encryption
struct Cv25519Recipient {
    let subkeyPublicKey: [UInt8]     // 32-byte raw X25519 public key
    let subkeyFingerprint: [UInt8]   // 20-byte V4 fingerprint of encryption subkey
    let subkeyID: [UInt8]            // 8-byte key ID (last 8 of fingerprint)
    let kdfHashID: UInt8             // From KDF params (usually SHA-256 = 8)
    let kdfCipherID: UInt8           // From KDF params (usually AES-128 = 7)
}

/// An RSA recipient (the encryption-capable (sub)key) for a v3 PKESK. The session
/// key is encrypted to the modulus with PKCS#1 v1.5 padding.
struct RSARecipient {
    let keyID: [UInt8]      // 8-byte key ID of the encryption (sub)key
    let modulus: [UInt8]    // RSA modulus n, big-endian
    let exponent: [UInt8]   // RSA public exponent e, big-endian
}

// MARK: - Ed25519 Signing Info

/// Info needed to produce an inline Ed25519 signature during encryption
struct Ed25519SigningInfo {
    let privateKey: Curve25519.Signing.PrivateKey   // CryptoKit signing key
    let keyID: [UInt8]                               // 8-byte key ID of primary key
    let fingerprint: [UInt8]                         // 20-byte fingerprint of primary key
}

// MARK: - OpenPGP Packet Builder

class OpenPGPPacketBuilder {

    // Default session cipher: AES-128
    private static let defaultSessionCipherID: UInt8 = 7  // AES-128
    private static let defaultSessionKeySize = 16

    // MARK: - Build Encrypted Message

    /// Build a complete OpenPGP encrypted message for Cv25519 ECDH recipients.
    /// Optionally signs the message with an Ed25519 key (inline signature).
    ///
    /// Output format:
    ///   PKESK(recipient1) || ... || SEIPD(encrypted_data)
    ///
    /// When signed, the encrypted payload contains:
    ///   prefix || OnePassSig(tag4) || LiteralData(tag11) || Signature(tag2) || MDC(tag19)
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - recipients: Array of Cv25519 recipient key info
    ///   - signingInfo: Optional Ed25519 signing key info (nil = unsigned)
    ///   - filename: Optional filename for literal data packet (nil = empty)
    ///   - armor: If true, returns ASCII-armored output
    /// - Returns: The encrypted OpenPGP message as Data
    static func buildEncryptedMessage(
        plaintext: Data,
        recipients: [Cv25519Recipient],
        rsaRecipients: [RSARecipient] = [],
        signingInfo: Ed25519SigningInfo? = nil,
        prebuiltSignature: (packet: [UInt8], keyID: [UInt8])? = nil,
        filename: String? = nil,
        armor: Bool = true
    ) throws -> Data {

        guard !recipients.isEmpty || !rsaRecipients.isEmpty else {
            throw PacketBuilderError.noRecipients
        }

        // 1. Choose the session cipher and generate a random session key.
        // v6.0 Phase V6-C: the all-v6 path uses AES-256 (algo 9) to match the v6
        // ecosystem (Sequoia sq, GnuPG 2.4), which emit AES-256 for v6 SEIPDv2 and
        // reject AES-128 there by policy. The legacy v3 + SEIPDv1 path stays on
        // AES-128 (the historic default for v4 recipients). RSA recipients are v4,
        // so any RSA recipient forces the legacy path.
        let allV6 = rsaRecipients.isEmpty
            && !recipients.isEmpty
            && recipients.allSatisfy { $0.subkeyFingerprint.count == 32 }
        let cipherID: UInt8 = allV6 ? 9 : defaultSessionCipherID
        let sessionKeySize = allV6 ? 32 : defaultSessionKeySize

        var sessionKey = [UInt8](repeating: 0, count: sessionKeySize)
        guard SecRandomCopyBytes(kSecRandomDefault, sessionKeySize, &sessionKey) == errSecSuccess else {
            throw PacketBuilderError.sessionKeyGenerationFailed
        }

        // 2. Build recipient packets + encrypted payload.
        // When EVERY recipient is a v6 key (32-byte fingerprint), emit v6 PKESK
        // packets followed by a SEIPDv2 (AES-OCB) packet, per RFC 9580 (a v6 PKESK
        // MUST precede a v2 SEIPD). If any recipient is a v4 key, fall back to the
        // legacy v3 PKESK + SEIPDv1/MDC path so v4 recipients can still read it.
        var message = Data()

        if allV6 {
            for recipient in recipients {
                message.append(try buildV6PKESKPacket(sessionKey: sessionKey, recipient: recipient))
            }
            let seipd2 = try buildSEIPDv2Packet(
                plaintext: Array(plaintext),
                sessionKey: sessionKey,
                cipherAlgorithmID: cipherID,
                signingInfo: signingInfo,
                prebuiltSignature: prebuiltSignature,
                filename: filename
            )
            message.append(seipd2)
        } else {
            for recipient in recipients {
                let pkesk = try buildPKESKPacket(
                    sessionKey: sessionKey,
                    sessionAlgorithmID: defaultSessionCipherID,
                    recipient: recipient
                )
                message.append(pkesk)
            }
            for rsaRecipient in rsaRecipients {
                let pkesk = try buildRSAPKESKPacket(
                    sessionKey: sessionKey,
                    sessionAlgorithmID: defaultSessionCipherID,
                    recipient: rsaRecipient
                )
                message.append(pkesk)
            }

            // Encrypt plaintext with session key → SEIPDv1 packet
            let seipd = try buildSEIPDPacket(
                plaintext: Array(plaintext),
                sessionKey: sessionKey,
                sessionAlgorithmID: defaultSessionCipherID,
                signingInfo: signingInfo,
                prebuiltSignature: prebuiltSignature,
                filename: filename
            )
            message.append(seipd)
        }

        // 4. Armor if requested
        if armor {
            let armored = armorMessage(message)
            return armored.data(using: .utf8) ?? message
        }

        return message
    }

    // MARK: - PKESK Packet (Tag 1)

    /// Build a Public-Key Encrypted Session Key packet (tag 1) for ECDH.
    ///
    /// Format (RFC 4880 §5.1 + RFC 6637 §10):
    ///   version(1) || key_id(8) || algorithm(1) || ephemeral_pubkey_MPI || wrapped_key_len(1) || wrapped_key
    private static func buildPKESKPacket(
        sessionKey: [UInt8],
        sessionAlgorithmID: UInt8,
        recipient: Cv25519Recipient
    ) throws -> Data {

        let ecdhResult = try Cv25519ECDHService.encryptSessionKey(
            sessionKey: sessionKey,
            sessionAlgorithmID: sessionAlgorithmID,
            recipientPublicKey: recipient.subkeyPublicKey,
            recipientFingerprint: recipient.subkeyFingerprint,
            kdfHashID: recipient.kdfHashID,
            kdfCipherID: recipient.kdfCipherID
        )

        var body: [UInt8] = []

        // Version 3
        body.append(3)

        // Key ID (8 bytes)
        body.append(contentsOf: recipient.subkeyID)

        // Algorithm: ECDH (18)
        body.append(18)

        // Ephemeral public key as MPI
        let ephBits = UInt16(ecdhResult.ephemeralPublicKey.count * 8 - countLeadingZeroBits(ecdhResult.ephemeralPublicKey))
        body.append(UInt8((ephBits >> 8) & 0xFF))
        body.append(UInt8(ephBits & 0xFF))
        body.append(contentsOf: ecdhResult.ephemeralPublicKey)

        // Wrapped session key: length(1) + data
        body.append(UInt8(ecdhResult.wrappedSessionKey.count))
        body.append(contentsOf: ecdhResult.wrappedSessionKey)

        return buildNewFormatPacket(tag: 1, body: Data(body))
    }

    // MARK: - RSA PKESK Packet (Tag 1)

    /// Build a v3 Public-Key Encrypted Session Key packet (tag 1) for an RSA
    /// recipient. The session-key block — cipher algorithm ID, the session key,
    /// and a 2-byte checksum — is encrypted to the recipient's modulus with PKCS#1
    /// v1.5 padding (via the Security framework, which performs the padding and the
    /// modular exponentiation), and the result is stored as a single MPI.
    ///
    /// Format (RFC 4880 §5.1):
    ///   version(3) || key_id(8) || algorithm(1=RSA) || MPI(m^e mod n)
    private static func buildRSAPKESKPacket(
        sessionKey: [UInt8],
        sessionAlgorithmID: UInt8,
        recipient: RSARecipient
    ) throws -> Data {
        // Session-key block: algo(1) || sessionKey || checksum(2, BE sum mod 65536).
        var block: [UInt8] = [sessionAlgorithmID]
        block.append(contentsOf: sessionKey)
        var sum = 0
        for b in sessionKey { sum = (sum + Int(b)) & 0xFFFF }
        block.append(UInt8((sum >> 8) & 0xFF))
        block.append(UInt8(sum & 0xFF))

        let pubKey = try makeRSAPublicSecKey(modulus: recipient.modulus, exponent: recipient.exponent)
        var err: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(pubKey, .rsaEncryptionPKCS1, Data(block) as CFData, &err) as Data? else {
            let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "RSA encryption failed"
            throw PacketBuilderError.encryptionFailed(msg)
        }
        let ct = [UInt8](cipher)
        var body: [UInt8] = [3]                  // version 3
        body.append(contentsOf: recipient.keyID) // 8-byte key ID
        body.append(1)                           // public-key algorithm: RSA
        // MPI of the ciphertext m^e mod n.
        let bits = UInt16(ct.count * 8 - countLeadingZeroBits(ct))
        body.append(UInt8((bits >> 8) & 0xFF))
        body.append(UInt8(bits & 0xFF))
        body.append(contentsOf: ct)

        return buildNewFormatPacket(tag: 1, body: Data(body))
    }

    /// Encrypt `plaintext` to an RSA public key with PKCS#1 v1.5, returning the raw
    /// ciphertext (m^e mod n). Same operation `buildRSAPKESKPacket` uses; exposed so
    /// the hardware-key RSA self-test exercises the exact production encryption path.
    static func rsaEncryptPKCS1(plaintext: [UInt8], modulus: [UInt8], exponent: [UInt8]) throws -> [UInt8] {
        let pubKey = try makeRSAPublicSecKey(modulus: modulus, exponent: exponent)
        var err: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(pubKey, .rsaEncryptionPKCS1, Data(plaintext) as CFData, &err) as Data? else {
            let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "RSA encryption failed"
            throw PacketBuilderError.encryptionFailed(msg)
        }
        return [UInt8](cipher)
    }

    /// Build a SecKey for an RSA public key from its modulus and exponent. iOS
    /// expects PKCS#1 `RSAPublicKey` DER (SEQUENCE { INTEGER n, INTEGER e }).
    private static func makeRSAPublicSecKey(modulus: [UInt8], exponent: [UInt8]) throws -> SecKey {
        let der = rsaPublicKeyDER(modulus: modulus, exponent: exponent)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, &err) else {
            let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "Invalid RSA public key"
            throw PacketBuilderError.invalidKeyData(msg)
        }
        return key
    }

    /// DER length octets (short or long form).
    static func derLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var len = n
        var bytes: [UInt8] = []
        while len > 0 { bytes.insert(UInt8(len & 0xFF), at: 0); len >>= 8 }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    /// DER INTEGER: strip leading zero bytes, then prepend a 0x00 if the high bit
    /// is set so the value stays positive (unsigned big-endian → signed DER).
    static func derInteger(_ value: [UInt8]) -> [UInt8] {
        var v = value
        while v.first == 0x00 && v.count > 1 { v.removeFirst() }
        if let first = v.first, (first & 0x80) != 0 { v.insert(0x00, at: 0) }
        return [0x02] + derLength(v.count) + v
    }

    /// PKCS#1 RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    static func rsaPublicKeyDER(modulus: [UInt8], exponent: [UInt8]) -> [UInt8] {
        let seq = derInteger(modulus) + derInteger(exponent)
        return [0x30] + derLength(seq.count) + seq
    }

    // MARK: - SEIPD Packet (Tag 18)

    /// Build a Symmetrically Encrypted Integrity Protected Data packet (tag 18).
    ///
    /// Format (RFC 4880 §5.13):
    ///   version(1) || encrypted( prefix(bs+2) || literal_data_packet || MDC_packet )
    ///
    /// The prefix is: bs random bytes + first 2 bytes repeated (for quick check).
    /// Encryption: AES-CFB with zero IV (continuous CFB-128, no resync).
    /// When signingInfo is provided, wraps the literal data in
    /// OnePassSignature(tag4) || LiteralData(tag11) || Signature(tag2).
    static func buildSEIPDPacket(
        plaintext: [UInt8],
        sessionKey: [UInt8],
        sessionAlgorithmID: UInt8,
        signingInfo: Ed25519SigningInfo? = nil,
        prebuiltSignature: (packet: [UInt8], keyID: [UInt8])? = nil,
        filename: String? = nil
    ) throws -> Data {

        let blockSize = try cipherBlockSize(for: sessionAlgorithmID)

        // Build the literal data packet that wraps the plaintext
        let literalPacket = buildLiteralDataPacket(data: plaintext, filename: filename)

        // Build the inner packet sequence
        var innerPackets: [UInt8]

        if let signer = signingInfo {
            // Signed: OnePassSig || LiteralData || Signature
            // Phase V6-D: a v6 signing key must emit v6 inline framing even when
            // the envelope is SEIPDv1 (e.g. mixed v4 recipients).
            if signer.fingerprint.count == 32 {
                var sigSalt = [UInt8](repeating: 0, count: 16)
                guard SecRandomCopyBytes(kSecRandomDefault, sigSalt.count, &sigSalt) == errSecSuccess else {
                    throw PacketBuilderError.sessionKeyGenerationFailed
                }
                let fp = Array(signer.fingerprint.prefix(32))
                let onePassSig = buildOnePassSignaturePacketV6(sigType: 0x00, salt: sigSalt, fingerprint: fp)
                let signaturePacket = try buildBinarySignaturePacketV6(
                    signingKey: signer.privateKey,
                    fingerprint: fp,
                    literalBody: plaintext,
                    salt: sigSalt
                )
                innerPackets = onePassSig
                innerPackets.append(contentsOf: literalPacket)
                innerPackets.append(contentsOf: signaturePacket)
            } else {
                let onePassSig = buildOnePassSignaturePacket(keyID: signer.keyID)
                let signaturePacket = try buildBinarySignaturePacket(
                    signingKey: signer.privateKey,
                    keyID: signer.keyID,
                    fingerprint: signer.fingerprint,
                    literalBody: plaintext
                )
                innerPackets = onePassSig
                innerPackets.append(contentsOf: literalPacket)
                innerPackets.append(contentsOf: signaturePacket)
            }
        } else if let pre = prebuiltSignature {
            // v6.0 — Phase 9i: inline signature produced on a hardware key.
            // The signature packet was built over this exact plaintext (sig type
            // 0x00) by CardSigner; we only need the matching one-pass packet so
            // the recipient knows a signature follows the literal data.
            let onePassSig = buildOnePassSignaturePacket(keyID: pre.keyID, pubkeyAlgo: signaturePacketPubkeyAlgo(pre.packet))
            innerPackets = onePassSig
            innerPackets.append(contentsOf: literalPacket)
            innerPackets.append(contentsOf: pre.packet)
        } else {
            // Unsigned: just the literal data
            innerPackets = literalPacket
        }

        // Build prefix: blockSize random bytes + repeat last 2
        var prefix = [UInt8](repeating: 0, count: blockSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, blockSize, &prefix)
        prefix.append(prefix[blockSize - 2])
        prefix.append(prefix[blockSize - 1])

        // Assemble plaintext for encryption: prefix || inner_packets || MDC
        var plaintextStream: [UInt8] = prefix
        plaintextStream.append(contentsOf: innerPackets)

        // MDC packet (tag 19): SHA-1 of everything before it including MDC header
        var mdcInput = plaintextStream
        mdcInput.append(0xD3)  // MDC packet tag (new format)
        mdcInput.append(0x14)  // MDC body length = 20

        var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(mdcInput, CC_LONG(mdcInput.count), &sha1)

        // Append MDC packet
        plaintextStream.append(0xD3)  // Tag 19 new format
        plaintextStream.append(0x14)  // Length 20
        plaintextStream.append(contentsOf: sha1)

        // Encrypt with OpenPGP CFB mode (continuous, no resync)
        let encrypted = try openPGPCFBEncrypt(
            plaintext: plaintextStream,
            key: sessionKey,
            algorithmID: sessionAlgorithmID
        )

        // Build SEIPD body: version(1) + encrypted data
        var seipdBody: [UInt8] = [1]  // Version 1
        seipdBody.append(contentsOf: encrypted)

        return buildNewFormatPacket(tag: 18, body: Data(seipdBody))
    }

    // MARK: - v6 PKESK + SEIPDv2 (RFC 9580) — Phase V6-C

    /// SEIPDv2 chunk size byte: actual chunk = 2^(byte + 6) bytes (here 4096).
    private static let seipdV2ChunkSizeByte: UInt8 = 0x06
    private static let aeadOCB: UInt8 = 2

    /// RFC 9580 §5.1.6 — encrypt a session key to an X25519 recipient.
    /// HKDF-SHA256 (no salt, info "OpenPGP X25519",
    /// ikm = ephemeral(32) || recipient(32) || shared(32)) → 16-byte AES-128 KEK,
    /// then AES key wrap of the raw session key (no checksum / padding).
    /// Returns the 32-byte ephemeral public key and the wrapped session key.
    private static func encryptV6X25519SessionKey(
        sessionKey: [UInt8],
        recipientX25519PublicKey: [UInt8]
    ) throws -> (ephemeral: [UInt8], wrapped: [UInt8]) {
        guard recipientX25519PublicKey.count == 32 else {
            throw PacketBuilderError.invalidKeyData("v6 X25519 recipient key must be 32 bytes")
        }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = Array(ephemeral.publicKey.rawRepresentation)
        let recipientPub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(recipientX25519PublicKey)
        )
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientPub)
        let sharedBytes = shared.withUnsafeBytes { Array($0) }

        var ikm = ephemeralPub
        ikm.append(contentsOf: recipientX25519PublicKey)
        ikm.append(contentsOf: sharedBytes)

        let kek = try OpenPGPPacketParser.hkdfSHA256(
            ikm: ikm,
            salt: [],
            info: Array("OpenPGP X25519".utf8),
            outputLength: 16
        )
        let wrapped = try AESKeyWrap.wrap(plaintext: sessionKey, kek: kek)
        return (ephemeralPub, wrapped)
    }

    /// RFC 9580 §5.1.2 / §5.1.6 — v6 PKESK (tag 1) for an X25519 recipient.
    /// Layout: version(6) | size(33) | keyVersion(6) | fingerprint(32) |
    ///         algo(25) | ephemeral(32) | size(1) | wrapped_session_key
    /// The symmetric cipher ID is NOT carried here for a v6 PKESK — it lives in
    /// the SEIPDv2 header.
    private static func buildV6PKESKPacket(
        sessionKey: [UInt8],
        recipient: Cv25519Recipient
    ) throws -> Data {
        guard recipient.subkeyFingerprint.count == 32 else {
            throw PacketBuilderError.invalidKeyData("v6 PKESK needs a 32-byte fingerprint")
        }
        let (ephemeral, wrapped) = try encryptV6X25519SessionKey(
            sessionKey: sessionKey,
            recipientX25519PublicKey: recipient.subkeyPublicKey
        )

        var body: [UInt8] = []
        body.append(6)                                        // PKESK version 6
        body.append(33)                                       // size of (keyVersion + fingerprint)
        body.append(6)                                        // target key version
        body.append(contentsOf: recipient.subkeyFingerprint)  // 32-byte v6 fingerprint
        body.append(25)                                       // public-key algorithm: X25519
        body.append(contentsOf: ephemeral)                    // 32-byte ephemeral public key
        body.append(UInt8(wrapped.count))                     // size of following fields (no algo id in v6)
        body.append(contentsOf: wrapped)                      // wrapped session key

        return buildNewFormatPacket(tag: 1, body: Data(body))
    }

    // MARK: - Composite (RFC 9980, algorithm 35) Encrypt

    /// A recipient's RFC 9980 ML-KEM-768 + X25519 composite encryption subkey,
    /// parsed from its v6 public-subkey packet.
    struct CompositeRecipient {
        let subkeyFingerprint: [UInt8]  // 32-byte v6 fingerprint of the subkey
        let x25519Public: [UInt8]       // 32-byte X25519 public
        let mlkemPublic: [UInt8]        // 1184-byte ML-KEM-768 public
    }

    /// Encrypt to a single RFC 9980 composite recipient (algorithm 35). Emits a
    /// v6 PKESK (algo 35) followed by a SEIPDv2 (AES-256-OCB) packet — the exact
    /// inverse of OpenPGPPacketParser's composite decrypt path, and the wire
    /// format Sequoia (sq) produces and consumes.
    static func buildCompositeEncryptedMessage(
        plaintext: Data,
        recipient: CompositeRecipient,
        signingInfo: Ed25519SigningInfo? = nil,
        filename: String? = nil,
        armor: Bool = true
    ) throws -> Data {
        guard recipient.subkeyFingerprint.count == 32 else {
            throw PacketBuilderError.invalidKeyData("composite PKESK needs a 32-byte fingerprint")
        }

        // AES-256 session key (the v6 ecosystem rejects AES-128 there by policy).
        var sessionKey = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &sessionKey) == errSecSuccess else {
            throw PacketBuilderError.sessionKeyGenerationFailed
        }

        // Composite KEM → 32-octet KEK, then RFC 3394 key-wrap the session key.
        let enc = try CompositeKEMService.encapsulate(
            mlkemPublicKey: Data(recipient.mlkemPublic),
            ecdhPublicKey: Data(recipient.x25519Public)
        )
        let wrapped = try AESKeyWrap.wrap(plaintext: sessionKey, kek: Array(enc.kek))  // 40 octets

        // v6 PKESK, algorithm 35: fingerprint header, then algorithm-specific
        // ecdhCipherText(32) ‖ mlkemCipherText(1088) ‖ len(1) ‖ wrappedSessionKey.
        var body: [UInt8] = []
        body.append(6)                                        // PKESK version 6
        body.append(33)                                       // size of (keyVersion + fingerprint)
        body.append(6)                                        // target key version
        body.append(contentsOf: recipient.subkeyFingerprint)  // 32-byte v6 fingerprint
        body.append(35)                                       // public-key algorithm: ML-KEM-768 + X25519
        body.append(contentsOf: Array(enc.ecdhCipherText))    // V (32)
        body.append(contentsOf: Array(enc.mlkemCipherText))   // ML-KEM ciphertext (1088)
        body.append(UInt8(wrapped.count))                     // size of wrapped session key (40)
        body.append(contentsOf: wrapped)                      // wrapped session key
        let pkesk = buildNewFormatPacket(tag: 1, body: Data(body))

        let seipd2 = try buildSEIPDv2Packet(
            plaintext: Array(plaintext),
            sessionKey: sessionKey,
            cipherAlgorithmID: 9,          // AES-256
            signingInfo: signingInfo,
            filename: filename
        )

        var message = Data()
        message.append(pkesk)
        message.append(seipd2)

        if armor {
            let armored = armorMessage(message)
            return armored.data(using: .utf8) ?? message
        }
        return message
    }

    /// RFC 9580 §5.13.2 — SEIPDv2 (tag 18, version 2) with AES-OCB.
    /// Inverse of OpenPGPPacketParser.decryptSEIPDv2, using the identical HKDF so
    /// the two sides derive byte-for-byte the same key and nonce.
    static func buildSEIPDv2Packet(
        plaintext: [UInt8],
        sessionKey: [UInt8],
        cipherAlgorithmID: UInt8,
        signingInfo: Ed25519SigningInfo? = nil,
        prebuiltSignature: (packet: [UInt8], keyID: [UInt8])? = nil,
        filename: String? = nil
    ) throws -> Data {
        // Inner packet stream — NO random prefix and NO MDC (AEAD provides integrity).
        let literalPacket = buildLiteralDataPacket(data: plaintext, filename: filename)
        var innerPackets: [UInt8]
        if let signer = signingInfo {
            // Phase V6-D: emit v6 inline framing (OPS v6 + v6 sig, shared salt) for
            // v6 signing keys; keep v4 framing for v4 keys.
            if signer.fingerprint.count == 32 {
                var sigSalt = [UInt8](repeating: 0, count: 16)
                guard SecRandomCopyBytes(kSecRandomDefault, sigSalt.count, &sigSalt) == errSecSuccess else {
                    throw PacketBuilderError.sessionKeyGenerationFailed
                }
                let fp = Array(signer.fingerprint.prefix(32))
                let onePassSig = buildOnePassSignaturePacketV6(sigType: 0x00, salt: sigSalt, fingerprint: fp)
                let signaturePacket = try buildBinarySignaturePacketV6(
                    signingKey: signer.privateKey,
                    fingerprint: fp,
                    literalBody: plaintext,
                    salt: sigSalt
                )
                innerPackets = onePassSig
                innerPackets.append(contentsOf: literalPacket)
                innerPackets.append(contentsOf: signaturePacket)
            } else {
                let onePassSig = buildOnePassSignaturePacket(keyID: signer.keyID)
                let signaturePacket = try buildBinarySignaturePacket(
                    signingKey: signer.privateKey,
                    keyID: signer.keyID,
                    fingerprint: signer.fingerprint,
                    literalBody: plaintext
                )
                innerPackets = onePassSig
                innerPackets.append(contentsOf: literalPacket)
                innerPackets.append(contentsOf: signaturePacket)
            }
        } else if let pre = prebuiltSignature {
            let onePassSig = buildOnePassSignaturePacket(keyID: pre.keyID, pubkeyAlgo: signaturePacketPubkeyAlgo(pre.packet))
            innerPackets = onePassSig
            innerPackets.append(contentsOf: literalPacket)
            innerPackets.append(contentsOf: pre.packet)
        } else {
            innerPackets = literalPacket
        }

        let cipher = cipherAlgorithmID
        let aead = aeadOCB
        let chunkByte = seipdV2ChunkSizeByte
        let keySize = sessionKey.count
        let nonceSize = AEADService.nonceSize(for: aead)
        guard nonceSize > 8 else { throw PacketBuilderError.sessionKeyGenerationFailed }

        // 32-byte salt
        var salt = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &salt) == errSecSuccess else {
            throw PacketBuilderError.sessionKeyGenerationFailed
        }

        // HKDF → messageKey(keySize) || iv-prefix(nonceSize-8); last 8 nonce bytes
        // start at zero and are XORed with the big-endian chunk index per chunk.
        let info: [UInt8] = [0xD2, 0x02, cipher, aead, chunkByte]
        let ivPrefixLen = nonceSize - 8
        let derived = try OpenPGPPacketParser.hkdfSHA256(
            ikm: sessionKey,
            salt: salt,
            info: info,
            outputLength: keySize + ivPrefixLen
        )
        let messageKey = Array(derived[0..<keySize])
        var baseIV = Array(derived[keySize...])
        baseIV.append(contentsOf: [UInt8](repeating: 0, count: 8))

        func nonce(forChunk index: UInt64) -> [UInt8] {
            var n = baseIV
            let ib = withUnsafeBytes(of: index.bigEndian) { Array($0) }
            let len = n.count
            for i in 0..<8 { n[len - 8 + i] ^= ib[i] }
            return n
        }

        let chunkSize = 1 << (Int(chunkByte) + 6)
        var encrypted = [UInt8]()
        var chunkIndex: UInt64 = 0
        var total: UInt64 = 0
        var offset = 0
        while offset < innerPackets.count {
            let end = min(offset + chunkSize, innerPackets.count)
            let chunk = Array(innerPackets[offset..<end])
            // RFC 9580 SEIPDv2: per-chunk AAD is the 5 header octets ONLY
            // (0xD2, version, cipher, aead, chunkByte). The chunk index is mixed
            // into the nonce, NOT the associated data. (The old tag-20 AEAD packet
            // folded the index into the AAD; SEIPDv2 does not.)
            let aad = info
            let sealed = try AEADService.encryptWithAppendedTag(
                plaintext: chunk,
                key: messageKey,
                nonce: nonce(forChunk: chunkIndex),
                aeadAlgo: aead,
                associatedData: aad
            )
            encrypted.append(contentsOf: sealed)
            total += UInt64(chunk.count)
            offset = end
            chunkIndex += 1
        }

        // Final authentication tag over empty plaintext.
        // RFC 9580 SEIPDv2: final AAD = the 5 header octets || total plaintext
        // length (8, BE). No chunk index in the AAD. The nonce still advances to
        // the next chunk index.
        var finalAAD = info
        finalAAD.append(contentsOf: withUnsafeBytes(of: total.bigEndian) { Array($0) })
        let finalTag = try AEADService.encryptWithAppendedTag(
            plaintext: [],
            key: messageKey,
            nonce: nonce(forChunk: chunkIndex),
            aeadAlgo: aead,
            associatedData: finalAAD
        )
        encrypted.append(contentsOf: finalTag)

        // SEIPDv2 body: version(2) | cipher | aead | chunkByte | salt(32) | encrypted
        var body: [UInt8] = [2, cipher, aead, chunkByte]
        body.append(contentsOf: salt)
        body.append(contentsOf: encrypted)
        return buildNewFormatPacket(tag: 18, body: Data(body))
    }

    // MARK: - Literal Data Packet (Tag 11)

    /// Build a literal data packet wrapping the plaintext.
    /// Format: format(1) || filename_len(1) || filename || date(4) || data
    private static func buildLiteralDataPacket(data: [UInt8], filename: String? = nil) -> [UInt8] {
        var body: [UInt8] = []

        // Format: 'b' = binary, 't' = text
        body.append(0x62)  // 'b' for binary

        // Filename (truncated to 255 bytes per RFC 4880)
        if let name = filename, !name.isEmpty {
            let nameBytes = Array(name.utf8).prefix(255)
            body.append(UInt8(nameBytes.count))
            body.append(contentsOf: nameBytes)
        } else {
            body.append(0)  // No filename
        }

        // Date (4 bytes — current unix timestamp)
        let now = UInt32(Date().timeIntervalSince1970)
        body.append(UInt8((now >> 24) & 0xFF))
        body.append(UInt8((now >> 16) & 0xFF))
        body.append(UInt8((now >> 8) & 0xFF))
        body.append(UInt8(now & 0xFF))

        // Literal data
        body.append(contentsOf: data)

        return buildNewFormatPacketBytes(tag: 11, body: body)
    }

    // MARK: - One-Pass Signature Packet (Tag 4)

    /// Build a v3 One-Pass Signature packet.
    /// This tells the recipient "a signature follows the literal data."
    /// RFC 4880 §5.4
    static func buildOnePassSignaturePacket(keyID: [UInt8], pubkeyAlgo: UInt8 = 22) -> [UInt8] {
        var body: [UInt8] = []

        body.append(3)            // Version 3
        body.append(0x00)         // Signature type: 0x00 = binary document
        body.append(8)            // Hash algorithm: SHA-256
        body.append(pubkeyAlgo)   // Public-key algorithm (22 = EdDSA, 1 = RSA)
        body.append(contentsOf: keyID)  // 8-byte signer key ID
        body.append(1)     // Nested flag: 1 = last one-pass packet (not nested)

        return buildNewFormatPacketBytes(tag: 4, body: body)
    }

    /// Read the public-key algorithm byte from a v4 signature packet (new-format
    /// tag 2). Used so the One-Pass Signature that precedes a card-produced inline
    /// signature advertises the same algorithm (otherwise an RSA card signature
    /// would be wrapped in a OnePassSig claiming EdDSA, and verification fails).
    static func signaturePacketPubkeyAlgo(_ packet: [UInt8]) -> UInt8 {
        guard packet.count >= 2 else { return 22 }
        let l = packet[1]
        let bodyStart: Int
        if l < 192 { bodyStart = 2 }
        else if l < 224 { bodyStart = 3 }
        else if l == 255 { bodyStart = 5 }
        else { bodyStart = 2 }
        let algoIdx = bodyStart + 2   // body: version, sigtype, [pubkeyalgo]
        return packet.count > algoIdx ? packet[algoIdx] : 22
    }

    // MARK: - Binary Document Signature Packet (Tag 2)

    /// Build a v4 binary document signature (type 0x00) using Ed25519.
    /// Signs the raw literal data body (not the packet wrapper).
    /// RFC 4880 §5.2.1
    static func buildBinarySignaturePacket(
        signingKey: Curve25519.Signing.PrivateKey,
        keyID: [UInt8],
        fingerprint: [UInt8],
        literalBody: [UInt8]
    ) throws -> [UInt8] {

        let creationTime = UInt32(Date().timeIntervalSince1970)

        // Hashed subpackets
        var hashedSubpackets: [UInt8] = []

        // Signature creation time (subpacket type 2)
        let timeSubpacket = buildSignatureSubpacket(type: 2, data: [
            UInt8((creationTime >> 24) & 0xFF),
            UInt8((creationTime >> 16) & 0xFF),
            UInt8((creationTime >> 8) & 0xFF),
            UInt8(creationTime & 0xFF)
        ])
        hashedSubpackets.append(contentsOf: timeSubpacket)

        // Issuer fingerprint (subpacket type 33 / 0x21)
        // Data: version(1) || fingerprint(20 for v4)
        var fpData: [UInt8] = [4]  // V4 key
        fpData.append(contentsOf: fingerprint)
        let fpSubpacket = buildSignatureSubpacket(type: 33, data: fpData)
        hashedSubpackets.append(contentsOf: fpSubpacket)

        // Unhashed subpackets
        var unhashedSubpackets: [UInt8] = []

        // Issuer key ID (subpacket type 16)
        let issuerSubpacket = buildSignatureSubpacket(type: 16, data: keyID)
        unhashedSubpackets.append(contentsOf: issuerSubpacket)

        // Build the data to hash:
        //   literal_body || sig_trailer
        // sig_trailer = version(4) || sigType(0x00) || pubAlgo(22) || hashAlgo(8) ||
        //               hashedSubpacketsLen(2) || hashedSubpackets ||
        //               v4_final_trailer(6)
        var hashInput = Data(literalBody)

        var trailer: [UInt8] = []
        trailer.append(4)     // Version 4
        trailer.append(0x00)  // Signature type: binary document
        trailer.append(22)    // EdDSA
        trailer.append(8)     // SHA-256

        let hashedLen = UInt16(hashedSubpackets.count)
        trailer.append(UInt8((hashedLen >> 8) & 0xFF))
        trailer.append(UInt8(hashedLen & 0xFF))
        trailer.append(contentsOf: hashedSubpackets)

        hashInput.append(contentsOf: trailer)

        // V4 final trailer: 0x04 0xFF + 4-byte count of hashed portion
        let totalHashedLen = UInt32(trailer.count)
        hashInput.append(4)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashedLen >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashedLen >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashedLen >> 8) & 0xFF))
        hashInput.append(UInt8(totalHashedLen & 0xFF))

        // Hash with SHA-256
        let digest = SHA256.hash(data: hashInput)
        let digestBytes = Array(digest)

        // Sign the digest (OpenPGP EdDSA signs the hash, not the raw data)
        let signature: Data
        do {
            signature = try signingKey.signature(for: Data(digestBytes))
        } catch {
            throw PacketBuilderError.signingFailed(error.localizedDescription)
        }
        let sigBytes = Array(signature)

        // Assemble signature packet body
        var sigBody: [UInt8] = []
        sigBody.append(4)     // Version
        sigBody.append(0x00)  // Binary document
        sigBody.append(22)    // EdDSA
        sigBody.append(8)     // SHA-256

        // Hashed subpackets
        sigBody.append(UInt8((hashedLen >> 8) & 0xFF))
        sigBody.append(UInt8(hashedLen & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)

        // Unhashed subpackets
        let unhashedLen = UInt16(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen >> 8) & 0xFF))
        sigBody.append(UInt8(unhashedLen & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)

        // Left 16 bits of hash (for quick check)
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])

        // EdDSA signature: two MPIs (R and S, each 32 bytes)
        let rBytes = Array(sigBytes[0..<32])
        let sBytes = Array(sigBytes[32..<64])

        let rBits = UInt16(rBytes.count * 8 - countLeadingZeroBits(rBytes))
        sigBody.append(UInt8((rBits >> 8) & 0xFF))
        sigBody.append(UInt8(rBits & 0xFF))
        sigBody.append(contentsOf: rBytes)

        let sBits = UInt16(sBytes.count * 8 - countLeadingZeroBits(sBytes))
        sigBody.append(UInt8((sBits >> 8) & 0xFF))
        sigBody.append(UInt8(sBits & 0xFF))
        sigBody.append(contentsOf: sBytes)

        return buildNewFormatPacketBytes(tag: 2, body: sigBody)
    }

    // MARK: - v6 inline signing (RFC 9580) — Phase V6-D

    /// Build a v6 One-Pass Signature packet (RFC 9580 §5.4). The salt MUST be the
    /// same one used by the corresponding v6 signature packet.
    /// Field order: version(6) | sigType | hashAlgo | pubAlgo | saltSize | salt |
    ///              issuerFingerprint(32) | nestedFlag.
    private static func buildOnePassSignaturePacketV6(
        sigType: UInt8,
        salt: [UInt8],
        fingerprint: [UInt8]
    ) -> [UInt8] {
        var body: [UInt8] = []
        body.append(6)            // version 6
        body.append(sigType)      // 0x00 = binary document
        body.append(8)            // hash algo: SHA-256
        body.append(27)           // pub algo: Ed25519 (native)
        body.append(UInt8(salt.count))
        body.append(contentsOf: salt)
        body.append(contentsOf: fingerprint)  // 32-byte issuer fingerprint
        body.append(1)            // nested flag: last OPS
        return buildNewFormatPacketBytes(tag: 4, body: body)
    }

    /// Build a v6 binary document signature (type 0x00) over `literalBody` using
    /// Ed25519, with the provided salt (shared with the v6 OPS packet). Mirrors
    /// SigningService.signDetachedEd25519v6 but returns a raw tag-2 packet (not
    /// armored) and signs the raw literal body (no canonicalization).
    private static func buildBinarySignaturePacketV6(
        signingKey: Curve25519.Signing.PrivateKey,
        fingerprint: [UInt8],
        literalBody: [UInt8],
        salt: [UInt8]
    ) throws -> [UInt8] {
        let v6FP = Array(fingerprint.prefix(32))
        let creationTime = UInt32(Date().timeIntervalSince1970)

        // Hashed subpackets: creation time (2) + issuer fingerprint (33, v6 = 6||fp).
        var hashedSubpackets: [UInt8] = []
        hashedSubpackets.append(contentsOf: buildSignatureSubpacket(type: 2, data: [
            UInt8((creationTime >> 24) & 0xFF),
            UInt8((creationTime >> 16) & 0xFF),
            UInt8((creationTime >> 8) & 0xFF),
            UInt8(creationTime & 0xFF)
        ]))
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: v6FP)
        hashedSubpackets.append(contentsOf: buildSignatureSubpacket(type: 33, data: fpData))

        // Unhashed: issuer key ID (16) = leading 8 of the v6 fingerprint (courtesy).
        var unhashedSubpackets: [UInt8] = []
        unhashedSubpackets.append(contentsOf: buildSignatureSubpacket(type: 16, data: Array(v6FP.prefix(8))))

        // rawHashedPortion: 6 | sigType | algo(27) | hash(8) | hashedLen(4) | hashed
        let sigType: UInt8 = 0x00
        var rawHashedPortion: [UInt8] = [6, sigType, 27, 8]
        let hashedLen32 = UInt32(hashedSubpackets.count)
        rawHashedPortion.append(UInt8((hashedLen32 >> 24) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen32 >> 16) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen32 >> 8) & 0xFF))
        rawHashedPortion.append(UInt8(hashedLen32 & 0xFF))
        rawHashedPortion.append(contentsOf: hashedSubpackets)

        // Hash input (v6): salt || literalBody || rawHashedPortion || 0x06 0xFF || 4-byte BE total
        var hashInput = Data()
        hashInput.append(contentsOf: salt)
        hashInput.append(contentsOf: literalBody)
        hashInput.append(contentsOf: rawHashedPortion)
        let totalHashed4 = UInt32(rawHashedPortion.count)
        hashInput.append(0x06)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashed4 >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >>  8) & 0xFF))
        hashInput.append(UInt8( totalHashed4        & 0xFF))

        let digestBytes = Array(SHA256.hash(data: hashInput))
        let signature: Data
        do {
            signature = try signingKey.signature(for: Data(digestBytes))
        } catch {
            throw PacketBuilderError.signingFailed(error.localizedDescription)
        }
        let sigBytes = Array(signature)
        guard sigBytes.count == 64 else {
            throw PacketBuilderError.signingFailed("v6 Ed25519 signature must be 64 bytes, got \(sigBytes.count)")
        }

        // Packet body: 6 | sigType | 27 | 8 | hashedLen(4) | hashed | unhashedLen(4) |
        //              unhashed | hashPrefix(2) | saltLen(1) | salt | sig(64)
        var sigBody: [UInt8] = [6, sigType, 27, 8]
        sigBody.append(UInt8((hashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(hashedLen32 & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)
        let unhashedLen32 = UInt32(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(unhashedLen32 & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])
        sigBody.append(UInt8(salt.count))
        sigBody.append(contentsOf: salt)
        sigBody.append(contentsOf: sigBytes)   // native 64-byte Ed25519 sig (no MPI)

        return buildNewFormatPacketBytes(tag: 2, body: sigBody)
    }

    /// Build a signature subpacket: length(1-2) || type(1) || data
    private static func buildSignatureSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        var subpacket: [UInt8] = []
        let totalLen = data.count + 1  // +1 for type byte

        if totalLen < 192 {
            subpacket.append(UInt8(totalLen))
        } else if totalLen < 16576 {
            let adj = totalLen - 192
            subpacket.append(UInt8((adj >> 8) + 192))
            subpacket.append(UInt8(adj & 0xFF))
        }

        subpacket.append(type)
        subpacket.append(contentsOf: data)
        return subpacket
    }

    // MARK: - OpenPGP CFB Encryption

    /// OpenPGP CFB encryption (continuous CFB-128, no resync).
    ///
    /// Modern GnuPG uses standard CFB without the legacy "resync after prefix"
    /// shift described in RFC 4880 §13.9. The entire plaintext is encrypted
    /// as one continuous CFB-128 stream:
    ///   1. IV = zero block
    ///   2. Encrypt all bytes sequentially in 16-byte blocks
    ///   3. Feedback register = previous ciphertext block (standard CFB)
    ///
    /// This matches the decrypt side in OpenPGPPacketParser.openPGPCFBDecrypt.
    private static func openPGPCFBEncrypt(
        plaintext: [UInt8],
        key: [UInt8],
        algorithmID: UInt8
    ) throws -> [UInt8] {

        let bs = try cipherBlockSize(for: algorithmID)
        var ciphertext = [UInt8](repeating: 0, count: plaintext.count)

        // Continuous CFB-128: encrypt the entire plaintext as one stream
        var feedback = [UInt8](repeating: 0, count: bs)  // IV = all zeros
        var offset = 0

        while offset < plaintext.count {
            let keystream = try aesECBBlock(input: feedback, key: key)
            let blockEnd = min(offset + bs, plaintext.count)

            for i in offset..<blockEnd {
                ciphertext[i] = plaintext[i] ^ keystream[i - offset]
            }

            // Feedback = ciphertext block (standard CFB)
            if blockEnd - offset == bs {
                feedback = Array(ciphertext[offset..<blockEnd])
            } else {
                // Final partial block: pad with zeros for feedback
                var newFB = Array(ciphertext[offset..<blockEnd])
                newFB.append(contentsOf: [UInt8](repeating: 0, count: bs - newFB.count))
                feedback = newFB
            }

            offset += bs
        }

        return ciphertext
    }

    // MARK: - Packet Helpers

    /// Build new-format OpenPGP packet as Data
    private static func buildNewFormatPacket(tag: UInt8, body: Data) -> Data {
        var packet = Data()
        packet.append(0xC0 | tag)

        let len = body.count
        if len < 192 {
            packet.append(UInt8(len))
        } else if len < 8384 {
            let adj = len - 192
            packet.append(UInt8((adj >> 8) + 192))
            packet.append(UInt8(adj & 0xFF))
        } else {
            packet.append(0xFF)
            packet.append(UInt8((len >> 24) & 0xFF))
            packet.append(UInt8((len >> 16) & 0xFF))
            packet.append(UInt8((len >> 8) & 0xFF))
            packet.append(UInt8(len & 0xFF))
        }

        packet.append(body)
        return packet
    }

    /// Build new-format packet as [UInt8] (for nesting)
    static func buildNewFormatPacketBytes(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var packet: [UInt8] = [0xC0 | tag]

        let len = body.count
        if len < 192 {
            packet.append(UInt8(len))
        } else if len < 8384 {
            let adj = len - 192
            packet.append(UInt8((adj >> 8) + 192))
            packet.append(UInt8(adj & 0xFF))
        } else {
            packet.append(0xFF)
            packet.append(UInt8((len >> 24) & 0xFF))
            packet.append(UInt8((len >> 16) & 0xFF))
            packet.append(UInt8((len >> 8) & 0xFF))
            packet.append(UInt8(len & 0xFF))
        }

        packet.append(contentsOf: body)
        return packet
    }

    // MARK: - Crypto Helpers

    private static func aesECBBlock(input: [UInt8], key: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 32) // Extra space for CCCrypt
        var outLen = 0

        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,  // no IV for ECB
            input, 16,
            &output, 32,
            &outLen
        )
        guard status == kCCSuccess else {
            throw PacketBuilderError.encryptionFailed("AES-ECB encrypt failed: status \(status)")
        }
        return Array(output[0..<16])
    }

    private static func cipherBlockSize(for algorithmID: UInt8) throws -> Int {
        switch algorithmID {
        case 7, 8, 9: return 16  // AES-128/192/256 all use 128-bit blocks
        default: throw PacketBuilderError.encryptionFailed("Unsupported cipher: \(algorithmID)")
        }
    }

    private static func countLeadingZeroBits(_ bytes: [UInt8]) -> Int {
        for (i, byte) in bytes.enumerated() {
            if byte != 0 {
                return i * 8 + byte.leadingZeroBitCount
            }
        }
        return bytes.count * 8
    }

    // MARK: - ASCII Armor

    static func armorMessage(_ data: Data) -> String {
        let base64 = data.base64EncodedString(options: .lineLength76Characters)
        let crc = crc24(data)
        let crcBase64 = Data(crc).base64EncodedString()
        // Splice in the user-configured Comment header (or nothing) between
        // the BEGIN line and the required blank-line separator.
        return "-----BEGIN PGP MESSAGE-----\n\(ArmorComment.headerBlock())\n\(base64)\n=\(crcBase64)\n-----END PGP MESSAGE-----"
    }

    private static func crc24(_ data: Data) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 {
                    crc ^= 0x1864CFB
                }
            }
        }
        crc &= 0xFFFFFF
        return [
            UInt8((crc >> 16) & 0xFF),
            UInt8((crc >> 8) & 0xFF),
            UInt8(crc & 0xFF)
        ]
    }
}
