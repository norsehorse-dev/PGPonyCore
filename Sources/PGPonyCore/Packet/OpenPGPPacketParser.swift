// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// OpenPGPPacketParser.swift
// PGPony
//
// Parses OpenPGP encrypted messages to extract PKESK and SEIPD packets
// for native Cv25519 ECDH decryption.
//
// Supports RFC 4880 v4 and RFC 9580 v6 key packet formats.

import Foundation
import CommonCrypto
import CryptoKit
import zlib

enum PacketParserError: LocalizedError {
    case invalidPacket(String)
    case noPKESKFound
    case noSEIPDFound
    case noMatchingKey
    case decryptionFailed(String)
    case mdcVerificationFailed
    case unsupportedPacketVersion(UInt8)
    case unsupportedAlgorithm(UInt8)
    case decompressionFailed(String)
    case unsupportedCompression(UInt8)
    case unsupportedKeyVersion(UInt8)

    var errorDescription: String? {
        switch self {
        case .invalidPacket(let msg): return "Invalid OpenPGP packet: \(msg)"
        case .noPKESKFound: return "No Public-Key Encrypted Session Key packet found"
        case .noSEIPDFound: return "No encrypted data packet found"
        case .noMatchingKey: return "No matching decryption key found"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        case .mdcVerificationFailed: return "Message integrity check failed (MDC mismatch)"
        case .unsupportedPacketVersion(let v): return "Unsupported packet version: \(v)"
        case .unsupportedAlgorithm(let a): return "Unsupported algorithm: \(a)"
        case .decompressionFailed(let msg): return "Decompression failed: \(msg)"
        case .unsupportedCompression(let a): return "Unsupported compression algorithm: \(a)"
        case .unsupportedKeyVersion(let v): return "Unsupported key version: \(v)"
        }
    }
}

// MARK: - Parsed Packet Types

struct ParsedPKESK {
    let version: UInt8
    let keyID: [UInt8]           // 8-byte key ID (v3: from packet, v6: derived from fingerprint)
    let algorithm: UInt8          // 18 = ECDH (v4), 25 = X25519 (v6)
    let ephemeralPublicKey: [UInt8]  // MPI-decoded (v3) or raw 32 bytes (v6 X25519)
    let wrappedSessionKey: [UInt8]
    let keyFingerprint: [UInt8]  // V6 only: full fingerprint from PKESK; empty for v3
    let keyVersion: UInt8        // V6 only: key version byte; 0 for v3
    let rsaCipher: [UInt8]       // RSA (algo 1) v3 PKESK: the m^e mod n cryptogram; empty otherwise
}

struct ParsedSEIPD {
    let version: UInt8
    let encryptedData: [UInt8]
    // V2-specific fields (all zero/empty for v1)
    let cipherAlgorithm: UInt8   // V2: symmetric cipher (e.g., 9 = AES-256)
    let aeadAlgorithm: UInt8     // V2: AEAD mode (1=EAX, 2=OCB, 3=GCM)
    let chunkSizeByte: UInt8     // V2: encoded chunk size (actual = 2^(val+6) bytes)
    let salt: [UInt8]            // V2: 32-byte salt

    /// Computed chunk size in bytes for v2 and tag 20 (sentinel version 100)
    var chunkSize: Int {
        guard version == 2 || version == 100 else { return 0 }
        return 1 << (Int(chunkSizeByte) + 6)
    }
}

struct ParsedPacket {
    let tag: UInt8
    let body: [UInt8]
}

// MARK: - Decryption Key Info

/// Info about a Cv25519 private key available for decryption
struct Cv25519DecryptionKey {
    let subkeyID: [UInt8]           // 8-byte key ID
    let subkeyFingerprint: [UInt8]  // 20-byte (v4) or 32-byte (v6) fingerprint
    let privateKey: [UInt8]          // 32-byte raw X25519 private key
    let kdfHashID: UInt8
    let kdfCipherID: UInt8
}

// MARK: - RFC 9580 v6 Public Key Info

/// Parsed public key fields from a v4 or v6 public key packet (tag 6 or 14).
/// Provides version-aware fingerprint, key ID, algorithm, and raw key material.
struct ParsedPublicKeyInfo {
    let version: UInt8              // 4 or 6
    let creationTime: UInt32        // Unix timestamp
    let algorithm: UInt8            // RFC 4880/9580 algorithm ID
    let keyMaterial: [UInt8]        // Raw key material bytes
    let fingerprint: [UInt8]        // 20 bytes (v4 SHA-1) or 32 bytes (v6 SHA-256)
    let keyID: [UInt8]              // 8 bytes: v4 = last 8 of fingerprint, v6 = first 8

    /// Human-readable fingerprint hex string
    var fingerprintHex: String {
        fingerprint.map { String(format: "%02x", $0) }.joined()
    }

    /// Human-readable key ID hex string
    var keyIDHex: String {
        keyID.map { String(format: "%02x", $0) }.joined()
    }

    /// Algorithm display name for UI
    var algorithmName: String {
        switch algorithm {
        case 1, 2, 3:   return "RSA"
        case 16:         return "Elgamal"
        case 17:         return "DSA"
        case 18:         return "ECDH"
        case 19:         return "ECDSA"
        case 22:         return "EdDSA (Legacy)"
        case 25:         return "X25519"
        case 26:         return "X448"
        case 27:         return "Ed25519"
        case 28:         return "Ed448"
        default:         return "Unknown (\(algorithm))"
        }
    }

    /// Whether this is a v6 (RFC 9580) key
    var isV6: Bool { version == 6 }
}

// MARK: - OpenPGP Packet Parser

class OpenPGPPacketParser {

    // MARK: - Decrypt Message

    /// Decrypt an OpenPGP message using available Cv25519 keys.
    ///
    /// - Parameters:
    ///   - messageData: Raw (dearmored) OpenPGP message data
    ///   - decryptionKeys: Available Cv25519 private keys
    /// - Returns: Decrypted plaintext
    /// v5.0 Feature C — sibling of `decryptMessage` that returns BOTH the
    /// extracted literal data AND the full list of inner-level packets parsed
    /// from the decrypted plaintext. The signature packet (tag 2) lives at the
    /// inner level for encrypt-then-sign messages, so callers who want to
    /// verify embedded signatures need access to it.
    ///
    /// In the typical OpenPGP encrypt+sign packet layout:
    ///   PKESK | SEIPD( OnePassSignature | Compressed(Literal) | Signature )
    /// After SEIPD decryption, the inner stream is:
    ///   OnePassSignature(tag 4) | Compressed(tag 8) | Signature(tag 2)
    /// or, without compression:
    ///   OnePassSignature(tag 4) | Literal(tag 11) | Signature(tag 2)
    ///
    /// `extractLiteralData` recurses into compressed packets to find the
    /// literal content, but signatures are siblings of the compression
    /// container at the inner level, so we return the top-level inner packet
    /// list without recursing.
    static func decryptMessageReturningInnerPackets(
        messageData: Data,
        decryptionKeys: [Cv25519DecryptionKey]
    ) throws -> DecryptedMessageContents {
        // Mirrors decryptMessage's pipeline but captures the inner packet
        // stream before literal-data extraction. Kept as a parallel function
        // (rather than refactoring decryptMessage to share a helper) so the
        // legacy code path stays byte-identical and lower-risk.

        let packets = try parsePackets(data: Array(messageData))

        var pkeskPackets: [ParsedPKESK] = []
        var seipdPacket: ParsedSEIPD?

        for packet in packets {
            switch packet.tag {
            case 1:
                if let pkesk = try? parsePKESK(body: packet.body) {
                    pkeskPackets.append(pkesk)
                }
            case 18:
                seipdPacket = try parseSEIPD(body: packet.body)
            case 20:
                seipdPacket = try parseAEADEncryptedData(body: packet.body)
            default:
                continue
            }
        }

        guard !pkeskPackets.isEmpty else { throw PacketParserError.noPKESKFound }
        guard let seipd = seipdPacket else { throw PacketParserError.noSEIPDFound }

        // Try to decrypt session key with available keys (same logic as
        // decryptMessage; see that function for the per-PKESK-version
        // walkthrough).
        var sessionAlgorithmID: UInt8?
        var sessionKey: [UInt8]?

        for pkesk in pkeskPackets {
            if pkesk.version == 3 && pkesk.algorithm == 18 {
                for key in decryptionKeys {
                    if pkesk.keyID == key.subkeyID || pkesk.keyID == [UInt8](repeating: 0, count: 8) {
                        if let result = try? Cv25519ECDHService.decryptSessionKey(
                            ephemeralPublicKey: pkesk.ephemeralPublicKey,
                            wrappedSessionKey: pkesk.wrappedSessionKey,
                            recipientPrivateKey: key.privateKey,
                            recipientFingerprint: key.subkeyFingerprint,
                            kdfHashID: key.kdfHashID,
                            kdfCipherID: key.kdfCipherID
                        ) {
                            sessionAlgorithmID = result.algorithmID
                            sessionKey = result.sessionKey
                            break
                        }
                    }
                }
            }

            if pkesk.version == 6 && pkesk.algorithm == 25 {
                for key in decryptionKeys {
                    if pkesk.keyID == key.subkeyID || pkesk.keyFingerprint == key.subkeyFingerprint {
                        if let result = try? decryptV6X25519SessionKey(
                            pkesk: pkesk,
                            recipientPrivateKey: key.privateKey,
                            recipientFingerprint: key.subkeyFingerprint
                        ) {
                            // V6 takes session-cipher from SEIPDv2 header, not PKESK
                            sessionAlgorithmID = seipd.cipherAlgorithm != 0 ? seipd.cipherAlgorithm : result.algorithmID
                            sessionKey = result.sessionKey
                            break
                        }
                    }
                }
            }

            if sessionKey != nil { break }
        }

        guard let algID = sessionAlgorithmID, let sKey = sessionKey else {
            throw PacketParserError.noMatchingKey
        }

        let plaintext: [UInt8]
        if seipd.version == 2 {
            plaintext = try decryptSEIPDv2(seipd: seipd, sessionKey: sKey)
        } else if seipd.version == 100 {
            plaintext = try decryptAEADTag20(seipd: seipd, sessionKey: sKey)
        } else {
            plaintext = try decryptSEIPD(
                encryptedData: seipd.encryptedData,
                sessionKey: sKey,
                algorithmID: algID
            )
        }

        let innerPackets = try parsePackets(data: plaintext)
        let literalData = (try? extractLiteralData(from: innerPackets)) ?? nil

        return DecryptedMessageContents(
            literalData: literalData ?? Data(plaintext),
            innerPackets: innerPackets
        )
    }

    struct DecryptedMessageContents {
        let literalData: Data
        let innerPackets: [ParsedPacket]
    }

    /// Original entry point, preserved for callers that don't care about
    /// signature packets. Returns only the literal data content (compression
    /// transparently handled).
    static func decryptMessage(
        messageData: Data,
        decryptionKeys: [Cv25519DecryptionKey]
    ) throws -> Data {

        // 1. Parse all packets
        pgpDebugLog("DEBUG Parser: raw message data size = \(messageData.count) bytes")
        let packets = try parsePackets(data: Array(messageData))

        // 2. Extract PKESK and SEIPD packets
        var pkeskPackets: [ParsedPKESK] = []
        var seipdPacket: ParsedSEIPD?

        for packet in packets {
            switch packet.tag {
            case 1:
                if let pkesk = try? parsePKESK(body: packet.body) {
                    pkeskPackets.append(pkesk)
                }
            case 18:
                // SEIPD v1 (CFB+MDC) or v2 (AEAD with HKDF)
                seipdPacket = try parseSEIPD(body: packet.body)
                pgpDebugLog("DEBUG Parser: SEIPD tag 18, version=\(seipdPacket?.version ?? 0), body size = \(packet.body.count), encrypted data size = \(seipdPacket?.encryptedData.count ?? -1)")
            case 20:
                // Tag 20: AEAD Encrypted Data (GnuPG 2.4.x legacy AEAD format)
                // Structure: version(1) | cipher(1) | aead(1) | chunkSizeByte(1) | nonce(N) | encrypted_data
                // This is different from SEIPDv2: no 32-byte salt, session key used directly, nonce in packet
                seipdPacket = try parseAEADEncryptedData(body: packet.body)
                pgpDebugLog("DEBUG Parser: AEAD tag 20, cipher=\(seipdPacket?.cipherAlgorithm ?? 0), aead=\(seipdPacket?.aeadAlgorithm ?? 0), encrypted data size = \(seipdPacket?.encryptedData.count ?? -1)")
            default:
                continue
            }
        }

        guard !pkeskPackets.isEmpty else {
            throw PacketParserError.noPKESKFound
        }
        guard let seipd = seipdPacket else {
            throw PacketParserError.noSEIPDFound
        }

        // 3. Try to decrypt session key with available keys
        var sessionAlgorithmID: UInt8?
        var sessionKey: [UInt8]?

        for pkesk in pkeskPackets {
            // V3 PKESK with algo 18 (ECDH) — existing v4 path
            if pkesk.version == 3 && pkesk.algorithm == 18 {
                pgpDebugLog("DEBUG Parser: PKESK v3 targets key ID = \(pkesk.keyID.map { String(format: "%02x", $0) }.joined())")

                for key in decryptionKeys {
                    pgpDebugLog("DEBUG Parser: checking against subkey ID = \(key.subkeyID.map { String(format: "%02x", $0) }.joined())")
                    if pkesk.keyID == key.subkeyID || pkesk.keyID == [UInt8](repeating: 0, count: 8) {
                        do {
                            let result = try Cv25519ECDHService.decryptSessionKey(
                                ephemeralPublicKey: pkesk.ephemeralPublicKey,
                                wrappedSessionKey: pkesk.wrappedSessionKey,
                                recipientPrivateKey: key.privateKey,
                                recipientFingerprint: key.subkeyFingerprint,
                                kdfHashID: key.kdfHashID,
                                kdfCipherID: key.kdfCipherID
                            )
                            sessionAlgorithmID = result.algorithmID
                            sessionKey = result.sessionKey
                            break
                        } catch {
                            pgpDebugLog("DEBUG Parser: PKESK v3 session key decrypt FAILED for subkey \(key.subkeyID.map { String(format: "%02x", $0) }.joined()): \(error)")
                            continue
                        }
                    }
                }
            }

            // V6 PKESK with algo 25 (X25519) — new v6 path
            if pkesk.version == 6 && pkesk.algorithm == 25 {
                pgpDebugLog("DEBUG Parser: PKESK v6 X25519 targets key ID = \(pkesk.keyID.map { String(format: "%02x", $0) }.joined())")

                for key in decryptionKeys {
                    pgpDebugLog("DEBUG Parser: checking v6 against subkey ID = \(key.subkeyID.map { String(format: "%02x", $0) }.joined())")
                    if pkesk.keyID == key.subkeyID || pkesk.keyFingerprint == key.subkeyFingerprint {
                        do {
                            let result = try decryptV6X25519SessionKey(
                                pkesk: pkesk,
                                recipientPrivateKey: key.privateKey,
                                recipientFingerprint: key.subkeyFingerprint
                            )
                            // V6 PKESK: the session key algo comes from the SEIPD v2 header, not the PKESK
                            sessionAlgorithmID = seipd.cipherAlgorithm != 0 ? seipd.cipherAlgorithm : result.algorithmID
                            sessionKey = result.sessionKey
                            break
                        } catch {
                            pgpDebugLog("DEBUG Parser: v6 X25519 decrypt failed: \(error)")
                            continue
                        }
                    }
                }
            }

            if sessionKey != nil { break }
        }

        guard let algID = sessionAlgorithmID, let sKey = sessionKey else {
            throw PacketParserError.noMatchingKey
        }
        
        pgpDebugLog("DEBUG Parser: session algorithm ID = \(algID) (7=AES128, 8=AES192, 9=AES256)")
        pgpDebugLog("DEBUG Parser: session key size = \(sKey.count) bytes")

        // 4. Decrypt SEIPD with session key — branch on version
        let plaintext: [UInt8]
        if seipd.version == 2 {
            // SEIPDv2 (tag 18 version 2): HKDF-derived key + chunked AEAD
            plaintext = try decryptSEIPDv2(seipd: seipd, sessionKey: sKey)
        } else if seipd.version == 100 {
            // Tag 20 AEAD Encrypted Data (GnuPG 2.4.x): session key used directly + nonce from packet
            plaintext = try decryptAEADTag20(seipd: seipd, sessionKey: sKey)
        } else {
            // SEIPDv1 (tag 18 version 1): CFB + MDC
            plaintext = try decryptSEIPD(
                encryptedData: seipd.encryptedData,
                sessionKey: sKey,
                algorithmID: algID
            )
        }

        // 5. Extract literal data from decrypted packets (handles compression)
        let innerPackets = try parsePackets(data: plaintext)
        let literalData = try extractLiteralData(from: innerPackets)
        if let result = literalData {
            return result
        }

        // If no literal data packet found, return raw decrypted data
        return Data(plaintext)
    }

    /// Hardware-key decrypt. Identical to `decryptMessage`'s v4 ECDH path, except
    /// the ECDH step is delegated to `provideSharedSecret` (the card's PSO:DECIPHER)
    /// instead of a local private scalar. The card only performs the curve point
    /// multiplication; the RFC 6637 KDF, AES key-unwrap, and SEIPD/AEAD decryption
    /// all run host-side through the same proven helpers. Scope: v3 PKESK / algo 18
    /// (Cv25519), which is what OpenPGP smartcards expose.
    static func decryptMessageOnCard(
        messageData: Data,
        recipientSubkeyID: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8,
        kdfCipherID: UInt8,
        provideSharedSecret: (_ ephemeralPublicKey: [UInt8]) async throws -> [UInt8]
    ) async throws -> Data {
        let plaintext = try await decryptMessageOnCardRaw(
            messageData: messageData,
            recipientSubkeyID: recipientSubkeyID,
            recipientFingerprint: recipientFingerprint,
            kdfHashID: kdfHashID,
            kdfCipherID: kdfCipherID,
            provideSharedSecret: provideSharedSecret
        )
        let innerPackets = try parsePackets(data: plaintext)
        if let result = try extractLiteralData(from: innerPackets) { return result }
        return Data(plaintext)
    }

    /// v6.0 — Phase 9j: same hardware-key decrypt, but returns the decrypted inner
    /// packet stream (literal data plus any sibling packets) so the caller can
    /// find and verify an embedded signature (tag 2). Mirrors the software
    /// `decryptMessageReturningInnerPackets` so card decrypt can show the same
    /// "signature verified / signed by" banner.
    static func decryptMessageOnCardReturningInnerPackets(
        messageData: Data,
        recipientSubkeyID: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8,
        kdfCipherID: UInt8,
        provideSharedSecret: (_ ephemeralPublicKey: [UInt8]) async throws -> [UInt8]
    ) async throws -> DecryptedMessageContents {
        let plaintext = try await decryptMessageOnCardRaw(
            messageData: messageData,
            recipientSubkeyID: recipientSubkeyID,
            recipientFingerprint: recipientFingerprint,
            kdfHashID: kdfHashID,
            kdfCipherID: kdfCipherID,
            provideSharedSecret: provideSharedSecret
        )
        let innerPackets = try parsePackets(data: plaintext)
        let literalData = (try? extractLiteralData(from: innerPackets)) ?? nil
        return DecryptedMessageContents(
            literalData: literalData ?? Data(plaintext),
            innerPackets: innerPackets
        )
    }

    /// Shared hardware-key decrypt core. Returns the decrypted inner packet
    /// stream (the bytes inside the SEIPD/AEAD container) without extracting the
    /// literal data, so both the literal-only and inner-packets wrappers can build
    /// their result from it.
    private static func decryptMessageOnCardRaw(
        messageData: Data,
        recipientSubkeyID: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8,
        kdfCipherID: UInt8,
        provideSharedSecret: (_ ephemeralPublicKey: [UInt8]) async throws -> [UInt8]
    ) async throws -> [UInt8] {

        let packets = try parsePackets(data: Array(messageData))

        var pkeskPackets: [ParsedPKESK] = []
        var seipdPacket: ParsedSEIPD?
        for packet in packets {
            switch packet.tag {
            case 1:
                if let pkesk = try? parsePKESK(body: packet.body) { pkeskPackets.append(pkesk) }
            case 18:
                seipdPacket = try parseSEIPD(body: packet.body)
            case 20:
                seipdPacket = try parseAEADEncryptedData(body: packet.body)
            default:
                continue
            }
        }
        guard !pkeskPackets.isEmpty else { throw PacketParserError.noPKESKFound }
        guard let seipd = seipdPacket else { throw PacketParserError.noSEIPDFound }

        var sessionAlgorithmID: UInt8?
        var sessionKey: [UInt8]?
        var firstCardError: Error?
        for pkesk in pkeskPackets {
            // Card encryption keys are v4 Cv25519: v3 PKESK, public-key algo 18.
            guard pkesk.version == 3, pkesk.algorithm == 18 else { continue }
            // Match the card's encryption subkey, or a wildcard (all-zero) key ID.
            guard pkesk.keyID == recipientSubkeyID
                  || pkesk.keyID == [UInt8](repeating: 0, count: 8) else { continue }

            // The card's decipher() strips a leading 0x40 itself; hand it the
            // MPI-decoded ephemeral point as-is.
            let shared: [UInt8]
            do {
                shared = try await provideSharedSecret(pkesk.ephemeralPublicKey)
            } catch {
                // A card-level failure here (wrong PIN, blocked PIN, NFC drop) is the
                // real reason we can't proceed — not "this PKESK didn't match." Keep it
                // so we surface it instead of the generic noMatchingKey below.
                if firstCardError == nil { firstCardError = error }
                continue
            }
            do {
                let result = try Cv25519ECDHService.sessionKeyFromSharedSecret(
                    sharedSecret: shared,
                    wrappedSessionKey: pkesk.wrappedSessionKey,
                    recipientFingerprint: recipientFingerprint,
                    kdfHashID: kdfHashID,
                    kdfCipherID: kdfCipherID
                )
                sessionAlgorithmID = result.algorithmID
                sessionKey = result.sessionKey
                break
            } catch {
                continue
            }
        }

        guard let algID = sessionAlgorithmID, let sKey = sessionKey else {
            throw firstCardError ?? PacketParserError.noMatchingKey
        }

        let plaintext: [UInt8]
        if seipd.version == 2 {
            plaintext = try decryptSEIPDv2(seipd: seipd, sessionKey: sKey)
        } else if seipd.version == 100 {
            plaintext = try decryptAEADTag20(seipd: seipd, sessionKey: sKey)
        } else {
            plaintext = try decryptSEIPD(
                encryptedData: seipd.encryptedData,
                sessionKey: sKey,
                algorithmID: algID
            )
        }

        return plaintext
    }

    // MARK: - RSA hardware-key decrypt (HW-R3)

    /// Parse the session-key block the card returns from an RSA PSO:DECIPHER:
    /// cipher-algorithm(1) || session key || 2-byte checksum. The checksum is the
    /// 16-bit sum (mod 65536) of the session-key bytes, matching what the sender
    /// wrote into the PKESK. Returns the cipher algorithm ID and the session key.
    static func parseCardSessionKeyBlock(_ block: [UInt8]) throws -> (algorithmID: UInt8, sessionKey: [UInt8]) {
        // Minimum: algorithm(1) + at least one key byte + checksum(2).
        guard block.count >= 4 else {
            throw PacketParserError.invalidPacket("RSA session-key block too short")
        }
        let algorithmID = block[0]
        let sessionKey = Array(block[1..<(block.count - 2)])
        let expected = UInt16(block[block.count - 2]) << 8 | UInt16(block[block.count - 1])
        let actual = sessionKey.reduce(UInt16(0)) { $0 &+ UInt16($1) }
        guard actual == expected else {
            throw PacketParserError.invalidPacket("RSA session-key checksum mismatch")
        }
        return (algorithmID, sessionKey)
    }

    /// Shared RSA hardware-key decrypt core. Mirrors `decryptMessageOnCardRaw` but
    /// for an RSA encryption (sub)key: the matching v3 PKESK carries a single
    /// cryptogram MPI, the card's PSO:DECIPHER returns the unpadded session-key
    /// block directly (no host KDF / key unwrap), and the SEIPD is then decrypted
    /// with that session key. Returns the decrypted inner packet stream.
    private static func decryptMessageOnCardRSARaw(
        messageData: Data,
        recipientKeyID: [UInt8],
        provideSessionKeyBlock: (_ cryptogram: [UInt8]) async throws -> [UInt8]
    ) async throws -> [UInt8] {

        let packets = try parsePackets(data: Array(messageData))

        var pkeskPackets: [ParsedPKESK] = []
        var seipdPacket: ParsedSEIPD?
        for packet in packets {
            switch packet.tag {
            case 1:
                if let pkesk = try? parsePKESK(body: packet.body) { pkeskPackets.append(pkesk) }
            case 18:
                seipdPacket = try parseSEIPD(body: packet.body)
            case 20:
                seipdPacket = try parseAEADEncryptedData(body: packet.body)
            default:
                continue
            }
        }
        guard !pkeskPackets.isEmpty else { throw PacketParserError.noPKESKFound }
        guard let seipd = seipdPacket else { throw PacketParserError.noSEIPDFound }

        var sessionAlgorithmID: UInt8?
        var sessionKey: [UInt8]?
        var firstCardError: Error?
        for pkesk in pkeskPackets {
            // RSA card keys are v4: v3 PKESK, public-key algo 1.
            guard pkesk.version == 3, pkesk.algorithm == 1 else { continue }
            guard pkesk.keyID == recipientKeyID
                  || pkesk.keyID == [UInt8](repeating: 0, count: 8) else { continue }

            let block: [UInt8]
            do {
                block = try await provideSessionKeyBlock(pkesk.rsaCipher)
            } catch {
                // Card-level failure (wrong PIN, blocked PIN, NFC drop) — surface it
                // rather than masking it as noMatchingKey.
                if firstCardError == nil { firstCardError = error }
                continue
            }
            do {
                let result = try parseCardSessionKeyBlock(block)
                sessionAlgorithmID = result.algorithmID
                sessionKey = result.sessionKey
                break
            } catch {
                continue
            }
        }

        guard let algID = sessionAlgorithmID, let sKey = sessionKey else {
            throw firstCardError ?? PacketParserError.noMatchingKey
        }

        let plaintext: [UInt8]
        if seipd.version == 2 {
            plaintext = try decryptSEIPDv2(seipd: seipd, sessionKey: sKey)
        } else if seipd.version == 100 {
            plaintext = try decryptAEADTag20(seipd: seipd, sessionKey: sKey)
        } else {
            plaintext = try decryptSEIPD(
                encryptedData: seipd.encryptedData,
                sessionKey: sKey,
                algorithmID: algID
            )
        }
        return plaintext
    }

    /// RSA card decrypt → literal data (nil if none). Sibling of
    /// `decryptMessageOnCard`.
    static func decryptMessageOnCardRSA(
        messageData: Data,
        recipientKeyID: [UInt8],
        provideSessionKeyBlock: (_ cryptogram: [UInt8]) async throws -> [UInt8]
    ) async throws -> Data {
        let plaintext = try await decryptMessageOnCardRSARaw(
            messageData: messageData,
            recipientKeyID: recipientKeyID,
            provideSessionKeyBlock: provideSessionKeyBlock
        )
        let innerPackets = try parsePackets(data: plaintext)
        if let result = try extractLiteralData(from: innerPackets) { return result }
        throw PacketParserError.invalidPacket("No literal data after RSA card decrypt")
    }

    /// RSA card decrypt → literal data plus the inner packet stream, so an embedded
    /// signature can be verified host-side. Sibling of
    /// `decryptMessageOnCardReturningInnerPackets`.
    static func decryptMessageOnCardRSAReturningInnerPackets(
        messageData: Data,
        recipientKeyID: [UInt8],
        provideSessionKeyBlock: (_ cryptogram: [UInt8]) async throws -> [UInt8]
    ) async throws -> DecryptedMessageContents {
        let plaintext = try await decryptMessageOnCardRSARaw(
            messageData: messageData,
            recipientKeyID: recipientKeyID,
            provideSessionKeyBlock: provideSessionKeyBlock
        )
        let innerPackets = try parsePackets(data: plaintext)
        let literalData = (try? extractLiteralData(from: innerPackets)) ?? nil
        return DecryptedMessageContents(
            literalData: literalData ?? Data(),
            innerPackets: innerPackets
        )
    }

    /// List the recipient key IDs (PKESK, tag 1) in a message, so the UI can tell
    /// whether an encrypted message is addressed to a known card key before
    /// prompting for a PIN + tap. All-zero IDs are wildcard ("hidden recipient").
    static func messageRecipientKeyIDs(_ data: Data) -> [[UInt8]] {
        guard let packets = try? parsePackets(data: Array(data)) else { return [] }
        var ids: [[UInt8]] = []
        for p in packets where p.tag == 1 {
            if let pkesk = try? parsePKESK(body: p.body) { ids.append(pkesk.keyID) }
        }
        return ids
    }

    // MARK: - Literal Data Extraction (with Decompression)

    /// Recursively extract literal data from parsed packets.
    /// Handles: tag 11 (literal data) directly, tag 8 (compressed data) by
    /// decompressing then re-parsing the inner packets.
    static func extractLiteralData(from packets: [ParsedPacket]) throws -> Data? {
        for packet in packets {
            switch packet.tag {
            case 11:
                // Literal data packet — extract payload directly
                return Data(parseLiteralData(body: packet.body))

            case 8:
                // Compressed data packet — decompress, then parse inner packets
                guard !packet.body.isEmpty else {
                    throw PacketParserError.decompressionFailed("Empty compressed packet")
                }
                let compressionAlgo = packet.body[0]
                let compressedData = Array(packet.body[1...])
                pgpDebugLog("DEBUG Parser: compressed packet, algo=\(compressionAlgo) (0=none, 1=ZIP, 2=ZLIB, 3=BZip2), compressed size=\(compressedData.count)")

                let decompressedData: [UInt8]
                switch compressionAlgo {
                case 0:
                    // Uncompressed
                    decompressedData = compressedData
                case 1:
                    // ZIP (raw DEFLATE, RFC 1951 — no zlib header/trailer)
                    decompressedData = try zlibDecompress(compressedData, rawDeflate: true)
                case 2:
                    // ZLIB (RFC 1950 — has zlib header/trailer)
                    decompressedData = try zlibDecompress(compressedData, rawDeflate: false)
                case 3:
                    throw PacketParserError.unsupportedCompression(3)  // BZip2 not supported
                default:
                    throw PacketParserError.unsupportedCompression(compressionAlgo)
                }
                pgpDebugLog("DEBUG Parser: decompressed \(compressedData.count) → \(decompressedData.count) bytes")

                // Parse decompressed data for inner packets
                let innerPackets = try parsePackets(data: decompressedData)
                return try extractLiteralData(from: innerPackets)

            default:
                continue
            }
        }
        return nil
    }

    // MARK: - Packet Parsing

    /// Parse a stream of OpenPGP packets
    static func parsePackets(data: [UInt8]) throws -> [ParsedPacket] {
        var packets: [ParsedPacket] = []
        var offset = 0

        while offset < data.count {
            guard offset < data.count else { break }
            let ctb = data[offset]
            offset += 1

            guard ctb & 0x80 != 0 else {
                throw PacketParserError.invalidPacket("Invalid CTB byte at offset \(offset - 1)")
            }

            let tag: UInt8

            if ctb & 0x40 != 0 {
                // New format. The body may be split into a series of partial
                // body-length chunks (RFC 4880 §4.2.2.4) — gpg emits these when it
                // streams a packet without knowing the total length up front, e.g.
                // a SEIPD wrapping a multi-line / larger message. Each partial
                // header is followed by 2^n body octets and then more length
                // headers, terminated by a single definite-length header (which
                // may itself be zero). Reassemble every chunk into one contiguous
                // body. Reading only the first chunk — the previous behavior —
                // truncated the ciphertext, so the decrypted plaintext was wrong
                // and the trailing MDC check failed ("MDC mismatch"). This affects
                // the inner literal/compressed packets after decryption too, since
                // they share this parser.
                tag = ctb & 0x3F
                var body: [UInt8] = []
                while true {
                    let chunkLength: Int
                    let isPartial: Bool
                    (chunkLength, isPartial, offset) = try parseNewFormatLength(data: data, offset: offset)
                    guard offset + chunkLength <= data.count else {
                        throw PacketParserError.invalidPacket("Packet body extends past end of data (tag=\(tag), len=\(chunkLength), remaining=\(data.count - offset))")
                    }
                    body.append(contentsOf: data[offset..<(offset + chunkLength)])
                    offset += chunkLength
                    if !isPartial { break }
                }
                packets.append(ParsedPacket(tag: tag, body: body))
            } else {
                // Old format. Length types are fixed-size; no partial chunks.
                tag = (ctb & 0x3C) >> 2
                let lengthType = ctb & 0x03
                let bodyLength: Int
                (bodyLength, offset) = try parseOldFormatLength(data: data, offset: offset, lengthType: lengthType)
                guard offset + bodyLength <= data.count else {
                    throw PacketParserError.invalidPacket("Packet body extends past end of data (tag=\(tag), len=\(bodyLength), remaining=\(data.count - offset))")
                }
                let body = Array(data[offset..<(offset + bodyLength)])
                packets.append(ParsedPacket(tag: tag, body: body))
                offset += bodyLength
            }
        }

        return packets
    }

    // MARK: - Length Parsing

    private static func parseNewFormatLength(data: [UInt8], offset: Int) throws -> (Int, Bool, Int) {
        var off = offset
        guard off < data.count else {
            throw PacketParserError.invalidPacket("Unexpected end of data parsing length")
        }

        let first = data[off]
        off += 1

        if first < 192 {
            return (Int(first), false, off)
        } else if first < 224 {
            guard off < data.count else {
                throw PacketParserError.invalidPacket("Unexpected end of data parsing 2-byte length")
            }
            let second = data[off]
            off += 1
            let len = (Int(first) - 192) * 256 + Int(second) + 192
            return (len, false, off)
        } else if first == 255 {
            guard off + 4 <= data.count else {
                throw PacketParserError.invalidPacket("Unexpected end of data parsing 5-byte length")
            }
            let len = Int(data[off]) << 24 | Int(data[off + 1]) << 16 | Int(data[off + 2]) << 8 | Int(data[off + 3])
            off += 4
            return (len, false, off)
        } else {
            // Partial body length: 2^(first & 0x1F) octets follow, then more
            // length headers. Signal isPartial so the caller keeps reading chunks
            // until a terminating definite-length header.
            let partialLen = 1 << (Int(first) & 0x1F)
            return (partialLen, true, off)
        }
    }

    private static func parseOldFormatLength(data: [UInt8], offset: Int, lengthType: UInt8) throws -> (Int, Int) {
        var off = offset
        switch lengthType {
        case 0:
            guard off < data.count else {
                throw PacketParserError.invalidPacket("Unexpected end of data")
            }
            let len = Int(data[off])
            return (len, off + 1)
        case 1:
            guard off + 2 <= data.count else {
                throw PacketParserError.invalidPacket("Unexpected end of data")
            }
            let len = Int(data[off]) << 8 | Int(data[off + 1])
            return (len, off + 2)
        case 2:
            guard off + 4 <= data.count else {
                throw PacketParserError.invalidPacket("Unexpected end of data")
            }
            let len = Int(data[off]) << 24 | Int(data[off + 1]) << 16 | Int(data[off + 2]) << 8 | Int(data[off + 3])
            return (len, off + 4)
        case 3:
            // Indeterminate length — rest of data
            return (data.count - off, off)
        default:
            throw PacketParserError.invalidPacket("Invalid old-format length type")
        }
    }

    // MARK: - PKESK Parsing

    private static func parsePKESK(body: [UInt8]) throws -> ParsedPKESK {
        var off = 0

        guard body.count > 3 else {
            throw PacketParserError.invalidPacket("PKESK too short")
        }

        let version = body[off]; off += 1

        if version == 3 {
            return try parsePKESKv3(body: body, off: &off)
        } else if version == 6 {
            return try parsePKESKv6(body: body, off: &off)
        } else {
            throw PacketParserError.unsupportedPacketVersion(version)
        }
    }

    /// Parse a v3 PKESK: version(1)=3 | keyID(8) | algo(1) | encrypted_session_key
    private static func parsePKESKv3(body: [UInt8], off: inout Int) throws -> ParsedPKESK {
        guard off + 9 <= body.count else {
            throw PacketParserError.invalidPacket("PKESK v3 too short")
        }

        let keyID = Array(body[off..<(off + 8)]); off += 8
        let algorithm = body[off]; off += 1

        // RSA (algo 1): a single MPI cryptogram (m^e mod n) follows. There's no
        // ephemeral key or wrapped-key length octet — the card returns the unpadded
        // session-key block directly from PSO:DECIPHER.
        if algorithm == 1 {
            guard off + 2 <= body.count else {
                throw PacketParserError.invalidPacket("RSA PKESK: missing cryptogram MPI")
            }
            let bits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
            let byteLen = (bits + 7) / 8
            guard off + byteLen <= body.count else {
                throw PacketParserError.invalidPacket("RSA PKESK: cryptogram truncated")
            }
            let cipher = Array(body[off..<(off + byteLen)]); off += byteLen
            return ParsedPKESK(
                version: 3,
                keyID: keyID,
                algorithm: algorithm,
                ephemeralPublicKey: [],
                wrappedSessionKey: [],
                keyFingerprint: [],
                keyVersion: 0,
                rsaCipher: cipher
            )
        }

        guard algorithm == 18 else {
            throw PacketParserError.unsupportedAlgorithm(algorithm)
        }

        // Parse ephemeral public key MPI
        guard off + 2 <= body.count else {
            throw PacketParserError.invalidPacket("PKESK: missing ephemeral key MPI")
        }
        let ephBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let ephBytes = (ephBits + 7) / 8
        guard off + ephBytes <= body.count else {
            throw PacketParserError.invalidPacket("PKESK: ephemeral key truncated")
        }
        let ephemeralKey = Array(body[off..<(off + ephBytes)]); off += ephBytes

        // Parse wrapped session key
        guard off < body.count else {
            throw PacketParserError.invalidPacket("PKESK: missing wrapped key length")
        }
        let wrappedLen = Int(body[off]); off += 1
        guard off + wrappedLen <= body.count else {
            throw PacketParserError.invalidPacket("PKESK: wrapped key truncated")
        }
        let wrappedKey = Array(body[off..<(off + wrappedLen)])

        return ParsedPKESK(
            version: 3,
            keyID: keyID,
            algorithm: algorithm,
            ephemeralPublicKey: ephemeralKey,
            wrappedSessionKey: wrappedKey,
            keyFingerprint: [],
            keyVersion: 0,
            rsaCipher: []
        )
    }

    /// Parse a v6 PKESK (RFC 9580 §5.1.2). The version octet is already consumed
    /// by the caller. Layout:
    ///   size_of_next_two_fields(1) | key_version(1) | fingerprint(size-1) |
    ///   algo(1) | algorithm-specific
    /// (size may be 0 for an anonymous recipient: no key version, no fingerprint.)
    /// For X25519 (algo 25) the algorithm-specific fields are:
    ///   ephemeral_key(32) | size_of_wrapped(1) | wrapped_session_key(size)
    private static func parsePKESKv6(body: [UInt8], off: inout Int) throws -> ParsedPKESK {
        guard off < body.count else {
            throw PacketParserError.invalidPacket("PKESK v6: missing size octet")
        }
        let sizeOfNext = Int(body[off]); off += 1

        var keyVersion: UInt8 = 0
        var fingerprint: [UInt8] = []
        if sizeOfNext > 0 {
            guard off < body.count else {
                throw PacketParserError.invalidPacket("PKESK v6: missing key version")
            }
            keyVersion = body[off]; off += 1

            let fpLen = sizeOfNext - 1   // size covers key_version(1) + fingerprint
            guard fpLen >= 0, off + fpLen <= body.count else {
                throw PacketParserError.invalidPacket("PKESK v6: fingerprint truncated")
            }
            fingerprint = Array(body[off..<(off + fpLen)]); off += fpLen
        }

        // Derive key ID from fingerprint (v6 = leading 8, v4 = trailing 8).
        let keyID: [UInt8]
        if keyVersion == 6 && fingerprint.count >= 8 {
            keyID = Array(fingerprint.prefix(8))
        } else if keyVersion == 4 && fingerprint.count >= 8 {
            keyID = Array(fingerprint.suffix(8))
        } else {
            keyID = Array(fingerprint.prefix(min(8, fingerprint.count)))
        }

        guard off < body.count else {
            throw PacketParserError.invalidPacket("PKESK v6: missing algorithm")
        }
        let algorithm = body[off]; off += 1

        let ephemeralKey: [UInt8]
        let wrappedKey: [UInt8]

        if algorithm == 25 {
            // X25519: 32-byte ephemeral key, then a 1-octet size of the wrapped
            // session key, then the wrapped session key itself.
            guard off + 32 < body.count else {
                throw PacketParserError.invalidPacket("PKESK v6 X25519: ephemeral key truncated")
            }
            ephemeralKey = Array(body[off..<(off + 32)]); off += 32
            let wrapSize = Int(body[off]); off += 1
            guard off + wrapSize <= body.count else {
                throw PacketParserError.invalidPacket("PKESK v6 X25519: wrapped key truncated")
            }
            wrappedKey = Array(body[off..<(off + wrapSize)]); off += wrapSize
        } else {
            ephemeralKey = []
            wrappedKey = off < body.count ? Array(body[off...]) : []
        }

        pgpDebugLog("DEBUG PKESK v6: size=\(sizeOfNext), keyVer=\(keyVersion), fpLen=\(fingerprint.count), algo=\(algorithm), ephLen=\(ephemeralKey.count), wrappedLen=\(wrappedKey.count), keyID=\(keyID.map { String(format: "%02x", $0) }.joined())")

        return ParsedPKESK(
            version: 6,
            keyID: keyID,
            algorithm: algorithm,
            ephemeralPublicKey: ephemeralKey,
            wrappedSessionKey: wrappedKey,
            keyFingerprint: fingerprint,
            keyVersion: keyVersion,
            rsaCipher: []
        )
    }

    // MARK: - SEIPD Parsing

    static func parseSEIPD(body: [UInt8]) throws -> ParsedSEIPD {
        guard body.count > 1 else {
            throw PacketParserError.invalidPacket("SEIPD too short")
        }

        let version = body[0]

        if version == 1 {
            return ParsedSEIPD(
                version: 1,
                encryptedData: Array(body[1...]),
                cipherAlgorithm: 0,
                aeadAlgorithm: 0,
                chunkSizeByte: 0,
                salt: []
            )
        } else if version == 2 {
            // V2 header: version(1) | cipher(1) | aead(1) | chunkSize(1) | salt(32) | encrypted_data
            guard body.count >= 36 else {
                throw PacketParserError.invalidPacket("SEIPD v2 header too short (\(body.count) bytes)")
            }
            let cipher = body[1]
            let aead = body[2]
            let chunkByte = body[3]
            let salt = Array(body[4..<36])
            let encData = Array(body[36...])

            pgpDebugLog("DEBUG SEIPD v2: cipher=\(cipher), aead=\(aead) (1=EAX,2=OCB,3=GCM), chunkByte=\(chunkByte) (2^\(chunkByte+6)=\(1<<(Int(chunkByte)+6)) bytes), salt=\(salt.prefix(8).map { String(format: "%02x", $0) }.joined())..., encDataLen=\(encData.count)")

            return ParsedSEIPD(
                version: 2,
                encryptedData: encData,
                cipherAlgorithm: cipher,
                aeadAlgorithm: aead,
                chunkSizeByte: chunkByte,
                salt: salt
            )
        } else {
            throw PacketParserError.unsupportedPacketVersion(version)
        }
    }

    // MARK: - Tag 20: AEAD Encrypted Data Packet (GnuPG 2.4.x)

    /// Parse a tag 20 AEAD Encrypted Data packet (GnuPG 2.4.x legacy AEAD).
    /// Structure: version(1) | cipher(1) | aead(1) | chunkSizeByte(1) | nonce(N) | encrypted_data
    ///
    /// Different from SEIPDv2:
    /// - No 32-byte salt (uses nonce from packet directly)
    /// - Session key is used directly as the message key (no HKDF)
    /// - Nonce is stored in the packet, not derived
    ///
    /// We store the nonce in the `salt` field of ParsedSEIPD and use version=100
    /// as a sentinel to distinguish from SEIPDv1/v2 in the decryption path.
    private static func parseAEADEncryptedData(body: [UInt8]) throws -> ParsedSEIPD {
        guard body.count >= 4 else {
            throw PacketParserError.invalidPacket("Tag 20 AEAD packet too short")
        }

        var off = 0
        let version = body[off]; off += 1   // Should be 1 for GnuPG 2.4.x
        let cipher = body[off]; off += 1
        let aead = body[off]; off += 1
        let chunkByte = body[off]; off += 1

        // Nonce size depends on AEAD algorithm
        let nonceLen = AEADService.nonceSize(for: aead)
        guard nonceLen > 0 else {
            throw PacketParserError.unsupportedAlgorithm(aead)
        }
        guard off + nonceLen <= body.count else {
            throw PacketParserError.invalidPacket("Tag 20: nonce truncated")
        }
        let nonce = Array(body[off..<(off + nonceLen)]); off += nonceLen

        let encData = Array(body[off...])

        pgpDebugLog("DEBUG Tag20 AEAD: version=\(version), cipher=\(cipher), aead=\(aead), chunkByte=\(chunkByte), nonceLen=\(nonceLen), encDataLen=\(encData.count)")

        // Use version=100 as sentinel to distinguish tag 20 from SEIPDv1/v2
        // Store nonce in the salt field for access during decryption
        return ParsedSEIPD(
            version: 100,
            encryptedData: encData,
            cipherAlgorithm: cipher,
            aeadAlgorithm: aead,
            chunkSizeByte: chunkByte,
            salt: nonce   // Reuse salt field for the nonce
        )
    }

    /// Decrypt a tag 20 AEAD Encrypted Data packet.
    ///
    /// Tag 20 uses the session key DIRECTLY as the encryption key (no HKDF).
    /// The nonce is stored in the packet. Chunks are AEAD-encrypted with
    /// incrementing nonces (nonce XOR chunkIndex).
    ///
    /// Each chunk: encrypted_plaintext(chunkSize) + auth_tag(16)
    /// Final: auth_tag(16) for empty plaintext to authenticate the total.
    private static func decryptAEADTag20(
        seipd: ParsedSEIPD,
        sessionKey: [UInt8]
    ) throws -> [UInt8] {
        let aeadAlgo = seipd.aeadAlgorithm
        let baseNonce = seipd.salt  // Nonce stored in salt field by parseAEADEncryptedData
        let chunkSize = seipd.chunkSize
        let tagSize = AEADService.tagSize
        let encData = seipd.encryptedData

        pgpDebugLog("DEBUG Tag20 Decrypt: aead=\(aeadAlgo), chunkSize=\(chunkSize), nonce=\(baseNonce.map { String(format: "%02x", $0) }.joined()), encDataLen=\(encData.count)")

        var plaintext = [UInt8]()
        var offset = 0
        var chunkIndex: UInt64 = 0

        // Associated data for tag 20 chunks:
        // tag_byte(0xD4) | version(1) | cipher(1) | aead(1) | chunkSizeByte(1)
        let aadPrefix: [UInt8] = [0xD4, 0x01, seipd.cipherAlgorithm, seipd.aeadAlgorithm, seipd.chunkSizeByte]

        while offset < encData.count {
            // Compute nonce: baseNonce XOR chunkIndex (big-endian, right-aligned)
            var nonce = baseNonce
            let indexBytes = withUnsafeBytes(of: chunkIndex.bigEndian) { Array($0) }
            let nonceLen = nonce.count
            for i in 0..<min(8, nonceLen) {
                nonce[nonceLen - 8 + i] ^= indexBytes[i]
            }

            let remainingData = encData.count - offset

            // Determine chunk size
            let chunkCiphertextSize: Int
            let isLastDataChunk: Bool

            if remainingData > chunkSize + tagSize + tagSize {
                // Full chunk
                chunkCiphertextSize = chunkSize + tagSize
                isLastDataChunk = false
            } else if remainingData > tagSize {
                // Last data chunk (possibly short) + final auth tag
                chunkCiphertextSize = remainingData - tagSize
                isLastDataChunk = true
            } else {
                // Only final auth tag remains
                break
            }

            guard offset + chunkCiphertextSize <= encData.count else {
                throw PacketParserError.decryptionFailed("Tag 20: chunk extends past data")
            }

            let chunkData = Array(encData[offset..<(offset + chunkCiphertextSize)])

            // AAD = aadPrefix || chunkIndex(8, big-endian)
            var aad = aadPrefix
            aad.append(contentsOf: indexBytes)

            let decrypted = try AEADService.decryptWithAppendedTag(
                data: chunkData,
                key: sessionKey,
                nonce: nonce,
                aeadAlgo: aeadAlgo,
                associatedData: aad
            )
            plaintext.append(contentsOf: decrypted)

            offset += chunkCiphertextSize
            chunkIndex += 1

            if isLastDataChunk { break }
        }

        // Verify final auth tag
        if offset + tagSize <= encData.count {
            let finalTag = Array(encData[offset..<(offset + tagSize)])

            var finalNonce = baseNonce
            let finalIndexBytes = withUnsafeBytes(of: chunkIndex.bigEndian) { Array($0) }
            let nonceLen = finalNonce.count
            for i in 0..<min(8, nonceLen) {
                finalNonce[nonceLen - 8 + i] ^= finalIndexBytes[i]
            }

            // Final AAD = aadPrefix || chunkIndex(8) || totalOctets(8, big-endian)
            var finalAAD = aadPrefix
            finalAAD.append(contentsOf: finalIndexBytes)
            let totalLen = UInt64(plaintext.count)
            finalAAD.append(contentsOf: withUnsafeBytes(of: totalLen.bigEndian) { Array($0) })

            do {
                let _ = try AEADService.decrypt(
                    ciphertext: [],
                    tag: finalTag,
                    key: sessionKey,
                    nonce: finalNonce,
                    aeadAlgo: aeadAlgo,
                    associatedData: finalAAD
                )
            } catch {
                pgpDebugLog("DEBUG Tag20: final auth tag verification failed: \(error)")
                throw PacketParserError.mdcVerificationFailed
            }
        }

        pgpDebugLog("DEBUG Tag20 Decrypt: decrypted \(plaintext.count) bytes from \(chunkIndex) chunks")
        return plaintext
    }

    // MARK: - SEIPD Decryption

    /// Decrypt SEIPD data and verify MDC
    static func decryptSEIPD(
        encryptedData: [UInt8],
        sessionKey: [UInt8],
        algorithmID: UInt8
    ) throws -> [UInt8] {

        let bs = try cipherBlockSize(for: algorithmID)

        pgpDebugLog("DEBUG SEIPD: encrypted data hex = \(encryptedData.prefix(36).map { String(format: "%02x", $0) }.joined(separator: " "))... (\(encryptedData.count) bytes)")

        // OpenPGP CFB decrypt with resync
        let decrypted = try openPGPCFBDecrypt(
            ciphertext: encryptedData,
            key: sessionKey,
            algorithmID: algorithmID
        )

        // Verify prefix: bytes [bs-2] and [bs-1] should equal [bs] and [bs+1]
        guard decrypted.count > bs + 2 else {
            throw PacketParserError.decryptionFailed("Decrypted data too short for prefix check")
        }
        pgpDebugLog("DEBUG SEIPD: prefix check: [\(bs-2)]=\(decrypted[bs-2]) vs [\(bs)]=\(decrypted[bs]), [\(bs-1)]=\(decrypted[bs-1]) vs [\(bs+1)]=\(decrypted[bs+1])")
        guard decrypted[bs - 2] == decrypted[bs] && decrypted[bs - 1] == decrypted[bs + 1] else {
            throw PacketParserError.decryptionFailed("Prefix quick-check failed — wrong session key")
        }

        // Hex dump entire decrypted output for debugging
        let hexDump = decrypted.enumerated().map { i, b in
            let prefix = (i % 16 == 0) ? "\n  [\(String(format: "%03d", i))] " : ""
            return "\(prefix)\(String(format: "%02x", b))"
        }.joined(separator: " ")
        pgpDebugLog("DEBUG SEIPD: full decrypted hex:\(hexDump)")

        // Strip prefix (bs+2 bytes)
        let payload = Array(decrypted[(bs + 2)...])
        pgpDebugLog("DEBUG SEIPD: decrypted total=\(decrypted.count), payload=\(payload.count)")
        pgpDebugLog("DEBUG SEIPD: payload first 20 bytes: \(payload.prefix(20).map { String(format: "%02x", $0) }.joined(separator: " "))")
        pgpDebugLog("DEBUG SEIPD: payload last 30 bytes: \(payload.suffix(30).map { String(format: "%02x", $0) }.joined(separator: " "))")

        // Verify MDC (last 22 bytes: tag(1) + len(1) + sha1(20))
        guard payload.count >= 22 else {
            throw PacketParserError.decryptionFailed("Payload too short for MDC")
        }

        let mdcOffset = payload.count - 22
        pgpDebugLog("DEBUG SEIPD: MDC tag bytes at offset \(mdcOffset): 0x\(String(format: "%02x", payload[mdcOffset])) 0x\(String(format: "%02x", payload[mdcOffset + 1]))")
        guard payload[mdcOffset] == 0xD3 && payload[mdcOffset + 1] == 0x14 else {
            throw PacketParserError.mdcVerificationFailed
        }

        let storedHash = Array(payload[(mdcOffset + 2)...])
        let dataBeforeMDC = Array(decrypted[0..<(decrypted.count - 20)])
        pgpDebugLog("DEBUG SEIPD: dataBeforeMDC length=\(dataBeforeMDC.count), last 4 bytes: \(dataBeforeMDC.suffix(4).map { String(format: "%02x", $0) }.joined(separator: " "))")

        var computedHash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(dataBeforeMDC, CC_LONG(dataBeforeMDC.count), &computedHash)
        
        pgpDebugLog("DEBUG SEIPD: stored  hash = \(storedHash.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " "))...")
        pgpDebugLog("DEBUG SEIPD: computed hash = \(computedHash.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " "))...")

        guard storedHash == computedHash else {
            throw PacketParserError.mdcVerificationFailed
        }

        // Return everything before MDC packet
        return Array(payload[0..<mdcOffset])
    }

    // MARK: - SEIPDv2 / AEAD Decryption (RFC 9580 §5.13.2)

    /// Decrypt a SEIPD v2 packet using chunked AEAD.
    ///
    /// SEIPDv2 structure:
    ///   - Session key is used with HKDF to derive the message key and IV
    ///   - Data is split into chunks, each independently AEAD-encrypted
    ///   - Each chunk has its own authentication tag
    ///   - A final empty-ciphertext authentication tag verifies the total
    ///
    /// Key derivation (RFC 9580 §5.13.2):
    ///   HKDF-SHA256 with:
    ///     ikm = session_key
    ///     salt = SEIPDv2 salt (32 bytes)
    ///     info = packet_tag(0xD2) || version(0x02) || cipher || aead || chunkSizeByte
    ///     output = message_key(cipher_key_size) || iv(aead_nonce_size)
    static func decryptSEIPDv2(
        seipd: ParsedSEIPD,
        sessionKey: [UInt8]
    ) throws -> [UInt8] {
        guard seipd.version == 2 else {
            throw PacketParserError.invalidPacket("decryptSEIPDv2 called with version \(seipd.version)")
        }

        let aeadAlgo = seipd.aeadAlgorithm
        let cipherAlgo = seipd.cipherAlgorithm

        // Key and nonce sizes
        let keySize = try cipherKeySize(for: cipherAlgo)
        let nonceSize = AEADService.nonceSize(for: aeadAlgo)
        guard nonceSize > 0 else {
            throw PacketParserError.unsupportedAlgorithm(aeadAlgo)
        }

        // HKDF to derive message key + IV
        // info = 0xD2 (SEIPD packet tag in new format CTB) || 0x02 || cipher || aead || chunkSizeByte
        let info: [UInt8] = [0xD2, 0x02, cipherAlgo, aeadAlgo, seipd.chunkSizeByte]
        // RFC 9580 §5.13.2: HKDF derives the cipher key followed by ONLY the first
        // (nonceSize - 8) octets of the nonce. The trailing 8 octets begin at zero
        // and are XORed with the big-endian chunk index for each chunk. The earlier
        // code derived a full-length nonce from HKDF and XORed the index into HKDF
        // output — that round-trips PGPony<->PGPony but does NOT interoperate with
        // sq / RFC 9580 (see Phase V6-C). v6.0 Phase V6-C fix.
        let ivPrefixLen = nonceSize - 8
        let hkdfOutput = try hkdfSHA256(
            ikm: sessionKey,
            salt: seipd.salt,
            info: info,
            outputLength: keySize + ivPrefixLen
        )
        let messageKey = Array(hkdfOutput[0..<keySize])
        var baseIV = Array(hkdfOutput[keySize...])
        baseIV.append(contentsOf: [UInt8](repeating: 0, count: 8))

        pgpDebugLog("DEBUG SEIPDv2: cipher=\(cipherAlgo), aead=\(aeadAlgo), chunkSize=\(seipd.chunkSize), msgKeyLen=\(messageKey.count), ivLen=\(baseIV.count)")

        // Decrypt chunks
        let chunkSize = seipd.chunkSize
        let tagSize = AEADService.tagSize
        let encData = seipd.encryptedData

        var plaintext = [UInt8]()
        var offset = 0
        var chunkIndex: UInt64 = 0

        // Associated data for each chunk = info bytes
        let chunkAAD = info

        while offset < encData.count {
            // Compute nonce for this chunk: baseIV XOR chunkIndex (big-endian, right-aligned)
            var nonce = baseIV
            let indexBytes = withUnsafeBytes(of: chunkIndex.bigEndian) { Array($0) }
            // XOR the chunk index into the last 8 bytes of the nonce
            let nonceLen = nonce.count
            for i in 0..<min(8, nonceLen) {
                nonce[nonceLen - 8 + i] ^= indexBytes[i]
            }

            // Determine chunk ciphertext size
            let remainingData = encData.count - offset
            let isLastChunk: Bool
            let chunkCiphertextSize: Int

            // Each chunk = encrypted_plaintext(chunkSize) + tag(16)
            // Last chunk may be shorter
            // Final auth tag = tag for empty plaintext (no ciphertext, just tag)
            if remainingData > chunkSize + tagSize + tagSize {
                // Full chunk: chunkSize bytes of ciphertext + 16-byte tag
                chunkCiphertextSize = chunkSize + tagSize
                isLastChunk = false
            } else if remainingData > tagSize {
                // Last data chunk (possibly short) + its tag + final tag
                // The final tag is the last 16 bytes
                chunkCiphertextSize = remainingData - tagSize  // Everything except the final auth tag
                isLastChunk = true
            } else {
                // Only the final auth tag remains
                break
            }

            guard offset + chunkCiphertextSize <= encData.count else {
                throw PacketParserError.decryptionFailed("SEIPDv2: chunk extends past data")
            }

            let chunkData = Array(encData[offset..<(offset + chunkCiphertextSize)])

            // RFC 9580 SEIPDv2: per-chunk AAD is the 5 header octets ONLY.
            // The chunk index is mixed into the nonce, not the AAD. (Only the old
            // tag-20 AEAD packet folds the index into the AAD.)
            let aad = chunkAAD

            let decrypted = try AEADService.decryptWithAppendedTag(
                data: chunkData,
                key: messageKey,
                nonce: nonce,
                aeadAlgo: aeadAlgo,
                associatedData: aad
            )
            plaintext.append(contentsOf: decrypted)

            offset += chunkCiphertextSize
            chunkIndex += 1

            if isLastChunk { break }
        }

        // Verify final authentication tag
        if offset + tagSize <= encData.count {
            let finalTag = Array(encData[offset..<(offset + tagSize)])

            // Final tag nonce = baseIV XOR chunkIndex (the index after the last data chunk)
            var finalNonce = baseIV
            let finalIndexBytes = withUnsafeBytes(of: chunkIndex.bigEndian) { Array($0) }
            let nonceLen = finalNonce.count
            for i in 0..<min(8, nonceLen) {
                finalNonce[nonceLen - 8 + i] ^= finalIndexBytes[i]
            }

            // RFC 9580 SEIPDv2: final AAD = the 5 header octets || total plaintext
            // length (8, BE). No chunk index in the AAD (the nonce still uses the
            // advanced index).
            var finalAAD = chunkAAD
            let totalLen = UInt64(plaintext.count)
            finalAAD.append(contentsOf: withUnsafeBytes(of: totalLen.bigEndian) { Array($0) })

            // Verify: decrypt empty ciphertext with the final tag
            do {
                let _ = try AEADService.decrypt(
                    ciphertext: [],
                    tag: finalTag,
                    key: messageKey,
                    nonce: finalNonce,
                    aeadAlgo: aeadAlgo,
                    associatedData: finalAAD
                )
            } catch {
                pgpDebugLog("DEBUG SEIPDv2: final auth tag verification failed: \(error)")
                throw PacketParserError.mdcVerificationFailed
            }
        }

        pgpDebugLog("DEBUG SEIPDv2: decrypted \(plaintext.count) bytes total from \(chunkIndex) chunks")

        return plaintext
    }

    // MARK: - V6 X25519 Session Key Decryption (RFC 9580 §5.1.6)

    /// Decrypt a session key from a v6 PKESK using X25519 ECDH.
    ///
    /// RFC 9580 §5.1.6 X25519 session key decryption:
    ///   1. Compute shared secret: X25519(recipientPriv, ephemeralPub)
    ///   2. HKDF-SHA256 to derive KEK:
    ///      ikm = ephemeral_pub(32) || recipient_pub(32) || shared_secret(32)
    ///      salt = (empty)
    ///      info = key_version(1) || cipher_algo(1) || "OpenPGP X25519"
    ///            (note: cipher_algo comes from PKESK encrypted data, NOT SEIPD)
    ///   3. AES key unwrap the encrypted session key with the derived KEK
    ///
    /// The wrapped data format for v6 X25519 does NOT include an algorithm ID byte
    /// or checksum like v4 ECDH. The algorithm ID comes from the SEIPD v2 header.
    private static func decryptV6X25519SessionKey(
        pkesk: ParsedPKESK,
        recipientPrivateKey: [UInt8],
        recipientFingerprint: [UInt8]
    ) throws -> (algorithmID: UInt8, sessionKey: [UInt8]) {
        guard pkesk.ephemeralPublicKey.count == 32 else {
            throw PacketParserError.invalidPacket("V6 X25519 PKESK: ephemeral key must be 32 bytes")
        }
        guard recipientPrivateKey.count == 32 else {
            throw PacketParserError.invalidPacket("V6 X25519: recipient private key must be 32 bytes")
        }

        // 1. X25519 key agreement
        let privKey = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey)
        let ephPubKey = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: pkesk.ephemeralPublicKey)
        let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: ephPubKey)
        let sharedSecretBytes = sharedSecret.withUnsafeBytes { Array($0) }

        // Derive recipient public key from private key
        let recipientPubKey = privKey.publicKey.rawRepresentation

        // 2. HKDF-SHA256 to derive KEK
        // ikm = ephemeral(32) || recipient_pub(32) || shared_secret(32)
        var ikm = pkesk.ephemeralPublicKey
        ikm.append(contentsOf: Array(recipientPubKey))
        ikm.append(contentsOf: sharedSecretBytes)

        // info = "OpenPGP X25519" (no null terminator per RFC 9580)
        let infoString = Array("OpenPGP X25519".utf8)

        // The KEK size matches the wrapped session key: AES-128 (16), AES-192 (24), or AES-256 (32)
        // For v6, we derive enough for the largest possible key (32 bytes)
        // and use the appropriate prefix based on the wrapped key size
        let wrappedKeyLen = pkesk.wrappedSessionKey.count
        // RFC 9580 §5.1.6: the X25519 key-wrapping key (KEK) is ALWAYS AES-128
        // (16 octets), independent of the wrapped session key's cipher. (The
        // session key itself may be AES-128/192/256 — that's declared in the
        // SEIPDv2 packet, not here.)
        let kekSize = 16

        let kek = try hkdfSHA256(
            ikm: ikm,
            salt: [],
            info: infoString,
            outputLength: kekSize
        )


        // 3. AES key unwrap
        let unwrapped = try AESKeyWrap.unwrap(ciphertext: pkesk.wrappedSessionKey, kek: kek)

        // V6 X25519: unwrapped data IS the session key (no algo byte, no checksum)
        pgpDebugLog("DEBUG V6 X25519: unwrapped session key = \(unwrapped.count) bytes")

        return (algorithmID: 0, sessionKey: unwrapped)
    }

    // MARK: - HKDF-SHA256 (RFC 5869)

    /// HKDF-SHA256 key derivation.
    /// Used by SEIPDv2 for message key derivation and by v6 X25519 for KEK derivation.
    /// Internal (not private) so OpenPGPPacketBuilder uses the identical KDF on the
    /// encrypt side, guaranteeing symmetric byte-for-byte derivation.
    static func hkdfSHA256(
        ikm: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        // Step 1: Extract — PRK = HMAC-SHA256(salt, ikm)
        let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: 32) : salt
        let prk = hmacSHA256(key: effectiveSalt, data: ikm)

        // Step 2: Expand — T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        var output = [UInt8]()
        var previous = [UInt8]()
        var counter: UInt8 = 1

        while output.count < outputLength {
            var input = previous
            input.append(contentsOf: info)
            input.append(counter)
            let t = hmacSHA256(key: prk, data: input)
            output.append(contentsOf: t)
            previous = t
            counter += 1
        }

        return Array(output.prefix(outputLength))
    }

    /// HMAC-SHA256
    private static func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, data, data.count, &hmac)
        return hmac
    }

    /// Get AES key size in bytes from cipher algorithm ID
    private static func cipherKeySize(for cipherAlgo: UInt8) throws -> Int {
        switch cipherAlgo {
        case 7: return 16   // AES-128
        case 8: return 24   // AES-192
        case 9: return 32   // AES-256
        default: throw PacketParserError.unsupportedAlgorithm(cipherAlgo)
        }
    }

    // MARK: - OpenPGP CFB Decryption

    /// OpenPGP CFB decryption (continuous CFB-128, no resync).
    ///
    /// Modern GnuPG uses standard CFB without the legacy "resync after prefix"
    /// shift described in RFC 4880 §13.9. The entire ciphertext is decrypted
    /// as one continuous CFB-128 stream:
    ///   1. IV = zero block
    ///   2. Decrypt all bytes sequentially in 16-byte blocks
    ///   3. Feedback register = previous ciphertext block (standard CFB)
    ///
    /// The first bs+2 bytes of plaintext are the prefix (bs random bytes
    /// followed by copies of the last two random bytes for a quick check).
    private static func openPGPCFBDecrypt(
        ciphertext: [UInt8],
        key: [UInt8],
        algorithmID: UInt8
    ) throws -> [UInt8] {

        let bs = try cipherBlockSize(for: algorithmID)
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)

        // Continuous CFB-128: decrypt the entire ciphertext as one stream
        var feedback = [UInt8](repeating: 0, count: bs)  // IV = all zeros
        var offset = 0

        while offset < ciphertext.count {
            let keystream = try aesECBBlock(input: feedback, key: key)
            let blockEnd = min(offset + bs, ciphertext.count)

            for i in offset..<blockEnd {
                plaintext[i] = ciphertext[i] ^ keystream[i - offset]
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

        return plaintext
    }

    // MARK: - Literal Data Parsing

    /// Parse a literal data packet body to extract the payload
    private static func parseLiteralData(body: [UInt8]) -> [UInt8] {
        guard body.count > 1 else { return body }

        var off = 0
        // Format byte
        off += 1

        // Filename length + filename
        guard off < body.count else { return [] }
        let filenameLen = Int(body[off]); off += 1
        off += filenameLen

        // Date (4 bytes)
        guard off + 4 <= body.count else { return [] }
        off += 4

        // Rest is the literal data
        return Array(body[off...])
    }

    // MARK: - ZLIB / DEFLATE Decompression

    /// Decompress data using zlib (RFC 1950) or raw deflate (RFC 1951).
    ///
    /// - Parameters:
    ///   - data: Compressed bytes
    ///   - rawDeflate: If true, treat as raw DEFLATE (no zlib header). If false, treat as ZLIB.
    /// - Returns: Decompressed bytes
    private static func zlibDecompress(_ data: [UInt8], rawDeflate: Bool) throws -> [UInt8] {
        // Use the zlib C API via CommonCrypto / libz (always available on Apple platforms)
        var stream = z_stream()
        stream.next_in = UnsafeMutablePointer<UInt8>(mutating: data)
        stream.avail_in = uInt(data.count)

        // windowBits: negative = raw deflate, positive = zlib header
        // -15 for raw DEFLATE (ZIP), 15 for ZLIB, 15+32 for auto-detect
        let windowBits: Int32 = rawDeflate ? -15 : 15

        var status = inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard status == Z_OK else {
            throw PacketParserError.decompressionFailed("inflateInit2 failed: \(status)")
        }
        defer { inflateEnd(&stream) }

        var result = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 65536)

        repeat {
            stream.next_out = UnsafeMutablePointer<UInt8>(mutating: &buffer)
            stream.avail_out = uInt(buffer.count)

            status = inflate(&stream, Z_NO_FLUSH)
            guard status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR else {
                throw PacketParserError.decompressionFailed("inflate failed: \(status)")
            }

            let outputCount = buffer.count - Int(stream.avail_out)
            result.append(contentsOf: buffer[0..<outputCount])
        } while status != Z_STREAM_END

        return result
    }

    // MARK: - Helpers

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
            throw PacketParserError.decryptionFailed("AES-ECB failed: status \(status)")
        }
        return Array(output[0..<16])
    }

    private static func cipherBlockSize(for algorithmID: UInt8) throws -> Int {
        switch algorithmID {
        case 7, 8, 9: return 16
        default: throw PacketParserError.unsupportedAlgorithm(algorithmID)
        }
    }

    // MARK: - Dearmor

    /// Strip ASCII armor from an OpenPGP message, returning raw bytes
    static func dearmor(_ armoredText: String) throws -> Data {
        let lines = armoredText.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inBody = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("-----BEGIN") {
                inBody = false
                continue
            }
            if trimmed.hasPrefix("-----END") {
                break
            }
            if trimmed.isEmpty {
                if !inBody { inBody = true }
                continue
            }
            if inBody {
                // CRC line: starts with '=' and is exactly 5 chars (= + 4 base64 chars = 3 bytes)
                // A regular base64 line can END with '=' padding but won't START with it
                // unless it's the CRC. CRC is always =XXXX (5 chars exactly).
                if trimmed.count <= 5 && trimmed.hasPrefix("=") {
                    // This is the CRC — skip it and stop collecting
                    continue
                }
                // Skip any non-base64 content (headers like "Version: GnuPG v2")
                if trimmed.contains(": ") {
                    continue
                }
                base64Lines.append(trimmed)
            }
        }

        let base64String = base64Lines.joined()
        
        // Clean any stray whitespace from the base64 string
        let cleaned = base64String.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
            .replacingOccurrences(of: "\r", with: "")
        
        pgpDebugLog("DEBUG dearmor: \(base64Lines.count) base64 lines, joined length=\(base64String.count), cleaned length=\(cleaned.count)")
        for (i, line) in base64Lines.enumerated() {
            pgpDebugLog("DEBUG dearmor: line[\(i)] = '\(line)' (\(line.count) chars)")
        }
        
        guard let data = Data(base64Encoded: cleaned) else {
            throw PacketParserError.invalidPacket("Failed to decode base64 armor")
        }
        return data
    }

    // =========================================================================
    // MARK: - RFC 9580 v6 Public Key Parsing (Phase A)
    // =========================================================================

    /// Parse a public key or public subkey packet body (tag 6 or tag 14).
    /// Supports both RFC 4880 v4 and RFC 9580 v6 formats.
    ///
    /// V4 layout: version(1) | creation_time(4) | algorithm(1) | key_material(MPIs...)
    /// V6 layout: version(1) | creation_time(4) | algorithm(1) | key_material_length(4) | key_material(...)
    ///
    /// - Parameter body: Raw packet body bytes
    /// - Returns: Parsed public key info with version-aware fingerprint and key ID
    static func parsePublicKeyFields(body: [UInt8]) throws -> ParsedPublicKeyInfo {
        guard body.count >= 6 else {
            throw PacketParserError.invalidPacket("Public key packet too short (\(body.count) bytes)")
        }

        let version = body[0]

        switch version {
        case 4:
            return try parseV4PublicKeyFields(body: body)
        case 6:
            return try parseV6PublicKeyFields(body: body)
        default:
            throw PacketParserError.unsupportedKeyVersion(version)
        }
    }

    // MARK: - V4 Public Key Parsing

    /// Parse a v4 (RFC 4880) public key packet body.
    /// Layout: version(1)=4 | creation_time(4) | algorithm(1) | key_material(MPIs...)
    private static func parseV4PublicKeyFields(body: [UInt8]) throws -> ParsedPublicKeyInfo {
        var off = 0

        // Version byte (already validated as 4)
        let version = body[off]; off += 1

        // Creation time (4 bytes, big-endian)
        guard off + 4 <= body.count else {
            throw PacketParserError.invalidPacket("V4 public key: truncated creation time")
        }
        let creationTime = UInt32(body[off]) << 24 | UInt32(body[off+1]) << 16 |
                           UInt32(body[off+2]) << 8 | UInt32(body[off+3])
        off += 4

        // Algorithm byte
        guard off < body.count else {
            throw PacketParserError.invalidPacket("V4 public key: missing algorithm byte")
        }
        let algorithm = body[off]; off += 1

        // Key material = everything from here to end of body
        let keyMaterial = Array(body[off...])

        // V4 fingerprint: SHA-1( 0x99 | 2-byte body length | full body )
        let fingerprint = computeV4Fingerprint(packetBody: body)

        // V4 Key ID: last 8 bytes of fingerprint
        let keyID = Array(fingerprint.suffix(8))

        pgpDebugLog("DEBUG V4 PubKey: algo=\(algorithm), creation=\(creationTime), fp=\(fingerprint.map { String(format: "%02x", $0) }.joined()), keyID=\(keyID.map { String(format: "%02x", $0) }.joined())")

        return ParsedPublicKeyInfo(
            version: version,
            creationTime: creationTime,
            algorithm: algorithm,
            keyMaterial: keyMaterial,
            fingerprint: fingerprint,
            keyID: keyID
        )
    }

    // MARK: - V6 Public Key Parsing

    /// Parse a v6 (RFC 9580) public key packet body.
    /// Layout: version(1)=6 | creation_time(4) | algorithm(1) | key_material_length(4) | key_material(...)
    ///
    /// New algorithm IDs use raw fixed-length bytes (no MPI wrapping, no OID prefix):
    ///   25 = X25519 (32 bytes)
    ///   26 = X448 (56 bytes)
    ///   27 = Ed25519 (32 bytes)
    ///   28 = Ed448 (57 bytes)
    private static func parseV6PublicKeyFields(body: [UInt8]) throws -> ParsedPublicKeyInfo {
        var off = 0

        // Version byte (already validated as 6)
        let version = body[off]; off += 1

        // Creation time (4 bytes, big-endian)
        guard off + 4 <= body.count else {
            throw PacketParserError.invalidPacket("V6 public key: truncated creation time")
        }
        let creationTime = UInt32(body[off]) << 24 | UInt32(body[off+1]) << 16 |
                           UInt32(body[off+2]) << 8 | UInt32(body[off+3])
        off += 4

        // Algorithm byte
        guard off < body.count else {
            throw PacketParserError.invalidPacket("V6 public key: missing algorithm byte")
        }
        let algorithm = body[off]; off += 1

        // Key material length (4 bytes, big-endian) — NEW in v6
        guard off + 4 <= body.count else {
            throw PacketParserError.invalidPacket("V6 public key: truncated key material length")
        }
        let keyMaterialLength = Int(body[off]) << 24 | Int(body[off+1]) << 16 |
                                Int(body[off+2]) << 8 | Int(body[off+3])
        off += 4

        // Key material (exactly keyMaterialLength bytes)
        guard off + keyMaterialLength <= body.count else {
            throw PacketParserError.invalidPacket("V6 public key: key material truncated (expected \(keyMaterialLength) bytes, have \(body.count - off))")
        }
        let keyMaterial = Array(body[off..<(off + keyMaterialLength)])

        // Validate key material length for known v6 algorithms
        try validateV6KeyMaterial(algorithm: algorithm, keyMaterial: keyMaterial)

        // V6 fingerprint: SHA-256( 0x9B | 4-byte body length | full body )
        let fingerprint = computeV6Fingerprint(packetBody: body)

        // V6 Key ID: FIRST 8 bytes of fingerprint (opposite of v4)
        let keyID = Array(fingerprint.prefix(8))

        pgpDebugLog("DEBUG V6 PubKey: algo=\(algorithm) (\(algorithmName(algorithm))), creation=\(creationTime), keyMatLen=\(keyMaterialLength), fp=\(fingerprint.map { String(format: "%02x", $0) }.joined()), keyID=\(keyID.map { String(format: "%02x", $0) }.joined())")

        return ParsedPublicKeyInfo(
            version: version,
            creationTime: creationTime,
            algorithm: algorithm,
            keyMaterial: keyMaterial,
            fingerprint: fingerprint,
            keyID: keyID
        )
    }

    // MARK: - V6 Key Material Validation

    /// Validate that the key material length matches what we expect for the given
    /// algorithm. RFC 9580 §9.1 algorithms 25-28 use fixed-length native key bytes.
    private static func validateV6KeyMaterial(algorithm: UInt8, keyMaterial: [UInt8]) throws {
        let expectedLength: Int?
        switch algorithm {
        case 25: expectedLength = 32   // X25519: 32-byte public key
        case 26: expectedLength = 56   // X448: 56-byte public key
        case 27: expectedLength = 32   // Ed25519: 32-byte public key
        case 28: expectedLength = 57   // Ed448: 57-byte public key
        // Legacy algorithms (RSA, DSA, EdDSA/22, ECDH/18, etc.) use MPI/OID formats
        // with variable lengths — don't validate those here.
        default: expectedLength = nil
        }

        if let expected = expectedLength {
            guard keyMaterial.count == expected else {
                throw PacketParserError.invalidPacket(
                    "V6 key material for algo \(algorithm): expected \(expected) bytes, got \(keyMaterial.count)"
                )
            }
        }
    }

    // MARK: - Fingerprint Computation

    /// Compute a v4 fingerprint: SHA-1( 0x99 | 2-byte body length | body )
    /// Returns 20 bytes.
    static func computeV4Fingerprint(packetBody: [UInt8]) -> [UInt8] {
        let bodyLen = packetBody.count
        var hashInput = [UInt8]()
        hashInput.append(0x99)                              // v4 prefix
        hashInput.append(UInt8((bodyLen >> 8) & 0xFF))      // 2-byte length, big-endian
        hashInput.append(UInt8(bodyLen & 0xFF))
        hashInput.append(contentsOf: packetBody)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(hashInput, CC_LONG(hashInput.count), &hash)
        return hash
    }

    /// Extract the PUBLIC prefix of a v4 secret-key (tag 5) or secret-subkey
    /// (tag 7) packet body — i.e. everything up to but not including the S2K
    /// usage octet. This is the byte string that a v4 *public* key packet would
    /// contain, so it can be fed to `computeV4Fingerprint` and used to build the
    /// public half of an imported secret key.
    ///
    /// Layout: version(1)=4 | creation_time(4) | algo(1) | public key material.
    /// The public material is algorithm-specific (MPIs / OID + point / KDF).
    /// Returns nil if the body isn't a parseable v4 secret key.
    static func v4PublicPrefix(secretBody body: [UInt8]) -> [UInt8]? {
        guard body.count >= 6, body[0] == 4 else { return nil }
        let algo = body[5]
        var off = 6  // version(1) + creation_time(4) + algo(1)

        // Advance past one MPI (2-octet bit length, big-endian, then ceil(bits/8) octets)
        func skipMPI() -> Bool {
            guard off + 2 <= body.count else { return false }
            let bits = Int(body[off]) << 8 | Int(body[off + 1])
            let bytes = (bits + 7) / 8
            off += 2 + bytes
            return off <= body.count
        }
        // Advance past a 1-octet-length-prefixed field (curve OID, KDF params)
        func skipLenPrefixed() -> Bool {
            guard off < body.count else { return false }
            let n = Int(body[off]); off += 1
            guard n != 0 && n != 0xFF else { return false }  // 0/0xFF are reserved sentinels
            off += n
            return off <= body.count
        }

        switch algo {
        case 1, 2, 3:                       // RSA: n, e
            guard skipMPI(), skipMPI() else { return nil }
        case 16:                            // Elgamal: p, g, y
            guard skipMPI(), skipMPI(), skipMPI() else { return nil }
        case 17:                            // DSA: p, q, g, y
            guard skipMPI(), skipMPI(), skipMPI(), skipMPI() else { return nil }
        case 19, 22:                        // ECDSA / EdDSALegacy: OID, point MPI
            guard skipLenPrefixed(), skipMPI() else { return nil }
        case 18:                            // ECDH: OID, point MPI, KDF params
            guard skipLenPrefixed(), skipMPI(), skipLenPrefixed() else { return nil }
        default:
            return nil
        }
        guard off <= body.count else { return nil }
        return Array(body[0..<off])
    }

    /// Compute a v6 fingerprint: SHA-256( 0x9B | 4-byte body length | body )
    /// Returns 32 bytes.
    ///
    /// Per RFC 9580 §5.5.4:
    ///   "A v6 fingerprint is the 256-bit SHA2-256 hash of the octet 0x9B,
    ///    followed by a four-octet scalar octet count of the key packet body,
    ///    followed by the key packet body."
    static func computeV6Fingerprint(packetBody: [UInt8]) -> [UInt8] {
        let bodyLen = packetBody.count
        var hashInput = [UInt8]()
        hashInput.append(0x9B)                              // v6 prefix
        hashInput.append(UInt8((bodyLen >> 24) & 0xFF))     // 4-byte length, big-endian
        hashInput.append(UInt8((bodyLen >> 16) & 0xFF))
        hashInput.append(UInt8((bodyLen >> 8) & 0xFF))
        hashInput.append(UInt8(bodyLen & 0xFF))
        hashInput.append(contentsOf: packetBody)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(hashInput, CC_LONG(hashInput.count), &hash)
        return hash
    }

    // MARK: - Key Packet Utilities

    /// Extract key version from a key packet body (first byte).
    /// Useful for quick dispatch without full parsing.
    static func keyVersion(from packetBody: [UInt8]) -> UInt8? {
        guard !packetBody.isEmpty else { return nil }
        return packetBody[0]
    }

    /// Returns the expected native key material length for RFC 9580 v6 algorithm IDs.
    /// Returns nil for legacy algorithms that use MPI/OID encoding.
    static func v6NativeKeyLength(for algorithm: UInt8) -> Int? {
        switch algorithm {
        case 25: return 32   // X25519
        case 26: return 56   // X448
        case 27: return 32   // Ed25519
        case 28: return 57   // Ed448
        default: return nil
        }
    }

    /// Human-readable algorithm name for logging/debug.
    static func algorithmName(_ algorithm: UInt8) -> String {
        switch algorithm {
        case 1, 2, 3:   return "RSA"
        case 16:         return "Elgamal"
        case 17:         return "DSA"
        case 18:         return "ECDH"
        case 19:         return "ECDSA"
        case 22:         return "EdDSA (Legacy)"
        case 25:         return "X25519"
        case 26:         return "X448"
        case 27:         return "Ed25519"
        case 28:         return "Ed448"
        default:         return "Unknown(\(algorithm))"
        }
    }

    /// Parse ALL public key and public subkey packets from raw key data.
    /// Returns an array of ParsedPublicKeyInfo — the first element is always
    /// the primary key (tag 6), followed by subkeys (tag 14).
    ///
    /// Works for both v4 and v6 keys. Useful for key import where you need to
    /// inspect the primary key algorithm, subkey algorithms, and all fingerprints.
    static func parseAllPublicKeys(from data: [UInt8]) throws -> [ParsedPublicKeyInfo] {
        let packets = try parsePackets(data: data)
        var results: [ParsedPublicKeyInfo] = []

        for packet in packets {
            switch packet.tag {
            case 6, 14:
                // Tag 6 = Public-Key, Tag 14 = Public-Subkey
                do {
                    let info = try parsePublicKeyFields(body: packet.body)
                    results.append(info)
                    pgpDebugLog("DEBUG parseAllPublicKeys: tag=\(packet.tag), version=\(info.version), algo=\(info.algorithmName), fp=\(info.fingerprintHex)")
                } catch {
                    pgpDebugLog("DEBUG parseAllPublicKeys: failed to parse tag \(packet.tag): \(error)")
                    // Continue — don't fail the whole import for one bad subkey
                }
            default:
                continue
            }
        }

        return results
    }

    /// Convenience: detect the key version of the primary key in raw key data.
    /// Inspects the first tag-6 (Public-Key) or tag-5 (Secret-Key) packet.
    static func detectKeyVersion(from data: [UInt8]) throws -> UInt8 {
        let packets = try parsePackets(data: data)
        for packet in packets {
            if packet.tag == 6 || packet.tag == 5 {
                guard !packet.body.isEmpty else { continue }
                return packet.body[0]
            }
        }
        throw PacketParserError.invalidPacket("No key packet (tag 5 or 6) found")
    }

    // =========================================================================
    // MARK: - RFC 9580 v6 Signature Parsing (Phase C)
    // =========================================================================

    // MARK: - Parsed Signature Types

    /// A parsed signature subpacket.
    struct ParsedSubpacket {
        let type: UInt8
        let isCritical: Bool
        let data: [UInt8]
    }

    /// Parsed OpenPGP signature packet (tag 2). Supports both v4 and v6.
    struct ParsedSignature {
        let version: UInt8              // 4 or 6
        let signatureType: UInt8        // 0x00 = binary, 0x01 = text, 0x13 = certification, etc.
        let publicKeyAlgorithm: UInt8   // 22 = EdDSA (v4), 27 = Ed25519 (v6), 1 = RSA, etc.
        let hashAlgorithm: UInt8        // 8 = SHA-256, 10 = SHA-512, etc.
        let hashedSubpackets: [ParsedSubpacket]
        let unhashedSubpackets: [ParsedSubpacket]
        let hashPrefix: [UInt8]         // 2-byte left hash prefix for quick check

        // V6-specific fields
        let salt: [UInt8]               // V6 signature salt (typically 16 bytes for Ed25519); empty for v4

        // Signature data (raw bytes after hash prefix + optional salt)
        let signatureData: [UInt8]      // For EdDSA: two MPIs (R, S). For v6 Ed25519: raw 64 bytes.

        // Raw hashed portion (for verification: needed to reconstruct the hash input)
        let rawHashedPortion: [UInt8]   // version || sigType || algo || hashAlgo || hashedSubpackets area

        /// Whether this is a v6 signature
        var isV6: Bool { version == 6 }

        /// Extract the issuer key ID from subpackets.
        /// Checks unhashed Issuer Key ID (type 16) first, then hashed Issuer Fingerprint (type 33).
        var issuerKeyID: [UInt8]? {
            // Type 16: Issuer Key ID (8 bytes)
            for sp in unhashedSubpackets + hashedSubpackets {
                if sp.type == 16 && sp.data.count == 8 {
                    return sp.data
                }
            }
            // Type 33: Issuer Fingerprint — extract key ID from fingerprint
            for sp in hashedSubpackets + unhashedSubpackets {
                if sp.type == 33 && sp.data.count >= 5 {
                    let fpVersion = sp.data[0]
                    let fpBytes = Array(sp.data[1...])
                    if fpVersion == 4 && fpBytes.count >= 20 {
                        return Array(fpBytes.suffix(8))  // V4: last 8 bytes
                    } else if fpVersion == 6 && fpBytes.count >= 32 {
                        return Array(fpBytes.prefix(8))  // V6: first 8 bytes
                    }
                }
            }
            return nil
        }

        /// Extract the issuer fingerprint from subpackets (type 33).
        var issuerFingerprint: [UInt8]? {
            for sp in hashedSubpackets + unhashedSubpackets {
                if sp.type == 33 && sp.data.count >= 5 {
                    return Array(sp.data[1...])  // Skip the version byte
                }
            }
            return nil
        }

        /// Signature creation time (subpacket type 2).
        var creationTime: Date? {
            for sp in hashedSubpackets {
                if sp.type == 2 && sp.data.count == 4 {
                    let timestamp = UInt32(sp.data[0]) << 24 | UInt32(sp.data[1]) << 16 |
                                    UInt32(sp.data[2]) << 8 | UInt32(sp.data[3])
                    return Date(timeIntervalSince1970: TimeInterval(timestamp))
                }
            }
            return nil
        }

        /// Algorithm display name
        var algorithmName: String {
            OpenPGPPacketParser.algorithmName(publicKeyAlgorithm)
        }

        /// Hash algorithm display name
        var hashAlgorithmName: String {
            switch hashAlgorithm {
            case 2:  return "SHA-1"
            case 8:  return "SHA-256"
            case 9:  return "SHA-384"
            case 10: return "SHA-512"
            case 11: return "SHA-224"
            default: return "Unknown(\(hashAlgorithm))"
            }
        }
    }

    // MARK: - Signature Packet Parsing

    /// Parse a signature packet (tag 2) body. Supports both v4 and v6.
    ///
    /// V4 layout (RFC 4880 §5.2.3):
    ///   version(1)=4 | sigType(1) | pubAlgo(1) | hashAlgo(1) |
    ///   hashedSubpacketsLen(2) | hashedSubpackets |
    ///   unhashedSubpacketsLen(2) | unhashedSubpackets |
    ///   hashPrefix(2) | signature MPIs
    ///
    /// V6 layout (RFC 9580 §5.2.3):
    ///   version(1)=6 | sigType(1) | pubAlgo(1) | hashAlgo(1) |
    ///   hashedSubpacketsLen(4) | hashedSubpackets |        ← 4 bytes, not 2
    ///   unhashedSubpacketsLen(4) | unhashedSubpackets |    ← 4 bytes, not 2
    ///   hashPrefix(2) |
    ///   saltLen(1) | salt(saltLen) |                        ← NEW in v6
    ///   signature data
    static func parseSignaturePacket(body: [UInt8]) throws -> ParsedSignature {
        guard body.count >= 4 else {
            throw PacketParserError.invalidPacket("Signature packet too short (\(body.count) bytes)")
        }

        let version = body[0]
        switch version {
        case 4:
            return try parseV4SignaturePacket(body: body)
        case 6:
            return try parseV6SignaturePacket(body: body)
        default:
            throw PacketParserError.unsupportedPacketVersion(version)
        }
    }

    // MARK: - V4 Signature Parsing

    private static func parseV4SignaturePacket(body: [UInt8]) throws -> ParsedSignature {
        var off = 0

        let version = body[off]; off += 1  // = 4
        let sigType = body[off]; off += 1
        let pubAlgo = body[off]; off += 1
        let hashAlgo = body[off]; off += 1

        // Save the start of the hashed portion for verification
        let hashedPortionStart = 0

        // Hashed subpackets length (2 bytes for v4)
        guard off + 2 <= body.count else {
            throw PacketParserError.invalidPacket("V4 signature: truncated hashed subpackets length")
        }
        let hashedLen = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        guard off + hashedLen <= body.count else {
            throw PacketParserError.invalidPacket("V4 signature: hashed subpackets truncated")
        }
        let hashedSubpacketBytes = Array(body[off..<(off + hashedLen)]); off += hashedLen

        // Raw hashed portion = everything from version through end of hashed subpackets
        let rawHashedPortion = Array(body[hashedPortionStart..<off])

        // Unhashed subpackets length (2 bytes for v4)
        guard off + 2 <= body.count else {
            throw PacketParserError.invalidPacket("V4 signature: truncated unhashed subpackets length")
        }
        let unhashedLen = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        guard off + unhashedLen <= body.count else {
            throw PacketParserError.invalidPacket("V4 signature: unhashed subpackets truncated")
        }
        let unhashedSubpacketBytes = Array(body[off..<(off + unhashedLen)]); off += unhashedLen

        // Hash prefix (2 bytes)
        guard off + 2 <= body.count else {
            throw PacketParserError.invalidPacket("V4 signature: missing hash prefix")
        }
        let hashPrefix = Array(body[off..<(off + 2)]); off += 2

        // Signature data (rest of packet)
        let signatureData = Array(body[off...])

        // Parse subpackets
        let hashedSPs = parseSubpackets(data: hashedSubpacketBytes)
        let unhashedSPs = parseSubpackets(data: unhashedSubpacketBytes)

        pgpDebugLog("DEBUG V4 Sig: type=0x\(String(format: "%02x", sigType)), algo=\(pubAlgo), hash=\(hashAlgo), hashedSPs=\(hashedSPs.count), unhashedSPs=\(unhashedSPs.count)")

        return ParsedSignature(
            version: version,
            signatureType: sigType,
            publicKeyAlgorithm: pubAlgo,
            hashAlgorithm: hashAlgo,
            hashedSubpackets: hashedSPs,
            unhashedSubpackets: unhashedSPs,
            hashPrefix: hashPrefix,
            salt: [],
            signatureData: signatureData,
            rawHashedPortion: rawHashedPortion
        )
    }

    // MARK: - V6 Signature Parsing

    private static func parseV6SignaturePacket(body: [UInt8]) throws -> ParsedSignature {
        var off = 0

        let version = body[off]; off += 1  // = 6
        let sigType = body[off]; off += 1
        let pubAlgo = body[off]; off += 1
        let hashAlgo = body[off]; off += 1

        let hashedPortionStart = 0

        // Hashed subpackets length (4 bytes for v6)
        guard off + 4 <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: truncated hashed subpackets length")
        }
        let hashedLen = Int(body[off]) << 24 | Int(body[off+1]) << 16 |
                        Int(body[off+2]) << 8 | Int(body[off+3])
        off += 4
        guard off + hashedLen <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: hashed subpackets truncated (expected \(hashedLen), have \(body.count - off))")
        }
        let hashedSubpacketBytes = Array(body[off..<(off + hashedLen)]); off += hashedLen

        let rawHashedPortion = Array(body[hashedPortionStart..<off])

        // Unhashed subpackets length (4 bytes for v6)
        guard off + 4 <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: truncated unhashed subpackets length")
        }
        let unhashedLen = Int(body[off]) << 24 | Int(body[off+1]) << 16 |
                          Int(body[off+2]) << 8 | Int(body[off+3])
        off += 4
        guard off + unhashedLen <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: unhashed subpackets truncated")
        }
        let unhashedSubpacketBytes = Array(body[off..<(off + unhashedLen)]); off += unhashedLen

        // Hash prefix (2 bytes)
        guard off + 2 <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: missing hash prefix")
        }
        let hashPrefix = Array(body[off..<(off + 2)]); off += 2

        // V6 salt field (NEW): 1-byte length + salt bytes
        guard off < body.count else {
            throw PacketParserError.invalidPacket("V6 signature: missing salt length")
        }
        let saltLen = Int(body[off]); off += 1
        guard off + saltLen <= body.count else {
            throw PacketParserError.invalidPacket("V6 signature: salt truncated (expected \(saltLen) bytes)")
        }
        let salt = Array(body[off..<(off + saltLen)]); off += saltLen

        // Signature data (rest of packet)
        let signatureData = (off < body.count) ? Array(body[off...]) : []

        // Parse subpackets
        let hashedSPs = parseSubpackets(data: hashedSubpacketBytes)
        let unhashedSPs = parseSubpackets(data: unhashedSubpacketBytes)

        pgpDebugLog("DEBUG V6 Sig: type=0x\(String(format: "%02x", sigType)), algo=\(pubAlgo), hash=\(hashAlgo), saltLen=\(saltLen), hashedSPs=\(hashedSPs.count), unhashedSPs=\(unhashedSPs.count), sigDataLen=\(signatureData.count)")

        return ParsedSignature(
            version: version,
            signatureType: sigType,
            publicKeyAlgorithm: pubAlgo,
            hashAlgorithm: hashAlgo,
            hashedSubpackets: hashedSPs,
            unhashedSubpackets: unhashedSPs,
            hashPrefix: hashPrefix,
            salt: salt,
            signatureData: signatureData,
            rawHashedPortion: rawHashedPortion
        )
    }

    // MARK: - Subpacket Parsing

    /// Parse a stream of signature subpackets.
    /// Subpacket format: length(variable) | type(1) | data
    /// Length encoding: same as new-format packet lengths (1, 2, or 5 bytes).
    static func parseSubpackets(data: [UInt8]) -> [ParsedSubpacket] {
        var subpackets: [ParsedSubpacket] = []
        var off = 0

        while off < data.count {
            // Parse subpacket length (same encoding as new-format packet body lengths)
            let first = data[off]; off += 1
            let totalLen: Int

            if first < 192 {
                totalLen = Int(first)
            } else if first < 255 {
                guard off < data.count else { break }
                let second = data[off]; off += 1
                totalLen = (Int(first) - 192) * 256 + Int(second) + 192
            } else {
                // 5-byte length
                guard off + 4 <= data.count else { break }
                totalLen = Int(data[off]) << 24 | Int(data[off+1]) << 16 |
                           Int(data[off+2]) << 8 | Int(data[off+3])
                off += 4
            }

            guard totalLen >= 1, off + totalLen - 1 <= data.count else { break }

            // Type byte (bit 7 = critical flag)
            let typeByte = data[off]; off += 1
            let isCritical = (typeByte & 0x80) != 0
            let subpacketType = typeByte & 0x7F

            // Data = remaining bytes
            let dataLen = totalLen - 1  // -1 for type byte
            let subpacketData: [UInt8]
            if dataLen > 0 && off + dataLen <= data.count {
                subpacketData = Array(data[off..<(off + dataLen)])
                off += dataLen
            } else {
                subpacketData = []
                off += max(0, dataLen)
            }

            subpackets.append(ParsedSubpacket(
                type: subpacketType,
                isCritical: isCritical,
                data: subpacketData
            ))
        }

        return subpackets
    }

    // MARK: - Signature Extraction

    /// Parse ALL signature packets (tag 2) from raw data.
    /// Useful for extracting binding signatures, certification signatures, etc.
    static func parseAllSignatures(from data: [UInt8]) throws -> [ParsedSignature] {
        let packets = try parsePackets(data: data)
        var signatures: [ParsedSignature] = []

        for packet in packets where packet.tag == 2 {
            do {
                let sig = try parseSignaturePacket(body: packet.body)
                signatures.append(sig)
            } catch {
                pgpDebugLog("DEBUG parseAllSignatures: failed to parse sig: \(error)")
            }
        }

        return signatures
    }

    // MARK: - Ed25519 Signature Verification

    /// Verify an Ed25519 signature (v4 or v6) against a document.
    ///
    /// For v4 (algo 22, EdDSA): signature data is two MPIs (R, S).
    /// For v6 (algo 27, Ed25519): signature data is raw 64 bytes (no MPI wrapping).
    ///
    /// The hash input is constructed as:
    ///   V4: document || rawHashedPortion || 0x04 0xFF <4-byte hashed length>
    ///   V6: salt || document || rawHashedPortion || 0x06 0xFF <8-byte hashed length>
    ///
    /// - Parameters:
    ///   - signature: Parsed signature packet
    ///   - document: The signed document data
    ///   - publicKey: 32-byte Ed25519 public key
    /// - Returns: true if signature is valid
    static func verifyEd25519Signature(
        signature: ParsedSignature,
        document: [UInt8],
        publicKey: [UInt8]
    ) throws -> Bool {
        guard publicKey.count == 32 else {
            throw PacketParserError.invalidPacket("Ed25519 public key must be 32 bytes")
        }

        // Extract the raw 64-byte Ed25519 signature
        let sigBytes: [UInt8]
        if signature.version == 6 && signature.publicKeyAlgorithm == 27 {
            // V6 Ed25519: raw 64 bytes (no MPI wrapping)
            guard signature.signatureData.count == 64 else {
                throw PacketParserError.invalidPacket("V6 Ed25519 signature must be 64 bytes, got \(signature.signatureData.count)")
            }
            sigBytes = signature.signatureData
        } else if signature.publicKeyAlgorithm == 22 {
            // V4 EdDSA: two MPIs (R and S)
            sigBytes = try extractEdDSAMPIs(from: signature.signatureData)
        } else {
            throw PacketParserError.unsupportedAlgorithm(signature.publicKeyAlgorithm)
        }

        // Build hash input
        var hashInput = Data()

        if signature.version == 6 {
            // V6: salt || document || rawHashedPortion || trailer
            hashInput.append(contentsOf: signature.salt)
        }

        hashInput.append(contentsOf: document)
        hashInput.append(contentsOf: signature.rawHashedPortion)

        // Trailer
        if signature.version == 6 {
            // V6 trailer: 0x06 0xFF <4-byte hashed length> (RFC 9580 §5.2.4 —
            // four octets for v4 and v6; the 8-octet form was v5).
            let hashedLen = UInt32(signature.rawHashedPortion.count)
            hashInput.append(0x06)
            hashInput.append(0xFF)
            hashInput.append(UInt8((hashedLen >> 24) & 0xFF))
            hashInput.append(UInt8((hashedLen >> 16) & 0xFF))
            hashInput.append(UInt8((hashedLen >>  8) & 0xFF))
            hashInput.append(UInt8( hashedLen        & 0xFF))
        } else {
            // V4 trailer: 0x04 0xFF <4-byte hashed length>
            let hashedLen = UInt32(signature.rawHashedPortion.count)
            hashInput.append(0x04)
            hashInput.append(0xFF)
            hashInput.append(UInt8((hashedLen >> 24) & 0xFF))
            hashInput.append(UInt8((hashedLen >> 16) & 0xFF))
            hashInput.append(UInt8((hashedLen >> 8) & 0xFF))
            hashInput.append(UInt8(hashedLen & 0xFF))
        }

        // Hash with the specified algorithm
        let digestBytes: [UInt8]
        switch signature.hashAlgorithm {
        case 8:  // SHA-256
            let digest = SHA256.hash(data: hashInput)
            digestBytes = Array(digest)
        case 10: // SHA-512
            let digest = SHA512.hash(data: hashInput)
            digestBytes = Array(digest)
        default:
            throw PacketParserError.unsupportedAlgorithm(signature.hashAlgorithm)
        }

        // ---- DIAGNOSTIC (TEMP, Phase 2b debug) ----
        if signature.version == 6 {
            let hashInputArr = Array(hashInput)
            pgpDebugLog("DEBUG V6 Verify: doc=\(document.count)B salt=\(signature.salt.count)B rawHashed=\(signature.rawHashedPortion.count)B hashInput total=\(hashInputArr.count)B")
            let dumpRange = min(64, hashInputArr.count)
            let hexPrefix = hashInputArr.prefix(dumpRange).map { String(format: "%02x", $0) }.joined(separator: " ")
            let hexSuffix = hashInputArr.suffix(min(48, hashInputArr.count)).map { String(format: "%02x", $0) }.joined(separator: " ")
            pgpDebugLog("DEBUG V6 Verify: hashInput[0..\(dumpRange)] = \(hexPrefix)")
            pgpDebugLog("DEBUG V6 Verify: hashInput[last 48] = \(hexSuffix)")
            pgpDebugLog("DEBUG V6 Verify: SHA-256 digest = \(digestBytes.map { String(format: "%02x", $0) }.joined())")
        }
        // ---- END DIAGNOSTIC ----

        // Quick check: first 2 bytes of hash should match hashPrefix
        guard digestBytes[0] == signature.hashPrefix[0] &&
              digestBytes[1] == signature.hashPrefix[1] else {
            pgpDebugLog("DEBUG Ed25519 Verify: hash prefix mismatch — computed \(String(format: "%02x%02x", digestBytes[0], digestBytes[1])) vs stored \(String(format: "%02x%02x", signature.hashPrefix[0], signature.hashPrefix[1]))")
            return false
        }

        // Verify with CryptoKit
        // OpenPGP EdDSA: the signature is over the HASH, not the raw document
        do {
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            let isValid = pubKey.isValidSignature(Data(sigBytes), for: Data(digestBytes))
            pgpDebugLog("DEBUG Ed25519 Verify: \(isValid ? "VALID" : "INVALID") (v\(signature.version), algo=\(signature.publicKeyAlgorithm))")
            return isValid
        } catch {
            pgpDebugLog("DEBUG Ed25519 Verify: CryptoKit error: \(error)")
            return false
        }
    }

    /// Extract R and S from EdDSA MPI-encoded signature data (v4 format).
    /// Returns concatenated 64 bytes (R || S).
    private static func extractEdDSAMPIs(from data: [UInt8]) throws -> [UInt8] {
        var off = 0

        // R MPI
        guard off + 2 <= data.count else {
            throw PacketParserError.invalidPacket("EdDSA sig: missing R MPI header")
        }
        let rBits = Int(data[off]) << 8 | Int(data[off + 1]); off += 2
        let rBytes = (rBits + 7) / 8
        guard off + rBytes <= data.count else {
            throw PacketParserError.invalidPacket("EdDSA sig: R MPI truncated")
        }
        var r = Array(data[off..<(off + rBytes)]); off += rBytes

        // S MPI
        guard off + 2 <= data.count else {
            throw PacketParserError.invalidPacket("EdDSA sig: missing S MPI header")
        }
        let sBits = Int(data[off]) << 8 | Int(data[off + 1]); off += 2
        let sBytes = (sBits + 7) / 8
        guard off + sBytes <= data.count else {
            throw PacketParserError.invalidPacket("EdDSA sig: S MPI truncated")
        }
        var s = Array(data[off..<(off + sBytes)])

        // Pad to 32 bytes each if needed
        while r.count < 32 { r.insert(0, at: 0) }
        while s.count < 32 { s.insert(0, at: 0) }

        // Truncate if somehow longer (shouldn't happen for Ed25519)
        r = Array(r.suffix(32))
        s = Array(s.suffix(32))

        return r + s
    }
}
