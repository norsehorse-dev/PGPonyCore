// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Cv25519ECDHService.swift
// PGPony
//
// Native Cv25519 ECDH encryption/decryption for OpenPGP.
// Implements RFC 6637 §7-8 key derivation and session key wrapping
// using Apple CryptoKit for X25519 key agreement.

import Foundation
import CryptoKit
import CommonCrypto

enum ECDHError: LocalizedError {
    case keyAgreementFailed(String)
    case kdfFailed
    case sessionKeyWrapFailed(String)
    case sessionKeyUnwrapFailed(String)
    case invalidPublicKey
    case invalidEphemeralKey
    case invalidWrappedData
    case unsupportedAlgorithm(UInt8)

    var errorDescription: String? {
        switch self {
        case .keyAgreementFailed(let msg): return "ECDH key agreement failed: \(msg)"
        case .kdfFailed: return "ECDH KDF failed"
        case .sessionKeyWrapFailed(let msg): return "Session key wrap failed: \(msg)"
        case .sessionKeyUnwrapFailed(let msg): return "Session key unwrap failed: \(msg)"
        case .invalidPublicKey: return "Invalid Cv25519 public key"
        case .invalidEphemeralKey: return "Invalid ephemeral key data"
        case .invalidWrappedData: return "Invalid wrapped session key data"
        case .unsupportedAlgorithm(let id): return "Unsupported symmetric algorithm ID: \(id)"
        }
    }
}

// MARK: - ECDH Session Key Result

struct ECDHEncryptedSessionKey {
    let ephemeralPublicKey: [UInt8]   // 33 bytes: 0x40 prefix + 32-byte X25519 public key
    let wrappedSessionKey: [UInt8]    // AES key-wrapped session key
}

// MARK: - Cv25519 ECDH Service

class Cv25519ECDHService {

    // Cv25519 OID: 1.3.6.1.4.1.3029.1.5.1
    static let cv25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]

    // OpenPGP symmetric algorithm IDs
    static let aes128ID: UInt8 = 7
    static let aes192ID: UInt8 = 8
    static let aes256ID: UInt8 = 9

    // OpenPGP hash algorithm IDs
    static let sha256ID: UInt8 = 8

    // MARK: - Encrypt Session Key

    /// Encrypt a session key to a Cv25519 ECDH recipient.
    /// Per RFC 6637 §8:
    ///   1. Generate ephemeral X25519 keypair
    ///   2. Compute shared secret via X25519(ephemeral_private, recipient_public)
    ///   3. Derive KEK via KDF(shared_secret, params)
    ///   4. Wrap session key with AES Key Wrap (RFC 3394)
    ///
    /// - Parameters:
    ///   - sessionKey: The symmetric session key to wrap (e.g., 16 bytes for AES-128)
    ///   - sessionAlgorithmID: OpenPGP algorithm ID for the session cipher (e.g., 7 = AES-128)
    ///   - recipientPublicKey: 32-byte raw Cv25519 public key
    ///   - recipientFingerprint: 20-byte V4 fingerprint of the recipient's encryption subkey
    ///   - kdfHashID: Hash algorithm for KDF (default: SHA-256 = 8)
    ///   - kdfCipherID: Cipher for key wrapping (default: AES-128 = 7)
    static func encryptSessionKey(
        sessionKey: [UInt8],
        sessionAlgorithmID: UInt8,
        recipientPublicKey: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8 = sha256ID,
        kdfCipherID: UInt8 = aes128ID
    ) throws -> ECDHEncryptedSessionKey {

        // 1. Generate ephemeral X25519 keypair
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicBytes = Array(ephemeralKey.publicKey.rawRepresentation)

        // 2. Compute shared secret
        let recipientPubKey: Curve25519.KeyAgreement.PublicKey
        do {
            recipientPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        } catch {
            throw ECDHError.invalidPublicKey
        }

        let sharedSecret: SharedSecret
        do {
            sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientPubKey)
        } catch {
            throw ECDHError.keyAgreementFailed(error.localizedDescription)
        }

        let sharedSecretBytes = sharedSecret.withUnsafeBytes { Array($0) }

        // 3. Derive KEK via RFC 6637 §7 KDF
        let kekSize = try keySize(for: kdfCipherID)
        let kdfParams = buildKDFParams(
            kdfHashID: kdfHashID,
            kdfCipherID: kdfCipherID
        )
        let kek = try deriveKEK(
            sharedSecret: sharedSecretBytes,
            curveOID: Cv25519ECDHService.cv25519OID,
            kdfParams: kdfParams,
            fingerprint: recipientFingerprint,
            keySize: kekSize,
            hashID: kdfHashID
        )

        // 4. Build plaintext for wrapping: algorithm ID + session key + 2-byte checksum
        var wrappingInput: [UInt8] = []
        wrappingInput.append(sessionAlgorithmID)
        wrappingInput.append(contentsOf: sessionKey)
        let checksum = sessionKey.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }
        wrappingInput.append(UInt8((checksum >> 8) & 0xFF))
        wrappingInput.append(UInt8(checksum & 0xFF))

        // Pad to multiple of 8 bytes for AES Key Wrap
        let padded = pkcs5Pad(wrappingInput, blockSize: 8)

        // 5. AES Key Wrap
        let wrapped: [UInt8]
        do {
            wrapped = try AESKeyWrap.wrap(plaintext: padded, kek: kek)
        } catch {
            throw ECDHError.sessionKeyWrapFailed(error.localizedDescription)
        }

        // Ephemeral public key with 0x40 prefix (OpenPGP Cv25519 encoding)
        let ephemeralEncoded: [UInt8] = [0x40] + ephemeralPublicBytes

        return ECDHEncryptedSessionKey(
            ephemeralPublicKey: ephemeralEncoded,
            wrappedSessionKey: wrapped
        )
    }

    // MARK: - Decrypt Session Key

    /// Decrypt a session key from a Cv25519 ECDH PKESK packet.
    ///
    /// - Parameters:
    ///   - ephemeralPublicKey: The ephemeral public key from PKESK (33 bytes: 0x40 + 32)
    ///   - wrappedSessionKey: The AES-wrapped session key data
    ///   - recipientPrivateKey: 32-byte raw Cv25519 private key
    ///   - recipientFingerprint: 20-byte V4 fingerprint of the recipient's encryption subkey
    ///   - kdfHashID: Hash algorithm for KDF (from the recipient's public key KDF params)
    ///   - kdfCipherID: Cipher for key wrapping (from the recipient's public key KDF params)
    /// - Returns: Tuple of (sessionAlgorithmID, sessionKey)
    static func decryptSessionKey(
        ephemeralPublicKey: [UInt8],
        wrappedSessionKey: [UInt8],
        recipientPrivateKey: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8 = sha256ID,
        kdfCipherID: UInt8 = aes128ID
    ) throws -> (algorithmID: UInt8, sessionKey: [UInt8]) {

        // 1. Parse ephemeral public key (strip 0x40 prefix)
        var ephemeralRaw = ephemeralPublicKey
        if ephemeralRaw.first == 0x40 {
            ephemeralRaw = Array(ephemeralRaw.dropFirst())
        }
        guard ephemeralRaw.count == 32 else {
            throw ECDHError.invalidEphemeralKey
        }

        // 2. Compute shared secret
        let privKey: Curve25519.KeyAgreement.PrivateKey
        do {
            privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey)
        } catch {
            throw ECDHError.keyAgreementFailed("Invalid private key: \(error.localizedDescription)")
        }

        let ephPubKey: Curve25519.KeyAgreement.PublicKey
        do {
            ephPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralRaw)
        } catch {
            throw ECDHError.invalidEphemeralKey
        }

        let sharedSecret: SharedSecret
        do {
            sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: ephPubKey)
        } catch {
            throw ECDHError.keyAgreementFailed(error.localizedDescription)
        }

        let sharedSecretBytes = sharedSecret.withUnsafeBytes { Array($0) }

        return try sessionKeyFromSharedSecret(
            sharedSecret: sharedSecretBytes,
            wrappedSessionKey: wrappedSessionKey,
            recipientFingerprint: recipientFingerprint,
            kdfHashID: kdfHashID,
            kdfCipherID: kdfCipherID
        )
    }

    /// Steps 3–5 of session-key recovery, factored out so the hardware-key path
    /// can supply the ECDH shared secret from the card (PSO:DECIPHER) and reuse
    /// the identical RFC 6637 KDF + AES key-unwrap + checksum logic. `sharedSecret`
    /// is the 32-byte X coordinate of the ECDH point.
    static func sessionKeyFromSharedSecret(
        sharedSecret: [UInt8],
        wrappedSessionKey: [UInt8],
        recipientFingerprint: [UInt8],
        kdfHashID: UInt8 = sha256ID,
        kdfCipherID: UInt8 = aes128ID
    ) throws -> (algorithmID: UInt8, sessionKey: [UInt8]) {

        // 3. Derive KEK
        let kekSize = try keySize(for: kdfCipherID)
        let kdfParams = buildKDFParams(
            kdfHashID: kdfHashID,
            kdfCipherID: kdfCipherID
        )
        let kek = try deriveKEK(
            sharedSecret: sharedSecret,
            curveOID: Cv25519ECDHService.cv25519OID,
            kdfParams: kdfParams,
            fingerprint: recipientFingerprint,
            keySize: kekSize,
            hashID: kdfHashID
        )

        // 4. AES Key Unwrap
        let unwrapped: [UInt8]
        do {
            unwrapped = try AESKeyWrap.unwrap(ciphertext: wrappedSessionKey, kek: kek)
        } catch {
            throw ECDHError.sessionKeyUnwrapFailed(error.localizedDescription)
        }

        // 5. Parse: algorithm_id(1) + session_key(N) + checksum(2)
        guard unwrapped.count >= 4 else {
            throw ECDHError.invalidWrappedData
        }

        // Strip PKCS5 padding
        let unpadded = pkcs5Unpad(unwrapped)

        let algorithmID = unpadded[0]
        let sessionKey = Array(unpadded[1..<(unpadded.count - 2)])
        let checksumHi = unpadded[unpadded.count - 2]
        let checksumLo = unpadded[unpadded.count - 1]
        let expectedChecksum = UInt16(checksumHi) << 8 | UInt16(checksumLo)
        let actualChecksum = sessionKey.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }

        guard expectedChecksum == actualChecksum else {
            throw ECDHError.sessionKeyUnwrapFailed("Session key checksum mismatch")
        }

        return (algorithmID, sessionKey)
    }

    // MARK: - RFC 6637 §7 KDF

    /// Key Derivation Function per RFC 6637 §7:
    ///   Hash(00 || 00 || 00 || 01 || ZZ || param)
    /// Where param = curve_OID_len || curve_OID || public_algo_id(18) ||
    ///               03 || 01 || kdf_hash || kdf_cipher ||
    ///               "Anonymous Sender    " || fingerprint
    private static func deriveKEK(
        sharedSecret: [UInt8],
        curveOID: [UInt8],
        kdfParams: [UInt8],
        fingerprint: [UInt8],
        keySize: Int,
        hashID: UInt8
    ) throws -> [UInt8] {

        // Build the param block
        var param: [UInt8] = []

        // Curve OID with length prefix
        param.append(UInt8(curveOID.count))
        param.append(contentsOf: curveOID)

        // Public key algorithm ID (18 = ECDH)
        param.append(18)

        // KDF params (already includes 03 01 hash cipher)
        param.append(contentsOf: kdfParams)

        // "Anonymous Sender    " (20 bytes, padded with spaces)
        let anonSender: [UInt8] = [
            0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75,
            0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
            0x20, 0x20, 0x20, 0x20
        ]
        param.append(contentsOf: anonSender)

        // Recipient fingerprint (20 bytes for v4)
        param.append(contentsOf: fingerprint)

        // Hash: SHA-256(00 00 00 01 || shared_secret || param)
        var hashInput: [UInt8] = [0x00, 0x00, 0x00, 0x01]
        hashInput.append(contentsOf: sharedSecret)
        hashInput.append(contentsOf: param)

        let digest: [UInt8]
        switch hashID {
        case sha256ID:
            let hash = SHA256.hash(data: hashInput)
            digest = Array(hash)
        default:
            throw ECDHError.unsupportedAlgorithm(hashID)
        }

        // Truncate to KEK size
        return Array(digest.prefix(keySize))
    }

    // MARK: - Helpers

    /// Build KDF params bytes: length(3) || 01 || hash_id || cipher_id
    static func buildKDFParams(kdfHashID: UInt8, kdfCipherID: UInt8) -> [UInt8] {
        return [0x03, 0x01, kdfHashID, kdfCipherID]
    }

    /// Get the key size in bytes for an OpenPGP symmetric algorithm
    static func keySize(for algorithmID: UInt8) throws -> Int {
        switch algorithmID {
        case 7: return 16   // AES-128
        case 8: return 24   // AES-192
        case 9: return 32   // AES-256
        default: throw ECDHError.unsupportedAlgorithm(algorithmID)
        }
    }

    /// PKCS5 pad to block size
    private static func pkcs5Pad(_ data: [UInt8], blockSize: Int) -> [UInt8] {
        let padLen = blockSize - (data.count % blockSize)
        return data + [UInt8](repeating: UInt8(padLen), count: padLen)
    }

    /// PKCS5 unpad
    private static func pkcs5Unpad(_ data: [UInt8]) -> [UInt8] {
        guard let last = data.last, last > 0 && last <= 8 else { return data }
        let padLen = Int(last)
        guard data.count >= padLen else { return data }
        // Verify all padding bytes are the same
        let padStart = data.count - padLen
        for i in padStart..<data.count {
            if data[i] != last { return data }
        }
        return Array(data[0..<padStart])
    }

    /// Calculate the V4 fingerprint of a subkey body (for KDF param)
    static func subkeyFingerprint(keyBody: [UInt8]) -> [UInt8] {
        var data: [UInt8] = [0x99]
        let len = UInt16(keyBody.count)
        data.append(UInt8((len >> 8) & 0xFF))
        data.append(UInt8(len & 0xFF))
        data.append(contentsOf: keyBody)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(data, CC_LONG(data.count), &hash)
        return hash
    }
}
