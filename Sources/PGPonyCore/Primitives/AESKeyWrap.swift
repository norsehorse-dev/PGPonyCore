// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// AESKeyWrap.swift
// PGPony
//
// RFC 3394 AES Key Wrap / Unwrap using CommonCrypto.
// Used by OpenPGP ECDH to wrap/unwrap session keys.

import Foundation
import CommonCrypto

enum AESKeyWrapError: LocalizedError {
    case invalidKeySize
    case invalidDataSize
    case integrityCheckFailed
    case encryptionFailed

    var errorDescription: String? {
        switch self {
        case .invalidKeySize: return "AES key wrap: invalid KEK size (must be 16, 24, or 32 bytes)"
        case .invalidDataSize: return "AES key wrap: data must be a multiple of 8 bytes and at least 16"
        case .integrityCheckFailed: return "AES key unwrap: integrity check failed (wrong key or corrupted data)"
        case .encryptionFailed: return "AES key wrap: AES-ECB encryption failed"
        }
    }
}

struct AESKeyWrap {

    // Default IV per RFC 3394 §2.2.3.1
    private static let defaultIV: [UInt8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]

    // MARK: - Wrap

    /// Wrap key data using AES Key Wrap (RFC 3394)
    /// - Parameters:
    ///   - plaintext: The key material to wrap (must be multiple of 8 bytes, >= 16)
    ///   - kek: The Key Encryption Key (16, 24, or 32 bytes)
    /// - Returns: Wrapped key (plaintext.count + 8 bytes)
    static func wrap(plaintext: [UInt8], kek: [UInt8]) throws -> [UInt8] {
        guard kek.count == 16 || kek.count == 24 || kek.count == 32 else {
            throw AESKeyWrapError.invalidKeySize
        }
        guard plaintext.count >= 16 && plaintext.count % 8 == 0 else {
            throw AESKeyWrapError.invalidDataSize
        }

        let n = plaintext.count / 8  // Number of 64-bit blocks
        var a = defaultIV
        var r = [[UInt8]](repeating: [], count: n)

        // Initialize R[i] from plaintext
        for i in 0..<n {
            r[i] = Array(plaintext[(i * 8)..<((i + 1) * 8)])
        }

        // 6 rounds of wrapping
        for j in 0..<6 {
            for i in 0..<n {
                // B = AES(K, A | R[i])
                var block = a + r[i]  // 16 bytes
                let encrypted = try aesECBEncrypt(block: &block, key: kek)

                // A = MSB(64, B) ^ t where t = (n*j)+i+1
                let t = UInt64(n * j + i + 1)
                a = Array(encrypted[0..<8])
                a = xorWithCounter(a, t)

                // R[i] = LSB(64, B)
                r[i] = Array(encrypted[8..<16])
            }
        }

        // Output: A || R[1] || R[2] || ... || R[n]
        var result = a
        for i in 0..<n {
            result.append(contentsOf: r[i])
        }
        return result
    }

    // MARK: - Unwrap

    /// Unwrap key data using AES Key Unwrap (RFC 3394)
    /// - Parameters:
    ///   - ciphertext: The wrapped key (must be multiple of 8 bytes, >= 24)
    ///   - kek: The Key Encryption Key (16, 24, or 32 bytes)
    /// - Returns: Unwrapped key material (ciphertext.count - 8 bytes)
    static func unwrap(ciphertext: [UInt8], kek: [UInt8]) throws -> [UInt8] {
        guard kek.count == 16 || kek.count == 24 || kek.count == 32 else {
            throw AESKeyWrapError.invalidKeySize
        }
        guard ciphertext.count >= 24 && ciphertext.count % 8 == 0 else {
            throw AESKeyWrapError.invalidDataSize
        }

        let n = (ciphertext.count / 8) - 1
        var a = Array(ciphertext[0..<8])
        var r = [[UInt8]](repeating: [], count: n)

        for i in 0..<n {
            r[i] = Array(ciphertext[((i + 1) * 8)..<((i + 2) * 8)])
        }

        // 6 rounds of unwrapping (reverse)
        for j in stride(from: 5, through: 0, by: -1) {
            for i in stride(from: n - 1, through: 0, by: -1) {
                let t = UInt64(n * j + i + 1)
                let aXored = xorWithCounter(a, t)

                // B = AES-1(K, (A ^ t) | R[i])
                var block = aXored + r[i]
                let decrypted = try aesECBDecrypt(block: &block, key: kek)

                a = Array(decrypted[0..<8])
                r[i] = Array(decrypted[8..<16])
            }
        }

        // Verify IV
        guard a == defaultIV else {
            throw AESKeyWrapError.integrityCheckFailed
        }

        var result: [UInt8] = []
        for i in 0..<n {
            result.append(contentsOf: r[i])
        }
        return result
    }

    // MARK: - Helpers

    private static func xorWithCounter(_ bytes: [UInt8], _ counter: UInt64) -> [UInt8] {
        var result = bytes
        for i in 0..<8 {
            result[7 - i] ^= UInt8((counter >> (i * 8)) & 0xFF)
        }
        return result
    }

    private static func aesECBEncrypt(block: inout [UInt8], key: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0

        var cryptor: CCCryptorRef?
        let status = CCCryptorCreate(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            &cryptor
        )
        guard status == kCCSuccess, let c = cryptor else {
            throw AESKeyWrapError.encryptionFailed
        }
        CCCryptorUpdate(c, block, 16, &out, 16, &outLen)
        CCCryptorRelease(c)
        return out
    }

    private static func aesECBDecrypt(block: inout [UInt8], key: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0

        var cryptor: CCCryptorRef?
        let status = CCCryptorCreate(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            &cryptor
        )
        guard status == kCCSuccess, let c = cryptor else {
            throw AESKeyWrapError.encryptionFailed
        }
        CCCryptorUpdate(c, block, 16, &out, 16, &outLen)
        CCCryptorRelease(c)
        return out
    }
}
