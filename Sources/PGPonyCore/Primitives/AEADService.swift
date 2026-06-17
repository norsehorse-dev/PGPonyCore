// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// AEADService.swift
// PGPony
//
// AEAD decryption for RFC 9580 v6 secret key material.
// Supports AES-OCB (GnuPG default, algo 2) and AES-GCM (algo 3, via CryptoKit).
//
// V6 secret keys use S2K usage octet 253, meaning the secret key material
// is AEAD-encrypted (not CFB like v4). The AEAD algorithm byte specifies
// which mode: 1=EAX, 2=OCB, 3=GCM.
//
// OCB is implemented using CommonCrypto's AES-ECB as the block cipher,
// following RFC 7253 (The OCB Authenticated-Encryption Algorithm).
//
// GCM uses CryptoKit's native AES-GCM.
//
// References:
//   - RFC 7253: OCB Authenticated-Encryption Algorithm
//   - RFC 9580 §5.5.3: Secret-Key Packet Formats (v6)

import Foundation
import CommonCrypto
import CryptoKit

// MARK: - AEAD Error Types

enum AEADError: LocalizedError {
    case unsupportedAlgorithm(UInt8)
    case decryptionFailed(String)
    case authenticationFailed
    case invalidNonce(String)
    case invalidKeySize(Int)

    var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm(let a): return "Unsupported AEAD algorithm: \(a)"
        case .decryptionFailed(let msg): return "AEAD decryption failed: \(msg)"
        case .authenticationFailed: return "AEAD authentication tag verification failed"
        case .invalidNonce(let msg): return "Invalid AEAD nonce: \(msg)"
        case .invalidKeySize(let s): return "Invalid AES key size: \(s) bytes"
        }
    }
}

// MARK: - AEAD Service

class AEADService {

    /// AEAD algorithm IDs per RFC 9580 §9.6
    static let eaxAlgoID:  UInt8 = 1
    static let ocbAlgoID:  UInt8 = 2   // GnuPG default
    static let gcmAlgoID:  UInt8 = 3

    /// Nonce/IV sizes per algorithm
    static func nonceSize(for aeadAlgo: UInt8) -> Int {
        switch aeadAlgo {
        case 1: return 16  // EAX: 16 bytes
        case 2: return 15  // OCB: 15 bytes
        case 3: return 12  // GCM: 12 bytes
        default: return 0
        }
    }

    /// Authentication tag size (always 16 bytes for all RFC 9580 AEAD modes)
    static let tagSize = 16

    // MARK: - Public API

    /// Decrypt AEAD-encrypted data.
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted data WITHOUT the auth tag
    ///   - tag: 16-byte authentication tag
    ///   - key: AES key (16, 24, or 32 bytes)
    ///   - nonce: Nonce/IV (size depends on algorithm)
    ///   - aeadAlgo: AEAD algorithm ID (1=EAX, 2=OCB, 3=GCM)
    ///   - associatedData: Optional AAD (empty for v6 secret key decryption)
    /// - Returns: Decrypted plaintext
    static func decrypt(
        ciphertext: [UInt8],
        tag: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        aeadAlgo: UInt8,
        associatedData: [UInt8] = []
    ) throws -> [UInt8] {
        switch aeadAlgo {
        case ocbAlgoID:
            return try ocbDecrypt(
                ciphertext: ciphertext,
                tag: tag,
                key: key,
                nonce: nonce,
                associatedData: associatedData
            )
        case gcmAlgoID:
            return try gcmDecrypt(
                ciphertext: ciphertext,
                tag: tag,
                key: key,
                nonce: nonce,
                associatedData: associatedData
            )
        case eaxAlgoID:
            throw AEADError.unsupportedAlgorithm(1)  // EAX not implemented yet
        default:
            throw AEADError.unsupportedAlgorithm(aeadAlgo)
        }
    }

    /// Convenience: decrypt ciphertext+tag combined (tag is last 16 bytes).
    /// This is the typical format in v6 secret key packets.
    static func decryptWithAppendedTag(
        data: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        aeadAlgo: UInt8,
        associatedData: [UInt8] = []
    ) throws -> [UInt8] {
        guard data.count >= tagSize else {
            throw AEADError.decryptionFailed("Data too short for AEAD tag (\(data.count) bytes)")
        }

        let ciphertext = Array(data[0..<(data.count - tagSize)])
        let tag = Array(data[(data.count - tagSize)...])

        return try decrypt(
            ciphertext: ciphertext,
            tag: tag,
            key: key,
            nonce: nonce,
            aeadAlgo: aeadAlgo,
            associatedData: associatedData
        )
    }

    // MARK: - Public API (encrypt) — v6.0 Phase V6-C

    /// AEAD-encrypt (seal) a plaintext, returning ciphertext and the 16-byte tag
    /// separately. Used by the SEIPDv2 builder.
    static func encrypt(
        plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        aeadAlgo: UInt8,
        associatedData: [UInt8] = []
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        switch aeadAlgo {
        case ocbAlgoID:
            return try ocbEncrypt(
                plaintext: plaintext,
                key: key,
                nonce: nonce,
                associatedData: associatedData
            )
        case gcmAlgoID:
            return try gcmEncrypt(
                plaintext: plaintext,
                key: key,
                nonce: nonce,
                associatedData: associatedData
            )
        case eaxAlgoID:
            throw AEADError.unsupportedAlgorithm(1)  // EAX not implemented
        default:
            throw AEADError.unsupportedAlgorithm(aeadAlgo)
        }
    }

    /// Convenience: seal and return ciphertext with the tag appended (the layout
    /// used inside SEIPDv2 chunks).
    static func encryptWithAppendedTag(
        plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        aeadAlgo: UInt8,
        associatedData: [UInt8] = []
    ) throws -> [UInt8] {
        let sealed = try encrypt(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            aeadAlgo: aeadAlgo,
            associatedData: associatedData
        )
        return sealed.ciphertext + sealed.tag
    }

    // MARK: - AES-GCM encrypt (via CryptoKit)

    private static func gcmEncrypt(
        plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        associatedData: [UInt8]
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        do {
            let symKey = SymmetricKey(data: Data(key))
            let gcmNonce = try AES.GCM.Nonce(data: Data(nonce))
            let sealed = try AES.GCM.seal(
                Data(plaintext),
                using: symKey,
                nonce: gcmNonce,
                authenticating: Data(associatedData)
            )
            return (Array(sealed.ciphertext), Array(sealed.tag))
        } catch {
            throw AEADError.decryptionFailed("AES-GCM seal failed: \(error)")
        }
    }

    // MARK: - AES-GCM (via CryptoKit)

    private static func gcmDecrypt(
        ciphertext: [UInt8],
        tag: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        associatedData: [UInt8]
    ) throws -> [UInt8] {
        guard nonce.count == 12 else {
            throw AEADError.invalidNonce("GCM nonce must be 12 bytes, got \(nonce.count)")
        }

        let symmetricKey: SymmetricKey
        switch key.count {
        case 16: symmetricKey = SymmetricKey(data: key)
        case 24: symmetricKey = SymmetricKey(data: key)
        case 32: symmetricKey = SymmetricKey(data: key)
        default: throw AEADError.invalidKeySize(key.count)
        }

        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: ciphertext,
                tag: tag
            )
            let decrypted = try AES.GCM.open(
                sealedBox,
                using: symmetricKey,
                authenticating: associatedData
            )
            return Array(decrypted)
        } catch {
            throw AEADError.decryptionFailed("AES-GCM: \(error.localizedDescription)")
        }
    }

    // MARK: - AES-OCB (RFC 7253)

    /// AES-OCB decryption per RFC 7253.
    /// OCB is the GnuPG default AEAD mode for v6 keys.
    ///
    /// OCB3 with full 128-bit tag, nonce = 15 bytes (RFC 9580 mandates 15-byte nonce).
    /// Uses CommonCrypto's AES-ECB as the underlying block cipher.
    /// RFC 7253 OCB encrypt. Mirror of `ocbDecrypt`; the offset/L-table/Ktop/
    /// Stretch setup is identical. Validated byte-for-byte against a reference
    /// OCB3 implementation for empty, partial, full, and multi-block inputs.
    /// v6.0 Phase V6-C.
    private static func ocbEncrypt(
        plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        associatedData: [UInt8]
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        guard nonce.count == 15 else {
            throw AEADError.invalidNonce("OCB nonce must be 15 bytes, got \(nonce.count)")
        }
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw AEADError.invalidKeySize(key.count)
        }

        // L_*, L_$, L_0, ... (same as decrypt)
        let lStar = try aesECB(input: [UInt8](repeating: 0, count: 16), key: key)
        let lDollar = double(lStar)
        var lTable = [lStar, lDollar]
        lTable.append(double(lDollar))  // L_0

        func getL(_ i: Int) -> [UInt8] {
            let tableIndex = i + 2
            while lTable.count <= tableIndex {
                lTable.append(double(lTable.last!))
            }
            return lTable[tableIndex]
        }

        // Initial offset from nonce (RFC 7253 §4.2), identical to ocbDecrypt.
        let bottom = Int(nonce[14]) & 0x3F
        var nonceBlock = [UInt8](repeating: 0, count: 16)
        nonceBlock[0] = 0x01
        for i in 0..<15 {
            nonceBlock[i + 1] = nonce[i]
        }
        var topBlock = nonceBlock
        topBlock[15] &= 0xC0
        let ktop = try aesECB(input: topBlock, key: key)
        var stretch = ktop
        for i in 0..<8 {
            stretch.append(ktop[i] ^ ktop[i + 1])
        }
        let offset0 = extractBits(from: stretch, bitOffset: bottom, bitCount: 128)

        let numFullBlocks = plaintext.count / 16
        let lastBlockLen = plaintext.count % 16

        var offset = offset0
        var checksum = [UInt8](repeating: 0, count: 16)
        var ciphertext = [UInt8]()

        // Full blocks: C_i = Offset_i XOR ENCIPHER(K, P_i XOR Offset_i)
        for i in 0..<numFullBlocks {
            offset = xorBlocks(offset, getL(ntz(i + 1)))
            let pi = Array(plaintext[(i * 16)..<((i + 1) * 16)])
            let enc = try aesECB(input: xorBlocks(pi, offset), key: key)
            ciphertext.append(contentsOf: xorBlocks(enc, offset))
            checksum = xorBlocks(checksum, pi)
        }

        // Final partial block
        if lastBlockLen > 0 {
            offset = xorBlocks(offset, lStar)
            let pad = try aesECB(input: offset, key: key)
            let pStar = Array(plaintext[(numFullBlocks * 16)...])
            var cStar = [UInt8](repeating: 0, count: lastBlockLen)
            for j in 0..<lastBlockLen {
                cStar[j] = pStar[j] ^ pad[j]
            }
            ciphertext.append(contentsOf: cStar)

            var paddedPStar = pStar
            paddedPStar.append(0x80)
            while paddedPStar.count < 16 { paddedPStar.append(0x00) }
            checksum = xorBlocks(checksum, paddedPStar)
        }

        // Tag = ENCIPHER(K, Checksum XOR Offset_final XOR L_$) XOR HASH(K, A)
        let tagInput = xorBlocks(xorBlocks(checksum, offset), lDollar)
        var tag = try aesECB(input: tagInput, key: key)
        let hashA = try ocbHash(associatedData: associatedData, key: key, lTable: &lTable, lStar: lStar)
        tag = xorBlocks(tag, hashA)

        return (ciphertext, tag)
    }

    private static func ocbDecrypt(
        ciphertext: [UInt8],
        tag: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        associatedData: [UInt8]
    ) throws -> [UInt8] {
        guard nonce.count == 15 else {
            throw AEADError.invalidNonce("OCB nonce must be 15 bytes, got \(nonce.count)")
        }
        guard tag.count == 16 else {
            throw AEADError.decryptionFailed("OCB tag must be 16 bytes, got \(tag.count)")
        }
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw AEADError.invalidKeySize(key.count)
        }

        // Step 1: Compute L_*, L_$, L_0, L_1, ...
        let lStar = try aesECB(input: [UInt8](repeating: 0, count: 16), key: key)
        let lDollar = double(lStar)
        var lTable = [lStar, lDollar]
        lTable.append(double(lDollar))  // L_0
        // We'll extend lazily as needed

        func getL(_ i: Int) -> [UInt8] {
            // L_i for i >= 0: L_0 = double(L_$), L_i = double(L_{i-1})
            let tableIndex = i + 2  // lTable[0]=L_*, [1]=L_$, [2]=L_0, [3]=L_1, ...
            while lTable.count <= tableIndex {
                lTable.append(double(lTable.last!))
            }
            return lTable[tableIndex]
        }

        // Step 2: Compute initial offset from nonce
        // RFC 7253 §4.2: Nonce-dependent values
        // For TAGLEN=128 (full block tag), bottom = Nonce[15] & 0x3F
        // Nonce is 15 bytes for OCB in RFC 9580.
        //
        // Ktop = ENCIPHER(K, 0^(128-|N|) || 1 || N[1..len-1])
        // where |N| is the nonce bit length.
        //
        // For 15-byte (120-bit) nonce:
        //   Top = 0x00 || Nonce[0..13] with bit manipulation for bottom
        let bottom = Int(nonce[14]) & 0x3F

        // Build the nonce block: 0^7 || 1 || Nonce[0..14]
        // For 15-byte nonce: we put 0 in byte 0 (128 - 120 = 8 bits = 1 byte of zeros,
        // but the format is: taglen bits in top 7, then the nonce)
        // Actually RFC 7253 for taglen=128: top byte = taglen mod 128 << 1 = 0
        var nonceBlock = [UInt8](repeating: 0, count: 16)
        // Copy nonce into bytes 1..15
        for i in 0..<15 {
            nonceBlock[i + 1] = nonce[i]
        }
        // Set the bit at position 128 - nonceBitLen (for 120-bit nonce, position 8, which is byte 1 bit 0)
        // Actually: the leading byte encodes (tag_length mod 128) << 1, which for 128 is 0
        // Then bit 128-len(nonce in bits) is set to 1
        // For 15-byte nonce: that's bit 8 from MSB = byte 1, bit 7 (MSB of byte 1)
        nonceBlock[0] = 0  // taglen mod 128 = 0, shifted left 1
        nonceBlock[1] |= 0x01  // Set the separator bit (bit 127-120+1 = bit at index 120 in big-endian)
        // Wait — let me re-read RFC 7253 more carefully.
        // The Nonce input to OCB is at most 120 bits (15 bytes).
        // "Nonce = num2str(TAGLEN mod 128, 7) || zeros(120-|N|) || 1 || N"
        // So: 7 bits of (128 mod 128 = 0), then (120 - 120 = 0) zeros, then 1, then N.
        // That's: 0000000 || 1 || N (120 bits) = 0x00 with MSB bit set after 7 zero bits = 0x01? No:
        // 7 bits of 0 = 0000000, then 1 bit = 1, then 120 bits = nonce
        // So byte 0 = 00000001 = 0x01, bytes 1-15 = nonce
        nonceBlock[0] = 0x01
        for i in 0..<15 {
            nonceBlock[i + 1] = nonce[i]
        }

        // Clear the bottom 6 bits of byte 15 to get the "top" portion for Ktop
        var topBlock = nonceBlock
        topBlock[15] &= 0xC0

        let ktop = try aesECB(input: topBlock, key: key)

        // Stretch = Ktop || (Ktop[1..8] XOR Ktop[9..16])
        var stretch = ktop
        for i in 0..<8 {
            stretch.append(ktop[i] ^ ktop[i + 1])
        }
        // Actually RFC 7253: Stretch = Ktop || (Ktop[1..64] XOR Ktop[9..72])
        // where indices are bit positions (1-indexed)
        // Ktop[1..64] = first 8 bytes, Ktop[9..72] = bytes 1..8 (shifted by 1 byte)
        // So Stretch is 24 bytes: ktop (16) + xor part (8)

        // Offset_0 = Stretch[1+bottom .. 128+bottom] (bit-level shift)
        let offset0 = extractBits(from: stretch, bitOffset: bottom, bitCount: 128)

        // Step 3: Decrypt
        let numFullBlocks = ciphertext.count / 16
        let lastBlockLen = ciphertext.count % 16

        var offset = offset0
        var checksum = [UInt8](repeating: 0, count: 16)
        var plaintext = [UInt8]()

        // Process full blocks
        for i in 0..<numFullBlocks {
            // Offset_i = Offset_{i-1} XOR L_{ntz(i)}
            let ntzVal = ntz(i + 1)  // RFC 7253 uses 1-based block numbering
            let li = getL(ntzVal)
            offset = xorBlocks(offset, li)

            // P_i = Offset_i XOR DECIPHER(K, C_i XOR Offset_i)
            let ci = Array(ciphertext[(i * 16)..<((i + 1) * 16)])
            let decInput = xorBlocks(ci, offset)
            let decResult = try aesECBDecrypt(input: decInput, key: key)
            let pi = xorBlocks(decResult, offset)

            plaintext.append(contentsOf: pi)

            // Checksum_i = Checksum_{i-1} XOR P_i
            checksum = xorBlocks(checksum, pi)
        }

        // Process final partial block (if any)
        if lastBlockLen > 0 {
            // Offset_* = Offset_m XOR L_*
            offset = xorBlocks(offset, lStar)

            // Pad = ENCIPHER(K, Offset_*)
            let pad = try aesECB(input: offset, key: key)

            // P_* = C_* XOR Pad[1..|C_*|]
            let cStar = Array(ciphertext[(numFullBlocks * 16)...])
            var pStar = [UInt8](repeating: 0, count: lastBlockLen)
            for j in 0..<lastBlockLen {
                pStar[j] = cStar[j] ^ pad[j]
            }
            plaintext.append(contentsOf: pStar)

            // Checksum_* = Checksum_m XOR (P_* || 1 || zeros)
            var paddedPStar = pStar
            paddedPStar.append(0x80)
            while paddedPStar.count < 16 {
                paddedPStar.append(0x00)
            }
            checksum = xorBlocks(checksum, paddedPStar)
        }

        // Step 4: Compute and verify tag
        // Tag = ENCIPHER(K, Checksum XOR Offset_final XOR L_$) XOR HASH(K, A)
        let tagInput = xorBlocks(xorBlocks(checksum, offset), lDollar)
        var computedTag = try aesECB(input: tagInput, key: key)

        // HASH(K, A) for associated data
        let hashA = try ocbHash(associatedData: associatedData, key: key, lTable: &lTable, lStar: lStar)
        computedTag = xorBlocks(computedTag, hashA)

        // Constant-time tag comparison
        var diff: UInt8 = 0
        for i in 0..<16 {
            diff |= computedTag[i] ^ tag[i]
        }
        guard diff == 0 else {
            pgpDebugLog("DEBUG OCB: tag mismatch — computed=\(computedTag.map { String(format: "%02x", $0) }.joined()) vs expected=\(tag.map { String(format: "%02x", $0) }.joined())")
            throw AEADError.authenticationFailed
        }

        return plaintext
    }

    /// OCB HASH function for associated data (RFC 7253 §4.1)
    private static func ocbHash(
        associatedData: [UInt8],
        key: [UInt8],
        lTable: inout [[UInt8]],
        lStar: [UInt8]
    ) throws -> [UInt8] {
        if associatedData.isEmpty {
            return [UInt8](repeating: 0, count: 16)
        }

        func getHL(_ i: Int) -> [UInt8] {
            let tableIndex = i + 2
            while lTable.count <= tableIndex {
                lTable.append(double(lTable.last!))
            }
            return lTable[tableIndex]
        }

        let numFullBlocks = associatedData.count / 16
        let lastLen = associatedData.count % 16

        var offset = [UInt8](repeating: 0, count: 16)
        var sum = [UInt8](repeating: 0, count: 16)

        for i in 0..<numFullBlocks {
            let ntzVal = ntz(i + 1)
            let li = getHL(ntzVal)
            offset = xorBlocks(offset, li)

            let ai = Array(associatedData[(i * 16)..<((i + 1) * 16)])
            let encInput = xorBlocks(ai, offset)
            let encResult = try aesECB(input: encInput, key: key)
            sum = xorBlocks(sum, encResult)
        }

        if lastLen > 0 {
            offset = xorBlocks(offset, lStar)
            var aStar = Array(associatedData[(numFullBlocks * 16)...])
            aStar.append(0x80)
            while aStar.count < 16 {
                aStar.append(0x00)
            }
            let encInput = xorBlocks(aStar, offset)
            let encResult = try aesECB(input: encInput, key: key)
            sum = xorBlocks(sum, encResult)
        }

        return sum
    }

    // MARK: - AES Block Operations

    /// AES-ECB encrypt a single 16-byte block
    private static func aesECB(input: [UInt8], key: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 32)
        var outLen = 0

        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            input, 16,
            &output, 32,
            &outLen
        )
        guard status == kCCSuccess else {
            throw AEADError.decryptionFailed("AES-ECB encrypt failed: \(status)")
        }
        return Array(output[0..<16])
    }

    /// AES-ECB decrypt a single 16-byte block
    private static func aesECBDecrypt(input: [UInt8], key: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 32)
        var outLen = 0

        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            input, 16,
            &output, 32,
            &outLen
        )
        guard status == kCCSuccess else {
            throw AEADError.decryptionFailed("AES-ECB decrypt failed: \(status)")
        }
        return Array(output[0..<16])
    }

    // MARK: - OCB Helpers

    /// Double operation in GF(2^128) with the OCB polynomial.
    /// If MSB(S) == 0: return S << 1
    /// If MSB(S) == 1: return (S << 1) XOR (0...0 10000111)
    private static func double(_ block: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 16)
        let carry = block[0] >> 7  // MSB

        for i in 0..<15 {
            result[i] = (block[i] << 1) | (block[i + 1] >> 7)
        }
        result[15] = block[15] << 1

        // XOR with polynomial 0x87 if carry
        if carry != 0 {
            result[15] ^= 0x87
        }

        return result
    }

    /// Number of trailing zeros in the binary representation of n.
    /// Used for L-table indexing in OCB.
    private static func ntz(_ n: Int) -> Int {
        guard n != 0 else { return 0 }
        var count = 0
        var val = n
        while val & 1 == 0 {
            count += 1
            val >>= 1
        }
        return count
    }

    /// XOR two 16-byte blocks
    @inline(__always)
    private static func xorBlocks(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 {
            result[i] = a[i] ^ b[i]
        }
        return result
    }

    /// Extract 128 bits starting at the given bit offset from a byte array.
    /// Used for the OCB nonce-to-offset computation.
    private static func extractBits(from data: [UInt8], bitOffset: Int, bitCount: Int) -> [UInt8] {
        let byteOffset = bitOffset / 8
        let bitShift = bitOffset % 8
        var result = [UInt8](repeating: 0, count: bitCount / 8)

        for i in 0..<result.count {
            let srcIdx = byteOffset + i
            if srcIdx < data.count {
                result[i] = data[srcIdx] << bitShift
            }
            if bitShift > 0 && srcIdx + 1 < data.count {
                result[i] |= data[srcIdx + 1] >> (8 - bitShift)
            }
        }

        return result
    }
}
