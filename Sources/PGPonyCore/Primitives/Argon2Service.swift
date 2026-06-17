// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Argon2Service.swift
// PGPony
//
// Pure Swift implementation of Argon2id for RFC 9580 v6 S2K type 4.
// Implements Argon2id (variant 2) per RFC 9106.
//
// This is used exclusively for key derivation from passphrases when importing
// GnuPG 2.4+ v6 secret keys. Performance is adequate for single-passphrase
// derivation (the user waits once while we derive).
//
// References:
//   - RFC 9106: Argon2 Memory-Hard Function for Password Hashing
//   - RFC 9580 §3.7.2.2: Argon2 S2K
//   - https://github.com/P-H-C/phc-winner-argon2 (reference C implementation)

import Foundation
import CommonCrypto

// MARK: - Argon2 Error Types

enum Argon2Error: LocalizedError {
    case invalidParameters(String)
    case memoryAllocationFailed
    case hashLengthTooShort

    var errorDescription: String? {
        switch self {
        case .invalidParameters(let msg): return "Argon2 invalid parameters: \(msg)"
        case .memoryAllocationFailed: return "Argon2 could not allocate memory"
        case .hashLengthTooShort: return "Argon2 hash length must be at least 4 bytes"
        }
    }
}

// MARK: - Argon2 Service

/// Pure Swift Argon2id implementation.
///
/// Argon2id is a hybrid of Argon2i (data-independent, side-channel resistant)
/// and Argon2d (data-dependent, GPU/ASIC resistant). It uses Argon2i for the
/// first half of the first pass and Argon2d for the rest.
///
/// RFC 9580 v6 keys use Argon2id with parameters encoded as:
///   - t: number of passes (iterations)
///   - p: degree of parallelism (lanes)
///   - m: encoded memory size (actual memory = 2^m KiB)
class Argon2Service {

    // MARK: - Public API

    /// Derive a key from a passphrase using Argon2id.
    ///
    /// - Parameters:
    ///   - passphrase: The user's passphrase (UTF-8 encoded)
    ///   - salt: 16-byte salt from the S2K specifier
    ///   - iterations: Number of passes (t parameter)
    ///   - parallelism: Degree of parallelism / lanes (p parameter)
    ///   - memoryExponent: Encoded memory size (actual = 2^m KiB)
    ///   - hashLength: Desired output key length in bytes
    /// - Returns: Derived key bytes
    static func deriveKey(
        passphrase: String,
        salt: [UInt8],
        iterations t: Int,
        parallelism p: Int,
        memoryExponent m: Int,
        hashLength: Int
    ) throws -> [UInt8] {
        let password = Array(passphrase.utf8)
        let memorySizeKiB = 1 << m  // 2^m KiB

        guard t >= 1 else { throw Argon2Error.invalidParameters("iterations must be >= 1") }
        guard p >= 1 else { throw Argon2Error.invalidParameters("parallelism must be >= 1") }
        guard m >= 3 else { throw Argon2Error.invalidParameters("memory exponent must be >= 3 (8 KiB)") }
        guard hashLength >= 4 else { throw Argon2Error.hashLengthTooShort }
        guard salt.count == 16 else { throw Argon2Error.invalidParameters("salt must be 16 bytes") }

        // Number of 1 KiB blocks. Must be at least 8*p (RFC 9106 §3.1).
        var memoryBlocks = memorySizeKiB
        if memoryBlocks < 8 * p {
            memoryBlocks = 8 * p
        }
        // Align to 4*p
        memoryBlocks = (memoryBlocks / (4 * p)) * (4 * p)

        let segmentLength = memoryBlocks / (4 * p)
        let laneLength = segmentLength * 4

        pgpDebugLog("DEBUG Argon2: t=\(t), p=\(p), m=\(m) (2^\(m) KiB = \(memorySizeKiB) KiB), blocks=\(memoryBlocks), segLen=\(segmentLength), laneLen=\(laneLength), hashLen=\(hashLength)")

        // Allocate memory: each block is 1024 bytes (128 x 8-byte words)
        var blocks = [[UInt64]](repeating: [UInt64](repeating: 0, count: 128), count: memoryBlocks)

        // H0 = BLAKE2b-64(p | tagLength | m | t | version | type | |P| | P | |S| | S | |X| | X | |K| | K)
        // For OpenPGP: X (associated data) and K (secret) are empty
        let h0 = computeH0(
            password: password,
            salt: salt,
            parallelism: p,
            tagLength: hashLength,
            memorySizeKiB: memorySizeKiB,
            iterations: t,
            version: 0x13,   // Argon2 version 1.3
            type: 2          // Argon2id
        )

        // Initialize first two blocks of each lane
        for lane in 0..<p {
            // B[lane][0] = H'(H0 || 0 || lane)
            var input0 = h0
            input0.append(contentsOf: uint32LE(UInt32(0)))
            input0.append(contentsOf: uint32LE(UInt32(lane)))
            blocks[lane * laneLength] = hPrime(input0, tagLength: 1024)

            // B[lane][1] = H'(H0 || 1 || lane)
            var input1 = h0
            input1.append(contentsOf: uint32LE(UInt32(1)))
            input1.append(contentsOf: uint32LE(UInt32(lane)))
            blocks[lane * laneLength + 1] = hPrime(input1, tagLength: 1024)
        }

        // Fill memory
        for pass in 0..<t {
            for slice in 0..<4 {
                for lane in 0..<p {
                    fillSegment(
                        blocks: &blocks,
                        pass: pass,
                        lane: lane,
                        slice: slice,
                        totalPasses: t,
                        lanes: p,
                        segmentLength: segmentLength,
                        laneLength: laneLength,
                        totalBlocks: memoryBlocks
                    )
                }
            }
        }

        // Finalize: XOR last blocks of each lane
        var finalBlock = blocks[(0 + 1) * laneLength - 1]
        for lane in 1..<p {
            let lastBlock = blocks[(lane + 1) * laneLength - 1]
            for i in 0..<128 {
                finalBlock[i] ^= lastBlock[i]
            }
        }

        // H'(final_block, hashLength)
        let finalBytes = blockToBytes(finalBlock)
        let result = hPrimeBytes(finalBytes, tagLength: hashLength)


        return result
    }

    // MARK: - H0 Computation

    /// Compute H0 per RFC 9106 §3.2
    private static func computeH0(
        password: [UInt8],
        salt: [UInt8],
        parallelism: Int,
        tagLength: Int,
        memorySizeKiB: Int,
        iterations: Int,
        version: Int,
        type: Int
    ) -> [UInt8] {
        // Input to BLAKE2b-64:
        // p(4) | T(4) | m(4) | t(4) | v(4) | y(4) | |P|(4) | P | |S|(4) | S | |X|(4) | X | |K|(4) | K
        var input = [UInt8]()
        input.append(contentsOf: uint32LE(UInt32(parallelism)))
        input.append(contentsOf: uint32LE(UInt32(tagLength)))
        input.append(contentsOf: uint32LE(UInt32(memorySizeKiB)))
        input.append(contentsOf: uint32LE(UInt32(iterations)))
        input.append(contentsOf: uint32LE(UInt32(version)))
        input.append(contentsOf: uint32LE(UInt32(type)))
        input.append(contentsOf: uint32LE(UInt32(password.count)))
        input.append(contentsOf: password)
        input.append(contentsOf: uint32LE(UInt32(salt.count)))
        input.append(contentsOf: salt)
        input.append(contentsOf: uint32LE(UInt32(0)))  // |X| = 0 (no associated data)
        input.append(contentsOf: uint32LE(UInt32(0)))  // |K| = 0 (no secret)

        return blake2b(input, digestLength: 64)
    }

    // MARK: - H' Variable-Length Hash (RFC 9106 §3.2)

    /// H' variable-length hash function. Produces tagLength bytes of output.
    /// If tagLength <= 64: H' = BLAKE2b-tagLength(LE32(tagLength) || input)
    /// If tagLength > 64: uses iterated BLAKE2b-64 with final BLAKE2b-(tagLength mod 32)
    private static func hPrime(_ input: [UInt8], tagLength: Int) -> [UInt64] {
        let bytes = hPrimeBytes(input, tagLength: tagLength)
        // Convert bytes to UInt64 words (little-endian)
        var words = [UInt64](repeating: 0, count: tagLength / 8)
        for i in 0..<words.count {
            var val: UInt64 = 0
            for j in 0..<8 {
                val |= UInt64(bytes[i * 8 + j]) << (j * 8)
            }
            words[i] = val
        }
        return words
    }

    private static func hPrimeBytes(_ input: [UInt8], tagLength: Int) -> [UInt8] {
        let tagInput = uint32LE(UInt32(tagLength)) + input

        if tagLength <= 64 {
            return blake2b(tagInput, digestLength: tagLength)
        }

        // RFC 9106 §3.2 H': write the 32-byte prefix of V_1, V_2, ... while MORE
        // than 64 bytes remain, then one final block of the remaining length
        // (which is 33...64 bytes — NOT truncated to 32). The previous version
        // emitted one extra 32-byte prefix and a 32-byte tail, which is a
        // different (non-standard) byte string and broke gpg/sq interop.
        var result = [UInt8]()
        var v = blake2b(tagInput, digestLength: 64)        // V_1
        result.append(contentsOf: v[0..<32])
        var todo = tagLength - 32
        while todo > 64 {
            v = blake2b(v, digestLength: 64)                // V_2 ... V_r
            result.append(contentsOf: v[0..<32])
            todo -= 32
        }
        result.append(contentsOf: blake2b(v, digestLength: todo))  // V_{r+1}, length = todo
        return result
    }

    // MARK: - Segment Fill (RFC 9106 §3.4)

    private static func fillSegment(
        blocks: inout [[UInt64]],
        pass: Int,
        lane: Int,
        slice: Int,
        totalPasses: Int,
        lanes: Int,
        segmentLength: Int,
        laneLength: Int,
        totalBlocks: Int
    ) {
        let startIndex = (pass == 0 && slice == 0) ? 2 : 0

        // Pseudo-random value generation depends on Argon2 type:
        // Argon2id: first pass, slices 0-1 use Argon2i (data-independent)
        //           everything else uses Argon2d (data-dependent)
        let useDataIndependent = (pass == 0 && slice < 2)

        // Pre-generate addresses for data-independent mode
        var addressBlock = [UInt64](repeating: 0, count: 128)
        var inputBlock = [UInt64](repeating: 0, count: 128)
        var addressChunk = -1

        if useDataIndependent {
            inputBlock[0] = UInt64(pass)
            inputBlock[1] = UInt64(lane)
            inputBlock[2] = UInt64(slice)
            inputBlock[3] = UInt64(totalBlocks)
            inputBlock[4] = UInt64(totalPasses)
            inputBlock[5] = 2  // Argon2id type
        }

        var prevIndex = (lane * laneLength + slice * segmentLength + startIndex - 1)
        if prevIndex < lane * laneLength {
            prevIndex = (lane + 1) * laneLength - 1
        }

        for s in startIndex..<segmentLength {
            let currentIndex = lane * laneLength + slice * segmentLength + s

            // Get pseudo-random J1, J2
            let j1: UInt64
            let j2: UInt64

            if useDataIndependent {
                // RFC 9106 §3.3: one address block yields 128 (J1,J2) pairs — one
                // per 64-bit word (J1=low 32, J2=high 32). Regenerate per 128-block
                // chunk of the segment; the chunk counter is 1-indexed.
                let chunk = s / 128
                if chunk != addressChunk {
                    addressChunk = chunk
                    inputBlock[6] = UInt64(chunk + 1)
                    var zeroBlock = [UInt64](repeating: 0, count: 128)
                    addressBlock = compressG(&zeroBlock, inputBlock)
                    addressBlock = compressG(&zeroBlock, addressBlock)
                }
                let w = addressBlock[s % 128]
                j1 = w & 0xFFFFFFFF
                j2 = w >> 32
            } else {
                // Data-dependent: J1=low 32, J2=high 32 of the FIRST word of the
                // previous block (a single word split — not two separate words).
                let w = blocks[prevIndex][0]
                j1 = w & 0xFFFFFFFF
                j2 = w >> 32
            }

            // Compute reference block index (RFC 9106 §3.4.2)
            let refLane: Int
            if pass == 0 && slice == 0 {
                refLane = lane
            } else {
                refLane = Int(j2 % UInt64(lanes))
            }

            // Reference set size
            let referenceAreaSize: Int
            if pass == 0 {
                if slice == 0 {
                    referenceAreaSize = s - 1
                } else if refLane == lane {
                    referenceAreaSize = slice * segmentLength + s - 1
                } else {
                    referenceAreaSize = slice * segmentLength - (s == 0 ? 1 : 0)
                }
            } else {
                if refLane == lane {
                    referenceAreaSize = laneLength - segmentLength + s - 1
                } else {
                    referenceAreaSize = laneLength - segmentLength - (s == 0 ? 1 : 0)
                }
            }

            guard referenceAreaSize > 0 else {
                prevIndex = currentIndex
                continue
            }

            // Map J1 to an index within the reference area.
            // NOTE: in Swift, `>>` binds tighter than `&*`, so `ras &* y >> 32`
            // would parse as `ras &* (y >> 32)` (== 0, since y < 2^32) and pin z
            // to ras-1 every time — non-standard. Parenthesize the multiply.
            let x = j1 & 0xFFFFFFFF
            let y = (x &* x) >> 32
            let z = UInt64(referenceAreaSize) - 1 - ((UInt64(referenceAreaSize) &* y) >> 32)

            let startPosition: Int
            if pass == 0 {
                startPosition = 0
            } else {
                startPosition = ((slice + 1) % 4) * segmentLength
            }

            let refIndex = refLane * laneLength + (startPosition + Int(z)) % laneLength

            // Compress: B[current] = G(B[prev], B[ref]) XOR B[current] (for pass > 0)
            var compressed = compressG(&blocks[prevIndex], blocks[refIndex])
            if pass > 0 {
                for i in 0..<128 {
                    compressed[i] ^= blocks[currentIndex][i]
                }
            }
            blocks[currentIndex] = compressed

            prevIndex = currentIndex
        }
    }

    // MARK: - Compression Function G (RFC 9106 §3.5)

    /// The G compression function. Takes two 1024-byte blocks, returns one 1024-byte block.
    /// G(X, Y) = P(X XOR Y) XOR (X XOR Y)
    /// where P is a permutation operating on 8x8 matrices of 16-byte values.
    private static func compressG(_ x: inout [UInt64], _ y: [UInt64]) -> [UInt64] {
        // R = X XOR Y
        var r = [UInt64](repeating: 0, count: 128)
        for i in 0..<128 {
            r[i] = x[i] ^ y[i]
        }

        // Save Z = R for final XOR
        let z = r

        // Apply P: process as 8 rows of 128 bytes (16 UInt64 words) each
        // Then process columns

        // Row-wise: process 8 rows of 16 words (128 bytes) each
        for i in 0..<8 {
            let base = i * 16
            applyBlake2bRound(&r, v0: base, v1: base + 1, v2: base + 2, v3: base + 3,
                              v4: base + 4, v5: base + 5, v6: base + 6, v7: base + 7,
                              v8: base + 8, v9: base + 9, v10: base + 10, v11: base + 11,
                              v12: base + 12, v13: base + 13, v14: base + 14, v15: base + 15)
        }

        // Column-wise: process 8 columns
        for i in 0..<8 {
            let off = i * 2
            applyBlake2bRound(&r, v0: off, v1: off + 1, v2: off + 16, v3: off + 17,
                              v4: off + 32, v5: off + 33, v6: off + 48, v7: off + 49,
                              v8: off + 64, v9: off + 65, v10: off + 80, v11: off + 81,
                              v12: off + 96, v13: off + 97, v14: off + 112, v15: off + 113)
        }

        // Final: R = R XOR Z
        for i in 0..<128 {
            r[i] ^= z[i]
        }

        return r
    }

    /// Apply a BLAKE2b-like round (GB) to 16 words (two "rows" of the BLAKE2b state).
    private static func applyBlake2bRound(
        _ v: inout [UInt64],
        v0: Int, v1: Int, v2: Int, v3: Int,
        v4: Int, v5: Int, v6: Int, v7: Int,
        v8: Int, v9: Int, v10: Int, v11: Int,
        v12: Int, v13: Int, v14: Int, v15: Int
    ) {
        gb(&v, a: v0, b: v4, c: v8, d: v12)
        gb(&v, a: v1, b: v5, c: v9, d: v13)
        gb(&v, a: v2, b: v6, c: v10, d: v14)
        gb(&v, a: v3, b: v7, c: v11, d: v15)
        gb(&v, a: v0, b: v5, c: v10, d: v15)
        gb(&v, a: v1, b: v6, c: v11, d: v12)
        gb(&v, a: v2, b: v7, c: v8, d: v13)
        gb(&v, a: v3, b: v4, c: v9, d: v14)
    }

    /// GB mixing function (Argon2 variant of BLAKE2b's G).
    /// Uses multiplication instead of message injection.
    @inline(__always)
    private static func gb(_ v: inout [UInt64], a: Int, b: Int, c: Int, d: Int) {
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFFFFFF) &* (v[b] & 0xFFFFFFFF)
        v[d] = (v[d] ^ v[a]).rotateRight(32)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFFFFFF) &* (v[d] & 0xFFFFFFFF)
        v[b] = (v[b] ^ v[c]).rotateRight(24)
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFFFFFF) &* (v[b] & 0xFFFFFFFF)
        v[d] = (v[d] ^ v[a]).rotateRight(16)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFFFFFF) &* (v[d] & 0xFFFFFFFF)
        v[b] = (v[b] ^ v[c]).rotateRight(63)
    }

    // MARK: - BLAKE2b (RFC 7693)

    /// Full BLAKE2b hash with variable output length.
    /// Used as the core hash function in Argon2.
    static func blake2b(_ input: [UInt8], digestLength: Int) -> [UInt8] {
        // BLAKE2b IV
        let iv: [UInt64] = [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
        ]

        // Initialize state
        var h = iv
        // Parameter block: fanout=1, depth=1, digest_length, all else zero
        h[0] ^= 0x01010000 ^ UInt64(digestLength)

        // Process message blocks (128 bytes each)
        var offset = 0
        var bytesCompressed: UInt64 = 0

        while offset + 128 <= input.count {
            bytesCompressed += 128
            let block = Array(input[offset..<(offset + 128)])
            let m = bytesToWords(block)
            blake2bCompress(&h, m: m, t: bytesCompressed, f: (offset + 128 >= input.count))
            offset += 128
        }

        // Final block (padded with zeros)
        var lastBlock = [UInt8](repeating: 0, count: 128)
        let remaining = input.count - offset
        if remaining > 0 {
            lastBlock[0..<remaining] = input[offset..<input.count]
        }
        bytesCompressed += UInt64(remaining)
        let m = bytesToWords(lastBlock)
        blake2bCompress(&h, m: m, t: bytesCompressed, f: true)

        // Produce output
        var output = [UInt8]()
        for word in h {
            for i in 0..<8 {
                output.append(UInt8((word >> (i * 8)) & 0xFF))
            }
        }

        return Array(output.prefix(digestLength))
    }

    /// BLAKE2b compression function
    private static func blake2bCompress(_ h: inout [UInt64], m: [UInt64], t: UInt64, f: Bool) {
        let iv: [UInt64] = [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
        ]

        var v = [UInt64](repeating: 0, count: 16)
        v[0..<8] = h[0..<8]
        v[8..<16] = iv[0..<8]
        v[12] ^= t         // Low 64 bits of counter
        v[13] ^= 0         // High 64 bits of counter (always 0 for our use)
        if f {
            v[14] ^= ~UInt64(0)  // Finalization flag
        }

        // 12 rounds of mixing
        let sigma: [[Int]] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
            [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
            [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
            [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
            [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
            [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
            [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
            [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
            [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
        ]

        for round in 0..<12 {
            let s = sigma[round]
            blake2bG(&v, a: 0, b: 4, c: 8,  d: 12, x: m[s[0]],  y: m[s[1]])
            blake2bG(&v, a: 1, b: 5, c: 9,  d: 13, x: m[s[2]],  y: m[s[3]])
            blake2bG(&v, a: 2, b: 6, c: 10, d: 14, x: m[s[4]],  y: m[s[5]])
            blake2bG(&v, a: 3, b: 7, c: 11, d: 15, x: m[s[6]],  y: m[s[7]])
            blake2bG(&v, a: 0, b: 5, c: 10, d: 15, x: m[s[8]],  y: m[s[9]])
            blake2bG(&v, a: 1, b: 6, c: 11, d: 12, x: m[s[10]], y: m[s[11]])
            blake2bG(&v, a: 2, b: 7, c: 8,  d: 13, x: m[s[12]], y: m[s[13]])
            blake2bG(&v, a: 3, b: 4, c: 9,  d: 14, x: m[s[14]], y: m[s[15]])
        }

        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    /// BLAKE2b G mixing function (standard, with message words)
    @inline(__always)
    private static func blake2bG(_ v: inout [UInt64], a: Int, b: Int, c: Int, d: Int, x: UInt64, y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(63)
    }

    // MARK: - Helpers

    private static func uint32LE(_ value: UInt32) -> [UInt8] {
        return [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF)
        ]
    }

    private static func bytesToWords(_ bytes: [UInt8]) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: bytes.count / 8)
        for i in 0..<words.count {
            var val: UInt64 = 0
            for j in 0..<8 {
                val |= UInt64(bytes[i * 8 + j]) << (j * 8)
            }
            words[i] = val
        }
        return words
    }

    private static func blockToBytes(_ block: [UInt64]) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: block.count * 8)
        for i in 0..<block.count {
            for j in 0..<8 {
                bytes[i * 8 + j] = UInt8((block[i] >> (j * 8)) & 0xFF)
            }
        }
        return bytes
    }
}

// MARK: - UInt64 Rotate Extension

extension UInt64 {
    @inline(__always)
    func rotateRight(_ n: Int) -> UInt64 {
        return (self >> n) | (self << (64 - n))
    }
}
