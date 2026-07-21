// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Keccak.swift
// PGPony — Phase F (PQC), LibrePGP support.
//
// SHA-3 / SHAKE / cSHAKE / KMAC primitives. GnuPG's LibrePGP composite KEM
// combiner (common/kem.c) derives the key-encryption key with KMAC256, which is
// not available in CryptoKit and not exposed by liboqs's SHA3 API. This is a
// self-contained Keccak-f[1600] core plus the NIST SP 800-185 cSHAKE/KMAC
// framing, validated in KMACTests against NIST-derived KMAC256 vectors (and the
// SHA3-256 path against a known digest, cross-checking the permutation).
//
// Not performance-critical: it runs once per composite decryption.

import Foundation

enum Keccak {

    // MARK: - Keccak-f[1600] permutation (canonical "tiny_sha3" schedule)

    private static let rndc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rotc: [UInt64] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ]
    private static let piln: [Int] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ]

    @inline(__always) private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }

    private static func permute(_ st: inout [UInt64]) {
        var bc = [UInt64](repeating: 0, count: 5)
        for r in 0..<24 {
            // Theta
            for i in 0..<5 { bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20] }
            for i in 0..<5 {
                let t = bc[(i+4)%5] ^ rotl(bc[(i+1)%5], 1)
                var j = 0
                while j < 25 { st[j+i] ^= t; j += 5 }
            }
            // Rho + Pi
            var t = st[1]
            for i in 0..<24 {
                let j = piln[i]
                let tmp = st[j]
                st[j] = rotl(t, rotc[i])
                t = tmp
            }
            // Chi
            var j = 0
            while j < 25 {
                for i in 0..<5 { bc[i] = st[j+i] }
                for i in 0..<5 { st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5] }
                j += 5
            }
            // Iota
            st[0] ^= rndc[r]
        }
    }

    // MARK: - Sponge (rate 136 for the 256-bit-capacity functions)

    private static let rate = 136   // 1600/8 - 2*256/8 = 136 octets

    /// Absorb `input`, apply `domain` suffix padding, and squeeze `outLen` bytes.
    private static func sponge(_ input: [UInt8], domain: UInt8, outLen: Int) -> [UInt8] {
        var st = [UInt64](repeating: 0, count: 25)
        var pt = 0
        for b in input {
            st[pt >> 3] ^= UInt64(b) << UInt64(8 * (pt & 7))
            pt += 1
            if pt == rate { permute(&st); pt = 0 }
        }
        // Pad: domain suffix at pt, 0x80 at the last rate byte.
        st[pt >> 3] ^= UInt64(domain) << UInt64(8 * (pt & 7))
        st[(rate - 1) >> 3] ^= UInt64(0x80) << UInt64(8 * ((rate - 1) & 7))
        permute(&st)

        var out = [UInt8]()
        out.reserveCapacity(outLen)
        var op = 0
        while out.count < outLen {
            if op == rate { permute(&st); op = 0 }
            out.append(UInt8((st[op >> 3] >> UInt64(8 * (op & 7))) & 0xff))
            op += 1
        }
        return out
    }

    // MARK: - Public digests

    static func sha3_256(_ input: [UInt8]) -> [UInt8] { sponge(input, domain: 0x06, outLen: 32) }
    static func shake256(_ input: [UInt8], outLen: Int) -> [UInt8] { sponge(input, domain: 0x1f, outLen: outLen) }

    // MARK: - NIST SP 800-185 encodings

    /// left_encode(x): [n] || big-endian(x), n = byte length of x (min 1).
    private static func leftEncode(_ x: Int) -> [UInt8] {
        var v = x, bytes = [UInt8]()
        repeat { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 } while v > 0
        return [UInt8(bytes.count)] + bytes
    }
    /// right_encode(x): big-endian(x) || [n].
    private static func rightEncode(_ x: Int) -> [UInt8] {
        var v = x, bytes = [UInt8]()
        repeat { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 } while v > 0
        return bytes + [UInt8(bytes.count)]
    }
    /// encode_string(S): left_encode(bitlen(S)) || S.
    private static func encodeString(_ s: [UInt8]) -> [UInt8] {
        leftEncode(s.count * 8) + s
    }
    /// bytepad(X, w): left_encode(w) || X, zero-padded to a multiple of w.
    private static func bytePad(_ x: [UInt8], _ w: Int) -> [UInt8] {
        var out = leftEncode(w) + x
        while out.count % w != 0 { out.append(0) }
        return out
    }

    // MARK: - cSHAKE256 / KMAC256

    /// cSHAKE256(X, L bits, N, S). With empty N and S this is SHAKE256.
    static func cshake256(_ x: [UInt8], outLen: Int, functionName n: [UInt8], customization s: [UInt8]) -> [UInt8] {
        if n.isEmpty && s.isEmpty { return shake256(x, outLen: outLen) }
        let prefix = bytePad(encodeString(n) + encodeString(s), rate)
        // cSHAKE domain: two-bit "00" before pad10*1 -> suffix byte 0x04.
        return sponge(prefix + x, domain: 0x04, outLen: outLen)
    }

    /// KMAC256(key, data, L octets, customization). Matches GnuPG's compute_kmac256.
    static func kmac256(key: [UInt8], data: [UInt8], outLen: Int, customization s: [UInt8]) -> [UInt8] {
        let newX = bytePad(encodeString(key), rate) + data + rightEncode(outLen * 8)
        return cshake256(newX, outLen: outLen, functionName: Array("KMAC".utf8), customization: s)
    }
}
