// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// X448.swift
// PGPony
//
// v8.2.0 §1 (ML-KEM-1024 + X448 composite). X448 Diffie-Hellman (RFC 7748)
// over Curve448, hand-rolled in Swift.
//
// WHY HAND-ROLLED
// The 1024-level composite KEM (RFC 9980 algorithm 36) pairs ML-KEM-1024
// with X448, and nothing on iOS supplies the curve: CryptoKit stops at
// Curve25519, liboqs is KEMs only, and Android's answer (Bouncy Castle)
// does not exist here. The choice was a third-party dependency in the
// crypto core or our own implementation locked to the RFC's test vectors,
// and this codebase already prefers the latter (see Keccak.swift and the
// hand-built packet layer). X448Tests carries every vector RFC 7748
// publishes for this curve, plus cross-checks; the arithmetic below was
// additionally validated against an independent big-integer implementation
// on random inputs before it was transcribed into Swift. Do not modify any
// of it without re-running X448Tests.
//
// FIELD REPRESENTATION
// p = 2^448 - 2^224 - 1, elements as 16 limbs of 28 bits (little-endian
// limb order) held in UInt64. This is the standard Curve448 radix: a
// 28x28-bit product is at most 2^56, so a full 16-term schoolbook column
// accumulates to at most 16 * 2^56 = 2^60, comfortably inside UInt64 with
// no intermediate overflow. Reduction leans on the "golden ratio" shape of
// the prime: 2^448 = 2^224 + 1 (mod p), and 224 is exactly 8 limbs, so a
// column k >= 16 folds into columns k-16 and k-8 with two adds.
//
// CONSTANT-TIME NOTES
// The ladder performs the same operation sequence for every scalar: the
// conditional swap is arithmetic (XOR with a 0/all-ones mask derived from
// the key bit), there are no secret-dependent branches or array indices,
// and the final inversion is a fixed-exponent Fermat power. Swift makes no
// hard constant-time guarantees, but the same is true of the arithmetic in
// the platform's other hand-rolled primitives; this is best effort, and
// the secret being protected (a per-message ephemeral, or a subkey held in
// the Keychain) matches that posture.

import Foundation
import Security

enum X448 {

    /// Everything on this curve is 56 octets: scalars, u-coordinates,
    /// public keys, shared secrets.
    static let keyBytes = 56

    enum Failure: Error, LocalizedError {
        case badLength(field: String, expected: Int, got: Int)
        case zeroSharedSecret
        case randomnessUnavailable

        var errorDescription: String? {
            switch self {
            case let .badLength(field, expected, got):
                return "X448 \(field) has wrong size: expected \(expected) bytes, got \(got)."
            case .zeroSharedSecret:
                return "X448 produced an all-zero shared secret (low-order peer key)."
            case .randomnessUnavailable:
                return "X448 could not obtain secure random bytes."
            }
        }
    }

    // MARK: - Public API

    /// A fresh 56-byte private scalar from the system CSPRNG. Stored raw;
    /// clamping (RFC 7748 §5) happens inside scalar multiplication, so the
    /// stored form round-trips through packets unchanged.
    static func generatePrivateKey() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: keyBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, keyBytes, &bytes)
        guard status == errSecSuccess else { throw Failure.randomnessUnavailable }
        return Data(bytes)
    }

    /// Public key = X448(k, 5). The base point's u-coordinate is 5
    /// (RFC 7748 §4.2).
    static func publicKey(for privateKey: Data) throws -> Data {
        var base = [UInt8](repeating: 0, count: keyBytes)
        base[0] = 5
        return try scalarMultiply(scalar: privateKey, u: Data(base))
    }

    /// Diffie-Hellman agreement, with the RFC 7748 §6.2 all-zero output
    /// check: a low-order peer key collapses the shared secret to zero, and
    /// the RFC says implementations SHOULD reject that. The raw
    /// `scalarMultiply` below does NOT perform this check (the RFC's own
    /// scalar-multiplication test vectors need the unchecked primitive).
    static func sharedSecret(privateKey: Data, publicKey: Data) throws -> Data {
        let out = try scalarMultiply(scalar: privateKey, u: publicKey)
        var acc: UInt8 = 0
        for b in out { acc |= b }
        guard acc != 0 else { throw Failure.zeroSharedSecret }
        return out
    }

    /// RFC 7748 X448: clamp the scalar, run the Montgomery ladder over the
    /// peer u-coordinate, return the resulting u-coordinate. All inputs and
    /// outputs are 56-byte little-endian strings, exactly as they appear on
    /// the wire in OpenPGP composite key material.
    static func scalarMultiply(scalar: Data, u: Data) throws -> Data {
        guard scalar.count == keyBytes else {
            throw Failure.badLength(field: "scalar", expected: keyBytes, got: scalar.count)
        }
        guard u.count == keyBytes else {
            throw Failure.badLength(field: "u-coordinate", expected: keyBytes, got: u.count)
        }

        // Clamp (RFC 7748 §5): clear the low 2 bits, set the top bit.
        var k = [UInt8](scalar)
        k[0] &= 252
        k[55] |= 128

        let x1 = fromBytes([UInt8](u))
        var x2 = FEConst.one, z2 = FEConst.zero
        var x3 = x1,          z3 = FEConst.one
        var swap: UInt64 = 0

        var t = 447
        while t >= 0 {
            let kt = UInt64((k[t >> 3] >> (UInt8(t & 7))) & 1)
            swap ^= kt
            // 0 or all-ones, without branching on the key bit.
            let mask = 0 &- swap
            cswap(mask, &x2, &x3)
            cswap(mask, &z2, &z3)
            swap = kt

            let a  = addFE(x2, z2)
            let aa = mulFE(a, a)
            let b  = subFE(x2, z2)
            let bb = mulFE(b, b)
            let e  = subFE(aa, bb)
            let c  = addFE(x3, z3)
            let d  = subFE(x3, z3)
            let da = mulFE(d, a)
            let cb = mulFE(c, b)
            let s  = addFE(da, cb)
            x3 = mulFE(s, s)
            let m  = subFE(da, cb)
            z3 = mulFE(x1, mulFE(m, m))
            x2 = mulFE(aa, bb)
            z2 = mulFE(e, addFE(aa, mulSmall(e, 39081)))   // a24 = (156326-2)/4
            t -= 1
        }
        let mask = 0 &- swap
        cswap(mask, &x2, &x3)
        cswap(mask, &z2, &z3)

        return Data(toBytes(mulFE(x2, invert(z2))))
    }

    // MARK: - Field arithmetic (16 x 28-bit limbs in UInt64)

    private typealias FE = [UInt64]

    private static let nLimbs = 16
    private static let mask28: UInt64 = (1 << 28) - 1

    private enum FEConst {
        static let zero: FE = [UInt64](repeating: 0, count: 16)
        static var one: FE { var f = zero; f[0] = 1; return f }
    }

    /// p limbwise. p = (2^224 - 2) * 2^224 + (2^224 - 1), so limbs 0..7 and
    /// 9..15 are all-ones and limb 8 is one less.
    private static let pLimbs: FE = {
        var p = [UInt64](repeating: 0xFFFFFFF, count: 16)
        p[8] = 0xFFFFFFE
        return p
    }()

    private static func fromBytes(_ b: [UInt8]) -> FE {
        // Little-endian bits 28i..28i+27 per limb. Walk the bytes once,
        // spilling each into the limb(s) its bits land in.
        var f = [UInt64](repeating: 0, count: nLimbs)
        for i in 0..<56 {
            let bitPos = 8 * i
            let limb = bitPos / 28
            let off = bitPos % 28
            f[limb] |= (UInt64(b[i]) << UInt64(off)) & mask28
            if off > 20 && limb + 1 < nLimbs {
                f[limb + 1] |= UInt64(b[i]) >> UInt64(28 - off)
            }
        }
        return f
    }

    /// Carry-propagate to limbs < 2^28, folding the top carry back in via
    /// 2^448 = 2^224 + 1 (adds into limbs 0 and 8). Two passes: the first
    /// can leave a fold-induced carry, the second's own top carry is zero
    /// for every input range the operations here produce (validated against
    /// the big-integer model over the full vector set and random inputs).
    private static func norm(_ input: FE) -> FE {
        var c = input
        for _ in 0..<2 {
            var carry: UInt64 = 0
            for i in 0..<nLimbs {
                let v = c[i] &+ carry
                c[i] = v & mask28
                carry = v >> 28
            }
            c[0] &+= carry
            c[8] &+= carry
        }
        return c
    }

    private static func addFE(_ a: FE, _ b: FE) -> FE {
        var c = [UInt64](repeating: 0, count: nLimbs)
        for i in 0..<nLimbs { c[i] = a[i] &+ b[i] }
        return norm(c)
    }

    /// a - b, biased by 2p so every limb difference stays non-negative in
    /// unsigned arithmetic (inputs are normalized, so a[i] + 2p[i] always
    /// exceeds b[i]).
    private static func subFE(_ a: FE, _ b: FE) -> FE {
        var c = [UInt64](repeating: 0, count: nLimbs)
        for i in 0..<nLimbs { c[i] = a[i] &+ (2 &* pLimbs[i]) &- b[i] }
        return norm(c)
    }

    private static func mulFE(_ a: FE, _ b: FE) -> FE {
        // Schoolbook columns; see the header comment for the overflow
        // budget. Column k >= 16 folds into k-16 and k-8.
        var cols = [UInt64](repeating: 0, count: 2 * nLimbs - 1)
        for i in 0..<nLimbs {
            let ai = a[i]
            for j in 0..<nLimbs {
                cols[i + j] &+= ai &* b[j]
            }
        }
        var k = 2 * nLimbs - 2
        while k >= nLimbs {
            let v = cols[k]
            cols[k] = 0
            cols[k - 16] &+= v
            cols[k - 8]  &+= v
            k -= 1
        }
        return norm(Array(cols[0..<nLimbs]))
    }

    private static func mulSmall(_ a: FE, _ s: UInt64) -> FE {
        var c = [UInt64](repeating: 0, count: nLimbs)
        for i in 0..<nLimbs { c[i] = a[i] &* s }
        return norm(c)
    }

    /// Arithmetic conditional swap: mask is 0 or all-ones.
    private static func cswap(_ mask: UInt64, _ a: inout FE, _ b: inout FE) {
        for i in 0..<nLimbs {
            let t = mask & (a[i] ^ b[i])
            a[i] ^= t
            b[i] ^= t
        }
    }

    /// Fermat inversion a^(p-2). The exponent is a fixed public constant,
    /// so plain square-and-multiply over its bits leaks nothing secret.
    private static func invert(_ a: FE) -> FE {
        // p - 2 = 2^448 - 2^224 - 3: bits 448.. are zero; bit pattern below
        // is consumed most-significant first.
        var result = FEConst.one
        let base = a
        var bit = 447
        while bit >= 0 {
            result = mulFE(result, result)
            if pMinus2Bit(bit) {
                result = mulFE(result, base)
            }
            bit -= 1
        }
        return result
    }

    /// Bit `i` of p - 2 = 2^448 - 2^224 - 3. Derivation: the value is
    /// (2^224 - 2) * 2^224 + (2^224 - 3), i.e. the low 224 bits are
    /// 0b111...101 (bit 1 clear) and the high 224 bits are 0b111...110
    /// (bit 224 clear), with everything else set.
    private static func pMinus2Bit(_ i: Int) -> Bool {
        if i == 1 || i == 224 { return false }
        return i >= 0 && i < 448
    }

    /// Canonical little-endian serialization: normalize (value < 2^448),
    /// then one constant-time conditional subtract of p (2p > 2^448, so
    /// once is enough).
    private static func toBytes(_ input: FE) -> [UInt8] {
        let c = norm(input)
        var d = [UInt64](repeating: 0, count: nLimbs)
        var borrow: UInt64 = 0
        for i in 0..<nLimbs {
            let t = c[i] &- pLimbs[i] &- borrow
            borrow = (t >> 63) & 1
            d[i] = t &+ (borrow << 28)
            d[i] &= mask28
        }
        // borrow == 0 means c >= p: use the subtracted form.
        let useD = 0 &- (1 &- borrow)
        var out = [UInt8](repeating: 0, count: 56)
        var acc: UInt64 = 0
        var accBits = 0
        var byteIdx = 0
        for i in 0..<nLimbs {
            let limb = (d[i] & useD) | (c[i] & ~useD)
            acc |= limb << UInt64(accBits)
            accBits += 28
            while accBits >= 8 && byteIdx < 56 {
                out[byteIdx] = UInt8(acc & 0xFF)
                acc >>= 8
                accBits -= 8
                byteIdx += 1
            }
        }
        return out
    }
}
