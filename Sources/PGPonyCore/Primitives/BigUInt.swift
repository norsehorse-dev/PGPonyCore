// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BigUInt.swift
// PGPony
//
// 8.4.0 build 7 (plan K3, K4): the integer arithmetic under the DSA and
// brainpool ECDSA verifiers. CryptoKit and Security offer neither DSA nor
// the brainpool curves, so PGPony does this itself: an unsigned big integer
// with 32-bit limbs, and Montgomery multiplication (CIOS) for all modular
// work, so no general long division is needed (a remainder is taken bit by
// bit, which is only used to set up a modulus and for a final reduction).
//
// The Montgomery multiply, add and subtract are branch-free (masked final
// subtraction), so secret field elements do not steer control flow; the
// brainpool ECDH and key generation path (`BrainpoolCurve.multiplySecret`, a
// Montgomery ladder over complete addition formulas) relies on that. The
// rest (remainder, comparison, `inverse`, and `power`, whose timing follows
// its exponent) is variable time and only ever sees public values or public
// exponents.
//
// `nonisolated`: plain value arithmetic, callable from any thread (the
// verifiers also run inside `runOffMainThread` work).

import Foundation

nonisolated struct BigUInt: Equatable, Comparable, Sendable {

    /// Little-endian 32-bit limbs with no zero limbs at the top; zero is [].
    private(set) var limbs: [UInt32]

    init() { limbs = [] }

    init(_ value: UInt32) { limbs = value == 0 ? [] : [value] }

    init(limbs: [UInt32]) {
        var trimmed = limbs
        while let top = trimmed.last, top == 0 { trimmed.removeLast() }
        self.limbs = trimmed
    }

    /// A big-endian octet string (an MPI body, a point coordinate, a digest).
    init(bytes: [UInt8]) {
        var out = [UInt32](repeating: 0, count: (bytes.count + 3) / 4)
        var shift: UInt32 = 0
        var index = 0
        for byte in bytes.reversed() {
            out[index] |= UInt32(byte) << shift
            shift += 8
            if shift == 32 {
                shift = 0
                index += 1
            }
        }
        self.init(limbs: out)
    }

    /// Big-endian hexadecimal (the curve constants); nil on a non-hex character.
    init?(hex: String) {
        var digits = Array(hex.utf8)
        if digits.count % 2 == 1 { digits.insert(UInt8(ascii: "0"), at: 0) }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        var i = 0
        while i < digits.count {
            guard let high = Self.hexValue(digits[i]), let low = Self.hexValue(digits[i + 1]) else { return nil }
            bytes.append(high << 4 | low)
            i += 2
        }
        self.init(bytes: bytes)
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    // MARK: - Properties

    var isZero: Bool { limbs.isEmpty }

    var isOdd: Bool { (limbs.first ?? 0) & 1 == 1 }

    /// The position of the highest set bit plus one; 0 for zero.
    var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return limbs.count * 32 - top.leadingZeroBitCount
    }

    /// Bit `index` (0 is the least significant).
    func bit(_ index: Int) -> Bool {
        guard index >= 0 else { return false }
        let limb = index / 32
        guard limb < limbs.count else { return false }
        return (limbs[limb] >> UInt32(index % 32)) & 1 == 1
    }

    /// Big-endian octets left-padded with zeros to `length`; nil when the
    /// value does not fit.
    func bytes(length: Int) -> [UInt8]? {
        guard (bitWidth + 7) / 8 <= length else { return nil }
        var out = [UInt8](repeating: 0, count: length)
        let available = min(length, limbs.count * 4)
        for i in 0..<available {
            out[length - 1 - i] = UInt8(truncatingIfNeeded: limbs[i / 4] >> UInt32(8 * (i % 4)))
        }
        return out
    }

    /// Big-endian octets with no leading zero octet (empty for zero).
    var minimalBytes: [UInt8] { bytes(length: (bitWidth + 7) / 8) ?? [] }

    // MARK: - Comparison

    /// -1, 0 or 1 as `lhs` is less than, equal to or greater than `rhs`.
    static func compare(_ lhs: BigUInt, _ rhs: BigUInt) -> Int {
        if lhs.limbs.count != rhs.limbs.count { return lhs.limbs.count < rhs.limbs.count ? -1 : 1 }
        var i = lhs.limbs.count - 1
        while i >= 0 {
            if lhs.limbs[i] != rhs.limbs[i] { return lhs.limbs[i] < rhs.limbs[i] ? -1 : 1 }
            i -= 1
        }
        return 0
    }

    static func < (lhs: BigUInt, rhs: BigUInt) -> Bool { compare(lhs, rhs) < 0 }

    // MARK: - Arithmetic

    static func + (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let count = max(lhs.limbs.count, rhs.limbs.count)
        var out = [UInt32](repeating: 0, count: count + 1)
        var carry: UInt64 = 0
        for i in 0..<count {
            let x = UInt64(i < lhs.limbs.count ? lhs.limbs[i] : 0)
            let y = UInt64(i < rhs.limbs.count ? rhs.limbs[i] : 0)
            let sum = x + y + carry
            out[i] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        out[count] = UInt32(truncatingIfNeeded: carry)
        return BigUInt(limbs: out)
    }

    /// `lhs - rhs`; `lhs` must not be smaller than `rhs`.
    static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        precondition(lhs >= rhs, "BigUInt subtraction would go below zero")
        var out = lhs.limbs
        var borrow: UInt64 = 0
        for i in 0..<out.count {
            let x = UInt64(out[i])
            let y = UInt64(i < rhs.limbs.count ? rhs.limbs[i] : 0) + borrow
            if x >= y {
                out[i] = UInt32(truncatingIfNeeded: x - y)
                borrow = 0
            } else {
                out[i] = UInt32(truncatingIfNeeded: x + 0x1_0000_0000 - y)
                borrow = 1
            }
        }
        return BigUInt(limbs: out)
    }

    func shiftedLeft(by bits: Int) -> BigUInt {
        guard !isZero, bits > 0 else { return self }
        let limbShift = bits / 32
        let bitShift = UInt64(bits % 32)
        var out = [UInt32](repeating: 0, count: limbs.count + limbShift + 1)
        for i in 0..<limbs.count {
            let wide = UInt64(limbs[i]) << bitShift
            out[i + limbShift] |= UInt32(truncatingIfNeeded: wide)
            out[i + limbShift + 1] |= UInt32(truncatingIfNeeded: wide >> 32)
        }
        return BigUInt(limbs: out)
    }

    func shiftedRight(by bits: Int) -> BigUInt {
        guard bits > 0 else { return self }
        let limbShift = bits / 32
        let bitShift = UInt64(bits % 32)
        guard limbShift < limbs.count else { return BigUInt() }
        var out = [UInt32](repeating: 0, count: limbs.count - limbShift)
        for i in 0..<out.count {
            let low = UInt64(limbs[i + limbShift])
            let high: UInt64 = i + limbShift + 1 < limbs.count ? UInt64(limbs[i + limbShift + 1]) : 0
            out[i] = UInt32(truncatingIfNeeded: ((high << 32) | low) >> bitShift)
        }
        return BigUInt(limbs: out)
    }

    /// `self mod modulus`, one bit at a time (cost: bit width of self times
    /// the limbs of the modulus). `modulus` must not be zero.
    func remainder(dividingBy modulus: BigUInt) -> BigUInt {
        precondition(!modulus.isZero, "BigUInt remainder by zero")
        if self < modulus { return self }
        let one = BigUInt(1)
        var rest = BigUInt()
        var i = bitWidth - 1
        while i >= 0 {
            rest = rest.shiftedLeft(by: 1)
            if bit(i) { rest = rest + one }
            if rest >= modulus { rest = rest - modulus }
            i -= 1
        }
        return rest
    }

    /// The leftmost `count` bits of a digest as an integer: the hash
    /// truncation of FIPS 186-5 (DSA, section 4.6; ECDSA, section 6.4.2)
    /// and SEC 1 section 4.1.4. A shorter digest is taken whole.
    static func leftmostBits(of digest: [UInt8], count: Int) -> BigUInt {
        let value = BigUInt(bytes: digest)
        let available = digest.count * 8
        return available > count ? value.shiftedRight(by: available - count) : value
    }
}

// MARK: - Montgomery arithmetic modulo an odd number

/// Arithmetic modulo an odd `modulus` m with n limbs, in Montgomery form
/// (x is held as x * R mod m, R = 2^(32 n)). Elements are n-limb arrays,
/// fully reduced (below m). `multiply` is CIOS (coarsely integrated operand
/// scanning, Koc, Acar and Kaliski 1996).
nonisolated struct MontgomeryModulus: Sendable {

    let modulus: BigUInt
    let limbCount: Int
    private let m: [UInt32]
    /// -m^-1 mod 2^32.
    private let mPrime: UInt32
    /// R^2 mod m, which takes a value into Montgomery form.
    private let rSquared: [UInt32]
    /// R mod m: one in Montgomery form.
    let one: [UInt32]
    /// Zero, n limbs.
    let zero: [UInt32]

    /// Nil unless `modulus` is odd and at least 3.
    init?(_ modulus: BigUInt) {
        guard modulus.isOdd, modulus.bitWidth >= 2 else { return nil }
        let n = modulus.limbs.count
        let low = modulus.limbs[0]
        // Newton's iteration for low^-1 mod 2^32: low * low is 1 mod 8, so
        // `low` is right to 3 bits, and each step doubles that.
        var inverse = low
        for _ in 0..<5 { inverse = inverse &* (2 &- low &* inverse) }
        self.modulus = modulus
        self.limbCount = n
        self.m = modulus.limbs
        self.mPrime = 0 &- inverse
        let r = BigUInt(limbs: [UInt32](repeating: 0, count: n) + [1])
        let r2 = BigUInt(limbs: [UInt32](repeating: 0, count: 2 * n) + [1])
        self.one = Self.padded(r.remainder(dividingBy: modulus), to: n)
        self.rSquared = Self.padded(r2.remainder(dividingBy: modulus), to: n)
        self.zero = [UInt32](repeating: 0, count: n)
    }

    static func padded(_ value: BigUInt, to count: Int) -> [UInt32] {
        precondition(value.limbs.count <= count, "value wider than the modulus")
        return value.limbs + [UInt32](repeating: 0, count: count - value.limbs.count)
    }

    // MARK: Montgomery-form elements

    /// a * b * R^-1 mod m. Both are n limbs; `b` must be below m (`a` may
    /// be any n-limb value), so the result needs at most one subtraction.
    func multiply(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let n = limbCount
        let mPrime = self.mPrime
        var t = [UInt32](repeating: 0, count: n + 2)
        t.withUnsafeMutableBufferPointer { t in
            a.withUnsafeBufferPointer { a in
                b.withUnsafeBufferPointer { b in
                    m.withUnsafeBufferPointer { m in
                        for i in 0..<n {
                            // t += a[i] * b
                            let ai = UInt64(a[i])
                            var carry: UInt64 = 0
                            for j in 0..<n {
                                let sum = UInt64(t[j]) + ai * UInt64(b[j]) + carry
                                t[j] = UInt32(truncatingIfNeeded: sum)
                                carry = sum >> 32
                            }
                            var sum = UInt64(t[n]) + carry
                            t[n] = UInt32(truncatingIfNeeded: sum)
                            t[n + 1] = UInt32(truncatingIfNeeded: sum >> 32)

                            // t = (t + q * m) / 2^32, q chosen so the low limb is 0
                            let q = UInt64(t[0] &* mPrime)
                            sum = UInt64(t[0]) + q * UInt64(m[0])
                            carry = sum >> 32
                            var j = 1
                            while j < n {
                                sum = UInt64(t[j]) + q * UInt64(m[j]) + carry
                                t[j - 1] = UInt32(truncatingIfNeeded: sum)
                                carry = sum >> 32
                                j += 1
                            }
                            sum = UInt64(t[n]) + carry
                            t[n - 1] = UInt32(truncatingIfNeeded: sum)
                            t[n] = t[n + 1] &+ UInt32(truncatingIfNeeded: sum >> 32)
                        }
                    }
                }
            }
        }
        // 8.4.0 build 7 wave 2 (plan K3): the final subtraction is a masked
        // select, not a branch, so a secret operand (brainpool ECDH and key
        // generation) does not steer control flow. The result is below 2m,
        // so t[n] is 0 or 1.
        let low = Array(t[0..<n])
        let (reduced, borrow) = Self.subtractWrapping(low, m)
        let useReduced = UInt32(truncatingIfNeeded: (UInt64(t[n]) | (borrow ^ 1)) & 1)
        return Self.select(mask: 0 &- useReduced, reduced, low)
    }

    /// (a + b) mod m for elements below m. Branch-free.
    func add(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let (sum, carry) = Self.addWrapping(a, b)
        let (reduced, borrow) = Self.subtractWrapping(sum, m)
        let useReduced = UInt32(truncatingIfNeeded: (carry | (borrow ^ 1)) & 1)
        return Self.select(mask: 0 &- useReduced, reduced, sum)
    }

    /// (a - b) mod m for elements below m. Branch-free.
    func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let (difference, borrow) = Self.subtractWrapping(a, b)
        let fixed = Self.addWrapping(difference, m).value
        return Self.select(mask: 0 &- UInt32(truncatingIfNeeded: borrow), fixed, difference)
    }

    /// `a` where `mask` is all ones, `b` where it is zero, limb by limb.
    static func select(mask: UInt32, _ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = b
        for i in 0..<out.count { out[i] = (a[i] & mask) | (b[i] & ~mask) }
        return out
    }

    /// Swap `a` and `b` where `mask` is all ones, leave them where it is zero.
    static func conditionalSwap(mask: UInt32, _ a: inout [UInt32], _ b: inout [UInt32]) {
        for i in 0..<a.count {
            let d = (a[i] ^ b[i]) & mask
            a[i] ^= d
            b[i] ^= d
        }
    }

    func isZero(_ a: [UInt32]) -> Bool { a.allSatisfy { $0 == 0 } }

    /// x into Montgomery form (x reduced first when it is wider than m).
    func toMontgomery(_ x: BigUInt) -> [UInt32] {
        let reduced = x.limbs.count > limbCount ? x.remainder(dividingBy: modulus) : x
        return multiply(Self.padded(reduced, to: limbCount), rSquared)
    }

    func fromMontgomery(_ a: [UInt32]) -> BigUInt {
        var unit = zero
        unit[0] = 1
        return BigUInt(limbs: multiply(a, unit))
    }

    /// base^exponent for a Montgomery-form base, with a fixed 4-bit window.
    func power(_ base: [UInt32], _ exponent: BigUInt) -> [UInt32] {
        let bits = exponent.bitWidth
        guard bits > 0 else { return one }
        var table: [[UInt32]] = [one, base]
        for i in 2..<16 { table.append(multiply(table[i - 1], base)) }
        var accumulator = one
        var window = (bits + 3) / 4 - 1
        var first = true
        while window >= 0 {
            if !first {
                for _ in 0..<4 { accumulator = multiply(accumulator, accumulator) }
            }
            first = false
            var digit = 0
            for k in 0..<4 where exponent.bit(window * 4 + k) { digit |= 1 << k }
            if digit != 0 { accumulator = multiply(accumulator, table[digit]) }
            window -= 1
        }
        return accumulator
    }

    // MARK: Plain integers

    /// (a * b) mod m.
    func multiplyMod(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        let reducedB = b < modulus ? b : b.remainder(dividingBy: modulus)
        return BigUInt(limbs: multiply(toMontgomery(a), Self.padded(reducedB, to: limbCount)))
    }

    /// (a + b) mod m.
    func addMod(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        (a + b).remainder(dividingBy: modulus)
    }

    /// base^exponent mod m.
    func powerMod(_ base: BigUInt, _ exponent: BigUInt) -> BigUInt {
        fromMontgomery(power(toMontgomery(base), exponent))
    }

    /// x^-1 mod m for a PRIME modulus, by Fermat (x^(m-2)). Nil when x is 0
    /// mod m, or when the result does not check out (m was not prime).
    func inverse(_ x: BigUInt) -> BigUInt? {
        let reduced = x < modulus ? x : x.remainder(dividingBy: modulus)
        guard !reduced.isZero else { return nil }
        let candidate = powerMod(reduced, modulus - BigUInt(2))
        guard multiplyMod(reduced, candidate) == BigUInt(1) else { return nil }
        return candidate
    }

    // MARK: Limb helpers (equal-length little-endian arrays)

    /// (a + b) mod 2^(32 n), and the carry out of the top limb.
    private static func addWrapping(_ a: [UInt32], _ b: [UInt32]) -> (value: [UInt32], carry: UInt64) {
        var out = a
        var carry: UInt64 = 0
        for i in 0..<a.count {
            let sum = UInt64(a[i]) + UInt64(b[i]) + carry
            out[i] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        return (out, carry)
    }

    /// (a - b) mod 2^(32 n), and the borrow out of the top limb.
    private static func subtractWrapping(_ a: [UInt32], _ b: [UInt32]) -> (value: [UInt32], borrow: UInt64) {
        var out = a
        var borrow: UInt64 = 0
        for i in 0..<a.count {
            let difference = UInt64(a[i]) &- UInt64(b[i]) &- borrow
            out[i] = UInt32(truncatingIfNeeded: difference)
            borrow = difference >> 63
        }
        return (out, borrow)
    }
}
