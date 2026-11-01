// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Ed448.swift
// PGPony
//
// 8.4.0 build 8 (plan 2, Android 4.6.0 item 3): Ed448 signatures (RFC 8032
// section 5.2), hand-rolled in Swift on top of the curve448 field arithmetic
// in X448.swift.
//
// WHY
// RFC 9980 algorithm 31 (ML-DSA-87 + Ed448) needs an Ed448 half, and nothing
// on iOS supplies one: CryptoKit stops at Curve25519. The field (p = 2^448 -
// 2^224 - 1, 16 limbs of 28 bits) is already here, locked by X448Tests, so
// this file adds only the Edwards layer, the scalar arithmetic mod L and the
// RFC 8032 framing. Everything below was first written as a Python prototype
// that models the X448 limb arithmetic exactly (wrapping UInt64, with an
// overflow check on every intermediate) and checked against every pure Ed448
// vector in RFC 8032 section 7.4, against OpenSSL's Ed448 (Python
// `cryptography`) on random keys and messages, and against the Ed448 halves
// of a Sequoia-made ML-DSA-87 + Ed448 certificate. This Swift follows that
// prototype line for line. Build8Ed448Tests carries the same vectors.
//
// WHAT IS IMPLEMENTED
// Pure Ed448 with an empty context, the only form RFC 9980 uses (Section
// 5.1.1: PureEdDSA over the signature digest, empty context). Unlike
// Ed25519, pure Ed448 always hashes dom4(0, context) in front, so with the
// empty context the prefix is "SigEd448" || 0x00 || 0x00. Android's
// CompositeSigner does the same through Bouncy Castle's Ed448Signer(empty
// context). Ed448ph and non-empty contexts are not offered.
//
// CURVE
// The untwisted Edwards curve x^2 + y^2 = 1 + d x^2 y^2, d = -39081, in
// projective coordinates (X : Y : Z). RFC 8032 section 5.2.4 gives the
// addition and doubling formulas used here; with d a non-square the addition
// law is complete, so the ladder needs no special cases for the identity or
// for adding a point to itself.
//
// STRICT VERIFICATION
// A public key or R that does not decode (bits 448..454 set, y >= p, no
// square root, x = 0 with the sign bit set) fails; S >= L fails (signature
// malleability); then the cofactored equation [4][S]B = [4]R + [4][k]A of
// RFC 8032 section 5.2.7 must hold. Honest signatures pass both the
// cofactored and the cofactorless forms.
//
// CONSTANT-TIME NOTES
// Key derivation and signing multiply by the secret scalar s and the secret
// nonce r. Both go through `ladder`, which runs a fixed 448-step sequence
// with arithmetic conditional swaps (X448.cswap) and no branch or array index
// that depends on a secret bit. Reduction mod L is a fixed-length
// shift-and-conditional-subtract with masks, and the schoolbook k * s + r
// product has a fixed shape. Verification handles only public data. As with
// X448.swift, Swift itself makes no hard constant-time guarantees; this is
// best effort with no secret-dependent control flow.

import Foundation

enum Ed448 {

    /// The secret key is a 57-octet seed; public keys are 57 octets;
    /// signatures are R (57 octets) || S (57 octets).
    static let seedBytes = 57
    static let publicKeyBytes = 57
    static let signatureBytes = 114

    enum Failure: Error, LocalizedError {
        case badLength(field: String, expected: Int, got: Int)

        var errorDescription: String? {
            switch self {
            case let .badLength(field, expected, got):
                return String(localized: "Ed448 \(field) has wrong size: expected \(String(describing: expected)) bytes, got \(String(describing: got)).")
            }
        }
    }

    // MARK: - Public API

    /// A fresh 57-octet seed from the system CSPRNG.
    static func generateSeed() throws -> [UInt8] {
        try SecureRandom.bytes(seedBytes)
    }

    /// The public key A = [s]B for a 57-octet seed (RFC 8032 5.2.5).
    static func publicKey(seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedBytes else {
            throw Failure.badLength(field: "seed", expected: seedBytes, got: seed.count)
        }
        let (s, _) = expand(seed)
        return encode(ladder(Array(s[0..<56]), basePoint))
    }

    /// Pure Ed448, empty context (RFC 8032 5.2.6). The public key is always
    /// derived from the seed, never taken from the caller, so a mismatched
    /// public key can never be hashed into a signature.
    static func sign(message: [UInt8], seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedBytes else {
            throw Failure.badLength(field: "seed", expected: seedBytes, got: seed.count)
        }
        let (s, prefix) = expand(seed)
        let a = encode(ladder(Array(s[0..<56]), basePoint))
        let r = reduceModL(Keccak.shake256(dom4 + prefix + message, outLen: 114))
        let rEncoded = encode(ladder(Array(r[0..<56]), basePoint))
        let k = reduceModL(Keccak.shake256(dom4 + rEncoded + a + message, outLen: 114))
        let sScalar = reduceModL(mulAdd(k, s, r))
        return rEncoded + sScalar
    }

    /// Pure Ed448 verification, empty context (RFC 8032 5.2.7), strict:
    /// both points must decode canonically and S must be below L.
    static func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard publicKey.count == publicKeyBytes, signature.count == signatureBytes else { return false }
        guard let a = decode(publicKey) else { return false }
        let rBytes = Array(signature[0..<57])
        guard let r = decode(rBytes) else { return false }
        let sBytes = Array(signature[57..<114])
        guard reduceModL(sBytes) == sBytes else { return false }   // S >= L
        let k = reduceModL(Keccak.shake256(dom4 + rBytes + publicKey + message, outLen: 114))
        let sB = ladder(Array(sBytes[0..<56]), basePoint)
        let kA = ladder(Array(k[0..<56]), negate(a))
        // [4]([S]B - [k]A - R) must be the identity (0 : Z : Z).
        var q = add(add(sB, kA), negate(r))
        q = double(double(q))
        return X448.toBytes(q.x).allSatisfy { $0 == 0 } && X448.toBytes(q.y) == X448.toBytes(q.z)
    }

    // MARK: - RFC 8032 framing

    /// dom4(0, "") = "SigEd448" || octet(0) || octet(0).
    private static let dom4: [UInt8] = Array("SigEd448".utf8) + [0, 0]

    /// SHAKE256(seed, 114): the low 57 octets, pruned, are the secret scalar
    /// s; the high 57 octets are the nonce prefix.
    private static func expand(_ seed: [UInt8]) -> (scalar: [UInt8], prefix: [UInt8]) {
        let h = Keccak.shake256(seed, outLen: 114)
        var s = Array(h[0..<57])
        s[0] &= 0xFC
        s[55] |= 0x80
        s[56] = 0
        return (s, Array(h[57..<114]))
    }

    // MARK: - Points

    private typealias FE = X448.FE

    private struct Point {
        var x: FE
        var y: FE
        var z: FE
    }

    private static let identity = Point(x: X448.FEConst.zero, y: X448.FEConst.one, z: X448.FEConst.one)

    /// RFC 8032 5.2 base point B, coordinates as 56 little-endian octets.
    private static let basePoint = Point(
        x: X448.fromBytes(hexBytes("5ec00cc72ba826268e93008be1803b431165b62af71aae1264a4d3a324e36dea67170f477065149eda36bf22a6151d22ed0ded6bc670194f")),
        y: X448.fromBytes(hexBytes("14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69")),
        z: X448.FEConst.one)

    private static func hexBytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16) ?? 0)
            index = next
        }
        return out
    }

    /// d * a with d = -39081.
    private static func mulD(_ a: FE) -> FE {
        X448.subFE(X448.FEConst.zero, X448.mulSmall(a, 39081))
    }

    private static func neg(_ a: FE) -> FE {
        X448.subFE(X448.FEConst.zero, a)
    }

    private static func negate(_ p: Point) -> Point {
        Point(x: neg(p.x), y: p.y, z: p.z)
    }

    /// RFC 8032 5.2.4 addition (complete on this curve).
    private static func add(_ p: Point, _ q: Point) -> Point {
        let a = X448.mulFE(p.z, q.z)
        let b = X448.mulFE(a, a)
        let c = X448.mulFE(p.x, q.x)
        let d = X448.mulFE(p.y, q.y)
        let e = mulD(X448.mulFE(c, d))
        let f = X448.subFE(b, e)
        let g = X448.addFE(b, e)
        let h = X448.mulFE(X448.addFE(p.x, p.y), X448.addFE(q.x, q.y))
        let x3 = X448.mulFE(X448.mulFE(a, f), X448.subFE(X448.subFE(h, c), d))
        let y3 = X448.mulFE(X448.mulFE(a, g), X448.subFE(d, c))
        let z3 = X448.mulFE(f, g)
        return Point(x: x3, y: y3, z: z3)
    }

    /// RFC 8032 5.2.4 doubling.
    private static func double(_ p: Point) -> Point {
        let s = X448.addFE(p.x, p.y)
        let b = X448.mulFE(s, s)
        let c = X448.mulFE(p.x, p.x)
        let d = X448.mulFE(p.y, p.y)
        let e = X448.addFE(c, d)
        let h = X448.mulFE(p.z, p.z)
        let j = X448.subFE(e, X448.addFE(h, h))
        let x3 = X448.mulFE(X448.subFE(b, e), j)
        let y3 = X448.mulFE(e, X448.subFE(c, d))
        let z3 = X448.mulFE(e, j)
        return Point(x: x3, y: y3, z: z3)
    }

    private static func cswap(_ mask: UInt64, _ a: inout Point, _ b: inout Point) {
        X448.cswap(mask, &a.x, &b.x)
        X448.cswap(mask, &a.y, &b.y)
        X448.cswap(mask, &a.z, &b.z)
    }

    /// [k]P for a 56-octet little-endian scalar: a Montgomery ladder over the
    /// Edwards group. Every bit costs one addition and one doubling, and the
    /// swaps are arithmetic, so the sequence never depends on k.
    private static func ladder(_ k: [UInt8], _ p: Point) -> Point {
        precondition(k.count == 56)
        var r0 = identity
        var r1 = p
        var t = 447
        while t >= 0 {
            let bit = UInt64((k[t >> 3] >> UInt8(t & 7)) & 1)
            let mask = 0 &- bit
            cswap(mask, &r0, &r1)
            let sum = add(r0, r1)
            let twice = double(r0)
            r1 = sum
            r0 = twice
            cswap(mask, &r0, &r1)
            t -= 1
        }
        return r0
    }

    /// y as 57 little-endian octets, the low bit of x in bit 7 of the last.
    private static func encode(_ p: Point) -> [UInt8] {
        let zInverse = X448.invert(p.z)
        let x = X448.toBytes(X448.mulFE(p.x, zInverse))
        let y = X448.toBytes(X448.mulFE(p.y, zInverse))
        return y + [(x[0] & 1) << 7]
    }

    /// a^((p-3)/4). (p-3)/4 = 2^446 - 2^222 - 1: bits 0 to 445 set except
    /// bit 222. A fixed public exponent.
    private static func powP3Over4(_ a: FE) -> FE {
        var result = X448.FEConst.one
        var bit = 445
        while bit >= 0 {
            result = X448.mulFE(result, result)
            if bit != 222 {
                result = X448.mulFE(result, a)
            }
            bit -= 1
        }
        return result
    }

    /// RFC 8032 5.2.3 decoding, strict.
    private static func decode(_ b: [UInt8]) -> Point? {
        guard b.count == 57, b[56] & 0x7F == 0 else { return nil }
        let x0 = b[56] >> 7
        let yBytes = Array(b[0..<56])
        let y = X448.fromBytes(yBytes)
        guard X448.toBytes(y) == yBytes else { return nil }   // y >= p
        let one = X448.FEConst.one
        let yy = X448.mulFE(y, y)
        let u = X448.subFE(yy, one)
        let v = X448.subFE(mulD(yy), one)
        let u2 = X448.mulFE(u, u)
        let u3 = X448.mulFE(u2, u)
        let u5 = X448.mulFE(u3, u2)
        let v3 = X448.mulFE(X448.mulFE(v, v), v)
        var x = X448.mulFE(X448.mulFE(u3, v), powP3Over4(X448.mulFE(u5, v3)))
        guard X448.toBytes(X448.mulFE(v, X448.mulFE(x, x))) == X448.toBytes(u) else { return nil }
        let xBytes = X448.toBytes(x)
        if xBytes.allSatisfy({ $0 == 0 }) && x0 == 1 { return nil }
        if (xBytes[0] & 1) != x0 { x = neg(x) }
        return Point(x: x, y: y, z: one)
    }

    // MARK: - Scalars mod L

    private static let mask28: UInt64 = (1 << 28) - 1

    /// L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885,
    /// as 16 limbs of 28 bits, least significant first.
    private static let lLimbs: [UInt64] = [
        0xB5844F3, 0x78C292A, 0x58F5523, 0xC2728DC, 0x690216C, 0x49AED63, 0x9C44EDB, 0x7CCA23E,
        0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0x3FFFFFF,
    ]

    /// `b` (little-endian, any length) mod L, as 57 octets. Bit by bit from
    /// the top: r = 2r + bit, then subtract L under a mask when r >= L. r
    /// stays below 2L < 2^447, inside 16 limbs, and the work per bit is the
    /// same for every input.
    private static func reduceModL(_ b: [UInt8]) -> [UInt8] {
        var r = [UInt64](repeating: 0, count: 16)
        var d = [UInt64](repeating: 0, count: 16)
        var t = 8 * b.count - 1
        while t >= 0 {
            var carry = UInt64((b[t >> 3] >> UInt8(t & 7)) & 1)
            for i in 0..<16 {
                let v = (r[i] << 1) | carry
                r[i] = v & mask28
                carry = v >> 28
            }
            var borrow: UInt64 = 0
            for i in 0..<16 {
                let x = r[i] &- lLimbs[i] &- borrow
                borrow = (x >> 63) & 1
                d[i] = (x &+ (borrow << 28)) & mask28
            }
            // borrow == 0 means r >= L: keep the subtracted form.
            let keep = 0 &- (1 &- borrow)
            for i in 0..<16 {
                r[i] = (d[i] & keep) | (r[i] & ~keep)
            }
            t -= 1
        }
        var out = [UInt8](repeating: 0, count: 57)
        var acc: UInt64 = 0
        var accBits = 0
        var byteIndex = 0
        for i in 0..<16 {
            acc |= r[i] << UInt64(accBits)
            accBits += 28
            while accBits >= 8 && byteIndex < 57 {
                out[byteIndex] = UInt8(acc & 0xFF)
                acc >>= 8
                accBits -= 8
                byteIndex += 1
            }
        }
        return out
    }

    /// a * b + c over little-endian octet strings, schoolbook, fixed shape.
    /// Column sums stay below 57 * 255^2 + 255, far inside UInt64.
    private static func mulAdd(_ a: [UInt8], _ b: [UInt8], _ c: [UInt8]) -> [UInt8] {
        let n = a.count + b.count
        var columns = [UInt64](repeating: 0, count: n)
        for i in 0..<a.count {
            for j in 0..<b.count {
                columns[i + j] &+= UInt64(a[i]) &* UInt64(b[j])
            }
        }
        for i in 0..<c.count {
            columns[i] &+= UInt64(c[i])
        }
        var out = [UInt8](repeating: 0, count: n)
        var carry: UInt64 = 0
        for i in 0..<n {
            let v = columns[i] &+ carry
            out[i] = UInt8(v & 0xFF)
            carry = v >> 8
        }
        return out
    }
}
