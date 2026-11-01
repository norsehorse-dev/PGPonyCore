// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BrainpoolCurve.swift
// PGPony
//
// 8.4.0 build 7 (plan K3, K4): the brainpool curves (RFC 5639) and ECDSA
// verification on them, so signatures and self-signatures from GnuPG
// brainpool keys (OpenPGP algorithm 19 with a brainpool OID, RFC 6637 as
// extended by GnuPG) check instead of reading as uncheckable. CryptoKit has
// no brainpool, so the curve arithmetic is PGPony's own, on `BigUInt` and
// `MontgomeryModulus`.
//
// The curves are short Weierstrass, y^2 = x^3 + a x + b over a prime field,
// with cofactor 1. Unlike the NIST curves, a is NOT -3, so the doubling
// formula here is the general one (M = 3 X^2 + a Z^4). Points are added in
// Jacobian coordinates (x = X / Z^2, y = Y / Z^3) with Z = 0 for the point
// at infinity, and only converted back to affine at the end.
//
// `multiply` and `linearCombination` are variable time, for public scalars
// (verification). 8.4.0 build 7 wave 2 (plan K3): a secret scalar (the
// LibrePGP ML-KEM + brainpool composite's ECDH and key generation, see
// `BrainpoolECDH`) goes through `multiplySecret`, a Montgomery ladder over a
// fixed number of bits with masked swaps, using the complete addition
// formulas of Renes, Costello and Batina (2016, algorithm 1, any a) in
// homogeneous projective coordinates, so no point case (doubling, infinity)
// takes a different path. The field operations underneath are branch-free.

import Foundation
import Security

nonisolated struct BrainpoolCurve: Sendable {

    nonisolated enum Name: String, CaseIterable, Sendable {
        case p256r1 = "brainpoolP256r1"
        case p384r1 = "brainpoolP384r1"
        case p512r1 = "brainpoolP512r1"
    }

    /// An affine point; the point at infinity is represented by nil where
    /// it can occur.
    nonisolated struct Point: Equatable, Sendable {
        let x: BigUInt
        let y: BigUInt
    }

    let name: Name
    /// The DER OID body, as it sits in a v4 key packet after the length octet.
    let oid: [UInt8]
    /// The field prime p.
    let prime: BigUInt
    /// The order n of the generator (the cofactor is 1).
    let order: BigUInt
    /// Octets of a coordinate.
    let fieldSize: Int
    let generator: Point
    /// Arithmetic modulo p (coordinates).
    let field: MontgomeryModulus
    /// Arithmetic modulo n (scalars).
    let scalars: MontgomeryModulus
    /// a and b in Montgomery form.
    private let a: [UInt32]
    private let b: [UInt32]
    /// 3b in Montgomery form, for the complete addition formulas.
    private let b3: [UInt32]

    private init(name: Name, oid: [UInt8], fieldSize: Int,
                 p: String, a: String, b: String, x: String, y: String, n: String) {
        // The constants below are RFC 5639 section 3.4, 3.6 and 3.7, checked
        // against GnuPG signatures in Build7CurvesTests; a failure here is a
        // typo in this file, never input.
        guard let prime = BigUInt(hex: p), let aValue = BigUInt(hex: a), let bValue = BigUInt(hex: b),
              let gx = BigUInt(hex: x), let gy = BigUInt(hex: y), let order = BigUInt(hex: n),
              let field = MontgomeryModulus(prime), let scalars = MontgomeryModulus(order) else {
            preconditionFailure("brainpool constants for \(name.rawValue) did not parse")
        }
        self.name = name
        self.oid = oid
        self.fieldSize = fieldSize
        self.prime = prime
        self.order = order
        self.generator = Point(x: gx, y: gy)
        self.field = field
        self.scalars = scalars
        self.a = field.toMontgomery(aValue)
        self.b = field.toMontgomery(bValue)
        self.b3 = field.toMontgomery((bValue + bValue + bValue).remainder(dividingBy: prime))
    }

    // MARK: - The three curves (RFC 5639)

    static let p256r1 = BrainpoolCurve(
        name: .p256r1, oid: [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], fieldSize: 32,
        p: "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        a: "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        b: "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
        x: "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
        y: "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
        n: "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7")

    static let p384r1 = BrainpoolCurve(
        name: .p384r1, oid: [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], fieldSize: 48,
        p: "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
        a: "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
        b: "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
        x: "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
        y: "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
        n: "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565")

    static let p512r1 = BrainpoolCurve(
        name: .p512r1, oid: [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], fieldSize: 64,
        p: "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
        a: "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
        b: "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
        x: "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
        y: "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
        n: "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069")

    static let all: [BrainpoolCurve] = [p256r1, p384r1, p512r1]

    /// The curve whose OID body this is; nil for any other curve.
    static func forOID(_ oid: [UInt8]) -> BrainpoolCurve? {
        all.first { $0.oid == oid }
    }

    /// 0x04 || X || Y.
    var pointLength: Int { 1 + 2 * fieldSize }

    // MARK: - Points

    /// Whether `point` satisfies y^2 = x^3 + a x + b with both coordinates
    /// below p.
    func isOnCurve(_ point: Point) -> Bool {
        guard point.x < prime, point.y < prime else { return false }
        let x = field.toMontgomery(point.x)
        let y = field.toMontgomery(point.y)
        let left = field.multiply(y, y)
        let xCubed = field.multiply(field.multiply(x, x), x)
        let right = field.add(field.add(xCubed, field.multiply(a, x)), b)
        return left == right
    }

    /// An uncompressed SEC 1 point (0x04 || X || Y) that lies on the curve.
    /// Nil for anything else, including the compressed forms GnuPG does not
    /// write for brainpool.
    func decodePoint(_ bytes: [UInt8]) -> Point? {
        guard bytes.count == pointLength, bytes.first == 0x04 else { return nil }
        let point = Point(x: BigUInt(bytes: Array(bytes[1...fieldSize])),
                          y: BigUInt(bytes: Array(bytes[(1 + fieldSize)...])))
        return isOnCurve(point) ? point : nil
    }

    /// 0x04 || X || Y, each coordinate padded to the field size.
    func encodePoint(_ point: Point) -> [UInt8] {
        [0x04] + (point.x.bytes(length: fieldSize) ?? []) + (point.y.bytes(length: fieldSize) ?? [])
    }

    /// k * point; nil when that is the point at infinity. Variable time.
    func multiply(_ point: Point, by k: BigUInt) -> Point? {
        let base = jacobian(point)
        var accumulator = infinity
        var i = k.bitWidth - 1
        while i >= 0 {
            accumulator = double(accumulator)
            if k.bit(i) { accumulator = add(accumulator, base) }
            i -= 1
        }
        return affine(accumulator)
    }

    /// lhs + rhs, with nil standing for the point at infinity.
    func sum(_ lhs: Point?, _ rhs: Point?) -> Point? {
        guard let lhs else { return rhs }
        guard let rhs else { return lhs }
        return affine(add(jacobian(lhs), jacobian(rhs)))
    }

    /// The same point added to itself, computed by the doubling formula.
    func doubled(_ point: Point) -> Point? {
        affine(double(jacobian(point)))
    }

    /// u1 * p1 + u2 * p2 in one pass over the bits (Shamir's trick); nil
    /// when the result is the point at infinity.
    func linearCombination(_ u1: BigUInt, _ p1: Point, _ u2: BigUInt, _ p2: Point) -> Point? {
        let j1 = jacobian(p1)
        let j2 = jacobian(p2)
        let both = add(j1, j2)
        var accumulator = infinity
        var i = max(u1.bitWidth, u2.bitWidth) - 1
        while i >= 0 {
            accumulator = double(accumulator)
            switch (u1.bit(i), u2.bit(i)) {
            case (true, true): accumulator = add(accumulator, both)
            case (true, false): accumulator = add(accumulator, j1)
            case (false, true): accumulator = add(accumulator, j2)
            case (false, false): break
            }
            i -= 1
        }
        return affine(accumulator)
    }

    // MARK: - Secret scalars (constant-time ladder)

    /// k * point for a SECRET scalar `k` (big-endian, at most the order's
    /// width in octets). Runs the same number of ladder steps, with the same
    /// operations, whatever k is; nil when the result is the point at
    /// infinity (k is 0 or a multiple of n) or `k` is too long.
    func multiplySecret(_ point: Point, by k: [UInt8]) -> Point? {
        let bits = order.bitWidth
        let limbCount = (bits + 31) / 32
        guard k.count <= limbCount * 4 else { return nil }
        // Fixed-width limbs, so neither the length nor the leading zeros of
        // k change the loop.
        var scalar = [UInt32](repeating: 0, count: limbCount)
        for (i, byte) in k.reversed().enumerated() {
            scalar[i / 4] |= UInt32(byte) << UInt32(8 * (i % 4))
        }
        var r0 = Projective(x: field.zero, y: field.one, z: field.zero)   // infinity
        var r1 = Projective(x: field.toMontgomery(point.x), y: field.toMontgomery(point.y), z: field.one)
        var i = bits - 1
        while i >= 0 {
            let bit = (scalar[i / 32] >> UInt32(i % 32)) & 1
            let mask = 0 &- bit
            conditionalSwap(mask, &r0, &r1)
            r1 = completeAdd(r0, r1)
            r0 = completeAdd(r0, r0)
            conditionalSwap(mask, &r0, &r1)
            i -= 1
        }
        guard !field.isZero(r0.z) else { return nil }
        let zInverse = field.power(r0.z, prime - BigUInt(2))
        return Point(x: field.fromMontgomery(field.multiply(r0.x, zInverse)),
                     y: field.fromMontgomery(field.multiply(r0.y, zInverse)))
    }

    /// (X : Y : Z) with x = X / Z, y = Y / Z; infinity is (0 : 1 : 0).
    private nonisolated struct Projective {
        var x: [UInt32]
        var y: [UInt32]
        var z: [UInt32]
    }

    private func conditionalSwap(_ mask: UInt32, _ p: inout Projective, _ q: inout Projective) {
        MontgomeryModulus.conditionalSwap(mask: mask, &p.x, &q.x)
        MontgomeryModulus.conditionalSwap(mask: mask, &p.y, &q.y)
        MontgomeryModulus.conditionalSwap(mask: mask, &p.z, &q.z)
    }

    /// P + Q for any P and Q on the curve, the point at infinity and P = Q
    /// included: Renes, Costello and Batina, "Complete addition formulas for
    /// prime order elliptic curves" (2016), algorithm 1 (arbitrary a), step
    /// for step. Valid because the brainpool curves have prime order.
    private func completeAdd(_ p: Projective, _ q: Projective) -> Projective {
        let f = field
        var t0 = f.multiply(p.x, q.x)
        var t1 = f.multiply(p.y, q.y)
        var t2 = f.multiply(p.z, q.z)
        var t3 = f.add(p.x, p.y)
        var t4 = f.add(q.x, q.y)
        t3 = f.multiply(t3, t4)
        t4 = f.add(t0, t1)
        t3 = f.subtract(t3, t4)
        t4 = f.add(p.x, p.z)
        var t5 = f.add(q.x, q.z)
        t4 = f.multiply(t4, t5)
        t5 = f.add(t0, t2)
        t4 = f.subtract(t4, t5)
        t5 = f.add(p.y, p.z)
        var x3 = f.add(q.y, q.z)
        t5 = f.multiply(t5, x3)
        x3 = f.add(t1, t2)
        t5 = f.subtract(t5, x3)
        var z3 = f.multiply(a, t4)
        x3 = f.multiply(b3, t2)
        z3 = f.add(x3, z3)
        x3 = f.subtract(t1, z3)
        z3 = f.add(t1, z3)
        var y3 = f.multiply(x3, z3)
        t1 = f.add(t0, t0)
        t1 = f.add(t1, t0)
        t2 = f.multiply(a, t2)
        t4 = f.multiply(b3, t4)
        t1 = f.add(t1, t2)
        t2 = f.subtract(t0, t2)
        t2 = f.multiply(a, t2)
        t4 = f.add(t4, t2)
        t0 = f.multiply(t1, t4)
        y3 = f.add(y3, t0)
        t0 = f.multiply(t5, t4)
        x3 = f.multiply(t3, x3)
        x3 = f.subtract(x3, t0)
        t0 = f.multiply(t3, t1)
        z3 = f.multiply(t5, z3)
        z3 = f.add(z3, t0)
        return Projective(x: x3, y: y3, z: z3)
    }

    // MARK: - Jacobian arithmetic (Montgomery-form coordinates)

    private nonisolated struct Jacobian {
        var x: [UInt32]
        var y: [UInt32]
        var z: [UInt32]
    }

    private var infinity: Jacobian { Jacobian(x: field.one, y: field.one, z: field.zero) }

    private func jacobian(_ point: Point) -> Jacobian {
        Jacobian(x: field.toMontgomery(point.x), y: field.toMontgomery(point.y), z: field.one)
    }

    private func affine(_ point: Jacobian) -> Point? {
        guard !field.isZero(point.z) else { return nil }
        let zInverse = field.power(point.z, prime - BigUInt(2))
        let zInverse2 = field.multiply(zInverse, zInverse)
        let zInverse3 = field.multiply(zInverse2, zInverse)
        return Point(x: field.fromMontgomery(field.multiply(point.x, zInverse2)),
                     y: field.fromMontgomery(field.multiply(point.y, zInverse3)))
    }

    /// 2P for any a: S = 4 X Y^2, M = 3 X^2 + a Z^4, X3 = M^2 - 2 S,
    /// Y3 = M (S - X3) - 8 Y^4, Z3 = 2 Y Z.
    private func double(_ point: Jacobian) -> Jacobian {
        let f = field
        if f.isZero(point.z) || f.isZero(point.y) { return infinity }
        let yy = f.multiply(point.y, point.y)
        var s = f.multiply(point.x, yy)
        s = f.add(s, s)
        s = f.add(s, s)
        let xx = f.multiply(point.x, point.x)
        let zz = f.multiply(point.z, point.z)
        var m = f.add(f.add(xx, xx), xx)
        m = f.add(m, f.multiply(a, f.multiply(zz, zz)))
        let x3 = f.subtract(f.multiply(m, m), f.add(s, s))
        var yyyy8 = f.multiply(yy, yy)
        yyyy8 = f.add(yyyy8, yyyy8)
        yyyy8 = f.add(yyyy8, yyyy8)
        yyyy8 = f.add(yyyy8, yyyy8)
        let y3 = f.subtract(f.multiply(m, f.subtract(s, x3)), yyyy8)
        var z3 = f.multiply(point.y, point.z)
        z3 = f.add(z3, z3)
        return Jacobian(x: x3, y: y3, z: z3)
    }

    /// P + Q: U1 = X1 Z2^2, U2 = X2 Z1^2, S1 = Y1 Z2^3, S2 = Y2 Z1^3,
    /// H = U2 - U1, R = S2 - S1, X3 = R^2 - H^3 - 2 U1 H^2,
    /// Y3 = R (U1 H^2 - X3) - S1 H^3, Z3 = Z1 Z2 H. Equal points double;
    /// opposite points give infinity.
    private func add(_ lhs: Jacobian, _ rhs: Jacobian) -> Jacobian {
        let f = field
        if f.isZero(lhs.z) { return rhs }
        if f.isZero(rhs.z) { return lhs }
        let z1z1 = f.multiply(lhs.z, lhs.z)
        let z2z2 = f.multiply(rhs.z, rhs.z)
        let u1 = f.multiply(lhs.x, z2z2)
        let u2 = f.multiply(rhs.x, z1z1)
        let s1 = f.multiply(f.multiply(lhs.y, rhs.z), z2z2)
        let s2 = f.multiply(f.multiply(rhs.y, lhs.z), z1z1)
        if u1 == u2 { return s1 == s2 ? double(lhs) : infinity }
        let h = f.subtract(u2, u1)
        let r = f.subtract(s2, s1)
        let hh = f.multiply(h, h)
        let hhh = f.multiply(h, hh)
        let v = f.multiply(u1, hh)
        let x3 = f.subtract(f.subtract(f.multiply(r, r), hhh), f.add(v, v))
        let y3 = f.subtract(f.multiply(r, f.subtract(v, x3)), f.multiply(s1, hhh))
        let z3 = f.multiply(f.multiply(lhs.z, rhs.z), h)
        return Jacobian(x: x3, y: y3, z: z3)
    }
}

// MARK: - ECDSA verification

nonisolated enum BrainpoolECDSA {

    /// Verify an ECDSA signature (r, s as big-endian integers, leading zero
    /// octets optional) over a finished digest, against an uncompressed
    /// public point. SEC 1 section 4.1.4: r and s in [1, n-1], e the leftmost
    /// bits of the digest up to the bit length of n, w = s^-1 mod n,
    /// u1 = e w, u2 = r w, and the x of u1 G + u2 Q equal to r mod n.
    static func verify(r rBytes: [UInt8], s sBytes: [UInt8], digest: [UInt8],
                       curve: BrainpoolCurve, publicPoint: [UInt8]) -> Bool {
        guard !digest.isEmpty, let q = curve.decodePoint(publicPoint) else { return false }
        let n = curve.order
        let r = BigUInt(bytes: rBytes)
        let s = BigUInt(bytes: sBytes)
        guard !r.isZero, !s.isZero, r < n, s < n else { return false }
        guard let w = curve.scalars.inverse(s) else { return false }
        let e = BigUInt.leftmostBits(of: digest, count: n.bitWidth)
        let u1 = curve.scalars.multiplyMod(e, w)
        let u2 = curve.scalars.multiplyMod(r, w)
        guard let point = curve.linearCombination(u1, curve.generator, u2, q) else { return false }
        return point.x.remainder(dividingBy: n) == r
    }
}

// MARK: - ECDH and key generation (8.4.0 build 7 wave 2, plan K3)

/// Elliptic-curve Diffie-Hellman on the brainpool curves, as the LibrePGP
/// ML-KEM + brainpool composite (GnuPG ky768_bp256, ky1024_bp384) uses it:
/// a scalar is the big-endian private key padded to the field size, a public
/// key or ephemeral is the uncompressed SEC 1 point 0x04 || X || Y, and the
/// agreement output is the WHOLE uncompressed shared point (GnuPG feeds all
/// of it to its ECC key-share KDF, not just X; found by Android against a
/// gpg 2.5 brainpool message). Every secret-scalar multiplication goes
/// through `BrainpoolCurve.multiplySecret`.
nonisolated enum BrainpoolECDH {

    enum Failure: Error, Equatable {
        case randomFailed
        case invalidPoint
        case invalidScalar
    }

    /// A fresh key pair: a scalar uniform in [1, n-1] (rejection sampling
    /// from the system CSPRNG), as `curve.fieldSize` octets, and its public
    /// point.
    static func generateKeyPair(curve: BrainpoolCurve) throws -> (scalar: [UInt8], point: [UInt8]) {
        let one = BigUInt(1)
        for _ in 0..<128 {
            var bytes = [UInt8](repeating: 0, count: curve.fieldSize)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
                throw Failure.randomFailed
            }
            let candidate = BigUInt(bytes: bytes)
            guard candidate >= one, candidate < curve.order else { continue }
            let point = try publicPoint(curve: curve, scalar: bytes)
            return (bytes, point)
        }
        throw Failure.randomFailed
    }

    /// The uncompressed public point of `scalar` (scalar times the generator).
    static func publicPoint(curve: BrainpoolCurve, scalar: [UInt8]) throws -> [UInt8] {
        guard let point = curve.multiplySecret(curve.generator, by: try checked(scalar, curve: curve)) else {
            throw Failure.invalidScalar
        }
        return curve.encodePoint(point)
    }

    /// The uncompressed shared point scalar * peer. The peer point must be
    /// an uncompressed point on the curve (checked before any secret
    /// arithmetic, so an invalid-curve point is refused).
    static func sharedPoint(curve: BrainpoolCurve, scalar: [UInt8], peerPoint: [UInt8]) throws -> [UInt8] {
        guard let peer = curve.decodePoint(peerPoint) else { throw Failure.invalidPoint }
        guard let shared = curve.multiplySecret(peer, by: try checked(scalar, curve: curve)) else {
            throw Failure.invalidPoint
        }
        return curve.encodePoint(shared)
    }

    /// The scalar left-padded to the field size; refused when longer than
    /// that (GnuPG strips leading zero octets, never adds any).
    private static func checked(_ scalar: [UInt8], curve: BrainpoolCurve) throws -> [UInt8] {
        guard !scalar.isEmpty, scalar.count <= curve.fieldSize else { throw Failure.invalidScalar }
        return [UInt8](repeating: 0, count: curve.fieldSize - scalar.count) + scalar
    }
}
