// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// DSAVerifier.swift
// PGPony
//
// 8.4.0 build 7 (plan K4): DSA signature verification (OpenPGP algorithm
// 17, FIPS 186-4 section 4.7), so signatures and self-signatures from
// GnuPG DSA keys check instead of reading as uncheckable. Neither CryptoKit
// nor Security verifies DSA, so this runs on `BigUInt` and
// `MontgomeryModulus`. Verification only: PGPony does not make DSA keys or
// signatures (DSA is deprecated for new keys, RFC 9580 section 9.1).
//
// Cost: two modular exponentiations modulo p with exponents below q (at
// most 256 bits for a FIPS key), so a 3072-bit key is a few hundred
// Montgomery multiplications of 96 limbs.

import Foundation

nonisolated enum DSAVerifier {

    /// The largest p accepted. FIPS 186 stops at 3072 bits and GnuPG makes
    /// nothing bigger; a key claiming more is refused rather than computed.
    static let maximumPrimeBits = 4096

    /// The largest q accepted (FIPS 186 uses 160, 224 and 256 bits).
    static let maximumSubgroupBits = 512

    /// Verify (r, s) over a finished digest with the public key (p, q, g, y),
    /// all big-endian integers as read off their MPIs. r and s must be in
    /// [1, q-1]; z is the leftmost bits of the digest up to the bit length of
    /// q; w = s^-1 mod q, u1 = z w mod q, u2 = r w mod q, and
    /// (g^u1 y^u2 mod p) mod q must equal r.
    static func verify(r rBytes: [UInt8], s sBytes: [UInt8], digest: [UInt8],
                       p pBytes: [UInt8], q qBytes: [UInt8], g gBytes: [UInt8], y yBytes: [UInt8]) -> Bool {
        let p = BigUInt(bytes: pBytes)
        let q = BigUInt(bytes: qBytes)
        let g = BigUInt(bytes: gBytes)
        let y = BigUInt(bytes: yBytes)
        let one = BigUInt(1)
        guard !digest.isEmpty,
              p.bitWidth <= maximumPrimeBits, q.bitWidth <= maximumSubgroupBits,
              q.bitWidth < p.bitWidth,
              one < g, g < p, one < y, y < p,
              let pField = MontgomeryModulus(p), let qField = MontgomeryModulus(q) else { return false }
        let r = BigUInt(bytes: rBytes)
        let s = BigUInt(bytes: sBytes)
        guard !r.isZero, !s.isZero, r < q, s < q else { return false }
        guard let w = qField.inverse(s) else { return false }
        let z = BigUInt.leftmostBits(of: digest, count: q.bitWidth)
        let u1 = qField.multiplyMod(z, w)
        let u2 = qField.multiplyMod(r, w)
        let gu1 = pField.power(pField.toMontgomery(g), u1)
        let yu2 = pField.power(pField.toMontgomery(y), u2)
        let v = pField.fromMontgomery(pField.multiply(gu1, yu2)).remainder(dividingBy: q)
        return v == r
    }
}
