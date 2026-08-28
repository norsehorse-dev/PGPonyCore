// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// X448Tests.swift
// PGPony
//
// v8.2.0 §1. Known-answer tests for the hand-rolled X448 (RFC 7748), which
// the ML-KEM-1024 + X448 composite (RFC 9980 algorithm 36) stands on.
//
// Every vector below is from RFC 7748 itself: the two §5.2 scalar
// multiplication vectors, the §5.2 iterated vectors (1 and 1,000
// iterations; the million-iteration value is in the RFC too but takes
// minutes, so it stays out of the routine suite), and the §6.2
// Diffie-Hellman exchange. The vectors were machine-checked against an
// independent big-integer implementation of the RFC before being baked in,
// so a failure here means the Swift arithmetic regressed, not the data.
//
// The curve code is security-critical and was validated limb-for-limb
// before transcription; treat any edit to X448.swift as suspect until this
// entire suite passes again.

import XCTest
@testable import PGPonyCore

final class X448Tests: XCTestCase {

    // MARK: - RFC 7748 §5.2 scalar multiplication vectors

    func testScalarMultVector1() throws {
        let k = hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
        let u = hex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")
        let expected = hex("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")
        XCTAssertEqual(try X448.scalarMultiply(scalar: k, u: u), expected)
    }

    func testScalarMultVector2() throws {
        let k = hex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
        let u = hex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")
        let expected = hex("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")
        XCTAssertEqual(try X448.scalarMultiply(scalar: k, u: u), expected)
    }

    // MARK: - RFC 7748 §5.2 iterated vectors

    func testIteratedOnce() throws {
        var k = hex("05" + String(repeating: "00", count: 55))
        var u = k
        let r = try X448.scalarMultiply(scalar: k, u: u)
        (k, u) = (r, k)
        XCTAssertEqual(k, hex("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"))
    }

    func testIteratedThousand() throws {
        var k = hex("05" + String(repeating: "00", count: 55))
        var u = k
        for _ in 0..<1000 {
            let r = try X448.scalarMultiply(scalar: k, u: u)
            (k, u) = (r, k)
        }
        XCTAssertEqual(k, hex("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"))
    }

    // MARK: - RFC 7748 §6.2 Diffie-Hellman

    private let alicePriv = hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
    private let alicePub  = hex("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0")
    private let bobPriv   = hex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
    private let bobPub    = hex("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")
    private let sharedK   = hex("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")

    func testDHPublicKeyDerivation() throws {
        XCTAssertEqual(try X448.publicKey(for: alicePriv), alicePub)
        XCTAssertEqual(try X448.publicKey(for: bobPriv), bobPub)
    }

    func testDHSharedSecretBothDirections() throws {
        XCTAssertEqual(try X448.sharedSecret(privateKey: alicePriv, publicKey: bobPub), sharedK)
        XCTAssertEqual(try X448.sharedSecret(privateKey: bobPriv, publicKey: alicePub), sharedK)
    }

    // MARK: - Behavior

    func testGeneratedKeysAgree() throws {
        let a = try X448.generatePrivateKey()
        let b = try X448.generatePrivateKey()
        XCTAssertNotEqual(a, b)
        let aPub = try X448.publicKey(for: a)
        let bPub = try X448.publicKey(for: b)
        let s1 = try X448.sharedSecret(privateKey: a, publicKey: bPub)
        let s2 = try X448.sharedSecret(privateKey: b, publicKey: aPub)
        XCTAssertEqual(s1, s2)
        XCTAssertEqual(s1.count, X448.keyBytes)
    }

    func testZeroSharedSecretRejected() throws {
        // u = 0 is a low-order input: the ladder output is all zeros, and
        // sharedSecret must refuse it (RFC 7748 §6.2 check). The raw
        // primitive is deliberately unchecked.
        let priv = try X448.generatePrivateKey()
        let zeroU = Data(repeating: 0, count: X448.keyBytes)
        XCTAssertEqual(try X448.scalarMultiply(scalar: priv, u: zeroU),
                       Data(repeating: 0, count: X448.keyBytes))
        XCTAssertThrowsError(try X448.sharedSecret(privateKey: priv, publicKey: zeroU)) { error in
            guard case X448.Failure.zeroSharedSecret = error else {
                return XCTFail("wrong error: \(error)")
            }
        }
    }

    func testBadLengthsRejected() {
        let short = Data(repeating: 1, count: 55)
        let ok = Data(repeating: 1, count: 56)
        XCTAssertThrowsError(try X448.scalarMultiply(scalar: short, u: ok))
        XCTAssertThrowsError(try X448.scalarMultiply(scalar: ok, u: short))
    }

    // MARK: - Helpers

    private func hex(_ s: String) -> Data { Self.hex(s) }

    private static func hex(_ s: String) -> Data {
        precondition(s.count % 2 == 0, "odd-length hex")
        var out = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }
}
