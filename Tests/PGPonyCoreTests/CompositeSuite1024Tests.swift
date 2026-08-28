// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeSuite1024Tests.swift
// PGPony
//
// v8.2.0 §1. Self-consistency tests for the ML-KEM-1024 + X448 composite
// (RFC 9980 algorithm 36) through the suite-parameterized KEM core.
//
// What these prove: the 1024 suite round-trips against itself (encapsulate
// and decapsulate agree on the KEK), the sizes are the FIPS-203 / RFC 7748
// ones end to end, and the suites do not cross-open. What they do NOT
// prove: wire compatibility with gpg 2.5.x. That is the §1 interop matrix
// (PQC_1024_INTEROP.md procedure), run on real fixtures; the JVM twin of
// this suite on Android had the same limitation and the wire layout was
// proven there against gpg, which this port mirrors byte for byte.
//
// These tests REQUIRE the liboqs xcframework built with KEM_ml_kem_1024
// (build-liboqs-ios.sh as of 8.2.0). Against an old 768-only framework
// every 1024 call throws `.unavailable` and the suite fails loudly, which
// is the intended signal to rebuild the framework.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class CompositeSuite1024Tests: XCTestCase {

    // MARK: - Suite table sanity

    func testSuiteParameters() {
        XCTAssertEqual(CompositeSuite.ietf768.algId, 35)
        XCTAssertEqual(CompositeSuite.ietf1024.algId, 36)
        XCTAssertEqual(CompositeSuite.ietf768.compositePublicBytes, 1216)
        XCTAssertEqual(CompositeSuite.ietf1024.compositePublicBytes, 1624)
        XCTAssertEqual(CompositeSuite.ietf768.compositeSecretBytes, 96)
        XCTAssertEqual(CompositeSuite.ietf1024.compositeSecretBytes, 120)
        XCTAssertEqual(CompositeSuite.from(algId: 35), .ietf768)
        XCTAssertEqual(CompositeSuite.from(algId: 36), .ietf1024)
        XCTAssertNil(CompositeSuite.from(algId: 25))
    }

    // MARK: - ML-KEM-1024 primitive

    func testMLKEM1024RoundTrip() throws {
        let (pk, sk) = try MLKEMService.generateKeyPair(level: .mlkem1024)
        XCTAssertEqual(pk.count, 1568)
        XCTAssertEqual(sk.count, 3168)
        let (ct, ss1) = try MLKEMService.encapsulate(publicKey: pk, level: .mlkem1024)
        XCTAssertEqual(ct.count, 1568)
        let ss2 = try MLKEMService.decapsulate(ciphertext: ct, secretKey: sk, level: .mlkem1024)
        XCTAssertEqual(ss1, ss2, "ML-KEM-1024 shared secrets disagree")
    }

    func testMLKEM1024SeedExpansionIsDeterministic() throws {
        var seed = Data(count: 64)
        seed.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 64, $0.baseAddress!) }
        let (pk1, sk1) = try MLKEMService.generateKeyPair(seed: seed, level: .mlkem1024)
        let (pk2, sk2) = try MLKEMService.generateKeyPair(seed: seed, level: .mlkem1024)
        XCTAssertEqual(pk1, pk2)
        XCTAssertEqual(sk1, sk2)
    }

    // MARK: - Composite 1024 round trip

    func testComposite1024RoundTrip() throws {
        let (mlkemPK, mlkemSK) = try MLKEMService.generateKeyPair(level: .mlkem1024)
        let ecdhPriv = try X448.generatePrivateKey()
        let ecdhPub = try X448.publicKey(for: ecdhPriv)

        let enc = try CompositeKEMService.encapsulate(mlkemPublicKey: mlkemPK,
                                                      ecdhPublicKey: ecdhPub,
                                                      suite: .ietf1024)
        XCTAssertEqual(enc.mlkemCipherText.count, 1568)
        XCTAssertEqual(enc.ecdhCipherText.count, 56)
        XCTAssertEqual(enc.kek.count, 32)

        let kek2 = try CompositeKEMService.decapsulate(
            mlkemCipherText: enc.mlkemCipherText,
            ecdhCipherText: enc.ecdhCipherText,
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: ecdhPriv,
            ecdhPublicKey: ecdhPub,
            algId: 36)
        XCTAssertEqual(enc.kek, kek2, "encaps/decaps KEK disagree for the 1024 suite")
    }

    /// The 768 path must be untouched by the parameterization: this is the
    /// same round trip CompositeKEMKATTests runs, repeated here with the
    /// suite passed explicitly, to prove the default and the explicit
    /// argument take the identical path.
    func testComposite768ExplicitSuiteRoundTrip() throws {
        let (mlkemPK, mlkemSK) = try MLKEMService.generateKeyPair(level: .mlkem768)
        let ecdhPriv = Curve25519.KeyAgreement.PrivateKey()
        let ecdhPub = ecdhPriv.publicKey.rawRepresentation

        let enc = try CompositeKEMService.encapsulate(mlkemPublicKey: mlkemPK,
                                                      ecdhPublicKey: ecdhPub,
                                                      suite: .ietf768)
        let kek2 = try CompositeKEMService.decapsulate(
            mlkemCipherText: enc.mlkemCipherText,
            ecdhCipherText: enc.ecdhCipherText,
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: ecdhPriv.rawRepresentation,
            ecdhPublicKey: ecdhPub,
            algId: 35)
        XCTAssertEqual(enc.kek, kek2)
    }

    // MARK: - Suites must not cross

    func testSuitesDoNotCross() throws {
        let ecdhPub768 = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let (mlkemPK1024, _) = try MLKEMService.generateKeyPair(level: .mlkem1024)
        // A 1024 ML-KEM key with a 32-byte curve key is not a valid suite
        // combination in either direction.
        XCTAssertThrowsError(try CompositeKEMService.encapsulate(
            mlkemPublicKey: mlkemPK1024, ecdhPublicKey: ecdhPub768, suite: .ietf768))
        XCTAssertThrowsError(try CompositeKEMService.encapsulate(
            mlkemPublicKey: mlkemPK1024, ecdhPublicKey: ecdhPub768, suite: .ietf1024))
        // Unknown algorithm id on decapsulation is rejected up front.
        XCTAssertThrowsError(try CompositeKEMService.decapsulate(
            mlkemCipherText: Data(count: 1568),
            ecdhCipherText: Data(count: 56),
            mlkemSecretKey: Data(count: 3168),
            ecdhSecretKey: Data(count: 56),
            ecdhPublicKey: Data(count: 56),
            algId: 99))
    }
}

