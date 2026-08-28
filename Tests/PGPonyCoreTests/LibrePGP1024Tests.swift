// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGP1024Tests.swift
// PGPony
//
// v8.2.0 §1 (K2a). The LibrePGP ky1024_cv448 suite: SHA3-512 primitive
// vectors, the suite table, point normalization, key generation, and full
// encrypt/decrypt round trips. What these prove is self-consistency; the
// gpg 2.5.x matrix in PQC_1024_INTEROP.md (run on the desk, both
// directions) is the wire-compatibility proof, exactly as it was for the
// Android port these paths mirror. Requires the ML-KEM-1024-capable liboqs
// xcframework.

import XCTest
@testable import PGPonyCore

final class LibrePGP1024Tests: XCTestCase {

    // MARK: - SHA3-512 (the X448 ECC key-share KDF hash)

    /// NIST FIPS-202 vectors, machine-verified against Python's hashlib
    /// before baking in. SHA3-512 runs at rate 72, not the 136 the rest of
    /// the Keccak file uses, which is why it gets its own lock here.
    func testSHA3_512KnownVectors() {
        XCTAssertEqual(Data(Keccak.sha3_512([])).hexString,
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")
        XCTAssertEqual(Data(Keccak.sha3_512(Array("abc".utf8))).hexString,
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
        // And the 256 twin still matches (the rate refactor must not move it).
        XCTAssertEqual(Data(Keccak.sha3_256(Array("abc".utf8))).hexString,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    }

    // MARK: - Suite table

    func testSuiteTable() {
        XCTAssertEqual(LibrePGPSuite.fromOidTail([0x2b, 0x65, 0x6e]), .ky768_cv25519)
        XCTAssertEqual(LibrePGPSuite.fromOidTail([0x2b, 0x65, 0x6f]), .ky1024_cv448)
        XCTAssertNil(LibrePGPSuite.fromOidTail([0x2b, 0x65, 0x70]))
        XCTAssertEqual(LibrePGPSuite.ky768_cv25519.secretBytes, 96)
        XCTAssertEqual(LibrePGPSuite.ky1024_cv448.secretBytes, 120)
        XCTAssertEqual(LibrePGPSuite.ky1024_cv448.mlkemPublicBytes, 1568)
        XCTAssertEqual(LibrePGPSuite.ky1024_cv448.mlkemCiphertextBytes, 1568)
    }

    func testNormalizePoint() {
        let s = LibrePGPSuite.ky1024_cv448
        let exact = [UInt8](repeating: 7, count: 56)
        XCTAssertEqual(s.normalizePoint(exact), exact)
        // 0x40 native-point prefix dropped.
        XCTAssertEqual(s.normalizePoint([0x40] + exact), exact)
        // A minimal MPI short a leading zero byte is left-padded back.
        let short = Array(exact.dropFirst())
        XCTAssertEqual(s.normalizePoint(short), [0] + short)
        // The KDFs differ between the suites for identical input, which is
        // the gpg trap: same bytes, different hash, different KEK.
        let a = [UInt8](repeating: 1, count: 56)
        XCTAssertNotEqual(
            LibrePGPSuite.ky768_cv25519.eccKemKdf(rawECDH: a, eccCipherText: a, eccPublic: a),
            Array(LibrePGPSuite.ky1024_cv448.eccKemKdf(rawECDH: a, eccCipherText: a, eccPublic: a).prefix(32)))
    }

    // MARK: - Key generation

    private func assertConsistent1024Key(_ result: Ed25519KeyGeneratorResult,
                                         passphrase: String?) throws {
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: [UInt8](result.publicKeyData))
        let subPub = try XCTUnwrap(pubPackets.first {
            $0.tag == 14 && $0.body.count > 6 && $0.body[0] == 5 && $0.body[5] == 8
        }, "generated key must expose a v5 algo-8 encryption subkey")
        // The curve OID must be X448 (the only marker of the 1024 form).
        XCTAssertEqual(subPub.body[10], 3)
        XCTAssertEqual(Array(subPub.body[11..<14]), [0x2b, 0x65, 0x6f])

        let decKey = try XCTUnwrap(LibrePGPDecryptService.extractDecryptionKey(
            privateKeyData: [UInt8](result.privateKeyData), passphrase: passphrase))
        XCTAssertEqual(decKey.suite, .ky1024_cv448)
        XCTAssertEqual(decKey.eccSecret.count, 56)
        XCTAssertEqual(decKey.eccPublic.count, 56)
        XCTAssertEqual(decKey.mlkemSeed.count, 64)
        // The stored X448 scalar must derive the packet's public point.
        XCTAssertEqual([UInt8](try X448.publicKey(for: Data(decKey.eccSecret))), decKey.eccPublic)
        // And the seed must derive an ML-KEM-1024 keypair deterministically.
        let (pub1, _) = try MLKEMService.generateKeyPair(seed: Data(decKey.mlkemSeed), level: .mlkem1024)
        let (pub2, _) = try MLKEMService.generateKeyPair(seed: Data(decKey.mlkemSeed), level: .mlkem1024)
        XCTAssertEqual(pub1, pub2)
    }

    func testGeneratesUnprotected1024LibrePGPKey() throws {
        let result = try Ed25519KeyGenerator.generate(
            name: "LibrePGP 1024 Test", email: "ky1024@pgpony.test",
            passphrase: nil, expirationInterval: nil,
            pqcEncryption: true, pqcSuite: .ky1024_cv448)
        try assertConsistent1024Key(result, passphrase: nil)
    }

    func testGeneratesProtected1024LibrePGPKey() throws {
        let result = try Ed25519KeyGenerator.generate(
            name: "LibrePGP 1024 Test", email: "ky1024@pgpony.test",
            passphrase: "ky1024-pass", expirationInterval: nil,
            pqcEncryption: true, pqcSuite: .ky1024_cv448)
        try assertConsistent1024Key(result, passphrase: "ky1024-pass")
    }

    // MARK: - Round trips

    func testRoundTrip1024() throws {
        let result = try Ed25519KeyGenerator.generate(
            name: "LibrePGP 1024 RT", email: "ky1024rt@pgpony.test",
            passphrase: nil, expirationInterval: nil,
            pqcEncryption: true, pqcSuite: .ky1024_cv448)
        let plaintext = "gpg-flavored 1024, round and back"
        let message = try LibrePGPEncryptService.encrypt(
            plaintext: Array(plaintext.utf8),
            publicKeyData: [UInt8](result.publicKeyData))
        let decrypted = try LibrePGPDecryptService.decrypt(
            messageData: message,
            secretKeyData: [UInt8](result.privateKeyData))
        XCTAssertEqual(String(decoding: decrypted, as: UTF8.self), plaintext)
    }

    func testRoundTrip1024Protected() throws {
        let result = try Ed25519KeyGenerator.generate(
            name: "LibrePGP 1024 RTP", email: "ky1024rtp@pgpony.test",
            passphrase: "round-trip-pass", expirationInterval: nil,
            pqcEncryption: true, pqcSuite: .ky1024_cv448)
        let plaintext = "protected 1024 round trip"
        let message = try LibrePGPEncryptService.encrypt(
            plaintext: Array(plaintext.utf8),
            publicKeyData: [UInt8](result.publicKeyData))
        let decrypted = try LibrePGPDecryptService.decrypt(
            messageData: message,
            secretKeyData: [UInt8](result.privateKeyData),
            passphrase: "round-trip-pass")
        XCTAssertEqual(String(decoding: decrypted, as: UTF8.self), plaintext)
        // Wrong passphrase must fail loudly, not decrypt garbage.
        XCTAssertThrowsError(try LibrePGPDecryptService.decrypt(
            messageData: message,
            secretKeyData: [UInt8](result.privateKeyData),
            passphrase: "wrong"))
    }

    /// The 768 path must be untouched by the suite refactor: same round trip
    /// the existing LibrePGP tests run, repeated with the suite explicit.
    func testRoundTrip768ExplicitSuiteUnchanged() throws {
        let result = try Ed25519KeyGenerator.generate(
            name: "LibrePGP 768 RT", email: "ky768rt@pgpony.test",
            passphrase: nil, expirationInterval: nil,
            pqcEncryption: true, pqcSuite: .ky768_cv25519)
        let plaintext = "the 768 suite, exactly as it always was"
        let message = try LibrePGPEncryptService.encrypt(
            plaintext: Array(plaintext.utf8),
            publicKeyData: [UInt8](result.publicKeyData))
        let decrypted = try LibrePGPDecryptService.decrypt(
            messageData: message,
            secretKeyData: [UInt8](result.privateKeyData))
        XCTAssertEqual(String(decoding: decrypted, as: UTF8.self), plaintext)
    }
}

private extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
