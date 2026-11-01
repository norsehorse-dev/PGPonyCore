// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardKDFTests.swift
// PGPonyCoreTests
//
// v8.1.0 — §4b. Hardware-free tests for the OpenPGP card KDF-DO (00F9).
//
// Why these matter more than most: the failure this code fixes is silent and
// destructive. On a KDF-provisioned card PGPony sent the raw PIN, the card
// rejected it with 63Cx, and one PW1 attempt was gone. Three of those and the
// user's card is blocked with no recourse but the admin PIN. A regression here
// does not show up as a crash or a wrong answer — it shows up as a stranger's
// hardware key locking itself, which is why the derivation is pinned to
// known-answer vectors rather than to "it round-trips".
//
// The expected digests below were generated with an independent Python
// implementation of RFC 4880 §3.7.1.3 over hashlib, not by running this code.

import XCTest
@testable import PGPonyCore

final class CardKDFTests: XCTestCase {

    // 01 02 03 04 05 06 07 08 — the PW1 salt used by the vectors.
    private let salt: [UInt8] = Array(1...8)
    private let saltPW3 = [UInt8](repeating: 0xAA, count: 8)

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    // MARK: - Derivation known-answer vectors

    func testIteratedSaltedS2K_SHA256_GnuPGDefaultCount() {
        let out = CardKDF.iteratedSaltedS2K(
            passphrase: Array("123456".utf8), salt: salt,
            iterationCount: 100_000, hash: .sha256
        )
        XCTAssertEqual(out.count, 32)
        XCTAssertEqual(
            hex(out),
            "8FC77436DED3825377DA921ACC4FB1E0C619E426B926C30F06FBB428C6AC9701"
        )
    }

    func testIteratedSaltedS2K_SHA512() {
        let out = CardKDF.iteratedSaltedS2K(
            passphrase: Array("123456".utf8), salt: salt,
            iterationCount: 100_000, hash: .sha512
        )
        XCTAssertEqual(out.count, 64)
        XCTAssertEqual(
            hex(out),
            "186D660008735555E233E307A33BEA690644C7E0C4C0C14CEA8DFB083F957DAB"
            + "A1B486610887820018029D8B1A6877866746777ABF7A139A607C9A13F2CD67B3"
        )
    }

    func testIteratedSaltedS2K_PW3SaltDiffersFromPW1() {
        let out = CardKDF.iteratedSaltedS2K(
            passphrase: Array("12345678".utf8), salt: saltPW3,
            iterationCount: 100_000, hash: .sha256
        )
        XCTAssertEqual(
            hex(out),
            "8386C3832BFFC232CC6B0B4D958F07317235437F271A13E6D611DF8DE5721310"
        )
    }

    /// The octet count is a FLOOR, not a cap: libgcrypt raises any count below
    /// the salt+passphrase length up to it, so the whole value is always hashed
    /// at least once. A truncating loop would produce a different digest and
    /// burn an attempt on every verify.
    func testIterationCountBelowBlockLengthHashesWholeBlockOnce() {
        let derived = CardKDF.iteratedSaltedS2K(
            passphrase: Array("123456".utf8), salt: salt,
            iterationCount: 1, hash: .sha256
        )
        let plainSinglePass = CardKDF.iteratedSaltedS2K(
            passphrase: Array("123456".utf8), salt: salt,
            iterationCount: 14, hash: .sha256   // exactly 8 + 6
        )
        XCTAssertEqual(hex(derived), hex(plainSinglePass))
        XCTAssertEqual(
            hex(derived),
            "1AE0F1043E1492A1ACFFC2319DE52FA4713CF4BFD7123563345550F0DA8EEE9A"
        )
    }

    /// A count that is not a whole multiple of the block truncates the final
    /// repetition rather than rounding up — pinned so the loop can't drift.
    func testPartialFinalRepetition() {
        let out = CardKDF.iteratedSaltedS2K(
            passphrase: Array("123456".utf8), salt: salt,
            iterationCount: 64, hash: .sha256   // 64 = 4×14 + 8
        )
        XCTAssertEqual(
            hex(out),
            "7D2D05F75B00CAF57F9E2741A6B5FA1B7C267B56A6F0AF91741E63E879C100B1"
        )
    }

    // MARK: - DO 00F9 parsing

    /// A full KDF-DO as `gpg --card-edit` -> `kdf-setup` writes it.
    private func realisticDO() -> [UInt8] {
        var d: [UInt8] = []
        d += [0x81, 0x01, 0x03]                              // KDF_ITERSALTED_S2K
        d += [0x82, 0x01, 0x08]                              // SHA-256
        d += [0x83, 0x04, 0x00, 0x01, 0x86, 0xA0]            // 100000, big-endian
        d += [0x84, 0x08] + salt                             // PW1 salt
        d += [0x85, 0x08] + [UInt8](repeating: 0xBB, count: 8) // RC salt
        d += [0x86, 0x08] + saltPW3                          // PW3 salt
        d += [0x87, 0x20] + [UInt8](repeating: 0xC1, count: 32)
        d += [0x88, 0x20] + [UInt8](repeating: 0xC3, count: 32)
        return d
    }

    func testParseRealisticDO() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        XCTAssertTrue(kdf.isEnabled)
        XCTAssertEqual(kdf.algorithm, .iterSaltedS2K)
        XCTAssertEqual(kdf.hashAlgorithm, .sha256)
        XCTAssertEqual(kdf.iterationCount, 100_000)
        XCTAssertEqual(kdf.saltPW1, salt)
        XCTAssertEqual(kdf.saltPW3, saltPW3)
        XCTAssertEqual(kdf.initialHashPW1.count, 32)
        XCTAssertEqual(kdf.initialHashPW3.count, 32)
    }

    /// The end-to-end shape: parse what the card reports, derive what we send.
    func testParseThenDeriveMatchesVector() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        let derived = try XCTUnwrap(kdf.derive(pin: "123456", reference: .pw1))
        XCTAssertEqual(
            hex(derived),
            "8FC77436DED3825377DA921ACC4FB1E0C619E426B926C30F06FBB428C6AC9701"
        )
    }

    /// Both PW1 modes (0x81 signing, 0x82 confidentiality) are the same secret
    /// and must derive identically. Getting this wrong would make signing work
    /// and decryption fail, or vice versa — and burn an attempt each time.
    func testBothPW1ModesShareTheSameSalt() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        XCTAssertEqual(OpenPGPCardPIN.signing.kdfReference, .pw1)
        XCTAssertEqual(OpenPGPCardPIN.confidentiality.kdfReference, .pw1)
        XCTAssertEqual(OpenPGPCardPIN.admin.kdfReference, .pw3)

        let signing = kdf.derive(pin: "123456", reference: OpenPGPCardPIN.signing.kdfReference)
        let conf = kdf.derive(pin: "123456", reference: OpenPGPCardPIN.confidentiality.kdfReference)
        XCTAssertEqual(signing, conf)
    }

    func testAdminDerivesWithPW3Salt() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        let admin = try XCTUnwrap(kdf.derive(pin: "12345678", reference: .pw3))
        XCTAssertEqual(
            hex(admin),
            "8386C3832BFFC232CC6B0B4D958F07317235437F271A13E6D611DF8DE5721310"
        )
        // Same PIN, different reference, must not collide.
        let asPW1 = try XCTUnwrap(kdf.derive(pin: "12345678", reference: .pw1))
        XCTAssertNotEqual(admin, asPW1)
    }

    /// Algorithm byte 0x00 means "configured off" — a valid parse whose effect
    /// is the unchanged raw-PIN path, NOT an error and NOT derivation.
    func testAlgorithmNoneParsesAsDisabled() throws {
        let kdf = try XCTUnwrap(CardKDF.parse([0x81, 0x01, 0x00]))
        XCTAssertFalse(kdf.isEnabled)
        XCTAssertNil(kdf.derive(pin: "123456", reference: .pw1))
    }

    func testSHA512DOParses() throws {
        var d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x0A]
        d += [0x83, 0x04, 0x00, 0x01, 0x86, 0xA0]
        d += [0x84, 0x08] + salt
        let kdf = try XCTUnwrap(CardKDF.parse(d))
        XCTAssertEqual(kdf.hashAlgorithm, .sha512)
        XCTAssertEqual(kdf.derive(pin: "123456", reference: .pw1)?.count, 64)
    }

    // MARK: - Single-salt layout (`kdf-setup single`)

    /// GnuPG's 90-byte KDF-DO carries only tag 84 and reuses that one salt for
    /// PW1, the reset code and PW3 alike. A parse that leaves the PW3 salt empty
    /// makes every admin operation — PIN change, unblock, factory reset, on-card
    /// key generation — throw, while sign and decrypt keep working. That presents
    /// as "the admin PIN stopped working" and is exactly the kind of failure this
    /// whole file exists to prevent.
    private func singleSaltDO() -> [UInt8] {
        var d: [UInt8] = []
        d += [0x81, 0x01, 0x03]
        d += [0x82, 0x01, 0x08]
        d += [0x83, 0x04, 0x00, 0x01, 0x86, 0xA0]
        d += [0x84, 0x08] + salt
        d += [0x87, 0x20] + [UInt8](repeating: 0xC1, count: 32)
        d += [0x88, 0x20] + [UInt8](repeating: 0xC3, count: 32)
        return d
    }

    func testSingleSaltLayoutParses() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(singleSaltDO()))
        XCTAssertTrue(kdf.isEnabled)
        XCTAssertEqual(kdf.saltPW1, salt)
        XCTAssertTrue(kdf.saltPW3.isEmpty)
        XCTAssertTrue(kdf.saltResetCode.isEmpty)
    }

    func testSingleSaltLayoutDerivesAdminPINFromPW1Salt() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(singleSaltDO()))
        let admin = try XCTUnwrap(
            kdf.derive(pin: "12345678", reference: .pw3),
            "admin PIN must derive on a single-salt card, not return nil"
        )
        let asPW1 = try XCTUnwrap(kdf.derive(pin: "12345678", reference: .pw1))
        XCTAssertEqual(admin, asPW1)

        let rc = try XCTUnwrap(kdf.derive(pin: "12345678", reference: .resetCode))
        XCTAssertEqual(rc, asPW1)
    }

    /// The three-salt layout must NOT collapse — the fallback applies only when a
    /// salt is genuinely absent.
    func testThreeSaltLayoutKeepsSaltsDistinct() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        XCTAssertNotEqual(
            kdf.derive(pin: "12345678", reference: .pw3),
            kdf.derive(pin: "12345678", reference: .pw1)
        )
    }

    // MARK: - Malformed input is rejected, never guessed

    func testEmptyDOReturnsNil() {
        XCTAssertNil(CardKDF.parse([]))
    }

    func testUnknownHashAlgorithmRejected() {
        // SHA-1 (0x02) is not permitted by the card spec for KDF.
        let d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x02,
                          0x83, 0x04, 0x00, 0x01, 0x86, 0xA0, 0x84, 0x08] + salt
        XCTAssertNil(CardKDF.parse(d))
    }

    func testUnknownKDFAlgorithmRejected() {
        XCTAssertNil(CardKDF.parse([0x81, 0x01, 0x09]))
    }

    func testMissingPW1SaltRejected() {
        let d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x08,
                          0x83, 0x04, 0x00, 0x01, 0x86, 0xA0]
        XCTAssertNil(CardKDF.parse(d))
    }

    func testTruncatedFieldRejectedRatherThanMisparsed() {
        // Declares 8 salt bytes, supplies 3.
        let d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x08,
                          0x83, 0x04, 0x00, 0x01, 0x86, 0xA0,
                          0x84, 0x08, 0x01, 0x02, 0x03]
        XCTAssertNil(CardKDF.parse(d))
    }

    func testZeroIterationCountRejected() {
        let d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x08,
                          0x83, 0x04, 0x00, 0x00, 0x00, 0x00, 0x84, 0x08] + salt
        XCTAssertNil(CardKDF.parse(d))
    }

    func testWrongLengthIterationCountRejected() {
        let d: [UInt8] = [0x81, 0x01, 0x03, 0x82, 0x01, 0x08,
                          0x83, 0x02, 0x86, 0xA0, 0x84, 0x08] + salt
        XCTAssertNil(CardKDF.parse(d))
    }

    // MARK: - Description shown on the card-status screen

    func testDisplayDescriptionNamesParameters() throws {
        let kdf = try XCTUnwrap(CardKDF.parse(realisticDO()))
        // The count is a localized number, so it carries the locale's grouping.
        XCTAssertEqual(kdf.displayDescription, "SHA-256, \(100_000.formatted()) iterations")
    }
}
