// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BackupCodeTests.swift
// PGPonyTests
//
// v8.0.0 Phase A — the backup code generator/formatter/validator. Pure, no
// external dependencies. The known-vector test ties this base32 implementation
// to the checked-in cross-platform fixture: the documented fixture code MUST be
// what these 15 entropy bytes encode to, or the fixture can't be opened.

import XCTest
@testable import PGPonyCore

final class BackupCodeTests: XCTestCase {

    // 15 entropy bytes behind the checked-in fixture (see the Phase A README).
    private let fixtureEntropy: [UInt8] =
        [0x8f, 0x3a, 0x1c, 0x9d, 0x5e, 0x0b, 0x47, 0xa6,
         0xc2, 0xf8, 0x0d, 0x19, 0xb3, 0xe7, 0x5a]
    private let fixtureCanonical = "HWX1S7AY1D3TDGQR1MCV7STT"
    private let fixtureDisplay = "HWX1S7-AY1D3T-DGQR1M-CV7STT"

    // MARK: Generation shape

    func testGenerateHasFourGroupsOfSix() throws {
        let code = try BackupCode.generate()
        let groups = code.split(separator: "-").map(String.init)
        XCTAssertEqual(groups.count, 4)
        for g in groups { XCTAssertEqual(g.count, 6) }
    }

    func testGeneratedCodeNormalizesToTwentyFourSymbols() throws {
        let code = try BackupCode.generate()
        let canonical = try BackupCode.normalize(code)
        XCTAssertEqual(canonical.count, 24)
        for ch in canonical {
            XCTAssertTrue(BackupCode.alphabet.contains(ch), "‘\(ch)’ not in the code alphabet")
        }
    }

    func testGeneratedCodesAreUnique() throws {
        var seen = Set<String>()
        for _ in 0..<64 {
            let c = try BackupCode.normalize(try BackupCode.generate())
            XCTAssertFalse(seen.contains(c), "duplicate code generated")
            seen.insert(c)
        }
    }

    func testGeneratorNeverEmitsAmbiguousSymbols() throws {
        // I, L, O, U must never appear — that's the whole point of Crockford.
        for _ in 0..<200 {
            let canonical = try BackupCode.normalize(try BackupCode.generate())
            XCTAssertNil(canonical.first { "ILOU".contains($0) })
        }
    }

    // MARK: Base32 known vector (ties Swift to the fixture)

    func testBase32KnownVector() {
        XCTAssertEqual(BackupCode.encodeBase32(fixtureEntropy), fixtureCanonical)
    }

    func testBase32ProducesTwentyFourSymbolsFromFifteenBytes() {
        let bytes = [UInt8](repeating: 0xAB, count: BackupCode.entropyByteCount)
        XCTAssertEqual(BackupCode.encodeBase32(bytes).count, BackupCode.symbolCount)
    }

    // MARK: Formatting

    func testFormatInsertsGroupHyphens() {
        XCTAssertEqual(BackupCode.format(fixtureCanonical), fixtureDisplay)
    }

    func testFormatIsReversibleByNormalize() throws {
        let display = BackupCode.format(fixtureCanonical)
        XCTAssertEqual(try BackupCode.normalize(display), fixtureCanonical)
    }

    // MARK: Normalization / typo tolerance

    func testNormalizeIgnoresCaseSpacesAndHyphens() throws {
        let messy = "  hwx1s7 ay1d3t-dgqr1m  cv7stt "
        XCTAssertEqual(try BackupCode.normalize(messy), fixtureCanonical)
    }

    func testNormalizeFoldsLookAlikes() throws {
        // o/O→0, i/I & l/L→1, u/U→V. Build a 24-symbol string exercising each.
        // Canonical target:  0 1 1 V  then 20 filler symbols.
        let typed = "OiLu" + "23456789ABCDEFGHJKMN"   // 4 + 20 = 24
        let expected = "011V" + "23456789ABCDEFGHJKMN"
        XCTAssertEqual(try BackupCode.normalize(typed), expected)
    }

    func testNormalizeRejectsOutOfAlphabet() {
        XCTAssertThrowsError(try BackupCode.normalize("HWX1S7-AY1D3T-DGQR1M-CV7ST!")) { error in
            guard case BackupCodeError.invalidCharacter = error else {
                return XCTFail("expected invalidCharacter, got \(error)")
            }
        }
    }

    func testNormalizeRejectsWrongLength() {
        XCTAssertThrowsError(try BackupCode.normalize("HWX1S7-AY1D3T-DGQR1M-CV7ST")) { error in
            guard case BackupCodeError.wrongLength(let n) = error else {
                return XCTFail("expected wrongLength, got \(error)")
            }
            XCTAssertEqual(n, 23)
        }
    }

    func testNormalizeRejectsEmpty() {
        XCTAssertThrowsError(try BackupCode.normalize("   -- ")) { error in
            guard case BackupCodeError.emptyInput = error else {
                return XCTFail("expected emptyInput, got \(error)")
            }
        }
    }

    func testIsValidMatchesNormalize() {
        XCTAssertTrue(BackupCode.isValid(fixtureDisplay))
        XCTAssertFalse(BackupCode.isValid("too-short"))
        XCTAssertFalse(BackupCode.isValid(""))
    }
}
