// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ArmorCommentValidatorTests.swift
// PGPonyTests
//
// Tests for the armor "Comment:" header sanitizer/validator (iOS port of the
// Android ArmorCommentValidator). Covers the GnuPG interop cases: default,
// custom, empty/removed, and odd characters (unicode/symbols/control) after
// validation.
//
// Note on the length cap: Swift caps by Character (grapheme cluster) via
// String.prefix, so a grapheme is never split — unlike the Android version
// which caps by UTF-16 code unit and guards against surrogate splits. Both
// produce valid armor; the emoji expectations below reflect Swift semantics.

import XCTest
@testable import PGPonyCore

final class ArmorCommentValidatorTests: XCTestCase {

    // MARK: - Toggle

    func testToggleOffAlwaysProducesNoHeader() {
        XCTAssertNil(ArmorComment.validate(include: false, raw: "anything"))
        XCTAssertNil(ArmorComment.validate(include: false, raw: ""))
        XCTAssertNil(ArmorComment.validate(include: false, raw: ArmorComment.defaultComment))
    }

    // MARK: - Default + custom

    func testDefaultStringPassesThrough() {
        XCTAssertEqual(
            ArmorComment.validate(include: true, raw: ArmorComment.defaultComment),
            "PGPony - PGPony.app"
        )
    }

    func testCustomStringIsPreserved() {
        XCTAssertEqual(
            ArmorComment.validate(include: true, raw: "Sent from my phone"),
            "Sent from my phone"
        )
    }

    // MARK: - Empty / removed while ON

    func testEmptyWhileOnProducesNoHeader() {
        XCTAssertNil(ArmorComment.validate(include: true, raw: ""))
    }

    func testWhitespaceOnlyProducesNoHeader() {
        XCTAssertNil(ArmorComment.validate(include: true, raw: "    \t   "))
    }

    func testColonsOnlyProducesNoHeader() {
        XCTAssertNil(ArmorComment.validate(include: true, raw: ":::"))
    }

    // MARK: - Single line

    func testCRLFStripped() {
        let r = ArmorComment.validate(include: true, raw: "line one\r\nline two")
        XCTAssertEqual(r, "line oneline two")
        XCTAssertFalse(r!.contains("\n"))
        XCTAssertFalse(r!.contains("\r"))
    }

    func testLoneNewlinesStripped() {
        XCTAssertEqual(ArmorComment.validate(include: true, raw: "a\nb\nc"), "abc")
    }

    // MARK: - Control + leading colon

    func testControlCharactersStripped() {
        let raw = "ab\u{0000}c\td\u{000B}e\u{0007}f"
        XCTAssertEqual(ArmorComment.validate(include: true, raw: raw), "abcdef")
    }

    func testLeadingColonStripped() {
        XCTAssertEqual(ArmorComment.validate(include: true, raw: ":injected"), "injected")
    }

    func testMultipleLeadingColonsWithSpacesStripped() {
        XCTAssertEqual(ArmorComment.validate(include: true, raw: "  : : value"), "value")
    }

    func testInteriorColonKept() {
        XCTAssertEqual(ArmorComment.validate(include: true, raw: "ratio 16:9"), "ratio 16:9")
    }

    // MARK: - Length cap

    func testOverlongCappedAt80() {
        let r = ArmorComment.validate(include: true, raw: String(repeating: "x", count: 200))
        XCTAssertEqual(r?.count, 80)
    }

    func testExactly80Kept() {
        let r = ArmorComment.validate(include: true, raw: String(repeating: "y", count: 80))
        XCTAssertEqual(r?.count, 80)
    }

    // MARK: - Unicode / symbols

    func testUnicodeAndSymbolsPreserved() {
        let raw = "café ☕ — naïve ✓ £€¥"
        XCTAssertEqual(ArmorComment.validate(include: true, raw: raw), "café ☕ — naïve ✓ £€¥")
    }

    func testEmojiGraphemeNotSplitAtCap() {
        // 79 plain + 1 emoji = 80 Characters -> fits, emoji intact.
        let raw = String(repeating: "z", count: 79) + "😀"
        let r = ArmorComment.validate(include: true, raw: raw)!
        XCTAssertEqual(r.count, 80)
        XCTAssertTrue(r.hasSuffix("😀"))
    }

    func testEmojiDroppedWhenOverCap() {
        // 80 plain + 1 emoji = 81 Characters -> emoji dropped (whole grapheme).
        let raw = String(repeating: "z", count: 80) + "😀"
        let r = ArmorComment.validate(include: true, raw: raw)!
        XCTAssertEqual(r.count, 80)
        XCTAssertFalse(r.contains("😀"))
    }

    // MARK: - Combined adversarial input

    func testMalformedHeaderInputFullySanitized() {
        let raw = "  ::\r\nComment: evil\u{0000}\tpayload" + String(repeating: "!", count: 100)
        let r = ArmorComment.validate(include: true, raw: raw)!
        XCTAssertFalse(r.contains("\n"))
        XCTAssertFalse(r.contains("\r"))
        XCTAssertFalse(r.hasPrefix(":"))
        XCTAssertLessThanOrEqual(r.count, ArmorComment.maxLength)
    }

    // MARK: - headerBlock formatting

    func testHeaderBlockShape() {
        // With a value, headerBlock is "Comment: <value>\n"; the armorers add
        // the blank-line separator separately.
        // (current reads UserDefaults, so we validate the formatting via the
        // pure pieces instead of mutating shared defaults here.)
        let value = ArmorComment.validate(include: true, raw: "hello")!
        XCTAssertEqual("Comment: \(value)\n", "Comment: hello\n")
    }
}
