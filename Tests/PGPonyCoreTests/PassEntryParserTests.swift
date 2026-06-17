// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import XCTest
@testable import PGPonyCore

/// Starter tests for the pure `pass` parser — no keys, no fixtures, no secrets.
///
/// This is intentionally a small, self-contained example so CI has something real
/// to run. Populate the rest of `Tests/` from the app's existing `PGPonyTests`,
/// bringing over ONLY fixture-free cases (RFC test vectors, packet round-trips,
/// interop checks) and NEVER any fixture that embeds a real private key.
final class PassEntryParserTests: XCTestCase {

    func testPasswordIsFirstLine() {
        let c = PassEntryParser.parse("hunter2\nusername: bob")
        XCTAssertEqual(c.password, "hunter2")
    }

    func testKeyValueFieldParsed() {
        let c = PassEntryParser.parse("pw\nusername: bob")
        XCTAssertEqual(c.fields.first?.key, "username")
        XCTAssertEqual(c.fields.first?.value, "bob")
    }

    func testOtpauthDetectedNotGenerated() {
        let c = PassEntryParser.parse("pw\notpauth://totp/Example?secret=ABC")
        XCTAssertEqual(c.otpauth, "otpauth://totp/Example?secret=ABC")
    }

    func testBareURLStaysFreeform() {
        // A standalone URL must not be misread as `key: value` on its scheme colon.
        let c = PassEntryParser.parse("pw\nhttps://example.com")
        XCTAssertTrue(c.fields.isEmpty)
        XCTAssertEqual(c.extraLines, ["https://example.com"])
    }

    func testValueMayContainColons() {
        let c = PassEntryParser.parse("pw\nnote: see 12:30")
        XCTAssertEqual(c.fields.first?.key, "note")
        XCTAssertEqual(c.fields.first?.value, "see 12:30")
    }

    func testCRLFNormalised() {
        let c = PassEntryParser.parse("pw\r\nusername: bob\r\n")
        XCTAssertEqual(c.password, "pw")
        XCTAssertEqual(c.fields.first?.value, "bob")
    }
}
