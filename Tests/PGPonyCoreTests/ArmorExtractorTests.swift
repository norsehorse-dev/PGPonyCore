// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ArmorExtractorTests.swift
// PGPonyTests
//
// 8.3.0 (6.5, Android 4.5.0 item 19): the six cases Android's
// ArmorExtractorTest covers, plus CRLF and a BOM.

import XCTest
@testable import PGPonyCore

final class ArmorExtractorTests: XCTestCase {

    private let publicKey = """
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    mDMEZgAAABYJKwYBBAHaRw8BAQdAexample/PUBLIC/one
    =AbCd
    -----END PGP PUBLIC KEY BLOCK-----
    """

    private let privateKey = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----

    lFgEZgAAABYJKwYBBAHaRw8BAQdAexample/PRIVATE
    =EfGh
    -----END PGP PRIVATE KEY BLOCK-----
    """

    private let signature = """
    -----BEGIN PGP SIGNATURE-----

    iHUEABYKAB0WIQSexample/SIGNATURE
    =IjKl
    -----END PGP SIGNATURE-----
    """

    private let message = """
    -----BEGIN PGP MESSAGE-----

    hF4Dexample/MESSAGE
    =MnOp
    -----END PGP MESSAGE-----
    """

    func testCleanKeyPassesThroughUnchanged() {
        XCTAssertEqual(ArmorExtractor.extract(from: publicKey), publicKey)
        XCTAssertTrue(ArmorExtractor.isCleanSingleBlock(publicKey))
        let withTrailingNewline = publicKey + "\n"
        XCTAssertEqual(ArmorExtractor.extract(from: withTrailingNewline), withTrailingNewline, "byte for byte, trailing newline included")
    }

    func testPageTextAroundAKeyIsDropped() {
        let noisy = """
        Here is my key, thanks!

        \(publicKey)

        Sent from my phone. Fingerprint below:
        ABCD 1234
        """
        let out = ArmorExtractor.extract(from: noisy)
        XCTAssertEqual(out, publicKey + "\n")
        XCTAssertEqual(ArmorExtractor.blocks(in: noisy).map(\.type), ["PUBLIC KEY BLOCK"])
    }

    func testKeyBlocksArePreferredOverAStraySignature() {
        let mixed = signature + "\n\nquoted reply\n\n" + publicKey + "\n\n" + privateKey
        let out = ArmorExtractor.extract(from: mixed)
        XCTAssertEqual(out, publicKey + "\n\n" + privateKey + "\n")
        XCTAssertEqual(ArmorExtractor.blocks(in: mixed).map(\.type), ["SIGNATURE", "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK"])
    }

    func testNoKeyFallsBackToEveryBlock() {
        let noKeys = "intro\n" + message + "\nmiddle\n" + signature + "\nend"
        XCTAssertEqual(ArmorExtractor.extract(from: noKeys), message + "\n\n" + signature + "\n")
    }

    func testNoBlockIsNil() {
        XCTAssertNil(ArmorExtractor.extract(from: "just some text with -----BEGIN but no block"))
        XCTAssertNil(ArmorExtractor.extract(from: ""))
        // An unmatched BEGIN (END of another type) is not a block.
        let mismatched = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP MESSAGE-----\n"
        XCTAssertNil(ArmorExtractor.extract(from: mismatched))
    }

    func testEndIsMatchedToItsOwnBegin() {
        // A message END inside a key block does not close the key block.
        let nested = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP MESSAGE-----\ndef\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----\n"
        let blocks = ArmorExtractor.blocks(in: nested)
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0].type, "PUBLIC KEY BLOCK")
        XCTAssertTrue(blocks[0].text.contains("-----END PGP MESSAGE-----"))
    }

    func testCRLFAndBOMAreTolerated() {
        let crlf = "\u{FEFF}" + publicKey.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n"
        let out = ArmorExtractor.extract(from: crlf)
        XCTAssertEqual(out, publicKey + "\n")
        XCTAssertFalse(out?.contains("\r") ?? true)
    }
}
