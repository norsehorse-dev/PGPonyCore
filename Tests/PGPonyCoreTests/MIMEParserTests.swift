// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// MIMEParserTests
//
// Phase 1 of PGP/MIME multipart decrypt. These tests drive the pure-Swift
// `MIMEParser` / `MIMEPresentation` against fixtures in Resources/mime/.
//
// The headline fixture, `dong_real.eml`, is FHYQ Dong's actual Thunderbird
// PGP/MIME message (the decrypted bytes of his "carry both" report): nested
// multipart/mixed wrapping a multipart/alternative (base64 text/plain that is
// format=flowed, plus quoted-printable text/html) alongside a quoted-printable
// application/pgp-keys attachment. The two synthetic fixtures cover shapes the
// real one doesn't: two attachments with an RFC 2047 encoded-word filename, and
// a multipart/signed wrapper whose signature part must not surface as a file.
//
// Resources/mime/ is dropped into the synchronized PGPonyTests folder, so the
// fixtures bundle automatically. The dual lookup mirrors RFC9580VectorTests.

import XCTest
@testable import PGPonyCore

final class MIMEParserTests: XCTestCase {

    // MARK: - Resource loading

    private func loadFixture(_ name: String) throws -> Data {
        let bundle = Bundle.module
        let url = bundle.url(forResource: name, withExtension: "eml", subdirectory: "mime")
            ?? bundle.url(forResource: name, withExtension: "eml")
        guard let url else {
            throw XCTSkip("MIME fixture \(name).eml not bundled — add Resources/mime/ to the PGPonyTests target.")
        }
        return try Data(contentsOf: url)
    }

    private func text(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
    }

    // MARK: - dong_real.eml (the real reported case)

    func testDongReal_parsesAsStructuredMultipart() throws {
        let data = try loadFixture("dong_real")
        guard let message = MIMEParser.parseMultipart(data) else {
            return XCTFail("dong_real should parse as structured multipart")
        }
        XCTAssertEqual(message.root.contentType.mimeType, "multipart/mixed")
    }

    func testDongReal_bodyIsPlainTextWithHTMLAlternative() throws {
        let data = try loadFixture("dong_real")
        let p = try XCTUnwrap(MIMEParser.parseMultipart(data)).presentation

        let plain = try XCTUnwrap(p.plainText, "expected a decoded text/plain body")
        XCTAssertTrue(plain.hasPrefix("Hi NorseHorse,"), "flowed body should start with the greeting")
        XCTAssertTrue(plain.contains("Thanks again,"))
        XCTAssertTrue(plain.contains("FHYQ"))
        XCTAssertTrue(plain.contains("\u{2014}"), "em dash should survive base64 + UTF-8 decode")

        let html = try XCTUnwrap(p.htmlText, "the alternative text/html part should be retained")
        XCTAssertTrue(html.contains("<body"))
    }

    func testDongReal_notSigned() throws {
        let data = try loadFixture("dong_real")
        let p = try XCTUnwrap(MIMEParser.parseMultipart(data)).presentation
        XCTAssertFalse(p.isSigned, "no multipart/signed or pgp-signature part is present")
    }

    func testDongReal_pgpKeysAttachment() throws {
        let data = try loadFixture("dong_real")
        let p = try XCTUnwrap(MIMEParser.parseMultipart(data)).presentation

        XCTAssertEqual(p.attachments.count, 1, "only the public-key part is an attachment")
        let att = try XCTUnwrap(p.attachments.first)
        XCTAssertEqual(att.filename, "OpenPGP_0xCFE702FB746017E1_and_old_rev.asc")
        XCTAssertEqual(att.mimeType, "application/pgp-keys")
        XCTAssertEqual(att.byteCount, 2452, "quoted-printable decode is byte-exact")
        XCTAssertTrue(text(att.data).hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(text(att.data).contains("-----END PGP PUBLIC KEY BLOCK-----"))
    }

    // MARK: - mixed_two_attachments.eml

    func testMixedTwoAttachments_bodyAndTwoFiles() throws {
        let data = try loadFixture("mixed_two_attachments")
        let p = try XCTUnwrap(MIMEParser.parseMultipart(data)).presentation

        XCTAssertFalse(p.isSigned)
        XCTAssertNil(p.htmlText, "this message has no html alternative")
        let plain = try XCTUnwrap(p.plainText)
        XCTAssertTrue(plain.contains("Two files attached."))

        XCTAssertEqual(p.attachments.count, 2)

        let report = try XCTUnwrap(p.attachments.first { $0.filename == "report.csv" })
        XCTAssertEqual(report.mimeType, "text/csv")
        XCTAssertEqual(report.byteCount, 21)
        XCTAssertEqual(text(report.data), "a,b,c\r\n1,2,3\r\n4,5,6\r\n")

        // The second filename arrives RFC 2047 B-encoded and must be decoded.
        let resume = try XCTUnwrap(p.attachments.first { $0.filename == "résumé.txt" })
        XCTAssertEqual(resume.mimeType, "text/plain")
        XCTAssertEqual(resume.byteCount, 26)
    }

    // MARK: - signed_alternative.eml

    func testSignedAlternative_signedFlagAndNoSignatureAttachment() throws {
        let data = try loadFixture("signed_alternative")
        let message = try XCTUnwrap(MIMEParser.parseMultipart(data))
        XCTAssertEqual(message.root.contentType.mimeType, "multipart/signed")

        let p = message.presentation
        XCTAssertTrue(p.isSigned, "multipart/signed must set isSigned (without claiming verified)")

        let plain = try XCTUnwrap(p.plainText)
        XCTAssertTrue(plain.contains("Signed hello."))
        XCTAssertTrue(plain.contains("Line two."))
        XCTAssertNotNil(p.htmlText)

        XCTAssertEqual(p.attachments.count, 0, "the pgp-signature part is not a user attachment")
    }

    // MARK: - Detection / fallback guarantee (parseMultipart returns nil)

    func testPlainText_isNotStructured() {
        let data = Data("Hello NorseHorse,\n\nThis is a normal message.\n".utf8)
        XCTAssertNil(MIMEParser.parseMultipart(data),
                     "ordinary plain text must fall back to the existing view")
    }

    func testInlinePGP_isNotStructured() {
        let armored = """
        -----BEGIN PGP MESSAGE-----

        wcBMA1234567890abcdef
        -----END PGP MESSAGE-----
        """
        XCTAssertNil(MIMEParser.parseMultipart(Data(armored.utf8)),
                     "inline-PGP plaintext must not be treated as multipart")
    }

    func testSingleTextEntity_isNotStructured() {
        let entity = "Content-Type: text/plain; charset=UTF-8\n\nJust a single part.\n"
        XCTAssertNil(MIMEParser.parseMultipart(Data(entity.utf8)),
                     "a lone non-multipart entity is not structured")
    }

    // MARK: - Decoder units

    func testBase64Decode() {
        XCTAssertEqual(MIMEParser.decodeBase64(Array("SGVsbG8=".utf8)), Array("Hello".utf8))
    }

    func testQuotedPrintableDecode_withSoftBreakAndUTF8() {
        let input = Array("Hello=20World=\r\nNext=E2=80=94end".utf8)
        let decoded = MIMEParser.decodeText(MIMEParser.decodeQuotedPrintable(input), charset: "utf-8")
        XCTAssertEqual(decoded, "Hello WorldNext\u{2014}end")
    }

    func testFormatFlowedUnwrap() {
        let input = "Line one that wraps \nand continues.\nHard break here.\n"
        let out = MIMEParser.applyFormatFlowed(input, delSp: false)
        XCTAssertEqual(out, "Line one that wraps and continues.\nHard break here.\n")
    }

    func testEncodedWords_BAndQ() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?UTF-8?B?csOpc3Vtw6kudHh0?="), "résumé.txt")
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?UTF-8?Q?r=C3=A9sum=C3=A9.txt?="), "résumé.txt")
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?UTF-8?Q?hello_world?="), "hello world")
        XCTAssertEqual(MIMEParser.decodeEncodedWords("file =?UTF-8?B?csOpc3Vtw6kudHh0?= end"),
                       "file résumé.txt end")
        XCTAssertEqual(MIMEParser.decodeEncodedWords("plain.txt"), "plain.txt")
    }

    func testContentTypeParsing() {
        let ct = MIMEParser.parseContentType("text/plain; charset=UTF-8; format=flowed")
        XCTAssertEqual(ct.type, "text")
        XCTAssertEqual(ct.subtype, "plain")
        XCTAssertEqual(ct.charset, "UTF-8")
        XCTAssertTrue(ct.isFlowed)

        let mp = MIMEParser.parseContentType("multipart/mixed; boundary=\"abc123\"")
        XCTAssertTrue(mp.isMultipart)
        XCTAssertEqual(mp.boundary, "abc123")
    }
}
